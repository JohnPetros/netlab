#!/usr/bin/env python3
"""
Exercício 13 - Rastreamento de comandos de gerenciamento de pacotes
Arquivo de log: /var/log/apt/history.log (+ rotacionados .1, .2.gz, etc.)

O apt registra cada operação em blocos delimitados por Start-Date / End-Date.
Cada bloco pode conter os campos:

  Start-Date: 2026-02-18  19:54:00
  Commandline: apt-get install -y curl          ← comando exato executado
  Requested-By: joao (1000)                     ← usuário real (quando sudo)
  Install: curl:amd64 (8.5.0), ...              ← pacotes instalados
  Upgrade: libssl:amd64 (old, new), ...         ← pacotes atualizados
  Remove:  cowsay:amd64 (3.7.0), ...            ← pacotes removidos
  Purge:   cowsay:amd64 (3.7.0), ...            ← pacotes purgados
  Reinstall: apt:amd64 (2.7.14), ...            ← reinstalações
  End-Date: 2026-02-18  19:54:04

Quando não há Requested-By, o comando foi executado diretamente como root.
O campo Commandline revela qual ferramenta foi usada: apt, apt-get ou dpkg.
"""

import re
import os
import gzip
import glob
from datetime import datetime
from collections import defaultdict

LOG_DIR = "/var/log/apt"
LOG_BASE = os.path.join(LOG_DIR, "history.log")


# -------------------------------------------------------------------
# Descobre todos os arquivos de log: atual + rotacionados
# -------------------------------------------------------------------
def get_log_files():
    files = []
    if os.path.exists(LOG_BASE):
        files.append((LOG_BASE, False))

    rotated = sorted(
        glob.glob(LOG_BASE + ".*"),
        key=lambda f: (
            int(re.search(r"\.(\d+)", f).group(1)) if re.search(r"\.(\d+)", f) else 999
        ),
    )
    for path in rotated:
        files.append((path, path.endswith(".gz")))

    return files


# -------------------------------------------------------------------
# Parser: divide o arquivo em blocos Start-Date / End-Date
# e extrai os campos de cada bloco
# -------------------------------------------------------------------
def parse_blocks(lines):
    """Gera um dict por bloco encontrado no arquivo."""
    block = {}
    for line in lines:
        line = line.rstrip("\n")

        if line.startswith("Start-Date:"):
            block = {"Start-Date": line.split(":", 1)[1].strip()}

        elif ":" in line and block:
            key, _, value = line.partition(": ")
            block[key.strip()] = value.strip()

        elif line == "" and block.get("End-Date"):
            yield block
            block = {}

    # Último bloco sem linha em branco final
    if block.get("End-Date"):
        yield block


# -------------------------------------------------------------------
# Detecta a ferramenta usada na linha de comando
# -------------------------------------------------------------------
TOOL_PATTERN = re.compile(r"\b(?P<tool>apt-get|apt|dpkg)\b", re.IGNORECASE)


def detect_tool(cmdline):
    m = TOOL_PATTERN.search(cmdline or "")
    return m.group("tool").lower() if m else "desconhecido"


# -------------------------------------------------------------------
# Detecta a ação principal do comando
# Exemplos:
#   "apt-get install -y curl"  → install
#   "apt remove cowsay"        → remove
#   "dpkg -i pacote.deb"       → install (dpkg)
#   "apt-get install --reinstall apt" → reinstall
# -------------------------------------------------------------------
ACTION_PATTERN = re.compile(
    r"\b(?P<action>install|remove|purge|upgrade|reinstall|"
    r"dist-upgrade|autoremove|autoclean|clean|update|download)\b",
    re.IGNORECASE,
)


def detect_action(cmdline, block):
    """Tenta inferir a ação pelo cmdline; usa os campos do bloco como fallback."""
    m = ACTION_PATTERN.search(cmdline or "")
    if m:
        return m.group("action").lower()

    # Fallback: vê quais campos de ação existem no bloco
    for field in ("Install", "Upgrade", "Remove", "Purge", "Reinstall"):
        if field in block:
            return field.lower()

    return "desconhecido"


# -------------------------------------------------------------------
# Conta pacotes de uma linha de campo (ex: Install, Upgrade, Remove)
# Formato: "pkg1:arch (ver), pkg2:arch (ver, automatic), ..."
# Considera apenas pacotes explícitos (exclui "automatic")
# -------------------------------------------------------------------
PKG_PATTERN = re.compile(r"(\S+:\S+)\s+\(([^)]+)\)")


def parse_packages(field_value):
    """Retorna lista de (nome, versão, automático)."""
    packages = []
    for m in PKG_PATTERN.finditer(field_value or ""):
        pkg_arch = m.group(1)
        details = m.group(2)
        auto = "automatic" in details
        # Pega só o nome sem arquitetura
        name = pkg_arch.split(":")[0]
        # Versão: primeiro token antes de vírgula
        version = details.split(",")[0].strip()
        packages.append((name, version, auto))
    return packages


# -------------------------------------------------------------------
# Leitura e parsing de todos os arquivos
# -------------------------------------------------------------------
operations = []  # lista de dicts com todos os campos relevantes

for path, is_gz in get_log_files():
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            lines = f.readlines()

        for block in parse_blocks(lines):
            cmdline = block.get("Commandline", "")
            tool = detect_tool(cmdline)
            action = detect_action(cmdline, block)

            # Requested-By: "username (uid)"  → extrai só o nome
            requested_by_raw = block.get("Requested-By", "")
            if requested_by_raw:
                user = requested_by_raw.split("(")[0].strip()
            else:
                user = "root"  # sem Requested-By = executado como root diretamente

            # Conta pacotes por categoria
            pkg_counts = {}
            for field in ("Install", "Upgrade", "Remove", "Purge", "Reinstall"):
                pkgs = parse_packages(block.get(field, ""))
                if pkgs:
                    explicit = [p for p in pkgs if not p[2]]  # exclui automatic
                    pkg_counts[field] = {
                        "total": len(pkgs),
                        "explicit": len(explicit),
                        "names": [p[0] for p in explicit][:10],  # top 10 explícitos
                    }

            operations.append(
                {
                    "date": block.get("Start-Date", "—"),
                    "end_date": block.get("End-Date", "—"),
                    "user": user,
                    "tool": tool,
                    "action": action,
                    "cmdline": cmdline,
                    "pkg_counts": pkg_counts,
                    "source": path,
                }
            )

    except (PermissionError, FileNotFoundError) as e:
        print(f"[aviso] {path}: {e}")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 70
SEP2 = "-" * 55

TOOL_ICON = {
    "apt": "📦",
    "apt-get": "📦",
    "dpkg": "🔧",
    "desconhecido": "❓",
}
ACTION_ICON = {
    "install": "▶",
    "reinstall": "↺",
    "upgrade": "⬆",
    "dist-upgrade": "⬆",
    "remove": "🗑",
    "purge": "💣",
    "autoremove": "🗑",
    "autoclean": "🧹",
    "clean": "🧹",
    "update": "🔄",
    "download": "⬇",
    "desconhecido": "•",
}

print(SEP)
print("   AUDITORIA DE GERENCIAMENTO DE PACOTES")
print(f"   Fonte: {LOG_BASE}")
print(SEP)

if not operations:
    print("""
  Nenhuma operação de pacote encontrada.
  Verifique se o arquivo existe: /var/log/apt/history.log
""")
    raise SystemExit(0)

# ------- Listagem detalhada ---------------------------------------
for op in operations:
    tool_icon = TOOL_ICON.get(op["tool"], "❓")
    action_icon = ACTION_ICON.get(op["action"], "•")

    print(f"\n{tool_icon} [{op['date']}]")
    print(f"  {action_icon} Ação    : {op['action'].upper()}")
    print(f"  👤 Usuário  : {op['user']}")
    print(f"  🛠  Ferram.  : {op['tool']}")
    print(f"  💻 Comando  : {op['cmdline'][:80]}")

    if op["pkg_counts"]:
        for field, data in op["pkg_counts"].items():
            explicit_str = ""
            if data["names"]:
                names = ", ".join(data["names"])
                if data["explicit"] > len(data["names"]):
                    names += f" ... +{data['explicit'] - len(data['names'])} mais"
                explicit_str = f" → {names}"
            auto_count = data["total"] - data["explicit"]
            auto_str = f" (+{auto_count} automáticos)" if auto_count else ""
            print(
                f"  📋 {field:<10}: {data['explicit']} explícito(s){auto_str}{explicit_str}"
            )

# ------- Resumo por usuário e ferramenta -------------------------
print(f"\n{SEP}")
print("  RESUMO POR USUÁRIO")
print(SEP)

by_user = defaultdict(lambda: defaultdict(int))
for op in operations:
    by_user[op["user"]][op["action"]] += 1

for user, actions in sorted(by_user.items()):
    total = sum(actions.values())
    print(f"\n  👤 {user}  ({total} operação(ões))")
    for action, count in sorted(actions.items(), key=lambda x: -x[1]):
        icon = ACTION_ICON.get(action, "•")
        bar = "█" * min(count, 20)
        print(f"     {icon} {action:<15} {count:>3}x  {bar}")

# ------- Resumo por ferramenta -----------------------------------
print(f"\n{SEP}")
print("  RESUMO POR FERRAMENTA")
print(SEP)

by_tool = defaultdict(int)
for op in operations:
    by_tool[op["tool"]] += 1

for tool, count in sorted(by_tool.items(), key=lambda x: -x[1]):
    icon = TOOL_ICON.get(tool, "❓")
    bar = "█" * min(count, 30)
    print(f"  {icon} {tool:<15} {count:>4}x  {bar}")

print(f"\n{SEP}")
print(f"  Total de operações registradas : {len(operations)}")
print(SEP)
print()
print("  Dica: para monitorar em tempo real:")
print("    tail -f /var/log/apt/history.log")
print(SEP)
