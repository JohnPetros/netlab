#!/usr/bin/env python3
"""
Exercício 12 - Pacotes removidos do sistema
Arquivo de log: /var/log/dpkg.log (+ rotacionados .1, .2.gz, etc.)

O dpkg distingue dois tipos de remoção:

  remove — remove os binários mas mantém arquivos de configuração
    2026-03-08 10:00:01 remove curl:amd64 7.81.0-1ubuntu1 <none>

  purge  — remove tudo, incluindo arquivos de configuração
    2026-03-08 10:00:02 purge curl:amd64 7.81.0-1ubuntu1 <none>

Um pacote que passou por "remove" e depois "purge" aparece nos dois.
O script registra ambos os eventos separadamente e indica no resumo
quais pacotes foram completamente purgados.

Além da linha da ação principal, o dpkg também gera linhas de status
intermediárias como:
  status half-installed ...
  status config-files ...    ← aparece após remove (configs mantidas)
  status not-installed ...   ← aparece após purge (completamente removido)

O script foca apenas nas linhas de ação (remove/purge) para evitar
duplicatas dos registros de status.
"""

import re
import os
import gzip
import glob
from datetime import datetime
from collections import defaultdict

LOG_DIR = "/var/log"
LOG_BASE = os.path.join(LOG_DIR, "dpkg.log")

# -------------------------------------------------------------------
# Regex para linha de remoção do dpkg.log
#
# Formato:
#   2026-03-08 10:00:01 remove curl:amd64 7.81.0-1ubuntu1 <none>
#   2026-03-08 10:00:02 purge  curl:amd64 7.81.0-1ubuntu1 <none>
#
# Grupos capturados:
#   date, time, action (remove|purge), package, arch, version
# -------------------------------------------------------------------
LINE_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>remove|purge)\s+"
    r"(?P<package>[^:\s]+)(?::(?P<arch>\S+))?\s+"
    r"(?P<version>\S+)\s+\S+$"
)


# -------------------------------------------------------------------
# Descobre todos os arquivos de log para varrer
# Ordem: atual → .1 → .2.gz → .3.gz ...
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
# Leitura de todos os arquivos
# -------------------------------------------------------------------
# Estrutura:
# { package_name: {
#     "arch":    "amd64",
#     "events":  [ {"date","time","action","version"}, ... ]
#   }
# }
packages = defaultdict(lambda: {"arch": "—", "events": []})

total_files_read = 0

for path, is_gz in get_log_files():
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            total_files_read += 1
            for line in f:
                m = LINE_PATTERN.match(line.strip())
                if not m:
                    continue

                pkg = m.group("package")
                arch = m.group("arch") or "—"

                packages[pkg]["arch"] = arch
                packages[pkg]["events"].append(
                    {
                        "date": m.group("date"),
                        "time": m.group("time"),
                        "action": m.group("action"),
                        "version": m.group("version"),
                    }
                )

    except (PermissionError, FileNotFoundError) as e:
        print(f"[aviso] {path}: {e}")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 65
SEP2 = "-" * 50

print(SEP)
print("   PACOTES REMOVIDOS DO SISTEMA")
print(SEP)

if not packages:
    print(f"""
  Nenhum pacote removido encontrado nos logs.

  Logs consultados : {total_files_read} arquivo(s) em {LOG_DIR}
  Ações buscadas   : remove, purge

  Para gerar eventos de teste:
    sudo apt install cowsay -y   # instala
    sudo apt remove cowsay       # remove (mantém configs)
    sudo apt purge cowsay        # purge (remove configs)
    python3 ex12.py
""")
    raise SystemExit(0)

# Separa pacotes por tipo de remoção para o resumo
only_removed = []  # remove mas nunca purgado
fully_purged = []  # passou por purge
both = []  # teve remove E purge

for pkg, data in sorted(packages.items()):
    actions = {e["action"] for e in data["events"]}
    if "purge" in actions and "remove" in actions:
        both.append(pkg)
    elif "purge" in actions:
        fully_purged.append(pkg)
    else:
        only_removed.append(pkg)

# ------- Listagem detalhada por pacote ----------------------------
ACTION_ICON = {"remove": "🗑", "purge": "💣"}
ACTION_DESC = {
    "remove": "removido   (configs mantidas)",
    "purge": "purgado    (configs removidas)",
}

for pkg, data in sorted(packages.items()):
    events = data["events"]
    arch = data["arch"]

    print(f"\n  📦 {pkg}  [{arch}]  —  {len(events)} evento(s)")
    print(f"  {'-' * 48}")

    for e in events:
        icon = ACTION_ICON.get(e["action"], "•")
        desc = ACTION_DESC.get(e["action"], e["action"])
        print(f"    {icon}  {e['date']}  {e['time']}  |  {desc}")
        print(f"         Versão: {e['version']}")

# ------- Resumo ---------------------------------------------------
total = len(packages)
print(f"\n{SEP}")
print("  RESUMO")
print(SEP)
print(f"  Total de pacotes com remoção registrada : {total}")
print()
print(f"  🗑  Apenas removidos (configs mantidas) : {len(only_removed)}")
for p in only_removed:
    print(f"       • {p}")

print()
print(f"  💣  Completamente purgados              : {len(fully_purged)}")
for p in fully_purged:
    print(f"       • {p}")

if both:
    print()
    print(f"  🗑💣 Remove + Purge                     : {len(both)}")
    for p in both:
        print(f"       • {p}")

print()
print(f"  Logs consultados : {total_files_read} arquivo(s)")
print(SEP)
print()
print("  Dica: para ver remoções em tempo real:")
print("    sudo tail -f /var/log/dpkg.log | grep -E 'remove|purge'")
print(SEP)
