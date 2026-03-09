#!/usr/bin/env python3
"""
Exercício 11 - Pacotes instalados na última semana
Arquivo de log: /var/log/dpkg.log (+ rotacionados .1, .2.gz, etc.)

O dpkg.log registra todas as operações de pacotes com o formato:

  2026-02-10 14:05:33 install base-passwd:amd64 <none> 3.6.3build1
  │                   │       │                 │      └─ versão instalada
  │                   │       │                 └─ versão anterior (<none> = novo)
  │                   │       └─ pacote:arquitetura
  │                   └─ ação: install | upgrade | remove | purge
  └─ data e hora

Ações monitoradas:
  install — pacote novo instalado pela primeira vez
  upgrade — pacote atualizado (versão anterior → nova)

Estratégia:
  - Descobre a data de hoje e calcula o limite de 7 dias atrás
  - Varre o dpkg.log atual e os arquivos rotacionados (.1, .2.gz...)
  - Filtra apenas linhas dentro da janela de 7 dias
  - Exibe install e upgrade separadamente, ordenados por data
"""

import re
import os
import gzip
import glob
from datetime import datetime, timedelta
from collections import defaultdict

LOG_DIR = "/var/log"
LOG_BASE = os.path.join(LOG_DIR, "dpkg.log")

# -------------------------------------------------------------------
# Janela de tempo: últimos 7 dias a partir de hoje
# -------------------------------------------------------------------
TODAY = datetime.now().date()
WEEK_AGO = TODAY - timedelta(days=7)

# -------------------------------------------------------------------
# Regex para linha relevante do dpkg.log
#
# Captura:
#   date    : "2026-02-10"
#   time    : "14:05:33"
#   action  : "install" ou "upgrade"
#   package : "base-passwd:amd64"  (nome + arquitetura)
#   old_ver : "<none>" ou versão anterior
#   new_ver : versão instalada/atualizada
# -------------------------------------------------------------------
LINE_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>install|upgrade)\s+"
    r"(?P<package>\S+)\s+"
    r"(?P<old_ver>\S+)\s+"
    r"(?P<new_ver>\S+)$"
)


# -------------------------------------------------------------------
# Coleta todos os arquivos de log na ordem: atual → rotacionados
# -------------------------------------------------------------------
def get_log_files():
    files = []
    if os.path.exists(LOG_BASE):
        files.append((LOG_BASE, False))  # .log atual

    # Rotacionados: dpkg.log.1 (texto), dpkg.log.2.gz ... (comprimidos)
    rotated = sorted(
        glob.glob(LOG_BASE + ".*"),
        key=lambda f: (
            # Ordena: .1 antes de .2.gz etc.
            int(re.search(r"\.(\d+)", f).group(1)) if re.search(r"\.(\d+)", f) else 999
        ),
    )
    for path in rotated:
        files.append((path, path.endswith(".gz")))

    return files


# -------------------------------------------------------------------
# Lê um arquivo (gzip ou texto) e retorna linhas como strings
# -------------------------------------------------------------------
def read_log(path, is_gz):
    opener = gzip.open if is_gz else open
    with opener(path, "rt", errors="replace") as f:
        return f.readlines()


# -------------------------------------------------------------------
# Processa todas as linhas e coleta eventos dentro da janela
# -------------------------------------------------------------------
# Estrutura: { "install": [{"date","time","package","arch","old","new"},...],
#              "upgrade": [...] }
events = defaultdict(list)

for path, is_gz in get_log_files():
    try:
        for line in read_log(path, is_gz):
            m = LINE_PATTERN.match(line.strip())
            if not m:
                continue

            # Converte a data da linha para objeto date
            line_date = datetime.strptime(m.group("date"), "%Y-%m-%d").date()

            # Ignora linhas fora da janela de 7 dias
            if line_date < WEEK_AGO:
                continue

            # Separa nome do pacote da arquitetura (ex: "bash:amd64")
            pkg_full = m.group("package")
            if ":" in pkg_full:
                pkg_name, arch = pkg_full.rsplit(":", 1)
            else:
                pkg_name, arch = pkg_full, "—"

            events[m.group("action")].append(
                {
                    "date": m.group("date"),
                    "time": m.group("time"),
                    "package": pkg_name,
                    "arch": arch,
                    "old_ver": m.group("old_ver"),
                    "new_ver": m.group("new_ver"),
                }
            )

    except (PermissionError, FileNotFoundError):
        pass  # arquivo inacessível — continua com o próximo

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 70
SEP2 = "-" * 55

print(SEP)
print("   PACOTES INSTALADOS/ATUALIZADOS NA ÚLTIMA SEMANA")
print(f"   Período: {WEEK_AGO}  →  {TODAY}")
print(SEP)

if not events:
    print(f"""
  Nenhum pacote instalado ou atualizado nos últimos 7 dias.

  Período verificado : {WEEK_AGO} a {TODAY}
  Log consultado     : {LOG_BASE}

  Para instalar algo e testar:
    sudo apt install curl
""")
    raise SystemExit(0)

# ------- Instalações novas ----------------------------------------
installs = events.get("install", [])
if installs:
    print(f"\n📦  INSTALAÇÕES NOVAS  ({len(installs)} pacote(s))")
    print(SEP2)
    print(f"  {'DATA':<12} {'HORA':<10} {'PACOTE':<35} {'VERSÃO'}")
    print(f"  {'─' * 10}  {'─' * 8}  {'─' * 33}  {'─' * 20}")
    for e in installs:
        print(f"  {e['date']:<12} {e['time']:<10} {e['package']:<35} {e['new_ver']}")

# ------- Atualizações ---------------------------------------------
upgrades = events.get("upgrade", [])
if upgrades:
    print(f"\n🔄  ATUALIZAÇÕES  ({len(upgrades)} pacote(s))")
    print(SEP2)
    print(f"  {'DATA':<12} {'HORA':<10} {'PACOTE':<30} {'ANTES':<20} {'DEPOIS'}")
    print(f"  {'─' * 10}  {'─' * 8}  {'─' * 28}  {'─' * 18}  {'─' * 18}")
    for e in upgrades:
        print(
            f"  {e['date']:<12} {e['time']:<10} {e['package']:<30} {e['old_ver']:<20} {e['new_ver']}"
        )

# ------- Resumo por dia -------------------------------------------
print(f"\n{SEP}")
print("  ATIVIDADE POR DIA")
print(SEP)

by_day = defaultdict(lambda: {"install": 0, "upgrade": 0})
for action, evs in events.items():
    for e in evs:
        by_day[e["date"]][action] += 1

print(f"  {'DATA':<14} {'INSTALAÇÕES':>12} {'ATUALIZAÇÕES':>14}")
print(f"  {'─' * 42}")
for day in sorted(by_day.keys()):
    i = by_day[day]["install"]
    u = by_day[day]["upgrade"]
    bar_i = "▓" * min(i, 20)
    bar_u = "░" * min(u, 20)
    print(f"  {day:<14} {i:>6}  {bar_i:<20}  {u:>6}  {bar_u}")

print(f"\n{SEP}")
total_i = len(installs)
total_u = len(upgrades)
print(f"  📦  Instalações novas  : {total_i}")
print(f"  🔄  Atualizações       : {total_u}")
print(f"  {'─' * 35}")
print(f"       Total             : {total_i + total_u}")
print(SEP)
