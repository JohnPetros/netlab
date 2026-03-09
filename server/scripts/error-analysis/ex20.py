#!/usr/bin/env python3
"""
Exercício 20 - Pacotes atualizados no sistema: nome e data da atualização
Fontes de log: /var/log/dpkg.log  +  /var/log/apt/history.log  (+ rotacionados)

Por que duas fontes?
  ┌─────────────────┬────────────────────────────────────────────────┐
  │ dpkg.log        │ Registro linha-a-linha de cada operação dpkg.  │
  │                 │ Contém timestamp preciso por pacote.            │
  │                 │ Formato: DATA HORA upgrade PKG V_ANTIGA V_NOVA  │
  ├─────────────────┼────────────────────────────────────────────────┤
  │ apt/history.log │ Registro por sessão apt. Contém o comando que  │
  │                 │ originou a atualização (apt-get, unattended...) │
  │                 │ Formato: bloco Start-Date/Upgrade:.../End-Date  │
  └─────────────────┴────────────────────────────────────────────────┘

  O script usa o dpkg.log como fonte primária (timestamp por pacote)
  e enriquece os dados com o comando apt do history.log quando disponível.

Distingue 3 categorias de "upgrade":
  ✦ ATUALIZAÇÃO REAL  — versão mudou (ex: 2.7.14 → 2.8.3)
  ↺ REINSTALAÇÃO      — mesma versão instalada novamente
  ? SEM INFO          — só encontrado em history.log, sem par no dpkg.log

Uso:
  python3 ex20.py                    # todos os upgrades
  python3 ex20.py --real-only        # só onde a versão mudou de fato
  python3 ex20.py --since 2026-02-18 # a partir de uma data
  python3 ex20.py --pkg libc6        # filtra por nome de pacote
  python3 ex20.py --top 15           # limita exibição
"""

import re
import os
import gzip
import glob
import argparse
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Argumentos
# ─────────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Lista pacotes atualizados a partir dos logs do gerenciador."
)
parser.add_argument("--since", default=None, help="Filtra a partir de YYYY-MM-DD")
parser.add_argument("--until", default=None, help="Filtra até YYYY-MM-DD (inclusive)")
parser.add_argument("--pkg", default=None, help="Filtra por nome de pacote (parcial)")
parser.add_argument(
    "--real-only",
    action="store_true",
    help="Mostra só upgrades onde a versão realmente mudou",
)
parser.add_argument("--top", type=int, default=0, help="Limita a N pacotes (0 = todos)")
parser.add_argument(
    "--no-enrich",
    action="store_true",
    help="Não usa history.log para enriquecer os dados",
)
args = parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        print(f"[ERRO] Data inválida '{s}'. Use YYYY-MM-DD.")
        raise SystemExit(1)


def in_range(dt):
    if SINCE and dt < SINCE:
        return False
    if UNTIL and dt > UNTIL:
        return False
    return True


def pkg_base(name):
    """Remove arquitetura do nome: 'libc6:amd64' → 'libc6'."""
    return name.split(":")[0].strip()


SINCE = parse_date(args.since) if args.since else None
UNTIL = parse_date(args.until) if args.until else None

# ─────────────────────────────────────────────────────────────────────────────
# 1. Leitura do dpkg.log  (fonte principal — timestamp por pacote)
#
#    Formato de linha:
#    2026-02-10 14:05:33 upgrade libc6:amd64 2.39-0ubuntu8 2.39-0ubuntu8.7
#    └── DATA ──┘└─HORA─┘└─AÇÃO─┘└──PACOTE──┘└───V_ANTIGA──┘└────V_NOVA────┘
#
#    Campos:
#      [0] data        "2026-02-10"
#      [1] hora        "14:05:33"
#      [2] ação        "upgrade"
#      [3] pacote      "libc6:amd64"
#      [4] v_antiga    versão antes do upgrade
#      [5] v_nova      versão instalada
# ─────────────────────────────────────────────────────────────────────────────

DPKG_UPGRADE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"upgrade\s+(?P<pkg>\S+)\s+(?P<v_old>\S+)\s+(?P<v_new>\S+)"
)


def collect_dpkg_files(base):
    files = []
    for path in [base, base + ".1"] + sorted(
        glob.glob(base + ".*.gz"),
        key=lambda f: (
            int(re.search(r"\.(\d+)", f).group(1)) if re.search(r"\.(\d+)", f) else 99
        ),
    ):
        if os.path.exists(path):
            files.append(path)
    return files


# pkg_name → lista de dicts com info do upgrade
dpkg_records = defaultdict(list)

for path in collect_dpkg_files("/var/log/dpkg.log"):
    gz = path.endswith(".gz")
    try:
        with (gzip.open if gz else open)(path, "rt", errors="replace") as f:
            for line in f:
                m = DPKG_UPGRADE.match(line)
                if not m:
                    continue
                dt = datetime.strptime(m["date"], "%Y-%m-%d")
                if not in_range(dt):
                    continue
                pkg = pkg_base(m["pkg"])
                arch = m["pkg"].split(":")[1] if ":" in m["pkg"] else ""
                if args.pkg and args.pkg.lower() not in pkg.lower():
                    continue

                dpkg_records[pkg].append(
                    {
                        "date": m["date"],
                        "time": m["time"],
                        "v_old": m["v_old"],
                        "v_new": m["v_new"],
                        "arch": arch,
                        "changed": m["v_old"] != m["v_new"],
                        "source": os.path.basename(path),
                        "cmd": None,  # enriquecido depois
                    }
                )
    except (PermissionError, OSError):
        pass

# ─────────────────────────────────────────────────────────────────────────────
# 2. Leitura do apt/history.log  (fonte secundária — contexto do comando)
#
#    Formato de bloco:
#      Start-Date: 2026-02-10  14:05:44
#      Commandline: apt-get dist-upgrade
#      Upgrade: libc6:amd64 (2.39-0ubuntu8, 2.39-0ubuntu8.7), ...
#      End-Date: 2026-02-10  14:12:14
#
#    Cada entrada Upgrade: é uma lista de "pkg:arch (v_old, v_new)"
#    separados por vírgula+espaço. O bloco pode ter múltiplas linhas
#    de continuação (espaço no início).
# ─────────────────────────────────────────────────────────────────────────────

APT_DATE = re.compile(r"^Start-Date:\s+(?P<date>\d{4}-\d{2}-\d{2})")
APT_CMD = re.compile(r"^Commandline:\s+(?P<cmd>.+)")
APT_UPGRADE = re.compile(r"^Upgrade:\s+(?P<pkgs>.+)")
APT_PKG_ENTRY = re.compile(
    r"(?P<pkg>[^\s(,]+)\s*\((?P<v_old>[^,]+),\s*(?P<v_new>[^)]+)\)"
)

# session_date → { pkg_base: { v_old, v_new, cmd } }
history_index = {}  # (date, pkg) → cmd

if not args.no_enrich:
    for path in collect_dpkg_files("/var/log/apt/history.log"):
        gz = path.endswith(".gz")
        try:
            with (gzip.open if gz else open)(path, "rt", errors="replace") as f:
                cur_date = None
                cur_cmd = None
                in_upgrade = False
                upgrade_buf = ""

                for line in f:
                    line_s = line.rstrip("\n")

                    dm = APT_DATE.match(line_s)
                    if dm:
                        # Fecha buffer anterior se houver
                        if in_upgrade and upgrade_buf:
                            for em in APT_PKG_ENTRY.finditer(upgrade_buf):
                                key = (cur_date, pkg_base(em["pkg"]))
                                history_index[key] = cur_cmd or "apt"
                            upgrade_buf = ""
                        cur_date = dm["date"]
                        cur_cmd = None
                        in_upgrade = False
                        continue

                    cm = APT_CMD.match(line_s)
                    if cm:
                        # Extrai só o executável (basename), ex: "apt-get"
                        cmd_parts = cm["cmd"].strip().split()
                        cur_cmd = os.path.basename(cmd_parts[0]) if cmd_parts else "apt"
                        continue

                    um = APT_UPGRADE.match(line_s)
                    if um:
                        in_upgrade = True
                        upgrade_buf = um["pkgs"]
                        continue

                    # Linha de continuação do Upgrade:
                    if in_upgrade and line_s.startswith(" "):
                        upgrade_buf += " " + line_s.strip()
                        continue

                    # Fim do bloco de upgrade ao encontrar outra chave
                    if in_upgrade and not line_s.startswith(" ") and ":" in line_s:
                        for em in APT_PKG_ENTRY.finditer(upgrade_buf):
                            key = (cur_date, pkg_base(em["pkg"]))
                            history_index[key] = cur_cmd or "apt"
                        upgrade_buf = ""
                        in_upgrade = False

                # Fecha buffer final
                if in_upgrade and upgrade_buf:
                    for em in APT_PKG_ENTRY.finditer(upgrade_buf):
                        key = (cur_date, pkg_base(em["pkg"]))
                        history_index[key] = cur_cmd or "apt"

        except (PermissionError, OSError):
            pass

# Enriquece os registros dpkg com o comando apt
for pkg, records in dpkg_records.items():
    for rec in records:
        key = (rec["date"], pkg)
        if key in history_index:
            rec["cmd"] = history_index[key]

# ─────────────────────────────────────────────────────────────────────────────
# 3. Monta lista final de upgrades
#    Para cada pacote, guarda apenas o registro mais recente por data
#    (dpkg.log pode ter duplicatas quando um pacote passa por múltiplos
#    estágios de status no mesmo upgrade — ex: reinst durante dist-upgrade)
# ─────────────────────────────────────────────────────────────────────────────
seen = {}  # (pkg, date) → dict — mantém o mais recente por (pacote, data)
for pkg, records in dpkg_records.items():
    for rec in records:
        key = (pkg, rec["date"])
        # Prefere o registro com versão alterada; em caso de empate, último
        if key not in seen or (rec["changed"] and not seen[key]["changed"]):
            seen[key] = {**rec, "pkg": pkg}

all_upgrades = sorted(seen.values(), key=lambda x: (x["date"], x["time"]))

# Aplica filtro --real-only depois de consolidar
if args.real_only:
    all_upgrades = [u for u in all_upgrades if u["changed"]]

# Aplica --top
if args.top:
    all_upgrades = all_upgrades[: args.top]

# ─────────────────────────────────────────────────────────────────────────────
# 4. Relatório
# ─────────────────────────────────────────────────────────────────────────────
SEP = "═" * 70
SEP2 = "─" * 55

CMD_ICON = {
    "apt-get": "📦",
    "apt": "📦",
    "dpkg": "🔧",
    "unattended-upgrade": "🤖",
    "unattended-upgrades": "🤖",
}

print(SEP)
print("   PACOTES ATUALIZADOS — LOG DO GERENCIADOR DE PACOTES")
print(SEP)
print(f"  Fontes : /var/log/dpkg.log  +  /var/log/apt/history.log")
if args.since:
    print(f"  Desde  : {args.since}")
if args.until:
    print(f"  Até    : {args.until}")
if args.pkg:
    print(f"  Filtro : pacotes com '{args.pkg}'")
if args.real_only:
    print(f"  Modo   : só upgrades com versão alterada")
print(SEP)

if not all_upgrades:
    print("\n  Nenhum pacote encontrado com os filtros aplicados.\n")
    raise SystemExit(0)

# ── Tabela principal ──────────────────────────────────────────────
print(
    f"\n  {'DATA':<12} {'HORA':<9} {'PACOTE':<35} {'VERSÃO ANTERIOR':<22} {'VERSÃO NOVA':<22} {'CMD'}"
)
print(f"  {SEP2}")

n_real = 0
n_reinst = 0

for u in all_upgrades:
    changed = u["changed"]
    marker = "✦" if changed else "↺"
    cmd_str = u["cmd"] or "?"
    icon = CMD_ICON.get(cmd_str, "📦")

    if changed:
        n_real += 1
        # Destaca a parte que mudou na versão nova
        v_new_disp = u["v_new"]
    else:
        n_reinst += 1
        v_new_disp = u["v_new"] + " (=)"

    pkg_disp = (u["pkg"][:33] + "…") if len(u["pkg"]) > 34 else u["pkg"]

    print(
        f"  {marker} {u['date']:<11} {u['time']:<9} "
        f"{pkg_disp:<35} {u['v_old']:<22} {v_new_disp:<22} {icon} {cmd_str}"
    )

# ── Agrupado por data ─────────────────────────────────────────────
print(f"\n{SEP}")
print("  UPGRADES POR SESSÃO (DATA / COMANDO)")
print(SEP)

by_date = defaultdict(lambda: defaultdict(list))
for u in all_upgrades:
    cmd = u["cmd"] or "desconhecido"
    by_date[u["date"]][cmd].append(u)

for date in sorted(by_date):
    total_dia = sum(len(v) for v in by_date[date].values())
    print(f"\n  📅 {date}  —  {total_dia} pacote(s)")
    for cmd, pkgs in sorted(by_date[date].items()):
        icon = CMD_ICON.get(cmd, "📦")
        real = sum(1 for p in pkgs if p["changed"])
        print(
            f"     {icon} {cmd:<28} {len(pkgs):>4} upgrade(s)"
            f"  ({real} com versão alterada)"
        )
        # Lista os 5 primeiros pacotes da sessão
        for p in sorted(pkgs, key=lambda x: x["pkg"])[:5]:
            arrow = "→" if p["changed"] else "="
            print(f"        • {p['pkg']:<32} {p['v_old']} {arrow} {p['v_new']}")
        if len(pkgs) > 5:
            print(f"        … e mais {len(pkgs) - 5} pacote(s)")

# ── Totais ────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TOTAIS")
print(SEP)
print(f"  Total de upgrades registrados : {len(all_upgrades)}")
print(f"  ✦ Com versão alterada         : {n_real}")
print(f"  ↺ Reinstalações               : {n_reinst}")
print(f"  Sessões (datas) distintas     : {len(by_date)}")
print()
print("  Dica: para ver só os upgrades com versão alterada:")
print("    python3 ex20.py --real-only")
print("  Para filtrar por pacote:")
print("    python3 ex20.py --pkg libc6")
print("  Para um intervalo de datas:")
print("    python3 ex20.py --since 2026-02-18")
print(SEP)
