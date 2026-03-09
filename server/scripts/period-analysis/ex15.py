#!/usr/bin/env python3
"""
Exercício 15 - Filtrar log por janela de tempo (ex: 14h-15h de um dia)
Arquivo de log escolhido: /var/log/dpkg.log

Justificativa da escolha:
  O dpkg.log foi escolhido por:
    1. Ter o formato de timestamp mais preciso: "2026-02-10 14:05:33"
       (data completa + hora + minuto + segundo), ideal para filtro temporal
    2. Possuir eventos reais e densos nos períodos disponíveis
    3. Ser compreensível — cada linha tem uma ação clara (install, configure...)

Formato das linhas:
  2026-02-10 14:05:33 install base-passwd:amd64 <none> 3.6.3build1
  2026-02-10 14:05:33 status  half-installed base-passwd:amd64 3.6.3build1
  │          │        │
  data       hora     ação

Uso:
  python3 ex15.py                         # padrão: 2026-02-10, 14h-15h
  python3 ex15.py --date 2026-02-18       # outro dia
  python3 ex15.py --start 19 --end 20     # outro intervalo de horas
  python3 ex15.py --date 2026-02-18 --start 19 --end 20
  python3 ex15.py --log /var/log/syslog   # outro arquivo
"""

import re
import os
import argparse
import gzip
import glob
from datetime import datetime
from collections import Counter, defaultdict

# -------------------------------------------------------------------
# Argumentos de linha de comando
# -------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Filtra eventos de um log em uma janela de tempo específica."
)
parser.add_argument(
    "--log",
    default="/var/log/dpkg.log",
    help="Caminho do arquivo de log (padrão: /var/log/dpkg.log)",
)
parser.add_argument(
    "--date",
    default="2026-02-10",
    help="Data no formato YYYY-MM-DD (padrão: 2026-02-10)",
)
parser.add_argument(
    "--start", type=int, default=14, help="Hora inicial da janela, 0-23 (padrão: 14)"
)
parser.add_argument(
    "--end",
    type=int,
    default=15,
    help="Hora final da janela, exclusiva, 0-23 (padrão: 15)",
)
parser.add_argument(
    "--action",
    default=None,
    help="Filtra por ação específica: install, configure, status, upgrade, remove, purge",
)
parser.add_argument(
    "--show-all",
    action="store_true",
    help="Exibe todas as linhas (incluindo status intermediários)",
)
args = parser.parse_args()

# Valida argumentos
if args.start < 0 or args.start > 23 or args.end < 0 or args.end > 24:
    print("[ERRO] Horas devem estar entre 0 e 23.")
    raise SystemExit(1)
if args.start >= args.end:
    print("[ERRO] --start deve ser menor que --end.")
    raise SystemExit(1)

try:
    target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
except ValueError:
    print(f"[ERRO] Data inválida: '{args.date}'. Use o formato YYYY-MM-DD.")
    raise SystemExit(1)

LOG_FILE = args.log

# -------------------------------------------------------------------
# Regex para timestamp do dpkg.log e syslog
#
# dpkg.log  : "2026-02-10 14:05:33"  → formato ISO
# syslog    : "Feb 10 14:05:33"      → formato BSD
# kern.log  : mesma que syslog
# -------------------------------------------------------------------
ISO_TS = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
BSD_TS = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})")

CURRENT_YEAR = datetime.now().year
MONTHS = {
    m: i
    for i, m in enumerate(
        [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ],
        1,
    )
}


def parse_line_dt(line):
    """Extrai datetime da linha. Suporta formato ISO (dpkg) e BSD (syslog)."""
    m = ISO_TS.match(line)
    if m:
        try:
            return datetime.strptime(
                f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None

    m = BSD_TS.match(line)
    if m:
        try:
            month = MONTHS.get(m.group("month"), 0)
            day = int(m.group("day"))
            t = m.group("time")
            dt = datetime.strptime(
                f"{CURRENT_YEAR}-{month:02d}-{day:02d} {t}", "%Y-%m-%d %H:%M:%S"
            )
            if dt.date() > datetime.now().date():
                dt = dt.replace(year=CURRENT_YEAR - 1)
            return dt
        except (ValueError, KeyError):
            return None

    return None


# -------------------------------------------------------------------
# Ícones e rótulos por ação (dpkg.log)
# -------------------------------------------------------------------
ACTION_STYLE = {
    "install": ("▶", "INSTALAR  "),
    "upgrade": ("⬆", "ATUALIZAR "),
    "remove": ("🗑", "REMOVER   "),
    "purge": ("💣", "PURGAR    "),
    "configure": ("⚙", "CONFIGURAR"),
    "trigproc": ("⚡", "TRIGGER   "),
    "startup": ("🚀", "STARTUP   "),
    "status": ("·", "STATUS    "),
}


def style_line(line):
    """Retorna (icon, label, resto) para uma linha do dpkg.log."""
    parts = line.split()
    # Formato: "2026-02-10 14:05:33 <action> <rest>"
    # Após o timestamp de 2 tokens, o 3º é a ação
    if len(parts) >= 3:
        action = parts[2].lower()
        icon, label = ACTION_STYLE.get(action, ("•", f"{action:<10}"))
        rest = " ".join(parts[3:])
        return icon, label, rest
    return "•", "          ", line.strip()


# -------------------------------------------------------------------
# Leitura e filtragem
# -------------------------------------------------------------------
# Descobre se precisa de arquivo rotacionado também
def get_files(base):
    files = []
    if os.path.exists(base):
        files.append((base, False))
    for gz in sorted(
        glob.glob(base + ".*.gz"),
        key=lambda f: (
            int(re.search(r"\.(\d+)", f).group(1)) if re.search(r"\.(\d+)", f) else 999
        ),
    ):
        files.append((gz, True))
    rotated = base + ".1"
    if os.path.exists(rotated) and (rotated, False) not in files:
        files.insert(1, (rotated, False))
    return files


matched_lines = []
total_scanned = 0

for path, is_gz in get_files(LOG_FILE):
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue

                total_scanned += 1
                dt = parse_line_dt(line)
                if dt is None:
                    continue

                # Filtra data e janela de hora
                if dt.date() != target_date:
                    continue
                if not (args.start <= dt.hour < args.end):
                    continue

                # Filtra por ação se especificado
                if args.action:
                    parts = line.split()
                    if len(parts) < 3 or parts[2].lower() != args.action.lower():
                        continue

                # Oculta linhas de "status" intermediário por padrão
                if not args.show_all:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].lower() == "status":
                        continue

                matched_lines.append((dt, line))

    except (FileNotFoundError, PermissionError) as e:
        print(f"[aviso] {path}: {e}")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 65
SEP2 = "-" * 50

start_label = f"{args.start:02d}:00"
end_label = f"{args.end:02d}:00"

print(SEP)
print("   FILTRO TEMPORAL DE LOG")
print(SEP)
print(f"  Arquivo  : {LOG_FILE}")
print(f"  Data     : {target_date}  ({target_date.strftime('%A')})")
print(f"  Janela   : {start_label} → {end_label}")
if args.action:
    print(f"  Ação     : {args.action}")
print(f"  Linhas lidas: {total_scanned:,}")
print(SEP)

if not matched_lines:
    print(f"""
  Nenhum evento encontrado para os critérios:
    Data   : {target_date}
    Janela : {start_label} → {end_label}

  Datas disponíveis no log:
    Rode sem filtros para ver as datas existentes.
    Ou use: grep -oP '\\d{{4}}-\\d{{2}}-\\d{{2}}' {LOG_FILE} | sort -u
""")
    raise SystemExit(0)

# Agrupa por minuto para mostrar densidade
by_minute = Counter()
by_action = Counter()
for dt, line in matched_lines:
    by_minute[dt.strftime("%H:%M")] += 1
    parts = line.split()
    if len(parts) >= 3:
        by_action[parts[2].lower()] += 1

# Listagem dos eventos
print(f"\n  {len(matched_lines)} evento(s) encontrado(s)\n")

prev_minute = None
for dt, line in matched_lines:
    minute = dt.strftime("%H:%M")

    # Separador visual a cada mudança de minuto
    if minute != prev_minute:
        print(f"\n  ── {minute} ──────────────────────────────────────")
        prev_minute = minute

    icon, label, rest = style_line(line)
    time_str = dt.strftime("%H:%M:%S")
    print(f"  {icon} {time_str}  {label}  {rest[:55]}")

# Resumo por ação
print(f"\n{SEP}")
print("  RESUMO DO PERÍODO")
print(SEP)
print(f"\n  {'AÇÃO':<15} {'QTDE':>6}  PROPORÇÃO")
print(f"  {'─' * 45}")
for action, count in sorted(by_action.items(), key=lambda x: -x[1]):
    icon, label, _ = style_line(f"0000-00-00 00:00:00 {action} x")
    pct = count / len(matched_lines) * 100
    bar = "█" * int(pct / 3)
    print(f"  {icon} {action:<13} {count:>6}  {bar:<30} {pct:.1f}%")

print(f"\n  {'─' * 45}")
print(f"  {'TOTAL':<15} {len(matched_lines):>6}")

# Heatmap por minuto
print(f"\n  DENSIDADE POR MINUTO  ({start_label} → {end_label})")
print(f"  {'─' * 45}")
for minute in sorted(by_minute.keys()):
    count = by_minute[minute]
    bar = "▓" * min(count, 40)
    print(f"  {minute}  {bar} {count}")

print(f"\n{SEP}")
print("  Dica: para refinar o filtro:")
print(f"    python3 ex15.py --date {target_date} --start 14 --end 15 --action install")
print(f"    python3 ex15.py --date {target_date} --start 14 --end 15 --show-all")
print(SEP)
