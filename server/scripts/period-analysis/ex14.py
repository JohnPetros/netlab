#!/usr/bin/env python3
"""
Exercício 14 - Tempo de atividade do sistema
Fontes consultadas (em ordem de riqueza):

  1. /proc/uptime          — uptime atual em segundos desde o boot (sempre disponível)
  2. uptime -s             — data/hora exata do boot atual
  3. /var/log/syslog       — histórico de boots (rsyslogd: start) e
  /var/log/syslog.N.gz       shutdowns (systemd Stopping/Stopped)
  4. /var/log/kern.log     — histórico de boots (Linux version)
  /var/log/kern.log.N.gz
  5. journalctl --list-boots — histórico completo se systemd disponível

Estratégia para calcular uptime:
  - Boot atual  : uptime -s  → data/hora precisa
  - Uptime atual: /proc/uptime → segundos, convertido para d/h/m/s
  - Shutdown     : buscado nos logs como evento anterior ao boot

  Se o sistema ainda não foi desligado desde o boot atual,
  o uptime é calculado como: agora - boot_time.

Limitações no WSL / containers:
  - wtmp pode estar vazio (sem registro de runlevel/shutdown)
  - syslog pode não ter eventos de boot/shutdown anteriores
  - journald pode estar desabilitado
  O script informa explicitamente quando uma fonte está indisponível.
"""

import re
import os
import gzip
import glob
import subprocess
from datetime import datetime, timedelta
from collections import namedtuple

BootEvent = namedtuple("BootEvent", ["timestamp", "source", "kind"])


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def run(cmd):
    """Executa um comando e retorna stdout ou None em caso de erro."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def fmt_duration(seconds):
    """Formata segundos em string legível."""
    seconds = int(seconds)
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours:02d}h")
    if minutes:
        parts.append(f"{minutes:02d}m")
    parts.append(f"{secs:02d}s")
    return " ".join(parts)


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "—"


# -------------------------------------------------------------------
# FONTE 1 — /proc/uptime
# Formato: "760.32 0.00"  (segundos ativo, segundos idle)
# -------------------------------------------------------------------
uptime_seconds = None
try:
    with open("/proc/uptime") as f:
        uptime_seconds = float(f.read().split()[0])
except Exception:
    pass

# -------------------------------------------------------------------
# FONTE 2 — uptime -s
# Retorna: "2026-03-08 21:18:09"
# -------------------------------------------------------------------
boot_time = None
boot_source = None

uptime_s = run(["uptime", "-s"])
if uptime_s:
    try:
        boot_time = datetime.strptime(uptime_s, "%Y-%m-%d %H:%M:%S")
        boot_source = "uptime -s"
    except ValueError:
        pass

# -------------------------------------------------------------------
# FONTE 3 — logs históricos
# Busca padrões de boot e shutdown em syslog e kern.log (+ rotacionados)
# -------------------------------------------------------------------
BOOT_PATTERNS = [
    # rsyslogd: start → primeiro log após o boot
    re.compile(r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*rsyslogd.*\]\s+start"),
    # kernel: Linux version → boot real (máquinas físicas/VMs)
    re.compile(r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*kernel.*Linux version"),
    # systemd: Reached target → indica boot concluído
    re.compile(
        r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*systemd.*"
        r"Reached target.*(?:Basic System|Network)"
    ),
]

SHUTDOWN_PATTERNS = [
    # systemd: shutdown targets
    re.compile(
        r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*systemd.*"
        r"(?:Reached target.*Shutdown|Shutting down|Starting Halt|Starting Reboot)"
    ),
    # kernel: power down / restarting
    re.compile(
        r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*kernel.*"
        r"reboot:\s+(?:Power down|Restarting system)"
    ),
    # rsyslogd exiting
    re.compile(r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*rsyslogd.*exiting"),
]

# Ano atual para completar o timestamp (syslog não inclui ano)
CURRENT_YEAR = datetime.now().year


def parse_syslog_ts(ts_str):
    """Converte 'Mar  8 21:18:09' em datetime, assumindo ano atual."""
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
        # Se a data ficou no futuro, provavelmente é do ano anterior
        if dt > datetime.now() + timedelta(days=1):
            dt = dt.replace(year=CURRENT_YEAR - 1)
        return dt
    except ValueError:
        return None


historical_events = []

LOG_CANDIDATES = []
for base in ["/var/log/syslog", "/var/log/kern.log"]:
    if os.path.exists(base):
        LOG_CANDIDATES.append((base, False))
    for gz in sorted(
        glob.glob(base + ".*.gz"),
        key=lambda f: (
            int(re.search(r"\.(\d+)", f).group(1)) if re.search(r"\.(\d+)", f) else 999
        ),
    ):
        LOG_CANDIDATES.append((gz, True))
    rotated = base + ".1"
    if os.path.exists(rotated):
        LOG_CANDIDATES.insert(1, (rotated, False))

for path, is_gz in LOG_CANDIDATES:
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                ts_str = line[:15].strip()

                for pat in BOOT_PATTERNS:
                    m = pat.search(line)
                    if m:
                        dt = parse_syslog_ts(ts_str)
                        if dt:
                            historical_events.append(
                                BootEvent(dt, os.path.basename(path), "boot")
                            )
                        break
                else:
                    for pat in SHUTDOWN_PATTERNS:
                        m = pat.search(line)
                        if m:
                            dt = parse_syslog_ts(ts_str)
                            if dt:
                                historical_events.append(
                                    BootEvent(dt, os.path.basename(path), "shutdown")
                                )
                            break
    except (PermissionError, FileNotFoundError):
        pass

# Ordena por timestamp
historical_events.sort(key=lambda e: e.timestamp)

# -------------------------------------------------------------------
# FONTE 4 — journalctl --list-boots
# -------------------------------------------------------------------
journal_boots = []
jctl = run(["journalctl", "--list-boots", "--no-pager"])
if jctl:
    # Formato: " -1 <id>  Mon YYYY-MM-DD HH:MM:SS ...  Mon YYYY-MM-DD HH:MM:SS"
    for line in jctl.splitlines():
        parts = line.split()
        if len(parts) >= 7:
            try:
                # Boot start: posições 2-3 (data hora)
                boot_dt = datetime.strptime(
                    f"{parts[2]} {parts[3]}", "%Y-%m-%d %H:%M:%S"
                )
                journal_boots.append(boot_dt)
            except (ValueError, IndexError):
                pass

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 60
SEP2 = "-" * 48
now = datetime.now()

print(SEP)
print("   TEMPO DE ATIVIDADE DO SISTEMA")
print(SEP)

# ------- Boot e uptime atual ------------------------------------
print("\n📌  SESSÃO ATUAL")
print(SEP2)

if boot_time:
    duration = now - boot_time
    print(f"  Boot em         : {fmt_dt(boot_time)}  ({boot_source})")
    print(f"  Agora           : {fmt_dt(now)}")
    print(f"  Uptime calculado: {fmt_duration(duration.total_seconds())}")
elif uptime_seconds:
    boot_estimated = now - timedelta(seconds=uptime_seconds)
    print(f"  Boot estimado   : {fmt_dt(boot_estimated)}  (via /proc/uptime)")
    print(f"  Agora           : {fmt_dt(now)}")

if uptime_seconds:
    print(f"\n  /proc/uptime    : {fmt_duration(uptime_seconds)}")
    print(f"  ({int(uptime_seconds):,} segundos no total)")

# ------- Histórico de boots/shutdowns dos logs ------------------
print(f"\n📋  HISTÓRICO NOS LOGS")
print(SEP2)

if not historical_events:
    print("""
  Nenhum evento de boot/shutdown encontrado nos logs.

  Causas possíveis:
    • Logs ainda não registraram eventos de boot anteriores
    • rsyslog não estava ativo durante boots anteriores
    • Sistema WSL — kernel é compartilhado com o host Windows,
      boots do WSL não geram linha "Linux version" no kern.log

  Fontes verificadas:
    /var/log/syslog, /var/log/kern.log (e rotacionados)""")
else:
    # Emparelha boots com shutdowns para calcular uptime de cada sessão
    print(f"\n  {'TIPO':<10} {'TIMESTAMP':<22} {'DURAÇÃO DA SESSÃO':<20} FONTE")
    print(f"  {'─' * 8}  {'─' * 20}  {'─' * 18}  {'─' * 15}")

    prev_boot = None
    for ev in historical_events:
        icon = "▶" if ev.kind == "boot" else "■"
        kind = "BOOT    " if ev.kind == "boot" else "SHUTDOWN"

        if ev.kind == "boot":
            duration_str = "—"
            prev_boot = ev.timestamp
        else:
            if prev_boot:
                delta = ev.timestamp - prev_boot
                duration_str = fmt_duration(delta.total_seconds())
            else:
                duration_str = "boot anterior desconhecido"

        print(
            f"  {icon} {kind}  {fmt_dt(ev.timestamp)}  {duration_str:<20}  {ev.source}"
        )

# ------- journalctl ---------------------------------------------
if journal_boots:
    print(f"\n📓  HISTÓRICO VIA JOURNALD  ({len(journal_boots)} boot(s))")
    print(SEP2)
    for i, bt in enumerate(journal_boots, 1):
        print(f"  Boot #{i}: {fmt_dt(bt)}")

# ------- Resumo -------------------------------------------------
print(f"\n{SEP}")
print("  RESUMO")
print(SEP)

if boot_time and uptime_seconds:
    print(f"  Sistema ativo desde : {fmt_dt(boot_time)}")
    print(f"  Uptime atual        : {fmt_duration(uptime_seconds)}")

n_boots = sum(1 for e in historical_events if e.kind == "boot")
n_shutdowns = sum(1 for e in historical_events if e.kind == "shutdown")
if historical_events:
    print(f"  Boots encontrados   : {n_boots}")
    print(f"  Shutdowns encontrados: {n_shutdowns}")

print(SEP)
print()
print("  Dicas:")
print("    uptime -s          # data/hora do boot atual")
print("    uptime -p          # uptime em formato legível")
print("    last reboot        # histórico de reboots (via wtmp)")
print("    journalctl -b      # logs do boot atual")
print("    journalctl --list-boots  # todos os boots registrados")
print(SEP)
