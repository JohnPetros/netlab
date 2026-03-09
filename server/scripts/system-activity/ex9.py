#!/usr/bin/env python3
"""
Exercício 9 - Serviços iniciados ou parados recentemente
Arquivos de log consultados:

  /var/log/syslog               — serviços integrados ao rsyslog
  /var/log/auth.log             — sshd (start/stop via signal)
  /var/log/apache2/error.log    — apache2 (start/stop via AH codes)

Cada serviço tem seu próprio formato de log e padrões de evento:

  sshd (auth.log):
    START : "Server listening on"
    STOP  : "Received signal 15; terminating"
             "Received signal 1; rereading configuration"  → RELOAD

  apache2 (error.log):
    START : AH00489 "configured -- resuming normal operations"
    STOP  : AH00491 "caught SIGTERM, shutting down"
    RELOAD: AH00494 "caught SIGWINCH, shutting down gracefully"

  Serviços genéricos (syslog):
    START : "Started <service>" / "start" / "Starting"
    STOP  : "Stopped <service>" / "stop"  / "Stopping"
"""

import re
import os
from collections import namedtuple

Event = namedtuple("Event", ["timestamp", "service", "action", "detail", "source"])

events = []

# ===================================================================
# FONTE 1 — /var/log/auth.log  (sshd)
# ===================================================================
AUTH_LOG = "/var/log/auth.log"

# sshd START: começa a escutar em uma porta
SSHD_START = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Server listening on (?P<detail>.+)"
)

# sshd STOP: recebeu sinal de encerramento (15 = SIGTERM)
SSHD_STOP = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Received signal 15;\s+terminating"
)

# sshd RELOAD: sinal 1 = SIGHUP (relê configuração)
SSHD_RELOAD = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+"
    r"Received signal 1;\s+rereading"
)

if os.path.exists(AUTH_LOG):
    with open(AUTH_LOG, "r", errors="replace") as f:
        for line in f:
            m = SSHD_START.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service="sshd",
                        action="INICIADO",
                        detail=f"escutando em {m.group('detail').strip()}",
                        source=AUTH_LOG,
                    )
                )
                continue

            m = SSHD_STOP.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service="sshd",
                        action="PARADO",
                        detail="recebeu SIGTERM",
                        source=AUTH_LOG,
                    )
                )
                continue

            m = SSHD_RELOAD.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service="sshd",
                        action="RECARREGADO",
                        detail="recebeu SIGHUP — relendo configuração",
                        source=AUTH_LOG,
                    )
                )

# ===================================================================
# FONTE 2 — /var/log/apache2/error.log  (apache2)
#
# Formato do timestamp: [Sun Mar 08 21:10:28.514287 2026]
# ===================================================================
APACHE_LOG = "/var/log/apache2/error.log"

# Extrai a parte legível do timestamp do apache
APACHE_TS = re.compile(
    r"\[(?:\w{3} )(?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2})\.\d+ \d{4}\]"
)

# AH00489 / AH00494: apache started / resumed
APACHE_START = re.compile(r"AH0048[94].*resuming normal operations")

# AH00491: apache caught SIGTERM → shutting down
APACHE_STOP = re.compile(r"AH00491.*caught SIGTERM")

# AH00493: caught SIGTERM gracefully (graceful stop)
APACHE_GRACEFUL = re.compile(r"AH00493.*graceful")

if os.path.exists(APACHE_LOG):
    with open(APACHE_LOG, "r", errors="replace") as f:
        for line in f:
            ts_match = APACHE_TS.search(line)
            ts = ts_match.group("ts") if ts_match else "data desconhecida"

            if APACHE_START.search(line):
                events.append(
                    Event(
                        timestamp=ts,
                        service="apache2",
                        action="INICIADO",
                        detail="servidor configurado e operacional",
                        source=APACHE_LOG,
                    )
                )
            elif APACHE_GRACEFUL.search(line):
                events.append(
                    Event(
                        timestamp=ts,
                        service="apache2",
                        action="PARADO",
                        detail="graceful stop (SIGTERM)",
                        source=APACHE_LOG,
                    )
                )
            elif APACHE_STOP.search(line):
                events.append(
                    Event(
                        timestamp=ts,
                        service="apache2",
                        action="PARADO",
                        detail="recebeu SIGTERM — encerrando",
                        source=APACHE_LOG,
                    )
                )

# ===================================================================
# FONTE 3 — /var/log/syslog  (serviços genéricos via rsyslog/systemd)
#
# Cobre qualquer serviço que escreva no syslog, como cron, rsyslogd,
# e serviços de terceiros.
# ===================================================================
SYSLOG = "/var/log/syslog"

# Serviços a ignorar no syslog para não duplicar o que já foi
# capturado nas fontes dedicadas acima
SYSLOG_IGNORE = re.compile(r"\b(sshd|apache2)\b", re.IGNORECASE)

# systemd: "Started <service>" / "Stopped <service>"
SYSTEMD_START = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*systemd.*Started\s+(?P<svc>.+)"
)
SYSTEMD_STOP = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*systemd.*Stopped\s+(?P<svc>.+)"
)

# rsyslogd start (capturado como serviço também)
RSYSLOG_START = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*rsyslogd.*\]\s+start"
)

if os.path.exists(SYSLOG):
    with open(SYSLOG, "r", errors="replace") as f:
        for line in f:
            if SYSLOG_IGNORE.search(line):
                continue

            m = RSYSLOG_START.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service="rsyslogd",
                        action="INICIADO",
                        detail="serviço de logging iniciado",
                        source=SYSLOG,
                    )
                )
                continue

            m = SYSTEMD_START.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service=m.group("svc").strip(),
                        action="INICIADO",
                        detail="via systemd",
                        source=SYSLOG,
                    )
                )
                continue

            m = SYSTEMD_STOP.search(line)
            if m:
                events.append(
                    Event(
                        timestamp=m.group("ts"),
                        service=m.group("svc").strip(),
                        action="PARADO",
                        detail="via systemd",
                        source=SYSLOG,
                    )
                )

# ===================================================================
# Relatório
# ===================================================================
SEP = "=" * 65
SEP2 = "-" * 50

ACTION_ICON = {
    "INICIADO": "▶",
    "PARADO": "■",
    "RECARREGADO": "↺",
}

print(SEP)
print("   ALTERAÇÕES DE STATUS DE SERVIÇOS")
print(SEP)

if not events:
    print("""
  Nenhum evento de serviço encontrado.

  Tente gerar eventos e rodar novamente:
    service apache2 restart
    service ssh restart
""")
    raise SystemExit(0)

# Agrupa por serviço para exibição organizada
from collections import defaultdict

by_service = defaultdict(list)
for e in events:
    by_service[e.service].append(e)

for service, svc_events in sorted(by_service.items()):
    print(f"\n  Serviço: {service.upper()}  ({len(svc_events)} evento(s))")
    print(SEP2)
    for e in svc_events:
        icon = ACTION_ICON.get(e.action, "•")
        print(f"  {icon} {e.action:<12}  {e.timestamp}")
        print(f"    Detalhe : {e.detail}")
        print(f"    Fonte   : {e.source}")

# Resumo
print(f"\n{SEP}")
print("  RESUMO")
print(SEP)
totals = {"INICIADO": 0, "PARADO": 0, "RECARREGADO": 0}
for e in events:
    if e.action in totals:
        totals[e.action] += 1

for action, count in totals.items():
    icon = ACTION_ICON[action]
    print(f"  {icon}  {action:<14} {count:>3} evento(s)")
print(f"  {'─' * 30}")
print(f"     {'TOTAL':<14} {len(events):>3}")
print(SEP)
