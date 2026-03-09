#!/usr/bin/env python3
"""
Exercício 6 - Data e hora do último boot do sistema
Arquivo de log: /var/log/syslog

Em ambientes Docker, o kernel não é inicializado pelo container —
ele é compartilhado com o host. Por isso, linhas como
"kernel: Booting Linux" nunca aparecem no syslog do container.

O equivalente ao "boot" dentro de um container é o momento em que
o rsyslog é iniciado, registrado como:

  Mar  8 20:14:25 server rsyslogd: [origin ...] start

Essa é a primeira e mais antiga entrada confiável de tempo no syslog
do container, equivalente ao momento em que ele foi iniciado.

Complemento: /proc/uptime fornece o uptime do HOST (não do container),
mas ainda é útil como referência de tempo em atividade.
"""

import re
import os

LOG_FILE = "/var/log/syslog"

# -------------------------------------------------------------------
# Padrão Regex
#
# Busca a linha de inicialização do rsyslogd:
#   Mar  8 20:14:25 server rsyslogd: [origin software="rsyslogd" ...] start
#
# Grupo capturado:
#   - timestamp : "Mar  8 20:14:25"
# -------------------------------------------------------------------
BOOT_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    r".*rsyslogd.*\]\s+start"
)

# -------------------------------------------------------------------
# Varre o syslog guardando SEMPRE a última ocorrência —
# se o container foi reiniciado várias vezes, pega o boot mais recente
# -------------------------------------------------------------------
last_boot_line = None

try:
    with open(LOG_FILE, "r", errors="replace") as f:
        for line in f:
            if BOOT_PATTERN.search(line):
                last_boot_line = line.strip()

except FileNotFoundError:
    print(f"[ERRO] {LOG_FILE} não encontrado.")
    print("       Verifique se o rsyslog está ativo: rsyslogd")
    raise SystemExit(1)

except PermissionError:
    print(f"[ERRO] Sem permissão para ler {LOG_FILE}.")
    print("       Tente executar com: sudo python3 ex6.py")
    raise SystemExit(1)

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 55

print(SEP)
print("   ÚLTIMO BOOT DO CONTAINER")
print(SEP)

if not last_boot_line:
    print("\n  Nenhuma entrada de inicialização encontrada.")
    print(f"  Verifique o conteúdo de {LOG_FILE}.")
    print(f"\n{SEP}")
    raise SystemExit(1)

# Extrai o timestamp do início da linha
boot_ts = last_boot_line[:15].strip()

print(f"\n  Data/hora do boot  : {boot_ts}")
print(f"  Fonte              : {LOG_FILE}  (rsyslogd start)")
print(f"\n  Linha original:")
print(f"  {last_boot_line}")

# -------------------------------------------------------------------
# Uptime via /proc/uptime
#
# Atenção: em containers Docker, /proc/uptime reflete o uptime do
# HOST, não do container. É informativo mas não representa o tempo
# exato que o container está rodando.
# -------------------------------------------------------------------
print(f"\n  Uptime do host (via /proc/uptime):")
try:
    with open("/proc/uptime", "r") as f:
        uptime_seconds = float(f.read().split()[0])

    days = int(uptime_seconds // 86400)
    hours = int((uptime_seconds % 86400) // 3600)
    minutes = int((uptime_seconds % 3600) // 60)
    seconds = int(uptime_seconds % 60)

    print(f"    {days}d {hours:02d}h {minutes:02d}m {seconds:02d}s")
    print(f"    ({int(uptime_seconds):,} segundos no total)")
    print(f"\n  ⚠  Em containers Docker, /proc/uptime reflete o")
    print(f"     uptime do host, não do container.")

except FileNotFoundError:
    print("    /proc/uptime não disponível.")

print(f"\n{SEP}")
