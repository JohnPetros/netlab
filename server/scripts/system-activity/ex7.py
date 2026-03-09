#!/usr/bin/env python3
"""
Exercício 7 - Eventos de desligamento (shutdown) e reinicialização
Arquivo de log: /var/log/syslog

Em um Linux real (bare metal ou VM), o sistema registra eventos de
encerramento e reinicialização no syslog via systemd ou sysvinit.

Exemplos de linhas reais geradas no shutdown/reboot:

  Shutdown iniciado pelo usuário:
    Mar  8 21:00:01 host systemd[1]: Starting Halt...
    Mar  8 21:00:01 host systemd[1]: Reached target Shutdown.
    Mar  8 21:00:02 host systemd[1]: Shutting down.

  Reboot iniciado pelo usuário:
    Mar  8 21:00:01 host systemd[1]: Starting Reboot...
    Mar  8 21:00:01 host systemd[1]: Reached target Reboot.

  Kernel registrando o encerramento:
    Mar  8 21:00:03 host kernel: reboot: Power down
    Mar  8 21:00:03 host kernel: reboot: Restarting system

  shutdown via comando shutdown/halt/reboot:
    Mar  8 21:00:00 host shutdown[1234]: shutting down for system halt
    Mar  8 21:00:00 host shutdown[1234]: shutting down for system reboot

  sysvinit (sistemas mais antigos sem systemd):
    Mar  8 21:00:00 host init: Switching to runlevel: 0
    Mar  8 21:00:00 host init: Switching to runlevel: 6

Estratégia:
  - Varre o syslog linha a linha
  - Aplica múltiplos padrões para cobrir systemd, kernel e sysvinit
  - Classifica cada evento como SHUTDOWN ou REBOOT
  - Lista em ordem cronológica com timestamp e origem
"""

import re
from collections import namedtuple

LOG_FILE = "/var/log/syslog"

# -------------------------------------------------------------------
# Evento encontrado
# -------------------------------------------------------------------
Event = namedtuple("Event", ["timestamp", "kind", "source", "raw"])

# -------------------------------------------------------------------
# Padrões Regex — cada entrada tem:
#   pattern : regex compilado
#   kind    : "SHUTDOWN" ou "REBOOT"
#   source  : descrição da origem do evento
# -------------------------------------------------------------------
PATTERNS = [
    # --- systemd: targets de encerramento ---
    {
        "pattern": re.compile(r"systemd.*Reached target.*Shutdown", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "systemd (target Shutdown)",
    },
    {
        "pattern": re.compile(r"systemd.*Reached target.*Reboot", re.IGNORECASE),
        "kind": "REBOOT",
        "source": "systemd (target Reboot)",
    },
    {
        "pattern": re.compile(r"systemd.*Reached target.*Halt", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "systemd (target Halt)",
    },
    # --- systemd: mensagens de ação ---
    {
        "pattern": re.compile(r"systemd.*Starting.*Halt\b", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "systemd (Starting Halt)",
    },
    {
        "pattern": re.compile(r"systemd.*Starting.*Reboot\b", re.IGNORECASE),
        "kind": "REBOOT",
        "source": "systemd (Starting Reboot)",
    },
    {
        "pattern": re.compile(r"systemd.*Shutting down\b", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "systemd (Shutting down)",
    },
    # --- kernel: mensagem final antes do hardware desligar ---
    {
        "pattern": re.compile(r"kernel.*reboot:\s+Power down", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "kernel (Power down)",
    },
    {
        "pattern": re.compile(r"kernel.*reboot:\s+Restarting system", re.IGNORECASE),
        "kind": "REBOOT",
        "source": "kernel (Restarting system)",
    },
    # --- comando shutdown/halt/reboot ---
    {
        "pattern": re.compile(r"shutdown\[\d+\].*system halt", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "comando shutdown (halt)",
    },
    {
        "pattern": re.compile(r"shutdown\[\d+\].*system reboot", re.IGNORECASE),
        "kind": "REBOOT",
        "source": "comando shutdown (reboot)",
    },
    # --- sysvinit: runlevel 0 = halt, 6 = reboot ---
    {
        "pattern": re.compile(r"init.*Switching to runlevel:\s*0\b", re.IGNORECASE),
        "kind": "SHUTDOWN",
        "source": "sysvinit (runlevel 0)",
    },
    {
        "pattern": re.compile(r"init.*Switching to runlevel:\s*6\b", re.IGNORECASE),
        "kind": "REBOOT",
        "source": "sysvinit (runlevel 6)",
    },
]

# -------------------------------------------------------------------
# Leitura do log
# -------------------------------------------------------------------
events = []

try:
    with open(LOG_FILE, "r", errors="replace") as f:
        for line in f:
            timestamp = line[:15].strip()

            for p in PATTERNS:
                if p["pattern"].search(line):
                    events.append(
                        Event(
                            timestamp=timestamp,
                            kind=p["kind"],
                            source=p["source"],
                            raw=line.strip(),
                        )
                    )
                    # Uma linha pode casar com vários padrões do mesmo evento
                    # (ex: "Reached target Shutdown" e "Shutting down" são
                    # linhas separadas do mesmo shutdown). Não usamos break
                    # para capturar todas as linhas relevantes.

except FileNotFoundError:
    print(f"[ERRO] {LOG_FILE} não encontrado.")
    raise SystemExit(1)

except PermissionError:
    print(f"[ERRO] Sem permissão para ler {LOG_FILE}.")
    raise SystemExit(1)

SEP = "=" * 65
SEP2 = "-" * 50

print(SEP)
print("   EVENTOS DE DESLIGAMENTO E REINICIALIZAÇÃO DO SISTEMA")
print(SEP)

if not events:
    print("""
  Nenhum evento encontrado em /var/log/syslog.

  Possíveis causas:
    • O sistema ainda não foi desligado ou reiniciado desde que
      o syslog começou a ser gravado
    • O syslog foi rotacionado (verifique /var/log/syslog.1
      ou /var/log/syslog.*.gz para logs anteriores)
    • O sistema usa journald sem encaminhar para syslog
      (consulte: journalctl --list-boots)

  Padrões buscados: systemd targets, kernel reboot, shutdown(8),
  sysvinit runlevels 0 e 6.
""")
    raise SystemExit(0)

# Contadores
total_shutdown = sum(1 for e in events if e.kind == "SHUTDOWN")
total_reboot = sum(1 for e in events if e.kind == "REBOOT")

for e in events:
    icon = "⏻ " if e.kind == "SHUTDOWN" else "↺ "
    print(f"\n{icon} {e.kind}")
    print(f"   Timestamp : {e.timestamp}")
    print(f"   Origem    : {e.source}")
    print(f"   Log       : {e.raw}")

print(f"\n{SEP}")
print("  RESUMO")
print(SEP)
print(f"  Total de eventos    : {len(events)}")
print(f"  ⏻  Desligamentos    : {total_shutdown}")
print(f"  ↺  Reinicializações : {total_reboot}")
print()
print("  Dica: para logs anteriores ao syslog atual, use:")
print("    zcat /var/log/syslog.*.gz | grep -Ei 'shutdown|reboot|halt'")
print(SEP)
