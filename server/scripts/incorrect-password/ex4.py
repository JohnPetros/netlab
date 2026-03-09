#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

# -------------------------------------------------------------------
# Padrões Regex
#
# Linha de SUCESSO — contém os campos TTY, PWD, USER e COMMAND,
# mas NÃ O contém as palavras "incorrect" nem "NOT in sudoers".
#
#   sudo: <origin>  : TTY=... ; PWD=... ; USER=<target> ; COMMAND=<cmd>
#
# Linha de FALHA POR SENHA — contém "incorrect password attempts"
#
#   sudo: <origin> : N incorrect password attempts ; ... ; COMMAND=<cmd>
#
# Linha de FALHA POR PERMISSÃO — contém "NOT in sudoers"
#
#   sudo: <origin> : user NOT in sudoers ; ... ; COMMAND=<cmd>
# -------------------------------------------------------------------

# Sucesso: captura origin, target (USER=) e command (COMMAND=)
SUCCESS_PATTERN = re.compile(
    r"sudo:\s+(?P<origin>\S+)\s+:(?!.*(?:incorrect|NOT in sudoers))"
    r".*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)

# Falha por senha incorreta: captura origin, número de tentativas e command
FAILED_PASSWORD_PATTERN = re.compile(
    r"sudo:\s+(?P<origin>\S+)\s+:.*?(?P<attempts>\d+)\s+incorrect password attempts"
    r".*COMMAND=(?P<command>.+)"
)

# Falha por ausência no sudoers: captura origin e command
NOT_IN_SUDOERS_PATTERN = re.compile(
    r"sudo:\s+(?P<origin>\S+)\s+:.*NOT in sudoers.*COMMAND=(?P<command>.+)"
)

# -------------------------------------------------------------------
# Estrutura de dados
#
# { origin_user: {
#     "success":     [ {"timestamp", "target", "command"}, ... ],
#     "wrong_pass":  [ {"timestamp", "attempts", "command"}, ... ],
#     "not_sudoers": [ {"timestamp", "command"}, ... ]
#   }
# }
# -------------------------------------------------------------------
sudo_events = defaultdict(
    lambda: {
        "success": [],
        "wrong_pass": [],
        "not_sudoers": [],
    }
)

try:
    with open(LOG_FILE, "r") as log:
        for line in log:
            # Ignora linhas que não mencionam sudo
            if "sudo:" not in line:
                continue

            # Extrai timestamp — primeiros 15 caracteres: "Mon DD HH:MM:SS"
            timestamp = line[:15].strip()

            # --- Falha: NOT in sudoers ---
            # Testada primeiro para evitar falso-positivo no SUCCESS_PATTERN
            ns_match = NOT_IN_SUDOERS_PATTERN.search(line)
            if ns_match:
                origin = ns_match.group("origin")
                command = ns_match.group("command").strip()
                sudo_events[origin]["not_sudoers"].append(
                    {
                        "timestamp": timestamp,
                        "command": command,
                    }
                )
                continue

            # --- Falha: senha incorreta ---
            fp_match = FAILED_PASSWORD_PATTERN.search(line)
            if fp_match:
                origin = fp_match.group("origin")
                attempts = fp_match.group("attempts")
                command = fp_match.group("command").strip()
                sudo_events[origin]["wrong_pass"].append(
                    {
                        "timestamp": timestamp,
                        "attempts": attempts,
                        "command": command,
                    }
                )
                continue

            # --- Sucesso ---
            s_match = SUCCESS_PATTERN.search(line)
            if s_match:
                origin = s_match.group("origin")
                target = s_match.group("target")
                command = s_match.group("command").strip()
                sudo_events[origin]["success"].append(
                    {
                        "timestamp": timestamp,
                        "target": target,
                        "command": command,
                    }
                )

except FileNotFoundError:
    print(f"[ERRO] Arquivo não encontrado: {LOG_FILE}")
    print("       Execute o script dentro do container ubuntu-server.")
    raise SystemExit(1)

if not sudo_events:
    print("Nenhum evento de 'sudo' encontrado em", LOG_FILE)
    raise SystemExit(0)

SEP = "=" * 65
SEP2 = "-" * 55

print(SEP)
print("        AUDITORIA DE USO DO COMANDO sudo")
print(SEP)

total_success = 0
total_wrong_pass = 0
total_not_sudoers = 0

for origin, events in sorted(sudo_events.items()):
    s = len(events["success"])
    wp = len(events["wrong_pass"])
    ns = len(events["not_sudoers"])
    total = s + wp + ns

    total_success += s
    total_wrong_pass += wp
    total_not_sudoers += ns

    print(f"\nUsuário : {origin}   (eventos: {total})")
    print(SEP2)

    # Execuções bem-sucedidas
    if events["success"]:
        print(f"  ✔  Comandos executados com sucesso ({s}):")
        for e in events["success"]:
            print(f"       {e['timestamp']}  como '{e['target']}'")
            print(f"       CMD: {e['command']}")

    # Falhas por senha
    if events["wrong_pass"]:
        print(f"  ✘  Falhas por senha incorreta ({wp}):")
        for e in events["wrong_pass"]:
            print(f"       {e['timestamp']}  [{e['attempts']}x tentativa(s)]")
            print(f"       CMD: {e['command']}")

    # Falhas por falta de permissão
    if events["not_sudoers"]:
        print(f"  ⛔  Sem permissão no sudoers ({ns}):")
        for e in events["not_sudoers"]:
            print(f"       {e['timestamp']}")
            print(f"       CMD: {e['command']}")

# Resumo geral
print(f"\n{SEP}")
print("  RESUMO GERAL")
print(SEP)
print(f"  Usuários distintos que usaram sudo : {len(sudo_events)}")
print(f"  Execuções bem-sucedidas            : {total_success}")
print(f"  Falhas por senha incorreta         : {total_wrong_pass}")
print(f"  Falhas por ausência no sudoers     : {total_not_sudoers}")
print(SEP)
