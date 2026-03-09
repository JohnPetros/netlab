#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

# -------------------------------------------------------------------
# Padrões Regex
#
# Linha de SUCESSO:
#   su: (to <target_user>) <origin_user> on ...
#
# Linha de FALHA:
#   su: FAILED SU (to <target_user>) <origin_user> on ...
#
# Grupos nomeados capturados:
#   - target : usuário para o qual se tentou mudar
#   - origin : usuário que executou o comando
# -------------------------------------------------------------------
SUCCESS_PATTERN = re.compile(r"su:\s+\(to\s+(?P<target>\S+)\)\s+(?P<origin>\S+)\s+on")

FAILED_PATTERN = re.compile(
    r"su:\s+FAILED SU\s+\(to\s+(?P<target>\S+)\)\s+(?P<origin>\S+)\s+on"
)

# Estrutura: { origin_user: { "success": [(target, timestamp), ...],
#                             "failed":  [(target, timestamp), ...] } }
su_events = defaultdict(lambda: {"success": [], "failed": []})

try:
    with open(LOG_FILE, "r") as log:
        for line in log:
            timestamp = line[:15].strip()

            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                origin = failed_match.group("origin")
                target = failed_match.group("target")
                su_events[origin]["failed"].append((target, timestamp))
                continue

            success_match = SUCCESS_PATTERN.search(line)
            if success_match:
                origin = success_match.group("origin")
                target = success_match.group("target")
                su_events[origin]["success"].append((target, timestamp))

except FileNotFoundError:
    print(f"[ERRO] Arquivo não encontrado: {LOG_FILE}")
    print("       Execute o script dentro do container ubuntu-server.")
    raise SystemExit(1)

if not su_events:
    print("Nenhum evento de 'su' encontrado em", LOG_FILE)
    raise SystemExit(0)

print("=" * 60)
print("   RELATÓRIO DE USO DO COMANDO su")
print("=" * 60)

for origin, events in sorted(su_events.items()):
    total = len(events["success"]) + len(events["failed"])
    print(f"\nUsuário de origem : {origin}  (total de eventos: {total})")
    print("-" * 50)

    if events["success"]:
        print(f"  ✔ Bem-sucedidos ({len(events['success'])}):")
        for target, ts in events["success"]:
            print(f"      {ts}  →  su para '{target}'")

    if events["failed"]:
        print(f"  ✘ Falhas ({len(events['failed'])}):")
        for target, ts in events["failed"]:
            print(f"      {ts}  →  su para '{target}'  [FALHOU]")

print("\n" + "=" * 60)
print(f"Total de usuários que usaram su : {len(su_events)}")
success_total = sum(len(v["success"]) for v in su_events.values())
failed_total = sum(len(v["failed"]) for v in su_events.values())
print(f"Total de trocas bem-sucedidas   : {success_total}")
print(f"Total de tentativas falhas      : {failed_total}")
print("=" * 60)
