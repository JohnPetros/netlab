#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

# -------------------------------------------------------------------
# Padrões Regex — cada um mapeia para um motivo de rejeição
#
# Todos capturam:
#   - user      : nome do usuário que tentou o login
#   - ip        : endereço IP de origem (quando disponível)
#
# A chave "reason" é adicionada manualmente em cada bloco.
# -------------------------------------------------------------------

PATTERNS = [
    {
        "reason": "Usuário inexistente",
        # "Invalid user <user> from <ip>"
        "regex": re.compile(r"sshd.*Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
    },
    {
        "reason": "Usuário não listado no AllowUsers",
        # "User <user> from <ip> not allowed because not listed in AllowUsers"
        "regex": re.compile(r"sshd.*User (?P<user>\S+) from (?P<ip>\S+) not allowed"),
    },
    {
        "reason": "Permissão negada (root ou pubkey)",
        # "Permission denied for <user>"  OU  "Permission denied (publickey)"
        "regex": re.compile(
            r"sshd.*Permission denied.*?(?:for (?P<user>\S+)|from (?P<ip>\S+))"
        ),
    },
    {
        "reason": "Máximo de tentativas excedido",
        # "Disconnecting invalid user <user> ... Too many authentication failures"
        "regex": re.compile(
            r"sshd.*Too many authentication failures.*?user (?P<user>\S+)"
            r"|sshd.*Disconnecting (?:invalid user )?(?P<user2>\S+).*Too many"
        ),
    },
    {
        "reason": "Conta bloqueada / expirada (PAM)",
        # "PAM: User account has expired" — o usuário vem na linha anterior,
        # mas o sshd também loga: "error: PAM: ... for <user> from <ip>"
        "regex": re.compile(r"sshd.*PAM:.*?for (?P<user>\S+) from (?P<ip>\S+)"),
    },
    {
        "reason": "Conexão encerrada antes da autenticação",
        # "Connection closed by invalid user <user> <ip>"
        # "Connection closed by <ip>"  (usuário válido que não autenticou)
        "regex": re.compile(
            r"sshd.*Connection closed by (?:invalid user )?(?P<user>\S+) (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
    },
]

# -------------------------------------------------------------------
# Estrutura de dados
#
# { reason: [ {"timestamp", "user", "ip", "raw"}, ... ] }
# -------------------------------------------------------------------
rejections = defaultdict(list)

try:
    with open(LOG_FILE, "r") as log:
        for line in log:
            # Ignora linhas sem "sshd" — su/sudo têm outros exercícios
            if "sshd" not in line:
                continue

            # Ignora falhas de senha — cobertas pelo ex1.py
            if "authentication failure" in line.lower() or "Failed password" in line:
                continue

            timestamp = line[:15].strip()

            for pattern in PATTERNS:
                m = pattern["regex"].search(line)
                if m:
                    groups = m.groupdict()

                    # Alguns padrões têm grupos alternativos (user / user2)
                    user = groups.get("user") or groups.get("user2") or "desconhecido"
                    ip = groups.get("ip") or "N/A"

                    rejections[pattern["reason"]].append(
                        {
                            "timestamp": timestamp,
                            "user": user,
                            "ip": ip,
                            "raw": line.strip(),
                        }
                    )
                    break  # evita classificar a mesma linha em dois motivos

except FileNotFoundError:
    print(f"[ERRO] Arquivo não encontrado: {LOG_FILE}")
    print("       Execute o script dentro do container ubuntu-server.")
    raise SystemExit(1)

if not rejections:
    print("Nenhum login rejeitado (além de senha incorreta) encontrado em", LOG_FILE)
    raise SystemExit(0)

SEP = "=" * 65
SEP2 = "-" * 55

print(SEP)
print("   LOGINS REJEITADOS — MOTIVOS ALÉM DE SENHA INCORRETA")
print(SEP)

grand_total = 0

for reason, events in sorted(rejections.items()):
    grand_total += len(events)
    print(f"\n⚠  {reason.upper()}  ({len(events)} evento(s))")
    print(SEP2)

    # Agrupa por usuário para facilitar leitura
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e)

    for user, user_events in sorted(by_user.items()):
        print(f"\n   Usuário: {user}  ({len(user_events)} vez(es))")
        for e in user_events:
            print(f"     {e['timestamp']}  |  IP: {e['ip']}")

print(f"\n{SEP}")
print("  RESUMO")
print(SEP)

for reason, events in sorted(rejections.items(), key=lambda x: -len(x[1])):
    print(f"  {len(events):>4}x  {reason}")

print(f"  {'─' * 40}")
print(f"  {grand_total:>4}   total de rejeições")
print(SEP)
