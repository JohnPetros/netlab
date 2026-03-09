#!/usr/bin/env python3
"""
Exercício 18 - Tentativas de login falho: usuário e método de autenticação
Arquivo de log: /var/log/auth.log (+ rotacionados)

O auth.log registra falhas de autenticação com formatos distintos
para cada método. Este script cobre todos os casos reais:

  MÉTODO SSH — sshd
  ─────────────────
  1. Senha incorreta (usuário existente):
     sshd[N]: Failed password for devuser from 10.0.0.1 port 22 ssh2
     → método: ssh / submétodo: password

  2. Senha incorreta (usuário inexistente):
     sshd[N]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
     → método: ssh / submétodo: password / usuário: admin (inválido)

  3. Chave pública rejeitada:
     sshd[N]: Failed publickey for devuser from 10.0.0.1 port 22 ssh2
     → método: ssh / submétodo: publickey

  4. Usuário não permitido (AllowUsers):
     sshd[N]: User root from 10.0.0.1 not allowed because not listed in AllowUsers
     → método: ssh / motivo: not in AllowUsers

  5. Máx. tentativas excedido:
     sshd[N]: error: maximum authentication attempts exceeded for devuser
     → método: ssh / motivo: max attempts

  6. Usuário inválido (conexão encerrada):
     sshd[N]: Connection closed by invalid user ghost 10.0.0.1 port N [preauth]
     → método: ssh / usuário: ghost (inválido)

  MÉTODO SU — troca de usuário
  ─────────────────────────────
  7. su com senha errada:
     su[N]: FAILED SU (to root) devuser on pts/0
     → método: su / origem: devuser / destino: root

  MÉTODO SUDO — elevação de privilégio
  ──────────────────────────────────────
  8. Senha errada no sudo:
     sudo[N]: devuser : 3 incorrect password attempts ; ... ; COMMAND=...
     → método: sudo / submétodo: incorrect password

  9. Usuário não está no sudoers:
     sudo[N]: ubuntu : user NOT in sudoers ; ...
     → método: sudo / submétodo: not in sudoers

  MÉTODO PAM — autenticação via módulos
  ──────────────────────────────────────
  10. Falha genérica de PAM (login local, etc.):
      pam_unix(sshd:auth): authentication failure; ... user=devuser
      pam_unix(login:auth): authentication failure; ... user=ubuntu
      → método: extraído do contexto PAM (ssh, login, su)
"""

import re
import os
import gzip
import glob
import argparse
from collections import defaultdict, Counter, namedtuple

FailEvent = namedtuple(
    "FailEvent", ["timestamp", "user", "method", "detail", "ip", "raw"]
)

# -------------------------------------------------------------------
# Argumentos
# -------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Extrai usuário e método de cada tentativa de login falha."
)
parser.add_argument(
    "--log",
    default="/var/log/auth.log",
    help="Arquivo de log (padrão: /var/log/auth.log)",
)
parser.add_argument(
    "--all-rotated",
    action="store_true",
    help="Inclui arquivos rotacionados (.1, .2.gz...)",
)
args = parser.parse_args()

# -------------------------------------------------------------------
# Padrões de falha — ordem importa (mais específico primeiro)
# -------------------------------------------------------------------
PATTERNS = [
    # 1. SSH — senha errada para usuário inválido
    {
        "method": "ssh",
        "detail": "senha incorreta (usuário inexistente)",
        "regex": re.compile(
            r"Failed password for invalid user (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    # 2. SSH — senha errada para usuário válido
    {
        "method": "ssh",
        "detail": "senha incorreta",
        "regex": re.compile(
            r"Failed password for (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    # 3. SSH — chave pública rejeitada
    {
        "method": "ssh",
        "detail": "chave pública rejeitada",
        "regex": re.compile(
            r"Failed publickey for (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    # 4. SSH — usuário não listado em AllowUsers
    {
        "method": "ssh",
        "detail": "usuário não permitido (AllowUsers)",
        "regex": re.compile(
            r"User (?P<user>\S+) from (?P<ip>\S+)"
            r" not allowed because not listed in AllowUsers"
        ),
    },
    # 5. SSH — máximo de tentativas excedido
    {
        "method": "ssh",
        "detail": "máx. tentativas excedido",
        "regex": re.compile(
            r"maximum authentication attempts exceeded"
            r" for (?:invalid user )?(?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    # 6. SSH — conexão encerrada por usuário inválido
    {
        "method": "ssh",
        "detail": "usuário inválido (conexão encerrada)",
        "regex": re.compile(
            r"Connection closed by invalid user (?P<user>\S+)"
            r" (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
    },
    # 7. SU — troca de usuário falhou
    {
        "method": "su",
        "detail": "senha incorreta",
        "regex": re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on"),
        "user_field": "user",  # quem tentou
        "extra": lambda m: f"tentou virar '{m.group('target')}'",
    },
    # 8. SUDO — senha incorreta
    {
        "method": "sudo",
        "detail": "senha incorreta",
        "regex": re.compile(
            r"(?P<user>\S+)\s+:\s+\d+ incorrect password attempts"
            r".*COMMAND=(?P<cmd>.+)"
        ),
        "extra": lambda m: f"cmd: {m.group('cmd').strip()[:40]}",
    },
    # 9. SUDO — não está no sudoers
    {
        "method": "sudo",
        "detail": "usuário não está no sudoers",
        "regex": re.compile(
            r"(?P<user>\S+)\s+:\s+user NOT in sudoers"
            r".*COMMAND=(?P<cmd>.+)"
        ),
        "extra": lambda m: f"cmd: {m.group('cmd').strip()[:40]}",
    },
    # 10. PAM — authentication failure genérica
    #     pam_unix(sshd:auth): authentication failure; ... user=devuser
    {
        "method": None,  # método extraído do contexto PAM
        "detail": "falha PAM",
        "regex": re.compile(
            r"pam_unix\((?P<ctx>[^:]+):auth\): authentication failure"
            r".*\buser=(?P<user>\S+)"
        ),
        "method_from_ctx": True,
    },
]


# -------------------------------------------------------------------
# Coleta arquivos para ler
# -------------------------------------------------------------------
def get_files(base, all_rotated):
    files = [(base, False)] if os.path.exists(base) else []
    if all_rotated:
        r1 = base + ".1"
        if os.path.exists(r1):
            files.append((r1, False))
        for gz in sorted(
            glob.glob(base + ".*.gz"),
            key=lambda f: (
                int(re.search(r"\.(\d+)", f).group(1))
                if re.search(r"\.(\d+)", f)
                else 999
            ),
        ):
            files.append((gz, True))
    return files


# -------------------------------------------------------------------
# Leitura e parsing
# -------------------------------------------------------------------
events = []

for path, is_gz in get_files(args.log, args.all_rotated):
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue

                timestamp = line[:15].strip()

                for pat in PATTERNS:
                    m = pat["regex"].search(line)
                    if not m:
                        continue

                    # Usuário
                    user = m.group("user") if "user" in m.groupdict() else "?"

                    # Método — pode vir do contexto PAM
                    if pat.get("method_from_ctx"):
                        ctx = m.group("ctx")  # ex: "sshd", "login", "su"
                        method = ctx.rstrip("d")  # "sshd" → "ssh", "login" → "login"
                        if method == "ss":
                            method = "ssh"
                    else:
                        method = pat["method"]

                    # IP
                    ip = m.groupdict().get("ip", "N/A")

                    # Detalhe extra (su, sudo)
                    detail = pat["detail"]
                    if "extra" in pat:
                        try:
                            detail = f"{detail} — {pat['extra'](m)}"
                        except Exception:
                            pass

                    events.append(
                        FailEvent(
                            timestamp=timestamp,
                            user=user,
                            method=method,
                            detail=detail,
                            ip=ip,
                            raw=line.strip(),
                        )
                    )
                    break  # uma linha = um padrão

    except (FileNotFoundError, PermissionError) as e:
        print(f"[aviso] {path}: {e}")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 68
SEP2 = "-" * 52

METHOD_ICON = {
    "ssh": "🔐",
    "su": "🔄",
    "sudo": "⚡",
    "login": "🖥",
    "pam": "🔑",
}

print(SEP)
print("   TENTATIVAS DE LOGIN FALHAS — USUÁRIO E MÉTODO")
print(SEP)
print(f"  Fonte : {args.log}")
print(SEP)

if not events:
    print(f"""
  Nenhuma tentativa de falha encontrada em:
    {args.log}

  Para gerar eventos de teste, use o arquivo sintético:
    python3 ex18.py --log /tmp/auth_test.log

  Ou gere eventos reais no container:
    docker exec ubuntu-client sshpass -p 'errada' ssh \\
      -o StrictHostKeyChecking=no devuser@172.28.0.10
    docker exec ubuntu-server bash -c \\
      "echo errada | su - root 2>/dev/null; true"
    python3 ex18.py --log /var/log/auth.log
""")
    raise SystemExit(0)

# ------- Listagem por evento -------------------------------------
for e in events:
    icon = METHOD_ICON.get(e.method, "❓")
    print(f"\n  {icon} [{e.timestamp}]")
    print(f"     Usuário : {e.user}")
    print(f"     Método  : {e.method.upper()}")
    print(f"     Detalhe : {e.detail}")
    if e.ip and e.ip != "N/A":
        print(f"     IP      : {e.ip}")

# ------- Resumo por método ---------------------------------------
print(f"\n{SEP}")
print("  RESUMO POR MÉTODO DE AUTENTICAÇÃO")
print(SEP)

by_method = defaultdict(list)
for e in events:
    by_method[e.method].append(e)

for method, evs in sorted(by_method.items(), key=lambda x: -len(x[1])):
    icon = METHOD_ICON.get(method, "❓")
    bar = "█" * min(len(evs), 30)
    print(f"\n  {icon} {method.upper():<8} {len(evs):>4} tentativa(s)  {bar}")

    # Detalhes por subcategoria
    sub = Counter(e.detail.split(" —")[0] for e in evs)
    for detail, count in sub.most_common():
        print(f"     • {detail:<40} {count:>3}x")

# ------- Resumo por usuário --------------------------------------
print(f"\n{SEP}")
print("  USUÁRIOS COM MAIS FALHAS")
print(SEP)

by_user = Counter(e.user for e in events)
print(f"\n  {'USUÁRIO':<20} {'FALHAS':>7}  {'MÉTODOS USADOS'}")
print(f"  {'─' * 55}")
for user, count in by_user.most_common():
    methods = ", ".join(sorted({e.method for e in events if e.user == user}))
    bar = "█" * min(count, 20)
    print(f"  {user:<20} {count:>7}  {methods:<15}  {bar}")

# ------- Resumo por IP -------------------------------------------
ips = [e.ip for e in events if e.ip not in ("N/A", "?", "")]
if ips:
    print(f"\n{SEP}")
    print("  IPs DE ORIGEM")
    print(SEP)
    by_ip = Counter(ips)
    print(f"\n  {'IP':<20} {'TENTATIVAS':>10}")
    print(f"  {'─' * 35}")
    for ip, count in by_ip.most_common():
        bar = "█" * min(count, 20)
        print(f"  {ip:<20} {count:>10}  {bar}")

# ------- Totais --------------------------------------------------
print(f"\n{SEP}")
print("  TOTAIS")
print(SEP)
print(f"  Total de falhas       : {len(events)}")
print(f"  Usuários distintos    : {len(by_user)}")
print(f"  Métodos identificados : {len(by_method)}")
print(f"  IPs distintos         : {len(set(ips))}")
print(SEP)
print()
print("  Dica: para monitorar em tempo real:")
print("    tail -f /var/log/auth.log | grep -iE 'failed|invalid|FAILED'")
print(SEP)
