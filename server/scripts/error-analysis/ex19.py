#!/usr/bin/env python3
"""
Exercício 19 - Monitoramento em tempo real de tentativas de login falhas
Arquivo monitorado: /var/log/auth.log

Funciona como um "tail -f" inteligente — posiciona o cursor no final
do arquivo e aguarda novas linhas, exibindo imediatamente cada falha
detectada sem precisar relê-lo do início.

Mecanismo:
  1. Abre o arquivo e vai para o final (seek EOF)
  2. Loop infinito lendo linha a linha
  3. Se não há nova linha, dorme 0.5s e tenta de novo (polling)
  4. Se o arquivo foi rotacionado (inode mudou), reabre o novo arquivo
  5. Cada linha nova é testada contra os padrões de falha
  6. Match → exibe imediatamente com timestamp, usuário, método e IP

Rotação de log:
  O logrotate substitui o arquivo periodicamente. O script detecta isso
  comparando o inode do arquivo aberto com o do path — quando divergem,
  significa que o arquivo foi rotacionado e o script reabre o novo.

Uso:
  python3 ex19.py                          # monitora /var/log/auth.log
  python3 ex19.py --log /tmp/auth_test.log # outro arquivo
  python3 ex19.py --log /var/log/auth.log --from-start  # lê do início
  python3 ex19.py --simulate               # gera eventos falsos p/ demo
"""

import re
import os
import sys
import time
import argparse
import threading
from datetime import datetime

# -------------------------------------------------------------------
# Argumentos
# -------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Monitora tentativas de login falhas em tempo real."
)
parser.add_argument(
    "--log",
    default="/var/log/auth.log",
    help="Arquivo de log a monitorar (padrão: /var/log/auth.log)",
)
parser.add_argument(
    "--from-start", action="store_true", help="Lê o arquivo do início em vez do final"
)
parser.add_argument(
    "--simulate", action="store_true", help="Simula eventos de falha para demonstração"
)
parser.add_argument(
    "--interval",
    type=float,
    default=0.5,
    help="Intervalo de polling em segundos (padrão: 0.5)",
)
args = parser.parse_args()

# -------------------------------------------------------------------
# Padrões de falha — mesmo conjunto do ex18.py
# -------------------------------------------------------------------
PATTERNS = [
    {
        "method": "SSH",
        "detail": "senha incorreta (usuário inválido)",
        "regex": re.compile(
            r"Failed password for invalid user (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    {
        "method": "SSH",
        "detail": "senha incorreta",
        "regex": re.compile(
            r"Failed password for (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    {
        "method": "SSH",
        "detail": "chave pública rejeitada",
        "regex": re.compile(
            r"Failed publickey for (?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    {
        "method": "SSH",
        "detail": "não permitido (AllowUsers)",
        "regex": re.compile(r"User (?P<user>\S+) from (?P<ip>\S+) not allowed"),
    },
    {
        "method": "SSH",
        "detail": "máx. tentativas excedido",
        "regex": re.compile(
            r"maximum authentication attempts exceeded"
            r" for (?:invalid user )?(?P<user>\S+)"
            r".*from (?P<ip>\S+)"
        ),
    },
    {
        "method": "SSH",
        "detail": "usuário inválido (conexão encerrada)",
        "regex": re.compile(
            r"Connection closed by invalid user (?P<user>\S+)"
            r" (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
    },
    {
        "method": "SU",
        "detail": "troca de usuário falhou",
        "regex": re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on"),
        "extra": lambda m: f"→ '{m.group('target')}'",
    },
    {
        "method": "SUDO",
        "detail": "senha incorreta",
        "regex": re.compile(
            r"(?P<user>\S+)\s+:\s+\d+ incorrect password attempts"
            r".*COMMAND=(?P<cmd>.+)"
        ),
        "extra": lambda m: f"cmd: {m.group('cmd').strip()[:35]}",
    },
    {
        "method": "SUDO",
        "detail": "não está no sudoers",
        "regex": re.compile(
            r"(?P<user>\S+)\s+:\s+user NOT in sudoers"
            r".*COMMAND=(?P<cmd>.+)"
        ),
        "extra": lambda m: f"cmd: {m.group('cmd').strip()[:35]}",
    },
    {
        "method": None,  # extraído do contexto PAM
        "detail": "falha PAM",
        "regex": re.compile(
            r"pam_unix\((?P<ctx>[^:]+):auth\): authentication failure"
            r".*\buser=(?P<user>\S+)"
        ),
        "pam": True,
    },
]


# -------------------------------------------------------------------
# Cores ANSI para terminal
# -------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"


METHOD_COLOR = {
    "SSH": C.RED,
    "SU": C.YELLOW,
    "SUDO": C.CYAN,
    "LOGIN": C.WHITE,
    "PAM": C.GRAY,
}

METHOD_ICON = {
    "SSH": "🔐",
    "SU": "🔄",
    "SUDO": "⚡",
    "LOGIN": "🖥",
    "PAM": "🔑",
}


# -------------------------------------------------------------------
# Classifica uma linha e retorna dict com dados do evento ou None
# -------------------------------------------------------------------
def classify(line):
    for pat in PATTERNS:
        m = pat["regex"].search(line)
        if not m:
            continue

        user = m.groupdict().get("user", "?")
        ip = m.groupdict().get("ip", "")

        # Método via PAM context
        if pat.get("pam"):
            ctx = m.group("ctx")
            method = "SSH" if "ssh" in ctx else ctx.upper()
        else:
            method = pat["method"] or "?"

        detail = pat["detail"]
        if "extra" in pat:
            try:
                detail = f"{detail} {pat['extra'](m)}"
            except Exception:
                pass

        return {
            "user": user,
            "method": method,
            "detail": detail,
            "ip": ip,
        }
    return None


# -------------------------------------------------------------------
# Contador de eventos (thread-safe via GIL em CPython)
# -------------------------------------------------------------------
stats = {"total": 0, "by_method": {}, "by_user": {}}


def update_stats(event):
    stats["total"] += 1
    m = event["method"]
    u = event["user"]
    stats["by_method"][m] = stats["by_method"].get(m, 0) + 1
    stats["by_user"][u] = stats["by_user"].get(u, 0) + 1


# -------------------------------------------------------------------
# Exibe um evento formatado
# -------------------------------------------------------------------
def display_event(event, raw_line):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    method = event["method"]
    color = METHOD_COLOR.get(method, C.WHITE)
    icon = METHOD_ICON.get(method, "❓")

    print(f"\n{C.BOLD}{color}{'─' * 60}{C.RESET}")
    print(f"{C.BOLD}{color}{icon} [{now}]  {method}{C.RESET}")
    print(f"  {C.BOLD}Usuário{C.RESET} : {C.RED}{event['user']}{C.RESET}")
    print(f"  {C.BOLD}Método {C.RESET} : {color}{event['method']}{C.RESET}")
    print(f"  {C.BOLD}Detalhe{C.RESET} : {event['detail']}")
    if event["ip"]:
        print(f"  {C.BOLD}IP     {C.RESET} : {C.CYAN}{event['ip']}{C.RESET}")
    print(f"  {C.GRAY}LOG: {raw_line[:80]}{C.RESET}")
    print(
        f"{C.GRAY}  Total: {stats['total']}  |  "
        + "  ".join(f"{k}:{v}" for k, v in stats["by_method"].items())
        + C.RESET
    )


# -------------------------------------------------------------------
# Simulador — escreve eventos falsos no arquivo monitorado
# Roda em thread separada para não bloquear o monitor
# -------------------------------------------------------------------
FAKE_EVENTS = [
    "Mar  8 22:00:01 server sshd[1001]: Failed password for devuser from 192.168.1.100 port 54321 ssh2",
    "Mar  8 22:00:03 server sshd[1002]: Failed password for invalid user admin from 10.0.0.5 port 44322 ssh2",
    "Mar  8 22:00:06 server su[1003]: FAILED SU (to root) ubuntu on pts/0",
    "Mar  8 22:00:09 server sudo[1004]: devuser : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    "Mar  8 22:00:13 server sshd[1005]: Failed publickey for devuser from 172.28.0.20 port 55001 ssh2",
    "Mar  8 22:00:17 server sshd[1006]: User root from 10.0.0.1 not allowed because not listed in AllowUsers",
    "Mar  8 22:00:22 server sshd[1007]: Failed password for devuser from 172.28.0.20 port 55100 ssh2",
    "Mar  8 22:00:28 server sudo[1008]: ubuntu : user NOT in sudoers ; TTY=pts/2 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
]


def simulate(log_path, stop_event):
    """Escreve linhas falsas no arquivo com delay entre elas."""
    time.sleep(1)  # espera o monitor inicializar
    for line in FAKE_EVENTS:
        if stop_event.is_set():
            break
        with open(log_path, "a") as f:
            f.write(line + "\n")
        time.sleep(2)  # 2s entre eventos para ver em tempo real
    print(f"\n{C.GREEN}[simulação concluída — Ctrl+C para sair]{C.RESET}")


# -------------------------------------------------------------------
# Monitor principal — tail -f inteligente
# -------------------------------------------------------------------
def monitor(log_path, from_start, interval):
    """Monitora o arquivo em loop, detectando rotação."""

    # Aguarda o arquivo existir
    while not os.path.exists(log_path):
        print(
            f"{C.YELLOW}[aguardando] {log_path} ainda não existe...{C.RESET}", end="\r"
        )
        time.sleep(1)

    f = open(log_path, "r", errors="replace")
    inode = os.fstat(f.fileno()).st_ino

    # Posiciona no final ou no início
    if not from_start:
        f.seek(0, 2)  # EOF

    print(f"{C.GREEN}[monitorando] {log_path}{C.RESET}")
    print(f"{C.GRAY}Aguardando eventos de falha... (Ctrl+C para sair){C.RESET}")

    try:
        while True:
            line = f.readline()

            if not line:
                # Sem nova linha — verifica rotação
                try:
                    current_inode = os.stat(log_path).st_ino
                    if current_inode != inode:
                        # Arquivo foi rotacionado — reabre
                        f.close()
                        f = open(log_path, "r", errors="replace")
                        inode = os.fstat(f.fileno()).st_ino
                        print(
                            f"\n{C.YELLOW}[rotação detectada] reabrindo {log_path}{C.RESET}"
                        )
                        continue
                except FileNotFoundError:
                    pass  # arquivo temporariamente ausente durante rotação

                time.sleep(interval)
                continue

            line = line.rstrip("\n")
            if not line:
                continue

            event = classify(line)
            if event:
                update_stats(event)
                display_event(event, line)

    except KeyboardInterrupt:
        f.close()
        raise


# -------------------------------------------------------------------
# Ponto de entrada
# -------------------------------------------------------------------
SEP = "=" * 60

print(SEP)
print("   MONITOR DE LOGIN — TEMPO REAL")
print(SEP)
print(f"  Arquivo  : {args.log}")
print(f"  Polling  : {args.interval}s")
print(
    f"  Modo     : {'início do arquivo' if args.from_start else 'apenas novos eventos'}"
)
if args.simulate:
    print(f"  Simulação: ativada")
print(SEP)

# Prepara arquivo de log para simulação
log_path = args.log
if args.simulate:
    # Usa arquivo temporário para não poluir logs reais
    log_path = "/tmp/auth_monitor_sim.log"
    # Garante que existe e está vazio
    open(log_path, "w").close()
    print(f"\n{C.YELLOW}[simulação] escrevendo em {log_path}{C.RESET}")

    stop_event = threading.Event()
    sim_thread = threading.Thread(
        target=simulate, args=(log_path, stop_event), daemon=True
    )
    sim_thread.start()

try:
    monitor(
        log_path, from_start=args.from_start or args.simulate, interval=args.interval
    )
except KeyboardInterrupt:
    if args.simulate:
        stop_event.set()
    print(f"\n\n{SEP}")
    print("  SESSÃO ENCERRADA")
    print(SEP)
    print(f"  Total de falhas detectadas : {stats['total']}")
    if stats["by_method"]:
        print("\n  Por método:")
        for method, count in sorted(stats["by_method"].items(), key=lambda x: -x[1]):
            icon = METHOD_ICON.get(method, "❓")
            print(f"    {icon} {method:<8} {count}x")
    if stats["by_user"]:
        print("\n  Usuários mais visados:")
        for user, count in sorted(stats["by_user"].items(), key=lambda x: -x[1])[:5]:
            print(f"    • {user:<20} {count}x")
    print(SEP)
