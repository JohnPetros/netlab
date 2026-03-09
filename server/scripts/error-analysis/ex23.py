#!/usr/bin/env python3
"""
Exercício 23 — Tempo de permanência de usuários logados no sistema
Fontes: /var/log/auth.log  +  comando `last` (wtmp binário)

Como o Linux registra sessões:

  FONTE 1 — auth.log (texto, legível diretamente)
  ─────────────────────────────────────────────────
  Cada sessão gera um par de linhas com o mesmo PID:

    LOGIN  → pam_unix(<svc>:session): session opened for user <u> by ...
    LOGOUT → pam_unix(<svc>:session): session closed for user <u>

  O PID do processo (sshd[1001], su[2100], etc.) é a chave de correlação
  entre o "opened" e o "closed" correspondentes.

  Serviços registrados:
    sshd   — conexões SSH (remoto)
    login  — login local no console (tty)
    su     — switch user (troca de usuário)
    sudo   — elevação de privilégio

  A linha "Accepted password/publickey for <u> from <ip>" aparece antes
  do "session opened" e fornece o IP de origem para sessões SSH.

  FONTE 2 — wtmp via `last -F` (binário /var/log/wtmp)
  ─────────────────────────────────────────────────────
  O comando `last` lê o arquivo binário wtmp e exibe sessões históricas:

    devuser  pts/0  172.28.0.20  Sun Mar  8 22:00:01 2026 - Sun Mar  8 22:00:45 2026  (00:00)
    admin    pts/1  10.0.0.5     Sun Mar  8 22:01:00 2026 - Sun Mar  8 22:05:30 2026  (00:04)
    ubuntu   tty1                Sun Mar  8 22:10:00 2026   still logged in

  A coluna "still logged in" indica sessão ainda ativa (sem logout ainda).
  A duração "(HH:MM)" ao final já está calculada pelo sistema.

  Por que usar ambas as fontes?
    auth.log: maior detalhe (serviço, IP, PID)   — pode não ter wtmp
    wtmp/last: mais confiável historicamente      — pode estar vazio em containers
  O script tenta wtmp primeiro; se vazio, cai para auth.log.

Uso:
  python3 ex23.py                        # auto-detecta fonte
  python3 ex23.py --log /tmp/auth.log    # força auth.log específico
  python3 ex23.py --user devuser         # filtra por usuário
  python3 ex23.py --source wtmp          # força wtmp/last
  python3 ex23.py --source auth          # força auth.log
  python3 ex23.py --min-duration 5       # só sessões ≥ 5 minutos
"""

import re
import os
import gzip
import glob
import argparse
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Argumentos
# ─────────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Calcula o tempo de permanência de usuários logados."
)
parser.add_argument("--log", default=None, help="Arquivo auth.log específico")
parser.add_argument("--user", default=None, help="Filtra por usuário (parcial)")
parser.add_argument(
    "--source",
    choices=["auto", "wtmp", "auth"],
    default="auto",
    help="Fonte de dados (padrão: auto)",
)
parser.add_argument(
    "--min-duration", type=int, default=0, help="Duração mínima em minutos para exibir"
)
args = parser.parse_args()

CURRENT_YEAR = datetime.now().year
NOW = datetime.now()


# ─────────────────────────────────────────────────────────────────────────────
# Estrutura de sessão
# ─────────────────────────────────────────────────────────────────────────────
class Session:
    def __init__(self, user, service, pid, login_dt, ip="", tty=""):
        self.user = user
        self.service = service
        self.pid = pid
        self.login_dt = login_dt
        self.logout_dt = None
        self.ip = ip
        self.tty = tty
        self.active = False  # ainda logado

    @property
    def duration(self):
        end = self.logout_dt or NOW
        return end - self.login_dt

    def fmt_duration(self):
        total = int(self.duration.total_seconds())
        if total < 0:
            return "inválida"
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        if h > 0:
            return f"{h}h {m:02d}m {s:02d}s"
        if m > 0:
            return f"{m}m {s:02d}s"
        return f"{s}s"


# ─────────────────────────────────────────────────────────────────────────────
# FONTE 1 — last / wtmp
# ─────────────────────────────────────────────────────────────────────────────
#
# Formato de saída do `last -F`:
#   USER    TTY    FROM(IP)   LOGIN_DT                  - LOGOUT_DT              (DUR)
#   devuser pts/0  172.28.0.20 Sun Mar  8 22:00:01 2026 - Sun Mar  8 22:00:45 2026  (00:00)
#   ubuntu  tty1              Sun Mar  8 22:10:00 2026   still logged in
#   reboot  system boot  ...  Sun Mar  8 21:50:00 2026   still running
#
# Campos separados por espaços variáveis; datas no formato:
#   "Www Mmm  D HH:MM:SS YYYY"

RE_LAST_LINE = re.compile(
    r"^(?P<user>\S+)\s+"
    r"(?P<tty>\S+)\s+"
    r"(?P<from>\S+)?\s+"
    r"(?P<login>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
    r"(?:\s+-\s+(?P<logout>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
    r"|(?P<still>\s+still logged in|\s+still running))?"
)


def parse_last_dt(s):
    s = re.sub(r"\s+", " ", s.strip())
    for fmt in ["%a %b %d %H:%M:%S %Y", "%a %b  %d %H:%M:%S %Y"]:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def read_wtmp():
    sessions = []
    try:
        result = subprocess.run(
            ["last", "-F", "-w"], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return sessions

    SKIP = {"reboot", "shutdown", "runlevel", "wtmp"}

    for line in output.splitlines():
        line = line.strip()
        if not line or any(line.startswith(s) for s in SKIP):
            continue
        if line.startswith("wtmp begins"):
            continue

        # Tenta parsear manualmente porque `last -F` tem espaçamento irregular
        # Divide pelo padrão de data "Www Mmm ..."
        dt_pattern = re.compile(
            r"(?P<login>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
        )
        dts = list(dt_pattern.finditer(line))
        if not dts:
            continue

        # Extrai usuário e terminal (primeiros tokens antes da primeira data)
        prefix = line[: dts[0].start()].split()
        if len(prefix) < 2:
            continue

        user = prefix[0]
        tty = prefix[1]
        ip = prefix[2] if len(prefix) > 2 else ""

        if args.user and args.user.lower() not in user.lower():
            continue

        login_dt = parse_last_dt(dts[0].group("login"))
        if not login_dt:
            continue

        logout_dt = None
        active = False

        if len(dts) >= 2:
            logout_dt = parse_last_dt(dts[1].group("login"))
        elif "still logged in" in line or "still running" in line:
            active = True

        s = Session(
            user=user,
            service="ssh/login",
            pid="wtmp",
            login_dt=login_dt,
            ip=ip,
            tty=tty,
        )
        s.logout_dt = logout_dt
        s.active = active

        min_secs = args.min_duration * 60
        if s.duration.total_seconds() >= min_secs:
            sessions.append(s)

    return sessions


# ─────────────────────────────────────────────────────────────────────────────
# FONTE 2 — auth.log
# ─────────────────────────────────────────────────────────────────────────────
#
# Padrões relevantes em auth.log:
#
# LOGIN via PAM:
#   pam_unix(<svc>:session): session opened for user <u> by ...
#
# LOGOUT via PAM:
#   pam_unix(<svc>:session): session closed for user <u>
#
# IP de origem (SSH):
#   Accepted password/publickey for <u> from <ip> port N
#
# Correlação: PID do processo entre colchetes (ex: sshd[1001])
#   O PID conecta o "Accepted" → "session opened" → "session closed"

RE_PAM_OPEN = re.compile(
    r"pam_unix\((?P<svc>[^:]+):session\): session opened"
    r" for user (?P<user>\S+)"
)
RE_PAM_CLOSE = re.compile(
    r"pam_unix\((?P<svc>[^:]+):session\): session closed"
    r" for user (?P<user>\S+)"
)
RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+)"
    r" from (?P<ip>\S+) port \d+"
)
RE_PID = re.compile(r"\w+\[(?P<pid>\d+)\]:")
RE_TS = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def parse_bsd_ts(ts_str):
    ts_str = re.sub(r"\s+", " ", ts_str.strip())
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
        if dt > NOW:
            dt = dt.replace(year=CURRENT_YEAR - 1)
        return dt
    except ValueError:
        return None


def read_auth_log(path):
    sessions = []
    # pid → Session em aberto
    open_sess = {}
    # pid → ip (SSH: Accepted vem antes do session opened)
    pid_ip = {}

    gz = path.endswith(".gz")
    try:
        opener = gzip.open if gz else open
        with opener(path, "rt", errors="replace") as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError, OSError):
        return sessions

    for raw in lines:
        line = raw.rstrip("\n")

        ts_m = RE_TS.match(line)
        if not ts_m:
            continue
        dt = parse_bsd_ts(ts_m.group("ts"))
        if not dt:
            continue

        pid_m = RE_PID.search(line)
        pid = pid_m.group("pid") if pid_m else "?"

        # Captura IP do "Accepted" para associar ao pid
        m = RE_ACCEPTED.search(line)
        if m:
            pid_ip[pid] = m.group("ip")
            continue

        # session opened → inicia sessão
        m = RE_PAM_OPEN.search(line)
        if m:
            user = m.group("user")
            svc = m.group("svc")  # sshd, login, su, sudo
            if args.user and args.user.lower() not in user.lower():
                continue
            sess = Session(
                user=user,
                service=svc,
                pid=pid,
                login_dt=dt,
                ip=pid_ip.get(pid, ""),
            )
            open_sess[pid] = sess
            continue

        # session closed → fecha a sessão correspondente pelo pid
        m = RE_PAM_CLOSE.search(line)
        if m:
            user = m.group("user")
            sess = open_sess.pop(pid, None)
            if sess and sess.user == user:
                sess.logout_dt = dt
                min_secs = args.min_duration * 60
                if sess.duration.total_seconds() >= min_secs:
                    sessions.append(sess)

    # Sessões sem logout = ainda ativas
    for sess in open_sess.values():
        if args.user and args.user.lower() not in sess.user.lower():
            continue
        sess.active = True
        min_secs = args.min_duration * 60
        if sess.duration.total_seconds() >= min_secs:
            sessions.append(sess)

    return sessions


def collect_auth_files(base):
    files = []
    for path in [base, base + ".1"] + sorted(glob.glob(base + ".*.gz")):
        if os.path.exists(path):
            files.append(path)
    return files


# ─────────────────────────────────────────────────────────────────────────────
# Coleta sessões de acordo com a fonte escolhida
# ─────────────────────────────────────────────────────────────────────────────
sessions = []
source_used = "nenhuma"

if args.log:
    sessions = read_auth_log(args.log)
    source_used = f"auth.log ({args.log})"

elif args.source in ("wtmp", "auto"):
    sessions = read_wtmp()
    if sessions:
        source_used = "wtmp (last -F)"
    elif args.source == "auto":
        # Fallback para auth.log
        for path in collect_auth_files("/var/log/auth.log"):
            sessions.extend(read_auth_log(path))
        if sessions:
            source_used = "auth.log"

elif args.source == "auth":
    for path in collect_auth_files("/var/log/auth.log"):
        sessions.extend(read_auth_log(path))
    source_used = "auth.log"

# Ordena por login mais recente
sessions.sort(key=lambda s: s.login_dt, reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# Relatório
# ─────────────────────────────────────────────────────────────────────────────
SEP = "═" * 68
SEP2 = "─" * 52

SVC_ICON = {
    "sshd": "🔐",
    "ssh": "🔐",
    "login": "🖥",
    "su": "🔄",
    "sudo": "⚡",
    "ssh/login": "🔐",
}

RESET = "\033[0m"
BOLD = "\033[1m"
GRAY = "\033[90m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"


def color_duration(secs):
    """Colore a duração por tempo: verde curto, amarelo médio, vermelho longo."""
    if secs < 300:
        return GRAY
    if secs < 3600:
        return GREEN
    if secs < 3600 * 8:
        return YELLOW
    return RED


print(SEP)
print("   TEMPO DE PERMANÊNCIA DE USUÁRIOS LOGADOS")
print(SEP)
print(f"  Fonte      : {source_used}")
print(f"  Referência : {NOW.strftime('%Y-%m-%d %H:%M:%S')} (para sessões ativas)")
if args.user:
    print(f"  Filtro     : usuário '{args.user}'")
if args.min_duration:
    print(f"  Duração    : ≥ {args.min_duration} minuto(s)")
print(SEP)

# ── Sem dados ─────────────────────────────────────────────────────
if not sessions:
    print(f"""
  {YELLOW}Nenhuma sessão encontrada.{RESET}

  Possíveis causas:
    • wtmp zerado (comum em containers Docker e WSL)
    • auth.log vazio ou sem eventos de sessão
    • Nenhuma sessão com duração ≥ {args.min_duration} minuto(s)

  Para testar com dados sintéticos:
    python3 ex23.py --log /tmp/auth_sessions.log

  Para gerar sessões reais no container:
    docker exec ubuntu-client sshpass -p 'devpass' ssh \\
      -o StrictHostKeyChecking=no devuser@172.28.0.10 'sleep 30'
    docker exec ubuntu-server python3 \\
      /root/scripts/incorrect-password/ex23.py
""")
    raise SystemExit(0)

# ── Listagem de sessões ────────────────────────────────────────────
print(f"\n  {len(sessions)} sessão(ões) encontrada(s)\n")
print(
    f"  {'LOGIN':<20} {'LOGOUT':<20} {'DURAÇÃO':<14}"
    f"{'USUÁRIO':<16} {'SERV':<8} {'IP/ORIGEM'}"
)
print(f"  {SEP2}")

for s in sessions:
    icon = SVC_ICON.get(s.service, "🔧")
    secs = s.duration.total_seconds()
    dcol = color_duration(secs)
    dur = s.fmt_duration()

    login_s = s.login_dt.strftime("%Y-%m-%d %H:%M:%S")
    logout_s = (
        s.logout_dt.strftime("%Y-%m-%d %H:%M:%S")
        if s.logout_dt
        else f"{YELLOW}ainda ativo{RESET}"
    )

    active_tag = f" {YELLOW}●{RESET}" if s.active else ""
    ip_disp = s.ip[:18] if s.ip else "local"

    print(
        f"  {login_s:<20} {logout_s:<20} "
        f"{dcol}{dur:<14}{RESET}"
        f"{BOLD}{s.user:<16}{RESET} "
        f"{icon}{s.service:<7} "
        f"{GRAY}{ip_disp}{RESET}{active_tag}"
    )

# ── Estatísticas por usuário ──────────────────────────────────────
print(f"\n{SEP}")
print("  ESTATÍSTICAS POR USUÁRIO")
print(SEP)

by_user = defaultdict(list)
for s in sessions:
    by_user[s.user].append(s)

print(
    f"\n  {'USUÁRIO':<18} {'SESSÕES':>8} {'TOTAL LOGADO':>15}"
    f" {'MÉDIA/SESSÃO':>14} {'MAIOR SESSÃO':>14} {'SERVIÇOS'}"
)
print(f"  {'─' * 75}")

for user, sess_list in sorted(
    by_user.items(), key=lambda x: -sum(s.duration.total_seconds() for s in x[1])
):
    total_secs = sum(s.duration.total_seconds() for s in sess_list)
    avg_secs = total_secs / len(sess_list)
    max_secs = max(s.duration.total_seconds() for s in sess_list)
    services = ", ".join(sorted({s.service for s in sess_list}))
    active_cnt = sum(1 for s in sess_list if s.active)

    def fmt_s(secs):
        h, r = divmod(int(secs), 3600)
        m, s = divmod(r, 60)
        if h:
            return f"{h}h {m:02d}m"
        return f"{m}m {s:02d}s"

    active_tag = f" {YELLOW}({active_cnt} ativo){RESET}" if active_cnt else ""

    print(
        f"  {BOLD}{user:<18}{RESET} "
        f"{len(sess_list):>8} "
        f"{color_duration(total_secs)}{fmt_s(total_secs):>15}{RESET} "
        f"{fmt_s(avg_secs):>14} "
        f"{fmt_s(max_secs):>14}  "
        f"{GRAY}{services}{RESET}"
        f"{active_tag}"
    )

# ── Timeline visual por usuário ───────────────────────────────────
print(f"\n{SEP}")
print("  LINHA DO TEMPO — HISTÓRICO DE SESSÕES")
print(SEP)

for user, sess_list in sorted(by_user.items()):
    print(f"\n  {BOLD}{CYAN}{user}{RESET}")
    for s in sorted(sess_list, key=lambda x: x.login_dt):
        icon = SVC_ICON.get(s.service, "🔧")
        secs = s.duration.total_seconds()
        dcol = color_duration(secs)
        bar_w = max(1, min(int(secs / 60), 30))  # 1 char = 1 minuto, max 30
        bar = "█" * bar_w
        dur_str = s.fmt_duration()
        active_s = f" {YELLOW}[ativo]{RESET}" if s.active else ""
        ip_s = f" ← {s.ip}" if s.ip else ""

        login_s = s.login_dt.strftime("%m-%d %H:%M")
        logout_s = s.logout_dt.strftime("%H:%M") if s.logout_dt else "agora"

        print(
            f"    {icon} {login_s} → {logout_s:<6}  "
            f"{dcol}{dur_str:<12}{RESET} "
            f"{dcol}{bar}{RESET}"
            f"{GRAY}{ip_s}{RESET}{active_s}"
        )

# ── Totais ────────────────────────────────────────────────────────
total_all = sum(s.duration.total_seconds() for s in sessions)
active_all = sum(1 for s in sessions if s.active)

print(f"\n{SEP}")
print("  TOTAIS")
print(SEP)

h, rem = divmod(int(total_all), 3600)
m, sc = divmod(rem, 60)
print(f"  Sessões registradas   : {len(sessions)}")
print(f"  Sessões ativas agora  : {active_all}")
print(f"  Usuários distintos    : {len(by_user)}")
print(f"  Tempo total logado    : {h}h {m:02d}m {sc:02d}s (todos os usuários)")
print(SEP)
print()
print("  Filtros:")
print("    python3 ex23.py --user devuser")
print("    python3 ex23.py --min-duration 5   # sessões ≥ 5 min")
print("    python3 ex23.py --source auth       # força auth.log")
print("    python3 ex23.py --log /tmp/auth_sessions.log")
print(SEP)
