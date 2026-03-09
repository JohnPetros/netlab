#!/usr/bin/env python3
"""
Exercício 21 — Erros e avisos gerados pelo serviço apt/dpkg
Serviço escolhido: apt  (gerenciador de pacotes do Ubuntu/Debian)

Por que apt?
  O apt é o serviço mais ativo neste ambiente (WSL sem syslog/auth.log).
  Ele coordena múltiplos subprocessos durante instalações e upgrades:
  dpkg, update-alternatives, systemd-tmpfiles, invoke-rc.d, etc.
  Cada um pode emitir warnings e erros que ficam registrados em
  /var/log/apt/term.log.

Arquivos monitorados:
  /var/log/apt/term.log    — saída completa de cada sessão apt
                             Formato: blocos delimitados por
                             "Log started: YYYY-MM-DD  HH:MM:SS"
                             "Log ended:   YYYY-MM-DD  HH:MM:SS"

  /var/log/apt/history.log — registro estruturado (Start-Date/Upgrade/...)
                             Usado para correlacionar o comando apt que
                             gerou cada sessão do term.log

  /var/log/dpkg.log        — operações linha a linha do dpkg
                             Contém status de erros de configuração

Categorias de mensagem detectadas:
  ┌─────────┬────────────────────────────────────────────────────────────┐
  │ ERROR   │ Falhas que impedem a operação: dpkg error, failed to open  │
  ├─────────┼────────────────────────────────────────────────────────────┤
  │ WARNING │ Avisos não-fatais: update-alternatives skip, missing files │
  ├─────────┼────────────────────────────────────────────────────────────┤
  │ FAILED  │ Falha ao resolver usuário/grupo (systemd em containers)    │
  └─────────┴────────────────────────────────────────────────────────────┘

Exemplos reais encontrados neste ambiente:

  [WARNING] update-alternatives: warning: skip creation of
            /usr/share/man/man1/lzma.1.gz because associated file
            /usr/share/man/man1/xz.1.gz doesn't exist
  → O pacote xz-utils registrou alternativas de man page, mas o arquivo
    alvo não existe. Comum em ambientes minimalistas (Docker/WSL).

  [FAILED]  /usr/lib/tmpfiles.d/systemd-network.conf:10:
            Failed to resolve user 'systemd-network': No such process
  → O dpkg tentou criar diretórios com dono systemd-network, mas o
    usuário não existe no container. Inofensivo em ambientes Docker.

  [ERROR]   Failed to open connection to "system" message bus
  → D-Bus não está disponível no container. Serviços que dependem dele
    para notificar o systemd falham silenciosamente.

Uso:
  python3 ex21.py                      # análise completa
  python3 ex21.py --severity warning   # só warnings
  python3 ex21.py --severity error     # só erros
  python3 ex21.py --source dpkg        # filtra por subprocesso
  python3 ex21.py --session 2          # sessão apt específica
  python3 ex21.py --summary            # só o resumo, sem listagem
"""

import re
import os
import gzip
import glob
import argparse
from collections import defaultdict, Counter, namedtuple
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Argumentos
# ─────────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Busca erros e avisos gerados pelo apt/dpkg nos logs do sistema."
)
parser.add_argument(
    "--severity",
    choices=["error", "warning", "failed", "all"],
    default="all",
    help="Filtra por severidade (padrão: all)",
)
parser.add_argument(
    "--source",
    default=None,
    help="Filtra por subprocesso origem (ex: dpkg, update-alternatives)",
)
parser.add_argument(
    "--session", type=int, default=0, help="Exibe só a sessão N (1-based; 0 = todas)"
)
parser.add_argument(
    "--summary",
    action="store_true",
    help="Exibe só resumo, sem listagem de mensagens individuais",
)
parser.add_argument(
    "--since", default=None, help="Filtra sessões a partir de YYYY-MM-DD"
)
args = parser.parse_args()

SINCE = datetime.strptime(args.since, "%Y-%m-%d") if args.since else None

# ─────────────────────────────────────────────────────────────────────────────
# Padrões de detecção
#
# Cada padrão tem:
#   severity : "error" | "warning" | "failed"
#   regex    : o que casar na linha
#   source   : subprocesso emitente (extraído do texto ou fixo)
# ─────────────────────────────────────────────────────────────────────────────
DETECTORS = [
    # apt / dpkg erros explícitos  (E: no início)
    {
        "severity": "error",
        "regex": re.compile(r"^\s*E:\s+(?P<msg>.+)"),
        "source_fixed": "apt",
    },
    # dpkg: error ao configurar pacote
    {
        "severity": "error",
        "regex": re.compile(r"dpkg:\s+error\s+(?P<msg>.+)", re.I),
        "source_fixed": "dpkg",
    },
    # Failed to open D-Bus / message bus
    {
        "severity": "error",
        "regex": re.compile(r"(?P<msg>Failed to (?:open connection|connect).+bus.+)"),
        "source_fixed": "dbus",
    },
    # Warnings explícitos  (W: no início)
    {
        "severity": "warning",
        "regex": re.compile(r"^\s*W:\s+(?P<msg>.+)"),
        "source_fixed": "apt",
    },
    # update-alternatives: warning: ...
    {
        "severity": "warning",
        "regex": re.compile(r"(?P<src>update-alternatives):\s+warning:\s+(?P<msg>.+)"),
        "source_group": "src",
    },
    # dpkg: warning: ...
    {
        "severity": "warning",
        "regex": re.compile(
            r"(?P<src>dpkg(?:-[a-z]+)?):\s+warning:\s+(?P<msg>.+)", re.I
        ),
        "source_group": "src",
    },
    # invoke-rc.d: warning / could not determine ...
    {
        "severity": "warning",
        "regex": re.compile(
            r"(?P<src>invoke-rc\.d):\s+(?P<msg>(?:warning|could not).+)", re.I
        ),
        "source_group": "src",
    },
    # tmpfiles.d: Failed to resolve user/group
    {
        "severity": "failed",
        "regex": re.compile(
            r"(?P<src>/usr/lib/tmpfiles\.d/[^:]+):\d+:\s+"
            r"(?P<msg>Failed to resolve (?:user|group) .+)"
        ),
        "source_group": "src",
    },
    # Genérico: qualquer linha com "failed" isolado (não parte de palavra)
    {
        "severity": "failed",
        "regex": re.compile(
            r"^(?!.*(tmpfiles|update-alternatives|dpkg))"  # evita duplicatas
            r"(?P<msg>.+\bfailed\b.+)",
            re.I,
        ),
        "source_fixed": "apt",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Leitura do history.log para mapear sessão → comando apt
# ─────────────────────────────────────────────────────────────────────────────
# { "2026-02-18 19:54:00" → "apt-get install ..." }
session_cmd = {}

APT_START = re.compile(r"^Start-Date:\s+(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
APT_CMD = re.compile(r"^Commandline:\s+(?P<cmd>.+)")


def read_history(path):
    if not os.path.exists(path):
        return
    cur_dt = None
    with open(path, "rt", errors="replace") as f:
        for line in f:
            m = APT_START.match(line)
            if m:
                cur_dt = m.group("dt").strip()
                continue
            m = APT_CMD.match(line)
            if m and cur_dt:
                parts = m.group("cmd").strip().split()
                binary = os.path.basename(parts[0]) if parts else "apt"
                actions = [p for p in parts[1:] if not p.startswith("-")][:3]
                session_cmd[cur_dt] = f"{binary} {' '.join(actions)}".strip()
                cur_dt = None


read_history("/var/log/apt/history.log")
for gz in sorted(glob.glob("/var/log/apt/history.log.*.gz")):
    read_history(gz)  # simplificado — gzip seria igual ao ex anterior

# ─────────────────────────────────────────────────────────────────────────────
# Leitura e parsing do term.log
# ─────────────────────────────────────────────────────────────────────────────
LOG_START = re.compile(r"^Log started:\s+(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
LOG_END = re.compile(r"^Log ended:\s+(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

Entry = namedtuple(
    "Entry",
    [
        "session_n",
        "session_dt",
        "session_cmd",
        "line_num",
        "severity",
        "source",
        "msg",
        "raw",
    ],
)

sessions = []  # lista de dicts com metadados de cada sessão
entries = []  # todas as mensagens de erro/warning


def process_term_log(path):
    if not os.path.exists(path):
        return
    gz = path.endswith(".gz")
    opener = gzip.open if gz else open

    with opener(path, "rt", errors="replace") as f:
        all_lines = f.readlines()

    cur_session = None
    session_counter = len(sessions)

    for lineno, raw in enumerate(all_lines, 1):
        line = raw.rstrip("\n").replace("\r", "")

        # Início de sessão
        m = LOG_START.match(line)
        if m:
            session_counter += 1
            dt_str = m.group("dt").strip()
            try:
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = None
            # Correlaciona com history.log
            cmd = None
            for key in session_cmd:
                # history.log às vezes tem segundos diferentes — tolera ±5s
                try:
                    hdt = datetime.strptime(key, "%Y-%m-%d %H:%M:%S")
                    if dt and abs((hdt - dt).total_seconds()) < 10:
                        cmd = session_cmd[key]
                        break
                except ValueError:
                    pass
            cur_session = {
                "n": session_counter,
                "dt": dt_str,
                "dt_obj": dt,
                "cmd": cmd or "apt",
                "errors": 0,
                "warnings": 0,
                "failed": 0,
            }
            sessions.append(cur_session)
            continue

        # Fim de sessão
        if LOG_END.match(line):
            cur_session = None
            continue

        if cur_session is None:
            continue

        # Filtro de data
        if SINCE and cur_session["dt_obj"] and cur_session["dt_obj"] < SINCE:
            continue

        # Filtro de sessão
        if args.session and cur_session["n"] != args.session:
            continue

        # Testa cada detector na linha
        for det in DETECTORS:
            m = det["regex"].search(line)
            if not m:
                continue

            sev = det["severity"]

            # Filtro de severidade
            if args.severity != "all" and sev != args.severity:
                break  # este detector não serve mas pode haver outro

            # Extrai source
            if "source_group" in det:
                try:
                    source = m.group(det["source_group"])
                    source = os.path.basename(source)  # /usr/lib/... → conf
                except IndexError:
                    source = det.get("source_fixed", "apt")
            else:
                source = det.get("source_fixed", "apt")

            # Filtro de source
            if args.source and args.source.lower() not in source.lower():
                break

            # Extrai msg
            try:
                msg = m.group("msg").strip()
            except IndexError:
                msg = line.strip()

            # Ignora linhas em branco
            if not msg:
                break

            entries.append(
                Entry(
                    session_n=cur_session["n"],
                    session_dt=cur_session["dt"],
                    session_cmd=cur_session["cmd"],
                    line_num=lineno,
                    severity=sev,
                    source=source,
                    msg=msg,
                    raw=line,
                )
            )

            # Atualiza contadores da sessão
            cur_session[sev] = cur_session.get(sev, 0) + 1
            break  # uma linha → um detector


process_term_log("/var/log/apt/term.log")
for gz in sorted(glob.glob("/var/log/apt/term.log.*.gz")):
    process_term_log(gz)

# ─────────────────────────────────────────────────────────────────────────────
# Relatório
# ─────────────────────────────────────────────────────────────────────────────
SEV_COLOR = {
    "error": "\033[91m",  # vermelho
    "warning": "\033[93m",  # amarelo
    "failed": "\033[95m",  # magenta
}
SEV_ICON = {
    "error": "🔴",
    "warning": "🟡",
    "failed": "🟠",
}
RESET = "\033[0m"
BOLD = "\033[1m"
GRAY = "\033[90m"
CYAN = "\033[96m"

SEP = "═" * 68
SEP2 = "─" * 52

print(SEP)
print("   ERROS E AVISOS DO SERVIÇO apt/dpkg")
print(SEP)
print(f"  Serviço  : apt  (apt-get, dpkg, update-alternatives)")
print(f"  Log      : /var/log/apt/term.log")
print(f"  Sessões  : {len(sessions)} encontradas")
print(
    f"  Filtro   : severidade={args.severity}"
    + (f"  source={args.source}" if args.source else "")
    + (f"  sessão={args.session}" if args.session else "")
)
print(SEP)

# ── Resumo por sessão ─────────────────────────────────────────────
print(
    f"\n{'SESSÃO':<9} {'DATA/HORA':<22} {'COMANDO':<38} {'ERR':>4} {'WARN':>5} {'FAIL':>5}"
)
print(SEP2)

for s in sessions:
    total = s["errors"] + s["warnings"] + s["failed"]
    flag = " ◄" if total > 0 else ""
    cmd_disp = (s["cmd"][:36] + "…") if len(s["cmd"]) > 37 else s["cmd"]
    print(
        f"  #{s['n']:<6} {s['dt']:<22} {cmd_disp:<38}"
        f" {s['errors']:>4} {s['warnings']:>5} {s['failed']:>5}{flag}"
    )

if not entries:
    print(f"\n  {'─' * 55}")
    print(f"  ✅  Nenhuma mensagem de erro ou aviso encontrada")
    print(f"      com os filtros aplicados.")
    print(SEP)
    raise SystemExit(0)

# ── Listagem detalhada ────────────────────────────────────────────
if not args.summary:
    print(f"\n{SEP}")
    print(f"  MENSAGENS DETALHADAS ({len(entries)} total)")
    print(SEP)

    cur_session_n = None
    for e in entries:
        # Cabeçalho de sessão
        if e.session_n != cur_session_n:
            cur_session_n = e.session_n
            s = next((x for x in sessions if x["n"] == e.session_n), {})
            print(f"\n  {'─' * 60}")
            print(
                f"  {CYAN}{BOLD}📦 Sessão #{e.session_n}"
                f"  {e.session_dt}"
                f"  [{e.session_cmd}]{RESET}"
            )
            print(f"  {'─' * 60}")

        color = SEV_COLOR.get(e.severity, "")
        icon = SEV_ICON.get(e.severity, "❓")

        print(
            f"\n  {icon} {color}{BOLD}{e.severity.upper()}{RESET}"
            f"  {GRAY}(linha {e.line_num}){RESET}"
        )
        print(f"  {GRAY}Origem : {e.source}{RESET}")
        # Quebra msg longa em múltiplas linhas
        msg_words = e.msg.split()
        line_buf = "  Mensagem: "
        for word in msg_words:
            if len(line_buf) + len(word) > 78:
                print(line_buf)
                line_buf = "             "
            line_buf += word + " "
        if line_buf.strip():
            print(line_buf)

# ── Resumo por severidade ─────────────────────────────────────────
print(f"\n{SEP}")
print(f"  RESUMO POR SEVERIDADE")
print(SEP)

by_sev = Counter(e.severity for e in entries)
total = len(entries)
for sev in ["error", "warning", "failed"]:
    count = by_sev.get(sev, 0)
    if count == 0:
        continue
    pct = count / total * 100
    bar = "█" * int(count / max(by_sev.values()) * 25)
    color = SEV_COLOR.get(sev, "")
    icon = SEV_ICON.get(sev, "")
    print(f"  {icon} {color}{sev.upper():<10}{RESET} {count:>5}  ({pct:>4.1f}%)  {bar}")

# ── Resumo por subprocesso de origem ─────────────────────────────
print(f"\n{SEP}")
print(f"  MENSAGENS POR SUBPROCESSO (quem gerou o erro)")
print(SEP)
print(f"\n  {'SUBPROCESSO':<35} {'TOTAL':>6}  {'ERR':>5}  {'WARN':>5}  {'FAIL':>5}")
print(f"  {'─' * 60}")

by_src = defaultdict(lambda: Counter())
for e in entries:
    by_src[e.source][e.severity] += 1

for src, counts in sorted(by_src.items(), key=lambda x: -sum(x[1].values())):
    total_src = sum(counts.values())
    bar = "█" * min(total_src, 20)
    print(
        f"  {src:<35} {total_src:>6}"
        f"  {counts.get('error', 0):>5}"
        f"  {counts.get('warning', 0):>5}"
        f"  {counts.get('failed', 0):>5}"
        f"  {bar}"
    )

# ── Padrões mais frequentes ───────────────────────────────────────
print(f"\n{SEP}")
print(f"  PADRÕES MAIS FREQUENTES")
print(SEP)


# Agrupa msgs similares cortando após a parte variável
def normalize_msg(msg):
    # Remove paths específicos: /usr/share/man/man1/lzma.1.gz → <path>
    msg = re.sub(r"/\S+\.gz\b", "<arquivo.gz>", msg)
    msg = re.sub(r"/\S+\.conf:\d+", "<conf:N>", msg)
    msg = re.sub(r"'[^']+' ", "'<nome>' ", msg)
    return msg[:80]


pattern_counts = Counter(normalize_msg(e.msg) for e in entries)
for pattern, count in pattern_counts.most_common(8):
    icon = SEV_ICON.get(
        next(
            (e.severity for e in entries if normalize_msg(e.msg) == pattern), "warning"
        ),
        "❓",
    )
    print(f"  {icon} {count:>4}x  {pattern}")

# ── Totais finais ─────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TOTAIS")
print(SEP)
print(f"  Total de mensagens          : {len(entries)}")
print(
    f"  Sessões com problemas       : "
    f"{sum(1 for s in sessions if s['errors'] + s['warnings'] + s['failed'] > 0)}"
    f" de {len(sessions)}"
)
print(f"  Subprocessos envolvidos     : {len(by_src)}")
print(SEP)
print()
print("  Dica: para filtrar por severidade ou subprocesso:")
print("    python3 ex21.py --severity error")
print("    python3 ex21.py --severity warning")
print("    python3 ex21.py --source update-alternatives")
print("    python3 ex21.py --session 4  # sessão específica")
print(SEP)
