#!/usr/bin/env python3
"""
Exercício 22 — Processos terminados com erro grave: segfault e killed
Arquivo principal: /var/log/kern.log  (fallback: syslog)

Por que kern.log?
  Eventos de crash de processos são registrados pelo kernel Linux e
  encaminhados via printk() → rsyslog → /var/log/kern.log.
  O syslog também os contém (misturado com outros serviços), mas
  kern.log é a fonte canônica para eventos de nível kernel.

Tipos de evento detectados e como cada um aparece no log:

  ┌─────────────────┬──────────────────────────────────────────────────────┐
  │ SEGFAULT        │ kernel/signal.c — processo acessou endereço de        │
  │                 │ memória inválido (null pointer, use-after-free, etc.) │
  │                 │                                                        │
  │ Linha real:     │ kernel: bash[1234]: segfault at 0 ip 00007f… error 4  │
  │                 │   ↑processo↑ ↑pid↑  ↑endereço↑        ↑código erro↑  │
  │                 │                                                        │
  │ Código de erro: │ bit 0: page not present (0=não mapeado, 1=sem perm.) │
  │                 │ bit 1: escrita (0=leitura, 1=escrita)                  │
  │                 │ bit 2: modo (0=kernel, 1=userspace)                    │
  │                 │ bit 3: reserved bit violation                          │
  │                 │ bit 4: instruction fetch (execução NX)                 │
  ├─────────────────┼──────────────────────────────────────────────────────┤
  │ OOM KILLED      │ mm/oom_kill.c — sistema ficou sem memória e o kernel  │
  │                 │ escolheu um processo para matar (OOM killer)           │
  │                 │                                                        │
  │ Linha real:     │ Out of memory: Killed process 3301 (firefox)          │
  │                 │ total-vm:3456789kB, anon-rss:2345678kB                │
  │                 │                                                        │
  │ oom_score_adj:  │ -1000 = nunca mate este processo (ex: init)           │
  │                 │      0 = score padrão                                  │
  │                 │   +999 = mate este primeiro (ex: browsers)             │
  ├─────────────────┼──────────────────────────────────────────────────────┤
  │ KILLED          │ Processo morto por sinal SIGKILL (9) diretamente      │
  │                 │ — pode ser OOM killer, systemd, ou kill manual        │
  │                 │ Linha: Killed process 4567 (myapp) total-vm:…        │
  ├─────────────────┼──────────────────────────────────────────────────────┤
  │ GEN. PROT. FAULT│ Trap do processador por instrução ilegal, acesso a   │
  │                 │ endereço não-canônico (possível exploit ou bug grave)  │
  │ Linha real:     │ nginx[9012]: general protection fault, probably for   │
  │                 │ non-canonical address 0x4141414141414141              │
  └─────────────────┴──────────────────────────────────────────────────────┘

Uso:
  python3 ex22.py                        # varre /var/log automaticamente
  python3 ex22.py --log /tmp/kern.log    # arquivo específico
  python3 ex22.py --type segfault        # só segfaults
  python3 ex22.py --type oom             # só OOM kills
  python3 ex22.py --proc firefox         # filtra por processo
  python3 ex22.py --since 2026-02-10     # a partir de uma data
  python3 ex22.py --explain              # explica cada código de erro
"""

import re
import os
import gzip
import glob
import argparse
from datetime import datetime
from collections import defaultdict, Counter, namedtuple

# ─────────────────────────────────────────────────────────────────────────────
# Argumentos
# ─────────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Lista processos terminados por segfault ou killed nos logs."
)
parser.add_argument(
    "--log",
    default=None,
    help="Arquivo de log específico (padrão: auto-detecta em /var/log)",
)
parser.add_argument(
    "--type",
    choices=["segfault", "oom", "killed", "gpf", "all"],
    default="all",
    help="Tipo de evento (padrão: all)",
)
parser.add_argument(
    "--proc", default=None, help="Filtra por nome de processo (parcial)"
)
parser.add_argument("--since", default=None, help="Filtra a partir de YYYY-MM-DD")
parser.add_argument(
    "--explain", action="store_true", help="Explica o código de erro de cada segfault"
)
args = parser.parse_args()

SINCE = None
if args.since:
    try:
        SINCE = datetime.strptime(args.since, "%Y-%m-%d")
    except ValueError:
        print(f"[ERRO] Data inválida: {args.since!r}. Use YYYY-MM-DD.")
        raise SystemExit(1)

CURRENT_YEAR = datetime.now().year

# ─────────────────────────────────────────────────────────────────────────────
# Detectores — cada um captura um tipo de evento de crash
# ─────────────────────────────────────────────────────────────────────────────

# 1. SEGFAULT
#    kernel: PROC[PID]: segfault at ADDR ip IP sp SP error CODE [in LIB[...]]
RE_SEGFAULT = re.compile(
    r"kernel:\s+(?:\[[\d\s.]+\]\s+)?"
    r"(?P<proc>[^\[:\s]+)\[(?P<pid>\d+)\]:\s+segfault at (?P<addr>\S+)"
    r"\s+ip (?P<ip>\S+)"
    r"(?:.*\berror (?P<errcode>\d+))?"
    r"(?:.*\bin (?P<lib>[^\[]+))?"
)

# 2. OOM KILLED — linha "Out of memory: Killed process N (name) ..."
RE_OOM = re.compile(
    r"kernel:\s+(?:\[[\d\s.]+\]\s+)?"
    r"Out of memory:\s+Killed process (?P<pid>\d+)\s+\((?P<proc>[^)]+)\)"
    r".*?total-vm:(?P<total_vm>\d+)kB"
    r"(?:.*?anon-rss:(?P<anon_rss>\d+)kB)?"
    r"(?:.*?oom_score_adj:(?P<oom_adj>-?\d+))?"
)

# 3. OOM-KILL trigger — linha "oom-kill:constraint=...,task=NAME,pid=N,uid=N"
RE_OOM_TRIGGER = re.compile(
    r"kernel:\s+(?:\[[\d\s.]+\]\s+)?"
    r"oom-kill:.*?task=(?P<proc>[^,]+),pid=(?P<pid>\d+),uid=(?P<uid>\d+)"
)

# 4. KILLED (OOM ou sinal) — sem "Out of memory:" explícito
RE_KILLED = re.compile(
    r"kernel:\s+(?:\[[\d\s.]+\]\s+)?"
    r"Killed process (?P<pid>\d+)\s+\((?P<proc>[^)]+)\)"
    r"(?:.*?total-vm:(?P<total_vm>\d+)kB)?"
)

# 5. GENERAL PROTECTION FAULT
RE_GPF = re.compile(
    r"kernel:\s+(?:\[[\d\s.]+\]\s+)?"
    r"(?:(?P<proc>[^\[:\s]+)\[(?P<pid>\d+)\]:?\s+)?"
    r"general protection fault"
    r"(?:.*?address (?P<addr>0x[0-9a-fA-F]+))?"
)

# Timestamp BSD: "Mar  8 21:00:01" ou "Feb 10 14:00:01"
RE_TS = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

Event = namedtuple(
    "Event", ["etype", "timestamp", "proc", "pid", "extra", "raw", "file", "lineno"]
)


def parse_ts(ts_str):
    """Converte timestamp BSD em datetime, assumindo ano atual."""
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        if dt > datetime.now():
            dt = dt.replace(year=CURRENT_YEAR - 1)
        return dt
    except ValueError:
        return None


def fmt_kb(kb_str):
    """Formata kilobytes em unidade legível."""
    if not kb_str:
        return "N/A"
    kb = int(kb_str)
    if kb >= 1_048_576:
        return f"{kb / 1_048_576:.1f} GB"
    if kb >= 1_024:
        return f"{kb / 1_024:.1f} MB"
    return f"{kb} KB"


def decode_segfault_error(code_str):
    """Decodifica o código de erro de segfault (campo 'error N' do kernel)."""
    if not code_str:
        return "código desconhecido"
    code = int(code_str)
    parts = []
    parts.append("página não mapeada" if not (code & 1) else "sem permissão de acesso")
    parts.append("escrita" if (code & 2) else "leitura")
    parts.append("modo usuário" if (code & 4) else "modo kernel")
    if code & 8:
        parts.append("violação de bit reservado")
    if code & 16:
        parts.append("execução de memória não-executável (NX)")
    return ", ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Coleta arquivos para varrer
# ─────────────────────────────────────────────────────────────────────────────
SKIP_DIRS = {"journal", "private"}
SKIP_EXTS = {".xz", ".bz2"}


def get_log_files():
    """Prioriza kern.log, fallback para syslog, fallback para todos."""
    if args.log:
        return [args.log]

    priority = []
    for base in ["/var/log/kern.log", "/var/log/syslog"]:
        for path in [base, base + ".1"] + sorted(glob.glob(base + ".*.gz")):
            if os.path.exists(path) and os.path.getsize(path) > 0:
                priority.append(path)

    if priority:
        return priority

    # Fallback: todos os arquivos de texto em /var/log
    all_files = []
    for root, dirs, files in os.walk("/var/log"):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in SKIP_EXTS:
                all_files.append(os.path.join(root, f))
    return sorted(all_files)


# ─────────────────────────────────────────────────────────────────────────────
# Varredura principal
# ─────────────────────────────────────────────────────────────────────────────
events = []
files_scanned = 0
lines_scanned = 0

# PIDs de OOM-trigger já vistos — evita duplicar com a linha "Out of memory:"
oom_trigger_pids = set()

for path in get_log_files():
    is_gz = path.endswith(".gz")
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            file_lines = f.readlines()
    except (PermissionError, OSError):
        continue

    files_scanned += 1
    for lineno, raw in enumerate(file_lines, 1):
        line = raw.rstrip("\n").replace("\r", "")
        lines_scanned += 1

        # Extrai timestamp
        ts_m = RE_TS.match(line)
        ts = ts_m.group("ts") if ts_m else ""
        dt = parse_ts(ts)

        # Filtro de data
        if SINCE and dt and dt < SINCE:
            continue

        # ── OOM TRIGGER (registra o processo antes do "Out of memory:") ──
        m = RE_OOM_TRIGGER.search(line)
        if m and args.type in ("oom", "all"):
            proc = m.group("proc")
            pid = m.group("pid")
            uid = m.group("uid")
            if args.proc and args.proc.lower() not in proc.lower():
                pass
            else:
                oom_trigger_pids.add(pid)
                # Não cria evento aqui — aguarda linha "Out of memory:"
            continue

        # ── OOM KILLED ────────────────────────────────────────────────────
        m = RE_OOM.search(line)
        if m and args.type in ("oom", "all"):
            proc = m.group("proc")
            pid = m.group("pid")
            vm = fmt_kb(m.group("total_vm"))
            rss = fmt_kb(m.group("anon_rss")) if m.group("anon_rss") else "N/A"
            oom_adj = m.group("oom_adj") or "0"
            if not args.proc or args.proc.lower() in proc.lower():
                events.append(
                    Event(
                        etype="OOM",
                        timestamp=ts,
                        proc=proc,
                        pid=pid,
                        extra={
                            "total_vm": vm,
                            "anon_rss": rss,
                            "oom_adj": oom_adj,
                        },
                        raw=line.strip(),
                        file=os.path.basename(path),
                        lineno=lineno,
                    )
                )
            continue

        # ── KILLED (sem "Out of memory:" — outro tipo de kill) ───────────
        m = RE_KILLED.search(line)
        if m and "Out of memory" not in line and args.type in ("killed", "all"):
            proc = m.group("proc")
            pid = m.group("pid")
            vm = fmt_kb(m.group("total_vm")) if m.group("total_vm") else "N/A"
            if not args.proc or args.proc.lower() in proc.lower():
                events.append(
                    Event(
                        etype="KILLED",
                        timestamp=ts,
                        proc=proc,
                        pid=pid,
                        extra={"total_vm": vm},
                        raw=line.strip(),
                        file=os.path.basename(path),
                        lineno=lineno,
                    )
                )
            continue

        # ── SEGFAULT ──────────────────────────────────────────────────────
        m = RE_SEGFAULT.search(line)
        if m and args.type in ("segfault", "all"):
            proc = m.group("proc")
            pid = m.group("pid")
            addr = m.group("addr")
            ip = m.group("ip")
            errcode = m.group("errcode")
            lib = (m.group("lib") or "").strip()
            if not args.proc or args.proc.lower() in proc.lower():
                events.append(
                    Event(
                        etype="SEGFAULT",
                        timestamp=ts,
                        proc=proc,
                        pid=pid,
                        extra={
                            "addr": addr,
                            "ip": ip,
                            "errcode": errcode,
                            "lib": lib,
                            "decoded": decode_segfault_error(errcode)
                            if args.explain
                            else "",
                        },
                        raw=line.strip(),
                        file=os.path.basename(path),
                        lineno=lineno,
                    )
                )
            continue

        # ── GENERAL PROTECTION FAULT ──────────────────────────────────────
        m = RE_GPF.search(line)
        if m and args.type in ("gpf", "all"):
            proc = m.group("proc") or "kernel"
            pid = m.group("pid") or "?"
            addr = m.group("addr") or "?"
            if not args.proc or args.proc.lower() in proc.lower():
                events.append(
                    Event(
                        etype="GPF",
                        timestamp=ts,
                        proc=proc,
                        pid=pid,
                        extra={"addr": addr},
                        raw=line.strip(),
                        file=os.path.basename(path),
                        lineno=lineno,
                    )
                )
            continue

# ─────────────────────────────────────────────────────────────────────────────
# Relatório
# ─────────────────────────────────────────────────────────────────────────────
SEP = "═" * 68
SEP2 = "─" * 52

TYPE_ICON = {
    "SEGFAULT": "💥",
    "OOM": "🧠",
    "KILLED": "☠",
    "GPF": "⚡",
}
TYPE_COLOR = {
    "SEGFAULT": "\033[91m",  # vermelho
    "OOM": "\033[95m",  # magenta
    "KILLED": "\033[93m",  # amarelo
    "GPF": "\033[96m",  # ciano
}
RESET = "\033[0m"
BOLD = "\033[1m"
GRAY = "\033[90m"
GREEN = "\033[92m"

print(SEP)
print("   PROCESSOS TERMINADOS COM ERRO GRAVE — SEGFAULT / KILLED")
print(SEP)
print(f"  Fontes  : /var/log/kern.log  (fallback: syslog, todos os logs)")
print(f"  Tipos   : segfault, OOM killed, killed, general protection fault")
print(f"  Arquivos varridos : {files_scanned}")
print(f"  Linhas analisadas : {lines_scanned:,}")
if args.since:
    print(f"  Desde   : {args.since}")
if args.proc:
    print(f"  Processo: '{args.proc}'")
if args.type != "all":
    print(f"  Tipo    : {args.type}")
print(SEP)

# ── Sem resultados ────────────────────────────────────────────────
if not events:
    print(f"""
  {GREEN}✅  Nenhum crash detectado nos logs.{RESET}
  Sistema saudável ou kern.log vazio (comum em Docker/WSL).

  Para simular eventos e testar o script:

    # Segfault controlado (processo temporário — não afeta o sistema)
    python3 -c "import ctypes; ctypes.string_at(0)" 2>/dev/null || true
    # Após isso: dmesg | tail -5  (veja se gerou log no kern)

    # Arquivo de teste com eventos sintéticos reais
    python3 ex22.py --log /tmp/kern_test.log

  Em servidores de produção, kern.log e syslog terão eventos reais.
""")
    raise SystemExit(0)

# ── Listagem detalhada ────────────────────────────────────────────
print(f"\n  {len(events)} evento(s) encontrado(s)\n")

for e in events:
    color = TYPE_COLOR.get(e.etype, "")
    icon = TYPE_ICON.get(e.etype, "❓")

    print(f"  {'─' * 60}")
    print(
        f"  {icon} {BOLD}{color}{e.etype}{RESET}  "
        f"{BOLD}[{e.timestamp}]{RESET}  "
        f"arquivo: {GRAY}{e.file}:{e.lineno}{RESET}"
    )

    print(f"  {BOLD}Processo{RESET} : {color}{e.proc}{RESET}  (PID {e.pid})")

    # Detalhes específicos por tipo
    if e.etype == "SEGFAULT":
        ex = e.extra
        print(f"  {BOLD}Endereço{RESET} : {ex['addr']}  (IP: {ex['ip']})")
        if ex["lib"]:
            print(f"  {BOLD}Biblioteca{RESET}: {ex['lib']}")
        if ex["errcode"]:
            print(f"  {BOLD}Cód. erro{RESET} : {ex['errcode']}", end="")
            if args.explain and ex["decoded"]:
                print(f" → {ex['decoded']}", end="")
            print()

    elif e.etype == "OOM":
        ex = e.extra
        print(f"  {BOLD}Memória VM {RESET}: {ex['total_vm']}")
        print(f"  {BOLD}Memória RSS{RESET}: {ex['anon_rss']}")
        adj = int(ex["oom_adj"])
        if adj > 500:
            adj_note = " (alvo preferencial do OOM killer)"
        elif adj < -500:
            adj_note = " (protegido — raramente morto)"
        else:
            adj_note = " (score padrão)"
        print(f"  {BOLD}OOM adj   {RESET}: {adj}{adj_note}")

    elif e.etype == "KILLED":
        ex = e.extra
        if ex["total_vm"] != "N/A":
            print(f"  {BOLD}Memória VM{RESET} : {ex['total_vm']}")

    elif e.etype == "GPF":
        ex = e.extra
        print(f"  {BOLD}Endereço{RESET}: {ex['addr']}")
        if ex["addr"] != "?" and "41414141" in ex["addr"]:
            print(
                f"  {BOLD}{color}⚠  Padrão 0x41414141 detectado — "
                f"possível buffer overflow / exploit!{RESET}"
            )

    print(f"  {GRAY}LOG: {e.raw[:90]}{RESET}")

# ── Resumo por tipo ────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"  RESUMO POR TIPO DE EVENTO")
print(SEP)

by_type = Counter(e.etype for e in events)
total = len(events)
max_cnt = max(by_type.values())

print(f"\n  {'TIPO':<12} {'TOTAL':>6}  {'%':>5}  FREQUÊNCIA")
print(f"  {'─' * 50}")
for etype, count in by_type.most_common():
    icon = TYPE_ICON.get(etype, "❓")
    color = TYPE_COLOR.get(etype, "")
    pct = count / total * 100
    bar = "█" * int(count / max_cnt * 25)
    print(f"  {icon} {color}{etype:<10}{RESET} {count:>6}  {pct:>4.1f}%  {bar}")

# ── Processos mais afetados ────────────────────────────────────────
print(f"\n{SEP}")
print(f"  PROCESSOS COM MAIS EVENTOS")
print(SEP)

by_proc = Counter(e.proc for e in events)
print(f"\n  {'PROCESSO':<25} {'CRASHES':>8}  {'TIPOS'}")
print(f"  {'─' * 55}")
for proc, count in by_proc.most_common(10):
    types = ", ".join(sorted({e.etype for e in events if e.proc == proc}))
    bar = "█" * min(count, 20)
    print(f"  {proc:<25} {count:>8}  {types:<20}  {bar}")

# ── Linha do tempo ────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"  LINHA DO TEMPO")
print(SEP)
print(f"\n  {'TIMESTAMP':<20} {'TIPO':<10} {'PROCESSO':<20} {'PID':>6}  DETALHE")
print(f"  {'─' * 68}")
for e in events:
    icon = TYPE_ICON.get(e.etype, "❓")
    detail = ""
    if e.etype == "SEGFAULT":
        detail = f"addr={e.extra['addr']}"
    elif e.etype in ("OOM", "KILLED"):
        detail = f"vm={e.extra.get('total_vm', 'N/A')}"
    elif e.etype == "GPF":
        detail = f"addr={e.extra['addr']}"
    print(f"  {e.timestamp:<20} {icon}{e.etype:<9} {e.proc:<20} {e.pid:>6}  {detail}")

# ── Totais ────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  TOTAIS")
print(SEP)
print(f"  Total de crashes         : {len(events)}")
print(f"  Processos distintos      : {len(by_proc)}")
print(f"  Tipos distintos          : {len(by_type)}")
print(SEP)
print()
print("  Filtros disponíveis:")
print("    python3 ex22.py --type segfault")
print("    python3 ex22.py --type oom")
print("    python3 ex22.py --proc firefox")
print("    python3 ex22.py --explain            # decodifica erro de segfault")
print("    python3 ex22.py --log /tmp/kern_test.log  # arquivo sintético")
print(SEP)
