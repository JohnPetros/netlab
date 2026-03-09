#!/usr/bin/env python3
"""
Exercício 17 - Frequência de mensagens por serviço (ordem decrescente)
Arquivos varridos: todos os logs em /var/log (recursivo)

O script detecta automaticamente o formato de cada arquivo e extrai
o nome do processo/serviço gerador de cada linha.

Formatos suportados e como o serviço é extraído:

  1. Syslog BSD — syslog, auth.log, kern.log
     "Mar  8 21:18:09 host sshd[766]: Server listening..."
                           ^^^^
     Regex: r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([^\[:\s]+)"

  2. dpkg.log — operações de pacotes
     "2026-02-10 14:05:33 install base-passwd:amd64 ..."
     Serviço = "dpkg" (processo que escreve esse log)

  3. apt/history.log — histórico de comandos apt
     "Commandline: apt-get install -y curl"
     Serviço = "apt-get" / "apt" (extraído do Commandline)

  4. Apache error.log
     "[Sun Mar 08 21:10:28] [mpm_event:notice] [pid 23] AH00489: ..."
     Serviço = "apache2" + módulo entre colchetes (ex: mpm_event)

  5. Outros logs de texto — agrupados como "outros"

Uso:
  python3 ex17.py                    # varre /var/log completo
  python3 ex17.py --top 20           # mostra top 20 (padrão: 15)
  python3 ex17.py --dir /var/log     # diretório específico
  python3 ex17.py --no-recurse       # só o diretório raiz
  python3 ex17.py --show-files       # detalha quais arquivos cada serviço usa
"""

import re
import os
import gzip
import glob
import argparse
from collections import Counter, defaultdict

# -------------------------------------------------------------------
# Argumentos
# -------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Conta frequência de mensagens por serviço nos logs."
)
parser.add_argument("--dir", default="/var/log")
parser.add_argument("--top", type=int, default=15)
parser.add_argument("--no-recurse", action="store_true")
parser.add_argument(
    "--show-files",
    action="store_true",
    help="Exibe quais arquivos de log cada serviço usa",
)
args = parser.parse_args()

# -------------------------------------------------------------------
# Regex por formato de log
# -------------------------------------------------------------------

# Formato BSD: "Mar  8 21:18:09 hostname processo[pid]: ..."
#              "Mar  8 21:18:09 hostname processo: ..."
SYSLOG_BSD = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
    r"(?P<proc>[a-zA-Z0-9_\-\.\/]+)"  # nome do processo
    r"(?:\[\d+\])?[:\s]"
)

# Formato dpkg.log: "2026-02-10 14:05:33 <acao> ..."
DPKG_LINE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"(?P<action>install|upgrade|remove|purge|configure|status|startup|trigproc)"
)

# Formato apt/history.log
APT_CMDLINE = re.compile(r"^Commandline:\s+(?P<cmd>\S+)")

# Formato Apache error.log: "[...] [module:level] [pid N] ..."
APACHE_LINE = re.compile(r"^\[.*?\]\s+\[(?P<module>[a-zA-Z0-9_]+):[a-z]+\]")

# Formato systemd/journald exportado: "SYSLOG_IDENTIFIER=<service>"
SYSTEMD_ID = re.compile(r"^SYSLOG_IDENTIFIER=(?P<svc>.+)")


# -------------------------------------------------------------------
# Detecta o tipo de arquivo pelo nome e primeiras linhas
# -------------------------------------------------------------------
def detect_format(path, sample_lines):
    basename = os.path.basename(path).lower()

    if "dpkg" in basename:
        return "dpkg"
    if "history" in basename and "apt" in path:
        return "apt_history"
    if "apache" in path or "apache" in basename or "httpd" in basename:
        return "apache"

    # Verifica pelo conteúdo das primeiras linhas
    for line in sample_lines[:5]:
        if SYSLOG_BSD.match(line):
            return "syslog_bsd"
        if DPKG_LINE.match(line):
            return "dpkg"
        if APACHE_LINE.match(line):
            return "apache"
        if line.startswith("Start-Date:") or line.startswith("Commandline:"):
            return "apt_history"

    return "unknown"


# -------------------------------------------------------------------
# Extrai serviço de uma linha dado o formato detectado
# -------------------------------------------------------------------
def extract_service(line, fmt, path):
    """Retorna string com o nome do serviço ou None se não identificado."""

    if fmt == "syslog_bsd":
        m = SYSLOG_BSD.match(line)
        if m:
            proc = m.group("proc").strip()
            # Remove sufixos de path (ex: /usr/sbin/sshd → sshd)
            proc = os.path.basename(proc)
            # Normaliza: rsyslogd → rsyslog, sshd → sshd
            return proc if proc else None

    elif fmt == "dpkg":
        m = DPKG_LINE.match(line)
        if m:
            return "dpkg"

    elif fmt == "apt_history":
        m = APT_CMDLINE.match(line)
        if m:
            cmd = m.group("cmd")
            return os.path.basename(cmd)  # "apt-get", "apt", "dpkg"
        # Campos de ação também contam como atividade do apt
        for field in ("Install:", "Upgrade:", "Remove:", "Purge:", "Reinstall:"):
            if line.startswith(field):
                return "apt"
        return None

    elif fmt == "apache":
        m = APACHE_LINE.match(line)
        if m:
            return f"apache2/{m.group('module')}"
        return "apache2"

    elif fmt == "unknown":
        # Tenta BSD como último recurso
        m = SYSLOG_BSD.match(line)
        if m:
            return os.path.basename(m.group("proc").strip())

    return None


# -------------------------------------------------------------------
# Coleta arquivos para varredura
# -------------------------------------------------------------------
SKIP_DIRS = {"journal", "private"}
SKIP_EXTS = {".xz", ".bz2"}


def collect_files(root, recurse):
    files = []
    if recurse:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext not in SKIP_EXTS:
                    files.append(os.path.join(dirpath, name))
    else:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                ext = os.path.splitext(name)[1].lower()
                if ext not in SKIP_EXTS:
                    files.append(path)
    return sorted(files)


# -------------------------------------------------------------------
# Varredura principal
# -------------------------------------------------------------------
service_count = Counter()  # { service: total_lines }
service_files = defaultdict(set)  # { service: {arquivo1, arquivo2} }
file_stats = {}  # { path: {format, lines, services} }

files = collect_files(args.dir, not args.no_recurse)

total_lines = 0
total_files = 0
unknown_lines = 0

for path in files:
    is_gz = path.endswith(".gz")
    try:
        opener = gzip.open if is_gz else open
        with opener(path, "rt", errors="replace") as f:
            all_lines = f.readlines()

        if not all_lines:
            continue

        fmt = detect_format(path, all_lines)
        file_lines = 0
        file_services = Counter()

        for line in all_lines:
            line = line.rstrip("\n")
            if not line:
                continue

            total_lines += 1
            file_lines += 1

            svc = extract_service(line, fmt, path)
            if svc:
                service_count[svc] += 1
                service_files[svc].add(path)
                file_services[svc] += 1
            else:
                unknown_lines += 1

        file_stats[path] = {
            "format": fmt,
            "lines": file_lines,
            "top_svc": file_services.most_common(3),
        }
        total_files += 1

    except (PermissionError, UnicodeDecodeError):
        pass
    except Exception:
        pass

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 65
SEP2 = "-" * 50

FORMAT_LABEL = {
    "syslog_bsd": "syslog BSD",
    "dpkg": "dpkg.log",
    "apt_history": "apt history",
    "apache": "Apache",
    "unknown": "desconhecido",
}

print(SEP)
print("   FREQUÊNCIA DE MENSAGENS POR SERVIÇO")
print(SEP)
print(f"  Diretório : {args.dir}")
print(f"  Arquivos  : {total_files:,}")
print(f"  Linhas    : {total_lines:,}")
print(f"  Serviços  : {len(service_count):,} distintos")
print(SEP)

if not service_count:
    print("""
  Nenhum serviço identificado nos logs.

  Para gerar atividade e testar:
    sudo service ssh restart
    sudo service cron restart
    sudo apt install curl -y
    python3 ex17.py
""")
    raise SystemExit(0)

# ------- Ranking principal ----------------------------------------
top = service_count.most_common(args.top)
total_identified = sum(service_count.values())
max_count = top[0][1] if top else 1

print(
    f"\n  TOP {args.top} SERVIÇOS  (total: {total_identified:,} linhas identificadas)\n"
)
print(f"  {'#':>3}  {'SERVIÇO':<22} {'MSGS':>7}  {'%':>5}  PROPORÇÃO")
print(f"  {'─' * 3}  {'─' * 22}  {'─' * 7}  {'─' * 5}  {'─' * 25}")

for rank, (svc, count) in enumerate(top, 1):
    pct = count / total_identified * 100
    bar_w = int(count / max_count * 25)
    bar = "█" * bar_w
    # Ícone por tipo de serviço
    if any(x in svc for x in ("sshd", "ssh")):
        icon = "🔐"
    elif any(x in svc for x in ("apache", "http")):
        icon = "🌐"
    elif any(x in svc for x in ("dpkg", "apt")):
        icon = "📦"
    elif any(x in svc for x in ("kernel", "klog")):
        icon = "⚙"
    elif any(x in svc for x in ("cron", "systemd")):
        icon = "⏱"
    elif "rsyslog" in svc:
        icon = "📋"
    else:
        icon = "🔧"

    print(f"  {rank:>3}  {icon} {svc:<20} {count:>7,}  {pct:>4.1f}%  {bar}")

    # Exibe arquivos se pedido
    if args.show_files:
        for fpath in sorted(service_files[svc]):
            fname = os.path.relpath(fpath, args.dir)
            print(f"       └─ {fname}")

# ------- Distribuição por formato ---------------------------------
print(f"\n{SEP}")
print("  DISTRIBUIÇÃO POR FORMATO DE LOG")
print(SEP)

fmt_count = Counter()
fmt_lines = Counter()
for path, stats in file_stats.items():
    fmt_count[stats["format"]] += 1
    fmt_lines[stats["format"]] += stats["lines"]

print(f"\n  {'FORMATO':<18} {'ARQUIVOS':>8}  {'LINHAS':>8}")
print(f"  {'─' * 40}")
for fmt, cnt in fmt_count.most_common():
    label = FORMAT_LABEL.get(fmt, fmt)
    print(f"  {label:<18} {cnt:>8}  {fmt_lines[fmt]:>8,}")

# ------- Arquivos com mais atividade ------------------------------
print(f"\n{SEP}")
print("  ARQUIVOS COM MAIS ATIVIDADE")
print(SEP)

top_files = sorted(file_stats.items(), key=lambda x: -x[1]["lines"])[:8]
print(f"\n  {'LINHAS':>7}  {'FORMATO':<14}  ARQUIVO")
print(f"  {'─' * 55}")
for path, stats in top_files:
    label = FORMAT_LABEL.get(stats["format"], stats["format"])
    fname = os.path.relpath(path, args.dir)
    print(f"  {stats['lines']:>7,}  {label:<14}  {fname}")

# ------- Resumo final --------------------------------------------
print(f"\n{SEP}")
print("  RESUMO")
print(SEP)
if top:
    winner_svc, winner_cnt = top[0]
    pct = winner_cnt / total_identified * 100
    print(f"\n  🏆 Serviço mais ativo : {winner_svc}")
    print(f"     Mensagens          : {winner_cnt:,}  ({pct:.1f}% do total)")
    print(f"     Arquivos usados    : {len(service_files[winner_svc])}")

print(f"\n  Linhas identificadas  : {total_identified:,}")
print(f"  Linhas não mapeadas   : {unknown_lines:,}")
print(f"  Serviços distintos    : {len(service_count):,}")
print(SEP)
print()
print("  Dicas:")
print("    python3 ex17.py --top 30          # ranking maior")
print("    python3 ex17.py --show-files       # mostra arquivos por serviço")
print("    python3 ex17.py --no-recurse       # só /var/log sem subpastas")
print(SEP)
