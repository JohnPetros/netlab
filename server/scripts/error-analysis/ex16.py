#!/usr/bin/env python3
"""
Exercício 16 - Mensagens críticas: "critical", "fatal" ou "segfault"
Arquivos varridos: todos os logs em /var/log (recursivo), priorizando:

  /var/log/syslog        — logs gerais do sistema
  /var/log/kern.log      — mensagens do kernel (segfaults aparecem aqui)
  /var/log/auth.log      — autenticação
  /var/log/apache2/*.log — erros do Apache
  /var/log/dpkg.log      — pacotes
  ...e todos os outros arquivos .log e .gz encontrados

Exemplos reais dessas mensagens em produção:

  segfault (kern.log):
    Mar 8 14:00:01 host kernel: myapp[1234]: segfault at 0 ip 00007f...
    → processo acessou endereço de memória inválido; geralmente indica
      bug de programação (null pointer, buffer overflow, use-after-free)

  fatal (syslog/auth.log):
    Mar 8 14:00:05 host sshd[99]: fatal: Cannot bind any address.
    → serviço não conseguiu inicializar; erro irrecuperável

  critical (syslog):
    Mar 8 14:00:10 host kernel: ACPI: Fatal Error
    Mar 8 14:00:10 host myservice[55]: [CRITICAL] disk quota exceeded
    → severidade máxima; requer atenção imediata

Uso:
  python3 ex16.py                        # varre todos os logs
  python3 ex16.py --dir /var/log/apache2 # diretório específico
  python3 ex16.py --file /var/log/syslog # arquivo específico
  python3 ex16.py --words "error,warn"   # palavras customizadas
  python3 ex16.py --since 2026-02-18     # a partir de uma data
"""

import re
import os
import gzip
import glob
import argparse
from datetime import datetime
from collections import defaultdict, namedtuple

Match = namedtuple("Match", ["file", "line_num", "timestamp", "word", "raw"])

# -------------------------------------------------------------------
# Argumentos
# -------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Lista mensagens críticas nos logs do sistema."
)
parser.add_argument(
    "--dir", default="/var/log", help="Diretório raiz para varredura (padrão: /var/log)"
)
parser.add_argument("--file", default=None, help="Arquivo específico para analisar")
parser.add_argument(
    "--words",
    default="critical,fatal,segfault",
    help="Palavras-chave separadas por vírgula (padrão: critical,fatal,segfault)",
)
parser.add_argument(
    "--since", default=None, help="Filtra eventos a partir desta data YYYY-MM-DD"
)
parser.add_argument("--no-recurse", action="store_true", help="Não varre subdiretórios")
args = parser.parse_args()

# -------------------------------------------------------------------
# Palavras-chave → regex com word boundary
# -------------------------------------------------------------------
KEYWORDS = [w.strip() for w in args.words.split(",") if w.strip()]

PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in KEYWORDS) + r")\b", re.IGNORECASE
)

# Data mínima para filtro
SINCE_DATE = None
if args.since:
    try:
        SINCE_DATE = datetime.strptime(args.since, "%Y-%m-%d")
    except ValueError:
        print(f"[ERRO] Data inválida: '{args.since}'. Use YYYY-MM-DD.")
        raise SystemExit(1)

# -------------------------------------------------------------------
# Parsers de timestamp — suporta 3 formatos comuns
#
#   ISO  : "2026-02-10 14:05:33"       dpkg.log, syslog moderno
#   BSD  : "Mar  8 21:18:09"           syslog, auth.log, kern.log
#   Apache: "[Sun Mar 08 21:10:28.514287 2026]"  apache error.log
# -------------------------------------------------------------------
TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
TS_BSD = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
TS_APACHE = re.compile(r"\[(?:\w{3} )(\w{3} \d{2} \d{2}:\d{2}:\d{2})\.\d+ (\d{4})\]")

CURRENT_YEAR = datetime.now().year


def extract_timestamp(line):
    """Tenta extrair datetime da linha. Retorna datetime ou None."""
    m = TS_ISO.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    m = TS_BSD.match(line)
    if m:
        try:
            dt = datetime.strptime(f"{CURRENT_YEAR} {m.group(1)}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = dt.replace(year=CURRENT_YEAR - 1)
            return dt
        except ValueError:
            pass

    m = TS_APACHE.search(line)
    if m:
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%b %d %H:%M:%S %Y")
        except ValueError:
            pass

    return None


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "—"


# -------------------------------------------------------------------
# Descobre arquivos para varrer
# -------------------------------------------------------------------
SKIP_DIRS = {"journal", "private"}  # binários / sem permissão
SKIP_EXTS = {".xz", ".bz2", ".bin"}  # formatos não suportados


def collect_files(root, recurse=True):
    files = []
    if recurse:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                ext = os.path.splitext(name)[1].lower()
                if ext not in SKIP_EXTS:
                    files.append(path)
    else:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                ext = os.path.splitext(name)[1].lower()
                if ext not in SKIP_EXTS:
                    files.append(path)
    return sorted(files)


if args.file:
    files_to_scan = [args.file]
else:
    files_to_scan = collect_files(args.dir, recurse=not args.no_recurse)

# -------------------------------------------------------------------
# Varredura
# -------------------------------------------------------------------
matches = []  # lista de Match
files_scanned = 0
files_with_hits = 0
lines_scanned = 0
errors = []

for path in files_to_scan:
    is_gz = path.endswith(".gz")
    try:
        opener = gzip.open if is_gz else open
        file_hits = 0
        with opener(path, "rt", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                lines_scanned += 1
                line_clean = line.rstrip("\n")

                m = PATTERN.search(line_clean)
                if not m:
                    continue

                # Extrai timestamp para filtro de data
                dt = extract_timestamp(line_clean)

                # Aplica filtro --since
                if SINCE_DATE and dt and dt < SINCE_DATE:
                    continue

                # Palavra que casou (pode ser mais de uma na linha)
                words_found = list({w.lower() for w in PATTERN.findall(line_clean)})

                matches.append(
                    Match(
                        file=path,
                        line_num=line_num,
                        timestamp=fmt_ts(dt),
                        word=", ".join(sorted(words_found)),
                        raw=line_clean.strip(),
                    )
                )
                file_hits += 1

        files_scanned += 1
        if file_hits:
            files_with_hits += 1

    except PermissionError:
        errors.append(f"sem permissão: {path}")
    except Exception as e:
        errors.append(f"{path}: {e}")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 68
SEP2 = "-" * 52

WORD_ICON = {
    "critical": "🔴",
    "fatal": "💀",
    "segfault": "💥",
}

print(SEP)
print("   MENSAGENS CRÍTICAS NOS LOGS DO SISTEMA")
print(SEP)
print(f"  Palavras buscadas : {', '.join(KEYWORDS)}")
print(f"  Diretório varrido : {args.dir if not args.file else args.file}")
if SINCE_DATE:
    print(f"  A partir de       : {args.since}")
print(f"  Arquivos lidos    : {files_scanned:,}")
print(f"  Linhas analisadas : {lines_scanned:,}")
print(SEP)

if not matches:
    print(f"""
  Nenhuma ocorrência de  {" / ".join(f'"{k}"' for k in KEYWORDS)}
  encontrada nos logs.

  Isso indica um sistema saudável — ótima notícia!

  Para simular eventos e testar o script:

    # Gera um segfault manual (processo temporário)
    python3 -c "
import ctypes, sys
ctypes.string_at(0)   # acessa endereço NULL → segfault
" 2>/dev/null || true
    # O kernel registra em /var/log/kern.log se rsyslog estiver ativo

    # Simula linha crítica no syslog
    logger -p user.crit "CRITICAL: test message from ex16"
    logger -p user.emerg "fatal: test fatal message"
    python3 ex16.py   # roda novamente
""")
    if errors:
        print("  Arquivos inacessíveis:")
        for e in errors[:5]:
            print(f"    • {e}")
    raise SystemExit(0)

# Agrupa por arquivo para exibição organizada
by_file = defaultdict(list)
for m in matches:
    by_file[m.file].append(m)

# ------- Listagem por arquivo ------------------------------------
for filepath, file_matches in sorted(by_file.items()):
    print(f"\n📄 {filepath}  ({len(file_matches)} ocorrência(s))")
    print(f"  {SEP2}")
    for m in file_matches:
        icons = " ".join(WORD_ICON.get(w.strip(), "⚠") for w in m.word.split(","))
        print(f"\n  {icons} [{m.timestamp}]  linha {m.line_num}")
        # Destaca as palavras na linha (em maiúsculas)
        highlighted = PATTERN.sub(lambda x: x.group(0).upper(), m.raw)
        print(f"  {highlighted[:110]}")

# ------- Resumo por palavra --------------------------------------
print(f"\n{SEP}")
print("  RESUMO POR PALAVRA-CHAVE")
print(SEP)

word_counts = defaultdict(int)
for m in matches:
    for w in m.word.split(", "):
        word_counts[w.strip()] += 1

for word, count in sorted(word_counts.items(), key=lambda x: -x[1]):
    icon = WORD_ICON.get(word, "⚠")
    bar = "█" * min(count, 35)
    print(f"  {icon} {word:<12} {count:>5}x  {bar}")

# ------- Resumo por arquivo --------------------------------------
print(f"\n{SEP}")
print("  RESUMO POR ARQUIVO")
print(SEP)
for filepath, file_matches in sorted(by_file.items(), key=lambda x: -len(x[1])):
    fname = os.path.relpath(filepath, "/var/log")
    print(f"  {len(file_matches):>5}x  {fname}")

print(f"\n{SEP}")
print(f"  Total de ocorrências : {len(matches)}")
print(f"  Arquivos afetados    : {files_with_hits}")
print(SEP)
print()
print("  Dica: para monitorar em tempo real:")
print(f"    tail -f /var/log/syslog /var/log/kern.log | grep -iE '{args.words}'")
print(SEP)
