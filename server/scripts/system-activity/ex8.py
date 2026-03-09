#!/usr/bin/env python3
"""
Exercício 8 - Mensagens de erro e falha do kernel
Arquivos de log consultados (em ordem de prioridade):

  1. /var/log/kern.log  — dedicado exclusivamente a mensagens do kernel
  2. /var/log/syslog    — fallback: contém kernel + outros serviços

Em um Linux real, o kernel envia mensagens para o ring buffer interno
(acessível via `dmesg`) e o rsyslog as grava nesses arquivos com o
prefixo "kernel:".

Exemplos de linhas reais:

  Erro de hardware:
    Mar  8 10:01:22 host kernel: [12345.678] ata1.00: error: { UNC }
    Mar  8 10:01:22 host kernel: [12345.678] EXT4-fs error (device sda1): ...

  Aviso:
    Mar  8 10:01:22 host kernel: [12345.678] WARNING: CPU: 0 PID: 1 ...
    Mar  8 10:01:22 host kernel: [12345.678] usb 1-1: device descriptor read/64, error -71

  Falha crítica:
    Mar  8 10:01:22 host kernel: [12345.678] ACPI: Fatal Error
    Mar  8 10:01:22 host kernel: [12345.678] Oops: general protection fault

  Segfault:
    Mar  8 10:01:22 host kernel: [12345.678] myapp[1234]: segfault at 0 ip ...

Categorias detectadas (em ordem de severidade decrescente):
  CRITICAL  — fatal, panic, oops, bug, segfault, killed
  ERROR     — error, err, failed, failure
  WARNING   — warn, warning
  NOTICE    — notice, deprecated, invalid, denied, rejected
"""

import re
import os
from collections import defaultdict

# -------------------------------------------------------------------
# Arquivo de log — tenta kern.log primeiro, cai para syslog
# -------------------------------------------------------------------
CANDIDATES = ["/var/log/kern.log", "/var/log/syslog"]

LOG_FILE = None
for path in CANDIDATES:
    if os.path.exists(path):
        LOG_FILE = path
        break

# -------------------------------------------------------------------
# Categorias de severidade
#
# Cada categoria tem:
#   label    : nome exibido no relatório
#   icon     : ícone visual
#   keywords : palavras-chave buscadas (case-insensitive) na linha
#
# A ordem importa — uma linha é classificada na primeira categoria
# que casar, da mais grave para a menos grave.
# -------------------------------------------------------------------
CATEGORIES = [
    {
        "label": "CRITICAL",
        "icon": "💀",
        "pattern": re.compile(
            r"\b(fatal|panic|oops|bug:|segfault|killed|critical|corrupt|hang)\b",
            re.IGNORECASE,
        ),
    },
    {
        "label": "ERROR",
        "icon": "✘",
        "pattern": re.compile(
            r"\b(error|err\b|failed|failure|fault|exception|abort|bad|invalid dma)\b",
            re.IGNORECASE,
        ),
    },
    {
        "label": "WARNING",
        "icon": "⚠",
        "pattern": re.compile(r"\b(warn|warning)\b", re.IGNORECASE),
    },
    {
        "label": "NOTICE",
        "icon": "ℹ",
        "pattern": re.compile(
            r"\b(notice|deprecated|denied|rejected|refused|unexpected|unknown)\b",
            re.IGNORECASE,
        ),
    },
]

# Padrão que identifica linha do kernel (filtra outras fontes no syslog)
KERNEL_LINE = re.compile(r"\bkernel\b", re.IGNORECASE)

# -------------------------------------------------------------------
# Estrutura: { "CRITICAL": [{"timestamp", "category", "raw"}, ...], ... }
# -------------------------------------------------------------------
results = defaultdict(list)

if not LOG_FILE:
    print("[ERRO] Nenhum arquivo de log encontrado.")
    print("       Esperados: /var/log/kern.log ou /var/log/syslog")
    raise SystemExit(1)

try:
    with open(LOG_FILE, "r", errors="replace") as f:
        for line in f:
            # No syslog, filtra apenas linhas do kernel
            # No kern.log todas as linhas já são do kernel
            if LOG_FILE == "/var/log/syslog" and not KERNEL_LINE.search(line):
                continue

            timestamp = line[:15].strip()

            # Classifica na primeira categoria que casar
            for cat in CATEGORIES:
                if cat["pattern"].search(line):
                    results[cat["label"]].append(
                        {
                            "timestamp": timestamp,
                            "raw": line.strip(),
                        }
                    )
                    break  # uma linha = uma categoria (a mais grave)

except PermissionError:
    print(f"[ERRO] Sem permissão para ler {LOG_FILE}.")
    raise SystemExit(1)

SEP = "=" * 65
SEP2 = "-" * 50

print(SEP)
print("   MENSAGENS DE ERRO E FALHA DO KERNEL")
print(f"   Fonte: {LOG_FILE}")
print(SEP)

if not results:
    print("""
  Nenhuma mensagem de erro do kernel encontrada.

  Isso pode indicar:
    • Sistema saudável sem erros registrados
    • Logs rotacionados (verifique kern.log.1 ou syslog.1)
    • Container Docker (kernel compartilhado com o host,
      mensagens do kernel não são encaminhadas ao syslog
      do container — use `dmesg` no host para inspecionar)
""")
    raise SystemExit(0)

# Exibe por categoria, da mais grave para a menos grave
cat_order = ["CRITICAL", "ERROR", "WARNING", "NOTICE"]

total = 0
for label in cat_order:
    if label not in results:
        continue

    events = results[label]
    total += len(events)

    cat_info = next(c for c in CATEGORIES if c["label"] == label)
    icon = cat_info["icon"]

    print(f"\n{icon}  {label}  ({len(events)} ocorrência(s))")
    print(SEP2)

    for e in events:
        print(f"  {e['timestamp']}  |  {e['raw']}")

# Resumo
print(f"\n{SEP}")
print("  RESUMO POR SEVERIDADE")
print(SEP)
for label in cat_order:
    if label not in results:
        continue
    cat_info = next(c for c in CATEGORIES if c["label"] == label)
    count = len(results[label])
    bar = "█" * min(count, 40)
    print(f"  {cat_info['icon']}  {label:<10} {count:>5}x  {bar}")

print(f"  {'─' * 45}")
print(f"  {'TOTAL':<10} {total:>6}")
print(SEP)
print()
print("  Dica: para mensagens do kernel em tempo real, use:")
print("    dmesg -w --level=err,warn")
print("  Para logs anteriores:")
print("    zcat /var/log/kern.log.*.gz | grep -Ei 'error|warn|fail'")
print(SEP)
