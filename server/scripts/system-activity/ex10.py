#!/usr/bin/env python3
"""
Exercício 10 - Problemas com dispositivos de hardware
Arquivos de log consultados (em ordem de prioridade):

  1. /var/log/kern.log  — mensagens do kernel gravadas pelo rsyslog
  2. /var/log/dmesg     — ring buffer do kernel gravado no boot
  3. /var/log/syslog    — fallback com linhas "kernel:"

Baseado nos logs reais do ambiente WSL2 (DESKTOP-M9EM9IJ), os
dispositivos detectados incluem: PCI, USB, disk/VFS, memória,
rede virtual (veth/docker) e Hyper-V (hv_vmbus/hv_pci).

Categorias de dispositivo monitoradas:
  DISK     — sda, nvme, vda, ata, scsi, vfs, ext4, quota
  USB      — usb, usbcore, xhci, ehci
  PCI      — pci, pci_bus, pcie, acpi
  MEMORY   — memory, oom, mm, oom-killer, ramdisk
  NETWORK  — eth, veth, docker, bridge, br-
  HYPERV   — hv_vmbus, hv_pci, hyperv
  OTHER    — qualquer outro dispositivo com erro/aviso

Severidade detectada:
  CRITICAL — fatal, panic, oops, bug, corrupt, oom-killer
  ERROR    — error, failed, failure, fault
  WARNING  — warn, warning
  INFO     — registered, probing, detected, found, ready
"""

import re
import os
import gzip
from collections import defaultdict, namedtuple

Event = namedtuple("Event", ["timestamp", "uptime", "category", "severity", "raw"])

# -------------------------------------------------------------------
# Arquivos candidatos em ordem de preferência
# -------------------------------------------------------------------
CANDIDATES = [
    "/var/log/kern.log",
    "/var/log/dmesg",
    "/var/log/syslog",
]

# -------------------------------------------------------------------
# Categorias de dispositivo
# Cada entrada: label, ícone, regex que identifica o dispositivo
# -------------------------------------------------------------------
DEVICE_CATEGORIES = [
    {
        "label": "DISK",
        "icon": "💾",
        "pattern": re.compile(
            r"\b(sda\w*|nvme\w*|vda\w*|ata\d|scsi|vfs|ext4|xfs|btrfs|"
            r"quota|dquot|blk|block|mmc)\b",
            re.IGNORECASE,
        ),
    },
    {
        "label": "USB",
        "icon": "🔌",
        "pattern": re.compile(
            r"\b(usb\w*|usbcore|xhci|ehci|ohci|uhci)\b", re.IGNORECASE
        ),
    },
    {
        "label": "PCI",
        "icon": "🖥",
        "pattern": re.compile(r"\b(pci\w*|pcie|acpi|irq|apic|iommu)\b", re.IGNORECASE),
    },
    {
        "label": "MEMORY",
        "icon": "🧠",
        "pattern": re.compile(
            r"\b(memory|mem\b|oom|mm\b|ramdisk|swap|hugepage|cache)\b", re.IGNORECASE
        ),
    },
    {
        "label": "NETWORK",
        "icon": "🌐",
        "pattern": re.compile(
            r"\b(eth\d|veth\w+|docker\w*|br-\w+|bond\w*|tun\w*|tap\w*|"
            r"wlan\w*|enp\w*)\b",
            re.IGNORECASE,
        ),
    },
    {
        "label": "HYPERV",
        "icon": "☁",
        "pattern": re.compile(
            r"\b(hv_vmbus|hv_pci|hyperv|hyper.v|vmbus)\b", re.IGNORECASE
        ),
    },
]

# -------------------------------------------------------------------
# Severidade — testada na ordem (mais grave primeiro)
# -------------------------------------------------------------------
SEVERITY_LEVELS = [
    {
        "label": "CRITICAL",
        "icon": "💀",
        "pattern": re.compile(
            r"\b(fatal|panic|oops|bug:|corrupt|oom.killer|segfault|killed)\b",
            re.IGNORECASE,
        ),
    },
    {
        "label": "ERROR",
        "icon": "✘",
        "pattern": re.compile(
            r"\b(error|failed|failure|fault|exception|bad|invalid)\b", re.IGNORECASE
        ),
    },
    {
        "label": "WARNING",
        "icon": "⚠",
        "pattern": re.compile(r"\b(warn|warning|deprecated|mismatch)\b", re.IGNORECASE),
    },
    {
        "label": "INFO",
        "icon": "ℹ",
        "pattern": re.compile(
            r"\b(registered|probing|detected|found|ready|available|"
            r"assigned|enabled|loaded|starting|using)\b",
            re.IGNORECASE,
        ),
    },
]

# -------------------------------------------------------------------
# Regex para extrair timestamp e uptime da linha
#
# Formato kern.log/syslog:
#   Mar  8 12:54:33 host kernel: [  0.000000] mensagem
#
# Formato dmesg puro:
#   [  0.000000] mensagem
# -------------------------------------------------------------------
SYSLOG_LINE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*kernel:.*"
    r"\[\s*(?P<up>[\d.]+)\]\s*(?P<msg>.+)"
)
DMESG_LINE = re.compile(r"^\[\s*(?P<up>[\d.]+)\]\s*(?P<msg>.+)")


# -------------------------------------------------------------------
# Função que classifica uma linha de hardware
# Retorna Event ou None se não for relevante
# -------------------------------------------------------------------
def classify_line(line, timestamp, uptime):
    # Determina categoria do dispositivo
    category = "OTHER"
    for cat in DEVICE_CATEGORIES:
        if cat["pattern"].search(line):
            category = cat["label"]
            break

    # Determina severidade
    severity = None
    for sev in SEVERITY_LEVELS:
        if sev["pattern"].search(line):
            severity = sev["label"]
            break

    # Ignora linhas sem severidade identificável (muito genéricas)
    if not severity:
        return None

    return Event(
        timestamp=timestamp,
        uptime=uptime,
        category=category,
        severity=severity,
        raw=line.strip(),
    )


# -------------------------------------------------------------------
# Leitura dos logs
# -------------------------------------------------------------------
events = []
log_used = None

for path in CANDIDATES:
    if not os.path.exists(path):
        continue

    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Tenta formato syslog/kern.log primeiro
                m = SYSLOG_LINE.search(line)
                if m:
                    ts = m.group("ts")
                    up = m.group("up")
                    msg = m.group("msg")
                    ev = classify_line(msg, ts, up)
                    if ev:
                        events.append(ev)
                    continue

                # Tenta formato dmesg puro
                m = DMESG_LINE.match(line)
                if m:
                    ev = classify_line(m.group("msg"), "—", m.group("up"))
                    if ev:
                        events.append(ev)

        if events:
            log_used = path
            break  # usou o primeiro arquivo com dados

    except PermissionError:
        print(f"[aviso] Sem permissão para ler {path}, tentando próximo...")

# -------------------------------------------------------------------
# Relatório
# -------------------------------------------------------------------
SEP = "=" * 70
SEP2 = "-" * 55

print(SEP)
print("   PROBLEMAS COM DISPOSITIVOS DE HARDWARE")
if log_used:
    print(f"   Fonte: {log_used}")
print(SEP)

if not events:
    print("""
  Nenhum evento de hardware encontrado.

  Tente como root para acessar todos os logs:
    sudo python3 ex10.py

  Ou inspecione manualmente:
    sudo dmesg --level=err,warn
    sudo grep -i "error\|fail\|warn" /var/log/kern.log
""")
    raise SystemExit(0)

# Agrupa por categoria e depois por severidade
by_category = defaultdict(lambda: defaultdict(list))
for e in events:
    by_category[e.category][e.severity].append(e)

# Ordem de exibição das severidades (mais grave primeiro)
SEV_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO"]
CAT_ORDER = ["DISK", "USB", "PCI", "MEMORY", "NETWORK", "HYPERV", "OTHER"]

cat_icons = {c["label"]: c["icon"] for c in DEVICE_CATEGORIES}
cat_icons["OTHER"] = "🔧"
sev_icons = {s["label"]: s["icon"] for s in SEVERITY_LEVELS}

for cat_label in CAT_ORDER:
    if cat_label not in by_category:
        continue

    cat_data = by_category[cat_label]
    cat_total = sum(len(v) for v in cat_data.values())
    icon = cat_icons.get(cat_label, "🔧")

    print(f"\n{icon}  {cat_label}  ({cat_total} evento(s))")
    print(SEP2)

    for sev_label in SEV_ORDER:
        if sev_label not in cat_data:
            continue

        sev_events = cat_data[sev_label]
        sev_icon = sev_icons[sev_label]

        print(f"\n  {sev_icon} {sev_label} ({len(sev_events)}):")
        for e in sev_events:
            ts_part = f"{e.timestamp}" if e.timestamp != "—" else f"uptime +{e.uptime}s"
            print(f"    [{ts_part}]  {e.raw[:90]}")

# -------------------------------------------------------------------
# Resumo geral
# -------------------------------------------------------------------
print(f"\n{SEP}")
print("  RESUMO POR CATEGORIA E SEVERIDADE")
print(SEP)

# Cabeçalho
header = f"  {'CATEGORIA':<12}"
for sev in SEV_ORDER:
    header += f"  {sev:>8}"
header += f"  {'TOTAL':>6}"
print(header)
print(f"  {'─' * 60}")

grand_total = 0
for cat_label in CAT_ORDER:
    if cat_label not in by_category:
        continue

    row = f"  {cat_icons.get(cat_label, '🔧')} {cat_label:<10}"
    cat_total = 0
    for sev in SEV_ORDER:
        count = len(by_category[cat_label].get(sev, []))
        cat_total += count
        grand_total += count
        row += f"  {count:>8}"
    row += f"  {cat_total:>6}"
    print(row)

print(f"  {'─' * 60}")
print(f"  {'TOTAL':<12}{'':>{'48'}}  {grand_total:>6}")
print(SEP)
print()
print("  Dica: para monitorar hardware em tempo real:")
print("    sudo dmesg -w --level=err,warn,crit")
print("    sudo tail -f /var/log/kern.log")
print(SEP)
