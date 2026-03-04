#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"


def parse_failed_logins(log_file):
    failures = defaultdict(int)
    pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from")

    try:
        with open(log_file, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    user = match.group(1)
                    failures[user] += 1
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {log_file}")
        return {}

    return failures


def main():
    failures = parse_failed_logins(LOG_FILE)

    if not failures:
        print("Nenhuma tentativa de login falha encontrada.")
        return

    print(f"{'Usuário':<20} {'Tentativas':>10}")
    print("-" * 32)

    for user, count in sorted(failures.items(), key=lambda x: x[1], reverse=True):
        print(f"{user:<20} {count:>10}")


if __name__ == "__main__":
    main()
