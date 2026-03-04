#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"


def parse_successful_logins(log_file):
    logins = defaultdict(list)
    pattern = re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from")

    try:
        with open(log_file, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    datetime = match.group(1)
                    user = match.group(2)
                    logins[user].append(datetime)
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {log_file}")
        return {}

    return logins


def main():
    logins = parse_successful_logins(LOG_FILE)

    if not logins:
        print("Nenhum login bem-sucedido encontrado.")
        return

    total = sum(len(v) for v in logins.values())
    print(f"Total de logins bem-sucedidos: {total}\n")

    for user, timestamps in sorted(logins.items()):
        print(f"Usuário: {user}  ({len(timestamps)} acesso(s))")
        print("-" * 40)
        for ts in timestamps:
            print(f"  {ts}")
        print()


if __name__ == "__main__":
    main()
