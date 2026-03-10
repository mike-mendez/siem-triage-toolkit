#!/usr/bin/env python3
"""Generate additive Nginx attack log fixtures for scale testing.

The curated fixture set remains canonical. This generator creates extra lines
that preserve the existing field contract and can be appended/replayed.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


SQLI_PATHS = [
    "/products?id=%27%20OR%201=1--",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/catalog?item=1%27%20AND%20SLEEP(5)--",
]

WEBSHELL_PATHS = [
    "/wp-content/uploads/shell.php?cmd=id",
    "/uploads/cmd.php",
    "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
]

RECON_PATHS = ["/wp-admin", "/wp-login.php", "/.env", "/phpmyadmin/", "/admin/"]

USER_AGENTS = [
    "sqlmap/1.8.2",
    "curl/8.5.0",
    "python-requests/2.31",
    "Nmap Scripting Engine",
]


def format_line(ip: str, ts: datetime, target: str, status: int, ua: str) -> str:
    nginx_ts = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{ip} - - [{nginx_ts}] "GET {target} HTTP/1.1" {status} 128 "-" "{ua}"'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate additive Nginx attack fixtures")
    parser.add_argument("--output", default="samples/logs/nginx_access_generated.log")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--count-sqli", type=int, default=10)
    parser.add_argument("--count-webshell", type=int, default=8)
    parser.add_argument("--count-recon-burst", type=int, default=3)
    args = parser.parse_args()

    random.seed(args.seed)
    start = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
    lines: list[str] = []
    cursor = start

    for _ in range(args.count_sqli):
        ip = f"203.0.113.{random.randint(30, 99)}"
        target = random.choice(SQLI_PATHS)
        status = random.choice([403, 500, 504])
        ua = random.choice(USER_AGENTS)
        lines.append(format_line(ip, cursor, target, status, ua))
        cursor += timedelta(seconds=random.randint(2, 11))

    for _ in range(args.count_webshell):
        ip = f"203.0.113.{random.randint(100, 160)}"
        target = random.choice(WEBSHELL_PATHS)
        status = random.choice([400, 404, 500])
        ua = random.choice(USER_AGENTS)
        lines.append(format_line(ip, cursor, target, status, ua))
        cursor += timedelta(seconds=random.randint(2, 11))

    for _ in range(args.count_recon_burst):
        ip = f"198.51.100.{random.randint(200, 240)}"
        for target in RECON_PATHS:
            ua = "Nmap Scripting Engine"
            lines.append(format_line(ip, cursor, target, 404, ua))
            cursor += timedelta(seconds=random.randint(1, 6))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated={len(lines)} output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
