#!/usr/bin/env python3
"""
domain-correlate.py — Domain registration batch correlator

Takes a list of domains and groups them by registration date proximity
to identify infrastructure registered in batches. Batch registration is
a strong indicator of adversary pre-positioning: operators register all
domains for a campaign in a single session to minimize cost and effort.

Requires: python-whois  (pip install python-whois)

Usage:
    python3 domain-correlate.py domains.txt
    python3 domain-correlate.py domains.txt --window 3
    printf 'example.com\nother.com\n' | python3 domain-correlate.py -

    --window    Days within which registrations are grouped as a batch (default: 7)
    --csv       Output in CSV format
    --quiet     Only print batches of 2 or more domains

Input: one domain per line, stdin or file path.
"""

import sys
import csv
import io
import datetime
import argparse
from typing import Optional

try:
    import whois
except ImportError:
    print("[error] python-whois not installed. Run: pip install python-whois", file=sys.stderr)
    sys.exit(1)


def get_registration_date(domain: str) -> Optional[datetime.date]:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime.datetime):
            return created.date()
        if isinstance(created, datetime.date):
            return created
    except Exception:
        pass
    return None


def group_by_proximity(
    results: list[tuple[str, Optional[datetime.date]]], window_days: int
) -> list[list[tuple[str, datetime.date]]]:
    dated = sorted(
        [(d, r) for d, r in results if r is not None],
        key=lambda x: x[1],
    )

    if not dated:
        return []

    groups = []
    current = [dated[0]]

    for i in range(1, len(dated)):
        gap = (dated[i][1] - current[-1][1]).days
        if gap <= window_days:
            current.append(dated[i])
        else:
            groups.append(current)
            current = [dated[i]]
    groups.append(current)

    return groups


def main():
    parser = argparse.ArgumentParser(
        description="Group domains by registration date to find batch-registered infra"
    )
    parser.add_argument(
        "input", nargs="?", default="-", help="Domain list file or - for stdin"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=7,
        help="Days within which registrations are grouped (default: 7)",
    )
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print groups of 2 or more domains",
    )
    args = parser.parse_args()

    if args.input == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(args.input) as f:
            lines = f.read().splitlines()

    domains = [l.strip().lstrip("*.") for l in lines if l.strip() and not l.startswith("#")]
    if not domains:
        print("[error] no domains provided", file=sys.stderr)
        sys.exit(1)

    print(f"[*] looking up {len(domains)} domain(s)...", file=sys.stderr)

    results = []
    for domain in domains:
        sys.stderr.write(f"  {domain:<50} ")
        sys.stderr.flush()
        reg = get_registration_date(domain)
        results.append((domain, reg))
        sys.stderr.write(f"{reg or 'FAILED'}\n")

    groups = group_by_proximity(results, args.window)
    failed = [d for d, r in results if r is None]

    if args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(["domain", "registered", "batch_id", "batch_size"])
        for i, group in enumerate(groups, 1):
            if args.quiet and len(group) < 2:
                continue
            for domain, reg in group:
                writer.writerow([domain, reg.isoformat(), i, len(group)])
    else:
        print(f"\n[*] {len(groups)} registration group(s) (window: {args.window} days)\n")
        for i, group in enumerate(groups, 1):
            if args.quiet and len(group) < 2:
                continue
            flag = "  [BATCH]" if len(group) >= 2 else ""
            dates = [r.isoformat() for _, r in group]
            span = f"{min(dates)} to {max(dates)}" if len(dates) > 1 else dates[0]
            print(f"Group {i} — {len(group)} domain(s)  {span}{flag}")
            for domain, reg in group:
                print(f"  {reg}  {domain}")
            print()

    if failed:
        print(f"[!] WHOIS lookup failed for {len(failed)} domain(s):", file=sys.stderr)
        for d in failed:
            print(f"    {d}", file=sys.stderr)


if __name__ == "__main__":
    main()
