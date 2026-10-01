#!/usr/bin/env python3
"""
crtsh-timeline.py — Certificate Transparency log timeline builder

Queries crt.sh for all certificates issued to a domain and outputs a
chronological timeline of issuance events. Useful for mapping when a
domain's infrastructure went live and identifying related subdomains.

Usage:
    python3 crtsh-timeline.py <domain>
    python3 crtsh-timeline.py --include-expired example.com
    python3 crtsh-timeline.py --export example.com

Output columns:
    logged_at   — when the cert was submitted to CT logs
    not_before  — cert validity start (when the domain went TLS-live)
    not_after   — cert expiry
    issuer      — CA that issued the cert
    names       — all SANs in the cert (reveals subdomains)
"""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
import argparse
import urllib.parse
import time
import pandas as pd

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


def fetch_certs(domain: str, retries: int = 4) -> list[dict]:
    url = CRTSH_URL.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={"User-Agent": "crtsh-timeline/1.0"})
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code not in (502, 503, 504) or attempt == retries:
                print(f"[error] crt.sh returned HTTP {e.code}", file=sys.stderr)
                sys.exit(1)
            err = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries:
                print(f"[error] {e}", file=sys.stderr)
                sys.exit(1)
            err = str(e)
        wait = 5 * attempt
        print(f"[!] {err}, retrying in {wait}s ({attempt}/{retries})", file=sys.stderr)
        time.sleep(wait)


def parse_dt(s: str) -> datetime:
    if not s:
        return datetime.min.replace(tzinfo=timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s.rstrip("Z"), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.min.replace(tzinfo=timezone.utc)


def deduplicate(certs: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for c in certs:
        key = (c.get("issuer_ca_id"), c.get("not_before"), c.get("common_name"))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def format_names(name_value: str) -> str:
    names = sorted(set(name_value.replace("\\n", "\n").split("\n")))
    return ", ".join(n.strip() for n in names if n.strip())


def main():
    parser = argparse.ArgumentParser(description= "Process data and optionally export to excel")
    parser.add_argument("--export", action="store_true", help= "Export data to excel.")
    parser.add_argument("--include-expired", action="store_true", help= "Include expired certs in output")
    parser.add_argument("domain", help= "Domain to query.")
    args = parser.parse_args()

    domain = args.domain.lstrip("*.")
    print(f"[*] querying crt.sh for: {domain}", file=sys.stderr)

    certs = fetch_certs(domain)
    if not certs:
        print("[!] no certificates found", file=sys.stderr)
        sys.exit(0)

    certs = deduplicate(certs)
    now = datetime.now(timezone.utc)

    if not args.include_expired:
        certs = [c for c in certs if parse_dt(c.get("not_after", "")) > now]

    certs.sort(key=lambda c: parse_dt(c.get("not_before", "")))

    rows = []
    for c in certs:
        rows.append({
            "logged_at":  (c.get("entry_timestamp") or "n/a")[:19],
            "not_before": c.get("not_before", "")[:19],
            "not_after":  c.get("not_after", "")[:19],
            "issuer":     c.get("issuer_name", "").split("O=")[-1].split(",")[0][:38],
            "names":      format_names(c.get("name_value", c.get("common_name", ""))),
        })

    print(f"\n{'logged_at':<22} {'not_before':<22} {'not_after':<22} {'issuer':<40} names")
    print("-" * 140)
    for r in rows:
        print(f"{r['logged_at']:<22} {r['not_before']:<22} {r['not_after']:<22} {r['issuer']:<40} {r['names']}")

    print(f"\n[*] {len(rows)} certificate(s) shown", file=sys.stderr)

    if args.export:
        df = pd.DataFrame(rows)
        filename = f"crtsh_{domain}.xlsx"
        df.to_excel(filename, sheet_name="Certs", index=False)
        print(f"[*] exported to {filename}", file=sys.stderr)
    else:
        print("[*] tip: re-run with --export to save to Excel", file=sys.stderr)


if __name__ == "__main__":
    main()
