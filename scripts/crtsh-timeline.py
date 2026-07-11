#!/usr/bin/env python3
"""
crtsh-timeline.py — Certificate Transparency log timeline builder

Queries crt.sh for all certificates issued to a domain and outputs a
chronological timeline of issuance events. Useful for mapping when a
domain's infrastructure went live and identifying related subdomains.

Usage:
    python3 crtsh-timeline.py <domain>
    python3 crtsh-timeline.py ypprdf.top
    python3 crtsh-timeline.py --include-expired ypprdf.top

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

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


def fetch_certs(domain: str) -> list[dict]:
    url = CRTSH_URL.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={"User-Agent": "crtsh-timeline/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[error] crt.sh returned HTTP {e.code}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)


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
    import urllib.parse

    include_expired = False
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    flags = [a for a in sys.argv[1:] if a.startswith("-")]
    if "--include-expired" in flags:
        include_expired = True

    if not args:
        print(__doc__)
        sys.exit(0)

    domain = args[0].lstrip("*.")
    print(f"[*] querying crt.sh for: {domain}", file=sys.stderr)

    certs = fetch_certs(domain)
    if not certs:
        print("[!] no certificates found", file=sys.stderr)
        sys.exit(0)

    certs = deduplicate(certs)
    now = datetime.now(timezone.utc)

    if not include_expired:
        certs = [c for c in certs if parse_dt(c.get("not_after", "")) > now]

    certs.sort(key=lambda c: parse_dt(c.get("not_before", "")))

    print(f"\n{'logged_at':<22} {'not_before':<22} {'not_after':<22} {'issuer':<40} names")
    print("-" * 140)

    for c in certs:
        logged = c.get("entry_timestamp", "")[:19]
        not_before = c.get("not_before", "")[:19]
        not_after = c.get("not_after", "")[:19]
        issuer = c.get("issuer_name", "").split("O=")[-1].split(",")[0][:38]
        names = format_names(c.get("name_value", c.get("common_name", "")))
        print(f"{logged:<22} {not_before:<22} {not_after:<22} {issuer:<40} {names}")

    print(f"\n[*] {len(certs)} certificate(s) shown", file=sys.stderr)


if __name__ == "__main__":
    main()
