#!/usr/bin/env python3
"""
s3-probe.py — Passive S3 public bucket listing probe

Given a base name or list of candidate bucket names, probes each for
public listing access without authentication. Reports accessible buckets
and their object counts, date ranges, and top-level prefixes.

Used for identifying misconfigured victim-upload or static-asset buckets
during PBaaS and fraud platform infrastructure investigations.

Usage:
    python3 s3-probe.py --base <name> --region <region>
    python3 s3-probe.py --file candidates.txt --region ap-east-1
    python3 s3-probe.py --base jiuyun --region ap-east-1

    --base      Base name to generate candidate bucket names from
    --file      File containing one candidate bucket name per line
    --region    AWS region to probe (default: us-east-1)
    --max-keys  Max objects to list per bucket (default: 10, use 0 for full listing)

Candidate generation from --base:
    <base>, <base>-prod, prod-<base>, <base>prod, <base>-dev, <base>-static,
    <base>-upload, <base>-assets, <base>-storage, <base>-media

WARNING: Only probe infrastructure you are authorized to investigate.
Do not enumerate or access individual objects in buckets containing
personal data beyond confirming the misconfiguration exists.
"""

import sys
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime

S3_URL = "https://{bucket}.s3.{region}.amazonaws.com/"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def probe_bucket(bucket: str, region: str, max_keys: int = 10) -> dict | None:
    url = S3_URL.format(bucket=bucket, region=region)
    if max_keys > 0:
        url += f"?max-keys={max_keys}"

    req = urllib.request.Request(url, headers={"User-Agent": "s3-probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            return parse_listing(bucket, body)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {"bucket": bucket, "status": "ACCESS_DENIED"}
        if e.code == 404:
            return None
        return {"bucket": bucket, "status": f"HTTP_{e.code}"}
    except Exception:
        return None


def parse_listing(bucket: str, xml_body: str) -> dict:
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return {"bucket": bucket, "status": "PARSE_ERROR"}

    contents = root.findall(f"{NS}Contents")
    prefixes = set()
    dates = []

    for obj in contents:
        key = obj.findtext(f"{NS}Key", "")
        parts = key.split("/")
        if len(parts) > 1:
            prefixes.add(parts[0])
        last_mod = obj.findtext(f"{NS}LastModified", "")
        if last_mod:
            dates.append(last_mod[:10])

    is_truncated = root.findtext(f"{NS}IsTruncated", "false").lower() == "true"

    return {
        "bucket": bucket,
        "status": "PUBLIC",
        "objects_listed": len(contents),
        "truncated": is_truncated,
        "prefixes": sorted(prefixes),
        "date_range": f"{min(dates)} to {max(dates)}" if dates else "n/a",
    }


def generate_candidates(base: str) -> list[str]:
    return [
        base,
        f"{base}-prod",
        f"prod-{base}",
        f"{base}prod",
        f"{base}-dev",
        f"{base}-static",
        f"{base}-upload",
        f"{base}-assets",
        f"{base}-storage",
        f"{base}-media",
        f"{base}-files",
        f"{base}-data",
    ]


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Probe S3 buckets for public listing access"
    )
    parser.add_argument("--base", help="Base name to generate candidates from")
    parser.add_argument("--file", help="File with one candidate per line")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument(
        "--max-keys",
        type=int,
        default=10,
        help="Max objects to list (0 = unlimited, use carefully)",
    )
    args = parser.parse_args()

    if not args.base and not args.file:
        parser.print_help()
        sys.exit(0)

    candidates = []
    if args.base:
        candidates = generate_candidates(args.base)
    if args.file:
        with open(args.file) as f:
            candidates = [line.strip() for line in f if line.strip()]

    print(f"[*] probing {len(candidates)} candidate(s) in {args.region}")
    print(f"[*] endpoint: *.s3.{args.region}.amazonaws.com\n")

    found = []
    for bucket in candidates:
        sys.stdout.write(f"  {bucket:<50} ")
        sys.stdout.flush()
        result = probe_bucket(bucket, args.region, args.max_keys)
        if result is None:
            print("NOT_FOUND")
        elif result["status"] == "ACCESS_DENIED":
            print("ACCESS_DENIED  (bucket exists but private)")
            found.append(result)
        elif result["status"] == "PUBLIC":
            trunc = " (truncated)" if result["truncated"] else ""
            print(f"PUBLIC  {result['objects_listed']} objects{trunc}  {result['date_range']}")
            if result["prefixes"]:
                print(f"    prefixes: {', '.join(result['prefixes'])}")
            found.append(result)
        else:
            print(result["status"])

    print(f"\n[*] {len(found)} bucket(s) found (public or access-denied)")
    public = [r for r in found if r["status"] == "PUBLIC"]
    if public:
        print(f"[!] {len(public)} PUBLIC bucket(s):")
        for r in public:
            print(f"    https://{r['bucket']}.s3.{args.region}.amazonaws.com/")


if __name__ == "__main__":
    main()
