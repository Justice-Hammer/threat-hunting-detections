# scripts

Investigation utilities built from real hunt methodology. Each script is standalone with no external service dependencies beyond what's noted.

| Script | What it does | Depends on |
|---|---|---|
| `crtsh-timeline.py` | Queries crt.sh for all certs issued to a domain; outputs a chronological issuance timeline | stdlib only |
| `s3-probe.py` | Probes candidate S3 bucket names for public listing access; reports object counts, date ranges, and top-level prefixes | stdlib only |
| `domain-correlate.py` | Takes a list of domains, looks up registration dates, and groups them by proximity to identify batch-registered infrastructure | `pip install python-whois` |

## Usage

```bash
# CT log timeline for a domain
python3 crtsh-timeline.py example-backend.top

# Include expired certs
python3 crtsh-timeline.py --include-expired example.com

# Probe S3 buckets derived from a base name
python3 s3-probe.py --base jiuyun --region ap-east-1

# Probe from a candidate list
python3 s3-probe.py --file buckets.txt --region us-east-1

# Correlate domain registration dates
python3 domain-correlate.py domains.txt --window 7

# CSV output for spreadsheet analysis
python3 domain-correlate.py domains.txt --csv > results.csv
```

## Notes

- `crtsh-timeline.py` filters out expired certs by default. Pass `--include-expired` to see the full history.
- `s3-probe.py` generates 12 candidate bucket names from a base name. `--max-keys 0` omits the limit so S3 returns up to 1000 keys (the probe does not paginate — it samples, it does not exhaustively enumerate). Read the warning in the script first if the bucket may contain victim data.
- `domain-correlate.py` requires WHOIS lookups which can be slow and rate-limited. Run against short lists or add delays if hitting rate limits.
