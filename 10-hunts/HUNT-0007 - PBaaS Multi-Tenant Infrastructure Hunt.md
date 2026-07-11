---
id: HUNT-0007
title: "PBaaS Multi-Tenant Infrastructure Hunt"
type: hunt
hunt_class: intel
status: closed
hypothesis: "Pig-butchering-as-a-Service platforms hosting multiple company impersonations on a shared backend leave correlated CT log, Shodan, and S3 enumeration artifacts that expose the full platform infrastructure even when the front-end is Cloudflare-proxied."
attack_tactics: [resource-development, collection]
attack_techniques: [T1583.001, T1583.006, T1608.005, T1530]
platforms_hunted: [osint, shodan, crtsh, aws]
outcome: "Positive. Full backend IP recovered via WebSocket domain CT log pivot. Multi-tenant S3 storage confirmed via public bucket listing. Victim KYC documents publicly accessible without authentication in operator-misconfigured upload bucket. Three simultaneous company impersonations confirmed from single backend. Produced DET-0006."
produced_detections:
  - "[[DET-0006 - Vue.js Fake Trading Platform Kit Fingerprint]]"
related_research: ["[[RES-0006 - PBaaS Multi-Tenant Platform Architecture]]"]
created: 2026-07-11
updated: 2026-07-11
tags: [hunt, pig-butchering, pbaas, s3, ct-log, shodan, multi-tenant, osint]
---

# PBaaS Multi-Tenant Infrastructure Hunt

## Hypothesis

PBaaS platforms are built for operational efficiency, not OPSEC. A single operator backend serves multiple simultaneous company impersonations to reduce cost and maintenance overhead. This shared infrastructure creates correlated observable artifacts: CT log entries linking front-end and backend domains, a Cloudflare-proxied front-end that leaks its backend via an unproxied WebSocket domain, and S3 buckets that may be misconfigured to allow public listing. Starting from any one domain in the cluster, passive OSINT can recover the full infrastructure without touching live adversary systems.

## Scope and data sources

- **CT log (crt.sh):** Certificate Transparency records for all known domains in the cluster
- **Shodan:** TLS SAN enumeration, port/service fingerprinting on recovered backend IP
- **AWS S3:** Public bucket enumeration for storage associated with the backend infrastructure
- **WHOIS / registrar correlation:** Registration batch analysis for domain co-registration

All queries are passive. No active probing of adversary infrastructure.

## Hunt methodology

### Step 1 — CT log pivot from front-end to backend

Starting from the Cloudflare-proxied front-end domain, query crt.sh for all certificates:

```
https://crt.sh/?q=<front-end-domain>&output=json
```

The front-end will typically show only wildcard certs (no subdomain enumeration possible through CT). Identify any related domains registered in the same time window by searching registrar patterns or linked WHOIS data.

The backend WebSocket domain is often registered on the same day or within days of the front-end. Search crt.sh for the backend TLD pattern (`.top` is common for PBaaS backends):

```
https://crt.sh/?q=<suspected-backend-domain>&output=json
```

Backend domains typically do NOT use wildcard certs, revealing subdomains (`wss.`, `api.`, etc.) in named cert entries.

### Step 2 — Shodan backend IP recovery

Once the WebSocket backend domain is identified, resolve it directly (it is typically not Cloudflare-proxied):

```bash
dig +short wss.<backend-domain>
```

Query Shodan for the resolved IP:

```
https://www.shodan.io/host/<ip>
```

Check: open ports, TLS SAN (confirms backend domain), co-hosted domains (if any), HTTP/S service banners. PBaaS backends typically expose only 80/443 (Nginx), HTTP/3 + QUIC enabled, HSTS configured. No SSH or DB ports publicly exposed.

### Step 3 — S3 bucket enumeration

PBaaS platforms commonly use S3 for static asset serving and victim document collection. Enumerate predictable bucket names derived from the platform branding:

```bash
# Test for public listing on predictable bucket names
curl -s "https://<suspected-bucket>.s3.<region>.amazonaws.com/" | head -50
```

Signs of a victim upload bucket:
- `upload/` prefix containing many objects
- File extensions: `.jpg`, `.png`, `.pdf`, `.mp4` (KYC photos, ID scans, screen recordings)
- Object modification timestamps showing consistent recent activity (active platform)
- A `struct.md` or similar config file at the bucket root (operator platform initialization artifact)

If a world-readable victim upload bucket is found: **do not download or enumerate individual victim files.** Note the bucket name, object count, date range, and overall structure for the incident report, then stop. These files contain PII belonging to fraud victims. Exfiltrating them for analysis, even with good intent, creates legal and ethical exposure.

In this hunt, an operator-misconfigured S3 bucket made victim KYC documents publicly accessible without authentication. The bucket name is withheld. The finding was reported to the appropriate parties; individual victim documents were not accessed beyond confirming the misconfiguration.

### Step 4 — Multi-tenant brand pivot

If S3 static assets are accessible, look for logos and branding assets in the `icon/` or `images/` prefix:

```bash
curl -s "https://<bucket>.s3.<region>.amazonaws.com/?prefix=icon/" | grep -o 'Key>[^<]*</Key'
```

Each distinct company logo in the shared storage confirms another simultaneous impersonation. Cross-reference logo filenames against known company names. Check for front-end domains serving each brand by searching CT logs for recent `.vip`/`.top` registrations.

### Step 5 — Registration batch analysis

Co-registered domains from the same Dynadot/Namecheap account often share:
- Same registration date (within hours)
- Same nameserver configuration (e.g., Cloudflare)
- Same WHOIS privacy proxy

Querying WHOIS for each discovered domain and comparing registration metadata links all front-end domains to the same operator account.

## Findings

- Full backend infrastructure mapped from a single starting domain via CT log + Shodan pivot chain
- Backend IP recovered from WebSocket domain (not Cloudflare-proxied, resolves directly)
- S3 storage confirmed: static asset bucket (access denied) + victim upload bucket (public listing)
- Victim KYC data publicly accessible in misconfigured upload bucket; finding reported without accessing individual documents
- Three simultaneous company impersonations confirmed from shared backend S3 storage, all stood up within a 3-day window
- All front-end domains registered in a single batch; backend domain registered ~5 days earlier

## Detections produced

- [DET-0006 - Vue.js Fake Trading Platform Kit Fingerprint](../20-detections/DET-0006%20-%20Vue.js%20Fake%20Trading%20Platform%20Kit%20Fingerprint.md)

## ATT&CK mapping

- T1583.001 — Acquire Infrastructure: Domains (batch registration of front-end + backend domains)
- T1583.006 — Acquire Infrastructure: Web Services (AWS S3 + EC2 for backend hosting)
- T1530 — Data from Cloud Storage (victim documents in misconfigured public S3 bucket)
- T1608.005 — Stage Capabilities: Link Target (Vue.js SPA deployed for phishing lure)
