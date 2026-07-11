---
id: RES-0006
title: "PBaaS Multi-Tenant Platform Architecture"
type: research
attack_techniques: [T1583.001, T1583.006, T1530, T1608.005]
informs_detections: ["[[DET-0006 - Vue.js Fake Trading Platform Kit Fingerprint]]"]
informs_hunts: ["[[HUNT-0007 - PBaaS Multi-Tenant Infrastructure Hunt]]"]
references:
  - "https://attack.mitre.org/techniques/T1583/001/"
  - "https://attack.mitre.org/techniques/T1583/006/"
  - "https://attack.mitre.org/techniques/T1530/"
created: 2026-07-11
updated: 2026-07-11
tags: [research, pig-butchering, pbaas, infrastructure, multi-tenant, s3, aws, china]
---

# PBaaS Multi-Tenant Platform Architecture

## Overview

Pig-butchering-as-a-Service (PBaaS) is the productization of investment fraud infrastructure. Rather than building a fake trading platform per campaign, operators run a shared backend that serves multiple simultaneous company impersonations — different brands, same code, same server, same victim data pipeline. The multi-tenant model reduces operator overhead and makes individual takedowns less effective: removing one front-end domain leaves the backend and all other impersonations intact.

This note documents the infrastructure architecture of an observed PBaaS platform active in 2026, based on passive analysis. No live adversary systems were accessed.

## Platform architecture

```
Front-end tier (Cloudflare-proxied)
  [Company A].vip  ──┐
  [Company B].vip  ──┤──→ /prod-api/ REST API ──→ EC2 backend (AWS ap-east-1)
  [Company C].vip  ──┘         ↕                        ↕
                        wss://wss.<backend>.top     S3 storage (ap-east-1)
                        /socket/1 (WebSocket)         ├── static assets (locked)
                                                      └── victim uploads (misconfigured public)
```

Each front-end domain impersonates a different legitimate company. The victim sees company-specific branding; the backend is shared. Three simultaneous impersonations were confirmed in the observed platform, each stood up within a 3-day window.

## Front-end stack

The lure site is a Vue.js single-page application with TailwindCSS styling. Distinctive component vocabulary in the JS bundle:

| Component | Function |
|---|---|
| `useToRecharge` | Deposit workflow composable |
| `useToWithdraw` | Withdrawal workflow composable |
| `NoticeModal` | Pop-up notice / announcement modal |

These names are consistent across operator deployments because they reflect the platform's internal vocabulary, not the impersonated company. They survive front-end rebranding and are detectable in page source regardless of which company logo is displayed.

The social engineering flow follows a standard pig-butchering script: victims are recruited via messaging apps (Signal confirmed via uploaded file metadata), transitioned to the fake platform, deposited funds, shown artificial profits, then blocked when attempting withdrawal.

## Backend infrastructure

The backend runs on AWS EC2 in `ap-east-1` (Hong Kong). It is NOT Cloudflare-proxied, which means the real IP is recoverable by resolving the WebSocket domain (`wss.<backend-domain>`). This is a consistent OPSEC gap in this class of platform: operators proxy the front-end to hide the server but neglect to proxy the backend WebSocket domain.

Port profile (Shodan, 2026): 80/443 only (Nginx), HTTP/3 + QUIC enabled, HSTS configured. SSH and database ports not exposed.

## S3 storage and the public victim upload misconfiguration

The platform used two S3 buckets in `ap-east-1`:

- **Static asset bucket:** Access denied; contains platform UI assets and company logos for all active impersonations
- **Victim upload bucket:** World-readable — no authentication required to list or access objects

The victim upload bucket contained KYC documents submitted by fraud victims: identity photos, government-issued ID scans, and in some cases screen recordings. The bucket name is withheld. Victim files were not accessed or downloaded beyond confirming the misconfiguration.

This misconfiguration is significant for two reasons:

1. **For victims:** Their identity documents were publicly accessible to anyone who discovered the bucket name, not just the fraud operator.
2. **For investigators:** The bucket exposed the platform's operational timeline. Object modification timestamps showed consistent recent activity, confirming the platform was actively processing victims. A `struct.md` file at the bucket root recorded the platform initialization date. Brand logos in the static prefix confirmed all active impersonations without requiring access to any front-end domain.

The presence of a world-readable victim upload bucket is not unusual in this class of platform. Operators prioritize operational speed over security hardening. S3 bucket enumeration should be a standard step in any PBaaS infrastructure investigation.

## Chinese operator indicators

The following attributes, individually common, form a consistent cluster in Chinese-operated pig-butchering platforms:

| Indicator | Observation |
|---|---|
| TrustAsia LiteSSL CA (C=CN) | Day-0 cert provisioned on backend domain; Chinese CA auto-provisioned via Cloudflare APAC or Chinese hosting panel |
| AWS ap-east-1 (Hong Kong) | Both EC2 and S3 in the same APAC region |
| Chinese bucket naming | Bucket name prefix using Chinese pinyin (e.g., `jiuyun` = 九云 "Nine Cloud") |
| `.vip` + `.top` TLD preference | Cheap gTLDs with minimal abuse reporting friction, preferred by Chinese fraud operators |
| `/prod-api/` URL pattern | Common in Chinese-developed fake trading kits |
| Dynadot registrar with Chinese privacy proxy | Consistent across observed pig-butchering domain batches |

No single indicator is definitive. The cluster in combination supports high-confidence attribution to a Chinese-operated platform.

## Registration and deployment timeline

PBaaS platforms follow a predictable registration-to-deployment sequence:

1. Backend domain registered first, with TLS cert provisioned on registration day
2. Front-end domains registered in a batch 3-7 days later
3. Platform content deployed 4-6 weeks after domain registration (Cloudflare nameserver changes + CMS setup)
4. Victim recruitment predates domain registration by weeks to months (social engineering pipeline runs ahead of infrastructure)

The gap between initial victim contact and platform activation is a distinctive feature: victims are pre-groomed before the lure site even exists. By the time the platform goes live, the victim has already been cultivated and is expecting to "invest."

## Cloudflare abuse pattern

All front-end domains used Cloudflare for DNS and proxying. Cloudflare's abuse reporting process (`abuse.cloudflare.com`) is the primary takedown path for the front-end. However:

- Cloudflare only controls the proxy layer. Taking down the CF proxy removes the front-end but leaves the EC2 backend live
- New front-end domains can be stood up and CF-proxied in under an hour
- The backend and S3 storage are unaffected by CF takedowns

Effective takedowns require coordinating Cloudflare (front-end proxy), the registrar (Dynadot for all observed domains, same account), and AWS (EC2 + S3 abuse) simultaneously.

## References
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1530/
- https://attack.mitre.org/techniques/T1608/005/
