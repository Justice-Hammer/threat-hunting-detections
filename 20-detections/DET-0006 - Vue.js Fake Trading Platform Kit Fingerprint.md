---
id: DET-0006
title: "Vue.js Fake Trading Platform Kit Fingerprint"
type: detection
status: validated
confidence: high
attack_tactics: [resource-development]
attack_techniques: [T1583.001, T1608.005]
platforms: [sigma, elastic, splunk, kql]
data_sources: [web_proxy, dns, network_traffic_content]
lolbin: []
false_positive_rate: very-low
related_hunts: ["[[HUNT-0007 - PBaaS Multi-Tenant Infrastructure Hunt]]"]
related_research: ["[[RES-0006 - PBaaS Multi-Tenant Platform Architecture]]"]
references:
  - "https://attack.mitre.org/techniques/T1583/001/"
  - "https://attack.mitre.org/techniques/T1608/005/"
created: 2026-07-11
updated: 2026-07-11
tags: [detection, pig-butchering, pbaas, vue, fake-trading, web-proxy]
---

# Vue.js Fake Trading Platform Kit Fingerprint

## Logic summary

Pig-butchering-as-a-Service platforms commonly deploy Vue.js single-page applications impersonating legitimate investment brokerages. The kit vocabulary (`useToRecharge`, `useToWithdraw`, `NoticeModal`) and backend API path conventions (`/prod-api/`) are consistent across operator deployments and survive customization of the lure company, domain, and branding. They appear in web proxy content inspection logs and DNS telemetry regardless of which company the kit is impersonating at any given time.

The kit communicates with a WebSocket backend on a separate domain (pattern: `wss.<backend-domain>/socket/1`), typically on a `.top` TLD not fronted by Cloudflare — meaning the real backend IP is exposed in DNS even when the front-end domain is CF-proxied. This creates a detection opportunity: the WebSocket domain leaks the backend even if the front-end is otherwise opaque.

Validated against a live PBaaS platform impersonating multiple financial services firms simultaneously from a single AWS EC2 backend in ap-east-1.

## Detection surfaces

This kit targets humans via social engineering, not endpoint malware delivery. Detection is in network telemetry, not process creation.

| Surface | Signal |
|---|---|
| Web proxy (URL) | Requests to `.vip`/`.top` domains matching SPA bundle path patterns |
| Web proxy (content) | Page source containing `useToRecharge`, `useToWithdraw`, `NoticeModal` |
| DNS | Resolution of `wss.*` subdomain on `.top` TLD immediately following `.vip` domain resolution |
| Network | WebSocket connection to `wss://<domain>/socket/1` from browser process |

## Sigma (canonical)

```yaml
title: Pig-Butchering Platform Kit Component Fingerprint
id: 3f8c1e2a-6b4d-4c9a-d451-3a9f5e02c5b4
status: experimental
description: >
  Detects web proxy content inspection hits for Vue.js fake trading platform
  component vocabulary associated with pig-butchering-as-a-service kits.
  Component names survive operator rebranding and are consistent across deployments.
logsource:
  category: proxy
  product: windows
detection:
  selection_content:
    cs-method: GET
    c-uri-extension: js
    c-uri|contains:
      - 'useToRecharge'
      - 'useToWithdraw'
      - 'NoticeModal'
  selection_api:
    c-uri|contains: '/prod-api/'
    cs-host|endswith:
      - '.vip'
      - '.top'
  condition: selection_content or selection_api
falsepositives:
  - Legitimate Vue.js applications that happen to use matching variable names (unlikely at cluster level)
level: high
tags:
  - attack.resource_development
  - attack.t1583.001
  - attack.t1608.005
```

## Platform translations

### Elastic (ES|QL — web proxy)
```sql
FROM logs-proxy*
| WHERE http.request.method == "GET"
| WHERE (
    url.path LIKE "*useToRecharge*"
    OR url.path LIKE "*useToWithdraw*"
    OR url.path LIKE "*NoticeModal*"
    OR url.path LIKE "*/prod-api/*"
  )
| WHERE url.domain LIKE "*.vip" OR url.domain LIKE "*.top"
| KEEP @timestamp, host.name, user.name, url.full, http.response.status_code
| SORT @timestamp DESC
```

### Splunk (SPL — proxy)
```
index=proxy sourcetype=proxy
  (uri="*useToRecharge*" OR uri="*useToWithdraw*" OR uri="*NoticeModal*" OR uri="*/prod-api/*")
  (dest_domain="*.vip" OR dest_domain="*.top")
| table _time src_ip user dest_domain uri status
```

### Microsoft (KQL — Defender web content events)
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("useToRecharge","useToWithdraw","NoticeModal","/prod-api/")
| where RemoteUrl has_any (".vip",".top")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP
| sort by Timestamp desc
```

## WebSocket backend pivot

When the front-end domain is Cloudflare-proxied, pivot to the WebSocket backend to recover the real server IP:

```
// DNS query: resolve wss.<backend-domain> (typically .top TLD)
// The WebSocket domain is NOT Cloudflare-proxied — it resolves to the real EC2/VPS IP
// From there: Shodan lookup on IP, TLS SAN enumeration for co-hosted domains
```

The WebSocket path pattern `wss://<domain>/socket/1` is consistent across observed deployments. Finding this pattern in browser network telemetry or proxy logs confirms kit family membership.

## False positives

Legitimate use of `useToRecharge`, `useToWithdraw`, or `NoticeModal` as Vue.js composition function names is possible in isolation. In combination with `.vip`/`.top` TLDs and the `/prod-api/` pattern, the cluster is high-confidence. Tune by requiring at least two signals from different categories before alerting.

## Validation notes

Validated against a live PBaaS deployment serving multiple company impersonations from a single backend. All three component names and the `/prod-api/` pattern were confirmed in static analysis of the Vue.js SPA bundle. Platform was actively processing victims at time of validation.

## References
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1608/005/
