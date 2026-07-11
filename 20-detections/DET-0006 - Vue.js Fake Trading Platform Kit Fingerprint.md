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

| Surface | Signal | Where it's observable |
|---|---|---|
| Web proxy (URL) | `/prod-api/` and `/socket/1` paths on `.vip`/`.top` domains | Request URL — any proxy |
| Web proxy / file (content) | JS bundle body containing `useToRecharge`, `useToWithdraw`, `NoticeModal` | Response **body** — needs a content-inspecting proxy or the YARA rule below |
| DNS | Resolution of `wss.*` subdomain on `.top` TLD immediately following `.vip` domain resolution | DNS telemetry |
| Network | WebSocket connection to `wss://<domain>/socket/1` from browser process | Network / browser telemetry |

## Sigma (canonical)

```yaml
title: Pig-Butchering Platform Kit Component Fingerprint
id: 22c2e0ca-1923-4aa3-b4a1-0bee18cf8eb3
status: test
author: Justice Hammer
date: 2026-07-11
description: >
  Detects web proxy requests to pig-butchering-as-a-service fake trading platforms
  by their URL-observable backend conventions: the /prod-api/ REST prefix and the
  /socket/1 WebSocket path, on the .vip/.top TLDs these kits favour. The Vue.js
  component vocabulary that survives operator rebranding lives in the served JS
  bundle body, not the request URL — match that with the companion YARA rule below,
  which requires a proxy that logs response content.
logsource:
  category: proxy
detection:
  selection_host:
    cs-host|endswith:
      - '.vip'
      - '.top'
  selection_uri:
    c-uri|contains:
      - '/prod-api/'
      - '/socket/1'
  condition: selection_host and selection_uri
falsepositives:
  - Legitimate services on .vip/.top TLDs that expose a /prod-api/ path (rare; corroborate with the JS bundle content fingerprint / YARA rule below before escalating)
level: high
tags:
  - attack.resource_development
  - attack.t1583.001
  - attack.t1608.005
```

## Platform translations

These translations match the URL-observable signals (`/prod-api/`, `/socket/1` on `.vip`/`.top`). The component vocabulary lives in the JS bundle body — see the YARA rule below for that surface.

### Elastic (ES|QL — web proxy)
```sql
FROM logs-proxy*
| WHERE http.request.method == "GET"
| WHERE url.path LIKE "*/prod-api/*" OR url.path LIKE "*/socket/1*"
| WHERE url.domain LIKE "*.vip" OR url.domain LIKE "*.top"
| KEEP @timestamp, host.name, user.name, url.full, http.response.status_code
| SORT @timestamp DESC
```

### Splunk (SPL — proxy)
```
index=proxy sourcetype=proxy
  (uri="*/prod-api/*" OR uri="*/socket/1*")
  (dest_domain="*.vip" OR dest_domain="*.top")
| table _time src_ip user dest_domain uri status
```

### Microsoft (KQL — Defender network events)
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("/prod-api/","/socket/1")
| where RemoteUrl has_any (".vip",".top")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP
| sort by Timestamp desc
```

## Content fingerprint (YARA)

The component vocabulary (`useToRecharge`, `useToWithdraw`, `NoticeModal`) is the durable, rebranding-resistant signal, but it appears in the **served JS bundle body**, not the request URL. Match it with YARA against captured response bodies / retrieved bundles, or with a proxy that performs response-content inspection — not with a URL-only proxy rule.

```yara
rule pbaas_vuejs_trading_kit_bundle
{
    meta:
        author = "Justice Hammer"
        date = "2026-07-11"
        description = "Vue.js fake trading platform (PBaaS) SPA bundle component vocabulary"
        reference = "DET-0006"
    strings:
        $a = "useToRecharge" ascii
        $b = "useToWithdraw" ascii
        $c = "NoticeModal" ascii
        $api = "/prod-api/" ascii
    condition:
        2 of ($a, $b, $c) or (any of ($a, $b, $c) and $api)
}
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
