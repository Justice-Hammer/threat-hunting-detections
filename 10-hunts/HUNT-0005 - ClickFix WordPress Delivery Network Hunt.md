---
id: HUNT-0005
title: "ClickFix WordPress Delivery Network Hunt"
type: hunt
hunt_class: intel
status: closed
hypothesis: "ClickFix threat actors operating compromised WordPress delivery networks leave durable hash and behavioral signatures across web proxy logs and endpoint process telemetry that enable retrospective identification of victims and infrastructure."
attack_tactics: [initial-access, execution, command-and-control]
attack_techniques: [T1204.001, T1059.001, T1584.004]
platforms_hunted: [elastic, defender]
outcome: "Positive. Hash-based pivot against urlscan confirmed a 385-site centralized delivery network. Behavioral signatures (iex+irm parent-child lineage from browser/explorer) identified at-risk hosts. Produced DET-0002 and DET-0003."
produced_detections:
  - "[[DET-0002 - ClickFix PowerShell IRM Execution]]"
  - "[[DET-0003 - Msiexec Silent Install from ProgramData]]"
created: 2026-07-11
updated: 2026-07-11
tags: [hunt, clickfix, wordpress, delivery-network, intel-driven]
---

# ClickFix WordPress Delivery Network Hunt

## Hypothesis
ClickFix threat actors targeting enterprise users via compromised WordPress lure sites deploy a centralized delivery architecture: a byte-identical JavaScript loader is injected across many compromised sites, all funneling through a single operator-controlled hub. This centralization creates a durable hash-based hunting surface in web proxy/DNS telemetry. On the endpoint side, the ClickFix payload produces a distinctive parent-child process chain (browser/Run-dialog → powershell → msiexec) with near-zero benign volume.

## Scope & data sources
- **Web proxy / DNS:** Query for the byte-identical stage-2 JS loader hash and the hub domain in proxy logs. Hash is stable across the entire delivery network because the operator controls a single copy.
- **Endpoint process creation:** Hunt for `powershell.exe` children of `explorer.exe` or browser processes with `irm`+`iex` in the command line.
- **Time window:** 90-day lookback. ClickFix campaigns typically operate for weeks-to-months before rotating infrastructure.

## Queries run

### 1. Hash pivot — stage-2 loader (urlscan / web proxy)
The centralized ClickFix loader is a ~2KB JavaScript file. Hunt for the SHA256 of the observed loader in web proxy logs or urlscan to map the delivery network.

urlscan hash search (OSINT):
```
hash:4dda35a9da5e330e810e7e4c9d27a86c29ed5cde540dba76c284d80cbb28e2c2
```
Expected: multiple distinct domains all serving the byte-identical loader. Each hit is a confirmed compromised delivery site. Volume >20 hits confirms centralized-hub architecture.

### 2. C2 domain infrastructure hunt — keyboard-mash pattern
EVALUSION/UNC2190 C2 domains follow a low-entropy keyboard-mash naming pattern (e.g., `tiqwtkmma[.]com`, `mokitomaccito[.]com`). Hunt in DNS/proxy for .com domains matching this profile registered within the last 90 days:

```kql
// Defender — DNS events
DeviceNetworkEvents
| where RemoteUrl matches regex @"(?i)^[a-z]{8,18}\.com$"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","msiexec.exe")
| where Timestamp > ago(90d)
| summarize count() by RemoteUrl, DeviceName
| sort by count_ asc
```

Rare-by-frequency sorting surfaces newly-registered C2 domains before they accumulate volume.

### 3. Endpoint — ClickFix PowerShell lineage
```kql
// Defender
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~
    ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| where ProcessCommandLine has_any ("irm ","Invoke-RestMethod")
    and ProcessCommandLine has_any ("iex(","iex (","Invoke-Expression")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

### 4. Endpoint — msiexec ProgramData drop from PowerShell parent
```kql
// Defender — msiexec child of powershell
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "/qn"
| where ProcessCommandLine matches regex @"(?i)C:\\ProgramData\\"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

### 5. WordPress hub — centralized relay identification
The EVALUSION delivery architecture routes all delivery-site callbacks through a single compromised WordPress site repurposed as a relay hub. Hunt for a single domain appearing in referrer headers of many distinct source domains in proxy logs:

```
| stats dc(cs_host) as delivery_sites by cs_referer_host
| where delivery_sites > 10
| sort delivery_sites desc
```
High `delivery_sites` count against a single referrer = likely hub. Cross-reference against Shodan: hubs run standard WordPress on AS-type hosting (not the BPH C2 ASN).

## Findings
- Hash-based urlscan pivot confirmed centralized delivery architecture across 385 compromised sites (287 US-registered, 19 countries).
- Endpoint behavioral queries (Q3 + Q4) identified the full delivery chain on affected hosts.
- C2 domains confirmed via process-level network connections post-detonation, corroborated by sandbox analysis.
- Produced [[DET-0002 - ClickFix PowerShell IRM Execution]] and [[DET-0003 - Msiexec Silent Install from ProgramData]] as durable behavioral detections.

## Detections produced
- [[DET-0002 - ClickFix PowerShell IRM Execution]]
- [[DET-0003 - Msiexec Silent Install from ProgramData]]

## ATT&CK mapping
- T1204.001 — User Execution: Malicious Link (ClickFix social engineering)
- T1059.001 — PowerShell (`iex(irm)` delivery)
- T1218.007 — System Binary Proxy Execution: Msiexec
- T1584.004 — Compromise Infrastructure: Server (compromised WordPress delivery sites)
- T1583.001 — Acquire Infrastructure: Domains (keyboard-mash C2 domain registration)
