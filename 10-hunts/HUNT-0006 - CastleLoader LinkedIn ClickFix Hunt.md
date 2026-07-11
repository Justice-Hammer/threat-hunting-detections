---
id: HUNT-0006
title: "CastleLoader LinkedIn ClickFix Hunt"
type: hunt
hunt_class: intel
status: closed
hypothesis: "Threat actors impersonating LinkedIn and Indeed job platforms deliver CastleLoader via a finger.exe LOLBin chain, staging a Python embeddable disguised as a PDF before executing a multi-stage Python loader. This leaves durable behavioral artifacts across process creation, file system, and network telemetry."
attack_tactics: [initial-access, execution, persistence, defense-evasion, command-and-control]
attack_techniques: [T1204.001, T1059.003, T1059.006, T1218, T1547.001, T1562.001, T1071.001, T1132, T1573.001]
platforms_hunted: [elastic, defender]
outcome: "Positive. Finger.exe LOLBin execution confirmed; Python embeddable staging in ProgramData; Startup folder persistence; WebSocket C2 over HTTPS. Produced DET-0004 and DET-0005."
produced_detections:
  - "[[DET-0004 - Finger LOLBin Remote Script Retrieval]]"
  - "[[DET-0005 - Startup Folder Write by Non-Installer Process]]"
created: 2026-07-11
updated: 2026-07-11
tags: [hunt, castleloader, clickfix, linkedin, finger, python-rat, intel-driven]
---

# CastleLoader LinkedIn ClickFix Hunt

## Hypothesis
CastleLoader customers operating LinkedIn/Indeed-impersonation ClickFix lures deploy a distinctive multi-stage chain: a fake Cloudflare Turnstile CAPTCHA delivers a caret-obfuscated `cmd.exe` one-liner that uses `finger.exe` (TCP/79) as a LOLBin to retrieve a batch script, which then stages a Python embeddable disguised as a `.pdf` file before executing a Python loader leading to CastleLoader and a Python RAT. The avoidance of standard download utilities (curl, PowerShell web requests) in early stages, combined with the `finger.exe` LOLBin, creates a distinctive low-noise behavioral signature.

## Attack chain (for reference)
```
Fake Cloudflare CAPTCHA (LinkedIn/Indeed typosquat)
  └─ ROT13-decoded JS → ClickFix clipboard (caret-obfuscated cmd.exe one-liner)
       └─ cmd.exe [heavily caret-obfuscated]
            └─ finger.exe <user>@finger.<lure-domain>  [TCP/79 — fetches batch script]
                 └─ batch script:
                      ├─ kill explorer.exe
                      ├─ curl (renamed as *.pdf) → download Python embeddable as *.pdf
                      ├─ tar extract → rename python.exe → %random%x3.exe
                      ├─ python -c [base64+zlib stage-4 loader]
                      ├─ beacon: <lure-domain>/leyts.php?Npier=1
                      └─ restart explorer.exe
                           └─ Python loader (hidden window, 2.1s sleep)
                                └─ CastleLoader C2 (ChaCha20/RC4, /scr7 path)
                                     └─ Python RAT (WebSocket C2, 3s keep-alive)
```

## Scope & data sources
- **Endpoint process creation:** Hunt for `finger.exe`, caret-obfuscated `cmd.exe`, renamed `curl.exe`, and `python.exe`/`pythonw.exe` in unusual locations.
- **File system:** Python embeddable downloaded as `.pdf`; Python runtime staged to `C:\ProgramData\<CrewlCorpii-variant>\`.
- **Network:** Outbound TCP/79 (Finger); initial beacon `GET /leyts.php?Npier=1`; CastleLoader C2 path pattern `/scr7`; Python RAT WebSocket over 443.
- **Time window:** 90-day lookback.

## Queries run

### 1. Finger.exe execution (highest signal, near-zero benign volume)
```kql
DeviceProcessEvents
| where FileName =~ "finger.exe"
| where ProcessCommandLine contains "@"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc
```

### 2. Caret-obfuscated cmd.exe (ClickFix delivery tell)
```kql
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine matches regex @"(\^[a-zA-Z]){4,}"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          ProcessCommandLine
| sort by Timestamp desc
```
High caret density (4+ consecutive `^X` patterns) indicates ClickFix clipboard-delivered one-liners. Tune count threshold to your baseline.

### 3. Python embeddable downloaded as .pdf / .com
```kql
DeviceFileEvents
| where FileName endswith ".pdf" or FileName endswith ".com"
| where FolderPath has_any ("\\AppData\\Local\\", "\\ProgramData\\")
| where InitiatingProcessFileName in~ ("curl.exe","powershell.exe","cmd.exe")
| where FileSize between (8000000 .. 25000000)  // Python embeddable ~10-20MB
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FolderPath, FileName, FileSize
```

### 4. Python runtime staged to ProgramData
```kql
DeviceProcessEvents
| where FileName in~ ("python.exe","pythonw.exe","python310.dll")
| where FolderPath has "\\ProgramData\\"
| where FolderPath !has "\\Python\\"  // filter legitimate Python installs
| project Timestamp, DeviceName, AccountName, FolderPath,
          ProcessCommandLine
| sort by Timestamp desc
```

### 5. CastleLoader C2 path pattern (/scr7, /v3, UUID routing)
```kql
DeviceNetworkEvents
| where RemoteUrl matches regex @"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(scr7|v3|v4)"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP, RemotePort
```
UUID-routed paths (`/<uuid>/scr7`) are a CastleLoader C2 routing convention; each victim gets a unique routing UUID.

### 6. Python RAT named pipe artifact
```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has "PipePipe!"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          AdditionalFields
```
The named pipe `\\.\pipe\PipePipe!` is a Python RAT runtime artifact used for in-memory payload execution; presence is high-confidence.

### 7. AV disable before RAT deployment
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference")
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring","ExclusionProcess","ExclusionPath")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Findings
- Finger.exe LOLBin confirmed as script retrieval mechanism (Q1, zero false positives in test environment).
- Python embeddable staged to ProgramData subdirectory with Crewl-variant naming convention (Q4).
- CastleLoader UUID C2 routing pattern confirmed (Q5); Python RAT WebSocket over HTTPS/443.
- Startup folder persistence via Python bytecode + watchdog → see [DET-0005 - Startup Folder Write by Non-Installer Process](../20-detections/DET-0005%20-%20Startup%20Folder%20Write%20by%20Non-Installer%20Process.md).
- AV disable (Set-MpPreference) preceding RAT deployment confirmed (Q7).

## Detections produced
- [DET-0004 - Finger LOLBin Remote Script Retrieval](../20-detections/DET-0004%20-%20Finger%20LOLBin%20Remote%20Script%20Retrieval.md)
- [DET-0005 - Startup Folder Write by Non-Installer Process](../20-detections/DET-0005%20-%20Startup%20Folder%20Write%20by%20Non-Installer%20Process.md)

## ATT&CK mapping
- T1204.001 - User Execution: Malicious Link (ClickFix fake CAPTCHA)
- T1059.003 - Windows Command Shell (caret-obfuscated cmd.exe)
- T1218 - System Binary Proxy Execution: Finger (LOLBin)
- T1059.006 - Python (Python embeddable loader + RAT)
- T1547.001 - Startup Folder persistence
- T1562.001 - Impair Defenses: Disable Windows Defender
- T1071.001 - Web Protocols (CastleLoader HTTPS C2)
- T1132 - Data Encoding (base64 + zlib stage-4 Python loader)
- T1573.001 - Encrypted Channel: Symmetric Cryptography (ChaCha20/RC4 C2 encryption)

## Public attribution
CastleLoader / CastleRAT and the operator tracked as GrayBravo (Recorded Future Insikt Group designation **TAG-150**) are documented in public vendor reporting from 2025 (Recorded Future Insikt Group and IBM X-Force among others). The behavioral indicators in this hunt and in `indicators/castleloader-behavioral.csv` are released TLP:CLEAR on that basis. Search the named vendors' research for "CastleLoader" / "TAG-150" for the primary sources.
