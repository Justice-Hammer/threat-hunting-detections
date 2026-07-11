---
id: DET-0004
title: "Finger LOLBin Remote Script Retrieval"
type: detection
status: validated
confidence: high
attack_tactics: [execution, command-and-control]
attack_techniques: [T1218]
platforms: [sigma, elastic, splunk, kql, crowdstrike]
data_sources: [process_creation, network_connection]
lolbin: [finger.exe]
false_positive_rate: very-low
related_hunts: ["[[HUNT-0006 - CastleLoader LinkedIn ClickFix Hunt]]"]
references:
  - "https://attack.mitre.org/techniques/T1218/"
  - "https://lolbas-project.github.io/lolbas/Binaries/Finger/"
created: 2026-07-11
updated: 2026-07-11
tags: [detection, lolbin, finger, execution, living-off-the-land]
---

# Finger LOLBin Remote Script Retrieval

## Logic summary
`finger.exe` is a legacy Windows binary (present by default on all Windows versions) that implements the Finger protocol (TCP/79). Adversaries abuse it as a LOLBin to retrieve attacker-controlled content from a Finger server: the `.plan` field of a Finger response can carry arbitrary text — including multi-line batch scripts — and the output is captured directly in a command substitution (`for /f ... finger user@host`). This allows script retrieval without `curl`, `wget`, or PowerShell web requests, bypassing controls that monitor those specific download tools.

Legitimate enterprise use of `finger.exe` is effectively zero in modern environments. Any execution should be treated as high-confidence malicious.

Validated against real-world CastleLoader delivery chains where `finger.exe` retrieved a batch script containing Python downloader logic via TCP/79 to an attacker-controlled Finger server on a typosquatted job-platform domain.

## Sigma (canonical)
```yaml
title: Finger LOLBin Remote Script Retrieval
id: 7c4b2e1a-9f3d-4a8c-b240-1e7f3c90d3b2
status: experimental
description: >
  Detects finger.exe execution with a remote host argument — a LOLBin technique for
  retrieving attacker-controlled scripts via the Finger protocol (TCP/79) without
  using standard download utilities. Legitimate enterprise use is near-zero.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\finger.exe'
    CommandLine|contains: '@'
  condition: selection
falsepositives:
  - Legacy network administration in environments that still use Finger protocol
    (extremely rare; validate by confirming outbound TCP/79 policy and target host)
level: high
tags:
  - attack.execution
  - attack.t1218
```

## Platform translations
### Elastic (ES|QL)
```sql
FROM logs-endpoint.events.process-*
| WHERE event.category == "process" AND event.type == "start"
| WHERE process.name == "finger.exe"
| WHERE process.command_line LIKE "*@*"
| KEEP @timestamp, host.name, user.name, process.parent.name,
       process.parent.command_line, process.command_line
| SORT @timestamp DESC
```
### Splunk (SPL)
```
`process_creation`
  process_name="finger.exe"
  CommandLine="*@*"
| table _time host user parent_process parent_command CommandLine
```
### Microsoft (KQL)
```kql
DeviceProcessEvents
| where FileName =~ "finger.exe"
| where ProcessCommandLine contains "@"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc
```
### CrowdStrike (LogScale)
```
#event_simpleName=ProcessRollup2
  ImageFileName=/\\finger\.exe$/i
  CommandLine=/@/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
         ParentCommandLine, CommandLine])
```

## Network companion rule
Pair with a network alert for outbound TCP/79 from any workstation:
```kql
// Defender network events — alert on ALL outbound TCP/79
// Finger protocol has no legitimate enterprise use; any process making this connection is suspicious
DeviceNetworkEvents
| where RemotePort == 79
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
```

## Attack chain context
In observed campaigns, `finger.exe` is invoked from a caret-obfuscated `cmd.exe` one-liner (ClickFix clipboard payload). The Finger response `.plan` field carries a multi-line batch script, captured with `for /f "delims=" %i in ('finger user@host') do ...`. The batch script then downloads a Python embeddable disguised as a `.pdf`, extracts it, renames the binary, and executes the next stage. See [[HUNT-0006 - CastleLoader LinkedIn ClickFix Hunt]] for the full chain.

## False positives
Legitimate Finger protocol usage is functionally extinct in enterprise environments. If your environment has a documented Finger use case, baseline the specific binary paths and target hosts and filter accordingly. All other executions should be escalated immediately.

## References
- https://attack.mitre.org/techniques/T1218/
- https://lolbas-project.github.io/lolbas/Binaries/Finger/
