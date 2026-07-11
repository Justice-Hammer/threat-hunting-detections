---
id: DET-0003
title: "Msiexec Silent Install from ProgramData"
type: detection
status: validated
confidence: high
attack_tactics: [defense-evasion, execution]
attack_techniques: [T1218.007]
platforms: [sigma, elastic, splunk, kql, crowdstrike]
data_sources: [process_creation]
lolbin: [msiexec.exe]
false_positive_rate: low
related_hunts: ["[[HUNT-0005 - ClickFix WordPress Delivery Network Hunt]]"]
references:
  - "https://attack.mitre.org/techniques/T1218/007/"
  - "https://lolbas-project.github.io/lolbas/Binaries/Msiexec/"
created: 2026-07-11
updated: 2026-07-11
tags: [detection, msiexec, lolbin, programdata, defense-evasion]
---

# Msiexec Silent Install from ProgramData

## Logic summary
`msiexec.exe` is a Microsoft-signed binary routinely abused as a LOLBin to silently install malicious payloads (T1218.007). Adversaries pass `/qn` (quiet, no UI) and `/norestart` to suppress all user-visible prompts, then stage the MSI in `C:\ProgramData\` — a user-writable directory that doesn't require elevation and is less monitored than `C:\Windows\` or `C:\Program Files\`. Randomized subfolder names under `ProgramData` are used to frustrate path-based detection.

Legitimate enterprise MSI deployments (SCCM, Intune, vendor installers) typically invoke `msiexec` from `C:\Windows\Installer\`, a UNC path, or an elevated service context — not from a user-writable `ProgramData` subfolder. False-positive volume is low.

Validated against real-world EVALUSION/UNC2190 ClickFix campaigns where this pattern was used to drop NetSupport RAT.

## Sigma (canonical)
```yaml
title: Msiexec Silent Install from ProgramData
id: 2f9d4a7c-1e3b-4c8a-b132-8d4f2c90e2a1
status: experimental
description: >
  Detects msiexec.exe silently installing an MSI from a user-writable C:\ProgramData\
  subdirectory. Legitimate enterprise deployments use Windows Installer paths or UNC
  sources; ProgramData staging is strongly associated with malicious dropper chains.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\msiexec.exe'
    CommandLine|contains:
      - '/qn'
    CommandLine|re: '(?i)C:\\ProgramData\\.+'
  filter_managed:
    ParentImage|endswith:
      - '\svchost.exe'
      - '\services.exe'
    CommandLine|contains:
      - '\Windows\Installer\'
  condition: selection and not filter_managed
falsepositives:
  - Enterprise deployment tools (SCCM, Intune) staging to ProgramData — baseline
    known-good paths per environment
  - Vendor installers that legitimately drop to ProgramData (less common; verify with
    signed parent chain)
level: high
tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.007
```

## Platform translations
### Elastic (ES|QL)
```sql
FROM logs-endpoint.events.process-*
| WHERE event.category == "process" AND event.type == "start"
| WHERE TO_LOWER(process.name) == "msiexec.exe"
| WHERE process.command_line LIKE "*/qn*"
| WHERE process.command_line RLIKE "(?i)C:\\\\ProgramData\\\\.+"
| WHERE NOT (TO_LOWER(process.parent.name) IN ("svchost.exe","services.exe")
    AND process.command_line LIKE "*\\Windows\\Installer\\*")
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp DESC
```
### Splunk (SPL)
```
`process_creation`
  process_name="msiexec.exe"
  CommandLine="*/qn*"
  CommandLine="*C:\\ProgramData\\*"
  NOT (parent_process_name IN ("svchost.exe","services.exe") AND CommandLine="*\\Windows\\Installer\\*")
| table _time host user parent_process CommandLine
```
### Microsoft (KQL)
```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/qn"
| where ProcessCommandLine matches regex @"(?i)C:\\ProgramData\\"
| where not (InitiatingProcessFileName in~ ("svchost.exe","services.exe")
    and ProcessCommandLine has "\\Windows\\Installer\\")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc
```
### CrowdStrike (LogScale)
```
#event_simpleName=ProcessRollup2
  ImageFileName=/\\msiexec\.exe$/i
  CommandLine=/\/qn/i
  CommandLine=/C:\\ProgramData\\/i
  NOT (ParentBaseFileName=/\\(svchost|services)\.exe$/i CommandLine=/\\Windows\\Installer\\/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## False positives
- Enterprise MDM/SCCM deployments that cache MSIs to ProgramData subfolders — profile your environment's managed-deployment parent chains and add them to the filter.
- Vendor software (e.g., some security tools) that legitimately stage updates under ProgramData; verify by checking the parent process signature and the MSI signing chain.

## Validation notes
Validated against observed EVALUSION/UNC2190 dropper chain: `powershell iex(irm)` → `msiexec.exe /qn /norestart C:\ProgramData\<random>\<payload>.msi`. Subfolder names under ProgramData were randomized per delivery wave, confirming path-based rules alone are insufficient — the `/qn` + `ProgramData` combination is the durable signal. Benign volume near-zero when the managed-deployment parent filter is applied.

## References
- https://attack.mitre.org/techniques/T1218/007/
- https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
