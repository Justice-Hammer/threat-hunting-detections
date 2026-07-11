---
id: DET-0005
title: "Startup Folder Write by Non-Installer Process"
type: detection
status: validated
confidence: high
attack_tactics: [persistence]
attack_techniques: [T1547.001]
platforms: [sigma, elastic, splunk, kql, crowdstrike]
data_sources: [file_event]
lolbin: []
false_positive_rate: low
related_hunts:
  - "[[HUNT-0005 - ClickFix WordPress Delivery Network Hunt]]"
  - "[[HUNT-0006 - CastleLoader LinkedIn ClickFix Hunt]]"
references:
  - "https://attack.mitre.org/techniques/T1547/001/"
created: 2026-07-11
updated: 2026-07-11
tags: [detection, persistence, startup-folder, t1547]
---

# Startup Folder Write by Non-Installer Process

## Logic summary
The Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` and the all-users variant) causes any executable or shortcut placed there to run automatically at user logon, without admin privileges or registry modifications. Multiple threat actors use this as a first-choice persistence mechanism because it is user-writable and does not trigger UAC.

Legitimate writes to the Startup folder come from managed software installers running as `SYSTEM` or `TrustedInstaller`, signed by known publishers, or from explicit user action via Explorer. Writes initiated by `msiexec.exe`, `powershell.exe`, `cmd.exe`, or `python.exe` executing an adversary payload are high-confidence malicious. The parent process chain narrows this further.

Validated against two separate ClickFix campaigns (EVALUSION/UNC2190 NetSupport RAT and GrayBravo/TAG-150 CastleLoader/Python RAT) which both used the user Startup folder for persistence.

## Sigma (canonical)
```yaml
title: Startup Folder Write by Non-Installer Process
id: 023e1bee-e0a6-4b1d-81d4-470262cb534a
status: test
author: Justice Hammer
date: 2026-07-11
description: >
  Detects file creation events in Windows Startup folder locations initiated by
  processes associated with malicious delivery chains (msiexec, powershell, cmd,
  python, wscript, cscript). Legitimate installers running as SYSTEM or
  TrustedInstaller are filtered; scripting engines and LOLBins writing to Startup
  are high-confidence persistence indicators.
logsource:
  category: file_event
  product: windows
detection:
  selection_path:
    TargetFilename|contains:
      - '\Start Menu\Programs\Startup\'
  selection_initiator:
    Image|endswith:
      - '\msiexec.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\python.exe'
      - '\pythonw.exe'
      - '\curl.exe'
      - '\certutil.exe'
  filter_system_installer:
    Image|endswith:
      - '\TrustedInstaller.exe'
      - '\svchost.exe'
      - '\explorer.exe'
  condition: selection_path and selection_initiator and not filter_system_installer
falsepositives:
  - Enterprise software that legitimately installs Startup items via script
    (baseline known-good installer names/paths per environment)
  - Package managers (chocolatey, winget) — add to filter if present
level: high
tags:
  - attack.persistence
  - attack.t1547.001
```

## Platform translations
### Elastic (ES|QL)
```sql
FROM logs-endpoint.events.file-*
| WHERE event.category == "file" AND event.type IN ("creation","modification")
| WHERE file.path LIKE "*\\Start Menu\\Programs\\Startup\\*"
| WHERE TO_LOWER(process.name) IN
    ("msiexec.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe",
     "cscript.exe","python.exe","pythonw.exe","curl.exe","certutil.exe")
| WHERE NOT TO_LOWER(process.name) IN ("trustedinstaller.exe","svchost.exe","explorer.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, file.path
| SORT @timestamp DESC
```
### Splunk (SPL)
```
`file_event`
  file_path="*\\Start Menu\\Programs\\Startup\\*"
  process_name IN ("msiexec.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe",
                   "cscript.exe","python.exe","pythonw.exe","curl.exe","certutil.exe")
  NOT process_name IN ("TrustedInstaller.exe","svchost.exe","explorer.exe")
| table _time host user process_name process_command file_path
```
### Microsoft (KQL)
```kql
DeviceFileEvents
| where FolderPath has "\\Start Menu\\Programs\\Startup\\"
| where InitiatingProcessFileName in~ ("msiexec.exe","powershell.exe","pwsh.exe",
    "cmd.exe","wscript.exe","cscript.exe","python.exe","pythonw.exe",
    "curl.exe","certutil.exe")
| where InitiatingProcessFileName !in~ ("TrustedInstaller.exe","svchost.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath, FileName
| sort by Timestamp desc
```
### CrowdStrike (LogScale)
```
#event_simpleName=NewExecutableWritten OR #event_simpleName=NewScriptWritten
| TargetDirectoryName=/\\Start Menu\\Programs\\Startup\\/i
| ImageFileName=/\\(msiexec|powershell|pwsh|cmd|wscript|cscript|python|pythonw|curl|certutil)\.exe$/i
| ImageFileName!=/\\(TrustedInstaller|svchost|explorer)\.exe$/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, TargetFileName])
```

## False positives
- Legitimate enterprise tooling (endpoint agents, update managers) that write Startup items — profile your environment's known-good writers and add them to the filter.
- Package managers (Chocolatey, winget) occasionally write Startup entries — baseline as needed.

## Validation notes
Validated against:
1. NetSupport RAT (EVALUSION/UNC2190): `msiexec.exe` drops `SecurityHealth.exe` and associated config to Startup folder during silent MSI install from ProgramData.
2. Python RAT (GrayBravo/TAG-150): `pythonw.exe` from a ProgramData subfolder writes Python bytecode and watchdog script to Startup folder for persistence and auto-respawn.

Both campaigns used user Startup folder (`%APPDATA%`) rather than the all-users path, consistent with not requiring elevated privileges at this stage.

Lab reproduction: Atomic Red Team [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) (Startup folder persistence), driving the write from `powershell.exe`/`cmd.exe` rather than a signed installer. Fixtures: [`tests/fixtures/startup-folder-write-non-installer.json`](../tests/fixtures/startup-folder-write-non-installer.json).

## References
- https://attack.mitre.org/techniques/T1547/001/
