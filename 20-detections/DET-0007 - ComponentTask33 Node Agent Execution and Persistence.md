---
id: DET-0007
title: "ComponentTask33 Node Agent Execution and Persistence"
type: detection
status: experimental
confidence: medium
attack_tactics: [execution, persistence, defense-evasion]
attack_techniques: [T1218.007, T1059.001, T1059.005, T1059.007, T1053.005, T1564.001, T1036.005]
platforms: [sigma]
data_sources: [process_creation, file_event]
lolbin: [msiexec.exe, wscript.exe, powershell.exe]
false_positive_rate: low
related_research: ["[[RES-0007 - ComponentTask33 MSI Loader with On-Chain C2 Discovery]]"]
references:
  - "https://attack.mitre.org/techniques/T1218/007/"
  - "https://attack.mitre.org/techniques/T1564/001/"
  - "https://attack.mitre.org/techniques/T1053/005/"
created: 2026-08-28
updated: 2026-08-28
tags: [detection, msi-loader, nodejs-rat, scheduled-task, scatter, componenttask33]
---

# ComponentTask33 Node Agent Execution and Persistence

Six rules covering the ComponentTask33 loader chain. Full analysis:
[[RES-0007 - ComponentTask33 MSI Loader with On-Chain C2 Discovery]].

## Logic summary

The loader is hard to catch on any single artifact. The MSI is a per-user install that
needs no UAC; the payload is **scattered** at install time across four decoy directories
under `%LOCALAPPDATA%`/`%APPDATA%`, so no one directory looks like malware; and the
on-disk names rotate per build. A public sandbox scored the sample 3/100 with zero rule
hits.

What does not rotate is the **shape**. These rules key on that:

1. **Install-time custom actions** — `msiexec` spawning PowerShell against `._scatter.ps1`
   with the `-AnchorDir` switch, and `wscript //B` against a dot-prefixed `.vbs`.
   Dot-prefixed filenames are a Unix idiom and unusual on Windows.
2. **Agent-registered persistence** — the scheduled task is created by `node.exe` →
   `powershell.exe`, seconds *after* `msiexec` has already exited. That time-decoupling
   is the tell: installers register their own persistence, malware that registers it from
   the payload does not.
3. **A Node runtime living in shell/cache folders** — `node.exe` beside `node_modules\` under
   `%LOCALAPPDATA%\Microsoft\Windows\{Libraries,INetCache,Shell}\` or
   `%APPDATA%\Microsoft\Windows\Themes\`. Legitimate software does not stage Node there.

Rule 6 (`msiexec-large-msi`) is deliberately **low fidelity** — it is triage volume, not a
standalone alert. Pair it with the others or with a size filter.

> [!note] Status
> `experimental`, not `validated`. These rules were authored from static analysis of a
> single sample plus one sandbox report, not from production telemetry across an estate.
> Baseline them before you alert on them.

## Rules

Canonical machine-readable copies live in [`sigma/`](../sigma); the copies below are for
readability. **They must stay identical** — see [CONTRIBUTING](../CONTRIBUTING.md).
Fixtures: [`tests/fixtures/componenttask33-*.json`](../tests/fixtures).

### ComponentTask33 MSI Scatter Custom Action (PowerShell -AnchorDir)

`sigma/componenttask33-msi-scatter-powershell.yml` · level **high**

```yaml
title: ComponentTask33 MSI Scatter Custom Action (PowerShell -AnchorDir)
id: d36d7889-ab21-47e3-b654-f5cff85804b4
status: experimental
description: >
  MSI custom action ScatterInstall launching PowerShell against a dot-prefixed
  ._scatter.ps1 with the distinctive -AnchorDir switch. The -AnchorDir token on a
  hidden bypass-policy PowerShell is high-selectivity for this family.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.execution
  - attack.t1218.007
  - attack.t1059.001
  - attack.defense_evasion
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_cli:
    CommandLine|contains|all:
      - '._scatter.ps1'
      - '-AnchorDir'
  condition: selection_img and selection_cli
falsepositives:
  - None expected; -AnchorDir on ._scatter.ps1 is not used by legitimate software.
level: high
```

### ComponentTask33 Hidden VBScript Agent Launch (wscript //B ._agent.vbs)

`sigma/componenttask33-wscript-agent-vbs.yml` · level **high**

```yaml
title: ComponentTask33 Hidden VBScript Agent Launch (wscript //B ._agent.vbs)
id: fbf86b62-e0a0-444d-9c20-d741559ee338
status: experimental
description: >
  wscript.exe //B launching a dot-prefixed ._agent.vbs under a user AppData path.
  Fires both for the MSI StartAgent custom action (parent msiexec) and for the
  ComponentTask33Agent scheduled task at logon.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.execution
  - attack.t1059.005
  - attack.persistence
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\wscript.exe'
    CommandLine|contains|all:
      - '//B'
      - '._agent.vbs'
  scope:
    CommandLine|contains:
      - '\AppData\Local\'
      - '\AppData\Roaming\'
  condition: selection and scope
falsepositives:
  - Legitimate software rarely runs dot-prefixed .vbs from AppData via wscript //B.
level: high
```

### ComponentTask33 Agent Self-Registers Logon Scheduled Task

`sigma/componenttask33-agent-task-selfregister.yml` · level **high**

```yaml
title: ComponentTask33 Agent Self-Registers Logon Scheduled Task
id: 5cf0a32d-ecf7-4098-b5ba-e1a640cf26a6
status: experimental
description: >
  The Node agent (not msiexec) registers persistence: node.exe spawns PowerShell
  running Register-ScheduledTask with an AtLogon trigger whose action is a hidden
  wscript/AppData launch. Time-decoupled from the installer.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Register-ScheduledTask'
  parent:
    ParentImage|endswith: '\node.exe'
  condition: selection and parent
falsepositives:
  - Node-based installers that legitimately create scheduled tasks (rare; triage on the task action + AppData path).
level: high
```

### ComponentTask33 Scatter Destination File Drop

`sigma/componenttask33-scatter-filedrop.yml` · level **high**

```yaml
title: ComponentTask33 Scatter Destination File Drop
id: b200ee70-d871-4ea8-952b-903fdb276523
status: experimental
description: >
  Payload files written into the four scatter destinations under
  %LOCALAPPDATA%/%APPDATA%\Microsoft\Windows\{Themes,Libraries,INetCache,Shell}\.
  Legitimate software does not stage a Node runtime or app\src\index.js there.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.defense_evasion
  - attack.t1564
  - attack.t1036.005
logsource:
  category: file_event
  product: windows
detection:
  location:
    TargetFilename|contains:
      - '\Microsoft\Windows\Themes\'
      - '\Microsoft\Windows\Libraries\'
      - '\Microsoft\Windows\INetCache\'
      - '\Microsoft\Windows\Shell\'
  payload:
    TargetFilename|endswith:
      - '\node.exe'
      - '\index.js'
      - '\._agent.vbs'
      - '.dat'
  condition: location and payload
falsepositives:
  - node.exe under these specific shell/cache subfolders is not a normal Windows layout; low FP.
level: high
```

### ComponentTask33 Node Agent from AppData Spawning PTY Host

`sigma/componenttask33-node-appdata-pty.yml` · level **medium**

```yaml
title: ComponentTask33 Node Agent from AppData Spawning PTY Host
id: e875fc82-c63d-43b1-955c-ef1eb01f3b59
status: experimental
description: >
  node.exe executing from a user-writable AppData path and spawning a console/PTY
  host (conhost/OpenConsole via node-pty conpty). Filename-agnostic — catches the
  agent regardless of the per-build folder rename.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.execution
  - attack.t1059.007
  - attack.t1059.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\node.exe'
    ParentImage|contains:
      - '\AppData\Local\'
      - '\AppData\Roaming\'
  selection_child:
    Image|endswith:
      - '\conhost.exe'
      - '\OpenConsole.exe'
      - '\winpty-agent.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Developer tooling running Node with an interactive terminal from AppData (e.g. VS Code servers). Tune by folder path.
level: medium
```

### ComponentTask33 Msiexec Install of MSI from Downloads

`sigma/componenttask33-msiexec-large-msi.yml` · level **low**

```yaml
title: ComponentTask33 Msiexec Install of MSI from Downloads
id: 305eab13-df7a-4721-9445-bf0628b523e1
status: experimental
description: >
  msiexec /i installing an .msi directly from the user's Downloads folder. Weak on
  its own; corroborates the ComponentTask33 chain. MSI size (>50 MB) is not
  expressible in Sigma — enforce via EDR/telemetry enrichment.
references:
  - https://github.com/Justice-Hammer/threat-hunting-detections
author: Justice Hammer
date: 2026-08-28
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1218.007
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\msiexec.exe'
    CommandLine|contains: '/i'
    CommandLine|contains: '\Downloads\'
    CommandLine|contains: '.msi'
  condition: selection
falsepositives:
  - Users legitimately install MSIs from Downloads. Low fidelity by design; use as a corroborator.
level: low
```

## Network and file-content coverage

Sigma covers endpoint telemetry only. For this family see also
[`suricata/componenttask33.rules`](../suricata) — 8 PCAP-validated rules covering the C2
WebSocket upgrade, the panel banner, the remote-script pull, the delivery gate, MSI
delivery, and on-chain C2 discovery — and [`yara/componenttask33.yar`](../yara) (agent
source, config descriptor, builder residue).

Two things the capture corrected, worth knowing before you write your own network rules:
agent→C2 WebSocket **data frames are RFC6455-masked**, so the `register`/`heartbeat` JSON
is not matchable on the wire; and the `eth_call` RPC is **HTTPS**, so only its TLS SNI is
visible. Detect the plaintext upgrade handshake and the server banner instead.

Suricata `sid:9100006` and `sid:9100008` are **generic** EtherHiding analytics and will
fire on legitimate crypto tooling. Deploy them for hunting, not inline blocking.
