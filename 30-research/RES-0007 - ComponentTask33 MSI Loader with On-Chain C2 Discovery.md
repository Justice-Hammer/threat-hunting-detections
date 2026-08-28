---
id: RES-0007
title: "ComponentTask33 MSI Loader with On-Chain C2 Discovery"
type: research
attack_techniques: [T1189, T1218.007, T1059.005, T1059.001, T1053.005, T1036.005, T1027, T1480, T1113, T1071.001, T1102, T1008, T1571, T1547.001, T1005, T1119, T1552.001, T1105, T1564.001]
informs_detections: ["[[DET-0007 - ComponentTask33 Node Agent Execution and Persistence]]"]
references:
  - "https://attack.mitre.org/techniques/T1102/"
  - "https://attack.mitre.org/techniques/T1218/007/"
  - "https://attack.mitre.org/techniques/T1564/001/"
created: 2026-08-28
updated: 2026-08-28
tags: [research, msi-loader, nodejs-rat, etherhiding, on-chain-c2, polygon, first-disclosure, componenttask33]
---

# ComponentTask33 MSI Loader with On-Chain C2 Discovery

**TLP:CLEAR** · **First observed:** 2026-08-27 (sample MSI built 2026-08-24)

An MSI dropper impersonating a Spotify installer deploys a purpose-built Node.js
agent (`win-agent-client`) that talks WebSocket C2 and resolves its current C2
address from a **Polygon smart contract** — EtherHiding-style discovery that survives
domain takedown. Family is unattributed; `ComponentTask33` is a working designation
taken from the install directory.

> [!warning] First-disclosure release
> This note publishes live infrastructure indicators **ahead of any public vendor
> attribution**, under the first-disclosure exception in
> [CONTRIBUTING](../CONTRIBUTING.md#first-disclosure-exception). The basis:
>
> - **Nobody has reported this family.** No public vendor reporting, no public campaign
>   name. A public sandbox detonation scored the MSI **3/100 (clean)** with zero YARA,
>   Sigma, or Suricata hits. The sample is effectively invisible to signature tooling
>   until rules like the accompanying set exist.
> - **Sample-derived, not client-derived.** Everything here comes from static
>   examination of the sample and a public sandbox report. Nothing is victim-identifying.
> - **Live campaign selectors are redacted.** The per-victim bot `token` in the decoded
>   config is withheld — publishing it would burn visibility for no defensive gain.
> - **The tradeoff, stated plainly.** The Polygon contract is the durable, actor-controlled
>   indicator; publishing it tips the operator to redeploy. We judge that defenders
>   knowing about contract-based C2 discovery in a family nothing detects outweighs the
>   visibility lost. Reasonable people can disagree.
>
> No actor attribution is asserted and no country is attributed.

## Summary

An MSI installer impersonating a Spotify client drops a Node.js agent into
`%LOCALAPPDATA%\ComponentTask33\`, then **scatters** the payload across four
decoy directories under `%LOCALAPPDATA%`/`%APPDATA%` (Windows shell/cache
folders) so no single directory resembles malware. A launcher/persistence stub
remains in `ComponentTask33\`. The agent — not the MSI — then registers a
scheduled task (`ComponentTask33Agent`, AtLogon, per-user) that runs
`wscript.exe //B` against a hidden VBScript, which re-exports the scattered
paths and launches `node.exe`. Its configuration is stored base64-over-XOR on
disk and specifies a WebSocket C2 plus a **Polygon smart contract used to
discover the current C2 address**, making the infrastructure resistant to
domain takedown.

Notable: a public sandbox detonation scored this **3/100 (clean)** with no YARA,
Sigma, or Suricata hits — the payload's disk footprint is legitimate npm content
and the agent had not beaconed before analysis ended. The WebSocket C2 below was
recovered only by static config decryption; it does not appear in the sandbox's
network capture.

> Impersonation note: this malware impersonates Spotify. Spotify AB is not
> implicated or compromised in any way.

## Execution & persistence chain

1. **Install.** `msiexec /i` on the ~57 MB "Spotify" MSI — a **per-user** install (no
   UAC, medium integrity). Two custom actions fire **after `InstallFinalize`** in the
   user's context:
   - `powershell … -File "…\._scatter.ps1" -AnchorDir "<dir>"` — **scatters** the payload
     into four decoy directories (see Host artefacts).
   - `wscript.exe //B "…\._agent.vbs"` — **starts** the agent once.
2. **Persist.** On first run the **agent — not the MSI** — runs
   `StreamServiceSharedBridge.ps1`, which registers scheduled task `ComponentTask33Agent`
   (AtLogon, per-user, hidden); on failure it falls back to an HKCU Run key. Persistence
   therefore appears as `node.exe → powershell.exe`, seconds **after** `msiexec` exits.
3. **Four launch paths** (all resolve to `node.exe app\src\index.js` from the scattered
   runtime):
   - the scheduled task → `wscript //B ._agent.vbs` (steady state);
   - `._agent.vbs` / `WorkerLocalSnap.vbs` (hidden VBScript → node);
   - `ProfileQuickHost.exe` (native .NET launcher → node);
   - `ManagerPrivateLoader.cmd` (cmd → PowerShell persistence + VBScript).
4. **Beacon.** After a 10–30 s jitter: resolve the current C2 (read the Polygon contract →
   panel URL), open `ws[:]//…:3847`, send a `register` frame, then a heartbeat every
   ~12 minutes.

## Network indicators

| Indicator | Type | Role | Confidence | Provenance |
|---|---|---|---|---|
| `api-configuard[.]com` | domain | Delivery gate | High | Observed |
| `82.25.63[.]146` | IPv4 | Resolves `api-configuard[.]com` (ASN 207043) | High | Observed |
| `/capher.php?token=<30-32 chars>` | URI pattern | Delivery gate, token-gated (serves `ComponentTask33-*.msi`) | High | Observed |
| `shift-api-control[.]com` | domain | WebSocket C2 panel (Node.js Express) | High | **Wire-observed** |
| `ws[:]//shift-api-control[.]com:3847` → `176.65.144[.]127` | URL | C2 endpoint | High | **Wire-observed** (2026-08-27) |
| `0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4` | Polygon contract | On-chain C2 discovery | High | Config-derived |
| chainId `137` | Polygon mainnet | C2 discovery chain | High | Config-derived |

### Context only — DO NOT BLOCK

| Indicator | Why not to block |
|---|---|
| `polygon-bor.publicnode[.]com` | Legitimate free public Polygon RPC endpoint, used by many wallets and dApps. Abused here as the read path for contract-based C2 discovery. Blocking it breaks legitimate crypto tooling. |
| `104.20.24[.]117` | Shared CDN address fronting the above. Blocking causes broad collateral impact. |

The **contract address and chainId** are the durable, actor-controlled indicators.
The RPC endpoint is interchangeable and should be treated as context.

> Wire-observed 2026-08-27 (detonation): delivery `api-configuard[.]com` → `82.25.63[.]146`
> served `ComponentTask33-*.msi` via `/capher.php?token=`; the agent then read the Polygon
> contract over the RPC and beaconed `ws[:]//176.65.144[.]127:3847`. The C2 panel is a Node.js
> **Express** server (`X-Powered-By: Express`); it authenticates agents with a 16-char
> `X-Agent-Token` bearer (per-victim; **redacted**). Agent→C2 WebSocket frames are RFC6455-masked.

## File indicators

**MSI dropper** — `ComponentTask33-4d14e6ac.msi` (cached as `C:\Windows\Installer\<rand>.msi`)

```
MD5     14D37B2BA441E42D5D13BD2596DA3EBC
SHA1    0DC63AE29698CD3126EEFF0E47E999D8AB9485D7
SHA256  20A9E297220FE4CB9F939EAA82582C6E9A8F6DD4424635206DEC08FA1986B8FA
Size    56,943,312 bytes
Entropy 7.9948
```

**Encoded config** — `HiddenVirtualSilentLoader.dat`

```
MD5     039B73BD42E102F9366BD0B83189DCC7
SHA1    F4D56A9A29825006DFDF1C7178B11BBDF23E83D1
SHA256  601A84ADAA7100F10060F1E8432D5A1981491CEF944AA8212FAB87BCB11DFCFC
Size    400 bytes
Entropy 5.2597
```

**.NET helper tools** (unsigned, ~4.6 KB managed .NET 4.x, compiled 2026-08-21
21:17:54 UTC; on-disk filenames rotate per build — internal names and MVIDs do not):

`ProfileQuickHost.exe` — native launcher (internal name `WinAgent.exe`; launches
`node.exe app\src\index.js` hidden, `--uninstall`-aware)

```
MD5     44F618069D818E7DBD8E3B185957F3A7
SHA256  9FA80577B8B3CB9C3062E5E1986CC9FE0C26EED023F7D430DFA5C60169C15C45
MVID    c09f0e9b-1541-4553-858f-405d8c8ca297
```

`SearchTrustedRuntimeSvc.exe` — screenshot grabber (internal name `CaptureScreen.exe`;
full virtual-screen → PNG; `Usage: CaptureScreen.exe <output.png>`)

```
MD5     15D28D022A2417BF6E50030305EC6141
SHA256  7969CCAF1DB750BC3B02D51626D6916ECBD0C0CF2F7DE3C7BC0BE240F5F2978D
MVID    5c8e4531-c334-4e10-b389-481f7a12ade3
```

## Host artefacts

The payload is **scattered** at install time: `._scatter.ps1` (run by an MSI custom
action) relocates the executable payload out of `%LOCALAPPDATA%\ComponentTask33\`
into four decoy directories and leaves only a launcher/persistence stub behind. The
digit-suffixed folder names below are **constant for this build** but are expected to
**rotate between builds** (the builder is polymorphic) — treat the *layout shape* as
the durable indicator and the exact leaf names as build-specific.

**Post-install file layout**

| Role | Directory | Key contents |
|---|---|---|
| Anchor (stub) | `%LOCALAPPDATA%\ComponentTask33\` | `install-meta.json`, `._agent.vbs`, `._scatter.ps1`, `StreamServiceSharedBridge.ps1`, `WorkerLocalSnap.vbs`, `ManagerPrivateLoader.cmd` |
| Runtime | `%LOCALAPPDATA%\Microsoft\Windows\Libraries\QuickSystemSearch\` | `node.exe`, `npm.cmd`, `npx.cmd`, `node_modules\` |
| App (Roaming) | `%APPDATA%\Microsoft\Windows\Themes\SettingsHostStandard58\` | `app\src\*.js`, `app\node_modules\{ws, node-pty, node-addon-api}` |
| Config | `%LOCALAPPDATA%\Microsoft\Windows\INetCache\FilterManager\` | `HiddenVirtualSilentLoader.dat` (encoded config), `config.example.json`, `agent-id.txt`, `agent-version.json`, `connect-delay-state.json`, `wallet-check-state.json` |
| Tools | `%LOCALAPPDATA%\Microsoft\Windows\Shell\RemoteTempPrimary\` | `ProfileQuickHost.exe` (launcher), `SearchTrustedRuntimeSvc.exe` (screenshot tool) |

**Persistence**

| Artefact | Value |
|---|---|
| Scheduled task | `ComponentTask33Agent` — AtLogon, current user, hidden, no time limit. **Registered by the agent (`node.exe` → `powershell.exe`), not by `msiexec`.** |
| Task command | `wscript.exe //B "%LOCALAPPDATA%\ComponentTask33\._agent.vbs"` |
| Run-key fallback | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ComponentTask33Agent` — written **only if** scheduled-task registration fails; same command |

**Transient / teardown artefacts**

| Artefact | Context |
|---|---|
| `%TEMP%\wa-kill-*.cmd` | Self-deleting batch that `rd /s /q`'s the scattered dirs (operator `kill`) |
| `%TEMP%\wra-update-*.zip`, `%TEMP%\wra-apply-*.ps1` | Staged by the self-update handler |

> Notes:
> - The declared config value `scatter.anchor` -> `...\Themes\SharedSecureHelper30` is a
>   **dead string** — nothing is ever written there; the real anchor stays at
>   `ComponentTask33\`. Do not block/hunt `SharedSecureHelper30`.
> - `MonitorExtensionStreamLoader.cmd` is referenced in metadata but never shipped or
>   created — a dead reference, not an artefact.
> - Plaintext `config.json` is deleted during scatter; only the XOR-packed
>   `HiddenVirtualSilentLoader.dat` survives.
> - An MSI **uninstall does not remove** the scattered payload, the scheduled task, or
>   the Run-key fallback — they persist independently of the installer.

**MSI GUIDs**

```
ProductCode     {DBC7258E-9E9F-4064-8B65-BFEDEF7DC170}
UpgradeCode     {F22A91B0-7A00-4C4D-A9AC-0DE43E0BD888}   (durable cross-build pivot)
RevisionNumber  {D8A44DF9-B908-4D66-9A46-27E37C76A066}
Component (._agent.vbs)         {5C29ECCA-C989-4C0D-BBAC-70A5F809806F}
Component (._scatter.ps1)       {2DFE01AA-B480-467D-85D3-33BF792C71E8}
Component (agent-version.json)  {C01EC33B-C359-45A4-89B6-B528857F3AEE}
Component (config.example.json) {75E04C4F-0B92-4129-AABC-0BED294BDABB}
```

**MSI metadata (impersonation lure)**

```
Author    Spotify AB
Subject   Spotify music streaming client installer
Keywords  Spotify;Music;Streaming;Media
Builder   Windows Installer XML Toolset (3.14.1.8722)
Created   2026-08-24 11:20:32 UTC
```

## Configuration format

`HiddenVirtualSilentLoader.dat` is **base64 → repeating-key XOR**. **The XOR key is not a
constant** — it is the `buildSeed` value stored in that build's `install-meta.json`, and it
**rotates per build**. For this sample `buildSeed` = `c8c384083f`, but a hunt rule must
**never hardcode that value** — read it from the sibling `install-meta.json` instead:

```python
import base64, json
seed = json.load(open('install-meta.json'))['buildSeed'].encode()   # rotates per build
raw  = base64.b64decode(open('HiddenVirtualSilentLoader.dat','rb').read())
cfg  = bytes(b ^ seed[i % len(seed)] for i, b in enumerate(raw))
print(cfg.decode())
```

Decoded structure (indicators **defanged**; this build):

```json
{"token":"<per-victim bot id — redacted>",
 "heartbeatIntervalMs":720000,
 "reconnectDelayMs":15000,
 "panelUrl":"ws[:]//shift-api-control[.]com:3847",
 "contractDiscovery":{
   "enabled":true,
   "address":"0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4",
   "chainId":137,
   "rpcUrl":"hxxps://polygon-bor.publicnode[.]com",
   "cacheTtlMs":300000}}
```

Operational values: heartbeat 12 minutes, reconnect delay 15 seconds, C2 discovery cache
TTL 5 minutes. When `contractDiscovery.enabled` is true the agent **deletes** the static
`panelUrl` and takes its C2 solely from the contract — so the **contract is the durable
indicator**, and a takedown of the panel domain alone is low-value. The per-victim `token`
is a live campaign selector and is **kept redacted** (publishing it may burn visibility).

## Agent capabilities

A **purpose-built** Node.js RAT (`win-agent-client`), not a trojanised legitimate app. The
operator drives it over the WebSocket with JSON `{type, payload}` messages — **13 built-in
command types**, plus two ways to run arbitrary code, so the built-ins are a **floor, not a
ceiling**:

| Command | What it does |
|---|---|
| `powershell` / `cmd` | run a PowerShell / cmd.exe command; returns stdout/stderr/exit |
| `shell` | interactive PTY (node-pty ConPTY) — `cmd.exe` or `powershell.exe` |
| `eval` | run arbitrary JavaScript in-process (`fs`/`os`/`path`/`Buffer` exposed) |
| `download_run` | download a URL to `%TEMP%`, execute it detached + hidden |
| `deploy` | drop and run an MSI / PS1 / CMD (base64 or URL); MSI installs per-user |
| `files` | list / read / write / delete / download files; drive scan (read ≤5 MB, download ≤50 MB) |
| `screenshot` | full virtual-screen PNG (native tool, PowerShell fallback) |
| `wallet_scan` | **presence-only** crypto-wallet enumeration (see below) |
| `agent_update` | replace the agent's own source from a base64 zip and relaunch |
| `kill` | uninstall persistence and wipe the scattered directories |
| `reconnect` / `capabilities` / `load_script` | control / metadata |
| *(remote script)* | a per-connect script from `/api/agent/script` can register **new** command types via `extraCommands` |

**Wallet targeting — scope it precisely.** `wallet_scan` is **operator-triggered,
presence-only, report-only**: it enumerates ~37 desktop-wallet folders and ~48
browser-extension wallet IDs and returns `{name, type, path}`. **It reads no keystores or
seed phrases.** It is a *targeting* capability, not theft in itself — extraction would be a
separate second step (`files` / `eval` / `deploy`). Describe victim impact this way: neither
oversell it as a "wallet stealer" nor undersell the risk.

**No guardrails.** No VM/sandbox/geo checks anywhere in the agent (ATT&CK T1497 notably
**absent**) — worth stating explicitly, since its evasion relies entirely on looking like a
developer tool.

## MITRE ATT&CK

| Tactic | ID | Technique |
|---|---|---|
| Initial Access | T1189 | Drive-by Compromise (token-gated delivery URL) |
| Execution | T1218.007 | System Binary Proxy Execution: Msiexec |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location (Spotify) |
| Defense Evasion | T1027 | Obfuscated Files or Information (base64 + XOR config) |
| Defense Evasion | T1480 | Execution Guardrails (token-gated delivery) |
| Collection | T1113 | Screen Capture (`SearchTrustedRuntimeSvc.exe` / PS fallback) |
| C2 | T1071.001 | Application Layer Protocol: Web Protocols (WebSocket) |
| C2 | T1102 | Web Service (blockchain used for C2 resolution) |
| C2 | T1008 | Fallback Channels (on-chain C2 discovery) |
| C2 | T1571 | Non-Standard Port (3847) |
| Persistence | T1547.001 | Registry Run Key (fallback when task registration fails) |
| Collection | T1005 | Data from Local System (`files` read/download) |
| Collection | T1119 | Automated Collection (`wallet_scan` enumeration) |
| Collection | T1552.001 | Unsecured Credentials: Credentials in Files (wallet targeting) |
| Command & Control | T1105 | Ingress Tool Transfer (`download_run`, `deploy`, `agent_update`) |
| Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files/Dirs (dot-prefixed files, scatter into shell/cache dirs) |

## Hunting guidance

- Scheduled tasks named `ComponentTask33Agent`, or any AtLogon/per-user task invoking
  `wscript.exe //B` against a dot-prefixed `.vbs` under `%LOCALAPPDATA%`.
- Process lineage `msiexec.exe → powershell.exe` with `-File "*\._scatter.ps1"
  -AnchorDir "*"` (the `-AnchorDir` switch is high-selectivity), plus the sibling
  `msiexec.exe → wscript.exe //B "*\._agent.vbs"`.
- Scheduled-task creation via `node.exe → powershell.exe … Register-ScheduledTask`
  **decoupled in time from `msiexec`** — the tell that persistence is agent-registered,
  not installer-registered.
- `msiexec /i` against a >50 MB MSI in `%USERPROFILE%\Downloads`.
- Files named `._agent.vbs`, `._scatter.ps1`, or `HiddenVirtualSilentLoader.dat`
  anywhere on disk (dot-prefixed names are unusual on Windows).
- **Scattered Node runtime:** `node.exe` beside `node_modules\` in a leaf directory
  under `%LOCALAPPDATA%\Microsoft\Windows\{Libraries,INetCache,Shell}\` or
  `%APPDATA%\Microsoft\Windows\Themes\` — especially a leaf holding
  `app\src\index.js` beside `node_modules\ws`. Legitimate software does not stage a
  Node runtime in these shell/cache folders. (The exact leaf names rotate per build;
  match on the shape.)
- A `._agent.vbs` that sets `AGENT_ANCHOR`/`AGENT_RUNTIME`/`AGENT_APP`/`AGENT_CONFIG`/
  `AGENT_TOOLS` and launches `node.exe` from a *different* AppData leaf than its own.
- Self-deleting `%TEMP%\wa-kill-*.cmd` running `rd /s /q` against multiple AppData
  leaves (self-destruct), or `%TEMP%\wra-update-*.zip` + `wra-apply-*.ps1` (self-update).
- Endpoint DNS/flow to `shift-api-control[.]com`, or WebSocket traffic to port 3847.
- Non-crypto endpoints issuing `eth_call` / JSON-RPC to public blockchain RPC
  endpoints — a strong general signal for EtherHiding-style malware regardless of
  this specific family.

## Caveats

- The MSI's parent campaign, distribution method, and targeting are unknown. The
  delivery URL was token-gated; the token is likely single-use or short-lived.
- No public sandbox or AV verdict identified this as malicious at time of writing; a
  detonation scored it 3/100 (clean) with zero YARA/Sigma/Suricata hits. The sample is
  effectively invisible to signature tooling until rules like the accompanying set exist.
- `polygon-bor.publicnode[.]com` is a legitimate service — see the do-not-block table.
- No actor attribution is asserted. Hosting-provider overlap with unrelated
  campaigns is not treated as evidence of a shared operator.

## Detections

A companion rule set ships with this note:

| Format | Path | Covers |
|---|---|---|
| Sigma | [`sigma/componenttask33-*.yml`](../sigma) (6 rules) | all four launch paths, the scatter destinations, and the time-decoupled scheduled-task registration |
| YARA | [`yara/componenttask33.yar`](../yara) (4 rules) | agent source, config/build descriptor, builder residue, .NET helpers |
| Suricata | [`suricata/componenttask33.rules`](../suricata) (SIDs 9100001-9100008) | WS upgrade handshake, C2 panel banner, remote-script pull, delivery gate, MSI delivery, on-chain discovery, and two generic EtherHiding analytics |

Machine-readable indicators: [`indicators/componenttask33-infra.csv`](../indicators/componenttask33-infra.csv).

**The Suricata rules are PCAP-validated**, and the capture corrected two assumptions that
static analysis got wrong. Agent→C2 WebSocket data frames are **RFC6455-masked**, so the
`register`/`heartbeat` JSON is *not* content-matchable on the wire — detection has to key on
the plaintext upgrade handshake and the server banner instead. And the `eth_call` RPC runs
over **HTTPS**, so its body is encrypted; the rule matches TLS SNI. Rules written against
the pre-capture assumptions would not have fired.

Two design notes carry into the rules. The YARA does **not** hardcode the per-build XOR key —
it anchors on the `buildSeed` key name and JSON shape, because the key rotates every build.
And `sid:9100006`/`sid:9100008` are **generic** EtherHiding analytics covering the TLS-SNI and
cleartext-HTTP paths to public EVM RPCs: the most transferable rules here, and the noisiest.
Deploy them as hunting analytics correlated against hosts with no other crypto activity,
**not** as inline blocks.

Consider submitting the MSI to MalwareBazaar (tag the loader family) so others can
retrohunt — it is currently unflagged by public tooling.

---
*Published TLP:CLEAR. Analysis derived from a public sandbox report and static
examination of the sample. Indicators are defanged. No third-party or customer data is
included; no actor attribution is asserted.*
