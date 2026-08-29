---
id: HUNT-0008
title: "Scattered MSI Loader and On-Chain C2 Hunt"
type: hunt
hunt_class: malware-analysis
status: closed
hypothesis: "A loader that scatters its payload across decoy directories and rotates every on-disk name per build can still be detected reliably, provided the rules anchor on structure that survives a rebuild — layout shape, config key names, and protocol handshakes — rather than on any observed literal value."
attack_tactics: [execution, persistence, defense-evasion, command-and-control]
attack_techniques: [T1189, T1218.007, T1059.005, T1059.001, T1059.007, T1053.005, T1036.005, T1027, T1113, T1071.001, T1102, T1008, T1571, T1547.001, T1105, T1564.001]
platforms_hunted: [static-analysis, msi, pcap, blockchain]
outcome: "Positive. Full kill chain and all four launch paths recovered from an unobfuscated agent source tree. On-chain C2 discovery confirmed by reading the Polygon contract. A detonation PCAP then overturned two static-analysis assumptions and reshaped the network rules. Produced DET-0007, RES-0007, and 18 rules across three formats."
produced_detections:
  - "[[DET-0007 - ComponentTask33 Node Agent Execution and Persistence]]"
related_research: ["[[RES-0007 - ComponentTask33 MSI Loader with On-Chain C2 Discovery]]"]
created: 2026-08-28
updated: 2026-08-28
tags: [hunt, msi-loader, nodejs-rat, etherhiding, on-chain-c2, polygon, scatter, static-analysis, pcap]
---

# Scattered MSI Loader and On-Chain C2 Hunt

## Hypothesis

Two design choices in this loader are meant to defeat signature detection: the payload is
**scattered** across four decoy directories at install time so no single directory looks
like malware, and effectively every on-disk name — directories, executables, the config
XOR key — **rotates per build**.

The hypothesis was that neither actually defeats detection, because both leave structure
that a rebuild cannot change. Specifically: the *shape* of the scatter layout, the *key
names* in the config descriptor, the *lineage* of the persistence registration, and the
*protocol handshake* on the wire. A rule set anchored on those should survive the next
build; a rule set anchored on observed literals should not.

The corollary matters just as much: any rule that pins a value we observed **once** is
worse than no rule, because it creates false confidence.

## Scope and data sources

- **MSI structural analysis** — `msiinfo` / `msiextract` / `7z` table export, custom
  action sequencing, component GUIDs
- **Agent source review** — the payload shipped **unobfuscated**, so the full command
  dispatch table and protocol were readable directly
- **On-chain read** — Polygon (chainId 137) contract queried via public RPC
- **Detonation PCAP** — public sandbox capture, 2026-08-27

Analysis was performed on a quarantined copy in an isolated VM. No adversary
infrastructure was probed directly; the contract read is a public blockchain query, and
the PCAP came from a public sandbox run.

## Findings

### The scatter is defense evasion, not lateral movement

An MSI custom action runs `._scatter.ps1 -AnchorDir <dir>` after `InstallFinalize` and
relocates the payload out of `%LOCALAPPDATA%\ComponentTask33\` into four decoy
directories under `%LOCALAPPDATA%` and `%APPDATA%` — Windows shell and cache folders that
are noisy and rarely inspected. A launcher stub stays behind at the anchor.

The leaf directory names are constant for a given build and rotate between builds. The
**layout is not**: a Node runtime beside `node_modules\` in a leaf under
`%LOCALAPPDATA%\Microsoft\Windows\{Libraries,INetCache,Shell}\` or
`%APPDATA%\Microsoft\Windows\Themes\` is the durable artifact. Legitimate software does
not stage a Node runtime in those folders.

### Persistence is registered by the agent, not the installer

This was the single highest-value host finding. The scheduled task `ComponentTask33Agent`
is created by `node.exe → powershell.exe`, **seconds after `msiexec` has already exited**.

That time-decoupling is what makes it detectable. Installers register their own
persistence inline; a payload that registers its own persistence after the installer is
gone produces a lineage that has very few benign analogues.

### The config XOR key is a per-build seed

The config store (`HiddenVirtualSilentLoader.dat`) is base64 over repeating-key XOR, and
the key is **not a family constant** — it is the `buildSeed` value in that build's own
`install-meta.json`. This sample used `c8c384083f`.

Any YARA rule that hardcoded that value would match exactly one build. The published rule
therefore anchors on the `buildSeed` **key name** and the surrounding JSON shape instead.

### Four launch paths, not one

The hidden VBScript is a thin bootstrap, not the only entry point. All four resolve to
`node.exe app\src\index.js` from the scattered runtime: the scheduled task via
`wscript //B`, the VBScripts directly, a native .NET launcher, and a CMD wrapper. Rules
written against only the VBScript path would miss three quarters of live infections.

### On-chain C2 discovery makes domain takedown low-value

When contract discovery is enabled the agent **deletes** its static `panelUrl` and takes
its C2 address solely from a Polygon contract. The contract address and chainId are the
durable, actor-controlled indicators; the panel domain is disposable. This inverts the
usual takedown calculus and is the most transferable finding in the case.

The public RPC endpoint used to read the contract is *not* an indicator — it is
legitimate, shared infrastructure, and blocking it breaks unrelated tooling.

### The PCAP overturned two static conclusions

Static analysis said the WebSocket C2 was cleartext, so rules were drafted to match the
`register` and `heartbeat` JSON. The capture showed:

- Agent→C2 WebSocket **data frames are RFC6455-masked**. The JSON is not
  content-matchable at the network layer at all. Detection has to key on the plaintext
  upgrade handshake and the server banner instead.
- The `eth_call` RPC runs over **HTTPS**, so its body is encrypted and only TLS SNI is
  visible.

**Rules built on the pre-capture reads would not have fired.** This is the argument for
validating network rules against a capture before publishing them, not after.

## Evidence trail

> [!note] Infrastructure overlap with a prior case — coincidence until proven
> Two independent overlaps with a prior NetSupport case were observed. Both are recorded
> here deliberately and **neither is treated as evidence of a shared operator**:
>
> 1. The delivery host shares **ASN 207043** with that case's dropper host.
> 2. The C2 panel address sits in the **same /24** as that case's confirmed C2 gateway.
>
> Both are bottom-of-the-Pyramid-of-Pain observations on known **shared bulletproof
> hosting**, where multiple unrelated actors are documented tenants. The TTPs are not
> comparable — commodity RAT versus a bespoke Node agent with on-chain discovery. This
> project has previously been misled by exactly this class of same-ASN edge.
>
> To settle it rather than assume it, the C2 address needs checking against the prior
> case's sibling criteria: the specific port, a self-signed certificate matching that
> pattern, **and** a JARM match — all three, never one alone. Until then this stays
> logged and unasserted. Nothing published for this case asserts a shared actor.

> [!warning] What this hunt could not establish
> The parent campaign, distribution method, and targeting are unknown. The delivery URL
> was token-gated and the token is likely single-use or short-lived. No actor attribution
> is asserted and no country is attributed.

## Outcome and products

| Product | Detail |
|---|---|
| [[DET-0007 - ComponentTask33 Node Agent Execution and Persistence]] | 6 Sigma rules across all four launch paths, the scatter destinations, and the agent-registered task |
| [[RES-0007 - ComponentTask33 MSI Loader with On-Chain C2 Discovery]] | Full analysis and first-disclosure advisory |
| `yara/componenttask33.yar` | 4 rules — config descriptor, agent source, builder residue, .NET helpers |
| `suricata/componenttask33.rules` | 8 PCAP-validated rules, SIDs 9100001-9100008 |
| `indicators/componenttask33-infra.csv` | 21 indicators |

The family had **no public vendor reporting and no meaningful detection** at time of
analysis — a public sandbox scored the MSI 3/100 (clean) with zero YARA, Sigma, or
Suricata hits. That is why this became the first release under the repository's
[first-disclosure exception](../CONTRIBUTING.md#first-disclosure-exception).

## Transferable tradecraft

Most of this generalizes past this one family:

- **Hunt the layout, not the leaf.** When names rotate per build, the directory *shape* is
  the indicator.
- **Watch for persistence that outlives its installer.** Payload-registered persistence,
  decoupled in time from the install, is a strong and under-used lineage signal.
- **Never pin a value you have seen once.** If a key rotates per build, anchor on the
  field name that holds it.
- **Generic EtherHiding analytic:** a non-crypto host issuing `eth_call` JSON-RPC to a
  public blockchain RPC is a signal for on-chain C2 discovery *regardless of family*.
  Published as `sid:9100006` / `sid:9100008` — hunting analytics, explicitly not safe to
  deploy inline, because public RPCs are dual-use.
- **Validate network rules against a capture.** Two of six drafted rules were wrong in a
  way only a PCAP would reveal.
