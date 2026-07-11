# threat-hunting-detections

Production-grade detections, hunt playbooks, and research notes from real-world incident response and threat hunting engagements. All content is **TLP:CLEAR** and safe for public distribution.

---

## About

I'm a threat hunter and incident responder. This repo is where I publish finished work: detections that fired on real intrusions, hunt playbooks built around actual adversary behavior, and research notes on attack techniques I've had to understand deeply enough to detect.

Everything here started as internal case work. Cases are scrubbed before publishing: no client names, no victim identifiers, no proprietary context. What remains is the tradecraft: the detection logic, the hunt queries, the TTP analysis (which I think is more useful to the community than case details anyway).

### What's in here

| Folder | Contents |
|---|---|
| `20-detections/` | Finished detection rules with multi-platform Sigma + KQL/SPL/ES\|QL/LogScale translations |
| `10-hunts/` | Hunt hypothesis → query → findings → detection playbooks |
| `30-research/` | Attack technique deep-dives that informed detections or hunts |
| `indicators/` | TLP:CLEAR behavioral and kit-level indicators in CSV format; infrastructure IOCs released only after public vendor attribution |
| `sigma/` | Machine-readable canonical Sigma rules (one `.yml` per detection) for direct `sigma convert` |
| `scripts/` | Standalone investigation utilities: CT log timeline builder, S3 public bucket probe, domain registration batch correlator |
| `tests/` | Sample true-positive / benign events per detection, plus Atomic Red Team references |
| `attack/` | ATT&CK Navigator layer (`navigator-layer.json`) of technique coverage |

> **A note on the ID numbering.** Page IDs (HUNT-0005, DET-0002, RES-0004…) are the original internal case IDs, carried over so cross-references stay stable. They start mid-sequence because not every internal artifact is cleared for public release. Gaps are expected and do not indicate missing files.

### Detection format

Each detection ships in **Sigma** (canonical, also as a standalone file in `sigma/`) plus translations for Microsoft Defender / KQL, Elastic ES\|QL, Splunk SPL, and CrowdStrike LogScale. False positive context and validation notes are included for every rule. I only publish detections I've validated against real telemetry or a controlled lab environment.

The platform translations are **hand-written**, not `sigma convert` output, so verify against your schema before deploying. Two `status` vocabularies appear by design: the page frontmatter `status: validated` is my analyst workflow state (confirmed against telemetry), while the embedded Sigma `status: test` follows the [SigmaHQ maturity convention](https://github.com/SigmaHQ/sigma-specification) (tested, may still surface environment-specific FPs).

### Detection ↔ technique coverage

| Detection | Technique(s) | Platforms | Source hunt |
|---|---|---|---|
| DET-0002: ClickFix PowerShell IRM Execution | T1059.001, T1204.001 | Sigma · KQL · SPL · ES\|QL · LogScale | HUNT-0005 |
| DET-0003: Msiexec Silent Install from ProgramData | T1218.007 | Sigma · KQL · SPL · ES\|QL · LogScale | HUNT-0005 |
| DET-0004: Finger LOLBin Remote Script Retrieval | T1218, T1105 | Sigma · KQL · SPL · ES\|QL · LogScale | HUNT-0006 |
| DET-0005: Startup Folder Write by Non-Installer Process | T1547.001 | Sigma · KQL · SPL · ES\|QL · LogScale | HUNT-0005, HUNT-0006 |
| DET-0006: Vue.js Fake Trading Platform Kit Fingerprint | T1583.001, T1608.005 | Sigma · KQL · SPL · ES\|QL · YARA | HUNT-0007 |

Full technique map (including hunt-only techniques like T1573.001 and T1530) is in [`attack/navigator-layer.json`](attack/navigator-layer.json). Load it into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see coverage across the matrix.

### Coverage so far

- **ClickFix / fake CAPTCHA delivery chains** (PowerShell IRM, msiexec LOLBin, finger.exe LOLBin)
- **NetSupport RAT and CastleLoader/CastleRAT delivery** (EVALUSION and GrayBravo MaaS ecosystems)
- **Startup folder persistence** (user-writable, no elevation required)
- **Infrastructure reconnaissance** (PBN link injection for C2 domain reputation laundering)
- **Pig-butchering-as-a-Service (PBaaS)** (Vue.js fake trading platform fingerprints, multi-tenant S3 infrastructure, passive OSINT hunt methodology)

---

## Contributing

Issues and PRs welcome. If a query is wrong for your environment or a translation is off, [open an issue](../../issues/new/choose). See [CONTRIBUTING.md](CONTRIBUTING.md) for the rule format, the `status` conventions, and how to run the validators locally.

## License

Released under the [Apache License 2.0](LICENSE). You may reuse and adapt the detections, scripts, and research with attribution. Copyright © 2026 Justice Hammer.

### Contact
- justice-hammer.pancake566@passmail.net
- Threat Hunter | Detection Engineer
