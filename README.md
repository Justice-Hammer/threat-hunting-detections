# threat-hunting-detections

Production-grade detections, hunt playbooks, and research notes from real-world incident response and threat hunting engagements. All content is TLP:GREEN and safe for public distribution.

---

## About

I'm a threat hunter and incident responder. This repo is where I publish finished work which include: detections that fired on real intrusions, hunt playbooks built around actual adversary behavior, and research notes on attack techniques I've had to understand deeply enough to detect.

Everything here started as internal case work. Cases are scrubbed before publishing: no client names, no victim identifiers, no proprietary context. What remains is the tradecraft: the detection logic, the hunt queries, the TTP analysis (which I think is more useful to the community than case details anyway).

### What's in here

| Folder | Contents |
|---|---|
| `20-detections/` | Finished detection rules with multi-platform Sigma + KQL/SPL/ES\|QL/LogScale translations |
| `10-hunts/` | Hunt hypothesis → query → findings → detection playbooks |
| `30-research/` | Attack technique deep-dives that informed detections or hunts |

### Detection format

Each detection ships in **Sigma** (canonical) plus translations for Microsoft Defender / KQL, Elastic ES\|QL, Splunk SPL, and CrowdStrike LogScale. False positive context and validation notes are included for every rule. I only publish detections I've validated against real telemetry or a controlled lab environment.

### Coverage so far

- **ClickFix / fake CAPTCHA delivery chains** (PowerShell IRM, msiexec LOLBin, finger.exe LOLBin)
- **NetSupport RAT and CastleLoader/CastleRAT delivery** (EVALUSION and GrayBravo MaaS ecosystems)
- **Startup folder persistence** (user-writable, no elevation required)
- **Infrastructure reconnaissance** (PBN link injection for C2 domain reputation laundering)
- **Pig-butchering-as-a-Service (PBaaS)** (Vue.js fake trading platform fingerprints, multi-tenant S3 infrastructure, passive OSINT hunt methodology)

---

Issues and PRs welcome. If a query is wrong for your environment or a translation is off, open an issue.

### Contact
- justice-hammer.pancake566@passmail.net
- Threat Hunter | Detection Engineer 
- If you are an attacker/adversary, my apologies for disrupting your campaign.
