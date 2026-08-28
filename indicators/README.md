# indicators

TLP:CLEAR behavioral and kit-level indicators derived from real cases. Infrastructure IOCs (IPs, domains) are normally released here only once the associated campaign has public vendor attribution; until then they stay in private case files. The one exception is a **first disclosure** of a family nobody has reported yet — see [First-disclosure releases](#first-disclosure-releases) below and the full criteria in [`CONTRIBUTING.md`](../CONTRIBUTING.md#first-disclosure-exception).

## Format

Each CSV has these columns:

| Column | Description |
|---|---|
| `value` | The indicator value |
| `type` | Indicator type (see types below) |
| `context` | What this indicator represents |
| `first_seen` | Earliest observed date (YYYY-MM-DD) |
| `campaign` | Loose campaign label, not a case ID |
| `confidence` | high / medium / low |
| `tlp` | Always CLEAR in this folder (public repo) |

Values in the `value` column are **raw, not defanged** — these files are meant to be
fed to tooling. Prose everywhere else in this repo defangs (`1.2.3[.]4`, `hxxps://`).

### Indicator types

| Type | Description |
|---|---|
| `string` | Plaintext string literal in a file, memory, or network payload |
| `url-pattern` | URL path or query pattern (not a full URL) |
| `file-path` | File or directory path artifact |
| `mutex` | Windows mutex name |
| `named-pipe` | Windows named pipe path |
| `registry-key` | Windows registry key or value |
| `domain-pattern` | Regex or descriptive pattern matching a class of domains |
| `domain` | A specific domain name (first-disclosure releases only) |
| `ipv4` | A specific IPv4 address (first-disclosure releases only) |
| `url` | A full URL including scheme and port (first-disclosure releases only) |
| `contract-address` | Blockchain contract address used for on-chain C2 discovery |
| `sha256` | SHA-256 file hash |
| `mvid` | .NET module version id — stable across on-disk filename rotation |

## First-disclosure releases

A file may carry live infrastructure ahead of vendor attribution when the family is
genuinely unreported and undetected, the indicators come from a sample rather than a
client environment, and every live campaign selector (per-victim IDs, session or
delivery tokens) is redacted. Such files set `campaign` to the working designation and
are called out here:

| File | Basis |
|---|---|
| `componenttask33-infra.csv` | First disclosure. No public vendor reporting; a public sandbox detonation scored the MSI 3/100 (clean) with zero YARA/Sigma/Suricata hits. Per-victim bot token redacted. See `RES-0007`. |

## What's not here

- Live infrastructure IOCs (IPs, C2 domains) without public vendor attribution, unless
  released under the first-disclosure exception above
- Victim-identifying information of any kind
- Case IDs or client references
- Live campaign selectors (per-victim bot IDs, session tokens, single-use delivery
  tokens) — redacted even in first-disclosure releases

## Attribution basis

The behavioral and kit-level indicators here map to activity clusters with existing
public reporting; see the **Public attribution** sections in the related research
notes and hunts (`ClickFix/EVALUSION` → RES-0004, `CastleLoader/TAG-150` → HUNT-0006,
`PBaaS` → RES-0006). That prior public attribution is what makes these safe to
release TLP:CLEAR.
