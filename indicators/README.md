# indicators

TLP:CLEAR behavioral and kit-level indicators derived from real cases. Infrastructure IOCs (IPs, domains) are only released here once the associated campaign has public vendor attribution — until then they stay in private case files.

## Format

Each CSV has these columns:

| Column | Description |
|---|---|
| `value` | The indicator value |
| `type` | Indicator type (see types below) |
| `context` | What this indicator represents |
| `first_seen` | Earliest observed date (YYYY-MM-DD) |
| `campaign` | Loose campaign label — not a case ID |
| `confidence` | high / medium / low |
| `tlp` | Always CLEAR in this folder (public repo) |

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

## What's not here

- Live infrastructure IOCs (IPs, C2 domains) without public vendor attribution
- Victim-identifying information of any kind
- Case IDs or client references

## Attribution basis

The behavioral and kit-level indicators here map to activity clusters with existing
public reporting — see the **Public attribution** sections in the related research
notes and hunts (`ClickFix/EVALUSION` → RES-0004, `CastleLoader/TAG-150` → HUNT-0006,
`PBaaS` → RES-0006). That prior public attribution is what makes these safe to
release TLP:CLEAR.
