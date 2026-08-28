# Contributing

Thanks for helping improve these detections. This repo publishes sanitized
threat-hunting tradecraft: corrections, translations for other platforms, and
false-positive reports are all welcome.

## Ground rules

- **No client, victim, or case-identifying data** in issues, PRs, or commits.
- **No live infrastructure IOCs** (IPs, C2 domains) unless the associated campaign
  already has public vendor attribution, **or** the release qualifies as a first
  disclosure under the exception below. See `indicators/README.md`.

### First-disclosure exception

The attribution rule above assumes someone else has already published. For a family
that no vendor has reported and no engine detects, it deadlocks: nobody can ever be
first, and defenders get nothing.

Infrastructure IOCs may be released ahead of public vendor attribution when all of
the following hold, and the release note says so explicitly:

- The family has **no public vendor reporting and no meaningful AV/sandbox detection**
  at time of writing (state the evidence, e.g. a sandbox score).
- The indicators are **derived from a sample**, not from a client environment, and
  carry nothing victim-identifying.
- Any indicator that is a **live campaign selector** (per-victim bot IDs, session
  tokens, single-use delivery tokens) is **redacted** — those burn visibility for no
  defensive gain.
- The operational tradeoff is **stated in the note**: publishing durable infrastructure
  tips the operator to rotate it. Publish anyway only when defender value clearly
  exceeds the visibility you lose.

This is a deliberate, documented exception. It is not a general relaxation of the rule,
and it does not apply to anything sourced from a client engagement.
- Defang IOCs in prose (`1.2.3[.]4`, `hxxps://`); keep the raw value only in the
  machine-readable `value:` field of a CSV where a pivot needs it.
- Everything here is **TLP:CLEAR**. If it can't be, it doesn't belong in this repo.

## Editing a detection

Each detection has two copies of its Sigma rule:

1. The canonical, machine-readable rule in [`sigma/`](sigma). This is what CI validates.
2. A readability copy embedded in the `20-detections/` page.

**Change both and keep them identical.** CI validates the `.yml`; it does not yet
diff the two, so drift is on you to prevent.

### Rule conventions

- `id` must be a freshly generated **UUIDv4** (`uuidgen` or `python3 -c "import uuid;print(uuid.uuid4())"`), never hand-typed, so it's guaranteed unique and valid.
- Include `author`, `date`, `status`, `level`, `falsepositives`, and `tags`.
- `status:` uses the [SigmaHQ maturity values](https://github.com/SigmaHQ/sigma-specification) (`experimental` → `test` → `stable`). The page frontmatter's `status: validated` is a *separate* analyst workflow field; don't conflate them.
- Every named selection must be referenced by `condition`.
- Platform translations (KQL/SPL/ES\|QL/LogScale) are hand-written; note that they are not `sigma convert` output.

## Before you open a PR

```bash
pip install pyyaml sigma-cli
python3 tools/validate-sigma.py   # offline structural gate
sigma check sigma/                # pySigma schema + best-practice checks
python3 -m compileall scripts tools
```

CI runs the same checks (`.github/workflows/sigma-validate.yml`).

## Adding test fixtures

New or changed rules should ship a fixture in [`tests/fixtures/`](tests/fixtures)
with at least one `"_expect": "fire"` and one `"_expect": "quiet"` event using the
Sigma logsource field names. Wiring these into a pySigma backend for automated
fire/quiet assertions is a welcome contribution.
