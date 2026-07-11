# tests

Illustrative event fixtures for each detection: at least one event that **should**
fire the rule (`"_expect": "fire"`) and one benign event that **should not**
(`"_expect": "quiet"`). Field names follow the Sigma logsource taxonomy for the
rule's category (`process_creation`, `file_event`, `proxy`), so they double as
documentation of exactly what each rule keys on.

These are hand-authored examples, not captured customer telemetry — no client or
victim data. They are here to make the detection logic reviewable and to seed a
proper test harness.

## Running them for real

The canonical rules live in [`../sigma/`](../sigma). To exercise them end to end,
convert to a backend and replay the fixtures, e.g.:

```bash
pip install sigma-cli
sigma convert -t splunk ../sigma/clickfix-powershell-irm.yml
# then run the query against an index loaded with fixtures/clickfix-powershell-irm.json
```

`sigma check` (run in CI) validates rule structure; wiring the fixtures into a
pySigma backend pipeline for automated fire/quiet assertions is the next step —
see CONTRIBUTING.

## Live-behavior validation

Where a public [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
test reproduces the behavior safely in a lab, it is cited in the detection's
**Validation notes**. Atomics used:

| Detection | Technique | Atomic Red Team |
|---|---|---|
| DET-0003 | T1218.007 Msiexec | T1218.007 (msiexec install of local/remote MSI) |
| DET-0004 | T1218 / T1105 Finger | T1105 (finger.exe ingress transfer atomics) |
| DET-0005 | T1547.001 Startup folder | T1547.001 (Startup folder persistence atomics) |

Run atomics only in an isolated lab you own.
