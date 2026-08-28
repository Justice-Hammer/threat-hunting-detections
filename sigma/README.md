# sigma

Machine-readable canonical Sigma rules, one `.yml` per detection. These are the
same rules embedded in the `20-detections/` pages, extracted so you can feed them
straight into [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) / pySigma and
convert to your own backend rather than copy-pasting from Markdown.

| File | Detection | ATT&CK |
|---|---|---|
| `clickfix-powershell-irm.yml` | DET-0002: ClickFix PowerShell IRM Execution | T1059.001, T1204.001 |
| `msiexec-silent-install-programdata.yml` | DET-0003: Msiexec Silent Install from ProgramData | T1218.007 |
| `finger-lolbin-remote-script.yml` | DET-0004: Finger LOLBin Remote Script Retrieval | T1218, T1105 |
| `startup-folder-write-non-installer.yml` | DET-0005: Startup Folder Write by Non-Installer Process | T1547.001 |
| `pbaas-vuejs-trading-kit.yml` | DET-0006: Vue.js Fake Trading Platform Kit Fingerprint | T1583.001, T1608.005 |
| `componenttask33-msi-scatter-powershell.yml` | DET-0007: ComponentTask33 Node Agent Execution & Persistence | T1218.007, T1059.001 |
| `componenttask33-wscript-agent-vbs.yml` | DET-0007 | T1059.005, T1053.005 |
| `componenttask33-agent-task-selfregister.yml` | DET-0007 | T1053.005 |
| `componenttask33-scatter-filedrop.yml` | DET-0007 | T1564, T1036.005 |
| `componenttask33-node-appdata-pty.yml` | DET-0007 | T1059.007, T1059.003 |
| `componenttask33-msiexec-large-msi.yml` | DET-0007 (low-fidelity triage) | T1218.007 |

## Convert to your backend

```bash
pip install sigma-cli
sigma plugin install splunk        # or: microsoft365defender, elasticsearch, ...
sigma convert -t splunk sigma/clickfix-powershell-irm.yml
```

## Validate

```bash
sigma check sigma/               # pySigma schema + best-practice checks
python3 tools/validate-sigma.py  # offline structural gate (PyYAML only)
```

Both run in CI on every push; see `.github/workflows/sigma-validate.yml`.

## Other rule formats

Sigma covers endpoint telemetry only. Network and file-content coverage for the same
families lives in [`../suricata`](../suricata) and [`../yara`](../yara); neither is
validated by this CI job.

## Source of truth / avoiding drift

The `.yml` files here are the canonical rule text. The copies embedded in the
`20-detections/` pages are for readability. **When you change a rule, edit it in
both places** (or regenerate the `.yml` from the page). CI validates the `.yml`;
it does not currently diff the two, so keep them in sync by hand. The
platform translations (KQL/SPL/ES|QL/LogScale) in each detection page are
hand-written, not `sigma convert` output; verify them against your schema
before deploying.
