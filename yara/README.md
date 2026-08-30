# yara

TLP:CLEAR YARA rules, one `.yar` per family.

| File | Family | Rules |
|---|---|---|
| `componenttask33.yar` | ComponentTask33 (MSI loader → Node.js agent) | build/config descriptor, agent source, builder residue, .NET helpers |

## Scan

```bash
yara -r yara/componenttask33.yar /path/to/sample
```

## Design notes

Rules anchor on structure that survives a rebuild, not on per-build values. In
particular the ComponentTask33 config store is XOR-packed with a key that **rotates
per build** (it is the `buildSeed` field of that build's `install-meta.json`), so the
config rule matches the *key name* and surrounding JSON shape rather than any key
byte value. Do not "improve" these rules by hardcoding a seed you observed in one
sample — it will not match the next one.

The `.NET` helper rule is LOW priority: on-disk filenames rotate per build, so it
pins embedded internal names. Prefer the MVIDs listed in the related research note
when you need a hard identifier.

## A known false-positive class

These rules match on indicator strings, so they will also fire on **prose that discusses the
malware**: incident reports, IOC lists, this repository's own documentation. That is expected
rather than a defect, since the strings are exactly what the rules key on.

If you scan a directory that mixes samples with written analysis, exclude your notes, or filter
hits to the file types you actually care about. `ComponentTask33_BuilderResidue` is the most
prone to this because any single one of its strings is enough to trigger it, which is the
tradeoff for its being a retrohunt anchor rather than a triage rule.

