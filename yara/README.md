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
