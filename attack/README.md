# attack/

ATT&CK Navigator coverage layer for this repository. One file lives here: `navigator-layer.json`, a machine-readable map of every MITRE ATT&CK technique the detections, hunts, and research notes reference.

## What the layer shows

Each technique carries a score equal to the number of artifacts that cite it. A technique referenced by one detection and two hunts scores 3. Every technique's `comment` field lists the exact page IDs behind it, so a highlighted cell traces straight back to the work that covers it.

Higher-scoring techniques render darker on the matrix. The gradient runs from 1 (a single artifact) up to the current maximum. Only techniques with coverage appear; everything else stays hidden.

## Load it in ATT&CK Navigator

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Choose "Open Existing Layer", then "Upload from local".
3. Select `navigator-layer.json`.

The layer targets the Enterprise matrix (`enterprise-attack`, ATT&CK v15). Hover any highlighted cell to see which pages cover that technique.

## How it is generated

The layer is derived, not hand-maintained. `scripts/build-navigator-layer.py` reads the `attack_techniques` list from the frontmatter of every hunt, detection, and research page, inverts it into a technique-to-pages map, and writes this file. Editing `navigator-layer.json` by hand is pointless: the next run overwrites it.

Regenerate the layer whenever a page's technique list changes:

```
python3 scripts/build-navigator-layer.py
```

Verify the committed layer still matches the pages, without writing anything:

```
python3 scripts/build-navigator-layer.py --check
```

`--check` exits non-zero when the layer has drifted from the pages, which makes it a suitable gate for CI. A stale layer then fails the build instead of shipping.
