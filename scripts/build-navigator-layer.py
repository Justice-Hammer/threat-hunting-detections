#!/usr/bin/env python3
"""Regenerate attack/navigator-layer.json from page frontmatter.

Reads the `attack_techniques` list out of every hunt, detection, and research
page, inverts it into a technique -> pages map, and writes an ATT&CK Navigator
layer where each technique's score is the number of artifacts that reference it.

The layer is derived, not hand-maintained: run this whenever a page's
`attack_techniques` changes so coverage never drifts from the pages.

Usage:
    python3 scripts/build-navigator-layer.py           # write the layer
    python3 scripts/build-navigator-layer.py --check    # verify, no write (CI)

--check exits non-zero if the committed layer is stale, so CI can gate on it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAYER_PATH = REPO / "attack" / "navigator-layer.json"

# Page directories mapped to the noun used in the metadata artifact count.
PAGE_DIRS = {
    "10-hunts": "hunts",
    "20-detections": "detections",
    "30-research": "research notes",
}

_FRONTMATTER = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_ID = re.compile(r"^id:\s*(\S+)", re.MULTILINE)
_TECHNIQUES = re.compile(r"^attack_techniques:\s*\[([^\]]*)\]", re.MULTILINE)


def parse_page(path: Path) -> tuple[str | None, list[str]]:
    """Return (page_id, [technique_ids]) from a page's frontmatter."""
    text = path.read_text(encoding="utf-8")
    fm = _FRONTMATTER.search(text)
    if not fm:
        return None, []
    block = fm.group(1)
    id_match = _ID.search(block)
    page_id = id_match.group(1) if id_match else path.stem
    tech_match = _TECHNIQUES.search(block)
    techniques = []
    if tech_match:
        techniques = [t.strip() for t in tech_match.group(1).split(",") if t.strip()]
    return page_id, techniques


def build_layer() -> dict:
    coverage: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    for d, noun in PAGE_DIRS.items():
        pages = sorted((REPO / d).glob("*.md"))
        counts[noun] = len(pages)
        for path in pages:
            page_id, techniques = parse_page(path)
            if page_id is None:
                continue
            for tech in techniques:
                coverage.setdefault(tech, set()).add(page_id)

    techniques = []
    for tech in sorted(coverage):
        pages = sorted(coverage[tech])
        techniques.append({
            "techniqueID": tech,
            "score": len(pages),
            "comment": "Covered by: " + ", ".join(pages),
            "enabled": True,
        })

    max_score = max((t["score"] for t in techniques), default=1)
    # Metadata noun order follows the source directories (detections first
    # to match the README's framing), then hunts, then research notes.
    artifacts = ", ".join(
        f"{counts[n]} {n}" for n in ("detections", "hunts", "research notes")
    )

    return {
        "name": "threat-hunting-detections coverage",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "ATT&CK techniques covered by the detections, hunts, and research "
            "in this repo. Score = number of artifacts referencing the "
            "technique. Generated from the page frontmatter by "
            "scripts/build-navigator-layer.py."
        ),
        "sorting": 0,
        "hideDisabled": True,
        "techniques": techniques,
        "gradient": {
            "colors": ["#d7ecffff", "#1f6febff"],
            "minValue": 1,
            "maxValue": max_score,
        },
        "legendItems": [],
        "metadata": [{"name": "artifacts", "value": artifacts}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b93",
        "selectTechniquesAcrossTactics": True,
    }


def render(layer: dict) -> str:
    return json.dumps(layer, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify the committed layer is current; do not write")
    args = ap.parse_args()

    rendered = render(build_layer())

    if args.check:
        current = LAYER_PATH.read_text(encoding="utf-8") if LAYER_PATH.exists() else ""
        if current == rendered:
            print(f"OK    {LAYER_PATH.relative_to(REPO)} is current.")
            return 0
        print(f"STALE {LAYER_PATH.relative_to(REPO)} does not match the pages. "
              f"Run: python3 scripts/build-navigator-layer.py", file=sys.stderr)
        return 1

    LAYER_PATH.write_text(rendered, encoding="utf-8")
    n = rendered.count('"techniqueID"')
    print(f"Wrote {LAYER_PATH.relative_to(REPO)} ({n} techniques).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
