#!/usr/bin/env python3
"""
validate-sigma.py — offline structural gate for the sigma/ rules.

Dependency-light (PyYAML only) so it runs anywhere, including CI before the
heavier pySigma/sigma-cli check. Verifies each rule has the required fields,
a valid RFC 4122 v4 UUID id, a unique id, a recognized status/level, and that
every named selection is referenced by the condition.

Exit code 0 = all rules pass, 1 = at least one failure.
"""

import glob
import os
import sys
import uuid

try:
    import yaml
except ImportError:
    print("[error] PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REQUIRED = ("title", "id", "status", "logsource", "detection")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
LEVELS = ("informational", "low", "medium", "high", "critical")


def check(path: str, seen_ids: set) -> list:
    errs = []
    try:
        doc = yaml.safe_load(open(path).read())
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    for field in REQUIRED:
        if field not in doc:
            errs.append(f"missing required field: {field}")

    rid = str(doc.get("id", ""))
    try:
        if uuid.UUID(rid).version != 4:
            errs.append(f"id is not a v4 UUID: {rid}")
    except ValueError:
        errs.append(f"id is not a valid UUID: {rid}")
    if rid in seen_ids:
        errs.append(f"duplicate id: {rid}")
    seen_ids.add(rid)

    if doc.get("status") not in STATUSES:
        errs.append(f"unrecognized status: {doc.get('status')}")
    if "level" in doc and doc["level"] not in LEVELS:
        errs.append(f"unrecognized level: {doc['level']}")

    det = doc.get("detection", {}) or {}
    condition = det.get("condition", "")
    if not condition:
        errs.append("detection.condition is missing")
    for sel in [k for k in det if k != "condition"]:
        if sel not in str(condition):
            errs.append(f"selection '{sel}' is never used in the condition")

    return errs


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = sorted(glob.glob(os.path.join(root, "sigma", "*.yml")))
    if not files:
        print("[error] no sigma/*.yml rules found", file=sys.stderr)
        return 1

    seen_ids: set = set()
    failed = False
    for f in files:
        errs = check(f, seen_ids)
        rel = os.path.relpath(f, root)
        if errs:
            failed = True
            print(f"[FAIL] {rel}")
            for e in errs:
                print(f"         - {e}")
        else:
            print(f"[ok]   {rel}")

    print(f"\n{len(files)} rule(s) checked; {'FAILURES FOUND' if failed else 'all passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
