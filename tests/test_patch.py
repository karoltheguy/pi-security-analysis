#!/usr/bin/env python3
"""Patch-flow check: jobs/suggest-patches.md dispatch shape.

Asserts that jobs/suggest-patches.md dispatches through
`subagent({ agent: "..." })` calls, that its preconditions are intact, and
that scripts/patch_artifacts.py records the `git apply --check` outcome.

Stdlib-only, Python 3.9 compatible.

Run: python3 tests/test_patch.py
Exits non-zero and prints which checks failed.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAILURES = []


def check(name, ok, detail=""):
    if ok:
        print("PASS  %s" % name)
    else:
        print("FAIL  %s%s" % (name, (" — " + detail) if detail else ""))
        FAILURES.append(name)


def read_text(p):
    return (ROOT / p).read_text(encoding="utf-8")


print("Patch-flow check (issue #4)")

RECIPE = read_text("jobs/suggest-patches.md")
SCRIPT = read_text("scripts/patch_artifacts.py")

# --- 1. Dispatch shape ----------------------------------------------------

check("dispatch: recipe has NO 'Agent(pi-security-analysis:'",
      "Agent(pi-security-analysis:" not in RECIPE)
check("dispatch: recipe HAS 'subagent({ agent: \"patch-generator\"'",
      'subagent({ agent: "patch-generator"' in RECIPE)
check("dispatch: recipe HAS 'subagent({ agent: \"patch-verifier\"'",
      'subagent({ agent: "patch-verifier"' in RECIPE)
check("dispatch: recipe HAS 'subagent({ agent: \"scan-researcher\"'",
      'subagent({ agent: "scan-researcher"' in RECIPE)

# --- 2. Preconditions ------------------------------------------------------

check("preserved: recipe HAS 'stamp commit'",
      "stamp commit" in RECIPE)
check("preserved: recipe HAS 'revision.dirty'",
      "revision.dirty" in RECIPE)
check("preserved: recipe HAS '^F[0-9]{1,9}$'",
      "^F[0-9]{1,9}$" in RECIPE)
check("preserved: recipe HAS 'PATCH BASE'",
      "PATCH BASE" in RECIPE)
check("preserved: recipe HAS '--remove-scratch'",
      "--remove-scratch" in RECIPE)

# --- 3. Script behavior ----------------------------------------------------

check("script: patch_artifacts.py HAS 'git apply --check'",
      "git apply --check" in SCRIPT)

# --- Summary ---------------------------------------------------------------

print()
if FAILURES:
    print("%d check(s) failed:" % len(FAILURES))
    for f in FAILURES:
        print("  - %s" % f)
    sys.exit(1)
print("All checks passed.")
sys.exit(0)
