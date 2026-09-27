#!/usr/bin/env python3
"""Check: workflows/scan.js must use the pi-subagents primitives.

Asserts (via the Node sandbox harness tests/scan_sandbox.mjs) that
scan.js dispatches through `runs.run`/`runs.all` and runs to completion
in a vm context exposing only the workflow primitives (empty args ->
{started: false, reason: "no-args"} without throwing).

Stdlib-only, Python 3.9 compatible.

Run: python3 tests/test_scan.py
Exits non-zero and prints which checks failed.
"""

import json
import subprocess
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


# --- 1. Run the Node sandbox harness ----------------------------------------

proc = subprocess.run(
    ["node", str(ROOT / "tests" / "scan_sandbox.mjs")],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out = proc.stdout.decode("utf-8", "replace").strip()
err = proc.stderr.decode("utf-8", "replace").strip()

data = None
if proc.returncode != 0:
    check("harness: scan_sandbox.mjs exits 0", False,
          "exit code %d; stderr: %s" % (proc.returncode, err or "(none)"))
else:
    check("harness: scan_sandbox.mjs exits 0", True)

try:
    data = json.loads(out)
except Exception as e:
    check("harness: output is one JSON object", False,
          "%s: %s" % (type(e).__name__, out[:200] or "(empty)"))
    data = None

if data is not None:
    check("harness: output is one JSON object", True)

if data is None:
    # Cannot continue without the harness result; report what we have.
    print()
    print("%d check(s) failed:" % len(FAILURES))
    for f in FAILURES:
        print("  - %s" % f)
    sys.exit(1)

# --- 2. Static checks ------------------------------------------------------

static = data.get("static", {})
check("static: uses runs.run or runs.all", static.get("uses_runs") is True)

# --- 3. Dynamic check ------------------------------------------------------

dynamic = data.get("dynamic", {})
ok = (dynamic.get("ok") is True
      and dynamic.get("started") is False
      and dynamic.get("reason") == "no-args")
detail = ""
if not ok:
    if dynamic.get("error"):
        detail = "threw: %s" % dynamic.get("error")
    else:
        detail = "started=%r reason=%r" % (dynamic.get("started"), dynamic.get("reason"))
check("dynamic: runs to completion in the workflow sandbox; empty args -> "
      "{started: false, reason: 'no-args'}", ok, detail)

# --- Summary ---------------------------------------------------------------

print()
if FAILURES:
    print("%d check(s) failed:" % len(FAILURES))
    for f in FAILURES:
        print("  - %s" % f)
    sys.exit(1)
print("All checks passed.")
sys.exit(0)
