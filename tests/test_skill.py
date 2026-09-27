#!/usr/bin/env python3
"""Structural contract: Pi skill layout.

Asserts that the repo root follows the Pi skill layout. Stdlib-only, Python 3.9 compatible.

Run: python3 tests/test_skill.py
Exits non-zero and prints which checks failed.
"""

import re
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


def exists(p):
    return (ROOT / p).exists()


# --- 1. Tree layout -------------------------------------------------------

REQUIRED_FILES = [
    "SKILL.md",
    "role.md",
    "jobs/scan-codebase.md",
    "jobs/scan-changes.md",
    "jobs/suggest-patches.md",
    "specs/report-spec.md",
    "specs/patch-spec.md",
]
for p in REQUIRED_FILES:
    check("tree: %s exists" % p, exists(p))

agent_mds = sorted(p.name for p in (ROOT / "agents").glob("*.md")) if (ROOT / "agents").is_dir() else []
check(
    "tree: agents/ still holds its 8 .md files",
    len(agent_mds) == 8,
    "found %d: %s" % (len(agent_mds), ", ".join(agent_mds)),
)
check("tree: workflows/scan.js exists", exists("workflows/scan.js"))
check("tree: .pi-plugin/plugin.json exists", exists(".pi-plugin/plugin.json"))
check("tree: extension/ exists", (ROOT / "extension").is_dir())

# --- 2. SKILL.md frontmatter ----------------------------------------------


def read_text(p):
    return (ROOT / p).read_text(encoding="utf-8")


def frontmatter(path):
    """Return the YAML block between the leading '---' lines, or None."""
    if not exists(path):
        return None
    lines = read_text(path).splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return lines[1:i]
    return None


fm = frontmatter("SKILL.md")
if fm is None:
    check("frontmatter: SKILL.md has a leading --- block", False,
          "no '---' frontmatter block found")
else:
    fm_text = "\n".join(fm)
    name_m = re.search(r"^name:\s*(\S+)\s*$", fm_text, re.M)
    check("frontmatter: name: pi-security-analysis",
          name_m is not None and name_m.group(1) == "pi-security-analysis",
          "got: %s" % (name_m.group(1) if name_m else "missing"))

    desc_m = re.search(r"^description:\s*(.+?)\s*$", fm_text, re.M)
    if desc_m is None:
        check("frontmatter: description is present", False, "missing")
    else:
        desc = desc_m.group(1).strip().strip("'\"")
        check("frontmatter: description is non-empty", len(desc) > 0)
        check("frontmatter: description is at most 1024 chars",
              len(desc) <= 1024, "len=%d" % len(desc))

    check("frontmatter: disable-model-invocation: true",
          re.search(r"^disable-model-invocation:\s*true\s*$", fm_text, re.M) is not None)
    check("frontmatter: has a compatibility key",
          re.search(r"^compatibility:", fm_text, re.M) is not None)

# --- 3. Fail-closed contract strings ---------------------------------------

FAIL_CLOSED_STRINGS = [
    "This scan may take a while and may use a significant number of tokens",
    "This scan needs a 'Yes' to start, so nothing was run",
    "I understand it may take a while and use a significant number of tokens",
]
for path in ["jobs/scan-codebase.md", "jobs/scan-changes.md"]:
    if not exists(path):
        check("fail-closed: %s exists" % path, False, "missing")
        continue
    text = read_text(path)
    for s in FAIL_CLOSED_STRINGS:
        check("fail-closed: %s contains %r" % (path, s), s in text)

# --- 4. Manifest smoke test -----------------------------------------------

smoke = (
    "import sys; sys.path.insert(0, %r); "
    "from lib import plugin; v = plugin.version(); "
    "assert v == '0.11.0', v" % str(ROOT / "scripts")
)
proc = subprocess.run([sys.executable, "-c", smoke],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
check("manifest: plugin.version() == '0.11.0'", proc.returncode == 0,
      proc.stderr.decode("utf-8", "replace").strip() or
      "exit code %d" % proc.returncode)

# --- Summary ---------------------------------------------------------------

print()
if FAILURES:
    print("%d check(s) failed:" % len(FAILURES))
    for f in FAILURES:
        print("  - %s" % f)
    sys.exit(1)
print("All checks passed.")
sys.exit(0)
