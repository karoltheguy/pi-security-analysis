#!/usr/bin/env python3
"""Extension check: extensions/pi-security-analysis.mjs.

Asserts that the repo root contains extensions/pi-security-analysis.mjs,
that it imports as an ES module whose default export accepts a minimal
ExtensionAPI mock ({registerTool(def), on(event, handler)}), that
it registers a tool named "ask_user", and that its python-3.9 preflight
yields a warning containing "python3 3.9 or newer" when the environment
reports an older python3 (mocked here with a fake `python3` on PATH
that prints "Python 3.8.10").

Stdlib-only, Python 3.9 compatible.

Run: python3 tests/test_extension.py
Exits non-zero and prints which checks failed.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAILURES = []

# Node harness: imports the extension with a mock ExtensionAPI (no real
# pi runtime needed), records registerTool calls and event handlers,
# triggers the handlers to reach the banner/preflight path, and prints
# one JSON object to stdout. Exits 0 even when checks fail — the
# Python test parses the JSON and decides pass/fail.
NODE_SCRIPT = r"""
import { pathToFileURL } from "node:url";
import fs from "node:fs";

const root = process.env.PI_ROOT;
const extPath = root + "/extensions/pi-security-analysis.mjs";
const result = {
  exists: fs.existsSync(extPath),
  importError: null,
  tools: [],
  banner: null,
};

if (result.exists) {
  const registered = [];
  const handlers = {};
  const captured = [];
  const api = {
    registerTool: (def) => { registered.push(def.name); },
    on: (event, handler) => {
      (handlers[event] || (handlers[event] = [])).push(handler);
    },
  };
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, enc, cb) => {
    captured.push(String(chunk));
    if (cb) cb();
  };
  try {
    const mod = await import(pathToFileURL(extPath).href);
    const entry = mod.default !== undefined ? mod.default : mod;
    if (typeof entry === "function") {
      await entry(api);
    } else if (entry && typeof entry === "object") {
      for (const key of ["activate", "setup", "init"]) {
        if (typeof entry[key] === "function") {
          await entry[key](api);
          break;
        }
      }
    }
    // Trigger registered event handlers to reach the banner/preflight path.
    for (const list of Object.values(handlers)) {
      for (const h of list) {
        try {
          const r = await h({});
          if (typeof r === "string") captured.push(r);
        } catch (e) {
          captured.push(String(e));
        }
      }
    }
    // Allow async banner emission before stopping capture.
    await new Promise((r) => setTimeout(r, 200));
  } catch (e) {
    result.importError = String(e);
  } finally {
    process.stdout.write = origWrite;
  }
  result.tools = registered;
  result.banner = captured.join("");
}

console.log(JSON.stringify(result));
"""


def check(name, ok, detail=""):
    if ok:
        print("PASS  %s" % name)
    else:
        print("FAIL  %s%s" % (name, (" — " + detail) if detail else ""))
        FAILURES.append(name)


def main():
    ext = ROOT / "extensions" / "pi-security-analysis.mjs"
    check("extension_file_exists", ext.exists(),
          "extensions/pi-security-analysis.mjs not found at %s" % ext)

    result = None
    with tempfile.TemporaryDirectory(prefix="ext_port_") as tmp:
        fake = Path(tmp) / "python3"
        fake.write_text("#!/bin/sh\necho 'Python 3.8.10'\n")
        fake.chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = tmp + os.pathsep + env.get("PATH", "")
        env["PI_ROOT"] = str(ROOT)
        proc = subprocess.run(
            ["node", "--input-type=module", "-e", NODE_SCRIPT],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = proc.stdout.decode("utf-8", "replace").strip()
        err = proc.stderr.decode("utf-8", "replace").strip()
        if proc.returncode != 0 or not out:
            check("module_imports", False,
                  "node harness failed (rc=%d): %s" % (proc.returncode, err))
        else:
            try:
                result = json.loads(out)
            except ValueError:
                result = None
                check("module_imports", False,
                      "node harness output not JSON: %s" % out)
    if result is not None:
        check("module_imports", result.get("importError") is None,
              result.get("importError") or "")
        check("registers_ask_user_tool",
              "ask_user" in result.get("tools", []),
              "registered tools: %s" % result.get("tools"))
        check("banner_warns_python_3_9",
              "python3 3.9 or newer" in (result.get("banner") or ""),
              "banner: %r" % result.get("banner"))

    if FAILURES:
        print("%d check(s) failed: %s" % (len(FAILURES), ", ".join(FAILURES)))
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()
