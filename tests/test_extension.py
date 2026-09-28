#!/usr/bin/env python3
"""Extension check: extensions/pi-security-analysis.mjs.

Asserts that the repo root contains extensions/pi-security-analysis.mjs,
that it imports as an ES module whose default export accepts a minimal
ExtensionAPI mock ({registerTool(def), on(event, handler)}), and that
it registers a tool named "ask_user".

The session_start handler is invoked twice with a ctx mock: once in TUI
mode (ctx = {mode: "tui", ui: {notify}}) and once in print mode
(ctx = {mode: "print"}). The TUI run must write nothing to stdout (no
"Launching Pi Security" banner) and deliver the python-3.9 preflight
warning via ctx.ui.notify; the print run must write the banner and the
warning to stdout. The preflight warning (containing "python3 3.9 or
newer") is produced by a fake `python3` on PATH that prints
"Python 3.8.10".

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
# invokes the session_start handler twice — once with a TUI ctx mock
# (capturing stdout and ctx.ui.notify calls) and once with a print ctx
# mock (capturing stdout) — and prints one JSON object to stdout:
# { tools, tui: { stdout, notified }, print: { stdout } }. Exits 0 even
# when checks fail — the Python test parses the JSON and decides
# pass/fail.
NODE_SCRIPT = r"""
import { pathToFileURL } from "node:url";
import fs from "node:fs";

const root = process.env.PI_ROOT;
const extPath = root + "/extensions/pi-security-analysis.mjs";
const result = {
  exists: fs.existsSync(extPath),
  importError: null,
  tools: [],
  tui: { stdout: "", notified: [] },
  print: { stdout: "" },
};

if (result.exists) {
  const registered = [];
  const handlers = {};
  const api = {
    registerTool: (def) => { registered.push(def.name); },
    on: (event, handler) => {
      (handlers[event] || (handlers[event] = [])).push(handler);
    },
  };
  const origWrite = process.stdout.write.bind(process.stdout);
  // Run the session_start handlers with a ctx mock, capturing every
  // stdout write (and, for the TUI mock, every ctx.ui.notify call).
  const runSessionStart = async (ctx) => {
    const captured = [];
    process.stdout.write = (chunk, enc, cb) => {
      captured.push(String(chunk));
      if (cb) cb();
    };
    for (const h of handlers.session_start || []) {
      try {
        await h({}, ctx);
      } catch (e) {
        captured.push(String(e));
      }
    }
    // Allow async banner/preflight emission before stopping capture.
    await new Promise((r) => setTimeout(r, 200));
    process.stdout.write = origWrite;
    return captured.join("");
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
    // TUI run: no stdout banner; the preflight warning arrives via notify.
    result.tui.stdout = await runSessionStart({
      mode: "tui",
      ui: { notify: (msg) => { result.tui.notified.push(String(msg)); } },
    });
    // Print run: banner and warning on stdout.
    result.print.stdout = await runSessionStart({ mode: "print" });
    // Other handlers (e.g. tool_result) keep the old {} invocation.
    for (const [event, list] of Object.entries(handlers)) {
      if (event === "session_start") continue;
      for (const h of list) {
        try {
          await h({});
        } catch (e) {
          // Ignore: only the session_start runs are asserted on.
        }
      }
    }
  } catch (e) {
    result.importError = String(e);
  } finally {
    process.stdout.write = origWrite;
  }
  result.tools = registered;
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
        tui = result.get("tui") or {}
        print_run = result.get("print") or {}
        tui_stdout = tui.get("stdout") or ""
        tui_notified = tui.get("notified") or []
        print_stdout = print_run.get("stdout") or ""
        check("tui_no_stdout_banner",
              "Launching Pi Security" not in tui_stdout,
              "tui stdout: %r" % tui_stdout)
        check("tui_warning_via_notify",
              any("python3 3.9 or newer" in msg for msg in tui_notified),
              "notified: %r" % tui_notified)
        check("print_banner_on_stdout",
              "Launching Pi Security" in print_stdout
              and "python3 3.9 or newer" in print_stdout,
              "print stdout: %r" % print_stdout)

    if FAILURES:
        print("%d check(s) failed: %s" % (len(FAILURES), ", ".join(FAILURES)))
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()
