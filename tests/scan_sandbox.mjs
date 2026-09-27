#!/usr/bin/env node
// Sandbox harness for the scan.js check.
// Reads workflows/scan.js, runs static string checks, then evaluates the source
// in a node:vm context exposing the pi-subagents workflow primitives
// (args, log, phase, emit, runs).
// Prints one JSON object and exits 0 (even when checks fail — the Python test
// parses the JSON and decides pass/fail).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import path from "node:path";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(path.join(root, "workflows", "scan.js"), "utf8");
// The workflow source is an ES module (leading `export const meta`) and uses
// top-level `return` — the real workflow runtime wraps it in a function with
// the primitives as parameters. Mirror that: strip the export keyword and
// wrap in an async function for the dynamic check. Static checks run on the
// raw source.
const evalSource = "(async (args, log, phase, runs) => {\n"
  + source.replace(/^export\s+/, "")
  + "\n})";

const staticChecks = {
  uses_runs: source.includes("runs.run") || source.includes("runs.all"),
};

const sandbox = {
  args: {},
  log: () => {},
  phase: () => {},
  emit: () => {},
  runs: {
    run: async () => ({}),
    all: async (items) => items.map(() => ({})),
  },
};

let dynamic = { ok: false, started: undefined, reason: undefined, error: "" };
try {
  const ctx = vm.createContext(sandbox);
  const script = new vm.Script(evalSource, { filename: "workflows/scan.js" });
  const workflow = script.runInContext(ctx, { timeout: 10000 });
  const result = await workflow(
    sandbox.args, sandbox.log, sandbox.phase, sandbox.runs);
  dynamic = {
    ok: true,
    started: result && result.started,
    reason: result && result.reason,
    error: "",
  };
} catch (e) {
  dynamic = {
    ok: false,
    started: undefined,
    reason: undefined,
    error: String(e && e.message || e),
  };
}

console.log(JSON.stringify({ static: staticChecks, dynamic }));
