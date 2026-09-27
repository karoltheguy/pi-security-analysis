// harness/print-test.mjs — tests for the `scan` CLI (plain node, no framework)
// Spawns `node cli.mjs scan <fixture-repo> --effort low` against a temporary
// fixture git repo and asserts the exit code and the PI-SECURITY-* product
// directory contents; also checks the bad-args path (exit 2 + usage on
// stderr) and the refused-outcome mapping (mapOutcome: 3/0/1).
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { mapOutcome } from "./print.mjs";

const harnessDir = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.join(harnessDir, "cli.mjs");

function report(label, ok) {
  console.log(`${ok ? "OK  " : "FAIL"} ${label}`);
  return ok;
}

// Strip the pi-subagents env vars: with PI_SUBAGENT_CHILD=1 the pi-subagents
// extension skips registering the subagent tool and the scan stops at the
// recipe's "pipeline unavailable" branch.
function childEnv() {
  const env = { ...process.env };
  delete env.PI_SUBAGENT_CHILD;
  delete env.PI_SUBAGENT_PARENT_SESSION;
  return env;
}

function spawnCli(args, timeoutMs) {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [cliPath, ...args],
      {
        timeout: timeoutMs,
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        env: childEnv(),
      },
      (err, out, errOut) => {
        resolve({
          stdout: out ?? "",
          stderr: errOut ?? "",
          code: err ? (typeof err.code === "number" ? err.code : 1) : 0,
        });
      },
    );
    child.on("error", (e) => resolve({ stdout: "", stderr: String(e), code: 1 }));
  });
}

let failed = false;

// --- refused-mapping unit check ---
failed = !report(
  "mapOutcome: clean completion, no products → 3",
  mapOutcome({ errored: false, productsPresent: false }) === 3,
) || failed;
failed = !report(
  "mapOutcome: products present → 0",
  mapOutcome({ errored: false, productsPresent: true }) === 0,
) || failed;
failed = !report(
  "mapOutcome: error → 1",
  mapOutcome({ errored: true, productsPresent: false }) === 1,
) || failed;

// --- bad-args case: `scan` with no repo argument ---
{
  const { stderr, code } = await spawnCli(["scan"], 30 * 1000);
  console.log("--- bad-args stderr ---\n" + stderr);
  failed = !report("bad args: child exited with code 2", code === 2) || failed;
  failed =
    !report(
      "bad args: usage text on stderr",
      stderr.includes("usage: scan <repo> --effort"),
    ) || failed;
}

// --- e2e: fixture git repo (temp dir, temporary identity) ---
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "pi-security-fixture-"));

function git(args, cwd) {
  execFileSync("git", args, { cwd, encoding: "utf8", stdio: "pipe" });
}

try {
  fs.writeFileSync(path.join(fixture, "hello.py"), "def hello():\n    return \"hello\"\n");
  fs.writeFileSync(path.join(fixture, "README.md"), "# fixture\n");
  fs.writeFileSync(path.join(fixture, "notes.txt"), "trivial\n");

  git(["init"], fixture);
  git(["add", "-A"], fixture);
  git(
    ["-c", "user.name=test", "-c", "user.email=test@test", "commit", "-m", "fixture"],
    fixture,
  );

  // --- run the CLI as a child process ---
  const { stdout, stderr, code } = await spawnCli(
    ["scan", fixture, "--effort", "low"],
    30 * 60 * 1000,
  );
  console.log("--- child stdout ---\n" + stdout);
  console.log("--- child stderr ---\n" + stderr);

  // 1. child exits 0
  failed = !report("child exited with code 0", code === 0);

  // 2. PI-SECURITY-* product directory exists in the fixture repo
  const entries = fs.readdirSync(fixture);
  const productDir = entries.find((e) => e.startsWith("PI-SECURITY-"));
  failed = !report("PI-SECURITY-* product directory exists", Boolean(productDir)) || failed;

  // 3. product directory contains all three products
  const products = productDir
    ? fs.readdirSync(path.join(fixture, productDir))
    : [];
  failed = !report("PI-SECURITY-RESULTS.jsonl present", products.includes("PI-SECURITY-RESULTS.jsonl")) || failed;
  failed = !report("PI-SECURITY-RESULTS.sarif present", products.includes("PI-SECURITY-RESULTS.sarif")) || failed;
  failed = !report(
    "PI-SECURITY-REVISION-*.json present",
    products.some((p) => p.startsWith("PI-SECURITY-REVISION-") && p.endsWith(".json")),
  ) || failed;
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}

process.exitCode = failed ? 1 : 0;
