// harness/rpc-test.mjs — contract test for the `rpc` subcommand (plain node, no framework)
// Spawns `node cli.mjs rpc` as a child process with stdio pipes and drives it over
// the JSONL RPC protocol (see docs/rpc.md + docs/rpc-commands.md). Asserts that the
// session retains state across invocations (get_state reflects the first prompt) and
// that closing stdin yields an orderly exit 0.
//
// The test must not hang: every wait for a JSONL record is bounded by a 120 s
// timeout; on timeout it exits 1 with a clear message.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const harnessDir = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.join(harnessDir, "cli.mjs");
const TIMEOUT_MS = 120 * 1000;

function report(label, ok) {
  console.log(`${ok ? "OK  " : "FAIL"} ${label}`);
  return ok;
}

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

// Strip the pi-subagents env vars (mirrors print-test.mjs).
function childEnv() {
  const env = { ...process.env };
  delete env.PI_SUBAGENT_CHILD;
  delete env.PI_SUBAGENT_PARENT_SESSION;
  return env;
}

// --- spawn the rpc child with stdio pipes ---
const child = spawn(process.execPath, [cliPath, "rpc"], {
  stdio: ["pipe", "pipe", "pipe"],
  env: childEnv(),
});
child.stderr.on("data", () => {}); // drain stderr; never parsed as protocol data

let exitResolve = null;
let childExited = false;
let childExitCode = null;
child.on("exit", (code) => {
  childExitCode = code;
  childExited = true;
  if (exitResolve) exitResolve(code);
});

// --- JSONL reader over stdout: split on LF only (never U+2028/U+2029) ---
let buffer = "";
const recordQueue = [];
let resolveNext = null;

function emitLine(line) {
  const trimmed = line.replace(/\r$/, ""); // accept CRLF input
  if (trimmed.length === 0) return;
  if (resolveNext) {
    const r = resolveNext;
    resolveNext = null;
    r(trimmed);
  } else {
    recordQueue.push(trimmed);
  }
}

child.stdout.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  const lines = buffer.split("\n");
  buffer = lines.pop(); // last element is the incomplete remainder
  for (const line of lines) emitLine(line);
});

function nextRecord() {
  return new Promise((resolve) => {
    if (recordQueue.length) resolve(recordQueue.shift());
    else resolveNext = resolve;
  });
}

function withTimeout(promise, ms, onTimeout) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(onTimeout, ms);
    promise.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}

// Wait (bounded) for the first record matching `predicate`; skip non-JSON lines.
async function waitFor(predicate, label) {
  const deadline = Date.now() + TIMEOUT_MS;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      fail("timed out waiting for JSONL response (is the rpc subcommand missing?)");
    }
    const line = await withTimeout(nextRecord(), remaining, () =>
      fail("timed out waiting for JSONL response (is the rpc subcommand missing?)"),
    );
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue; // non-protocol line (e.g. check-mode output) — skip
    }
    if (predicate(rec)) return rec;
  }
}

function sendCommand(obj) {
  child.stdin.write(JSON.stringify(obj) + "\n");
}

let failed = false;

// --- 2. first prompt ---
sendCommand({ id: "prompt-1", type: "prompt", message: "Reply with exactly: MARK-1" });

// --- 3. wait for the response/agent_settled for that prompt ---
await waitFor(
  (r) =>
    (r.type === "response" && r.command === "prompt" && r.id === "prompt-1") ||
    r.type === "agent_settled",
  "first prompt",
);
failed = !report("first prompt: response/agent_settled received", true) || failed;

// --- 4. second prompt, then get_state ---
sendCommand({ id: "prompt-2", type: "prompt", message: "Reply with exactly: MARK-2" });
await waitFor(
  (r) =>
    (r.type === "response" && r.command === "prompt" && r.id === "prompt-2") ||
    r.type === "agent_settled",
  "second prompt",
);
failed = !report("second prompt: response/agent_settled received", true) || failed;

sendCommand({ id: "state-1", type: "get_state" });
const stateRec = await waitFor(
  (r) => r.type === "response" && r.command === "get_state",
  "get_state",
);
failed = !report("get_state: response received", true) || failed;

// --- 5. the session retained the first prompt (no state lost between invocations) ---
failed =
  !report(
    "get_state messageCount >= 2 (state retained across invocations)",
    typeof stateRec.data.messageCount === "number" && stateRec.data.messageCount >= 2,
  ) || failed;

// --- 6. close stdin and assert an orderly exit 0 ---
child.stdin.end();
const exitCode = await withTimeout(
  new Promise((resolve) => {
    if (childExited) resolve(childExitCode);
    else exitResolve = resolve;
  }),
  TIMEOUT_MS,
  () => fail("timed out waiting for child to exit after closing stdin"),
);
failed = !report("child exited with code 0 (orderly shutdown)", exitCode === 0) || failed;

process.exitCode = failed ? 1 : 0;
