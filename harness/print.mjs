#!/usr/bin/env node
// harness/print.mjs — headless `scan` subcommand: parses the job arguments,
// builds the one-shot invocation text (a specific job request that skips the
// front-desk menu, with the effort tier, the scope when given, and explicit
// cost acknowledgment so the fixed step-3 confirmation is skipped), and boots
// the one-shot session via the SDK's runPrintMode with the same three
// resources as createAgentSessionRuntime() in runtime.mjs.
// Exit codes: 0 clean run, 1 failure, 2 bad args,
// 3 refused (clean stop without products, e.g. an unattended gate).
// Optional SARIF upload hook: set PI_SECURITY_SARIF_UPLOAD to a command; it runs
// exactly once after a clean run (exit 0) with the SARIF product path as its
// single argument. It never fires on exit 1 or 3, and its failure never
// changes the exit code.

import { parseArgs } from "node:util";
import { spawn } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { runPrintMode } from "@earendil-works/pi-coding-agent";
import { createAgentSessionRuntime } from "./runtime.mjs";

const USAGE = "usage: scan <repo> --effort <low|medium|high|max> [--scope <dirs>]";
const TIERS = ["low", "medium", "high", "max"];

// Outcome mapping (unit-testable): the run errored (threw, or the SDK
// returned a non-zero code) → 1; it completed without error and the scanned
// repo has a PI-SECURITY-* product directory with all three products → 0;
// it completed without error but produced no products (the agent stopped
// cleanly, e.g. an unattended gate it could not resolve) → 3.
export function mapOutcome({ errored, productsPresent }) {
  if (errored) return 1;
  return productsPresent ? 0 : 3;
}

// The PI-SECURITY-* product directory name in repoDir, or undefined if there
// is none.
export function findProductDir(repoDir) {
  try {
    return fs.readdirSync(repoDir).find((e) => e.startsWith("PI-SECURITY-"));
  } catch {
    return undefined;
  }
}

// Whether repoDir holds a PI-SECURITY-* product directory with all three
// products (RESULTS.jsonl, RESULTS.sarif, REVISION-*.json).
export function productsPresent(repoDir) {
  const dir = findProductDir(repoDir);
  if (!dir) return false;
  let products;
  try {
    products = fs.readdirSync(path.join(repoDir, dir));
  } catch {
    return false;
  }
  return (
    products.includes("PI-SECURITY-RESULTS.jsonl") &&
    products.includes("PI-SECURITY-RESULTS.sarif") &&
    products.some((p) => p.startsWith("PI-SECURITY-REVISION-") && p.endsWith(".json"))
  );
}

// Whether the SARIF upload hook should run: the run exited 0 (clean, with
// products) and a non-empty hook command was configured.
export function shouldUploadSarif({ exitCode, hook }) {
  return exitCode === 0 && typeof hook === "string" && hook.length > 0;
}

// The last assistant message's text and stop reason from the session, for the
// exit-3 diagnostic. Returns { text, stopReason } or undefined when nothing is
// readable (e.g. the runtime was already disposed or no assistant message exists).
function lastAssistantMessage(session) {
  let messages;
  try {
    messages = session.state.messages;
  } catch {
    return undefined;
  }
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m && m.role === "assistant") {
      let text = "";
      for (const c of m.content ?? []) {
        if (c && c.type === "text") {
          text = c.text;
          break;
        }
      }
      return { text, stopReason: m.stopReason };
    }
  }
  return undefined;
}

function usageError() {
  console.error(USAGE);
  process.exit(2);
}

// The main flow only runs when print.mjs is the CLI entry point: executed
// directly, or dynamically imported by cli.mjs for the `scan` subcommand.
// Importing print.mjs for the exported helpers (e.g. from print-test.mjs)
// must not run the CLI.
const isMain =
  process.argv[1] === fileURLToPath(import.meta.url) ||
  (path.basename(process.argv[1] ?? "") === "cli.mjs" && process.argv[2] === "scan");

if (isMain) {
  // `scan` is the subcommand name; the job args follow it.
  const { values, positionals } = parseArgs({
    args: process.argv.slice(3),
    options: {
      effort: { type: "string" },
      scope: { type: "string" },
    },
    allowPositionals: true,
  });

  if (positionals.length !== 1) usageError();
  if (!values.effort) usageError();

  const repo = path.resolve(positionals[0]);
  let effort = values.effort;
  if (!TIERS.includes(effort)) {
    console.error(`unknown effort ${effort} -- using medium (tiers: ${TIERS.join(", ")})`);
    effort = "medium";
  }

  // A specific job request skips the front-desk menu (SKILL.md step 1); naming
  // the shape and the effort skips the sub-menu, and the explicit cost
  // acknowledgment is the "Yes" for the fixed step-3 confirmation
  // (jobs/scan-codebase.md step 3).
  const shape = values.scope ? `with scope ${values.scope}` : "the whole thing";
  const prompt =
    `scan ${repo} at ${effort} effort, ${shape}, ` +
    "and I understand it may take a while and use a significant number of tokens";

  const { runtime } = await createAgentSessionRuntime();
  try {
    const code = await runPrintMode(runtime, { mode: "text", initialMessage: prompt });
    const exitCode = mapOutcome({
      errored: code !== 0,
      productsPresent: productsPresent(repo),
    });
    if (code !== 0) console.error(`scan run failed with code ${code}`);
    if (exitCode === 3) {
      console.error(
        "aborted: the run stopped cleanly without producing results — an unattended gate could not be resolved",
      );
      const last = lastAssistantMessage(runtime.session);
      if (last) {
        const text = (last.text ?? "").trim().replace(/\s+/g, " ");
        console.error(
          `final message (stopReason=${last.stopReason ?? "unknown"}): ${text || "(no text)"}`,
        );
      }
    }
    process.exitCode = exitCode;

    // Optional SARIF upload hook (PI_SECURITY_SARIF_UPLOAD): after a clean run
    // (exit 0) it runs exactly once with the SARIF product path as its single
    // argument. It never fires on exit 1 or 3, and its failure never changes
    // the exit code.
    const hook = process.env.PI_SECURITY_SARIF_UPLOAD;
    if (shouldUploadSarif({ exitCode, hook })) {
      const dir = findProductDir(repo);
      const sarifPath = path.join(repo, dir, "PI-SECURITY-RESULTS.sarif");
      await new Promise((resolve) => {
        const child = spawn(hook, [sarifPath], { shell: true });
        child.on("error", (err) => {
          console.error(`sarif upload hook failed: ${err.message}`);
          resolve();
        });
        child.on("exit", (code) => {
          if (code !== 0) console.error(`sarif upload hook exited with code ${code}`);
          resolve();
        });
      });
    }
  } catch (err) {
    console.error(err);
    process.exitCode = 1;
  } finally {
    await runtime.dispose();
  }
}
