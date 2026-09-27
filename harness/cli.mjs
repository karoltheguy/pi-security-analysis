#!/usr/bin/env node
// harness/cli.mjs — CLI entry for issue #13: boots the harness session,
// verifies the three resources are loaded, and disposes cleanly.
// Exits 0 on success, 1 when any check fails.

import { createAgentSessionRuntime } from "./runtime.mjs";

if (process.argv[2] === "scan") {
  await import("./print.mjs");
  process.exit(process.exitCode ?? 0);
}

if (process.argv[2] === "rpc") {
  await import("./rpc.mjs");
  process.exit(process.exitCode ?? 0);
}

const { runtime, services } = await createAgentSessionRuntime();

let failed = false;
try {
  const loader = services.resourceLoader;
  const skillNames = loader.getSkills().skills.map((s) => s.name);
  const { extensions, errors } = loader.getExtensions();
  const extPaths = extensions.map((e) => e.resolvedPath);

  const checks = [
    ["skill pi-security-analysis loaded", skillNames.includes("pi-security-analysis")],
    ["metrics extension loaded", extPaths.some((p) => p.endsWith("extension/pi-security-analysis.mjs"))],
    ["pi-subagents extension loaded", extPaths.some((p) => p.includes("pi-subagents") && p.endsWith("index.js"))],
    ["no extension load errors", errors.length === 0],
  ];
  for (const [label, ok] of checks) {
    console.log(`${ok ? "OK  " : "FAIL"} ${label}`);
    if (!ok) failed = true;
  }
} finally {
  await runtime.dispose();
}
console.log(failed ? "disposed; checks failed" : "disposed without error");
process.exitCode = failed ? 1 : 0;
