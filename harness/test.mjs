// harness/test.mjs — acceptance test for issue #13 (plain node, no framework)
import assert from "node:assert/strict";
import { createAgentSessionRuntime } from "./runtime.mjs";

const { runtime, services } = await createAgentSessionRuntime();

try {
  const session = runtime.session;
  const loader = services.resourceLoader;

  // 1. Skill loaded
  const skillNames = loader.getSkills().skills.map((s) => s.name);
  assert.ok(
    skillNames.includes("pi-security-analysis"),
    `skill "pi-security-analysis" not loaded; got: [${skillNames.join(", ")}]`,
  );

  // 2. Extensions loaded (metrics + pi-subagents), no load errors
  const { extensions, errors } = loader.getExtensions();
  const extPaths = extensions.map((e) => e.resolvedPath);
  assert.ok(
    extPaths.some((p) => p.endsWith("extensions/pi-security-analysis.mjs")),
    `metrics extension not loaded; got: [${extPaths.join(", ")}]`,
  );
  assert.ok(
    extPaths.some((p) => p.includes("pi-subagents") && p.endsWith("index.js")),
    `pi-subagents extension not loaded; got: [${extPaths.join(", ")}]`,
  );
  assert.equal(
    errors.length,
    0,
    `extension load errors: ${JSON.stringify(errors)}`,
  );

  // 3. Metrics extension registered the ask_user tool
  const tools = session.getActiveToolNames();
  assert.ok(
    tools.includes("ask_user"),
    `ask_user tool not registered; got: [${tools.join(", ")}]`,
  );

  console.log("OK: all three resources loaded");
} finally {
  await runtime.dispose();
}
console.log("OK: disposed without error");
