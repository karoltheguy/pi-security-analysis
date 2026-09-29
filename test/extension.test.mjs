import extension from "../extensions/pi-security-analysis.mjs";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";

test("registers the scan workflow on session_start", async () => {
  const handlers = {};
  const pi = {
    registerTool: () => {},
    on: (event, handler) => {
      handlers[event] = handler;
    },
  };

  extension(pi);

  const ctx = {
    mode: "print",
    sessionManager: { getSessionId: () => "test-session-id" },
    ui: { notify: () => {} },
  };

  await handlers.session_start({}, ctx);

  const reg = globalThis[Symbol.for("pi-subagents.workflow-resources.v1")]?.bySession?.get("test-session-id");
  assert.ok(reg, "the pi-security-analysis.scan workflow is not registered for the session");
  assert.ok(reg.has("pi-security-analysis.scan"), "registry has no pi-security-analysis.scan entry");
  const expectedScript = readFileSync(new URL("../workflows/scan.js", import.meta.url), "utf8");
  const resolved = reg.get("pi-security-analysis.scan").resolve({});
  assert.equal(typeof resolved.script, "string");
  assert.equal(resolved.script, expectedScript, "resolve() did not return the workflows/scan.js script");
});
