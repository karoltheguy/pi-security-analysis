// harness/runtime.mjs — boots a Pi SDK session that loads the three
// resources of issue #13: the pi-security-analysis skill, the metrics
// extension, and the pi-subagents extension.

import {
  createAgentSessionRuntime as sdkCreateAgentSessionRuntime,
  createAgentSessionServices,
  createAgentSessionFromServices,
  getAgentDir,
  SessionManager,
} from "@earendil-works/pi-coding-agent";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const metricsExtension = `${repoRoot}/extensions/pi-security-analysis.mjs`;
const piSubagentsExtension = require.resolve("pi-subagents");

/**
 * Boot a session runtime with all three resources loaded.
 * Returns { runtime, services }; dispose with `await runtime.dispose()`.
 */
export async function createAgentSessionRuntime(options = {}) {
  const cwd = options.cwd ?? repoRoot;
  let services;
  const createRuntime = async ({ cwd, sessionManager, sessionStartEvent }) => {
    services = await createAgentSessionServices({
      cwd,
      resourceLoaderOptions: {
        additionalSkillPaths: [repoRoot],
        additionalExtensionPaths: [metricsExtension, piSubagentsExtension],
      },
    });
    return {
      ...(await createAgentSessionFromServices({
        services,
        sessionManager,
        sessionStartEvent,
      })),
      services,
      diagnostics: services.diagnostics,
    };
  };
  const runtime = await sdkCreateAgentSessionRuntime(createRuntime, {
    cwd,
    agentDir: getAgentDir(),
    sessionManager: options.sessionManager ?? SessionManager.inMemory(),
  });
  return { runtime, services };
}
