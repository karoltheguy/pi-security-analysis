#!/usr/bin/env node
// harness/rpc.mjs — headless `rpc` subcommand: boots the same session as
// createAgentSessionRuntime() in runtime.mjs and hands it to the SDK's
// runRpcMode, which takes over stdout, reads JSONL commands from stdin
// (see docs/rpc.md + docs/rpc-commands.md), keeps the session alive across
// invocations, and disposes the runtime when stdin closes.
// Exit codes: 0 clean shutdown after stdin closes, 1 failure.

import { runRpcMode } from "@earendil-works/pi-coding-agent";
import { createAgentSessionRuntime } from "./runtime.mjs";

const { runtime } = await createAgentSessionRuntime();
try {
  await runRpcMode(runtime);
} catch (err) {
  console.error(err);
  process.exitCode = 1;
}
