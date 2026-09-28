// Pi Security — a Pi extension for the pi-security-analysis skill.
//
// Registers the `ask_user` tool (ctx.ui.select/confirm when a UI is
// available, a plain-text prompt otherwise) and, on session_start, prints
// the launch banner and runs the python3 3.9 preflight. On each
// tool_result it records an opt-in usage-metrics line, written only when
// PI_SECURITY_METRICS=1.

import { execFile } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

function manifestVersion() {
  // The version in the repo's manifest; "" when there is not one.
  try {
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    );
    return typeof manifest.version === "string" ? manifest.version : "";
  } catch {
    return "";
  }
}

function center(text, width) {
  const pad = Math.max(0, width - text.length);
  const left = Math.floor(pad / 2);
  return " ".repeat(left) + text + " ".repeat(pad - left);
}

function banner() {
  const width = 23;
  const version = ` v${manifestVersion() || "unknown"} `;
  const box = [
    "    ██████",
    "    ██  ██",
    "    ████  ██",
    "    ██    ██",
    "     ",
    "  ┌" + "─".repeat(width) + "┐",
    "  │" + center("Security Analysis", width) + "│",
    "  └" + version.padStart(width - 3, "─") + "───┘",
  ];
  return "Launching Pi Security...\n\n\n" + box.join("\n") + "\n";
}

// Probe `python3 --version`; resolve to {major, minor, label} when the
// version could be parsed, or null when python3 is missing or unparseable.
function probePython3() {
  return new Promise((resolve) => {
    execFile("python3", ["--version"], { timeout: 10000 }, (error, stdout, stderr) => {
      const text = String(stdout || stderr || "");
      const m = text.match(/Python\s+(\d+)\.(\d+)(?:\.(\d+))?/);
      if (!m) {
        resolve(null);
        return;
      }
      resolve({ major: Number(m[1]), minor: Number(m[2]), label: `${m[1]}.${m[2]}.${m[3] || 0}` });
    });
  });
}

// The python-3.9 preflight warning.
async function pythonPreflight() {
  const v = await probePython3();
  if (v === null) {
    return "\n⚠️  Pi Security needs a working python3 (3.9 or newer) on PATH and could not run one. Install Python 3, then start a new session.\n";
  }
  if (v.major < 3 || (v.major === 3 && v.minor < 9)) {
    return `\n⚠️  Pi Security needs python3 3.9 or newer, but this python3 is ${v.label}. Scanning and fixing will fail until a newer python3 is first on PATH.\n`;
  }
  return "";
}

// --- Usage metrics -------------------------------------------------------
//
// A tool_result handler that recognizes a run of one of the repo's helper
// scripts and, when PI_SECURITY_METRICS=1, appends one JSONL line to the
// local metrics file. It writes nothing when the variable is unset.

// Telemetry codes are append-only: a reader keys on them, so none is ever
// renumbered.
const EVENTS = { scan_started: 1, scan_finished: 2, patches_written: 3, step_failed: 4 };
const STEPS = {
  "write_scan_meta.py": 1,
  "save_result.py": 2,
  "render_report.py": 3,
  "patch_artifacts.py": 4,
};
const MODES = { scan: 1, changes: 2, commit: 3 };
const EFFORTS = { low: 1, medium: 2, high: 3, max: 4 };
const REASONS = {
  "no-vote-record": 1,
  "no-candidate-count": 2,
  "nothing-examined": 3,
  "finding-panel-incomplete": 4,
  "finding-below-quorum": 5,
  "candidates-not-paneled": 6,
  "no-panel-completed": 7,
  "candidate-panel-incomplete": 8,
  "continuation-incomplete": 9,
  "findings-refused": 10,
};
const UNKNOWN_REASON = 99;
const COLLAPSED = new Set(["small-diff", "small-scope"]);
const STAMP_PREFIX = "PI-SECURITY-REVISION-";
const OPERATORS = new Set("();<>|&".split(""));
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCRIPTS = join(REPO_ROOT, "scripts");

// The local, append-only metrics file (opt-in via PI_SECURITY_METRICS=1).
const METRICS_FILE = join(homedir(), ".pi", "pi-security-metrics.jsonl");

function isObj(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// The JSON object in text; an empty object when text holds anything else.
function parseJson(text) {
  try {
    const value = JSON.parse(text);
    return isObj(value) ? value : {};
  } catch {
    return {};
  }
}

// value when it is a non-negative integer, else 0.
function count(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : 0;
}

// The table's code for a word; 0 for anything it does not name.
function code(table, value) {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(table, value) ? table[value] : 0;
}

// The file's bytes; null when it cannot be read.
function readSafe(path) {
  try {
    return readFileSync(path);
  } catch {
    return null;
  }
}

// A realpath that tolerates a missing path (os.path.realpath's default).
function realPath(p) {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

// A hand-rolled stand-in for shlex(punctuation_chars=True,
// whitespace_split=True, commenters=""): whitespace splits words, a run of
// ();<>|& is one token, quotes are honored and stripped, an unterminated
// quote is a ValueError.
function lex(command) {
  const tokens = [];
  let token = "";
  let inToken = false;
  const push = () => {
    if (inToken) {
      tokens.push(token);
      token = "";
      inToken = false;
    }
  };
  for (let i = 0; i < command.length; ) {
    const c = command[i];
    if (c === " " || c === "\t" || c === "\r" || c === "\v" || c === "\f") {
      push();
      i++;
    } else if (OPERATORS.has(c)) {
      let j = i;
      while (j < command.length && OPERATORS.has(command[j])) j++;
      push();
      tokens.push(command.slice(i, j));
      i = j;
    } else if (c === "'" || c === '"') {
      let j = i + 1;
      let part = "";
      let closed = false;
      while (j < command.length) {
        const ch = command[j];
        if (c === '"' && ch === "\\" && j + 1 < command.length && (command[j + 1] === '"' || command[j + 1] === "\\")) {
          part += command[j + 1];
          j += 2;
        } else if (ch === c) {
          closed = true;
          break;
        } else {
          part += ch;
          j++;
        }
      }
      if (!closed) return null;
      inToken = true;
      token += part;
      i = j + 1;
    } else if (c === "\\" && i + 1 < command.length) {
      inToken = true;
      token += command[i + 1];
      i += 2;
    } else {
      inToken = true;
      token += c;
      i++;
    }
  }
  push();
  return tokens;
}

// The words of a command that runs one of the repo's helper scripts on its
// own; null otherwise.
function helperWords(command) {
  for (const mark of ["\n", "\0", "`", "$("]) {
    if (command.includes(mark)) return null;
  }
  const lexed = lex(command);
  if (lexed === null) return null;
  for (const word of lexed) {
    if (word !== "" && [...word].every((ch) => OPERATORS.has(ch))) return null;
  }
  const words = [];
  for (const word of lexed) {
    if (word.startsWith("#")) break;
    words.push(word);
  }
  if (words.length < 2 || words[0] !== "python3") return null;
  const name = basename(words[1]);
  const own = realPath(join(SCRIPTS, name));
  return STEPS[name] !== undefined && realPath(words[1]) === own ? words : null;
}

// A helper's positional arguments and its --options, each of which takes a value.
function splitArguments(args) {
  const positionals = [];
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq !== -1) {
        options[arg.slice(0, eq)] = arg.slice(eq + 1);
      } else {
        options[arg] = i + 1 < args.length ? args[++i] : null;
      }
    } else {
      positionals.push(arg);
    }
  }
  return [positionals, options];
}

// The event for a write_scan_meta.py run; null unless it names a mode and an effort.
function scanStarted(scanRoot, options) {
  const mode = code(MODES, options["--mode"]);
  const effort = code(EFFORTS, options["--effort"]);
  const root = normalize(scanRoot);
  const scope = (options["--scope"] || "").split(",");
  let scoped = false;
  for (const entry of scope) {
    if (normalize(join(root, entry.trim())) !== root) {
      scoped = true;
      break;
    }
  }
  return mode && effort ? { mode, effort, scoped } : null;
}

// The event for a render_report.py run, from the one revision stamp it wrote; null otherwise.
function scanFinished(products) {
  let names;
  try {
    names = readdirSync(products);
  } catch {
    return null;
  }
  const stamps = names.filter((n) => n.startsWith(STAMP_PREFIX) && n.endsWith(".json"));
  if (stamps.length !== 1) return null;
  const data = readSafe(join(products, stamps[0]));
  const stamp = parseJson(data === null ? "" : data.toString("utf8"));
  if (Object.keys(stamp).length === 0) return null;
  const findings = isObj(stamp.findings) ? stamp.findings : {};
  const verification = isObj(stamp.verification) ? stamp.verification : {};
  const shape = isObj(stamp.run_shape) ? stamp.run_shape : {};
  const reason = code(REASONS, verification.reason_kind) || UNKNOWN_REASON;
  const dispatched = count(verification.researchers_dispatched);
  const refused = verification.refused_findings;
  return {
    mode: code(MODES, stamp.mode),
    effort: code(EFFORTS, stamp.effort),
    sev_critical: count(findings.critical),
    sev_high: count(findings.high),
    sev_medium: count(findings.medium),
    sev_low: count(findings.low),
    candidates: count(verification.candidates),
    candidates_deduped: count(verification.candidates_deduped),
    unverified_reason: verification.status === "verified" ? 0 : reason,
    researchers_dispatched: dispatched,
    researchers_lost: count(dispatched - count(verification.researchers_returned)),
    panels_short: count(verification.incomplete_panel_candidates),
    findings_refused: Array.isArray(refused) ? refused.length : 0,
    verify_runs: count(shape.verification_runs),
    collapsed: COLLAPSED.has(shape.collapsed),
    duration_s: count(stamp.duration_s),
  };
}

// The event for a patch_artifacts.py run, from the patches.jsonl it wrote; null otherwise.
function patchesWritten(patchesDir) {
  const data = readSafe(join(patchesDir, "patches.jsonl"));
  if (data === null) return null;
  const rows = data
    .toString("utf8")
    .split(/\r?\n/)
    .map(parseJson)
    .filter((row) => Object.keys(row).length > 0);
  const statuses = rows.map((row) => row.status);
  const checks = rows.map((row) => String(row.apply_check));
  return {
    units: rows.length,
    patches_written: statuses.filter((s) => s === "patch_written").length,
    declined: statuses.filter((s) => s === "declined").length,
    skipped_stale: statuses.filter((s) => s === "skipped_stale").length,
    untested: rows.filter((row) => row.untested === true).length,
    apply_clean: checks.filter((c) => c === "clean").length,
    apply_conflicts: checks.filter((c) => c.startsWith("conflicts")).length,
  };
}

// The event for a helper run that failed, from the error text.
function stepFailed(script, text, details) {
  const status = String(text).match(/^Exit code (\d+)/);
  return {
    step: STEPS[script],
    exit_code: status ? Math.min(Number(status[1]), 255) : -1,
    interrupted: isObj(details) && details.is_interrupt === true,
  };
}

// The error text of a tool result: a string, or the text blocks of one.
function textOf(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((block) => (isObj(block) && typeof block.text === "string" ? block.text : ""))
      .join("\n");
  }
  return "";
}

// Append one JSONL line to the local metrics file, only when opt-in is set.
function appendMetrics(name, body) {
  if (process.env.PI_SECURITY_METRICS !== "1") return;
  try {
    mkdirSync(dirname(METRICS_FILE), { recursive: true });
    appendFileSync(METRICS_FILE, JSON.stringify({ metrics: { ev: EVENTS[name], ...body } }) + "\n");
  } catch {
    // Metrics must never break the session.
  }
}

// The metrics for one tool_result event; a no-op unless it is a helper run.
function metricsEvent(event) {
  const input = isObj(event) && isObj(event.input) ? event.input : {};
  const words = helperWords(typeof input.command === "string" ? input.command : "");
  if (words === null) return;
  const script = basename(words[1]);
  const [positionals, options] = splitArguments(words.slice(2));
  if (options["--remove-scratch"] !== undefined) return;
  let name;
  let body;
  if (event.isError === true) {
    name = "step_failed";
    body = stepFailed(script, textOf(event.content), event.details);
  } else if (script === "write_scan_meta.py" && positionals.length >= 2) {
    name = "scan_started";
    body = scanStarted(join(process.cwd(), positionals[1]), options);
  } else if (script === "render_report.py" && positionals.length >= 1) {
    name = "scan_finished";
    body = scanFinished(join(process.cwd(), options["--products-dir"] || positionals[0]));
  } else if (script === "patch_artifacts.py" && positionals.length >= 2) {
    name = "patches_written";
    body = patchesWritten(join(process.cwd(), positionals[1]));
  } else {
    return;
  }
  if (body !== null) appendMetrics(name, body);
}

function textResult(text) {
  return { content: [{ type: "text", text }], details: undefined };
}

export default function (pi) {
  pi.registerTool({
    name: "ask_user",
    label: "Ask user",
    description:
      "Ask the user a question: a menu of options or a yes/no confirmation. With a UI this opens a dialog; without one (print mode) it returns a plain-text prompt to pose in text.",
    parameters: {
      type: "object",
      properties: {
        question: { type: "string", description: "The question to put to the user." },
        kind: {
          type: "string",
          enum: ["menu", "confirm"],
          description: "'menu' shows an options list; 'confirm' asks yes/no.",
        },
        options: {
          type: "array",
          items: { type: "string" },
          description: "The menu options (kind: menu).",
        },
        default: { type: "boolean", description: "The default answer for a confirm prompt." },
      },
      required: ["question", "kind"],
    },
    execute: async (_toolCallId, params, _signal, _onUpdate, ctx) => {
      const question = typeof params?.question === "string" ? params.question : "A question for the user";
      const options = Array.isArray(params?.options) ? params.options.map(String) : [];
      if (ctx && ctx.hasUI) {
        if (params?.kind === "confirm") {
          const ok = await ctx.ui.confirm(question, Boolean(params?.default));
          return textResult(ok ? "The user answered: Yes" : "The user answered: No");
        }
        if (options.length === 0) {
          return textResult("Menu prompt with no options; ask in plain text: " + question);
        }
        const choice = await ctx.ui.select(question, options);
        return textResult(
          choice === null ? "The user cancelled the menu." : `The user chose: ${choice}`,
        );
      }
      // No UI (print mode): a plain-text prompt for the agent to pose in text.
      let prompt = question;
      if (params?.kind === "confirm") {
        prompt += `\n(Reply Yes or No; default: ${params?.default ? "Yes" : "No"}. If the question cannot be put to a user, stop cleanly.)`;
      } else if (options.length > 0) {
        prompt += "\n" + options.map((o, i) => `${i + 1}) ${o}`).join("\n") +
          "\n(Reply with the number or the option. If the question cannot be put to a user, stop cleanly.)";
      }
      return textResult("No interactive UI is available. Pose this to the user in plain text:\n" + prompt);
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    const warning = await pythonPreflight();
    if (ctx.mode === "tui") {
      // Never write raw stdout in the TUI: it lands in the middle of the
      // rendered screen and moves the input cursor. Show only the warning.
      if (warning) ctx.ui.notify(warning.trim(), "warning");
      return;
    }
    process.stdout.write(banner() + "\n");
    if (warning) process.stdout.write(warning);
  });

  pi.on("tool_result", (event) => {
    metricsEvent(event);
  });
}
