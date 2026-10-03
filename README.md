# Pi Security Analysis

Put a team of agents to work as security researchers on your codebase: map the architecture, build a threat model, hunt across every component, and independently verify every finding before it reaches the report. Then, if you want, turn the confirmed findings into suggested fixes delivered as targeted patch files you review and apply when you choose.

It runs entirely inside your Pi session — no separate process, no daemon.

## Where it runs

A scan and a fix both run in your Pi session, under your permissions. Pi trusts the project, and the skill adds no isolation of its own: the directory's `.git/config`, its `.pi/` project settings, and everything else your session loads from that directory all apply exactly as they would in any other session.

That makes it a natural fit for code you control — your own repositories, where the question is which bugs are in the code rather than whether the code is trying something. If you are scanning a repository that you do not trust, such as a third-party dependency or an unfamiliar repository, we suggest running the whole session in a container or a VM.

## Installation

Pi discovers the skill from a skill directory, a `--skill` flag, or a package:

- **Skill directory** — copy the repository into `~/.pi/agent/skills/pi-security-analysis/` (a project `.pi/skills/` or `~/.agents/skills/` location works too).
- **`--skill`** — start Pi with `--skill <path-to-the-skill-directory>`.
- **Package** — the repository is a pi package: a root `package.json` whose `pi` manifest exposes the skill (the repository root) and the `extensions/pi-security-analysis.mjs` metrics extension, and whose `pi-subagents.agents` entry exposes the named agents. Install it with `pi install <path-or-git-url>`. The named agents and the scan workflow also need pi-subagents installed.

The package is also published to the npm registry (`pi-security-analysis` on [npmjs](https://www.npmjs.com/package/pi-security-analysis)) and to [GitHub Packages](https://github.com/karoltheguy/pi-security-analysis/pkgs/npm/pi-security-analysis) on each `v*` tag, for discoverability.

With skill commands enabled, the skill registers as `/skill:pi-security-analysis`.


## Getting started

Run `/skill:pi-security-analysis` for the menu. It offers the three jobs the skill does:

| Job | What it scans |
| --- | --- |
| **Scan codebase** | The whole repository, or a scoped part of it |
| **Scan changes** | This branch's diff, a pull request's diff, or one commit |
| **Suggest patches** | A report's findings, turned into patch files |

Everything happens in your session. A scan reports each stage as it starts in Pi's progress view, then assembles the report when the agents are done.

When the skill needs a choice from you, it uses its `ask_user` tool: in the TUI that is a select or confirm dialog; in print mode there is no UI, so the question comes back as a plain-text prompt for you to answer in text.

## Choosing scope and effort

Two things shape a scan: **scope**, how much of the tree it looks at, and **effort**, how much work it does there. Say what you want if you know; if you don't, the skill works it out with you rather than making you guess.

It reads the repository before it asks — how large the tree is, which directories hold real code, what branch you are on, whether there is a diff to scan — so the choice you are offered is concrete, with the cost of each option stated, and every question carries an "I don't know" that resolves to a sensible default. It then says what it settled on before the work starts.

From there the scan sizes itself to the target. A small diff or a narrow scope gets a pass proportionate to it, verified to the same standard: a thorough scan covers more ground, but every finding a quick scan does report has cleared the same verification bar. A large repository is scanned with attention on the code an attacker can reach, treating tests, fixtures, generated code, and vendored trees as background rather than targets, plus a dedicated secrets pass that still checks fixtures for real committed keys. Asking for an exhaustive scan overrides all of this. A target with nothing in it is not scanned at all; the run says there is nothing to scan.

## Cost profile

The scan's agents are tiered: cartography and research run on a cheaper model than the verifiers when the environment has two or more models configured. With a single model the tiering is inert and every agent runs on the session model — the scan still works, it just spends the session model's tokens on every step.

If that cost profile does not fit, the pipeline can be split at the inventory boundary: run the cartography pass in one harness invocation, then research and verification in a second. The pipeline returns everything a continuation needs, so nothing is lost between the two runs.

## What a scan gives you

Every scan writes its results into a timestamped `PI-SECURITY-<timestamp>/` directory in the repository:

- **`PI-SECURITY-RESULTS.md`** — the human-readable report: each finding with its impact, exploit scenario, preconditions, severity (CRITICAL, HIGH, MEDIUM or LOW, assigned from exploitability and impact along the lines of the [CVSS v4.0](https://www.first.org/cvss/v4-0/specification-document) qualitative scale), confidence, and an outcome-focused recommendation.
- **`PI-SECURITY-RESULTS.jsonl`** — the same findings in machine-readable form, one JSON object per line. Each record carries a `piSecurityFindingId` derived from the code at the finding (for a hard-coded credential, and any finding within a few lines of one, from its location instead, since that code holds the secret), designed to stay the same from scan to scan while that code (or, for those, its location) is unchanged so tooling can tell a known finding from a new one; the SARIF log carries the same value in each result's properties. Neither this file nor the SARIF log quotes the source line of a hard-coded credential finding, since that line is the credential; file, line and symbol locate it.
- **`PI-SECURITY-RESULTS.sarif`** — the same findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log for GitHub code scanning, IDE SARIF viewers, and other tooling that speaks the standard.
- **`PI-SECURITY-REVISION-<sha12>.json`** — the revision stamp: which commit was scanned, at what effort, the severity counts, and how thoroughly the run was verified. The filename carries `-dirty` when uncommitted changes were part of the scanned tree, so a report is always tied to the code it describes.

That is the whole report — the run's working files are removed once it is written, so the directory holds only what you read. It carries its own `.gitignore`, so a stray `git add` never sweeps a report or a suggested patch into a commit; the report stays searchable where it sits, and if you want it in history, delete that one `.gitignore` and commit it like any other file.

A whole-repository scan accounts for the whole repository. Every top-level directory has to be either scanned or explicitly set aside with a reason — vendored code, generated code, documentation — and that accounting is checked before the search begins, not taken on trust. Whatever was left out, and why, is named in the report's Coverage section. A clean result tells you what was examined rather than leaving you to assume it.

## How a finding earns its place

However much effort a scan spends, a finding reaches the report only after surviving verification. Every candidate is handed to independent verifiers whose job is to disprove it, working from the code rather than from the report of it, and told to call it a false positive unless they can confirm a real path to exploitation. Findings that survive that are what you read; the rest are discarded, never shown. That is why the reports stay short.

A finding also cannot claim more confidence than its verification earned, nor, once two of the verifiers who confirmed it have rated it, a higher severity than they support, and the record of how thoroughly a run was verified is computed in code rather than asserted by the model that produced the findings — so the report's own account of its rigor is one you can check.

Throughout, what the repository says is evidence rather than instruction. Code, comments, and any `AGENTS.md` in the tree are read as data under review, so text addressed to the scan is noted rather than obeyed. Under the trusted-code model this keeps the work anchored to the evidence; it is not a defense against a hostile repository.

Scans are nondeterministic. Two scans of the same code can surface different findings, and the same scan finds more over time as models improve; running scans regularly builds coverage. The skill reasons about code the way a human security researcher does, which complements SAST, dependency scanning, and code review rather than replacing them.

## Addressing vulnerabilities

"Suggest patches" from the menu turns a report's findings into patch files you apply when you choose — from an existing report you pick, or from a fresh scan it runs first. The report has to still describe the code you have: the skill will not draft a fix against code the scan never saw, and it will tell you when a report has gone stale rather than patch from it.

Each fix is developed away from your working tree, in a scratch copy of the repository — your own checkout and index are never touched — and then reviewed by agents independent of the one that wrote it, including a review of your project's tests against the change and a fresh look at the diff on its own terms for anything new it might introduce.

A patch is written only when that review can vouch for three things: the change addresses that one finding, it introduces no new vulnerability, and it leaves the code's behaviour otherwise unchanged — and a change to which inputs the code accepts counts as a behaviour change. When it cannot vouch for all three, you get a short note explaining why instead of a patch. When the patched code has no tests, the patch says so, so you know the claim rests on review rather than on a test run.

The patches land in the report's `patches/` folder: one `F<n>.patch` per finding, a short note beside each explaining the change and how to apply it (`git apply PI-SECURITY-<ts>/patches/F<n>.patch`), and an index. Nothing is applied for you — the job does not apply, commit, or push anything. If you want a patch applied or turned into a pull request, ask, and the session does that as a separate request you can watch.

## Requirements

- Pi with this skill installed (skill directory, `--skill`, or package)
- Python 3.9 or newer on `PATH`
- A git checkout for scanning changes and suggesting patches — a whole-repository scan works without one

## CI surface

Run a scan headless, without a session: `node harness/cli.mjs scan <repo> --effort <tier> [--scope <dirs>]`.

For long-lived CI use the harness has an RPC mode (`node harness/cli.mjs rpc`) that keeps a session open across runs.

Exit codes: 0 clean, 1 failure, 2 bad args, 3 refused (a clean stop without products).

Products land in the unchanged `PI-SECURITY-<timestamp>/` directory: `PI-SECURITY-RESULTS.md`, `PI-SECURITY-RESULTS.jsonl`, `PI-SECURITY-RESULTS.sarif`, and `PI-SECURITY-REVISION-<sha12>.json`.

To ship the SARIF log, set `PI_SECURITY_SARIF_UPLOAD` to a command. It runs once after a clean run (exit 0) with the SARIF path as its single argument; its failure never changes the exit code.

Metrics stay local: `PI_SECURITY_METRICS=1` appends one JSON line per helper step to `~/.pi/pi-security-metrics.jsonl`.

## Metrics

Metrics are opt-in and local. Set `PI_SECURITY_METRICS=1` and the extension appends one JSON line per helper step to `~/.pi/pi-security-metrics.jsonl` — scans started and finished, patches written, and which step failed when one does. With the variable unset the extension writes nothing: metrics are off by default, and nothing ever leaves your machine.

## Security

The trust model and how to report a vulnerability in the skill itself are in [SECURITY.md](SECURITY.md).
