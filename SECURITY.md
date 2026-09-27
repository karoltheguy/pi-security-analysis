# Security policy

This skill is a security tool, so it is held to the standard it applies to other people's code. If you find a vulnerability in it, report it.

## Reporting a vulnerability

Report security issues **privately** to the pi-security-analysis maintainers; do not open a public issue for a security report. Include what you can of: the project version, your platform and Pi version, reproduction steps, and the impact you believe it has.

In scope: a vulnerability in the skill's own code — its scripts, workflows, skill and job definitions, agent definitions, and the extension.

Out of scope: findings the scan produces about *your* code (best-effort by design, so a missed vulnerability there is a quality issue, not a skill vulnerability); the behavior of the model itself, such as jailbreaks or harmful content; and anything downstream of a hostile repository, per the trust model below.

## Trust model

**The code you scan is trusted.** Pi trusts the project, and a scan and a fix run in your Pi session, under your permissions, with no isolation layer of the skill's own — so the repository's `.git/config`, its `.pi/` project settings, and everything else your session loads from that directory apply as usual. The skill does not attempt to stop a hostile repository from influencing a scan.

To work with code you do not fully trust, run the whole session in a container or a VM first, so the repository's settings and anything it loads apply only inside that boundary.

The trust model is not the integrity boundary. The scripts' fail-closed gates — the provenance check, the renderer's refusals, and `git apply --check` — are the real integrity boundary, and they hold even when the repository's own text is untrusted.

## Supported versions

Security fixes land on the latest released version of the skill. There are no long-lived support branches. Update to the newest version before reporting.
