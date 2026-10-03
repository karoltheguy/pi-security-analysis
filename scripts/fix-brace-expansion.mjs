#!/usr/bin/env node
/**
 * Post-install enforcer for brace-expansion.
 *
 * @earendil-works/pi-coding-agent ships its own npm-shrinkwrap.json, which
 * pins brace-expansion to 5.0.9. npm overrides do not apply to a dependency's
 * own shrinkwrap, so every `npm install` re-resolves the nested copy back to
 * 5.0.9 — which is covered by several DoS advisories (fixed in 5.0.12).
 *
 * This script runs after install and:
 *   1. Replaces any brace-expansion copy below MIN_VERSION with the patched
 *      tarball from the npm registry.
 *   2. Rewrites the corresponding package-lock.json entries so the committed
 *      lockfile matches the installed tree (and Dependabot sees 5.0.12).
 *
 * Idempotent: a no-op when the tree already has the patched version.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MIN_VERSION = "5.0.12";
const REGISTRY = "https://registry.npmjs.org";

const here = dirname(fileURLToPath(import.meta.url));
const root = process.argv[2] ? join(process.cwd(), process.argv[2]) : join(here, "..");
const nm = join(root, "node_modules");

function parseVer(v) {
  return v.split(".").map((n) => parseInt(n, 10));
}

function lt(a, b) {
  const [ma, na, pa] = parseVer(a);
  const [mb, nb, pb] = parseVer(b);
  return (
    ma < mb ||
    (ma === mb && na < nb) ||
    (ma === mb && na === nb && pa < pb)
  );
}

/** Fetch and extract the patched tarball over `destDir`. */
function installPatched(destDir) {
  const tmp = join(root, ".brace-expansion-patch-tmp");
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  execFileSync("npm", ["pack", `brace-expansion@${MIN_VERSION}`, `--pack-destination=${tmp}`], { stdio: "pipe" });
  const tgz = join(tmp, `brace-expansion-${MIN_VERSION}.tgz`);
  rmSync(destDir, { recursive: true, force: true });
  mkdirSync(destDir, { recursive: true });
  execFileSync("tar", ["-xzf", tgz, "-C", destDir, "--strip-components=1"], { stdio: "pipe" });
  rmSync(tmp, { recursive: true, force: true });
}

/** Patch one lockfile in place; returns true if anything changed. */
function patchLockfile(lockPath) {
  if (!existsSync(lockPath)) return false;
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const meta = JSON.parse(
    execFileSync("npm", ["view", `brace-expansion@${MIN_VERSION}`, "dist.integrity", "--json"], { stdio: "pipe" }),
  );
  let changed = false;
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (key.endsWith("/brace-expansion") && entry.version && lt(entry.version, MIN_VERSION)) {
      entry.version = MIN_VERSION;
      entry.resolved = `${REGISTRY}/brace-expansion/-/brace-expansion-${MIN_VERSION}.tgz`;
      entry.integrity = meta;
      changed = true;
    }
  }
  if (changed) writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\n");
  return changed;
}

/** All brace-expansion package dirs in the tree (hoisted + nested). */
function findCopies() {
  const copies = [];
  const top = join(nm, "brace-expansion");
  if (existsSync(join(top, "package.json"))) copies.push(top);
  if (existsSync(nm)) {
    const out = execFileSync(
      "find",
      [nm, "-maxdepth", "4", "-path", "*/node_modules/brace-expansion", "-type", "d"],
      { encoding: "utf8" },
    );
    for (const line of out.split("\n")) {
      const p = line.trim();
      if (p && !p.includes(".brace-expansion-patch-tmp")) copies.push(p);
    }
  }
  return [...new Set(copies)];
}

let patched = 0;
for (const dir of findCopies()) {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  if (lt(pkg.version, MIN_VERSION)) {
    console.log(`[fix-brace-expansion] patching ${dir}: ${pkg.version} -> ${MIN_VERSION}`);
    installPatched(dir);
    patched++;
  }
}
if (patchLockfile(join(root, "package-lock.json"))) {
  console.log("[fix-brace-expansion] lockfile entries updated");
}
// Verify: no stale copy may remain after patching.
for (const dir of findCopies()) {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  if (lt(pkg.version, MIN_VERSION)) {
    throw new Error(`[fix-brace-expansion] ${dir} still at ${pkg.version} after patch`);
  }
}
console.log(`[fix-brace-expansion] OK (${patched} patched)`);
