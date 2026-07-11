// S3-priv Slice 1 — pure data-shape + config schema for the (not-yet-implemented) opt-in
// elevated read path. See docs/plans/2026-07-11-s3-priv-elevated-read-path.md §0/§1.
//
// This slice is PURE DATA-SHAPE + CONFIG SCHEMA: no elevated invocation, probe, Rust, or
// privilege happens anywhere here. `provenance-elevated-config.js` is a structural copy of
// constraint-store.js's loadLearnedConfig/writeLearnedConfig/normalizeLearnedConfig/
// resolveConstraintStorePaths template. `computePrivilege` (in tools/provenance.js) is a pure,
// behavior-preserving extraction of the old hardcoded emptyPrivilege() literal.

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import {
  PROVENANCE_MECHANISMS,
  loadProvenanceConfig,
  normalizeProvenanceConfig,
  resolveProvenanceConfigPaths,
  writeProvenanceConfig,
} from "../src/provenance-elevated-config.js";
import { computePrivilege } from "../src/tools/provenance.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-elevated-config-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// ---------------------------------------------------------------------------------------------
// resolveProvenanceConfigPaths: path shape.
// ---------------------------------------------------------------------------------------------

test("resolveProvenanceConfigPaths resolves to configDir/provenance.json with no doubled 'descartes' segment", async () => {
  const paths = await tempPaths();
  const resolved = resolveProvenanceConfigPaths(paths);
  assert.equal(resolved.configFile, path.join(paths.configDir, "provenance.json"));

  const occurrences = resolved.configFile.split(path.sep).filter((segment) => segment === "descartes").length;
  assert.equal(occurrences, 1, `expected exactly one "descartes" path segment in ${resolved.configFile}`);
});

test("resolved provenance config paths pass the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const resolved = resolveProvenanceConfigPaths(paths);
  assert.doesNotThrow(() => assertNoPiOwnedPath(resolved));
});

// ---------------------------------------------------------------------------------------------
// loadProvenanceConfig: ENOENT-defaults-disabled, corrupt-fails-closed — never throws.
// ---------------------------------------------------------------------------------------------

test("loadProvenanceConfig defaults to disabled/auto when provenance.json is absent, without throwing", async () => {
  const paths = await tempPaths();
  const config = await loadProvenanceConfig(paths);
  assert.deepEqual(config, { elevated: { enabled: false, mechanism: "auto" } });
});

test("loadProvenanceConfig fails closed to disabled with a corrupt:true marker when provenance.json contains malformed JSON, without throwing", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveProvenanceConfigPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, "{ not json", { mode: 0o600 });

  const config = await loadProvenanceConfig(paths);
  assert.equal(config.elevated.enabled, false);
  assert.equal(config.elevated.mechanism, "auto");
  assert.equal(config.corrupt, true);
});

// ---------------------------------------------------------------------------------------------
// writeProvenanceConfig: atomic tmp-write(0o600)+rename round-trip.
// ---------------------------------------------------------------------------------------------

test("writeProvenanceConfig/loadProvenanceConfig round-trips atomically at file mode 0o600", async () => {
  const paths = await tempPaths();
  const written = await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  assert.deepEqual(written, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });

  const { configFile } = resolveProvenanceConfigPaths(paths);
  const stat = await fs.stat(configFile);
  assert.equal(stat.mode & 0o777, 0o600);

  // No leftover tmp file after the atomic rename.
  const dirEntries = await fs.readdir(path.dirname(configFile));
  assert.deepEqual(dirEntries, ["provenance.json"]);

  const reread = await loadProvenanceConfig(paths);
  assert.deepEqual(reread, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
});

// ---------------------------------------------------------------------------------------------
// mechanism closed-enum validation (plan §1 TDD item 5).
// ---------------------------------------------------------------------------------------------

test("normalizeProvenanceConfig accepts every value in the closed mechanism enum verbatim", () => {
  for (const mechanism of PROVENANCE_MECHANISMS) {
    const normalized = normalizeProvenanceConfig({ elevated: { enabled: true, mechanism } });
    assert.equal(normalized.elevated.mechanism, mechanism);
  }
});

test("normalizeProvenanceConfig degrades an unrecognized mechanism value to 'auto'", () => {
  const normalized = normalizeProvenanceConfig({ elevated: { enabled: true, mechanism: "sudo_everything" } });
  assert.equal(normalized.elevated.mechanism, "auto");
  assert.equal(normalized.elevated.enabled, true);
});

test("normalizeProvenanceConfig defaults a missing mechanism to 'auto' and a missing enabled to false", () => {
  assert.deepEqual(normalizeProvenanceConfig(), { elevated: { enabled: false, mechanism: "auto" } });
  assert.deepEqual(normalizeProvenanceConfig({}), { elevated: { enabled: false, mechanism: "auto" } });
  assert.deepEqual(normalizeProvenanceConfig({ elevated: {} }), { elevated: { enabled: false, mechanism: "auto" } });
});

test("an unrecognized mechanism value hand-written directly to provenance.json normalizes to 'auto' on load (never crashes, never silently accepted)", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveProvenanceConfigPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, JSON.stringify({ elevated: { enabled: true, mechanism: "not_a_real_mechanism" } }), { mode: 0o600 });

  const config = await loadProvenanceConfig(paths);
  assert.equal(config.elevated.mechanism, "auto");
  assert.equal(config.elevated.enabled, true);
  assert.equal(config.corrupt, undefined);
});

test("writeProvenanceConfig never persists an invalid mechanism value verbatim — it is normalized to 'auto' before the atomic write", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "not_a_real_mechanism" } });

  const { configFile } = resolveProvenanceConfigPaths(paths);
  const onDisk = JSON.parse(await fs.readFile(configFile, "utf8"));
  assert.equal(onDisk.elevated.mechanism, "auto");
});

// ---------------------------------------------------------------------------------------------
// computePrivilege (tools/provenance.js): pure extraction of the old hardcoded emptyPrivilege()
// literal — the default (no elevated attempt) call must produce byte-identical output to
// today's shipped `{ mechanism: 'unprivileged', elevated_available: false, elevated_used: false }`.
// ---------------------------------------------------------------------------------------------

test("computePrivilege() with no arguments produces the exact legacy emptyPrivilege shape", () => {
  assert.deepEqual(computePrivilege(), {
    mechanism: "unprivileged",
    elevated_available: false,
    elevated_used: false,
  });
});

test("computePrivilege with explicit default/false inputs (no elevated attempt made) is byte-identical to the legacy shape", () => {
  const result = computePrivilege({
    mechanism: "unprivileged",
    elevatedAvailable: false,
    elevatedUsed: false,
    elevatedConfigEnabled: false,
  });
  assert.deepEqual(result, {
    mechanism: "unprivileged",
    elevated_available: false,
    elevated_used: false,
  });
  assert.deepEqual(Object.keys(result).sort(), ["elevated_available", "elevated_used", "mechanism"]);
});
