// S3-priv Slice 1 — pure data-shape + config schema for the (not-yet-implemented) opt-in
// elevated read path. See docs/plans/2026-07-11-s3-priv-elevated-read-path.md §0/§1.
//
// This module is a structural copy of constraint-store.js's loadLearnedConfig/
// writeLearnedConfig/normalizeLearnedConfig/resolveConstraintStorePaths template: same
// ENOENT-defaults-disabled / JSON.parse-failure-fails-closed-with-corrupt-marker /
// atomic-tmp-write(0o600)+rename shape. No elevated invocation, probe, Rust, or privilege
// happens anywhere in this file — it only reads/writes configDir/provenance.json.

import fs from "node:fs/promises";
import path from "node:path";

// Closed enum (plan §1 TDD item 5): an unrecognized/invalid mechanism string is never silently
// accepted (which could be misread downstream by a later slice) — it always normalizes to
// "auto" instead. "auto" and "none" are always safe/no-op defaults; "cap_sys_ptrace" and
// "helper_xpc" are probed under "auto"; "root_helper" must be named explicitly (never
// auto-selected — see plan §1/§6 open questions, enforced starting Slice 2).
export const PROVENANCE_MECHANISMS = ["auto", "cap_sys_ptrace", "root_helper", "helper_xpc", "none"];
const MECHANISM_SET = new Set(PROVENANCE_MECHANISMS);

export function resolveProvenanceConfigPaths(descartesPaths) {
  return { configFile: path.join(descartesPaths.configDir, "provenance.json") };
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

/**
 * Coerces a raw (possibly absent/malformed/hand-edited) config object to the closed shape
 * `{ elevated: { enabled: boolean, mechanism: PROVENANCE_MECHANISMS } }`. Never throws: an
 * unrecognized/missing mechanism value degrades to "auto"; a non-`true` enabled value degrades
 * to `false` (mirrors normalizeLearnedConfig's `config.enabled === true` coercion).
 */
export function normalizeProvenanceConfig(config = {}) {
  const elevated = config?.elevated ?? {};
  const mechanism = MECHANISM_SET.has(elevated.mechanism) ? elevated.mechanism : "auto";
  return {
    elevated: {
      enabled: elevated.enabled === true,
      mechanism,
    },
  };
}

/**
 * Reads configDir/provenance.json. Defaults to `{ elevated: { enabled: false, mechanism: "auto" } }`
 * when the file is absent (ENOENT), mirroring loadLearnedConfig's ENOENT-defaults-disabled
 * behavior. Malformed JSON fails CLOSED to the same disabled default plus an additive
 * `corrupt: true` marker — this never throws out of a daemon iteration.
 */
export async function loadProvenanceConfig(descartesPaths) {
  const { configFile } = resolveProvenanceConfigPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeProvenanceConfig();
    throw error;
  }
  try {
    return normalizeProvenanceConfig(JSON.parse(contents));
  } catch {
    // Malformed JSON: fail CLOSED to the disabled default rather than throwing out of a daemon
    // iteration, mirroring loadLearnedConfig's own corrupt-file tolerance. `corrupt: true` is an
    // additive marker only.
    return { ...normalizeProvenanceConfig(), corrupt: true };
  }
}

/**
 * Atomically writes configDir/provenance.json (tmp-write mode 0o600 + rename), mirroring
 * writeLearnedConfig. The config is normalized before being persisted, so an invalid mechanism
 * string (or any other malformed shape) is never written to disk verbatim.
 */
export async function writeProvenanceConfig(descartesPaths, config) {
  const { configFile } = resolveProvenanceConfigPaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeProvenanceConfig(config);
  const tmpFile = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, configFile);
  return normalized;
}
