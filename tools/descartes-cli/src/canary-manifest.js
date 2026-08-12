// Hand-authored, read-only canary manifest loader. Operators MUST place decoys where every real
// system parser will ignore them (for example ~/.aws/credentials.bak, never the live credentials
// path). This loader intentionally has no writer and v0 has no listening/service canary kind.
import fs from "node:fs/promises";
import path from "node:path";

export const CANARY_KINDS = [
  "credential-file",
  "scheduled-job",
  "suid-binary",
  "sudoers-entry",
  "writable-directory",
];
export const CANARY_WATCHES = ["atime", "mtime", "executed"];

export function resolveCanaryManifestPaths(descartesPaths) {
  return { manifestFile: path.join(descartesPaths.configDir, "canaries.json") };
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// Tamper fix (canary v0 finalization): the top-level SHAPE check below (object, schema_version:1,
// `canaries` an array) is a distinct failure class from per-entry filtering just past it. A
// document that fails THIS check (not an object at all, wrong/missing schema_version, or
// `canaries` not an array — e.g. truncated-but-still-valid-JSON, a stray top-level array, an
// attacker's crude tamper attempt that isn't even shaped like a manifest) is schema-invalid: it is
// NOT reliably distinguishable from an intentional edit, so it must NOT be treated the same as a
// genuinely-authored, valid, empty `{schema_version:1, canaries:[]}` decommission. `schema_valid`
// lets loadCanaryManifest (below) tell the two apart and mark ONLY the invalid-shape case
// read_ok:false. Per-entry drops (a single malformed canary inside an otherwise-valid document)
// stay schema_valid:true and read_ok:true, unchanged — that is ordinary data-quality filtering,
// not evidence of tampering with the manifest itself.
export function normalizeCanaryManifest(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || raw.schema_version !== 1 || !Array.isArray(raw.canaries)) {
    return { canaries: [], schema_valid: false };
  }
  const canaries = raw.canaries.filter((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    if (!nonEmptyString(entry.id) || !nonEmptyString(entry.path) || !CANARY_KINDS.includes(entry.kind)) return false;
    if (!Array.isArray(entry.watch) || entry.watch.length === 0 || !entry.watch.every((watch) => CANARY_WATCHES.includes(watch))) return false;
    if (entry.sentinel_path !== undefined && !nonEmptyString(entry.sentinel_path)) return false;
    return true;
  });
  return { canaries, schema_valid: true };
}

// P1 fix (canary collector review round 2): callers (canary-baseline.js's current-manifest gate)
// MUST be able to tell a legitimately empty/absent manifest apart from one this loader failed to
// read or parse. Without that distinction, degrading BOTH cases to the identical `{ canaries: [] }`
// shape lets an attacker who corrupts, deletes-and-recreates-unreadably, or chmods canaries.json
// silence every established canary's alerts (the gate treats the degraded empty manifest as
// authoritative and suppresses all candidates) — a security primitive silenced by attacking its
// own config file. `read_ok` makes the distinction explicit and load-bearing for every caller:
//   - read_ok:true  -- the manifest was read (or is genuinely absent, ENOENT) and parsed
//                      successfully; `canaries` is authoritative, including when empty (a real
//                      decommission/opt-out).
//   - read_ok:false -- the manifest could not be READ (non-ENOENT fs error) or could not be
//                      PARSED (corrupt JSON / failed schema shape). `canaries` is always `[]` here
//                      too (nothing safe to trust was recovered) but it must NOT be treated as an
//                      authoritative empty set by any decommission-style gate.
export async function loadCanaryManifest(descartesPaths) {
  const { manifestFile } = resolveCanaryManifestPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(manifestFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { canaries: [], read_ok: true };
    return { canaries: [], unreadable: true, read_ok: false };
  }
  let parsed;
  try {
    parsed = JSON.parse(contents);
  } catch {
    return { canaries: [], corrupt: true, read_ok: false };
  }
  // Tamper fix (canary v0 finalization): valid JSON that fails the manifest's own top-level
  // shape check (see normalizeCanaryManifest's `schema_valid` above) is SCHEMA-INVALID -- treated
  // identically to a parse/fs failure (read_ok:false), not as an authoritative empty manifest.
  // `schema_valid` itself never leaks into the returned shape, keeping it identical to every
  // existing caller/fixture's expectations for the read_ok:true path.
  const { canaries, schema_valid: schemaValid } = normalizeCanaryManifest(parsed);
  if (!schemaValid) return { canaries: [], schema_invalid: true, read_ok: false };
  return { canaries, read_ok: true };
}
