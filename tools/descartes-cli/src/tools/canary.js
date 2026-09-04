// Filesystem-only canary collector. This module is deliberately read-only: it uses lstat for
// metadata, INCLUDING for optional execution sentinels (never access(), never a stat that follows
// symlinks), never reads file contents, starts a listener, or shells out. Canary paths are
// supplied by the manifest loader so this collector is easy to exercise against fixture files.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

export const MAX_CANARIES = 200;

const DEFAULT_NOTE = "Canary evidence is read-only filesystem metadata; canary planting is out of band.";

// Identity-binding fix (canary v0 finalization, FIX-A -- see canary-baseline.js's own header
// comment for the full rationale). A manifest edit to a canary's `path`/`sentinel_path` -- or
// reusing a canary_id for a different underlying file entirely -- must never let
// canary-baseline.js compare the OLD file's atime/mtime facts against the NEW file's under the
// same entity_key (canary_id) and fabricate a canary.tripped: the two are the same canary_id but
// NOT the same underlying canary. `identity_fingerprint` is a stable, domain-separated, HASHED
// fingerprint of (path, sentinel_path), computed here where the raw path is available and NEVER
// exposed downstream -- the raw path itself never leaves this collector (hash-at-source, the same
// discipline fact-translators.js's session/peer identity hashing already follows). The two inputs
// are joined with a NUL byte, which is illegal inside a POSIX path component and so can never
// appear in either input -- this keeps two distinct (path, sentinel_path) pairs from ever
// colliding by concatenation ambiguity (e.g. path="a", sentinel="b" vs path="ab", sentinel="").
const CANARY_IDENTITY_FINGERPRINT_DOMAIN = "descartes.canary.identity.v1";
const CANARY_IDENTITY_FINGERPRINT_SEPARATOR = "\u0000";

function canaryIdentityFingerprint(canaryPath, sentinelPath) {
  const preimage = [CANARY_IDENTITY_FINGERPRINT_DOMAIN, canaryPath, sentinelPath ?? ""].join(CANARY_IDENTITY_FINGERPRINT_SEPARATOR);
  return createHash("sha256").update(preimage).digest("hex").slice(0, 16);
}

function statAttribute(value) {
  return value instanceof Date ? value.toISOString() : String(value);
}

async function collectOneCanary(canary, lstat) {
  let stat;
  try {
    stat = await lstat(canary.path);
  } catch (error) {
    if (error?.code === "ENOENT") return { id: canary.id, kind: canary.kind, status: "absent" };
    return { id: canary.id, kind: canary.kind, status: "unreadable" };
  }

  const result = {
    id: canary.id,
    kind: canary.kind,
    status: "ok",
    atime: statAttribute(stat.atime),
    mtime: statAttribute(stat.mtime),
    ino: statAttribute(stat.ino),
    size: statAttribute(stat.size),
    watch: canary.watch,
    // FIX-A: bound to THIS canary's resolved path/sentinel_path -- see the module-header comment
    // above canaryIdentityFingerprint for the full rationale.
    identity_fingerprint: canaryIdentityFingerprint(canary.path, canary.sentinel_path),
  };

  if (canary.watch.includes("executed")) {
    if (!canary.sentinel_path) {
      // Close-the-last-fabrication-path fix (canary v0 finalization): an executed-watch with NO
      // sentinel_path configured is a CONFIG error, not a real "not executed" observation — there
      // is no sentinel to check, so we have performed no real check at all. Fabricating "false"
      // here (the old default) would plant exactly the same false-baseline hazard the ENOENT/
      // non-ENOENT access() split below exists to prevent: a LATER manifest fix that adds
      // sentinel_path could then observe a genuine "true" and manufacture a false->true trip
      // canary-baseline.js never actually watched for. Fail closed to "unknown" instead — never
      // "false" — so this can never seed a fabricated trip in either direction.
      result.executed = "unknown";
    } else {
      result.executed = "false";
      try {
        // Round-2 fix (positive-evidence re-gate, finding 4): lstat the SENTINEL itself, never
        // access()/stat() it. access(F_OK) follows symlinks -- if sentinel_path is (or becomes) a
        // dangling symlink, access() resolves and stats its TARGET, so an attacker who merely
        // creates the target (never touching the sentinel path itself) flips "executed" to
        // "true" even though the sentinel's own lstat identity (ino/mtime) never changed. lstat
        // never follows the final symlink component, so "executed" here reflects only whether the
        // sentinel path itself exists (ENOENT vs. present) -- exactly like every other watch in
        // this collector, which is lstat-only by the same module-header invariant.
        await lstat(canary.sentinel_path);
        result.executed = "true";
      } catch (error) {
        // Degrade-not-fabricate (HIGH fix, canary collector review): only an ENOENT — the
        // sentinel genuinely does not exist — is real evidence of "not executed", so only
        // ENOENT is allowed to leave `executed` at its "false" default. Any OTHER lstat()
        // failure (EACCES, or any error without a recognized code) means we simply don't know
        // whether the sentinel exists: asserting "false" here would plant a fabricated
        // false-baseline that a LATER successful lstat (e.g. a permission fix, or an
        // attacker manipulating perms) could flip to "true", manufacturing a false->true
        // "executed" trip canary-baseline.js never actually observed. Fail closed to
        // "unknown" instead — canary-baseline.js's trip comparison only fires on an explicit
        // "false"->"true" transition (never on "unknown"), so this can never itself trigger a
        // trip in either direction.
        if (error?.code !== "ENOENT") result.executed = "unknown";
      }
    }
  }
  return result;
}

export async function collectCanaryEvidence(canaries = [], options = {}) {
  const lstat = options.lstat ?? fs.lstat;
  const boundedCanaries = Array.isArray(canaries) ? canaries.slice(0, MAX_CANARIES) : [];
  const truncated = Array.isArray(canaries) && canaries.length > MAX_CANARIES;

  return timedEnvelope(async () => {
    const results = [];
    for (const canary of boundedCanaries) {
      results.push(await collectOneCanary(canary, lstat));
    }
    const summary = {
      total_count: results.length,
      ok_count: results.filter((entry) => entry.status === "ok").length,
      absent_count: results.filter((entry) => entry.status === "absent").length,
      unreadable_count: results.filter((entry) => entry.status === "unreadable").length,
      // P1 fix (canary collector review round 2): a per-canary EXECUTION-check failure (a
      // non-ENOENT access() error on the sentinel, degraded to executed:"unknown" above) is just
      // as much a this-tick read failure as an lstat "unreadable" — the collector genuinely does
      // not know the sentinel's state. It must surface here too, not just in the per-canary
      // record, so downstream (fact-translators.js's census marker) can treat the tick as
      // incomplete instead of silently reporting a "complete" census that lost the blackout.
      execution_unknown_count: results.filter((entry) => entry.executed === "unknown").length,
    };
    return {
      platform: options.platform ?? process.platform,
      status: summary.unreadable_count > 0 || summary.execution_unknown_count > 0 ? "warning" : "ok",
      request: { canary_count: results.length },
      summary,
      canaries: results,
      truncated,
      note: DEFAULT_NOTE,
    };
  }, (result) => evidenceEnvelope({
    id: "canary",
    status: result?.status ?? "ok",
    source: "filesystem",
    result,
    confidence: result?.status === "warning" ? 0.5 : 0.9,
    reviewHint: result?.status === "warning" ? "missing_permission" : "none",
    tool: "collect_canary_evidence",
  }));
}
