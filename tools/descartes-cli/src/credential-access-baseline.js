// Credential-file-access ALERT, Gap 3 / Slice D (docs/plans/2026-08-21-agent-intrusion-detection-
// gaps.md). Sibling of canary-baseline.js — but structurally different (P7): a per-path
// {atime, mtime, ino} last-known-stat compare over a small FIXED path set, NOT a multi-entity
// fact-store census. This module does NOT read fact-store.js at all.
//
// GATE DECISION (per-signal, stated explicitly — see the task's CRITICAL SECURITY-SEMANTICS
// LESSON): credential.access (`mtime_changed` / `ino_changed`) is POSITIVE DIRECT EVIDENCE — a
// concrete, observed two-snapshot lstat metadata change (a real inode/rewrite, not an inference
// over incomplete history that could be fabricated by a missing tick). It is therefore
// DELIBERATELY NOT completeness-gated: it fires on the first eligible (post-seed) observation,
// exactly like the canary tripwire (canary-baseline.js's canary.tripped, which is also emitted
// even while ITS OWN completeness lockout is pending — only canary_vanished, an absence claim, is
// gated there). Over-gating a positive tripwire would DISCARD real security events. The only gate
// this module applies is the per-path "no prior baseline yet" seed check, which is not a
// completeness/novelty gate at all — it is the structural fact that a CHANGE cannot be observed
// without two snapshots to compare, and a whole-store-invalid re-seed (see below), which likewise
// exists only to prevent comparing a live stat against garbled/untrustworthy prior data, not to
// suppress a positive observation once a trustworthy baseline exists.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { computeStatDiffTripReason } from "./stat-diff.js";
import { collectCredentialAccessEvidence } from "./tools/credential-access.js";

export const CREDENTIAL_ACCESS_RULE_ID = "credential.access";

export function resolveCredentialAccessBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "credential-access-baseline.json") };
}

async function ensureCredentialAccessBaselineDir(descartesPaths) {
  await fs.mkdir(resolveCredentialAccessBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

async function readJsonFile(file) {
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { parsed: undefined, missing: true };
    throw error;
  }
  try {
    return { parsed: JSON.parse(contents), missing: false };
  } catch {
    return { parsed: undefined, missing: false, corrupt: true };
  }
}

const PATH_HASH_PATTERN = /^[0-9a-f]{16}$/;

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function isValidCredentialEntryValue(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 3) return false;
  return isFiniteNumber(value.atime) && isFiniteNumber(value.mtime) && isFiniteNumber(value.ino);
}

/**
 * [REVIEW 2026-08-21, must-fix] Exact-schema validation, not merely corrupt-tolerant: `version
 * === 1`; `entries` is a plain object; EVERY key matches the 16-hex `path_hash` shape; EVERY
 * value is exactly `{atime, mtime, ino}` with all three finite numbers and no extra keys. ANY
 * single invalid entry invalidates the WHOLE store (not a per-entry skip — a partially-trusted
 * store is itself a fabrication surface: a garbled `mtime` under an otherwise-valid `path_hash`
 * key, compared against a fresh `lstat`, could fabricate a spurious trip). Discard entirely and
 * re-seed ALL paths fresh on the next tick, exactly like a missing store — re-seeding NEVER fires
 * (no baseline to diff against yet, the per-path analogue of the novelty detectors' cold-start:
 * no fabricated first-tick trip).
 */
export function isValidCredentialAccessBaselineStoreShape(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const keys = Object.keys(raw);
  if (!keys.every((key) => key === "version" || key === "entries")) return false;
  if (raw.version !== 1) return false;
  if (!("entries" in raw)) return false;
  const entries = raw.entries;
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) return false;
  for (const [key, value] of Object.entries(entries)) {
    if (!PATH_HASH_PATTERN.test(key)) return false;
    if (!isValidCredentialEntryValue(value)) return false;
  }
  return true;
}

/**
 * Returns `{ entries, corrupt, missing }` — `entries` is always a plain object (never `undefined`)
 * so callers never need a null-check: `{}` for missing/corrupt/schema-invalid (all three re-seed
 * identically, never fire on the seeding tick), the validated `raw.entries` otherwise.
 */
export async function loadCredentialAccessBaselineStore(descartesPaths) {
  const { storeFile } = resolveCredentialAccessBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { entries: {}, corrupt: false, missing: true };
  if (corrupt) return { entries: {}, corrupt: true, missing: false };
  if (!isValidCredentialAccessBaselineStoreShape(parsed)) return { entries: {}, corrupt: true, missing: false };
  return { entries: parsed.entries, corrupt: false, missing: false };
}

export async function writeCredentialAccessBaselineStore(descartesPaths, state) {
  await ensureCredentialAccessBaselineDir(descartesPaths);
  const { storeFile } = resolveCredentialAccessBaselineStorePaths(descartesPaths);
  const entries = state?.entries && typeof state.entries === "object" && !Array.isArray(state.entries) ? state.entries : {};
  const normalized = { version: 1, entries };
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

/**
 * Pure, no I/O. `previousEntries` is the validated (or freshly-reset) `{path_hash: {atime, mtime,
 * ino}}` map from the store; `latestSnapshot` is `collectCredentialAccessEvidence`'s per-entry
 * result array. For each entry with `status: "ok"`:
 *   - no prior baseline for this path_hash (first sight, or a post-reset re-seed) -> seeds the
 *     baseline SILENTLY, never a trip (there is nothing to compare against yet).
 *   - a prior baseline exists -> reuses the shared stat-diff.js trip-reason diff (mtime_changed
 *     primary / ino_changed additive; atime_advanced never fires for a v1 entry, whose `watch` is
 *     always `["mtime", "ino"]` — O7).
 *   - the baseline entry is advanced UNCONDITIONALLY either way (edge-triggered: the store
 *     advances on every compute whether or not a trip fired, which is what re-arms the trigger
 *     for the next observation — mirrors canary's own edge-triggered fold, applied per-path here).
 * `status: "absent"`/`"unreadable"` entries are skipped entirely: no comparison, no baseline
 * update (degrade-not-fabricate — an unobservable path carries no new information in either
 * direction, so its last-known-good baseline is left untouched rather than reset or guessed at).
 */
export function detectCredentialAccess(previousEntries = {}, latestSnapshot = [], options = {}) {
  const safePrevious = previousEntries && typeof previousEntries === "object" && !Array.isArray(previousEntries) ? previousEntries : {};
  const nextEntries = { ...safePrevious };
  const findings = [];
  for (const entry of latestSnapshot ?? []) {
    if (!entry || entry.status !== "ok") continue;
    const pathHash = entry.path_hash;
    if (typeof pathHash !== "string" || !pathHash) continue;
    const latest = { atime: entry.atime, mtime: entry.mtime, ino: entry.ino };
    const previous = safePrevious[pathHash];
    if (previous) {
      const tripReason = computeStatDiffTripReason(previous, latest, Array.isArray(entry.watch) ? entry.watch : []);
      if (tripReason) {
        findings.push({ category: entry.category, path_hash: pathHash, trip_reason: tripReason });
      }
    }
    nextEntries[pathHash] = latest;
  }
  return { findings, nextEntries };
}

function hashCredentialAccessKey(pathHash) {
  return crypto.createHash("sha256").update(`${CREDENTIAL_ACCESS_RULE_ID}:${pathHash}`).digest("hex").slice(0, 16);
}

/**
 * `severity: "warning"` UNCONDITIONALLY — real credential files ARE legitimately rewritten/
 * rotated by `ssh`/`git`/agents (explicitly NOT the canary's near-zero-FP `critical`). Diagnostics
 * carry only the closed-enum `category` + `trip_reason` + `path_hash` — never the literal path.
 */
export function buildCredentialAccessCandidates(entries = []) {
  return entries.map((entry) => {
    const fingerprint = hashCredentialAccessKey(entry.path_hash);
    const diagnostics = sanitizeDiagnostics({
      category: entry.category,
      trip_reason: entry.trip_reason,
      path_hash: entry.path_hash,
    });
    return {
      id: alertId(CREDENTIAL_ACCESS_RULE_ID, fingerprint),
      rule_id: CREDENTIAL_ACCESS_RULE_ID,
      fingerprint,
      severity: "warning",
      // Honest-claim wording (plan Slice D): mtime/ino evidence proves a REWRITE or REPLACE, not
      // a read — a genuine credential READ leaves mtime untouched, and atime is disabled for
      // every v1 entry (O7) / unreliable even when enabled (P3, relatime/noatime). "changed", not
      // "accessed" — this is not a read/theft detector in v1.
      title: "Credential file changed",
      summary: "A tracked credential file's metadata changed (rewritten or replaced) since it was last observed.",
      diagnostics,
      evidence_refs: ["credential-access-baseline"],
    };
  });
}

/**
 * `loadLearnedConfig(...).enabled` short-circuit BEFORE any I/O, matching every sibling
 * `computeX...Candidates`. Performs its OWN single `lstat` pass (no `defaultDaemonProfile`/
 * `activeCollectors`/structural push-sequence registration — P7/the plan's `[REVIEW]` fix: a
 * SECOND, independent structural-tick collection pass would be dead-collection duplication, since
 * structural evidence only ever reaches fact-history via a translator this module deliberately
 * does not have). Stated cadence: per-fast-tick `lstat` over the fixed v1 path list (~8 syscalls)
 * — cheap and acceptable at the fast-tick rate.
 */
export async function computeCredentialAccessCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const collectEvidence = options.collectCredentialAccessEvidence ?? collectCredentialAccessEvidence;
  const envelope = await collectEvidence(options.collectorOptions ?? {});
  const latestSnapshot = Array.isArray(envelope?.result?.entries) ? envelope.result.entries : [];

  const loadStore = options.loadCredentialAccessBaselineStore ?? loadCredentialAccessBaselineStore;
  const { entries: previousEntries } = await loadStore(descartesPaths);

  const { findings, nextEntries } = detectCredentialAccess(previousEntries, latestSnapshot, options);

  const writeStore = options.writeCredentialAccessBaselineStore ?? writeCredentialAccessBaselineStore;
  await writeStore(descartesPaths, { entries: nextEntries });

  // Positive direct evidence (see the module-header GATE DECISION) — emitted unconditionally,
  // never suppressed by any completeness/cold-start lockout.
  return buildCredentialAccessCandidates(findings);
}
