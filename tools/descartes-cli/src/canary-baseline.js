// Canary-trip ALERT — deterministic filesystem attribute/set-diff detector. NO LLM anywhere in
// this file. The collector is the only host-facing component; this module reads persisted facts
// and a tiny cumulative bookkeeping store, then recomputes the current candidates statelessly.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadCanaryManifest } from "./canary-manifest.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics, sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { factHistoryTrustworthy } from "./fact-store-completeness.js";
import {
  CANARY_CENSUS_FACT_NAME,
  CANARY_CENSUS_MARKER_ENTITY_KEY,
  CANARY_PRESENCE_FACT_NAME,
  sanitizeEntityKey,
} from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";
import { computeStatDiffTripReason } from "./stat-diff.js";

export { CANARY_CENSUS_MARKER_ENTITY_KEY, DEFAULT_BASELINE_FACT_WINDOW_MS };

export const CANARY_TRIPPED_RULE_ID = "canary.tripped";
// Tamper fix (canary v0 finalization): "tampering is suspicious in itself". We cannot PREVENT a
// root-capable local attacker from deleting the canary manifest, a listed canary file, or the
// baseline store (see the module header's residual-limitations note below), but silently
// degrading each of those failures — as every collector/loader in this file already correctly
// does, degrade-not-fabricate — must NOT also silence the operator. A distinct rule_id (rather
// than overloading canary.tripped with a "tamper" trip_reason) keeps the two alert FAMILIES
// cleanly separable downstream (a tamper alert has no meaningful trip_reason of its own — no
// atime/mtime/executed transition was observed, only the ABSENCE of a reliable observation) while
// staying in the exact same fail-closed posture: same file (no new module), same
// canary.*-namespace (classifyAlertNamespace is UNTOUCHED — "canary.tampered" fails the same
// unknown_namespace/unrecognized-prefix path canary.tripped already does, so it can never reach
// LLM adjudication regardless of enabled_namespaces), same critical severity, same deterministic
// local-delivery branch (see alert-intelligence.js's ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS).
export const CANARY_TAMPERED_RULE_ID = "canary.tampered";
export const DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT = 3;
export const DEFAULT_CANARY_FRESHNESS_FALLBACK_MS = 3 * 60 * 60 * 1000;

// Fact-store completeness hardening (docs/plans/2026-08-21-fact-store-completeness-hardening.md,
// Slice 7): the number of genuinely-new, complete (censusState === "complete") tick-groups that
// must accumulate strictly AFTER a cold-start lockout's cold_start_since_ts anchor before the
// lockout clears and canary.* novelty (tripped / tampered(canary_vanished)) resumes. Mirrors
// session-baseline.js's DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT / peer-baseline.js's
// DEFAULT_PEER_MIN_HISTORY_TICK_COUNT / service-baseline.js's DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT
// exactly -- independently defined, not imported, per each detector owning its own
// re-establishment tuning.
export const DEFAULT_CANARY_MIN_HISTORY_TICK_COUNT = 6;

export function resolveCanaryBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "canary-baseline.json") };
}

function freshCanaryBaselineState() {
  return {
    version: 1,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    trip_event_count: 0,
    // Persistent cold-start lockout (fact-store completeness hardening, Slice 7 -- ports the
    // mechanism process-lineage-baseline.js/session-baseline.js/peer-baseline.js/service-
    // baseline.js already carry, see the extended comment on computeCanaryBaselineCandidates below
    // for the full rationale). A brand new store starts pending, exactly like a genuine day-1 cold
    // start.
    cold_start_pending: true,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
  };
}

function finiteOrDefault(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function isValidIsoTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(new Date(value).getTime());
}

const COMPLETENESS_LOSS_TIMESTAMP_FIELDS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

// Mirrors session-baseline.js's/service-baseline.js's own hasCompletenessLossAfterAnchor exactly
// (defense-in-depth duplicate of the timestamp-vs-anchor comparison factHistoryTrustworthy already
// performs internally -- kept as its own local check per those hardened references so a future
// change to the shared helper's internals cannot silently widen what this detector treats as
// trustworthy without also updating this local, independently-reviewed comparison).
function hasCompletenessLossAfterAnchor(readResult, anchorTs, nowMs) {
  const completeness = readResult?.completeness;
  if (!completeness || typeof completeness !== "object" || Array.isArray(completeness)) return false;
  const anchorMs = isValidIsoTimestamp(anchorTs) ? new Date(anchorTs).getTime() : -Infinity;
  const upperBoundMs = Number.isFinite(nowMs) ? nowMs : Infinity;
  return COMPLETENESS_LOSS_TIMESTAMP_FIELDS.some((field) => {
    const timestamp = completeness[field];
    if (timestamp === undefined || timestamp === null) return false;
    const timestampMs = new Date(timestamp).getTime();
    return !Number.isFinite(timestampMs) || (timestampMs > anchorMs && timestampMs <= upperBoundMs);
  });
}

export function normalizeCanaryBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    trip_event_count: finiteOrDefault(base.trip_event_count, 0),
    // Fail-closed default (mirrors process-lineage-baseline.js's/session-baseline.js's/peer-
    // baseline.js's/service-baseline.js's own normalizeXBaselineState exactly): cold_start_pending
    // is trusted "false" only when the store explicitly and validly recorded it as such. Any other
    // value -- missing (a pre-Slice-7 store predating this field), non-boolean garbage, or an
    // explicit true -- is treated as still pending. This IS the per-detector P8-style migration: a
    // pre-migration store cold-starts once on first read. Lenient per-field normalization (not
    // process-lineage's exact-schema rejection) is deliberately kept here -- see the plan's "Shared
    // schema-extension spec for Slices 4-7".
    cold_start_pending: base.cold_start_pending !== false,
    cold_start_reason: typeof base.cold_start_reason === "string" ? base.cold_start_reason : undefined,
    cold_start_since_ts: typeof base.cold_start_since_ts === "string" ? base.cold_start_since_ts : undefined,
  };
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

/**
 * ENOENT-tolerant (fresh state -> empty counters) and corrupt-tolerant (mirrors
 * session-baseline.js's/service-baseline.js's loadXBaselineStore exactly): a corrupt/malformed
 * file yields a fresh baseline rather than throwing out of a daemon tick, with `corrupt:true`
 * surfaced to the caller. `missing`/`corrupt` are now distinctly surfaced (Slice 7) so
 * computeCanaryBaselineCandidates can tell "no store yet / store I/O loss this tick"
 * (storeLossThisTick) apart from a genuinely-read, lenient-normalized store -- both cases already
 * default cold_start_pending:true via freshCanaryBaselineState.
 */
export async function loadCanaryBaselineStore(descartesPaths) {
  const { storeFile } = resolveCanaryBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: { ...freshCanaryBaselineState(), cold_start_reason: "missing_store" }, corrupt: false, missing: true };
  if (corrupt) return { state: { ...freshCanaryBaselineState(), cold_start_reason: "corrupt_store" }, corrupt: true, missing: false };
  return { state: normalizeCanaryBaselineState(parsed), corrupt: false, missing: false };
}

// FAIL-SAFE (mirrors process-lineage-baseline.js's/session-baseline.js's/service-baseline.js's own
// writeXBaselineStore exactly): normalizeCanaryBaselineState's own defaulting deliberately leaves
// cold_start_since_ts undefined when a caller doesn't supply one -- but a store actually PERSISTED
// to disk with cold_start_pending:true and no anchor can never re-establish (the re-accumulation
// gate in computeCanaryBaselineCandidates has nothing to compare tick timestamps against). Compute
// paths must set the anchor from their injected clock before persisting pending state. Slice 7
// intentionally does NOT synthesize a wall-clock anchor here (`Date.now()`/`options.now` is not
// available in this function's own signature) -- re-arming happens entirely on the READ side
// (computeCanaryBaselineCandidates), which always has the injected clock; this function stays a
// pure normalize+persist step.
export async function writeCanaryBaselineStore(descartesPaths, state) {
  const { dir, storeFile } = resolveCanaryBaselineStorePaths(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const normalized = normalizeCanaryBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

function snapshotFromPoint(point) {
  const attributes = point.attributes ?? {};
  const snapshot = {
    atime: attributes.atime,
    mtime: attributes.mtime,
    ino: attributes.ino,
    size: attributes.size,
    executed: attributes.executed,
    kind: attributes.kind,
    watch: attributes.watch,
  };
  // FIX-A (identity binding): only set when the fact actually carries one (a real value, not
  // `undefined`) so a fixture/older fact-history record that predates this fix keeps the exact
  // same snapshot shape it always had -- detectCanaryTrips below treats an absent
  // identityFingerprint as "identity not verified" (fails closed to no-trip), never as a
  // fabricated match against another absent value.
  if (typeof attributes.identity_fingerprint === "string" && attributes.identity_fingerprint) {
    snapshot.identityFingerprint = attributes.identity_fingerprint;
  }
  return snapshot;
}

export function groupCanaryFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || typeof point.ts !== "string") continue;
    if (point.fact_name !== CANARY_PRESENCE_FACT_NAME && point.fact_name !== CANARY_CENSUS_FACT_NAME) continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, censusState: undefined, canaries: new Map() });
    }
    const group = byTs.get(point.ts);
    if (point.fact_name === CANARY_CENSUS_FACT_NAME) {
      const rawState = point.attributes?.census_state;
      group.censusState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
    } else if (typeof point.entity_key === "string" && point.entity_key) {
      group.canaries.set(point.entity_key, snapshotFromPoint(point));
    }
  }
  return [...byTs.values()].sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
}

function watchList(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return value.split(",").map((item) => item.trim()).filter(Boolean);
  return [];
}

// FIX-A (identity binding, canary v0 finalization). detectCanaryTrips' entity_key (canary_id) is
// a SANITIZED form of the manifest's operator-chosen `id` string alone -- it says nothing about
// WHICH underlying file that id currently points at. Left unbound, an operator (or an attacker
// with manifest write access) editing a canary's `path`/`sentinel_path` in canaries.json, or
// reusing an existing canary_id for an entirely different file, would make this function compare
// the OLD file's atime/mtime/executed facts (recorded under the old path, in `previousSnapshot`)
// against the NEW file's facts (recorded under the new path, in `latestSnapshot`) -- fabricating a
// canary.tripped off nothing more than a legitimate config edit. This function instead binds
// comparison to the canary's IDENTITY -- (canary_id, identity_fingerprint), where
// identity_fingerprint is tools/canary.js's hashed fingerprint of the canary's resolved
// path/sentinel_path (see canaryIdentityFingerprint there) -- at TWO points:
//   1. the established-sighting-count gate (canarySightingKey below) is keyed by the full
//      identity, not canary_id alone, so a new identity starts its minEstablishedCount clock at
//      zero rather than inheriting the OLD identity's sighting history under the same canary_id;
//   2. the trip comparison itself only proceeds when previousSnapshot and latestSnapshot carry the
//      SAME, defined identity_fingerprint -- a differing (or a missing, e.g. pre-migration)
//      fingerprint on either side fails CLOSED (skip, no comparison, no trip) rather than risking
//      a fabricated cross-identity match.
// A genuine access to an UNCHANGED canary (identity_fingerprint stable across ticks, as it always
// is when path/sentinel_path are untouched) is completely unaffected and still trips normally.
function canarySightingKey(canaryId, snapshot) {
  const fingerprint = typeof snapshot?.identityFingerprint === "string" && snapshot.identityFingerprint
    ? snapshot.identityFingerprint
    : "unknown";
  return `${canaryId} ${fingerprint}`;
}

// Keep this source-side identity derivation byte-for-byte aligned with tools/canary.js. The
// manifest's raw paths are used only while building this in-memory map; only the fingerprint is
// compared downstream and nothing raw is persisted or emitted.
const CANARY_IDENTITY_FINGERPRINT_DOMAIN = "descartes.canary.identity.v1";
const CANARY_IDENTITY_FINGERPRINT_SEPARATOR = "\u0000";

function canaryIdentityFingerprint(canaryPath, sentinelPath) {
  if (typeof canaryPath !== "string" || !canaryPath) return undefined;
  const preimage = [CANARY_IDENTITY_FINGERPRINT_DOMAIN, canaryPath, sentinelPath ?? ""].join(CANARY_IDENTITY_FINGERPRINT_SEPARATOR);
  return createHash("sha256").update(preimage).digest("hex").slice(0, 16);
}

export function detectCanaryTrips(groups = [], options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_CANARY_FRESHNESS_FALLBACK_MS,
    minEstablishedCount = DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT,
  } = options;
  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length < 2) return [];
  const latest = completeGroups[completeGroups.length - 1];
  const previous = completeGroups[completeGroups.length - 2];
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return [];

  // Keyed by (canary_id, identity_fingerprint) -- see the FIX-A header comment above
  // canarySightingKey -- so a fresh identity under a reused/edited canary_id never inherits the
  // OLD identity's established-sighting count.
  const sightingCounts = new Map();
  for (const group of completeGroups) {
    for (const [canaryId, snapshot] of group.canaries) {
      const key = canarySightingKey(canaryId, snapshot);
      sightingCounts.set(key, (sightingCounts.get(key) ?? 0) + 1);
    }
  }

  const trips = [];
  for (const [canaryId, previousSnapshot] of previous.canaries) {
    const latestSnapshot = latest.canaries.get(canaryId);
    if (!latestSnapshot) continue;
    // FIX-A: only compare attributes across ticks when both snapshots carry the SAME, defined
    // identity fingerprint -- i.e. this canary_id's resolved path/sentinel_path did not change
    // between the two compared ticks. A missing fingerprint on either side (older/pre-migration
    // fact history, or a simplified fixture) is treated the same as a mismatch: identity cannot be
    // verified, so this fails CLOSED (skip) rather than risking a fabricated trip.
    const identityStable =
      typeof previousSnapshot.identityFingerprint === "string" && previousSnapshot.identityFingerprint &&
      previousSnapshot.identityFingerprint === latestSnapshot.identityFingerprint;
    if (!identityStable) continue;
    const sightingKey = canarySightingKey(canaryId, latestSnapshot);
    if ((sightingCounts.get(sightingKey) ?? 0) < minEstablishedCount) continue;
    const watches = watchList(latestSnapshot.watch);
    // Extracted (Slice D, credential-access plan): the per-watch trip-reason diff itself now
    // lives in stat-diff.js's computeStatDiffTripReason, shared with credential-access-
    // baseline.js. Behavior is byte-identical to the inline loop this replaces (same three
    // reasons, same fail-closed missing-value discipline, same first-match-wins order) — see
    // canary-baseline.test.js's regression coverage. `ino` is additive/new and is never in a
    // canary manifest's `watch` list, so it never fires here.
    const tripReason = computeStatDiffTripReason(previousSnapshot, latestSnapshot, watches);
    if (tripReason) {
      trips.push({
        canary_id: canaryId,
        kind: latestSnapshot.kind,
        trip_reason: tripReason,
        tripped_at_ts: latest.ts,
        last_seen_ts: previous.ts,
        complete_census_seen_count: sightingCounts.get(sightingKey),
      });
    }
  }
  return trips;
}

// CANARY VANISHED: a canary STILL LISTED in the current, successfully-read manifest whose file
// went from present (in the previous COMPLETE census tick) to absent (missing from the latest
// COMPLETE tick's presence facts entirely — tools/canary.js's collectOneCanary never emits a
// presence fact for an ENOENT/"absent" canary, and fact-translators.js correctly does NOT treat a
// lone `absent` as a census-partial signal, since a genuine ENOENT is ordinary evidence, not a
// this-tick read failure). Mirrors detectCanaryTrips' own two-COMPLETE-group/freshness/
// established-count gating exactly (same false-positive posture: a canary that was never
// established, or whose last complete-census sighting has gone stale, does not fire) but flips its
// `continue`-on-missing-latest-snapshot branch (detectCanaryTrips silently skips a canary that
// dropped out of the latest complete tick entirely -- see the loop above -- which is precisely the
// silence this fix closes) into a positive finding, GATED on `currentCanaryIds`: still listed in
// the manifest = tamper; already removed from the manifest too = legit decommission (the existing
// manifest-gate philosophy computeCanaryBaselineCandidates already applies to canary.tripped,
// mirrored here rather than duplicated differently).
//
// FIX-A parity (identity binding, canary v0 finalization -- terminal fix): this function used to
// key its establishment/sighting count by canary_id ALONE, exactly the hole FIX-A closed for
// detectCanaryTrips above. Editing an established canary's manifest entry (or reusing its
// canary_id) to point at a new/absent file B let B INHERIT A's prior sighting history the moment
// canary_id "credential" stopped being observed -- fabricating a canary.tampered(canary_vanished)
// alert even though B, under its OWN identity, was never actually established. Fixed the same way
// as FIX-A: sighting counts are keyed by canarySightingKey (canary_id + identity_fingerprint), so
// a new identity under a reused/edited canary_id starts its establishment clock at zero rather
// than inheriting the old identity's count, and the gate itself is evaluated against the
// LAST-OBSERVED snapshot's own identity-scoped count. A missing identity_fingerprint on that
// last-observed snapshot (older/pre-migration fact history) fails CLOSED -- skip, no
// alert -- rather than risking a fabricated finding off an unverifiable identity. A genuinely
// established canary whose identity never changed (identity_fingerprint stable across every
// complete tick, as it always is when path/sentinel_path are untouched) is completely unaffected
// and still raises canary_vanished exactly as before.
export function detectCanaryVanished(groups = [], currentCanaryIds = new Set(), options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_CANARY_FRESHNESS_FALLBACK_MS,
    minEstablishedCount = DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT,
    currentCanaryIdentityFingerprints = new Map(),
  } = options;
  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length < 2) return [];
  const latest = completeGroups[completeGroups.length - 1];
  const previous = completeGroups[completeGroups.length - 2];
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return [];

  // Keyed by (canary_id, identity_fingerprint) -- see the FIX-A parity header comment above -- so
  // a fresh identity under a reused/edited canary_id never inherits the OLD identity's established
  // sighting count.
  const sightingCounts = new Map();
  for (const group of completeGroups) {
    for (const [canaryId, snapshot] of group.canaries) {
      const key = canarySightingKey(canaryId, snapshot);
      sightingCounts.set(key, (sightingCounts.get(key) ?? 0) + 1);
    }
  }

  const vanished = [];
  for (const [canaryId, previousSnapshot] of previous.canaries) {
    if (latest.canaries.has(canaryId)) continue;
    // FIX-A parity: a missing identity_fingerprint on the last-observed snapshot means identity
    // cannot be verified -- fail CLOSED (skip) rather than risking a fabricated finding, same
    // posture detectCanaryTrips takes on a missing/mismatched fingerprint.
    if (typeof previousSnapshot.identityFingerprint !== "string" || !previousSnapshot.identityFingerprint) continue;
    // The current manifest must still resolve this id to the exact identity that was observed.
    // Otherwise reusing an id for a different, already-absent path could fabricate a vanished
    // claim from the old identity's history.
    if (currentCanaryIdentityFingerprints.get(canaryId) !== previousSnapshot.identityFingerprint) continue;
    const sightingKey = canarySightingKey(canaryId, previousSnapshot);
    if ((sightingCounts.get(sightingKey) ?? 0) < minEstablishedCount) continue;
    if (!currentCanaryIds.has(canaryId)) continue;
    vanished.push({
      canary_id: canaryId,
      kind: previousSnapshot.kind,
      tampered_at_ts: latest.ts,
      last_seen_ts: previous.ts,
      complete_census_seen_count: sightingCounts.get(sightingKey),
    });
  }
  return vanished;
}

function hashCanaryId(canaryId) {
  return createHash("sha256").update(`canary.tripped:${canaryId}`).digest("hex").slice(0, 16);
}

function hashCanaryTamperKey(key) {
  return createHash("sha256").update(`canary.tampered:${key}`).digest("hex").slice(0, 16);
}

export function buildCanaryTrippedCandidates(entries = []) {
  return entries.map((entry) => {
    const canaryIdHash = hashCanaryId(entry.canary_id);
    const canaryId = sanitizeIdentityString(entry.canary_id);
    const diagnostics = sanitizeDiagnostics({
      canary_id: canaryId,
      canary_kind: entry.kind,
      trip_reason: entry.trip_reason,
      canary_id_hash: canaryIdHash,
      last_seen_ts: entry.last_seen_ts,
    });
    return {
      id: alertId(CANARY_TRIPPED_RULE_ID, canaryIdHash),
      rule_id: CANARY_TRIPPED_RULE_ID,
      fingerprint: canaryIdHash,
      severity: "critical",
      title: "Canary tripped",
      summary: "A decoy credential/persistence artifact was accessed or modified.",
      diagnostics,
      evidence_refs: ["canary-baseline"],
    };
  });
}

// CONVERT SILENCE INTO DETECTION: entries are one of
//   { reason: "manifest_unreadable" }                                    -- no canary_id, singleton
//   { reason: "canary_vanished", canary_id, kind, last_seen_ts }         -- per-canary
//   { reason: "baseline_store_error" }                                   -- no canary_id, singleton
// The two singleton reasons intentionally share ONE fingerprint per reason (alertId's own
// "global" default when no fingerprint is passed), the same pattern every other singleton/
// non-per-entity alert in this codebase uses (alert-store.js's alertId(ruleId, fingerprint =
// "global")) — so a persistently-unreadable manifest or persistently-broken store produces a
// STABLE alert id tick over tick (dedup/cooldown works normally) rather than a fresh id every
// time. canary_vanished stays per-canary (a distinct fingerprint per vanished id), matching
// canary.tripped's own per-canary fingerprinting.
export function buildCanaryTamperedCandidates(entries = []) {
  return entries.map((entry) => {
    const fingerprintKey = entry.canary_id ? `${entry.reason}:${entry.canary_id}` : entry.reason;
    const fingerprint = hashCanaryTamperKey(fingerprintKey);
    const diagnosticsRaw = { tamper_reason: entry.reason };
    if (entry.canary_id) {
      diagnosticsRaw.canary_id = sanitizeIdentityString(entry.canary_id);
      diagnosticsRaw.canary_kind = entry.kind;
      diagnosticsRaw.canary_id_hash = hashCanaryId(entry.canary_id);
    }
    if (entry.last_seen_ts) diagnosticsRaw.last_seen_ts = entry.last_seen_ts;
    const diagnostics = sanitizeDiagnostics(diagnosticsRaw);
    return {
      id: alertId(CANARY_TAMPERED_RULE_ID, fingerprint),
      rule_id: CANARY_TAMPERED_RULE_ID,
      fingerprint,
      severity: "critical",
      title: "Canary tampering suspected",
      summary: "Canary infrastructure integrity could not be verified — treat as suspicious.",
      diagnostics,
      evidence_refs: ["canary-baseline"],
    };
  });
}

export async function computeCanaryBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;
  const minHistoryTickCount = options.minHistoryTickCount ?? DEFAULT_CANARY_MIN_HISTORY_TICK_COUNT;

  // Fact-store completeness hardening (Slice 7): the FULL read result is captured (not just
  // `points`) so factHistoryTrustworthy can see corrupt_count/schema_invalid_count/completeness —
  // exactly what process-lineage-baseline.js/session-baseline.js/peer-baseline.js/
  // service-baseline.js do for their own candidate computations.
  const readFacts = options.readFactPoints ?? readFactPoints;
  const readResult = await readFacts(descartesPaths, { windowMs, now: options.now });
  const { points, corrupt_count: corruptFactCount } = readResult;
  const groups = groupCanaryFactsByTick(points);

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_CANARY_FRESHNESS_FALLBACK_MS;
  const minEstablishedCount = options.establishedMinCensusCount ?? DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT;
  // Fact-store completeness hardening (Slice 7): exclude future-dated groups from folding,
  // detection, windowed stats, AND re-accumulation -- a future-dated tick-group must never score,
  // advance the watermark, or satisfy re-accumulation (mirrors session-baseline.js's/
  // service-baseline.js's own currentGroups filter exactly).
  const currentGroups = groups.filter((group) => {
    const groupMs = new Date(group.ts).getTime();
    return Number.isFinite(groupMs) && groupMs <= nowMs;
  });

  // CONVERT SILENCE INTO DETECTION (pre-existing): a genuinely thrown load error (EACCES, EROFS, a
  // directory swapped in for the file, ...) is caught here rather than propagating out and
  // aborting the whole daemon tick. Slice 7: baselineStoreLoadFailed additionally now feeds the
  // cold-start lockout below (storeLossThisTick) -- an unreadable store is exactly as
  // untrustworthy as a missing/corrupt one for the lockout's own anchor bookkeeping (see the
  // extended comment on enteringColdStart below).
  const loadStore = options.loadCanaryBaselineStore ?? loadCanaryBaselineStore;
  let persistedState = freshCanaryBaselineState();
  let baselineStoreLoadFailed = false;
  let baselineStoreCorrupt = false;
  let missingBaselineStore = false;
  try {
    const loaded = await loadStore(descartesPaths);
    persistedState = loaded.state;
    baselineStoreCorrupt = Boolean(loaded.corrupt);
    missingBaselineStore = Boolean(loaded.missing);
  } catch {
    baselineStoreLoadFailed = true;
    persistedState = { ...freshCanaryBaselineState(), cold_start_reason: "load_failed" };
  }

  // BOUNDED fix, ported from process-lineage-baseline.js's/session-baseline.js's/peer-baseline.js's/
  // service-baseline.js's persistent cold-start lockout (fact-store completeness hardening plan,
  // Slice 7 — canary-baseline.js did not have this mechanism at all before this slice; see
  // computeServiceBaselineCandidates for the full deception/anomaly-detector-review rationale this
  // ports verbatim): an unreadable/corrupt fact-history this tick, a lost/corrupt/unreadable
  // canary-baseline store, or fact-history whose completeness cannot be trusted since this
  // detector's own last re-established anchor, must never be treated as authoritative "this really
  // is all the canary-census history" — that could make a perfectly normal, still-present canary
  // read as vanished purely because retention scrubbed the tick that would have shown it as
  // established, fabricating a canary.tampered(canary_vanished) alert.
  //
  // Canary-specific note (this detector's store, unlike the shared fact-history ledger, previously
  // held ONLY informational bookkeeping -- skipped_partial_tick_count/trip_event_count -- and trip
  // DETECTION itself has always been recomputed fresh from fact-history, never from the store; see
  // the pre-Slice-7 header comment this replaces). Since Slice 7, the SAME store also carries this
  // lockout's own anchor (cold_start_pending/_reason/_since_ts) -- a lost/corrupt/unreadable store
  // now also means the lockout's own bookkeeping is unrecoverable this tick, so this intentionally
  // arms the vanished-claim lockout. Positive trip evidence remains independent of that bookkeeping:
  // raw trip/vanished detection still does not read the store directly, and only the absence-based
  // vanished output is suppressed below.
  //
  // Corrupt/missing/unreadable store state (or degraded fact-history) enters (or keeps) a
  // PERSISTENT cold_start_pending lockout that survives across ticks: while pending, this detector
  // emits ZERO canary.tampered(canary_vanished) novelty — not just this tick, but every tick — until
  // minHistoryTickCount genuinely NEW complete ticks (ts strictly after cold_start_since_ts) have
  // been observed. Positive canary.tripped evidence is not covered by this lockout.
  // Re-establishment cannot be satisfied retroactively by fact-history that already existed
  // before/during the loss. canary.tampered(manifest_unreadable)
  // and canary.tampered(baseline_store_error) are NOT fact-history novelty claims (they are direct
  // I/O-failure signals, independent of whether fact-history is complete) and are deliberately NOT
  // gated by this lockout — see the return statement at the bottom of this function.
  const factsCorruptThisTick = Boolean(corruptFactCount);
  const storeLossThisTick = baselineStoreCorrupt === true || missingBaselineStore === true || baselineStoreLoadFailed === true;
  // FAIL-SAFE, additional to the shared 3-term arming formula (process-lineage-baseline.js avoids
  // this exact gap via its OWN exact-schema store validator, which rejects on disk any
  // cold_start_pending:true store missing a valid anchor before it is ever normalized — canary-
  // baseline.js deliberately keeps LENIENT per-field normalization instead, per the plan's "Shared
  // schema-extension spec for Slices 4-7", so that guard does not exist here). Without this term, a
  // pre-Slice-7 store migrated in place (cold_start_pending defaults to true, cold_start_since_ts
  // stays undefined) reading against an already-pristine, loss-free fact-history ledger would see
  // factHistoryTrustworthy return trust:true even with no anchor (anchorTs undefined has nothing to
  // compare against) — landing in the re-accumulation branch with sinceMs permanently Infinity, an
  // unrecoverable lockout. This term forces that first post-migration tick to (re-)arm with a REAL
  // anchor instead, so the migration cold-start is bounded ("cold-starts once"), never a silent
  // permanent latch — the exact class of bug this whole plan exists to close.
  const persistedAnchorMissingOrFuture = (persistedState.cold_start_pending && !isValidIsoTimestamp(persistedState.cold_start_since_ts))
    || (isValidIsoTimestamp(persistedState.cold_start_since_ts)
      && new Date(persistedState.cold_start_since_ts).getTime() > nowMs);
  const historyTrust = factHistoryTrustworthy(readResult, { anchorTs: persistedState.cold_start_since_ts, nowMs });
  const completenessLossAfterAnchor = hasCompletenessLossAfterAnchor(readResult, persistedState.cold_start_since_ts, nowMs);
  const enteringColdStart = factsCorruptThisTick
    || storeLossThisTick
    || persistedAnchorMissingOrFuture
    || completenessLossAfterAnchor
    || (!persistedState.cold_start_pending && !historyTrust.trust);

  // Gate THIS tick's detection using the state as it stood BEFORE any update below — a tick cannot
  // self-heal and alert in the same breath it (re)establishes trust.
  const coldStartPendingThisTick = persistedState.cold_start_pending || enteringColdStart || !historyTrust.trust;

  let nextColdStartPending = persistedState.cold_start_pending;
  let nextColdStartReason = persistedState.cold_start_reason;
  let nextColdStartSinceTs = persistedState.cold_start_since_ts;

  if (enteringColdStart) {
    // (Re-)arm the lockout. Any in-progress re-accumulation is discarded — it cannot be trusted to
    // have been continuous once corruption/loss is observed again.
    nextColdStartPending = true;
    nextColdStartReason = storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts";
    nextColdStartSinceTs = nowIso;
  } else if (persistedState.cold_start_pending && historyTrust.trust) {
    // Re-accumulating: count complete ticks genuinely observed strictly after the lockout began.
    // Recomputed fresh from the live window every call (not an incrementing counter) so a missed
    // or re-ordered tick can never double count, and so re-establishment cannot be satisfied by
    // ticks that already existed before the reset.
    //
    // Counted against `group.censusState === "complete"` — the SAME predicate detectCanaryTrips/
    // detectCanaryVanished themselves already use as "the" notion of a complete tick.
    //
    // Canary-specific disposition analysis (flagged per the Slice 7 dispatch, mirroring
    // service-baseline.js's own analysis for its Slice 6): peer-baseline.js (Slice 5) had to choose
    // between TWO disposition functions for its own re-accumulation counter (marker-gated vs.
    // marker-agnostic) because peer.count_spike has NO census-marker concept at all in v0 — a live,
    // ongoing peer.presence stream can structurally lack an availability_signature marker forever on
    // some hosts (e.g. the `wg` command permanently unavailable), so gating re-accumulation on the
    // marker-only disposition would have permanently latched that host's lockout. canary-baseline.js
    // has no such second disposition to choose from: groupCanaryFactsByTick already folds the census
    // marker's own state directly into each group's `censusState` (complete/partial/unknown/
    // undefined), and fact-translators.js's factPointsFromCanaryEvidence only ever emits the
    // canary.census marker ALONGSIDE canary.presence points for the SAME tick — the marker is
    // written whenever `summary.total_count >= 1` (i.e. whenever at least one canary is configured
    // to report on at all), which is exactly the condition under which any canary.presence points
    // can exist for that tick. A markerless tick-group here therefore means zero canaries were
    // configured that tick (no live stream to gate at all), NOT a supported host whose census marker
    // is permanently, structurally unavailable — there is no scenario, analogous to peer's
    // `wg`-failure case, where canary.presence facts keep landing every tick with the census marker
    // permanently absent. Gating re-accumulation on `censusState === "complete"` therefore cannot
    // regress an existing detection capability the way using a marker-agnostic disposition would
    // have for peer.count_drop — it is simply the one and only notion of "complete tick" this
    // detector has ever had.
    const sinceMs = persistedState.cold_start_since_ts ? new Date(persistedState.cold_start_since_ts).getTime() : Infinity;
    const reestablishedTickCount = currentGroups.filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return group.censusState === "complete" && groupMs > sinceMs && groupMs <= nowMs;
    }).length;
    if (reestablishedTickCount >= minHistoryTickCount) {
      nextColdStartPending = false;
    }
  }

  const rawTrips = detectCanaryTrips(currentGroups, { nowMs, freshnessMs, minEstablishedCount });

  // Manifest-gated (HIGH fix, canary collector review): candidates may ONLY be produced for
  // canary_ids present in the CURRENT manifest. Without this gate, stale fact-history for a
  // canary that has since been removed/decommissioned from canaries.json would keep producing
  // canary.tripped candidates forever off facts an operator can no longer see or correct in the
  // manifest. entity_key is a SANITIZED form of the manifest's raw `id` (see
  // factPointsFromCanaryEvidence), so the current-manifest ids are run through the identical
  // sanitizeEntityKey before comparison.
  //
  // P1 fix (canary collector review round 2): the gate above is only safe to apply when the
  // manifest was actually READ successfully (read_ok !== false — see canary-manifest.js's
  // loadCanaryManifest contract). loadCanaryManifest previously degraded EVERY failure mode —
  // genuinely absent (ENOENT), removed/emptied by the operator, AND corrupted/unreadable
  // (EACCES/EIO/truncated JSON/an attacker deleting-then-replacing the file with a directory) —
  // to the identical `{ canaries: [] }` shape. Applying the decommission gate against THAT
  // degraded empty set treats a corrupt/unreadable manifest as an authoritative "no canaries
  // configured", which SUPPRESSES every established canary's candidates: an attacker who can
  // merely corrupt or chmod canaries.json (a much softer target than the canaries themselves)
  // could silence the whole alarm and even mute/clear already-active alerts, with no execution
  // path near a canary needed at all. So: read_ok:false (a genuine read/parse FAILURE) fails the
  // GATE open — known canaries keep alerting off fact-history exactly as if no manifest gate
  // existed — while read_ok:true (including a genuinely empty/absent manifest, a legitimate
  // decommission) still gates normally. `read_ok !== false` (rather than `=== true`) keeps any
  // caller/fixture that doesn't set the field at all (e.g. simplified test doubles) defaulting to
  // the normal gated behavior, matching the pre-P1 contract for them.
  const loadManifest = options.loadCanaryManifest ?? loadCanaryManifest;
  const manifestResult = await loadManifest(descartesPaths);
  const manifestReadOk = manifestResult?.read_ok !== false;
  const currentCanaries = Array.isArray(manifestResult?.canaries) ? manifestResult.canaries : [];
  const currentCanaryIds = new Set(currentCanaries.map((entry) => sanitizeEntityKey(entry.id)).filter(Boolean));
  const currentCanaryIdentityFingerprints = new Map();
  for (const entry of currentCanaries) {
    const canaryId = sanitizeEntityKey(entry.id);
    const identityFingerprint = canaryIdentityFingerprint(entry.path, entry.sentinel_path);
    if (canaryId && identityFingerprint) currentCanaryIdentityFingerprints.set(canaryId, identityFingerprint);
  }
  const invalidManifestEntries = Array.isArray(manifestResult?.invalid_entries) ? manifestResult.invalid_entries : [];

  // Round-3 fix (positive-evidence suppression, daybreak-blue re-gate): canary.tripped is POSITIVE
  // two-snapshot evidence computed ENTIRELY off persisted fact-history (detectCanaryTrips never
  // reads the manifest, and rawTrips above already required minEstablishedCount sightings under a
  // stable identity before a trip is even produced) -- once observed, it must never be
  // suppressible by an attacker's manifest manipulation. The gate just above (currentCanaryIds)
  // exists to catch a LEGITIMATE decommission: the operator deletes the entry outright, so no
  // manifest entry -- valid OR isolated -- resolves to that entity_key anywhere any more. Round 2's
  // isolation fix (canary-manifest.js) means an entity_key collision or a manifest-order cap-flood
  // does NOT decommission the colliding/flooded-out id -- it isolates it, and the manifest still
  // "knows about" it via `invalid_entries`. That distinction -- present-but-isolated vs.
  // genuinely-absent -- is exactly what tells an attacker-forced isolation apart from a real
  // decommission, so a rawTrip whose canary_id resolves to one of these isolated entries is let
  // through even though currentCanaryIds excludes it. This can only ever UN-suppress a trip that
  // was already genuinely computed from real fact-history two-snapshot diffs; it can never
  // fabricate one -- an attacker who manipulates only the manifest (never touching the canary
  // itself) still produces zero rawTrips to un-suppress. "empty_entity_key" is deliberately left
  // out of the reason allowlist: it sanitizes to nothing (falsy) and so can never equal a real
  // canary_id in the first place.
  //
  // canary_vanished (below) is deliberately NOT given the same treatment: unlike canary.tripped,
  // it is an ABSENCE claim, fabricable from incomplete/manipulated state, so isolation there
  // correctly stays conservative (no vanished claim) rather than being made immune the same way --
  // see detectCanaryVanished's own currentCanaryIds gate and the "manifest_oversized... NOT a
  // fabricated canary_vanished" test above, both intentionally unchanged by this fix.
  //
  // Round-4 fix (positive-evidence isolation completeness, daybreak-blue finding 3):
  // "schema_invalid" joins the allowlist for the exact same reason entity_key_collision/
  // manifest_oversized are here -- canary-manifest.js's loader now isolates (rather than silently
  // drops) a per-entry validation failure whose id is still usable (e.g. an established canary's
  // `path` accidentally dropped by a config edit), and that id is just as PRESENT-but-malformed in
  // the manifest as a collision/cap-flood victim. "empty_entity_key" stays deliberately excluded
  // (unchanged): it sanitizes to nothing and so can never equal a real canary_id in the first
  // place, exactly as noted above.
  const isolatedEntityKeys = new Set(
    invalidManifestEntries
      .filter((entry) => entry.reason === "entity_key_collision" || entry.reason === "manifest_oversized" || entry.reason === "schema_invalid")
      .map((entry) => sanitizeEntityKey(entry.id))
      .filter(Boolean),
  );
  const trips = manifestReadOk
    ? rawTrips.filter((entry) => currentCanaryIds.has(entry.canary_id) || isolatedEntityKeys.has(entry.canary_id))
    : rawTrips;
  const outputTrips = trips;

  // MANIFEST TAMPER (tamper fix, canary v0 finalization): read_ok:false is a genuine read/parse/
  // schema-invalid FAILURE (canary-manifest.js's loadCanaryManifest contract) -- distinct from a
  // successfully-read, genuinely empty/absent manifest (read_ok:true, a legitimate decommission,
  // which raises NO tamper alert). The gate above already fails OPEN on this (known canaries keep
  // alerting); this ALSO raises a dedicated tamper alert so an attacker who merely corrupts/chmods
  // canaries.json (rather than touching a canary itself) does not go unnoticed just because the
  // gate happened to fail safe. NOT gated by coldStartPendingThisTick (Slice 7): this is a direct
  // I/O-failure signal, not a fact-history novelty/absence claim, so the completeness lockout above
  // must never suppress it.
  const tamperEntries = [];
  if (manifestResult?.read_ok === false) {
    tamperEntries.push({ reason: "manifest_unreadable" });
  }
  // Round-2 fix (findings 2/3/5): canary-manifest.js's loadCanaryManifest now ISOLATES an
  // entity_key collision, an id that sanitizes to no safe entity_key, or an entry beyond the
  // MAX_CANARIES cap -- rather than failing the WHOLE manifest closed the way round 1 did -- so
  // every OTHER canary keeps collecting/gating normally. An isolated entry never reaches
  // `canaries` above (currentCanaryIds excludes it, so it can never be gated as "still monitored")
  // and would otherwise vanish with no operator-visible signal at all; surfaced here as its own
  // canary.tampered instead. Ungated by coldStartPendingThisTick, same as manifest_unreadable
  // above: this is a direct manifest-shape signal, not a fact-history novelty/absence claim.
  // (invalidManifestEntries itself is computed earlier, above the trips filter -- round-3 fix --
  // and reused here unchanged.)
  //
  // Round-4 fix: this loop was already reason-agnostic, so "schema_invalid" entries (a per-entry
  // validation failure with a still-usable id -- see canary-manifest.js/isolatedEntityKeys above)
  // fall into it unchanged and get their own canary.tampered exactly like entity_key_collision/
  // manifest_oversized/empty_entity_key already do -- no new branch needed here. This is a
  // deliberate policy choice, not an oversight: a present-but-malformed manifest entry (bad path/
  // kind/watch on an otherwise-identifiable id) is itself worth flagging to the operator, same as
  // any other isolated entry -- "surfacing a malformed present-entry as an anomaly is desirable;
  // the silent-drop was the bug" (round-4 dispatch). No existing test's tamper count regresses:
  // no pre-round-4 test constructs an `invalid_entries` fixture with reason "schema_invalid", so
  // this can only add tamper entries for scenarios the round-4 tests below newly cover.
  for (const entry of invalidManifestEntries) {
    tamperEntries.push({ reason: entry.reason, canary_id: entry.id, kind: entry.kind });
  }
  // CANARY VANISHED (tamper fix, canary v0 finalization): only meaningful when the manifest itself
  // was read successfully -- with an unreadable manifest, currentCanaryIds is empty and every
  // candidate detectCanaryVanished would otherwise find is gated off as an indistinguishable
  // "removed from manifest" decommission (see its own header comment); the manifest_unreadable
  // alert above already covers that broader failure. Slice 7: this IS a fact-history absence claim
  // (an established canary reading as gone because retention/corruption/degraded history hid the
  // tick that would have shown it present). Compute it regardless of lockout state, then suppress
  // only the absence claim while pending; unlike canary.tripped, this claim is fabricable from
  // incomplete history.
  const rawVanished = manifestReadOk
    ? detectCanaryVanished(currentGroups, currentCanaryIds, {
      nowMs,
      freshnessMs,
      minEstablishedCount,
      currentCanaryIdentityFingerprints,
    })
    : [];
  const outputVanished = coldStartPendingThisTick ? [] : rawVanished;
  for (const entry of outputVanished) {
    tamperEntries.push({ reason: "canary_vanished", canary_id: entry.canary_id, kind: entry.kind, last_seen_ts: entry.last_seen_ts });
  }

  // BASELINE-STORE FAILURE (tamper fix, canary v0 finalization): loadCanaryBaselineStore/
  // writeCanaryBaselineStore can both throw on a genuinely unreadable/unwritable store (a
  // non-ENOENT fs error — EACCES, EROFS, ENOSPC, a directory swapped in for the file, ...),
  // previously UNCAUGHT here: the throw propagated all the way out through daemon.js's single
  // `await computeCanaryBaselineCandidates(...)` inside evaluateAndPersistAlerts' extraCandidates
  // array, ABORTING THE ENTIRE DAEMON TICK (every alert family, not just canary.*) rather than
  // degrading just this collector. Caught above instead: never abort the tick on a canary store
  // error, and raise a tamper alert of our own rather than silently losing the bookkeeping. A LOAD
  // failure skips the fold-write entirely this tick — there is no trustworthy prior state to fold
  // onto, and re-attempting a write from a fresh/degraded state would risk clobbering real prior
  // counters over what may be a transient failure.
  const persistedLastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const lastFoldedWasFuture = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs > nowMs;
  const lastFoldedMs = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs <= nowMs ? persistedLastFoldedMs : -Infinity;
  const effectiveLastFoldedTs = lastFoldedMs === -Infinity ? undefined : persistedState.last_folded_ts;
  const newGroups = currentGroups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  let baselineStoreWriteFailed = false;
  const coldStartStateChanged = nextColdStartPending !== persistedState.cold_start_pending
    || nextColdStartReason !== persistedState.cold_start_reason
    || nextColdStartSinceTs !== persistedState.cold_start_since_ts;
  if ((newGroups.length > 0 || coldStartStateChanged || lastFoldedWasFuture) && !baselineStoreLoadFailed) {
    const newGroupTs = new Set(newGroups.map((group) => group.ts));
    const partialCount = newGroups.filter((group) => group.censusState === "partial").length;
    const tripCount = outputTrips.filter((entry) => newGroupTs.has(entry.tripped_at_ts)).length;
    // Stays at the persisted value when newGroups is empty (an enteringColdStart-only call) --
    // mirrors session-baseline.js's/service-baseline.js's own loop-accumulated lastFoldedTs, which
    // likewise only advances across newly-observed groups.
    const lastFoldedTs = newGroups.length > 0 ? newGroups[newGroups.length - 1].ts : effectiveLastFoldedTs;
    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + partialCount,
      trip_event_count: persistedState.trip_event_count + tripCount,
      cold_start_pending: nextColdStartPending,
      cold_start_reason: nextColdStartReason,
      cold_start_since_ts: nextColdStartSinceTs,
    };
    const writeStore = options.writeCanaryBaselineStore ?? writeCanaryBaselineStore;
    try {
      await writeStore(descartesPaths, nextState);
    } catch {
      baselineStoreWriteFailed = true;
    }
  }
  // Bare baseline-store deletion (provisioned-then-removed) is deferred: distinguishing it from
  // never-provisioned first-run or decommission needs a durable provisioning-state marker set at
  // canary setup/enablement and cleared at decommission. Trip un-gating already prevents deletion
  // from evading the tripwire, so a cleanly absent store is not a tamper signal here.
  if (baselineStoreLoadFailed || baselineStoreCorrupt || baselineStoreWriteFailed) {
    tamperEntries.push({ reason: "baseline_store_error" });
  }

  // canary.tripped is positive two-snapshot evidence, so it is emitted even while the completeness
  // lockout is pending. canary_vanished remains gated through outputVanished above because absence
  // can be fabricated by incomplete history.
  return [...buildCanaryTrippedCandidates(outputTrips), ...buildCanaryTamperedCandidates(tamperEntries)];
}
