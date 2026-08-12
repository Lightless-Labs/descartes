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
import {
  CANARY_CENSUS_FACT_NAME,
  CANARY_CENSUS_MARKER_ENTITY_KEY,
  CANARY_PRESENCE_FACT_NAME,
  sanitizeEntityKey,
} from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";

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
  };
}

function finiteOrDefault(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

export function normalizeCanaryBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    trip_event_count: finiteOrDefault(base.trip_event_count, 0),
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

export async function loadCanaryBaselineStore(descartesPaths) {
  const { storeFile } = resolveCanaryBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: freshCanaryBaselineState(), corrupt: false };
  if (corrupt) return { state: freshCanaryBaselineState(), corrupt: true };
  return { state: normalizeCanaryBaselineState(parsed), corrupt: false };
}

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

function atimeValue(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : undefined;
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
    let tripReason;
    for (const watch of watches) {
      if (watch === "atime") {
        const latestAtime = atimeValue(latestSnapshot.atime);
        const previousAtime = atimeValue(previousSnapshot.atime);
        if (latestAtime !== undefined && previousAtime !== undefined && latestAtime > previousAtime) {
          tripReason = "atime_advanced";
          break;
        }
      } else if (
        watch === "mtime" &&
        latestSnapshot.mtime !== undefined &&
        previousSnapshot.mtime !== undefined &&
        latestSnapshot.mtime !== previousSnapshot.mtime
      ) {
        // Fail-closed (HIGH fix, canary collector review): a MISSING mtime on either side
        // (undefined !== "some-value" is trivially true in JS) must SKIP the comparison, not
        // trip — a hole in the fact record is not evidence of a real attribute change.
        tripReason = "mtime_changed";
        break;
      } else if (watch === "executed" && latestSnapshot.executed === "true" && previousSnapshot.executed === "false") {
        // Fail-closed (HIGH fix, canary collector review): trip ONLY on an explicit,
        // previously-observed "false" flipping to "true". Requiring previousSnapshot.executed
        // === "false" (rather than the looser `!== "true"`) means an UNDEFINED/missing
        // previous value and canary.js's new degrade-not-fabricate "unknown" value (see
        // tools/canary.js's access()-failure fix) can never themselves manufacture a trip —
        // only a genuine, previously-confirmed false->true transition does.
        tripReason = "executed";
        break;
      }
    }
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
  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupCanaryFactsByTick(points);
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_CANARY_FRESHNESS_FALLBACK_MS;
  const minEstablishedCount = options.establishedMinCensusCount ?? DEFAULT_CANARY_ESTABLISHED_MIN_CENSUS_COUNT;
  const rawTrips = detectCanaryTrips(groups, { nowMs, freshnessMs, minEstablishedCount });

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
  const trips = manifestReadOk ? rawTrips.filter((entry) => currentCanaryIds.has(entry.canary_id)) : rawTrips;

  // MANIFEST TAMPER (tamper fix, canary v0 finalization): read_ok:false is a genuine read/parse/
  // schema-invalid FAILURE (canary-manifest.js's loadCanaryManifest contract) -- distinct from a
  // successfully-read, genuinely empty/absent manifest (read_ok:true, a legitimate decommission,
  // which raises NO tamper alert). The gate above already fails OPEN on this (known canaries keep
  // alerting); this ALSO raises a dedicated tamper alert so an attacker who merely corrupts/chmods
  // canaries.json (rather than touching a canary itself) does not go unnoticed just because the
  // gate happened to fail safe.
  const tamperEntries = [];
  if (manifestResult?.read_ok === false) {
    tamperEntries.push({ reason: "manifest_unreadable" });
  }
  // CANARY VANISHED (tamper fix, canary v0 finalization): only meaningful when the manifest itself
  // was read successfully -- with an unreadable manifest, currentCanaryIds is empty and every
  // candidate detectCanaryVanished would otherwise find is gated off as an indistinguishable
  // "removed from manifest" decommission (see its own header comment); the manifest_unreadable
  // alert above already covers that broader failure.
  if (manifestReadOk) {
    const vanished = detectCanaryVanished(groups, currentCanaryIds, { nowMs, freshnessMs, minEstablishedCount });
    for (const entry of vanished) {
      tamperEntries.push({ reason: "canary_vanished", canary_id: entry.canary_id, kind: entry.kind, last_seen_ts: entry.last_seen_ts });
    }
  }

  // BASELINE-STORE FAILURE (tamper fix, canary v0 finalization): loadCanaryBaselineStore/
  // writeCanaryBaselineStore can both throw on a genuinely unreadable/unwritable store (a
  // non-ENOENT fs error — EACCES, EROFS, ENOSPC, a directory swapped in for the file, ...),
  // previously UNCAUGHT here: the throw propagated all the way out through daemon.js's single
  // `await computeCanaryBaselineCandidates(...)` inside evaluateAndPersistAlerts' extraCandidates
  // array, ABORTING THE ENTIRE DAEMON TICK (every alert family, not just canary.*) rather than
  // degrading just this collector. Caught here instead: never abort the tick on a canary store
  // error, and raise a tamper alert of our own rather than silently losing the bookkeeping. A
  // LOAD failure (thrown, or the already-non-throwing `corrupt:true` degrade
  // loadCanaryBaselineStore already performs for corrupt JSON) skips the fold-write entirely this
  // tick — there is no trustworthy prior state to fold onto, and re-attempting a write from a
  // fresh/degraded state would risk clobbering real prior counters over what may be a transient
  // failure. Trip DETECTION itself (`trips` above) never depended on the store either way — only
  // the skipped_partial_tick_count/trip_event_count bookkeeping does — so canary.tripped's own
  // alerting integrity is unaffected by any of this; only the informational counters (and now,
  // additionally, this tamper alert) are.
  const loadStore = options.loadCanaryBaselineStore ?? loadCanaryBaselineStore;
  let persistedState = freshCanaryBaselineState();
  let baselineStoreLoadFailed = false;
  let baselineStoreCorrupt = false;
  try {
    const loaded = await loadStore(descartesPaths);
    persistedState = loaded.state;
    baselineStoreCorrupt = Boolean(loaded.corrupt);
  } catch {
    baselineStoreLoadFailed = true;
  }

  const lastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const newGroups = groups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);
  let baselineStoreWriteFailed = false;
  if (newGroups.length > 0 && !baselineStoreLoadFailed) {
    const newGroupTs = new Set(newGroups.map((group) => group.ts));
    const partialCount = newGroups.filter((group) => group.censusState === "partial").length;
    const tripCount = trips.filter((entry) => newGroupTs.has(entry.tripped_at_ts)).length;
    const nextState = {
      version: 1,
      last_folded_ts: newGroups[newGroups.length - 1].ts,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + partialCount,
      trip_event_count: persistedState.trip_event_count + tripCount,
    };
    const writeStore = options.writeCanaryBaselineStore ?? writeCanaryBaselineStore;
    try {
      await writeStore(descartesPaths, nextState);
    } catch {
      baselineStoreWriteFailed = true;
    }
  }
  if (baselineStoreLoadFailed || baselineStoreCorrupt || baselineStoreWriteFailed) {
    tamperEntries.push({ reason: "baseline_store_error" });
  }

  return [...buildCanaryTrippedCandidates(trips), ...buildCanaryTamperedCandidates(tamperEntries)];
}
