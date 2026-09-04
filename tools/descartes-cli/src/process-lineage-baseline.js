// Layer-1 process-lineage novelty baseline. This module reads only the persisted
// process.lineage_edge fact history produced from the existing process snapshot collector.
// It is deterministic, read-only, and intentionally never eligible for LLM adjudication.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { factHistoryTrustworthy } from "./fact-store-completeness.js";
import {
  PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME,
  PROCESS_LINEAGE_EDGE_FACT_NAME,
} from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";

export const PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID = "process.lineage.novel_edge";
export const DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT = 6;
export const DEFAULT_LINEAGE_FRESHNESS_FALLBACK_MS = 3 * 60 * 60 * 1000;

export function resolveProcessLineageBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "process-lineage-baseline.json") };
}

async function ensureProcessLineageBaselineDir(descartesPaths) {
  await fs.mkdir(resolveProcessLineageBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshProcessLineageBaselineState() {
  return {
    version: 2,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    novel_edge_event_count: 0,
    // Persistent cold-start lockout (BOUNDED fix, deception/anomaly-detector review --
    // corrupt/missing-store self-heal-and-immediately-fire pattern): see the extended
    // comment on computeProcessLineageBaselineCandidates for the full rationale. A brand
    // new store starts pending, exactly like a genuine day-1 cold start.
    cold_start_pending: true,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
  };
}

function finiteOrDefault(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

export function normalizeProcessLineageBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 2,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    novel_edge_event_count: finiteOrDefault(base.novel_edge_event_count, 0),
    // Fail-closed default: cold_start_pending is trusted "false" only when the store
    // explicitly and validly recorded it as such. Any other value -- missing (old-format
    // store predating this field), non-boolean garbage, or an explicit true -- is treated
    // as still pending. This is what makes a schema-migration or a hand-truncated store
    // behave as a reset instead of as silently-already-established.
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

function isValidIsoTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(new Date(value).getTime());
}

const COMPLETENESS_LOSS_TIMESTAMP_FIELDS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

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

// FABRICATION fix (deception/anomaly-detector review -- schema-invalid-store trust pattern):
// JSON.parse succeeding is NOT sufficient to trust a persisted store. A parseable-but-wrong-shape
// blob -- a hand-truncated fragment like {"cold_start_pending":false} with no schema_version /
// cold_start_since_ts / counters, an old-format store predating a schema change, or an entirely
// foreign file that happens to be valid JSON -- must be treated exactly like a corrupt store, not
// accepted at face value just because a lenient field-by-field coercion (normalizeProcessLineage-
// BaselineState) can produce *something* from it. Trusting it would let a bare
// `cold_start_pending: false` claim -- backed by zero actually-validated history -- immediately
// authorize novel-edge detection against whatever the live fact window happens to contain right
// now, fabricating a claim from retained history the store never legitimately vouched for.
//
// This performs FULL structural validation, not per-field defaulting: every field required to
// trust the store must be present and correctly typed, or the whole store is rejected.
//
// TERMINAL fix (gpt-5.6-sol review -- exact-schema pattern): "check each field IF it is present"
// is still not exact-schema validation. A minimal parseable store like
// {version:2, <both counters>, cold_start_pending:false} that is simply MISSING last_folded_ts
// used to pass this function outright -- every field that WAS present validated fine, and
// last_folded_ts was only ever checked "if present" -- and was then trusted as a genuinely
// established baseline, fabricating a novel-edge claim from whatever history happens to be
// retained, with zero real folded-tick provenance behind it. Likewise a store carrying
// unknown/foreign top-level keys (a mismerged or tampered file) or out-of-range counters
// (negative, fractional -- never producible by this module's own writer) was silently accepted as
// long as the known fields individually parsed. Trust is now exact-schema, not per-field-lenient:
//   - only the known field set is allowed at all -- any foreign/unknown top-level key rejects the
//     whole store;
//   - the two counters must always be non-negative finite INTEGERS, not just finite numbers;
//   - an established store (cold_start_pending === false) must carry the COMPLETE
//     established-state schema -- version 2, a present-and-valid last_folded_ts, both counters
//     present and in range. A missing last_folded_ts (or anything else required) rejects the
//     whole store, exactly like a wrong-type field would.
// Any store that fails ANY of the above is not "mostly trusted with defaults filled in" -- it is
// rejected outright here, which routes the caller (loadProcessLineageBaselineStore) into the same
// persistent cold-start lockout as a corrupt/missing store, anchored with a real
// cold_start_since_ts (reason "invalid_store_schema") so it can actually re-establish instead of
// getting stuck. A perfectly-valid established store still trusts and fires immediately.
const PROCESS_LINEAGE_BASELINE_STORE_KEYS = new Set([
  "version",
  "last_folded_ts",
  "skipped_partial_tick_count",
  "novel_edge_event_count",
  "cold_start_pending",
  "cold_start_reason",
  "cold_start_since_ts",
]);

function isNonNegativeFiniteInteger(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value >= 0;
}

export function isValidProcessLineageBaselineStoreShape(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  for (const key of Object.keys(raw)) {
    if (!PROCESS_LINEAGE_BASELINE_STORE_KEYS.has(key)) return false;
  }
  if (raw.version !== 2) return false;
  if (typeof raw.cold_start_pending !== "boolean") return false;
  if (!isNonNegativeFiniteInteger(raw.skipped_partial_tick_count)) return false;
  if (!isNonNegativeFiniteInteger(raw.novel_edge_event_count)) return false;
  if (raw.cold_start_reason !== undefined && typeof raw.cold_start_reason !== "string") return false;
  if (raw.cold_start_pending) {
    // FAIL-SAFE fix (deception/anomaly-detector review -- Infinity re-establishment-boundary
    // pattern): a store that claims to be cold-start-pending but carries no valid anchor cannot
    // ever re-establish (the re-accumulation gate below falls back to `Infinity`, which no real
    // tick timestamp can ever exceed) -- it is permanently silenced. Such a store is corrupt by
    // definition and must be rejected here so the caller re-arms it with a genuine anchor instead.
    if (!isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
    // A pending store may or may not have folded any ticks yet (re-accumulation can be
    // mid-flight) -- last_folded_ts is optional here, but must be a valid ISO string if present.
    if (raw.last_folded_ts !== undefined && !isValidIsoTimestamp(raw.last_folded_ts)) return false;
  } else {
    // Established store: the COMPLETE established-state schema is required. last_folded_ts is no
    // longer merely "valid if present" -- an established store with zero folded-tick provenance
    // at all is exactly the fabrication pattern this fix closes.
    if (!isValidIsoTimestamp(raw.last_folded_ts)) return false;
    if (raw.cold_start_since_ts !== undefined && !isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
  }
  return true;
}

export async function loadProcessLineageBaselineStore(descartesPaths) {
  const { storeFile } = resolveProcessLineageBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) {
    return { state: { ...freshProcessLineageBaselineState(), cold_start_reason: "missing_store" }, corrupt: false, missing: true };
  }
  if (corrupt) {
    return { state: { ...freshProcessLineageBaselineState(), cold_start_reason: "corrupt_store" }, corrupt: true, missing: false };
  }
  if (!isValidProcessLineageBaselineStoreShape(parsed)) {
    return { state: { ...freshProcessLineageBaselineState(), cold_start_reason: "invalid_store_schema" }, corrupt: true, missing: false };
  }
  return { state: normalizeProcessLineageBaselineState(parsed), corrupt: false, missing: false };
}

export async function writeProcessLineageBaselineStore(descartesPaths, state) {
  await ensureProcessLineageBaselineDir(descartesPaths);
  const { storeFile } = resolveProcessLineageBaselineStorePaths(descartesPaths);
  const normalized = normalizeProcessLineageBaselineState(state);
  // FAIL-SAFE fix (deception/anomaly-detector review -- Infinity re-establishment-boundary
  // pattern): normalizeProcessLineageBaselineState's own defaulting deliberately leaves
  // cold_start_since_ts undefined when a caller doesn't supply one (see its direct-call use in
  // tests to describe the fresh/unset shape) -- but a store that is actually PERSISTED to disk
  // with cold_start_pending:true and no anchor can never re-establish (the re-accumulation gate
  // has nothing to compare tick timestamps against -- see computeProcessLineageBaselineCandidates)
  // and, since isValidProcessLineageBaselineStoreShape now requires an anchor whenever pending is
  // true, would not even round-trip through loadProcessLineageBaselineStore. Compute paths must
  // set the anchor from their injected clock before persisting pending state.
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

export function groupProcessLineageFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || typeof point.ts !== "string") continue;
    if (point.fact_name !== PROCESS_LINEAGE_EDGE_FACT_NAME && point.fact_name !== PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME) continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, censusState: undefined, censusMarkerSeen: false, entityKeys: new Set() });
    }
    const group = byTs.get(point.ts);
    if (point.fact_name === PROCESS_LINEAGE_EDGE_CENSUS_FACT_NAME) {
      const rawState = point.attributes?.census_state;
      const markerState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
      // Security-sweep F3 fix (2026-09-04 daybreak review): a SECOND census marker landing in this
      // SAME tick whose classified state differs from the first is CONTRADICTORY in-tick evidence
      // -- record order must never decide which marker "wins" (mirrors session-baseline.js's own
      // F3 fix exactly). Fail closed to "unknown". An identical duplicate marker is not a
      // contradiction and must not downgrade a benign double-write.
      group.censusState = group.censusMarkerSeen && markerState !== group.censusState ? "unknown" : markerState;
      group.censusMarkerSeen = true;
    } else {
      group.entityKeys.add(point.entity_key);
    }
  }
  return [...byTs.values()].sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
}

export function detectNovelProcessLineageEdges(groups = [], options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_LINEAGE_FRESHNESS_FALLBACK_MS,
    minHistoryTickCount = DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT,
  } = options;
  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length < minHistoryTickCount + 1) return [];

  const latest = completeGroups[completeGroups.length - 1];
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return [];

  const historical = new Set();
  for (const group of completeGroups.slice(0, -1)) {
    for (const entityKey of group.entityKeys) historical.add(entityKey);
  }

  const novel = [];
  for (const entityKey of latest.entityKeys) {
    if (historical.has(entityKey)) continue;
    novel.push({ entity_key: entityKey, first_seen_ts: latest.ts });
  }
  return novel;
}

function hashLineageEdgeEntityKey(entityKey) {
  return crypto.createHash("sha256")
    .update(`${PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID}:${entityKey}`)
    .digest("hex")
    .slice(0, 16);
}

export function buildNovelEdgeCandidates(entries = []) {
  return entries.map((entry) => {
    const entityKeyHash = hashLineageEdgeEntityKey(entry.entity_key);
    const diagnostics = sanitizeDiagnostics({
      entity_key_hash: entityKeyHash,
      first_seen_ts: entry.first_seen_ts,
    });
    return {
      id: alertId(PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, entityKeyHash),
      rule_id: PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
      fingerprint: entityKeyHash,
      severity: "warning",
      title: "Unexpected process lineage",
      summary: "A process spawn relationship not seen in this host's recent history just appeared.",
      diagnostics,
      evidence_refs: ["process-lineage-baseline"],
    };
  });
}

export async function computeProcessLineageBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;
  const readFacts = options.readFactPoints ?? readFactPoints;
  const readResult = await readFacts(descartesPaths, { windowMs, now: options.now });
  const { points, corrupt_count: corruptFactCount } = readResult;
  const groups = groupProcessLineageFactsByTick(points);

  const loadStore = options.loadProcessLineageBaselineStore ?? loadProcessLineageBaselineStore;
  const { state: persistedState, corrupt: corruptBaselineStore, missing: missingBaselineStore } = await loadStore(descartesPaths);
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_LINEAGE_FRESHNESS_FALLBACK_MS;
  const minHistoryTickCount = options.minHistoryTickCount ?? DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT;
  const currentGroups = groups.filter((group) => {
    const groupMs = new Date(group.ts).getTime();
    return Number.isFinite(groupMs) && groupMs <= nowMs;
  });

  // BOUNDED fix (deception/anomaly-detector review -- corrupt/missing-store
  // self-heal-and-immediately-fire pattern): an unreadable/corrupt fact-history this tick, or a
  // persisted baseline store that is corrupt, MISSING, or otherwise unrecognizable, must never be
  // treated as authoritative "this really is all the historical lineage" -- corruption/loss could
  // easily have silently dropped exactly the older tick(s) that would have shown an edge as
  // already established, making a perfectly normal, long-standing edge read as "never seen" and
  // fire a fabricated novel-edge alert.
  //
  // The prior version of this gate only suppressed novelty for the ONE tick where the corruption
  // was observed: the very next write self-healed the store file, and the tick after THAT went
  // straight back to trusting the live fact-store window in full -- i.e. it self-healed and then
  // immediately fired, using data no more trustworthy than the tick that was just gated. A
  // missing store (e.g. state dir wiped, or file lost independently of facts.jsonl) was worse:
  // `corrupt` was reported as `false` for a missing file, so it was trusted immediately, on the
  // very first tick, with zero suppression at all.
  //
  // Fix: corrupt/missing/unrecognizable store state now enters (or keeps) a PERSISTENT
  // cold_start_pending lockout, persisted on the store itself (cold_start_pending / _reason /
  // _since_ts), that survives across ticks. While pending, this detector emits ZERO novel-edge
  // claims -- not just this tick, but every tick -- until `minHistoryTickCount` genuinely NEW
  // complete ticks (ts strictly after cold_start_since_ts, the moment the lockout began) have
  // been observed. Re-establishment requires ticks to accumulate for real, one at a time, across
  // calls -- it cannot be satisfied retroactively by fact-store history that already existed
  // before/during the loss, which is exactly the untrustworthy signal being gated here. A genuine
  // day-1 cold start goes through this identical mechanism (a brand new store also starts
  // cold_start_pending) -- it differs from a corrupt/missing/reset store only in `cold_start_reason`
  // provenance; the zero-claims behavior and the re-accumulation requirement are the same.
  const factsCorruptThisTick = Boolean(corruptFactCount);
  const storeLossThisTick = corruptBaselineStore === true || missingBaselineStore === true;
  const persistedAnchorMissingOrFuture = (persistedState.cold_start_pending && !isValidIsoTimestamp(persistedState.cold_start_since_ts))
    || (isValidIsoTimestamp(persistedState.cold_start_since_ts)
      && new Date(persistedState.cold_start_since_ts).getTime() > nowMs);
  const historyTrust = factHistoryTrustworthy(readResult, { anchorTs: persistedState.cold_start_since_ts, nowMs });
  const completenessLossAfterAnchor = hasCompletenessLossAfterAnchor(readResult, persistedState.cold_start_since_ts, nowMs);
  // Security-sweep F4 fix (2026-09-04 daybreak review): hoisted ABOVE enteringColdStart (was
  // previously computed only after `novel`, purely to gate the store WRITE) and added as a 5th
  // arming term. A future/clock-rolled-back last_folded_ts means the persisted watermark cannot be
  // trusted relative to the current clock: the groupMs<=nowMs filter above already excludes any
  // pre-rollback (future-dated) history from `currentGroups`, so continuing to trust an
  // "established" store here would fire a novel-edge claim against a SHORTENED window that
  // silently dropped the very history proving the edge is old. Strict `> nowMs` (no tolerance),
  // mirroring persistedAnchorMissingOrFuture's own strict comparison.
  const persistedLastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const lastFoldedWasFuture = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs > nowMs;
  const enteringColdStart = factsCorruptThisTick
    || storeLossThisTick
    || persistedAnchorMissingOrFuture
    || completenessLossAfterAnchor
    || lastFoldedWasFuture
    || (!persistedState.cold_start_pending && !historyTrust.trust);

  // Gate THIS tick's detection using the state as it stood BEFORE any update below -- a tick
  // cannot self-heal and alert in the same breath it (re)establishes trust.
  const coldStartPendingThisTick = persistedState.cold_start_pending || enteringColdStart || !historyTrust.trust;

  let nextColdStartPending = persistedState.cold_start_pending;
  let nextColdStartReason = persistedState.cold_start_reason;
  let nextColdStartSinceTs = persistedState.cold_start_since_ts;

  if (enteringColdStart) {
    // (Re-)arm the lockout. Any in-progress re-accumulation is discarded -- it cannot be trusted
    // to have been continuous once corruption/loss is observed again.
    nextColdStartPending = true;
    // Prefer the specific provenance loadProcessLineageBaselineStore already determined for a
    // store-side loss (corrupt JSON, missing file, or a parseable-but-schema-invalid store) over
    // a generic re-derivation here -- this is what lets loadProcessLineageBaselineStore's
    // "invalid_store_schema" reason (a parseable-but-wrong-shape store) surface distinctly from
    // "corrupt_store" (unparsable JSON) instead of both collapsing to one label.
    nextColdStartReason = storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts";
    nextColdStartSinceTs = nowIso;
  } else if (persistedState.cold_start_pending && historyTrust.trust) {
    // Re-accumulating: count complete ticks genuinely observed strictly after the lockout began.
    // Recomputed fresh from the live window every call (not an incrementing counter) so a missed
    // or re-ordered tick can never double count, and so re-establishment cannot be satisfied by
    // ticks that already existed before the reset.
    const sinceMs = persistedState.cold_start_since_ts ? new Date(persistedState.cold_start_since_ts).getTime() : Infinity;
    const reestablishedTickCount = currentGroups.filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return group.censusState === "complete" && groupMs > sinceMs && groupMs <= nowMs;
    }).length;
    if (reestablishedTickCount >= minHistoryTickCount) {
      nextColdStartPending = false;
    }
  }

  const novel = coldStartPendingThisTick ? [] : detectNovelProcessLineageEdges(currentGroups, { nowMs, freshnessMs, minHistoryTickCount });

  // F4 fix: lastFoldedWasFuture is now computed earlier (above, as an enteringColdStart arming
  // term) -- only lastFoldedMs/effectiveLastFoldedTs (the fold-forward bookkeeping) are still
  // needed here.
  const lastFoldedMs = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs <= nowMs ? persistedLastFoldedMs : -Infinity;
  const effectiveLastFoldedTs = lastFoldedMs === -Infinity ? undefined : persistedState.last_folded_ts;
  const newGroups = currentGroups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);
  const coldStartStateChanged = nextColdStartPending !== persistedState.cold_start_pending
    || nextColdStartReason !== persistedState.cold_start_reason
    || nextColdStartSinceTs !== persistedState.cold_start_since_ts;
  if (newGroups.length > 0 || coldStartStateChanged || lastFoldedWasFuture) {
    const newGroupTs = new Set(newGroups.map((group) => group.ts));
    const skippedPartial = newGroups.filter((group) => group.censusState === "partial").length;
    const novelEvents = novel.filter((entry) => newGroupTs.has(entry.first_seen_ts)).length;
    const nextState = {
      version: 2,
      last_folded_ts: newGroups.length > 0 ? newGroups[newGroups.length - 1].ts : effectiveLastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + skippedPartial,
      novel_edge_event_count: persistedState.novel_edge_event_count + novelEvents,
      cold_start_pending: nextColdStartPending,
      cold_start_reason: nextColdStartReason,
      cold_start_since_ts: nextColdStartSinceTs,
    };
    const writeStore = options.writeProcessLineageBaselineStore ?? writeProcessLineageBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  return buildNovelEdgeCandidates(novel);
}
