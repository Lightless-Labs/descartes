// Persistence baseline, Slice B (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md) —
// scheduled_job.appeared novelty detector. Sibling of process-lineage-baseline.js: this module
// reads only the persisted scheduled_job.presence/scheduled_job.census fact history produced by
// Slice A's translator (fact-translators.js). Deterministic, read-only, NEVER eligible for LLM
// adjudication ("scheduled_job." has no reserved classifyAlertNamespace prefix -> unknown_namespace).
//
// GATE DECISION (per-signal, stated explicitly — see the task's CRITICAL SECURITY-SEMANTICS
// LESSON): scheduled_job.appeared is an ABSENCE/NOVELTY claim ("this entity was never seen before
// in this host's fact-history") — an incomplete/truncated fact-history CAN fabricate that claim
// (a normal, long-standing job reads as "new" purely because retention/corruption/cold-start
// dropped the earlier tick that would have shown it as established). It is therefore
// COMPLETENESS-GATED: a persistent cold-start lockout (mirroring process-lineage-baseline.js's
// exact-schema store + 4-term arming) suppresses novelty claims while fact-history trust cannot be
// established, exactly like process-lineage-baseline.js/session-baseline.js/service-baseline.js/
// canary-baseline.js's own *absence*-shaped claims (canary_vanished). This is NOT positive direct
// evidence the way a canary trip or a credential-file mtime/ino change is — it is an inference over
// the SHAPE of history, so it must fail closed on doubt about that history rather than fire.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { factHistoryTrustworthy } from "./fact-store-completeness.js";
import {
  SCHEDULED_JOB_CENSUS_FACT_NAME,
  SCHEDULED_JOB_PRESENCE_FACT_NAME,
} from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";

export const SCHEDULED_JOB_APPEARED_RULE_ID = "scheduled_job.appeared";

// [O2] Provisional default of 3 (matching DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT) was
// flagged in the plan as possibly too low given scheduled-job census is the MORE
// truncation-prone of the two shipped novelty domains (P2: fairness-cap + probe-level
// truncation). Resolved here with the fail-safe/stricter default, matching
// process-lineage-baseline.js's own DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT (6) rather than the
// looser service precedent (3) — a false "new scheduled job" claim triggered by an
// under-accumulated window is a worse outcome than a slightly slower time-to-first-detection.
export const DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT = 6;
export const DEFAULT_SCHEDULED_JOB_FRESHNESS_FALLBACK_MS = 3 * 60 * 60 * 1000;

export function resolvePersistenceBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "persistence-baseline.json") };
}

async function ensurePersistenceBaselineDir(descartesPaths) {
  await fs.mkdir(resolvePersistenceBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshPersistenceBaselineState() {
  return {
    version: 2,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    appeared_event_count: 0,
    // Persistent cold-start lockout (mirrors process-lineage-baseline.js's
    // freshProcessLineageBaselineState exactly — see the extended comment on
    // computeScheduledJobBaselineCandidates below for the full rationale). A brand new store
    // starts pending, exactly like a genuine day-1 cold start.
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

export function normalizePersistenceBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 2,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    appeared_event_count: finiteOrDefault(base.appeared_event_count, 0),
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

// [REVIEW 2026-08-21, must-fix] Exact-schema validation, mirroring
// process-lineage-baseline.js's isValidProcessLineageBaselineStoreShape/
// PROCESS_LINEAGE_BASELINE_STORE_KEYS byte-for-byte (see that module's own extended comment for
// the full fabrication-class rationale this closes): a closed key set (any unknown key rejects
// the whole store), non-negative-integer counters, a cold_start_pending:true store must carry a
// valid cold_start_since_ts anchor (or it can never re-establish), and an established
// (cold_start_pending:false) store must carry the COMPLETE established-state schema (a valid
// last_folded_ts) or it is rejected outright — never partially trusted.
const PERSISTENCE_BASELINE_STORE_KEYS = new Set([
  "version",
  "last_folded_ts",
  "skipped_partial_tick_count",
  "appeared_event_count",
  "cold_start_pending",
  "cold_start_reason",
  "cold_start_since_ts",
]);

function isNonNegativeFiniteInteger(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value >= 0;
}

export function isValidPersistenceBaselineStoreShape(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  for (const key of Object.keys(raw)) {
    if (!PERSISTENCE_BASELINE_STORE_KEYS.has(key)) return false;
  }
  if (raw.version !== 2) return false;
  if (typeof raw.cold_start_pending !== "boolean") return false;
  if (!isNonNegativeFiniteInteger(raw.skipped_partial_tick_count)) return false;
  if (!isNonNegativeFiniteInteger(raw.appeared_event_count)) return false;
  if (raw.cold_start_reason !== undefined && typeof raw.cold_start_reason !== "string") return false;
  if (raw.cold_start_pending) {
    if (!isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
    if (raw.last_folded_ts !== undefined && !isValidIsoTimestamp(raw.last_folded_ts)) return false;
  } else {
    if (!isValidIsoTimestamp(raw.last_folded_ts)) return false;
    if (raw.cold_start_since_ts !== undefined && !isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
  }
  return true;
}

export async function loadPersistenceBaselineStore(descartesPaths) {
  const { storeFile } = resolvePersistenceBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) {
    return { state: { ...freshPersistenceBaselineState(), cold_start_reason: "missing_store" }, corrupt: false, missing: true };
  }
  if (corrupt) {
    return { state: { ...freshPersistenceBaselineState(), cold_start_reason: "corrupt_store" }, corrupt: true, missing: false };
  }
  if (!isValidPersistenceBaselineStoreShape(parsed)) {
    return { state: { ...freshPersistenceBaselineState(), cold_start_reason: "invalid_store_schema" }, corrupt: true, missing: false };
  }
  return { state: normalizePersistenceBaselineState(parsed), corrupt: false, missing: false };
}

export async function writePersistenceBaselineStore(descartesPaths, state) {
  await ensurePersistenceBaselineDir(descartesPaths);
  const { storeFile } = resolvePersistenceBaselineStorePaths(descartesPaths);
  const normalized = normalizePersistenceBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

export function groupScheduledJobFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || typeof point.ts !== "string") continue;
    if (point.fact_name !== SCHEDULED_JOB_PRESENCE_FACT_NAME && point.fact_name !== SCHEDULED_JOB_CENSUS_FACT_NAME) continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, censusState: undefined, entityKeys: new Set() });
    }
    const group = byTs.get(point.ts);
    if (point.fact_name === SCHEDULED_JOB_CENSUS_FACT_NAME) {
      const rawState = point.attributes?.census_state;
      group.censusState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
    } else {
      group.entityKeys.add(point.entity_key);
    }
  }
  return [...byTs.values()].sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
}

export function detectScheduledJobAppearances(groups = [], options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_SCHEDULED_JOB_FRESHNESS_FALLBACK_MS,
    minHistoryTickCount = DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT,
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

  const appearances = [];
  for (const entityKey of latest.entityKeys) {
    if (historical.has(entityKey)) continue;
    appearances.push({ entity_key: entityKey, first_seen_ts: latest.ts });
  }
  return appearances;
}

function hashScheduledJobEntityKey(entityKey) {
  return crypto.createHash("sha256")
    .update(`${SCHEDULED_JOB_APPEARED_RULE_ID}:${entityKey}`)
    .digest("hex")
    .slice(0, 16);
}

// [O1] Hash-only diagnostics by default (unsigned): mirrors buildNovelEdgeCandidates' own
// hash-only shape, NOT service.disappeared's scoped 2026-07-24 cleartext-name exception. A future
// operator sign-off can flip this to carry a sanitized job_kind/job_source/job_name, exactly as
// noted in the plan — this default is a one-line follow-up away, not a redesign.
export function buildScheduledJobAppearedCandidates(entries = []) {
  return entries.map((entry) => {
    const entityKeyHash = hashScheduledJobEntityKey(entry.entity_key);
    const diagnostics = sanitizeDiagnostics({
      entity_key_hash: entityKeyHash,
      first_seen_ts: entry.first_seen_ts,
    });
    return {
      id: alertId(SCHEDULED_JOB_APPEARED_RULE_ID, entityKeyHash),
      rule_id: SCHEDULED_JOB_APPEARED_RULE_ID,
      fingerprint: entityKeyHash,
      // Severity capped at "warning" UNCONDITIONALLY (plan Slice B) — a new scheduled job is a
      // real-FP-rate heuristic (legitimate tooling/package managers install cron/launchd jobs
      // routinely), NOT the near-zero-FP canary tripwire. No critical tier in v1.
      severity: "warning",
      title: "Unexpected scheduled job",
      summary: "A scheduled job (cron/systemd timer/launchd job) not seen in this host's recent history just appeared.",
      diagnostics,
      evidence_refs: ["persistence-baseline"],
    };
  });
}

/**
 * GATE DECISION reminder (see module header): scheduled_job.appeared is an absence/novelty claim
 * — completeness-gated via the SAME persistent cold-start lockout mechanism
 * process-lineage-baseline.js/session-baseline.js/service-baseline.js/canary-baseline.js already
 * carry (3-term arming: this-tick fact corruption, store loss/invalid-schema, or
 * factHistoryTrustworthy() distrust; a 4th term below re-arms on a missing/future persisted
 * anchor). Behavior on incomplete history: emit NOTHING (cold-start / no-novelty-claim), never
 * fabricate.
 */
export async function computeScheduledJobBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;
  const minHistoryTickCount = options.minHistoryTickCount ?? DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT;

  const readFacts = options.readFactPoints ?? readFactPoints;
  const readResult = await readFacts(descartesPaths, { windowMs, now: options.now });
  const { points, corrupt_count: corruptFactCount } = readResult;
  const groups = groupScheduledJobFactsByTick(points);

  const loadStore = options.loadPersistenceBaselineStore ?? loadPersistenceBaselineStore;
  const { state: persistedState, corrupt: corruptBaselineStore, missing: missingBaselineStore } = await loadStore(descartesPaths);
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_SCHEDULED_JOB_FRESHNESS_FALLBACK_MS;
  const currentGroups = groups.filter((group) => {
    const groupMs = new Date(group.ts).getTime();
    return Number.isFinite(groupMs) && groupMs <= nowMs;
  });

  const factsCorruptThisTick = Boolean(corruptFactCount);
  const storeLossThisTick = corruptBaselineStore === true || missingBaselineStore === true;
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

  const coldStartPendingThisTick = persistedState.cold_start_pending || enteringColdStart || !historyTrust.trust;

  let nextColdStartPending = persistedState.cold_start_pending;
  let nextColdStartReason = persistedState.cold_start_reason;
  let nextColdStartSinceTs = persistedState.cold_start_since_ts;

  if (enteringColdStart) {
    nextColdStartPending = true;
    nextColdStartReason = storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts";
    nextColdStartSinceTs = nowIso;
  } else if (persistedState.cold_start_pending && historyTrust.trust) {
    const sinceMs = persistedState.cold_start_since_ts ? new Date(persistedState.cold_start_since_ts).getTime() : Infinity;
    const reestablishedTickCount = currentGroups.filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return group.censusState === "complete" && groupMs > sinceMs && groupMs <= nowMs;
    }).length;
    if (reestablishedTickCount >= minHistoryTickCount) {
      nextColdStartPending = false;
    }
  }

  const appearances = coldStartPendingThisTick ? [] : detectScheduledJobAppearances(currentGroups, { nowMs, freshnessMs, minHistoryTickCount });

  const persistedLastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const lastFoldedWasFuture = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs > nowMs;
  const lastFoldedMs = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs <= nowMs ? persistedLastFoldedMs : -Infinity;
  const effectiveLastFoldedTs = lastFoldedMs === -Infinity ? undefined : persistedState.last_folded_ts;
  const newGroups = currentGroups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);
  const coldStartStateChanged = nextColdStartPending !== persistedState.cold_start_pending
    || nextColdStartReason !== persistedState.cold_start_reason
    || nextColdStartSinceTs !== persistedState.cold_start_since_ts;
  if (newGroups.length > 0 || coldStartStateChanged || lastFoldedWasFuture) {
    const newGroupTs = new Set(newGroups.map((group) => group.ts));
    const skippedPartial = newGroups.filter((group) => group.censusState === "partial").length;
    const appearedEvents = appearances.filter((entry) => newGroupTs.has(entry.first_seen_ts)).length;
    const nextState = {
      version: 2,
      last_folded_ts: newGroups.length > 0 ? newGroups[newGroups.length - 1].ts : effectiveLastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + skippedPartial,
      appeared_event_count: persistedState.appeared_event_count + appearedEvents,
      cold_start_pending: nextColdStartPending,
      cold_start_reason: nextColdStartReason,
      cold_start_since_ts: nextColdStartSinceTs,
    };
    const writeStore = options.writePersistenceBaselineStore ?? writePersistenceBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  return buildScheduledJobAppearedCandidates(appearances);
}
