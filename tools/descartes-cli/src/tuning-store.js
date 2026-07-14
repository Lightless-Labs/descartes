// S14 (outcome-informed compile-down) — docs/plans/2026-07-14-compile-down-calibration.md §5.
//
// Turns S15's calibration report (calibration.js's computeCalibrationReport) into INERT,
// REVIEWABLE `tuning-candidates.json` entries: draft -> review-ready -> approved | rejected.
// A candidate is NEVER auto-applied by anything in this file — mining/merging/promoting to
// review-ready are all pure, read-only-of-live-state operations. The ONLY way a candidate's
// approval ever changes a live constraint is through tuning-authority.js's decideTuningApproval,
// which calls constraint-store.js's retireActiveConstraint/applyApprovedRetune — two functions
// this file never imports and never calls (see the no-mutation-path regression test).
//
// v1 scope (plan §5.1/§5.2, must-fix 6): only `constraint.violation.<family>` calibration rows are
// minable. `provenance.*`/`session.*`/`peer.*`/`correlation.*` rows are NEVER turned into a
// candidate here — mining those families is Slice 14b (§9), not this file.
//
// Deterministic, no I/O in the pure functions (mineTuningCandidates/mergeMinedTuningCandidates/
// promoteTuningDraftsToReviewReady/proposeRetune/backtestRetune/replayObservedValues): same inputs
// -> byte-identical outputs. All file I/O is isolated to the CLI handlers at the bottom.
//
// No LLM anywhere: this file never imports pi-harness.js or alert-intelligence.js's adjudication
// path — only calibration.js's pure computeCalibrationReport and alert-intelligence.js's/
// notification-delivery.js's/shadow-store.js's plain reader functions (same posture as
// calibration.js itself). See the no-LLM source-regex test in test/tuning-store.test.js.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { readAlertRecords } from "./alert-store.js";
import { readAlertIntelligenceAudit, readAlertIntelligenceConfig } from "./alert-intelligence.js";
import {
  DEFAULT_MIN_CHRONIC_FIRES,
  computeCalibrationReport,
} from "./calibration.js";
import { evaluateExpected } from "./constraint-eval.js";
import {
  buildConstraintTarget,
  checkShadowSoak,
  loadConstraints,
  loadLearnedConfig,
} from "./constraint-store.js";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { parseDurationMs } from "./history-store.js";
import { readNotificationDeliveryAudit } from "./notification-delivery.js";
import { buildShadowFactLookup, readShadowRecords } from "./shadow-store.js";

export const SCHEMA_VERSION = 1;

export const TUNING_KINDS = ["retire", "retune", "promote_shadow_hint"];
export const TUNING_STATUSES = ["draft", "review-ready", "approved", "rejected"];

// "Some but not chronic" retune band (plan §5.2): fired_count in [MIN_RETUNE_FIRES,
// MIN_CHRONIC_FIRES) — below this band, nothing is proposed ("healthy"); at/above
// MIN_CHRONIC_FIRES, chronically_firing (S15) is what drives `retire` instead.
export const DEFAULT_MIN_RETUNE_FIRES = 2;

// 5% safety margin past the observed extreme (plan §5.3) — loosen-only in v1.
export const DEFAULT_RETUNE_MARGIN_PCT = 0.05;

// Deterministic draft -> review-ready gate (plan §5.5), mirrors constraint-store.js's
// MIN_FIXTURE_COUNT-style bar: a retune draft needs a big-enough backtest sample; retire/
// promote_shadow_hint just need their (always-present, computed-at-mine-time) justification.
export const DEFAULT_MIN_BACKTEST_SAMPLES = 10;

const CONSTRAINT_VIOLATION_PREFIX = "constraint.violation.";

export function resolveTuningStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, tuningCandidatesFile: path.join(dir, "tuning-candidates.json") };
}

async function ensureTuningDir(descartesPaths) {
  await fs.mkdir(resolveTuningStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid tuning candidate ${field}: ${ts}`);
  return date.toISOString();
}

/**
 * Validates a TuningCandidate record (plan §5.4). Throws a descriptive Error on the first
 * invalid/missing required field; returns true otherwise. Mirrors constraint-store.js's
 * validateConstraint / promotion-store.js's validatePromotionRecord exactly.
 */
export function validateTuningCandidate(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Tuning candidate record must be an object");
  }

  const id = String(record.id ?? "").trim();
  if (!id) throw new Error("Tuning candidate record requires a non-empty id");

  if (!TUNING_KINDS.includes(record.kind)) {
    throw new Error(`Tuning candidate record kind must be one of ${TUNING_KINDS.join(", ")}, got: ${JSON.stringify(record.kind)}`);
  }

  const artifactRef = String(record.artifact_ref ?? "").trim();
  if (!artifactRef) throw new Error("Tuning candidate record requires a non-empty artifact_ref");

  const ruleIdFamily = String(record.rule_id_family ?? "").trim();
  if (!ruleIdFamily) throw new Error("Tuning candidate record requires a non-empty rule_id_family");

  if (!["artifact", "family"].includes(record.granularity)) {
    throw new Error(`Tuning candidate record granularity must be "artifact" or "family", got: ${JSON.stringify(record.granularity)}`);
  }

  if (!TUNING_STATUSES.includes(record.status)) {
    throw new Error(`Tuning candidate record status must be one of ${TUNING_STATUSES.join(", ")}, got: ${JSON.stringify(record.status)}`);
  }

  if (!record.justification || typeof record.justification !== "object" || Array.isArray(record.justification)) {
    throw new Error("Tuning candidate record requires a justification object");
  }

  if (typeof record.applied !== "boolean") {
    throw new Error("Tuning candidate record requires a boolean applied field");
  }

  if (!Number.isFinite(Number(record.schema_version))) {
    throw new Error("Tuning candidate record requires a numeric schema_version");
  }

  return true;
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
 * Loads the tuning-candidate store, tolerating a corrupt/malformed file (mirrors
 * constraint-store.js's loadConstraints exactly) rather than throwing.
 */
export async function loadTuningCandidates(descartesPaths) {
  const { tuningCandidatesFile } = resolveTuningStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(tuningCandidatesFile);
  if (missing) return { candidates: [], corrupt_count: 0 };
  if (corrupt) return { candidates: [], corrupt_count: 1 };

  const rawCandidates = Array.isArray(parsed) ? parsed : parsed?.candidates;
  if (!Array.isArray(rawCandidates)) return { candidates: [], corrupt_count: 1 };

  const candidates = [];
  for (const record of rawCandidates) {
    try {
      validateTuningCandidate(record);
      candidates.push(record);
    } catch {
      // Silently drop invalid individual records, mirroring loadConstraints.
    }
  }
  return { candidates, corrupt_count: 0 };
}

/**
 * Atomically writes the tuning-candidate store (tmp+rename, 0o600 file / 0o700 dir), mirroring
 * constraint-store.js's writeConstraints exactly. Every record is validated before persisting.
 */
export async function writeTuningCandidates(descartesPaths, candidates) {
  await ensureTuningDir(descartesPaths);
  const { tuningCandidatesFile } = resolveTuningStorePaths(descartesPaths);
  const normalized = (candidates ?? []).map((record) => {
    validateTuningCandidate(record);
    return record;
  });
  const payload = JSON.stringify({ schema_version: SCHEMA_VERSION, candidates: normalized }, null, 2);
  const tmpFile = `${tuningCandidatesFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, tuningCandidatesFile);
  return normalized;
}

/**
 * MUST-FIX 5 (plan §5.4/§5.5): deliberately timestamp-free id, mirroring constraint-miner.js's
 * minedId(family, entityKey). `mined_at` is a separate field on the record and is NEVER part of
 * this hash — including it would break mergeMinedTuningCandidates' idempotent refresh (every
 * re-mine of the same underlying (kind, artifact_ref) would compute a new id and accumulate a
 * duplicate draft forever instead of refreshing the existing one).
 */
export function tuningCandidateId(kind, artifactRef) {
  const digest = crypto.createHash("sha256").update(`${kind}\0${artifactRef}`).digest("hex").slice(0, 16);
  return `tuning.${digest}`;
}

// --- The backtest (plan §5.3): replay historical fact points through the SAME shared
// degraded-excluding projection (buildShadowFactLookup) the live daemon tick uses, keyed by the
// constraint's own target. Never a raw String attribute read off fact-store.js points directly —
// that would silently diverge from what the live evaluator actually saw (degraded observations
// would leak into the backtest, corrupting would_fire_count_current/proposed in a way a reviewer
// has no way to detect from the numbers alone). ---

/**
 * Groups points by their exact `ts` (the tick granularity fact-store.js already writes at — no
 * new time-bucketing invented), sorted chronologically. Each bucket is then run through
 * buildShadowFactLookup independently, exactly mirroring one live daemon tick's projection.
 */
function bucketPointsByTick(points) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || point.ts === undefined) continue;
    const key = point.ts;
    if (!byTs.has(key)) byTs.set(key, []);
    byTs.get(key).push(point);
  }
  return [...byTs.entries()].sort((left, right) => new Date(left[0]).getTime() - new Date(right[0]).getTime());
}

/**
 * Replays `points` (the retained fact-history for a single constraint target — see
 * buildFactHistoryByTarget below) through buildShadowFactLookup, one tick at a time, and returns
 * the chronological series of NUMERIC values `target` would have held at each tick. A tick where
 * the observation was degraded (owner_known:"false"/confidence:0, per buildShadowFactLookup's own
 * exclusion) or non-numeric is skipped entirely — not a fabricated zero/gap value — exactly
 * matching what the live evaluator would have seen ("no fact, no claim").
 */
export function replayObservedValues(points, target) {
  const observed = [];
  for (const [, bucket] of bucketPointsByTick(points)) {
    const lookup = buildShadowFactLookup(bucket);
    const value = lookup(target);
    if (value === undefined) continue; // degraded/excluded tick, or a tick that doesn't concern this target
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) continue; // non-numeric observation cannot inform a numeric retune
    observed.push(numeric);
  }
  return observed;
}

/**
 * Builds a `target -> raw fact points` index from a flat fact-history window (readFactPoints
 * output), reconstructing each point's target via the same shared buildConstraintTarget every
 * other store in this codebase uses — so a mined constraint's `target` always matches. Exported
 * so the CLI handler (below) can build this once per `tuning mine` run and hand it to
 * mineTuningCandidates as the `factHistoryByTarget` parameter.
 */
export function buildFactHistoryByTarget(factPoints) {
  const byTarget = new Map();
  for (const point of factPoints ?? []) {
    if (!point) continue;
    const target = buildConstraintTarget(point.fact_name, point.entity_key);
    if (!target) continue;
    if (!byTarget.has(target)) byTarget.set(target, []);
    byTarget.get(target).push(point);
  }
  return byTarget;
}

function factHistoryFor(factHistoryByTarget, target) {
  if (!factHistoryByTarget) return [];
  if (typeof factHistoryByTarget.get === "function") return factHistoryByTarget.get(target) ?? [];
  return factHistoryByTarget[target] ?? [];
}

/**
 * Pure, deterministic proposal for a LOOSENED numeric threshold (plan §5.3): a `gte` floor moves
 * down to just past the lowest observed value; a `lte` ceiling moves up to just past the highest.
 * `eq`/pattern comparators (categorical) have no numeric retune — returns undefined. Guards the
 * empty-observedValues case explicitly: Math.min/max(...[]) is +/-Infinity, and this must never
 * propose a threshold against zero data.
 *
 * Caveat (plan §5.3, noted not fixed in v1): the margin only "loosens away from zero" when the
 * extreme value is positive — for a negative-valued domain this would tighten, not loosen. None
 * of v1's real numeric targets have a negative domain; flagged for any future one that might.
 */
export function proposeRetune(comparator, observedValues, options = {}) {
  const marginPct = options.marginPct ?? DEFAULT_RETUNE_MARGIN_PCT;
  const values = Array.isArray(observedValues) ? observedValues : [];
  if (values.length === 0) return undefined;
  if (comparator === "gte") return Math.min(...values) * (1 - marginPct);
  if (comparator === "lte") return Math.max(...values) * (1 + marginPct);
  return undefined;
}

/**
 * Deterministic replay backtest (plan §5.3): reuses the EXACT comparator logic the live evaluator
 * uses (constraint-eval.js's evaluateExpected, exported additively for this purpose) against the
 * replayed `observedValues`, comparing how many historical ticks would have fired under the
 * current threshold vs. the proposed one. No wall-clock/random dependency — same inputs always
 * produce byte-identical output.
 */
export function backtestRetune(observedValues, currentExpected, proposedExpected) {
  const values = Array.isArray(observedValues) ? observedValues : [];
  const wouldFireCurrent = values.filter((value) => !evaluateExpected(currentExpected, value).satisfied).length;
  const wouldFireProposed = values.filter((value) => !evaluateExpected(proposedExpected, value).satisfied).length;
  return { sample_ticks: values.length, would_fire_count_current: wouldFireCurrent, would_fire_count_proposed: wouldFireProposed };
}

function safeRefString(value) {
  if (typeof value !== "string" || value.length === 0) return undefined;
  return sanitizeIdentityString(value);
}

function buildJustification(row, backtest) {
  return {
    fired_count: row?.fired_count ?? 0,
    auto_recovered_fast_count: row?.auto_recovered_fast_count ?? 0,
    never_escalated_count: row?.never_escalated_count ?? null,
    llm_suppressed_count: row?.llm_suppressed_count ?? 0,
    llm_adjudicated_count: row?.llm_adjudicated_count ?? 0,
    shadow_fire_rate: row?.shadow_fire_rate ?? null,
    backtest: backtest ?? null,
  };
}

function buildTuningCandidate({ kind, artifactRef, ruleIdFamily, granularity, current, proposed, justification, nowIso }) {
  return {
    id: tuningCandidateId(kind, artifactRef),
    kind,
    artifact_ref: artifactRef,
    rule_id_family: ruleIdFamily,
    granularity,
    status: "draft",
    current: current ?? null,
    proposed: proposed ?? null,
    justification,
    applied: false,
    apply_note: null,
    mined_at: nowIso,
    // The backtest IS the silent-observation equivalent (plan §5.5) — computed instantly from
    // retained history, not a new multi-day live soak — so every mined candidate is
    // "backtested" at mine time, whether or not it carries a numeric backtest block.
    backtested_at: nowIso,
    promotion_history: [],
    schema_version: SCHEMA_VERSION,
  };
}

/**
 * Mines status:"draft" tuning candidates (plan §5.2/§5.5). Pure, deterministic, no I/O.
 *
 * v1 scope (must-fix 6): only `constraint.violation.<family>` calibrationReport rows are ever
 * considered — `provenance.*`/`session.*`/`peer.*`/`correlation.*` rows (and any row whose
 * artifact_ref does not resolve to a live, status:"active" constraint) are skipped outright, no
 * candidate emitted. `promote_shadow_hint` is evaluated independently, directly against the live
 * `constraints` array (not the calibration report — a still-shadow constraint has never fired an
 * alert, so it has no calibration row at all), gated on `options.shadowRecords` +
 * constraint-store.js's own checkShadowSoak (reused, not reimplemented) and the constraint's LIVE
 * status still being "shadow" at mine-time.
 */
export function mineTuningCandidates(constraints, calibrationReport, factHistoryByTarget, options = {}) {
  const minRetuneFires = Number.isFinite(options.minRetuneFires) ? options.minRetuneFires : DEFAULT_MIN_RETUNE_FIRES;
  const minChronicFires = Number.isFinite(options.minChronicFires) ? options.minChronicFires : DEFAULT_MIN_CHRONIC_FIRES;
  const nowIso = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const shadowRecords = Array.isArray(options.shadowRecords) ? options.shadowRecords : [];

  const constraintsById = new Map((constraints ?? []).filter(Boolean).map((constraint) => [constraint.id, constraint]));
  const candidates = [];

  for (const row of calibrationReport?.artifacts ?? []) {
    const ruleIdFamily = String(row?.rule_id_family ?? "");
    if (!ruleIdFamily.startsWith(CONSTRAINT_VIOLATION_PREFIX)) continue; // v1 scope: constraint.*-only
    if (row.granularity !== "artifact") continue; // defense-in-depth; always true for constraint.* rows

    const safeRuleIdFamily = safeRefString(ruleIdFamily);
    const safeArtifactRef = safeRefString(row.artifact_ref);
    if (!safeRuleIdFamily || !safeArtifactRef) continue; // degrade: unresolvable ref, never fabricate

    const constraint = constraintsById.get(row.artifact_ref);
    if (!constraint || constraint.status !== "active") continue; // no live mutable target

    if (row.chronically_firing === true) {
      candidates.push(buildTuningCandidate({
        kind: "retire",
        artifactRef: safeArtifactRef,
        ruleIdFamily: safeRuleIdFamily,
        granularity: row.granularity,
        current: null,
        proposed: null,
        justification: buildJustification(row, null),
        nowIso,
      }));
      continue; // retire and retune are mutually exclusive triggers for the same row
    }

    if (row.fired_count >= minRetuneFires && row.fired_count < minChronicFires) {
      const comparator = constraint.expected?.comparator;
      if (comparator === "gte" || comparator === "lte") {
        const points = factHistoryFor(factHistoryByTarget, constraint.target);
        const observedValues = replayObservedValues(points, constraint.target);
        const proposedValue = proposeRetune(comparator, observedValues, options);
        if (proposedValue !== undefined) {
          const proposedExpected = { comparator, value: proposedValue };
          const backtest = backtestRetune(observedValues, constraint.expected, proposedExpected);
          candidates.push(buildTuningCandidate({
            kind: "retune",
            artifactRef: safeArtifactRef,
            ruleIdFamily: safeRuleIdFamily,
            granularity: row.granularity,
            current: { expected: constraint.expected },
            proposed: { expected: proposedExpected },
            justification: buildJustification(row, backtest),
            nowIso,
          }));
        }
      }
    }
  }

  for (const constraint of constraints ?? []) {
    if (!constraint || constraint.status !== "shadow") continue;
    if (!checkShadowSoak(constraint, shadowRecords, { soakDays: options.soakDays, now: options.now })) continue;

    const forRef = shadowRecords.filter((record) => record?.constraint_id === constraint.id);
    const shadowFireRate = forRef.length > 0 ? forRef.filter((record) => record.fired === true).length / forRef.length : null;
    if (shadowFireRate !== 0) continue;

    const safeArtifactRef = safeRefString(constraint.id);
    const safeRuleIdFamily = safeRefString(`constraint.violation.${constraint.family ?? "unknown"}`);
    if (!safeArtifactRef || !safeRuleIdFamily) continue;

    candidates.push(buildTuningCandidate({
      kind: "promote_shadow_hint",
      artifactRef: safeArtifactRef,
      ruleIdFamily: safeRuleIdFamily,
      granularity: "artifact",
      current: null,
      proposed: null,
      justification: buildJustification({ shadow_fire_rate: shadowFireRate }, null),
      nowIso,
    }));
  }

  return candidates;
}

/**
 * Idempotent merge (plan §5.5, must-fix 5), mirrors constraint-miner.js's mergeMinedConstraints:
 * a candidate whose id is new is added as a new draft; a candidate whose id already exists AND
 * that existing record is still status:"draft" is refreshed in place (re-mining the same
 * underlying signal refreshes justification/backtest/mined_at rather than duplicating); anything
 * already review-ready/approved/rejected is left completely untouched — mining never clobbers a
 * candidate it does not own the lifecycle of. Pure, no I/O.
 */
export function mergeMinedTuningCandidates(existingCandidates, minedCandidates) {
  const byId = new Map((existingCandidates ?? []).map((candidate) => [candidate.id, candidate]));
  let newCount = 0;
  let updatedCount = 0;
  let unchangedCount = 0;

  for (const candidate of minedCandidates ?? []) {
    const existing = byId.get(candidate.id);
    if (!existing) {
      byId.set(candidate.id, candidate);
      newCount += 1;
      continue;
    }

    if (existing.status !== "draft") {
      unchangedCount += 1;
      continue;
    }

    const merged = {
      ...existing,
      current: candidate.current,
      proposed: candidate.proposed,
      justification: candidate.justification,
      mined_at: candidate.mined_at,
      backtested_at: candidate.backtested_at,
    };
    const changed = JSON.stringify(merged) !== JSON.stringify(existing);
    byId.set(candidate.id, merged);
    if (changed) updatedCount += 1;
    else unchangedCount += 1;
  }

  return {
    candidates: [...byId.values()],
    new_count: newCount,
    updated_count: updatedCount,
    unchanged_count: unchangedCount,
  };
}

/**
 * Deterministic draft -> review-ready gate (plan §5.5). `retune` candidates require a
 * big-enough backtest sample (`justification.backtest.sample_ticks >= minBacktestSamples`);
 * `retire`/`promote_shadow_hint` candidates just need their (always-present) justification
 * counts. A candidate below the bar, or any non-draft candidate, passes through unchanged
 * (idempotent no-op). Pure, no I/O.
 */
export function promoteTuningDraftsToReviewReady(candidates, options = {}) {
  const minBacktestSamples = Number.isFinite(options.minBacktestSamples) ? options.minBacktestSamples : DEFAULT_MIN_BACKTEST_SAMPLES;
  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return (candidates ?? []).map((candidate) => {
    if (!candidate || candidate.status !== "draft") return candidate;
    if (!candidate.backtested_at) return candidate;

    const eligible = candidate.kind === "retune"
      ? Number.isFinite(candidate.justification?.backtest?.sample_ticks) && candidate.justification.backtest.sample_ticks >= minBacktestSamples
      : candidate.justification != null;
    if (!eligible) return candidate;

    return {
      ...candidate,
      status: "review-ready",
      promotion_history: [
        ...(candidate.promotion_history ?? []),
        { ts, from: "draft", to: "review-ready", actor: "deterministic-gate", note: "backtest/justification threshold met" },
      ],
    };
  });
}

// --- CLI: descartes learned tuning mine | promote | list ---
// "review"/"approve"/"reject" live in tuning-authority.js (the human authority gate), mirroring
// promotion-store.js's split from constraint-miner.js/constraint-store.js.

function tuningMineUsage() {
  return `Usage:
  descartes learned tuning mine [--json] [--window <duration>]

Mines status:"draft" tuning candidates (retire/retune/promote_shadow_hint) from the calibration
report (S15) + retained fact-history + the live constraint store. constraint.*-only in v1.
Mined drafts are INERT: they never change any live threshold. Gated behind configDir/learned.json
-- disabled prints { status: "disabled" } and reads nothing else.`;
}

async function safeReadSignal(readFn, label) {
  try {
    return await readFn();
  } catch (error) {
    console.warn(`descartes: tuning mine could not read ${label} (${error?.code ?? (error instanceof Error ? error.message : String(error))}); treating it as empty`);
    return undefined;
  }
}

function renderMineSummary(minedCount, merge) {
  return `Mined ${minedCount} tuning candidate(s): ${merge.new_count} new draft(s), ${merge.updated_count} updated, ${merge.unchanged_count} unchanged.`;
}

export async function runLearnedTuningMine(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const options = { json: false, windowMs: undefined };
  for (let index = 0; index < (args ?? []).length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--window") {
      const value = args[index + 1];
      if (!value) throw new Error(`--window requires a value\n\n${tuningMineUsage()}`);
      options.windowMs = parseDurationMs(value, options.windowMs);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      output(tuningMineUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned tuning mine argument: ${arg}\n\n${tuningMineUsage()}`);
    }
  }

  const loadLearned = runtime.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadLearned(descartesPaths);
  if (!learnedConfig.enabled) {
    const disabled = { status: "disabled" };
    if (options.json) output(JSON.stringify(disabled, null, 2));
    else output("Learned emission is disabled (configDir/learned.json). Run `descartes learned enable` first.");
    return disabled;
  }

  const now = runtime.now ?? new Date().toISOString();
  const readAlerts = runtime.readAlertRecords ?? readAlertRecords;
  const readAudit = runtime.readAlertIntelligenceAudit ?? readAlertIntelligenceAudit;
  const readDelivery = runtime.readNotificationDeliveryAudit ?? readNotificationDeliveryAudit;
  const readShadow = runtime.readShadowRecords ?? readShadowRecords;
  const readIntelligenceConfig = runtime.readAlertIntelligenceConfig ?? readAlertIntelligenceConfig;
  const loadConstraintsFn = runtime.loadConstraints ?? loadConstraints;
  const readFacts = runtime.readFactPoints ?? readFactPoints;

  const [alerts, auditRecords, deliveryRecords, shadowResult, intelligenceConfig, constraintsResult, factsResult] = await Promise.all([
    safeReadSignal(() => readAlerts(descartesPaths), "alerts.json"),
    safeReadSignal(() => readAudit(descartesPaths), "llm-decisions.jsonl"),
    safeReadSignal(() => readDelivery(descartesPaths), "notification-delivery.jsonl"),
    safeReadSignal(() => readShadow(descartesPaths), "shadow-violations.jsonl"),
    safeReadSignal(() => readIntelligenceConfig(descartesPaths), "alert-intelligence.json"),
    safeReadSignal(() => loadConstraintsFn(descartesPaths), "constraints.json"),
    safeReadSignal(() => readFacts(descartesPaths, { windowMs: options.windowMs, now: runtime.now }), "facts.jsonl"),
  ]);

  const calibrationReport = computeCalibrationReport(alerts, auditRecords, deliveryRecords, shadowResult?.records, {
    now,
    enabledNamespaces: intelligenceConfig?.enabled_namespaces,
  });

  const factHistoryByTarget = buildFactHistoryByTarget(factsResult?.points);
  const mined = mineTuningCandidates(constraintsResult?.constraints, calibrationReport, factHistoryByTarget, {
    now,
    shadowRecords: shadowResult?.records,
    ...runtime.mineOptions,
  });

  const { candidates: existing } = await loadTuningCandidates(descartesPaths);
  const merge = mergeMinedTuningCandidates(existing, mined);
  await writeTuningCandidates(descartesPaths, merge.candidates);

  const summary = {
    mined_candidates: mined.length,
    new_drafts: merge.new_count,
    updated_drafts: merge.updated_count,
    unchanged_drafts: merge.unchanged_count,
  };
  if (options.json) output(JSON.stringify({ learned_tuning_mine: summary }, null, 2));
  else output(renderMineSummary(mined.length, merge));
  return summary;
}

function tuningPromoteUsage() {
  return `Usage:
  descartes learned tuning promote [--json]

Deterministic draft -> review-ready gate (no human decision yet): promotes every draft tuning
candidate whose backtest/justification clears the minimum bar (plan §5.5). Never gated behind
configDir/learned.json -- mirrors 'descartes learned soak' listing/advancing already-mined state
regardless of the enable switch.`;
}

export async function runLearnedTuningPromote(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(tuningPromoteUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned tuning promote argument: ${arg}\n\n${tuningPromoteUsage()}`);
    }
  }

  const now = runtime.now ?? Date.now();
  const { candidates: existing } = await loadTuningCandidates(descartesPaths);
  const promoted = promoteTuningDraftsToReviewReady(existing, { now, minBacktestSamples: runtime.minBacktestSamples });
  await writeTuningCandidates(descartesPaths, promoted);

  const promotedIds = promoted
    .filter((candidate, index) => candidate.status === "review-ready" && existing[index]?.status === "draft")
    .map((candidate) => candidate.id);

  const summary = { promoted_count: promotedIds.length, promoted_ids: promotedIds };
  if (json) output(JSON.stringify({ learned_tuning_promote: summary }, null, 2));
  else output(promotedIds.length === 0 ? "No draft tuning candidates cleared the review-ready bar." : `Promoted ${promotedIds.length} candidate(s) to review-ready: ${promotedIds.join(", ")}`);
  return summary;
}

function tuningListUsage() {
  return `Usage:
  descartes learned tuning list [--json]

Lists every tuning candidate (any status) for human inspection. Read-only, never gated behind
configDir/learned.json -- mirrors 'descartes learned review's own posture of listing existing
state regardless of the enable switch.`;
}

function renderCandidate(candidate) {
  const lines = [`${candidate.id} [${candidate.kind}] ${candidate.artifact_ref} status=${candidate.status}`];
  if (candidate.proposed?.expected) lines.push(`  proposed: ${JSON.stringify(candidate.proposed.expected)}`);
  if (candidate.applied) lines.push("  applied: true");
  else if (candidate.apply_note) lines.push(`  apply_note: ${candidate.apply_note}`);
  return lines.join("\n");
}

export async function runLearnedTuningList(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(tuningListUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned tuning list argument: ${arg}\n\n${tuningListUsage()}`);
    }
  }

  const { candidates } = await loadTuningCandidates(descartesPaths);
  if (json) output(JSON.stringify({ learned_tuning_list: { candidates } }, null, 2));
  else output(candidates.length === 0 ? "No tuning candidates." : candidates.map(renderCandidate).join("\n"));
  return { candidates };
}
