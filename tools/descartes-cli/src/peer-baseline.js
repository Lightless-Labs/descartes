// Slice 4b (observed-incident collectors plan) — peer-count SPIKE deviation
// (peer.count_spike).
//
// Turns Slice 3's already-shipped peer.presence fact-history into a DETERMINISTIC deviation
// alert: a statistical (windowed Welford) INCREASE in the number of currently-observed VPN/SSH
// peers — the incident's peer half (a mass, odd-hour peer-login burst appearing, not
// disappearing). NO LLM anywhere in this file. See
// docs/plans/2026-07-13-observed-incident-collectors.md, Slice 4b (Decisions 1-7) for the full,
// Fable-reviewed design this module implements exactly.
//
// Sibling to session-baseline.js (Slice 4's own template): the two modules deliberately do NOT
// share tick-grouping/store/candidate logic — only the four generic Welford/EWMA/z-score
// primitives are shared, via welford-stats.js (Decision 4). Sessions and peers have genuinely
// different marker semantics (peers have no census marker in v0 — Decision 2), different trigger
// signs (drop vs. spike), and different overflow-handling (peers SCORE-BUT-NEVER-FOLD an overflow
// tick — Fable review MUST-FIX 3 — where sessions exclude it from scoring too).
//
// This module performs NO host execFile/I/O of its own — it only reads already-persisted
// fact-history (fact-store.js) and its own small state file, exactly mirroring
// session-baseline.js's own posture.
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { PEER_OVERFLOW_ENTITY_KEY } from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS, computeZScore, emptyWelfordStats, foldWelford, updateEwma } from "./welford-stats.js";

const PEER_FACT_NAME = "peer.presence";

export const PEER_COUNT_SPIKE_RULE_ID = "peer.count_spike";

// PROVISIONAL (mirrors session-baseline.js's own must-fix-7 constants) — placeholder defaults
// chosen to unblock shipping v0, NOT tuned values; peer-count variance dynamics are a fresh,
// untuned surface. Independently named (NOT imported from session-baseline.js), even though the
// starting numeric values match Slice 4's as a reasonable default (Decision 4) — each module owns
// its own tunable floor/sigma constants so they can be retuned independently without coupling.
export const DEFAULT_PEER_DEVIATION_SIGMA = 3;
// Currently INERT (Fable review MUST-FIX 1, hard requirement): computed for observability/
// diagnostics only, never used to escalate a candidate's own stored severity — see
// buildCountSpikeCandidate below. Reserved for if/when the v0 severity cap is ever lifted
// (Slice 4c or later), alongside the nice-to-have (iv) min-absolute-spike guard.
export const DEFAULT_PEER_CRITICAL_SIGMA = 5;
export const DEFAULT_PEER_STDDEV_FLOOR = 0.5;

// Matches session-baseline.js's own DEFAULT_MIN_SAMPLE_COUNT default (S10's stated "provisional
// until 30 complete tick-groups" convention) — no peer.count_spike candidate is ever emitted
// below this count (day-1/cold-start no-storm).
export const DEFAULT_PEER_MIN_SAMPLE_COUNT = 30;

// Undramatic smoothing constant for the persisted (but not v0-trigger-consuming) ewma/
// ewma_variance fields — not part of the trigger math, so not flagged PROVISIONAL, and (mirroring
// session-baseline.js's own DEFAULT_EWMA_ALPHA) not exported.
const DEFAULT_PEER_EWMA_ALPHA = 2 / (DEFAULT_PEER_MIN_SAMPLE_COUNT + 1);

// ---------------------------------------------------------------------------------------------
// Store I/O (atomic tmp+rename 0o600, corrupt-tolerant — mirrors session-baseline.js's own
// loadSessionBaselineStore/writeSessionBaselineStore convention exactly, simpler shape: v0 has no
// churn and no partial-census counter to track).
// ---------------------------------------------------------------------------------------------

export function resolvePeerBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "peer-baseline.json") };
}

async function ensurePeerBaselineDir(descartesPaths) {
  await fs.mkdir(resolvePeerBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshPeerBaselineState() {
  return {
    version: 1,
    last_folded_ts: undefined,
    confidence_state: "provisional",
    stats: { count: 0, mean: 0, m2: 0, variance: 0, stddev: 0, ewma: undefined, ewma_variance: undefined, min: undefined, max: undefined },
    last_observation: undefined,
    skipped_overflow_tick_count: 0,
  };
}

function finiteOrDefault(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function finiteOrUndefined(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

export function normalizePeerBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const stats = base.stats && typeof base.stats === "object" && !Array.isArray(base.stats) ? base.stats : {};
  const lastObservation = base.last_observation && typeof base.last_observation === "object" && !Array.isArray(base.last_observation)
    ? {
        ts: typeof base.last_observation.ts === "string" ? base.last_observation.ts : undefined,
        count: finiteOrUndefined(base.last_observation.count),
        z_score: finiteOrUndefined(base.last_observation.z_score),
        mean_before: finiteOrUndefined(base.last_observation.mean_before),
        stddev_before: finiteOrUndefined(base.last_observation.stddev_before),
        has_overflow: Boolean(base.last_observation.has_overflow),
      }
    : undefined;

  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    confidence_state: base.confidence_state === "established" ? "established" : "provisional",
    stats: {
      count: finiteOrDefault(stats.count, 0),
      mean: finiteOrDefault(stats.mean, 0),
      m2: finiteOrDefault(stats.m2, 0),
      variance: finiteOrDefault(stats.variance, 0),
      stddev: finiteOrDefault(stats.stddev, 0),
      ewma: finiteOrUndefined(stats.ewma),
      ewma_variance: finiteOrUndefined(stats.ewma_variance),
      min: finiteOrUndefined(stats.min),
      max: finiteOrUndefined(stats.max),
    },
    last_observation: lastObservation,
    skipped_overflow_tick_count: finiteOrDefault(base.skipped_overflow_tick_count, 0),
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
 * ENOENT-tolerant (fresh state -> empty/provisional baseline) and corrupt-tolerant (mirrors
 * session-baseline.js's loadSessionBaselineStore exactly): a corrupt/malformed file yields a
 * fresh baseline rather than throwing out of a daemon tick, with `corrupt:true` surfaced to the
 * caller). The cost of a corrupt-file reset is an honest, documented cold-start (30 real samples
 * before "established" again) — never a crashed tick.
 */
export async function loadPeerBaselineStore(descartesPaths) {
  const { storeFile } = resolvePeerBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: freshPeerBaselineState(), corrupt: false };
  if (corrupt) return { state: freshPeerBaselineState(), corrupt: true };
  return { state: normalizePeerBaselineState(parsed), corrupt: false };
}

export async function writePeerBaselineStore(descartesPaths, state) {
  await ensurePeerBaselineDir(descartesPaths);
  const { storeFile } = resolvePeerBaselineStorePaths(descartesPaths);
  const normalized = normalizePeerBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

// ---------------------------------------------------------------------------------------------
// Tick-grouping (Decision 1): "one observation" = the count of peer.presence fact points sharing
// one tick's `ts`, RESTRICTED to points whose attributes.presence_state === "observed_active"
// (excluding PEER_OVERFLOW_ENTITY_KEY). observed_historical is deliberately excluded from the
// count (Decision 1's "why observed_active-only" reasoning: bounded `last -n N` saturates in
// count once the window is full, which would make the count numb to exactly the burst this
// signal exists to catch) — but an observed_historical-only tick-group still creates a
// tick-group, which folds as a real, complete ZERO-count observation (Fable review MUST-FIX 2),
// never skipped.
// ---------------------------------------------------------------------------------------------

/**
 * Groups peer.presence fact points by their shared `ts` (one structural tick = one shared ts
 * string, confirmed against daemon.js's runDaemonIteration: `sessions` and `vpn-peer-status` are
 * registered back-to-back in collectStructuralEvidence's activeCollectors map, so every peer
 * fact emitted in one daemon iteration shares the identical `ts` as every session fact from that
 * same iteration). Returns tick-groups ORDERED ascending by ts, each `{ ts, count, hasOverflow }`:
 *   - `count` is the number of NON-overflow peer.presence points in this tick-group whose
 *     attributes.presence_state is NOT "observed_historical" — i.e. every point that is
 *     "observed_active" OR carries an unrecognized/missing presence_state (matching
 *     fact-translators.js's buildPeerFactPoint ternary default exactly — nice-to-have (i)).
 *   - `hasOverflow` is true iff this tick-group carries the PEER_OVERFLOW_ENTITY_KEY marker.
 * A tick-group exists whenever ANY peer.presence point (active OR historical) shares that ts —
 * an all-historical tick-group still produces a `{count: 0, hasOverflow: false}` group, per
 * Decision 1/MUST-FIX 2's documented "real zero, not skipped" semantics.
 */
export function groupPeerFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || point.fact_name !== PEER_FACT_NAME || typeof point.ts !== "string") continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, count: 0, hasOverflow: false });
    }
    const group = byTs.get(point.ts);
    if (point.entity_key === PEER_OVERFLOW_ENTITY_KEY) {
      group.hasOverflow = true;
      continue;
    }
    if (point.attributes?.presence_state !== "observed_historical") {
      group.count += 1;
    }
  }
  return [...byTs.values()].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}

/**
 * Disposition of a tick-group (v0 has only two — peers carry no census marker, so there is no
 * "partial"/"markerless" concept here, unlike session-baseline.js's tickGroupDisposition):
 *   - "overflow": PEER_OVERFLOW_ENTITY_KEY-marked — its true count is only bucketed, never exact.
 *   - "complete": every other tick-group, including a genuine (or false, per MUST-FIX 2) zero.
 */
function tickGroupDisposition(group) {
  return group.hasOverflow ? "overflow" : "complete";
}

/**
 * Fable review MUST-FIX 3 (hard requirement) — SCORE-BUT-NEVER-FOLD, the deliberate divergence
 * from session-baseline.js's computeWindowedSessionStats: an overflow tick-group is still
 * EXCLUDED from the persisted mean/variance/EWMA recompute (an inexact, bucketed count must never
 * distort the baseline) — but if that overflow tick-group is the single MOST RECENT tick-group,
 * it is still SCORED: `last_observation.z_score` is computed at its own (capped) count against
 * the window statistics as they stood BEFORE that tick (i.e. folded from every earlier complete
 * tick-group only). This is conservative/fabrication-free for a SPIKE detector specifically — a
 * truncated peer count is a lower bound on the true count (peers are only ever cut off the list
 * at the cap, never fabricated above it) — so scoring it can only ever make peer.count_spike fire
 * on a burst that is at least as large as reported, never larger. Contrast with
 * session-baseline.js's session.count_drop, which additionally excludes an overflow tick from
 * SCORING too (correct for a drop: a capped/truncated count sits far from zero and scoring it
 * would not help detect, and could even mask, a genuine drop).
 *
 * Folding otherwise mirrors computeWindowedSessionStats verbatim: the accumulator recomputes
 * fresh over every complete tick-group inside the window on every call, never an incrementally-
 * accumulated running total.
 */
export function computeWindowedPeerStats(groups, { stddevFloor = DEFAULT_PEER_STDDEV_FLOOR, ewmaAlpha = DEFAULT_PEER_EWMA_ALPHA, minSampleCount = DEFAULT_PEER_MIN_SAMPLE_COUNT } = {}) {
  const completeGroups = groups.filter((group) => tickGroupDisposition(group) === "complete");
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const mostRecentIsOverflow = mostRecentGroup ? tickGroupDisposition(mostRecentGroup) === "overflow" : false;

  // The most recent COMPLETE tick-group, if the tail of `groups` is itself complete, is also the
  // tail of `completeGroups` (filtering preserves order and cannot re-order past the tail).
  // Excluding it here gives the "pre-overflow"/pre-latest-observation window stats used to score
  // lastObservation below, whether the tail is complete (excluded so it can score against a
  // window that doesn't already include itself — self-dampening avoidance) or overflow (already
  // absent from completeGroups, so nothing further to exclude).
  const preScoreGroups = (mostRecentGroup && !mostRecentIsOverflow) ? completeGroups.slice(0, -1) : completeGroups;

  let preScoreStats = emptyWelfordStats();
  let preScoreEwma = { ewma: undefined, ewma_variance: undefined };
  for (const group of preScoreGroups) {
    preScoreStats = foldWelford(preScoreStats, group.count);
    preScoreEwma = updateEwma(preScoreEwma, group.count, ewmaAlpha);
  }

  let lastObservation;
  if (mostRecentGroup) {
    const zScore = computeZScore(mostRecentGroup.count, preScoreStats.mean, preScoreStats.stddev, stddevFloor);
    lastObservation = {
      ts: mostRecentGroup.ts,
      count: mostRecentGroup.count,
      z_score: zScore,
      mean_before: preScoreStats.mean,
      stddev_before: preScoreStats.stddev,
      has_overflow: mostRecentIsOverflow,
    };
  }

  // Persisted stats: preScoreStats PLUS the most recent tick-group itself, but ONLY if it is
  // "complete" — an overflow tick-group is NEVER folded into the persisted baseline, regardless
  // of whether it was just scored above (score-but-never-fold).
  let stats = preScoreStats;
  let ewmaState = preScoreEwma;
  if (mostRecentGroup && !mostRecentIsOverflow) {
    stats = foldWelford(stats, mostRecentGroup.count);
    ewmaState = updateEwma(ewmaState, mostRecentGroup.count, ewmaAlpha);
  }

  const confidence_state = stats.count >= minSampleCount ? "established" : "provisional";
  return {
    stats: { ...stats, ewma: ewmaState.ewma, ewma_variance: ewmaState.ewma_variance },
    confidence_state,
    last_observation: lastObservation,
  };
}

// ---------------------------------------------------------------------------------------------
// Candidate builder (Decision 4/5) — mirrors buildCountDropCandidate's shape exactly, sign
// flipped, severity capped.
// ---------------------------------------------------------------------------------------------

/**
 * Fires peer.count_spike when confidence_state === "established" AND z >= +deviationSigma AND
 * observed_count > mean_before (defense-in-depth, redundant given a positive z — same posture as
 * session-baseline.js's own drop-side guard).
 *
 * Fable review MUST-FIX 1 (hard requirement): stored severity is capped at "warning"
 * UNCONDITIONALLY in v0 — it NEVER escalates to "critical", regardless of z magnitude. A chronic
 * source-degradation-then-recovery sequence (e.g. `wg` permission-denied for 30+ ticks, then
 * recovering) can produce a false "warning"-tier spike; the cap keeps that accepted, bounded
 * false-positive class from ever consuming the shared critical-severity budget lane.
 * `DEFAULT_PEER_CRITICAL_SIGMA` is exported but INERT in v0: this function does not accept a
 * `criticalSigma` option and never reads it — severity is the hardcoded "warning" below. The
 * constant exists only as a named placeholder for a future critical tier, to be tuned alongside the
 * other PROVISIONAL constants (and gated behind a min-absolute-spike guard) if v0's data warrants.
 */
export function buildCountSpikeCandidate(state, { deviationSigma = DEFAULT_PEER_DEVIATION_SIGMA } = {}) {
  if (state?.confidence_state !== "established") return undefined;
  const obs = state.last_observation;
  if (!obs || !Number.isFinite(obs.z_score) || !Number.isFinite(obs.mean_before)) return undefined;
  if (!(obs.z_score >= deviationSigma)) return undefined;
  if (!(obs.count > obs.mean_before)) return undefined; // defense-in-depth guard, redundant given a positive z

  const diagnostics = sanitizeDiagnostics({
    observed_count: obs.count,
    mean_before: obs.mean_before,
    stddev_before: obs.stddev_before,
    z_score: obs.z_score,
    confidence_state: state.confidence_state,
  });
  return {
    id: alertId(PEER_COUNT_SPIKE_RULE_ID, "global"),
    rule_id: PEER_COUNT_SPIKE_RULE_ID,
    fingerprint: "global",
    // MUST-FIX 1: capped at "warning" unconditionally — never "critical" in v0.
    severity: "warning",
    title: "Peer count deviation",
    summary: "Currently-observed VPN/SSH peer count deviated significantly above its established baseline.",
    diagnostics,
    evidence_refs: ["peer-baseline"],
  };
}

// ---------------------------------------------------------------------------------------------
// Fast-tick side — the daemon.js extraCandidates entry.
// ---------------------------------------------------------------------------------------------

/**
 * Matches computeSessionBaselineCandidates' exact signature/short-circuit shape: gated by the
 * same loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O. Called on every daemon
 * tick, not just on a structural-due tick — an already-collected fact must be able to fire (or
 * keep firing / recover) an alert without waiting for the next hourly structural collection.
 *
 * readFactPoints is intentionally NOT skipped on fast ticks (the windowed stats recompute needs
 * to check whether a new tick-group has landed) — only the peer-baseline.json STORE WRITE is
 * skipped on ticks that find zero new tick-groups since state.last_folded_ts, so a fast tick
 * between hourly structural collections performs no disk write and leaves the persisted state
 * untouched.
 */
export async function computePeerBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const minSampleCount = options.minSampleCount ?? DEFAULT_PEER_MIN_SAMPLE_COUNT;
  const stddevFloor = options.stddevFloor ?? DEFAULT_PEER_STDDEV_FLOOR;
  const deviationSigma = options.deviationSigma ?? DEFAULT_PEER_DEVIATION_SIGMA;
  const ewmaAlpha = options.ewmaAlpha ?? DEFAULT_PEER_EWMA_ALPHA;
  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;

  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupPeerFactsByTick(points);

  const loadStore = options.loadPeerBaselineStore ?? loadPeerBaselineStore;
  const { state: persistedState } = await loadStore(descartesPaths);

  const lastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const newGroups = groups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  const windowed = computeWindowedPeerStats(groups, { stddevFloor, ewmaAlpha, minSampleCount });

  if (newGroups.length > 0) {
    let skippedOverflow = persistedState.skipped_overflow_tick_count;
    let lastFoldedTs = persistedState.last_folded_ts;
    for (const group of newGroups) {
      lastFoldedTs = group.ts;
      if (tickGroupDisposition(group) === "overflow") skippedOverflow += 1;
    }
    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      confidence_state: windowed.confidence_state,
      stats: windowed.stats,
      last_observation: windowed.last_observation,
      skipped_overflow_tick_count: skippedOverflow,
    };
    const writeStore = options.writePeerBaselineStore ?? writePeerBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  // Re-emission every tick (load-bearing, mirrors session-baseline.js's own Decision 3): built
  // fresh from `windowed` on EVERY call — including ticks where nothing new was folded — so
  // applyAlertCandidates never spuriously "recovers" an active peer.count_spike just because this
  // source skipped a redundant write.
  const candidate = buildCountSpikeCandidate(
    { confidence_state: windowed.confidence_state, last_observation: windowed.last_observation },
    { deviationSigma },
  );
  return candidate ? [candidate] : [];
}
