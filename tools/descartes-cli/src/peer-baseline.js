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
import { PEER_CENSUS_MARKER_ENTITY_KEY, PEER_OVERFLOW_ENTITY_KEY } from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS, computeZScore, emptyWelfordStats, foldWelford, updateEwma } from "./welford-stats.js";

const PEER_FACT_NAME = "peer.presence";

// Stage 2 adversarial-review fix (2026-07-23): the shape of a WELL-FORMED availability_signature,
// mirroring fact-translators.js's own buildPeerAvailabilitySignature output exactly -- "v1:" plus
// exactly 5 hyphen-joined codes drawn from its closed CLOSED_PEER_SOURCE_STATUS_VALUES set (plus
// "unknown", that same module's own catch-all fallback for anything outside that set). Defined
// independently here (not imported) -- this module only needs to RECOGNIZE the shape
// buildPeerAvailabilitySignature produces, not reconstruct it. A string that merely passes
// `typeof === "string"` but does NOT match this pattern (garbled facts.jsonl content, a bit-flip,
// a future/incompatible marker producer) is NOT a legitimate regime key -- see
// groupPeerFactsByTick's own use of this pattern below for why a type-only guard is insufficient.
const PEER_AVAILABILITY_SOURCE_CODE = "(?:ok|partial|absent|missing_permission|unable|not_applicable|unknown)";
const PEER_AVAILABILITY_SIGNATURE_PATTERN = new RegExp(`^v1:${PEER_AVAILABILITY_SOURCE_CODE}(?:-${PEER_AVAILABILITY_SOURCE_CODE}){4}$`);

export const PEER_COUNT_SPIKE_RULE_ID = "peer.count_spike";
// Slice 4c (observed-incident collectors plan) — the sign-flipped mirror of PEER_COUNT_SPIKE_RULE_ID.
export const PEER_COUNT_DROP_RULE_ID = "peer.count_drop";

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

function freshWelfordStatsShape() {
  return { count: 0, mean: 0, m2: 0, variance: 0, stddev: 0, ewma: undefined, ewma_variance: undefined, min: undefined, max: undefined };
}

// Slice 4c: nested sibling state for the drop direction, plus the current regime key and its own
// skipped-tick counter (§2e).
function freshPeerDropState() {
  return {
    confidence_state: "provisional",
    stats: freshWelfordStatsShape(),
    last_observation: undefined,
  };
}

function freshPeerBaselineState() {
  return {
    version: 1,
    last_folded_ts: undefined,
    confidence_state: "provisional",
    stats: freshWelfordStatsShape(),
    last_observation: undefined,
    skipped_overflow_tick_count: 0,
    availability_signature: undefined,
    drop: freshPeerDropState(),
    skipped_markerless_tick_count: 0,
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

function normalizeStatsShape(rawStats) {
  const stats = rawStats && typeof rawStats === "object" && !Array.isArray(rawStats) ? rawStats : {};
  return {
    count: finiteOrDefault(stats.count, 0),
    mean: finiteOrDefault(stats.mean, 0),
    m2: finiteOrDefault(stats.m2, 0),
    variance: finiteOrDefault(stats.variance, 0),
    stddev: finiteOrDefault(stats.stddev, 0),
    ewma: finiteOrUndefined(stats.ewma),
    ewma_variance: finiteOrUndefined(stats.ewma_variance),
    min: finiteOrUndefined(stats.min),
    max: finiteOrUndefined(stats.max),
  };
}

function normalizeLastObservationShape(rawLastObservation) {
  if (!rawLastObservation || typeof rawLastObservation !== "object" || Array.isArray(rawLastObservation)) return undefined;
  return {
    ts: typeof rawLastObservation.ts === "string" ? rawLastObservation.ts : undefined,
    count: finiteOrUndefined(rawLastObservation.count),
    z_score: finiteOrUndefined(rawLastObservation.z_score),
    mean_before: finiteOrUndefined(rawLastObservation.mean_before),
    stddev_before: finiteOrUndefined(rawLastObservation.stddev_before),
    has_overflow: Boolean(rawLastObservation.has_overflow),
  };
}

// Slice 4c (§2e): corrupt/missing-tolerant normalization for the nested `drop` sibling state --
// same discipline as every other field in this function: a missing/malformed `drop` object
// degrades to a fresh nested state rather than throwing or propagating a malformed shape.
function normalizePeerDropState(rawDrop) {
  const drop = rawDrop && typeof rawDrop === "object" && !Array.isArray(rawDrop) ? rawDrop : {};
  return {
    confidence_state: drop.confidence_state === "established" ? "established" : "provisional",
    stats: normalizeStatsShape(drop.stats),
    last_observation: normalizeLastObservationShape(drop.last_observation),
  };
}

export function normalizePeerBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};

  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    confidence_state: base.confidence_state === "established" ? "established" : "provisional",
    stats: normalizeStatsShape(base.stats),
    last_observation: normalizeLastObservationShape(base.last_observation),
    skipped_overflow_tick_count: finiteOrDefault(base.skipped_overflow_tick_count, 0),
    // Slice 4c additions (§2e): the CURRENT regime key (top-level, observability-only) and the
    // drop-direction nested sibling state. A non-string availability_signature (corrupt/malformed
    // persisted value) coerces to undefined -- the same markerless/undefined sentinel used
    // throughout this slice (§2a) -- never a fabricated regime string.
    availability_signature: typeof base.availability_signature === "string" ? base.availability_signature : undefined,
    drop: normalizePeerDropState(base.drop),
    skipped_markerless_tick_count: finiteOrDefault(base.skipped_markerless_tick_count, 0),
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
 * same iteration). Returns tick-groups ORDERED ascending by ts, each
 * `{ ts, count, hasOverflow, availabilitySignature }`:
 *   - `count` is the number of NON-overflow, non-marker peer.presence points in this tick-group
 *     whose attributes.presence_state is NOT "observed_historical" — i.e. every point that is
 *     "observed_active" OR carries an unrecognized/missing presence_state (matching
 *     fact-translators.js's buildPeerFactPoint ternary default exactly — nice-to-have (i)).
 *   - `hasOverflow` is true iff this tick-group carries the PEER_OVERFLOW_ENTITY_KEY marker.
 *   - `availabilitySignature` (Slice 4c) is the string carried by this tick-group's
 *     PEER_CENSUS_MARKER_ENTITY_KEY point's `attributes.availability_signature`, or `undefined`
 *     when no such marker is present in this tick-group (pre-Slice-4c/legacy fact-history) OR
 *     when a marker IS present but its `availability_signature` attribute is malformed/missing
 *     (non-string, OR a string that does not match PEER_AVAILABILITY_SIGNATURE_PATTERN's exact
 *     "v1:<5 closed-enum codes>" shape — e.g. a garbled/corrupted-but-still-parseable value) —
 *     all such cases collapse to the identical `undefined` sentinel (Decision 6, §2a; shape
 *     validation added in the Stage 2 adversarial-review fix, 2026-07-23), never a fabricated
 *     regime string.
 * A tick-group exists whenever ANY peer.presence point (active OR historical) shares that ts —
 * an all-historical tick-group still produces a `{count: 0, hasOverflow: false}` group, per
 * Decision 1/MUST-FIX 2's documented "real zero, not skipped" semantics.
 */
export function groupPeerFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || point.fact_name !== PEER_FACT_NAME || typeof point.ts !== "string") continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, count: 0, hasOverflow: false, availabilitySignature: undefined });
    }
    const group = byTs.get(point.ts);
    if (point.entity_key === PEER_OVERFLOW_ENTITY_KEY) {
      group.hasOverflow = true;
      continue;
    }
    if (point.entity_key === PEER_CENSUS_MARKER_ENTITY_KEY) {
      // Sentinel unification (Stage 1 review must-fix, 2026-07-23): a non-string OR a
      // string-but-not-shaped-like-a-real-signature availability_signature attribute
      // (malformed/corrupt fact point, e.g. disk corruption of facts.jsonl that leaves the JSON
      // line still parseable, or a future/incompatible marker producer) coerces to `undefined`,
      // the exact same value a tick-group that never saw a marker point at all already produces
      // (the "markerless" disposition, §2b/§2c) — see this module's own header comment and the
      // plan's §2a rationale for why this is the stricter, fail-toward-silence choice. Stage 2
      // adversarial-review fix (2026-07-23): a TYPE-ONLY guard is insufficient here -- a garbled
      // string is still a string, and would otherwise be trusted verbatim as a poolable regime key
      // (degrade-not-fabricate violation) -- so the value must additionally match
      // PEER_AVAILABILITY_SIGNATURE_PATTERN, the exact closed-enum shape
      // buildPeerAvailabilitySignature produces.
      const rawSignature = point.attributes?.availability_signature;
      group.availabilitySignature =
        typeof rawSignature === "string" && PEER_AVAILABILITY_SIGNATURE_PATTERN.test(rawSignature) ? rawSignature : undefined;
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

// Slice 4c (§2b): deliberately NOT unified with tickGroupDisposition above. Extending that
// function to a 3-way disposition would permanently exclude every marker-less (pre-Slice-4c)
// tick-group from peer.count_spike's own fold forever, resetting every live, already-shipped
// peer.count_spike baseline to "provisional" on upgrade — an unacceptable, unrequested regression
// to an unrelated-to-this-slice detector. This new function is peer.count_drop-only.
//
// peer.count_drop-only disposition (Decision 0.1: mirrors session.count_drop's own STRICTER
// exclude-from-scoring-AND-folding posture for overflow, transplanted from session-baseline.js's
// tickGroupDisposition); "markerless" additionally excludes any pre-Slice-4c tick-group, exactly
// mirroring session.count_drop's own must-fix-1/2 "an honest ~30-sample re-warm-up, never
// fabricated" pattern -- a marker-less peer.presence tick-group carries the identical "real zero
// vs. never observed" ambiguity Slice 1's own addendum was built to close for sessions, now
// closed for peers by THIS marker. Keyed on the marker's presence, not a partial/complete
// boolean: peers have no binary partial-census concept -- degradation is captured entirely by the
// signature's own content, which is what the regime key (§2c) exists for.
function dropTickGroupDisposition(group) {
  if (group.hasOverflow) return "overflow";
  if (group.availabilitySignature === undefined) return "markerless";
  return "complete";
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
 *
 * Slice 4c regime-keyed fold (Decision 2(c), retroactive fix for peer.count_spike's own accepted
 * false-positive class named in the Slice 4b plan): `completeGroups` gains a second predicate --
 * only tick-groups whose availability signature matches the CURRENT (most recent) tick's own
 * signature are eligible to fold. Chronic degradation now establishes its own baseline WITHIN its
 * own regime; a recovery flips the regime and triggers an honest re-warm-up (empty completeGroups
 * for the new signature until minSampleCount is met again) instead of scoring a recovery-driven
 * jump against a stale, differently-conditioned baseline. Backward compatibility: a fully
 * marker-less window (every group's availabilitySignature is undefined, including the most
 * recent) is a true no-op (`undefined === undefined`) -- see this module's own test file for the
 * one-time, self-healing post-upgrade reset this filter accepts for a live, already-marker-less
 * baseline (§2c of the plan).
 */
export function computeWindowedPeerStats(groups, { stddevFloor = DEFAULT_PEER_STDDEV_FLOOR, ewmaAlpha = DEFAULT_PEER_EWMA_ALPHA, minSampleCount = DEFAULT_PEER_MIN_SAMPLE_COUNT } = {}) {
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const currentSignature = mostRecentGroup?.availabilitySignature;
  const completeGroups = groups.filter(
    (group) => tickGroupDisposition(group) === "complete" && group.availabilitySignature === currentSignature,
  );
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
// Slice 4c — peer.count_drop's own windowed fold. NOT a parameterized variant of
// computeWindowedPeerStats above (their overflow-handling policies diverge: score-but-never-fold
// for spike vs. exclude-from-both for drop -- Decision 0.1); mirrors session-baseline.js's
// computeWindowedSessionStats fold+score-at-tail shape verbatim, plus the SAME regime filter as
// computeWindowedPeerStats above, keyed on dropTickGroupDisposition instead of
// tickGroupDisposition.
//
// Note on when peer.count_drop can first activate: if the current (most recent) tick-group is
// itself "markerless" (pre-Slice-4c or transitional), `eligibleGroups` is ALWAYS empty (a
// "markerless" group can never also be "complete"), so confidence_state stays "provisional" and
// no candidate is ever emitted -- an honest, unavoidable cold-start gate exactly matching
// session.count_drop's own pre-Slice-1-addendum era. peer.count_drop simply cannot fire until the
// census marker has been live and accumulating for DEFAULT_PEER_MIN_SAMPLE_COUNT same-signature
// ticks. This is intended, not a bug to route around.
// ---------------------------------------------------------------------------------------------
export function computeWindowedPeerDropStats(groups, { stddevFloor = DEFAULT_PEER_STDDEV_FLOOR, ewmaAlpha = DEFAULT_PEER_EWMA_ALPHA, minSampleCount = DEFAULT_PEER_MIN_SAMPLE_COUNT } = {}) {
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const currentSignature = mostRecentGroup?.availabilitySignature;
  const mostRecentIsOverflow = mostRecentGroup ? dropTickGroupDisposition(mostRecentGroup) === "overflow" : false;

  const eligibleGroups = groups.filter(
    (group) => dropTickGroupDisposition(group) === "complete" && group.availabilitySignature === currentSignature,
  );

  let stats = emptyWelfordStats();
  let ewmaState = { ewma: undefined, ewma_variance: undefined };
  let lastObservation;

  eligibleGroups.forEach((group, index) => {
    if (index === eligibleGroups.length - 1) {
      const zScore = computeZScore(group.count, stats.mean, stats.stddev, stddevFloor);
      lastObservation = {
        ts: group.ts,
        count: group.count,
        z_score: zScore,
        mean_before: stats.mean,
        stddev_before: stats.stddev,
        has_overflow: mostRecentIsOverflow, // purely observational, mirrors session-baseline.js's own nice-to-have (ii)
      };
    }
    stats = foldWelford(stats, group.count);
    ewmaState = updateEwma(ewmaState, group.count, ewmaAlpha);
  });

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

/**
 * Slice 4c — fires peer.count_drop when confidence_state === "established" AND
 * z <= -deviationSigma AND observed_count < mean_before (defense-in-depth, redundant given a
 * negative z — same posture as buildCountSpikeCandidate's own positive-z guard above and
 * session-baseline.js's own drop-side guard).
 *
 * Decision 0 (plan pinned), mirrors peer.count_spike's own MUST-FIX-1 cap: stored severity is
 * HARDCODED "warning" -- it never escalates to "critical" in v0, regardless of z magnitude. Peer-
 * count variance dynamics remain an untuned PROVISIONAL surface for BOTH directions; no new
 * INERT critical-tier constant is added for the drop direction (Decision 5) -- the existing
 * DEFAULT_PEER_CRITICAL_SIGMA (already inert for peer.count_spike) is reused as the same
 * future-facing placeholder here too.
 */
export function buildCountDropCandidate(state, { deviationSigma = DEFAULT_PEER_DEVIATION_SIGMA } = {}) {
  if (state?.confidence_state !== "established") return undefined;
  const obs = state.last_observation;
  if (!obs || !Number.isFinite(obs.z_score) || !Number.isFinite(obs.mean_before)) return undefined;
  if (!(obs.z_score <= -deviationSigma)) return undefined;
  if (!(obs.count < obs.mean_before)) return undefined; // defense-in-depth guard, redundant given a negative z

  const diagnostics = sanitizeDiagnostics({
    observed_count: obs.count,
    mean_before: obs.mean_before,
    stddev_before: obs.stddev_before,
    z_score: obs.z_score,
    confidence_state: state.confidence_state,
  });
  return {
    id: alertId(PEER_COUNT_DROP_RULE_ID, "global"),
    rule_id: PEER_COUNT_DROP_RULE_ID,
    fingerprint: "global",
    // Decision 0 (plan pinned), mirrors peer.count_spike's own MUST-FIX-1 cap: severity is
    // HARDCODED "warning" -- never escalates to "critical" in v0, regardless of z magnitude.
    // Peer-count variance dynamics remain an untuned PROVISIONAL surface for BOTH directions.
    severity: "warning",
    title: "Peer count drop",
    summary: "Currently-observed VPN/SSH peer count dropped significantly below its established (regime-matched) baseline.",
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
  // Slice 4c: the drop-direction windowed fold, computed alongside (not instead of) `windowed`
  // above -- SHARED tick-grouping (`groups`), independent Welford accumulators/dispositions.
  const windowedDrop = computeWindowedPeerDropStats(groups, { stddevFloor, ewmaAlpha, minSampleCount });

  if (newGroups.length > 0) {
    let skippedOverflow = persistedState.skipped_overflow_tick_count;
    let skippedMarkerless = persistedState.skipped_markerless_tick_count; // Slice 4c
    let lastFoldedTs = persistedState.last_folded_ts;
    for (const group of newGroups) {
      lastFoldedTs = group.ts;
      if (tickGroupDisposition(group) === "overflow") skippedOverflow += 1;
      if (dropTickGroupDisposition(group) === "markerless") skippedMarkerless += 1; // Slice 4c, independent counter
    }
    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      confidence_state: windowed.confidence_state,
      stats: windowed.stats,
      last_observation: windowed.last_observation,
      skipped_overflow_tick_count: skippedOverflow,
      // Slice 4c additions: the CURRENT regime key (top-level, observability-only) and the
      // drop-direction nested sibling state.
      availability_signature: groups.length > 0 ? groups[groups.length - 1].availabilitySignature : undefined,
      drop: {
        confidence_state: windowedDrop.confidence_state,
        stats: windowedDrop.stats,
        last_observation: windowedDrop.last_observation,
      },
      skipped_markerless_tick_count: skippedMarkerless,
    };
    const writeStore = options.writePeerBaselineStore ?? writePeerBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  // Re-emission every tick (load-bearing, mirrors session-baseline.js's own Decision 3): built
  // fresh from `windowed`/`windowedDrop` on EVERY call — including ticks where nothing new was
  // folded — so applyAlertCandidates never spuriously "recovers" an active peer.count_spike/
  // peer.count_drop just because this source skipped a redundant write.
  const candidates = [];
  const spikeCandidate = buildCountSpikeCandidate(
    { confidence_state: windowed.confidence_state, last_observation: windowed.last_observation },
    { deviationSigma },
  );
  if (spikeCandidate) candidates.push(spikeCandidate);
  const dropCandidate = buildCountDropCandidate(
    { confidence_state: windowedDrop.confidence_state, last_observation: windowedDrop.last_observation },
    { deviationSigma },
  );
  if (dropCandidate) candidates.push(dropCandidate);
  return candidates;
}
