// Slice 4 (observed-incident collectors plan) — Layer C session-count anomaly signature.
//
// Turns Slice 1's already-shipped session.presence fact-history into DETERMINISTIC deviation
// alerts: a statistical (Welford) drop in resident session count (session.count_drop), and a
// deterministic fingerprint-diff churn signal (session.churn) that catches a same-tick
// kill-then-resurrect count alone cannot see. NO LLM anywhere in this file. See
// docs/plans/2026-07-13-observed-incident-collectors.md, Slice 4 (Decisions 1-6) for the full,
// Fable-reviewed design this module implements exactly.
//
// Sibling to constraint-eval.js (plan Decision 4): this module performs NO host execFile/I/O of
// its own — it only reads already-persisted fact-history (fact-store.js) and its own small state
// file, exactly mirroring provenance-warnings.js's fast-tick side
// (computeProvenanceWarningCandidates).
//
// Implementation note on "re-derives fresh from state every call" (Decision 3): rather than
// re-reading the persisted session-baseline.json state to build the candidate, this module
// recomputes the windowed Welford/EWMA stats AND the candidate-relevant last_observation
// (mean_before/stddev_before/z_score) directly, in-memory, from the SAME already-read
// fact-history window on every single call (computeWindowedSessionStats). The persisted store is
// still written (mirroring that exact recomputation) whenever a new tick-group has landed, purely
// for cheap cross-process observability/display (`descartes learned`-style tooling) and the
// last_folded_ts / skipped-tick counters, which — unlike the Welford stats — genuinely are
// cumulative bookkeeping, not re-derivable from the current window alone. This sidesteps any
// disk-round-trip/timing desync between "what got written" and "what the candidate reflects" while
// still satisfying every must-fix's observable behavior (byte-identical repeated calls, re-emission
// every tick, at-most-one write per batch of unchanged history).
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { SESSION_CENSUS_MARKER_ENTITY_KEY, SESSION_OVERFLOW_ENTITY_KEY } from "./fact-translators.js";
// Slice 4b (observed-incident collectors plan), Decision 4 / Fable review MUST-FIX 5: the four
// pure Welford/EWMA/z-score primitives + DEFAULT_BASELINE_FACT_WINDOW_MS were extracted into
// welford-stats.js so peer-baseline.js can share the exact same, single-sourced math without a
// session -> peer (or peer -> session) dependency in either direction. This MUST be an
// import-then-re-export, NOT a bare `export {...} from "./welford-stats.js"` re-export-only
// clause: a bare re-export-only clause does NOT bind these names in THIS module's own scope, but
// computeWindowedSessionStats below calls emptyWelfordStats()/foldWelford()/updateEwma()/
// computeZScore() as bare, locally-resolved identifiers — under a bare re-export none of those
// names would be bound, and the very first call to computeWindowedSessionStats (the very first
// daemon tick) would throw a ReferenceError. The import below creates the local bindings this
// module's own internal calls need; the separate export statement re-exports the same names for
// session-baseline.test.js's existing name-imports and incident-correlation.js's/
// incident-correlation.test.js's DEFAULT_BASELINE_FACT_WINDOW_MS import — zero existing import
// breaks, both true simultaneously.
import { emptyWelfordStats, foldWelford, updateEwma, computeZScore, DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";
export { emptyWelfordStats, foldWelford, updateEwma, computeZScore, DEFAULT_BASELINE_FACT_WINDOW_MS };

// Re-exported for convenience (plan Decision 6): consumers of this module's tick-grouping should
// not need to reach into fact-translators.js directly for the marker literal.
export { SESSION_CENSUS_MARKER_ENTITY_KEY };

const SESSION_FACT_NAME = "session.presence";

export const SESSION_COUNT_DROP_RULE_ID = "session.count_drop";
export const SESSION_CHURN_RULE_ID = "session.churn";

// Decision 2b / must-fix 3: the CLOSED allowlist of rule_ids the deterministic, non-LLM local
// delivery branch (alert-intelligence.js's emitSessionAlertSignals) is scoped to. Importing these
// two constants (rather than restating the string literals there) keeps the allowlist unable to
// silently drift from the rule_ids this module actually emits.
export const DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS = [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID];

// PROVISIONAL (must-fix 7, Fable review 2026-07-14) — placeholder defaults chosen to unblock
// shipping v0, NOT tuned values. Low-variance severity-inflation risk, stated concretely in the
// plan: with a steady baseline whose stddev sits at/near STDDEV_FLOOR, the absolute trigger is
// DEVIATION_SIGMA * STDDEV_FLOOR sessions (1.5 by these defaults) and the critical tier is
// CRITICAL_SIGMA * STDDEV_FLOOR (2.5) — so a host that has stably run 5 sessions for weeks could
// see a routine 3-session end-of-day cleanup cross z <= -5 and fire CRITICAL. Tune after real data;
// a min-absolute-drop/fraction-of-mean guard on the CRITICAL tier is recorded as a nice-to-have,
// not required for v0.
export const DEFAULT_DEVIATION_SIGMA = 3;
export const DEFAULT_CRITICAL_SIGMA = 5;
export const DEFAULT_STDDEV_FLOOR = 0.5;

// Matches the parent roadmap's stated S10 default (docs/plans/2026-07-09-self-learning-stratified-
// monitoring.md:77/138/176) — "provisional" until this many complete tick-groups are inside the
// window; established.js: no session.count_drop candidate is ever emitted below this count.
export const DEFAULT_MIN_SAMPLE_COUNT = 30;

// A reasonable, undramatic smoothing constant for the persisted (but not v0-trigger-consuming,
// see Decision 3's "EWMA's role, scoped explicitly") ewma/ewma_variance fields — not part of the
// trigger math, so not flagged PROVISIONAL alongside the three sigma/floor constants above.
const DEFAULT_EWMA_ALPHA = 2 / (DEFAULT_MIN_SAMPLE_COUNT + 1);

// ---------------------------------------------------------------------------------------------
// Store I/O (atomic tmp+rename 0o600, corrupt-tolerant — mirrors provenance-store.js's
// loadSignatureStore/writeSignatureStore convention exactly).
// ---------------------------------------------------------------------------------------------

export function resolveSessionBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "session-baseline.json") };
}

async function ensureSessionBaselineDir(descartesPaths) {
  await fs.mkdir(resolveSessionBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshSessionBaselineState() {
  return {
    version: 1,
    last_folded_ts: undefined,
    confidence_state: "provisional",
    stats: { count: 0, mean: 0, m2: 0, variance: 0, stddev: 0, ewma: undefined, ewma_variance: undefined, min: undefined, max: undefined },
    last_observation: undefined,
    skipped_overflow_tick_count: 0,
    skipped_partial_tick_count: 0,
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

export function normalizeSessionBaselineState(raw) {
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
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
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
 * provenance-store.js's loadSignatureStore / constraint-store.js's loadLearnedConfig: a
 * corrupt/malformed file yields a fresh baseline rather than throwing out of a daemon tick, with
 * `corrupt:true` surfaced to the caller). The cost of a corrupt-file reset is an honest,
 * documented cold-start (30 real samples before "established" again) — never a crashed tick.
 */
export async function loadSessionBaselineStore(descartesPaths) {
  const { storeFile } = resolveSessionBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: freshSessionBaselineState(), corrupt: false };
  if (corrupt) return { state: freshSessionBaselineState(), corrupt: true };
  return { state: normalizeSessionBaselineState(parsed), corrupt: false };
}

export async function writeSessionBaselineStore(descartesPaths, state) {
  await ensureSessionBaselineDir(descartesPaths);
  const { storeFile } = resolveSessionBaselineStorePaths(descartesPaths);
  const normalized = normalizeSessionBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

// ---------------------------------------------------------------------------------------------
// Tick-grouping (Decision 3): "one observation" = the count of non-marker session.presence points
// sharing one tick's `ts`, for a tick-group that also carries a census marker (Slice 1 addendum).
// ---------------------------------------------------------------------------------------------

/**
 * Groups session.presence fact points by their shared `ts` (one structural tick = one shared ts
 * string, confirmed against daemon.js's runDaemonIteration — every translator call within one
 * iteration receives the identical `ts`). Returns tick-groups ORDERED ascending by ts, each
 * `{ ts, count, hasOverflow, censusState, points }`:
 *   - `count` excludes both the overflow-marker entity AND the census-marker entity (must-fixes
 *     1/2 — the marker is never counted as a session).
 *   - `hasOverflow` is true iff this tick-group carries the SESSION_OVERFLOW_ENTITY_KEY marker.
 *   - `censusState` is "complete" | "partial" (per the tick's own census marker, matched EXACTLY,
 *     not by elimination) | "unknown" (a census marker DID land for this tick, but its
 *     `attributes.census_state` is neither the literal string "complete" nor "partial" — e.g. disk
 *     corruption of facts.jsonl, or a future/garbled marker value; classified as a fail-closed
 *     third disposition rather than defaulting to "complete", per this module's own
 *     degrade-not-fabricate contract: an unrecognized census-state value must never be silently
 *     upgraded into a trusted complete census — mirrors groupServiceFactsByTick's own "unknown"
 *     disposition exactly) | undefined (no marker at all — a markerless, pre-Slice-4-addendum
 *     LEGACY tick-group).
 *   - `points` are the real (non-marker) session.presence fact points in this tick-group, in the
 *     order encountered — used by detectSessionChurn below.
 */
export function groupSessionFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || point.fact_name !== SESSION_FACT_NAME || typeof point.ts !== "string") continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, count: 0, hasOverflow: false, censusState: undefined, points: [] });
    }
    const group = byTs.get(point.ts);
    if (point.entity_key === SESSION_OVERFLOW_ENTITY_KEY) {
      group.hasOverflow = true;
      continue;
    }
    if (point.entity_key === SESSION_CENSUS_MARKER_ENTITY_KEY) {
      // Strict three-way match on the marker's own value — NEVER an else-defaults-to-"complete"
      // ternary (mirrors groupServiceFactsByTick's own fail-closed classification, service-baseline.js).
      // An unrecognized census_state value (corruption, future schema drift, a bug upstream) must
      // degrade to the fail-closed "unknown" disposition, not the max-trust one.
      const rawState = point.attributes?.census_state;
      group.censusState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
      continue;
    }
    group.count += 1;
    group.points.push(point);
  }
  return [...byTs.values()].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}

/**
 * Disposition of a tick-group for the WINDOWED WELFORD RECOMPUTE (Decision 3):
 *   - "overflow": excluded entirely from the recompute (an inexact/bucketed count must never
 *     masquerade as an exact sample); checked FIRST because a tick can carry both an overflow
 *     marker and a "complete" census marker simultaneously (the flood cap can trip even when
 *     every multiplexer itself succeeded) — overflow always wins for recompute purposes.
 *   - "partial": excluded, exactly like overflow (must-fix 2).
 *   - "unknown": a garbled/unrecognized census_state marker value (see groupSessionFactsByTick) —
 *     excluded, exactly like "partial"/markerless (degrade-not-fabricate: a garbled census must
 *     never be silently upgraded into a trusted "complete" fold via an else-catch-all).
 *   - "markerless": a legacy, pre-Slice-4-addendum tick-group — skipped entirely (never folded,
 *     never treated as zero, no throw); an honest ~30-sample re-warm-up.
 *   - "complete": foldable — including a genuine zero-session tick (must-fix 1). Matched EXACTLY
 *     on censusState === "complete", never as an else-catch-all, so an "unknown" tick can never
 *     slip through as trusted.
 */
function tickGroupDisposition(group) {
  if (group.hasOverflow) return "overflow";
  if (group.censusState === "complete") return "complete";
  if (group.censusState === "partial") return "partial";
  if (group.censusState === undefined) return "markerless";
  return "unknown";
}

/**
 * Must-fix 5: recomputes the windowed Welford/EWMA stats, confidence_state, and the candidate-
 * relevant last_observation FRESH from `groups` every time — never an incrementally-accumulated
 * running total. `last_observation.z_score` is computed against the window EXCLUDING the latest
 * complete tick-group (self-dampening avoidance) before that tick-group is folded into the
 * returned `stats` snapshot. `last_observation.has_overflow` reflects whether the single most
 * recent tick-group of ANY disposition is an overflow tick — purely observational: it never
 * changes ts/count/z_score/mean_before/stddev_before, which stay pinned to the latest REAL
 * (complete) tick-group's own evaluation (plan-text nice-to-have ii, decided+tested).
 */
export function computeWindowedSessionStats(groups, { stddevFloor = DEFAULT_STDDEV_FLOOR, ewmaAlpha = DEFAULT_EWMA_ALPHA, minSampleCount = DEFAULT_MIN_SAMPLE_COUNT } = {}) {
  const completeGroups = groups.filter((group) => tickGroupDisposition(group) === "complete");
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const hasOverflowNow = mostRecentGroup ? tickGroupDisposition(mostRecentGroup) === "overflow" : false;

  let stats = emptyWelfordStats();
  let ewmaState = { ewma: undefined, ewma_variance: undefined };
  let lastObservation;

  completeGroups.forEach((group, index) => {
    if (index === completeGroups.length - 1) {
      const zScore = computeZScore(group.count, stats.mean, stats.stddev, stddevFloor);
      lastObservation = {
        ts: group.ts,
        count: group.count,
        z_score: zScore,
        mean_before: stats.mean,
        stddev_before: stats.stddev,
        has_overflow: hasOverflowNow,
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
// Churn detection (Decision 3): a separate, simpler, stateless mechanism — no persisted state,
// no confidence_state gate. A pure function of already-persisted fact-history, recomputed fresh
// every tick, exactly like provenance-warnings.js's reduceLatestProvenanceWarnings pattern.
// ---------------------------------------------------------------------------------------------

/**
 * Must-fix 4 (recency bound, hard requirement): for each entity_key with two or more
 * session.presence points in the pool, compares the two most recent points' created_at_fingerprint.
 * Fires only when BOTH fingerprints are defined, neither is the literal "unknown" (the screen-
 * session case), they differ, AND the newer point belongs to the SINGLE latest "complete"
 * tick-group (K=1 default) — a stale pair (entity since vanished) or a pair buried in
 * pre-existing history at first run is silent by construction, since neither has its newer point
 * in the freshly-observed latest complete tick-group.
 *
 * Pool construction (must-fix 2, extended to the "unknown" disposition): any point belonging to
 * a "partial"-marked tick-group is excluded wholesale from the pool (not merely the marker
 * itself) — an undercounted census must not be allowed to manufacture a false churn signal
 * either. A tick-group whose census marker landed but is garbled/unrecognized ("unknown" — see
 * groupSessionFactsByTick) is excluded identically: it must never supply either side (older OR
 * newer) of a fingerprint pair, per this module's degrade-not-fabricate contract — an untrusted
 * tick can neither anchor nor feed a churn candidate. Markerless (legacy) tick-groups' points ARE
 * included in the pool (so a stale/legacy pair can be found and shown NOT to fire via the recency
 * bound alone, per the plan's own upgrade-day-storm reasoning) but a markerless tick-group can
 * never itself be the "latest complete tick-group" anchor.
 */
export function detectSessionChurn(points = []) {
  const groups = groupSessionFactsByTick(points);
  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length === 0) return [];
  const latestCompleteTs = completeGroups[completeGroups.length - 1].ts;

  const byEntity = new Map();
  for (const group of groups) {
    // "partial" and "unknown" groups are both excluded here (an undercounted OR garbled census
    // could drop/misattribute an entity's point mid-comparison). "overflow" (flood-capped) groups
    // are DELIBERATELY kept: churn needs only a same-entity fingerprint pair, not an accurate
    // total headcount, and a flood/mass-resurrection tick is exactly the incident shape churn
    // exists to catch. This intentionally differs from the count-drop fold, which excludes both
    // partial AND overflow groups.
    if (group.censusState === "partial" || group.censusState === "unknown") continue; // must-fix 2 + unknown-disposition hardening
    for (const point of group.points) {
      const fingerprint = point.attributes?.created_at_fingerprint;
      const list = byEntity.get(point.entity_key) ?? [];
      list.push({ ts: group.ts, fingerprint });
      byEntity.set(point.entity_key, list);
    }
  }

  const churnEntries = [];
  for (const [entityKey, observations] of byEntity) {
    if (observations.length < 2) continue;
    observations.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
    const newer = observations[observations.length - 1];
    const older = observations[observations.length - 2];
    if (!newer.fingerprint || !older.fingerprint) continue;
    if (newer.fingerprint === "unknown" || older.fingerprint === "unknown") continue;
    if (newer.fingerprint === older.fingerprint) continue;
    if (newer.ts !== latestCompleteTs) continue; // must-fix 4 recency bound (K=1)
    churnEntries.push({ entity_key: entityKey, prior_fingerprint: older.fingerprint, current_fingerprint: newer.fingerprint });
  }
  return churnEntries;
}

// ---------------------------------------------------------------------------------------------
// Candidate builders (Decision 4) — mirror buildPublicBindCandidate/buildDeletedExeCandidate's
// shape exactly.
// ---------------------------------------------------------------------------------------------

export function buildCountDropCandidate(state, { deviationSigma = DEFAULT_DEVIATION_SIGMA, criticalSigma = DEFAULT_CRITICAL_SIGMA } = {}) {
  if (state?.confidence_state !== "established") return undefined;
  const obs = state.last_observation;
  if (!obs || !Number.isFinite(obs.z_score) || !Number.isFinite(obs.mean_before)) return undefined;
  if (!(obs.z_score <= -deviationSigma)) return undefined;
  if (!(obs.count < obs.mean_before)) return undefined; // defense-in-depth guard, redundant given a negative z

  const severity = obs.z_score <= -criticalSigma ? "critical" : "warning";
  const diagnostics = sanitizeDiagnostics({
    observed_count: obs.count,
    mean_before: obs.mean_before,
    stddev_before: obs.stddev_before,
    z_score: obs.z_score,
    confidence_state: state.confidence_state,
  });
  return {
    id: alertId(SESSION_COUNT_DROP_RULE_ID, "global"),
    rule_id: SESSION_COUNT_DROP_RULE_ID,
    fingerprint: "global",
    severity,
    title: "Session count deviation",
    summary: "Resident tmux/screen session count deviated significantly below its established baseline.",
    diagnostics,
    evidence_refs: ["session-baseline"],
  };
}

export function buildChurnCandidates(churnEntries = []) {
  return churnEntries.map((entry) => {
    const diagnostics = sanitizeDiagnostics({
      entity_key: entry.entity_key,
      prior_fingerprint: entry.prior_fingerprint,
      current_fingerprint: entry.current_fingerprint,
    });
    return {
      id: alertId(SESSION_CHURN_RULE_ID, entry.entity_key),
      rule_id: SESSION_CHURN_RULE_ID,
      fingerprint: entry.entity_key,
      severity: "warning",
      title: "Session churn detected",
      summary: "A tracked session's creation fingerprint changed between observations (possible kill-then-resurrect).",
      diagnostics,
      evidence_refs: ["session-baseline"],
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Fast-tick side — the daemon.js extraCandidates entry.
// ---------------------------------------------------------------------------------------------

/**
 * Matches computeProvenanceWarningCandidates' exact signature/short-circuit shape: gated by the
 * same loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O. Called on every daemon
 * tick (~60s) from runDaemonIteration's extraCandidates concat, not just on a structural-due
 * tick — an already-collected fact must be able to fire (or keep firing / recover) an alert
 * without waiting for the next hourly structural collection.
 *
 * Fast-tick-vs-hourly-fold hazard (must-fix 5): readFactPoints is intentionally NOT skipped on
 * fast ticks (churn is recomputed fresh every call; the windowed stats recompute needs to check
 * whether a new tick-group has landed) — only the session-baseline.json STORE WRITE is skipped on
 * ticks that find zero new tick-groups since state.last_folded_ts, so a fast tick between hourly
 * structural collections performs no disk write and leaves the persisted state untouched.
 */
export async function computeSessionBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const minSampleCount = options.minSampleCount ?? DEFAULT_MIN_SAMPLE_COUNT;
  const stddevFloor = options.stddevFloor ?? DEFAULT_STDDEV_FLOOR;
  const deviationSigma = options.deviationSigma ?? DEFAULT_DEVIATION_SIGMA;
  const criticalSigma = options.criticalSigma ?? DEFAULT_CRITICAL_SIGMA;
  const ewmaAlpha = options.ewmaAlpha ?? DEFAULT_EWMA_ALPHA;
  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;

  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupSessionFactsByTick(points);

  const loadStore = options.loadSessionBaselineStore ?? loadSessionBaselineStore;
  const { state: persistedState } = await loadStore(descartesPaths);

  const lastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const newGroups = groups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  const windowed = computeWindowedSessionStats(groups, { stddevFloor, ewmaAlpha, minSampleCount });

  if (newGroups.length > 0) {
    let skippedOverflow = persistedState.skipped_overflow_tick_count;
    let skippedPartial = persistedState.skipped_partial_tick_count;
    let lastFoldedTs = persistedState.last_folded_ts;
    for (const group of newGroups) {
      lastFoldedTs = group.ts;
      const disposition = tickGroupDisposition(group);
      if (disposition === "overflow") skippedOverflow += 1;
      else if (disposition === "partial") skippedPartial += 1;
      // "unknown" (garbled census_state), "markerless" (legacy), and "complete": no counter —
      // last_folded_ts still advances. No new counter is introduced for "unknown" (mirrors
      // service-baseline.js, which also adds no new plumbing for its own "unknown" disposition).
    }
    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      confidence_state: windowed.confidence_state,
      stats: windowed.stats,
      last_observation: windowed.last_observation,
      skipped_overflow_tick_count: skippedOverflow,
      skipped_partial_tick_count: skippedPartial,
    };
    const writeStore = options.writeSessionBaselineStore ?? writeSessionBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  const candidates = [];
  // Re-emission every tick (load-bearing, Decision 3): built fresh from `windowed` on EVERY call
  // — including ticks where nothing new was folded — so applyAlertCandidates never spuriously
  // "recovers" an active session.count_drop just because this source skipped a redundant write.
  const dropCandidate = buildCountDropCandidate(
    { confidence_state: windowed.confidence_state, last_observation: windowed.last_observation },
    { deviationSigma, criticalSigma },
  );
  if (dropCandidate) candidates.push(dropCandidate);
  candidates.push(...buildChurnCandidates(detectSessionChurn(points)));
  return candidates;
}
