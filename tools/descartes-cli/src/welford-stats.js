// Slice 4b (observed-incident collectors plan) — shared, domain-agnostic Welford/EWMA/z-score
// primitives, extracted from session-baseline.js (Decision 4, Fable review MUST-FIX 5).
//
// These four functions plus DEFAULT_BASELINE_FACT_WINDOW_MS were already pure and
// domain-agnostic in signature in session-baseline.js (none of them mention sessions, peers, ts,
// or any fact-history shape — they operate on a plain numeric observedCount). Extracting them
// here lets session-baseline.js and the new peer-baseline.js share the exact same, single-sourced
// math without either forking it (risking silent drift) or forcing a full merge of their
// genuinely-different domain logic (tick-grouping, markers, dimension stratification, trigger
// sign) — see docs/plans/2026-07-13-observed-incident-collectors.md, Slice 4b Decision 4 for the
// full reasoning.
//
// Behavior-preserving extraction: every function below is byte-identical in logic to its
// session-baseline.js origin, with one deliberate signature change (documented at computeZScore)
// — stddevFloor no longer defaults to a session-tuned constant; callers must pass their own.

// Comfortably covers fact-store.js's own 30-day DEFAULT_FACT_RETENTION_MS ceiling — this is what
// makes "the windowed recompute is bounded by 30-day retention" literally true for every consumer
// (session-baseline.js, peer-baseline.js, incident-correlation.js all import this same constant).
export const DEFAULT_BASELINE_FACT_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;

export function emptyWelfordStats() {
  return { count: 0, mean: 0, m2: 0, variance: 0, stddev: 0, min: undefined, max: undefined };
}

/**
 * Classic Welford single-observation fold: given the PRIOR {count, mean, m2, min, max} (or none —
 * defaults to emptyWelfordStats()), returns the updated stats after folding in observedCount.
 * Sample variance (m2 / (count - 1)), matching the parent roadmap's own baseline-record shape.
 *
 * Callers recompute the FULL windowed stats fresh every time by reducing over every complete
 * tick-group's count currently inside the fact-history window, starting from emptyWelfordStats()
 * each time. It is never used as a forever-persisted, incrementally-accumulated running total —
 * that would grow unbounded and contradict the "bounded by 30-day retention" claim.
 */
export function foldWelford(stats, observedCount) {
  const prev = stats && typeof stats === "object" ? stats : emptyWelfordStats();
  const count = (Number.isFinite(prev.count) ? prev.count : 0) + 1;
  const prevMean = Number.isFinite(prev.mean) ? prev.mean : 0;
  const prevM2 = Number.isFinite(prev.m2) ? prev.m2 : 0;
  const delta = observedCount - prevMean;
  const mean = prevMean + delta / count;
  const delta2 = observedCount - mean;
  const m2 = prevM2 + delta * delta2;
  const variance = count > 1 ? m2 / (count - 1) : 0;
  const stddev = Math.sqrt(Math.max(variance, 0));
  const min = prev.min === undefined ? observedCount : Math.min(prev.min, observedCount);
  const max = prev.max === undefined ? observedCount : Math.max(prev.max, observedCount);
  return { count, mean, m2, variance, stddev, min, max };
}

/**
 * Single-observation EWMA-with-variance fold (Finch/West-style incremental update). `stats` is
 * `{ ewma, ewma_variance }` (or undefined/first-observation, in which case ewma seeds to
 * observedCount and ewma_variance to 0). Persisted for forward compatibility with a future
 * migration but NOT consumed by any v0 trigger formula (Welford-mean/stddev z-score only, both
 * for session.count_drop/session.churn and peer.count_spike).
 */
export function updateEwma(stats, observedCount, alpha) {
  const prevMean = stats?.ewma;
  const prevVariance = Number.isFinite(stats?.ewma_variance) ? stats.ewma_variance : 0;
  if (prevMean === undefined || !Number.isFinite(prevMean)) {
    return { ewma: observedCount, ewma_variance: 0 };
  }
  const diff = observedCount - prevMean;
  const increment = alpha * diff;
  const ewma = prevMean + increment;
  const ewma_variance = (1 - alpha) * (prevVariance + diff * increment);
  return { ewma, ewma_variance };
}

/**
 * z = (observedCount - meanBefore) / max(stddevBefore, stddevFloor). Callers are responsible for
 * computing meanBefore/stddevBefore over a window that EXCLUDES the observation being scored
 * (self-dampening-avoidance ordering requirement) — this function itself is a pure, stateless
 * formula with no opinion on what "before" means.
 *
 * Slice 4b Decision 4 (extraction signature change, deliberate, hard requirement): `stddevFloor`
 * is now a REQUIRED, explicit-only parameter — no session-tuned default. session-baseline.js and
 * peer-baseline.js each own an independently-named, independently-tunable floor constant
 * (DEFAULT_STDDEV_FLOOR / DEFAULT_PEER_STDDEV_FLOOR respectively) and pass it explicitly at every
 * call site; this shared module must never silently supply a domain-tuned value to either.
 */
export function computeZScore(observedCount, meanBefore, stddevBefore, stddevFloor) {
  const effectiveStddev = Math.max(Number.isFinite(stddevBefore) ? stddevBefore : 0, stddevFloor);
  if (!Number.isFinite(effectiveStddev) || effectiveStddev <= 0) return 0;
  const mean = Number.isFinite(meanBefore) ? meanBefore : 0;
  return (Number(observedCount) - mean) / effectiveStddev;
}
