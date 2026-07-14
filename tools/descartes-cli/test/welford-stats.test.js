import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_BASELINE_FACT_WINDOW_MS,
  computeZScore,
  emptyWelfordStats,
  foldWelford,
  updateEwma,
} from "../src/welford-stats.js";

// Slice 4b (observed-incident collectors plan), Decision 4 / Fable review MUST-FIX 5: these four
// pure-math unit tests were MOVED (not duplicated) from session-baseline.test.js's existing
// coverage of foldWelford/updateEwma/computeZScore/emptyWelfordStats, now that the functions
// themselves live in welford-stats.js. session-baseline.js still re-exports (import-then-
// re-export) the same names, so session-baseline.test.js's own name-imports of these functions
// continue to resolve — only the direct unit-test coverage of the math itself moved here, to
// avoid duplicating the same assertions in two files.

test("foldWelford: classic textbook sequence [2,4,4,4,5,5,7,9] -> mean=5, sample variance=32/7, stddev=sqrt(32/7)", () => {
  const sequence = [2, 4, 4, 4, 5, 5, 7, 9];
  const stats = sequence.reduce((acc, value) => foldWelford(acc, value), emptyWelfordStats());
  assert.equal(stats.count, 8);
  assert.equal(stats.mean, 5);
  assert.ok(Math.abs(stats.variance - 32 / 7) < 1e-9, `expected variance ~${32 / 7}, got ${stats.variance}`);
  assert.ok(Math.abs(stats.stddev - Math.sqrt(32 / 7)) < 1e-9);
  assert.equal(stats.min, 2);
  assert.equal(stats.max, 9);
});

test("foldWelford: a single observation has variance 0 and mean equal to that observation", () => {
  const stats = foldWelford(emptyWelfordStats(), 42);
  assert.equal(stats.count, 1);
  assert.equal(stats.mean, 42);
  assert.equal(stats.variance, 0);
  assert.equal(stats.stddev, 0);
});

test("updateEwma: first observation seeds ewma to that value with zero variance; a known two-step sequence matches hand computation", () => {
  const seed = updateEwma({ ewma: undefined, ewma_variance: undefined }, 10, 0.5);
  assert.deepEqual(seed, { ewma: 10, ewma_variance: 0 });
  const second = updateEwma(seed, 20, 0.5);
  assert.equal(second.ewma, 15);
  assert.equal(second.ewma_variance, 25);
});

test("computeZScore: known values, and an explicit STDDEV_FLOOR guard dampens a trivial fluctuation on a near-zero-variance baseline", () => {
  assert.equal(computeZScore(1, 10, 2, 0.5), -4.5);
  assert.equal(computeZScore(0, 5, 0.01, 0.5), -10);
  // stddev below the floor is clamped to the floor, not used directly.
  assert.equal(computeZScore(19, 20, 0, 0.5), (19 - 20) / 0.5);
});

// Decision 4, hard requirement: the extraction dropped computeZScore's session-tuned default
// (previously `stddevFloor = DEFAULT_STDDEV_FLOOR`). In the shared module, an omitted floor must
// NOT silently fall back to any domain-tuned value -- every real call site (session-baseline.js,
// peer-baseline.js) passes its own floor explicitly, 4-arg, always.
test("computeZScore: stddevFloor has NO domain-tuned default -- an omitted floor is NaN/undefined and clamps effectiveStddev to a non-positive value, yielding 0, not a hidden session-tuned fallback", () => {
  assert.equal(computeZScore(100, 0, 0), 0);
});

test("DEFAULT_BASELINE_FACT_WINDOW_MS is a positive finite constant (~31 days)", () => {
  assert.ok(Number.isFinite(DEFAULT_BASELINE_FACT_WINDOW_MS) && DEFAULT_BASELINE_FACT_WINDOW_MS > 0);
  assert.equal(DEFAULT_BASELINE_FACT_WINDOW_MS, 31 * 24 * 60 * 60 * 1000);
});
