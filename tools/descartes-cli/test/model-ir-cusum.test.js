import assert from "node:assert/strict";
import test from "node:test";
import { emptyWelfordStats, foldWelford } from "../src/welford-stats.js";
import { evaluateModel, evaluateFeatureNode } from "../src/model-ir.js";

// Slice-1 behavioral-model spike, step 3 (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 3): pure, offline tests for the new `cusum` FEATURE op -- a two-sided tabular CUSUM
// over a series, composed on top of step 1's `window`, feeding step 1's `threshold` model node.
// Same node:test / assert style as test/model-ir.test.js; a sibling file so the diff for this
// step is isolated to exactly one new op (git diff: src/model-ir.js + this file).

function validModelRecord(overrides = {}) {
  return {
    id: "model.test.cusum",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    feature: { op: "latest", of: { op: "fact", name: "test.fact" } },
    model: { op: "threshold", expected: { comparator: "gte", value: 1000 } },
    ...overrides,
  };
}

// An independent reference implementation of the two-sided tabular CUSUM, written directly in the
// test (not imported from src/model-ir.js) -- this is what makes the golden-lock tests below an
// actual lock rather than the implementation checking itself.
function referenceCusumMax(values, target, k) {
  let sHi = 0;
  let sLo = 0;
  let maxStat = 0;
  for (const x of values) {
    sHi = Math.max(0, sHi + (x - target - k));
    sLo = Math.max(0, sLo + (target - k - x));
    maxStat = Math.max(maxStat, sHi, sLo);
  }
  return maxStat;
}

function seriesFrom(startMs, stepMs, values) {
  return values.map((value, i) => ({ ts: startMs + i * stepMs, value }));
}

// --- Golden lock: explicit numeric target ------------------------------------------------------

test("cusum golden lock: explicit numeric target matches an independent reference loop exactly", () => {
  const values = [5, 8, 6, 12, 7];
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const series = seriesFrom(startMs, stepMs, values);
  const target = 6;
  const k = 1;

  const result = evaluateFeatureNode({ op: "cusum", of: { op: "fact", name: "metric.x" }, target, k }, { "metric.x": series });

  assert.equal(result.supported, true);
  assert.equal(result.kind, "scalar");
  assert.equal(result.value, referenceCusumMax(values, target, k));
});

// --- Golden lock: target:"mean" (via foldWelford, the same primitive zscore uses) --------------

test('cusum golden lock: target:"mean" matches a reference loop using foldWelford for the mean', () => {
  const values = [5, 8, 6, 12, 7];
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const series = seriesFrom(startMs, stepMs, values);
  const k = 1;

  const result = evaluateFeatureNode({ op: "cusum", of: { op: "fact", name: "metric.x" }, target: "mean", k }, { "metric.x": series });

  assert.equal(result.supported, true);
  assert.equal(result.kind, "scalar");

  const stats = values.reduce((acc, v) => foldWelford(acc, v), emptyWelfordStats());
  const expected = referenceCusumMax(values, stats.mean, k);
  assert.equal(result.value, expected);
  // sanity: the mean-derived target differs from the fixed-target lock above, so this is
  // genuinely exercising the "mean" branch, not accidentally re-testing the same number.
  assert.notEqual(stats.mean, 6);
});

test("cusum golden lock: an unsorted input series folds to the same golden statistic as the sorted one", () => {
  const values = [5, 8, 6, 12, 7];
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const ordered = seriesFrom(startMs, stepMs, values);
  const shuffled = [ordered[3], ordered[0], ordered[4], ordered[1], ordered[2]];
  const target = 6;
  const k = 1;

  const orderedResult = evaluateFeatureNode({ op: "cusum", of: { op: "fact", name: "metric.x" }, target, k }, { "metric.x": ordered });
  const shuffledResult = evaluateFeatureNode({ op: "cusum", of: { op: "fact", name: "metric.x" }, target, k }, { "metric.x": shuffled });

  assert.equal(shuffledResult.supported, true);
  assert.equal(shuffledResult.value, orderedResult.value);
});

// --- Changepoint fires / stable stays quiet, through the full composition ----------------------
//
// Deterministic (no randomness) baseline oscillating around 10, followed by an injected level
// shift to ~30; a stable comparison series repeats the same baseline pattern with no shift. Both
// are the same length so only the injected shift differs. target=10 (the known baseline mean),
// k=5 (roughly half the ~20-unit shift, the standard CUSUM allowance choice). h=50 sits well
// between the stable series' max (0, by construction: no drift means S_hi never grows away from
// its 0 floor) and the shifted series' max (150, verified below) -- a "sensible h" per the plan.

const BASELINE = [10, 11, 9, 10, 12, 8, 10, 11, 9, 10, 12, 8, 10, 11, 9, 10];
const SHIFT = [30, 31, 29, 30, 32, 28, 30, 31, 29, 30];
const CP_TARGET = 10;
const CP_K = 5;
const CP_H = 50;

function changepointModel(values, { startMs, stepMs, ms }) {
  const series = seriesFrom(startMs, stepMs, values);
  const model = validModelRecord({
    feature: {
      op: "cusum",
      of: { op: "window", of: { op: "fact", name: "metric.load" }, ms },
      target: CP_TARGET,
      k: CP_K,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: CP_H } },
  });
  const startTs = startMs;
  const now = startMs + (values.length - 1) * stepMs;
  const verdict = evaluateModel(model, { "metric.load": series }, { now });
  return { verdict, startTs, now };
}

test("cusum changepoint: a series with an injected level-shift fires (satisfied:true, crosses h) for a sensible h", () => {
  const withShift = [...BASELINE, ...SHIFT];
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const ms = (withShift.length + 5) * stepMs; // comfortably covers the whole series

  const { verdict } = changepointModel(withShift, { startMs, stepMs, ms });

  assert.equal(verdict.supported, true);
  // Independent reference confirms the shifted series' peak statistic crosses h.
  assert.equal(verdict.value, referenceCusumMax(withShift, CP_TARGET, CP_K));
  assert.ok(verdict.value >= CP_H, `expected the shifted series' cusum (${verdict.value}) to cross h=${CP_H}`);
  assert.equal(verdict.satisfied, true, "gte h comparator: satisfied:true means the statistic crossed h -- this is the 'fires' outcome");
});

test("cusum changepoint: a stable series (no shift) with the same h does not fire", () => {
  const stable = [...BASELINE, ...BASELINE.slice(0, SHIFT.length)];
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const ms = (stable.length + 5) * stepMs;

  const { verdict } = changepointModel(stable, { startMs, stepMs, ms });

  assert.equal(verdict.supported, true);
  assert.equal(verdict.value, referenceCusumMax(stable, CP_TARGET, CP_K));
  assert.ok(verdict.value < CP_H, `expected the stable series' cusum (${verdict.value}) to stay below h=${CP_H}`);
  assert.equal(verdict.satisfied, false, "stable series never crosses h -- does not 'fire'");
});

// --- Composition: cusum(window(...)) end-to-end through evaluateModel, independent of the
// changepoint scenario above (a simpler series, to isolate "does the plumbing work" from "is the
// changepoint semantics sensible") ---------------------------------------------------------------

test("cusum composition: cusum(window(ms, fact)) evaluates end-to-end through evaluateModel with a threshold node and opts.now", () => {
  const startMs = Date.parse("2026-09-03T00:00:00.000Z");
  const stepMs = 60_000;
  const values = [5, 8, 6, 12, 7, 999]; // last point (999) deliberately far outside the window
  const series = seriesFrom(startMs, stepMs, values);
  const ms = 5 * stepMs; // excludes the ts=startMs+5*stepMs (999) point by construction below
  const now = startMs + 4 * stepMs; // reference point is the 5th value (7), not the outlier

  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "window", of: { op: "fact", name: "metric.y" }, ms }, target: 6, k: 1 },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  const verdict = evaluateModel(model, { "metric.y": series }, { now });

  assert.equal(verdict.supported, true);
  // Windowed to [now-ms, now]: excludes the 999 outlier, matching window()'s own semantics.
  const windowed = series.filter((p) => p.ts <= now && p.ts >= now - ms).map((p) => p.value);
  assert.deepEqual(windowed, [5, 8, 6, 12, 7], "sanity: the outlier point must be excluded by window()");
  assert.equal(verdict.value, referenceCusumMax(windowed, 6, 1));
});

// --- Missing-input -> silence semantics ----------------------------------------------------------

test("cusum missing-input: of is a scalar, not a series -- cannot cusum a scalar", () => {
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.scalar" }, target: 0, k: 1 },
  });
  assert.deepEqual(evaluateModel(model, { "metric.scalar": 42 }), { supported: false });
});

test("cusum missing-input: an empty series silences the node", () => {
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.empty" }, target: 0, k: 1 },
  });
  assert.deepEqual(evaluateModel(model, { "metric.empty": [] }), { supported: false });
});

test("cusum missing-input: a sub-minSamples series silences the node (default minSamples=2)", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [42]);
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.short" }, target: 0, k: 1 },
  });
  assert.deepEqual(evaluateModel(model, { "metric.short": series }), { supported: false });
});

test("cusum missing-input: a non-finite point anywhere in the series silences the node, never fabricates", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [5, 8, NaN, 12, 7]);
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.degraded" }, target: 0, k: 1 },
  });
  assert.deepEqual(evaluateModel(model, { "metric.degraded": series }), { supported: false });
});

test("cusum missing-input: a non-numeric target (not \"mean\", not a finite number) silences the node", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [5, 8, 6, 12, 7]);
  // NB: `[]` is deliberately excluded here -- `Number([])` coerces to `0` (a finite number) in
  // JS, the same loose-coercion behavior `ms`/`stddevFloor` already accept elsewhere in this file
  // (e.g. `Number(null)` also coerces to a finite `0`) -- so it is not a "bad target" under this
  // file's own established coercion convention, even though it wasn't literally authored as a
  // number. Flagged in the step-3 report as a judgment call, not tested as a silence case here.
  for (const badTarget of ["not-a-number", {}, "median", undefined]) {
    const model = validModelRecord({
      feature: { op: "cusum", of: { op: "fact", name: "metric.x" }, target: badTarget, k: 1 },
    });
    const verdict = evaluateModel(model, { "metric.x": series });
    assert.deepEqual(verdict, { supported: false }, `expected silence for target=${JSON.stringify(badTarget)}`);
  }
});

test("cusum missing-input: a non-finite k silences the node", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [5, 8, 6, 12, 7]);
  for (const badK of [NaN, Infinity, -Infinity, "not-a-number"]) {
    const model = validModelRecord({
      feature: { op: "cusum", of: { op: "fact", name: "metric.x" }, target: 6, k: badK },
    });
    const verdict = evaluateModel(model, { "metric.x": series });
    assert.deepEqual(verdict, { supported: false }, `expected silence for k=${JSON.stringify(badK)}`);
  }
});

// --- Security hardening (adversarial-review fix-spec M3/M4/M5/M6, cusum-specific) --------------

test("M3: cusum rejects a coercible-but-non-numeric point value (null/[]/\"\"/false) instead of coercing it to 0", () => {
  for (const badValue of [null, [], "", false]) {
    const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [5, 8]);
    series[1] = { ...series[1], value: badValue };
    const model = validModelRecord({
      feature: { op: "cusum", of: { op: "fact", name: "metric.coerce" }, target: 0, k: 1 },
    });
    const verdict = evaluateModel(model, { "metric.coerce": series });
    assert.deepEqual(verdict, { supported: false }, `expected silence for value=${JSON.stringify(badValue)}`);
  }
});

test("M4: cusum minSamples must be an integer >= 2 -- a fractional/zero/negative/NaN minSamples silences rather than being accepted", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [5, 8]);
  for (const badMinSamples of [0, -1, 1.5, NaN]) {
    const model = validModelRecord({
      feature: { op: "cusum", of: { op: "fact", name: "metric.x" }, target: 6, k: 1, minSamples: badMinSamples },
    });
    const verdict = evaluateModel(model, { "metric.x": series });
    assert.deepEqual(verdict, { supported: false }, `expected silence for minSamples=${JSON.stringify(badMinSamples)}`);
  }
});

test("M4: cusum never fabricates a statistic from zero real samples, even when minSamples is invalid", () => {
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.emptyseries" }, target: "mean", k: 1, minSamples: 0 },
  });
  const verdict = evaluateModel(model, { "metric.emptyseries": [] });
  assert.deepEqual(verdict, { supported: false }, "zero samples must silence, never fabricate value:0");
});

test("M5: cusum rejects a negative k instead of fabricating a changepoint from it", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [10, 10, 10, 10, 10]); // perfectly flat, no real drift
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.flat" }, target: 10, k: -100 },
  });
  const verdict = evaluateModel(model, { "metric.flat": series });
  assert.deepEqual(verdict, { supported: false });
});

test("M6: cusum silences instead of returning a non-finite (overflow) statistic", () => {
  const series = seriesFrom(Date.parse("2026-09-03T00:00:00.000Z"), 60_000, [Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE]);
  const model = validModelRecord({
    feature: { op: "cusum", of: { op: "fact", name: "metric.overflow" }, target: -Number.MAX_VALUE, k: Number.MAX_VALUE },
  });
  const verdict = evaluateModel(model, { "metric.overflow": series });
  assert.deepEqual(verdict, { supported: false });
});
