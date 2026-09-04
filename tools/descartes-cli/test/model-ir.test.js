import assert from "node:assert/strict";
import test from "node:test";
import { evaluateExpected } from "../src/constraint-eval.js";
import { SEED_CONSTRAINTS } from "../src/constraint-store.js";
import { computeZScore, emptyWelfordStats, foldWelford } from "../src/welford-stats.js";
import { MAX_SERIES_POINTS, evaluateFeatureNode, evaluateModel, evaluateRecord, validateModel } from "../src/model-ir.js";

// Slice-1 behavioral-model spike, step 1 (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 1): pure, offline tests for the thin v2 IR + DAG interpreter. Two regression locks
// (byte-identical BY CONSTRUCTION, since both reuse the exact v1/welford functions under the
// hood) plus missing-input -> silence coverage and dual-read routing.

function validModelRecord(overrides = {}) {
  return {
    id: "model.test.example",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    feature: { op: "latest", of: { op: "fact", name: "test.fact" } },
    model: { op: "threshold", expected: { comparator: "gte", value: 1000 } },
    ...overrides,
  };
}

// --- validateModel ---------------------------------------------------------------------------

test("validateModel accepts a well-formed v2 model record", () => {
  assert.equal(validateModel(validModelRecord()), true);
});

test("validateModel throws on non-object record", () => {
  assert.throws(() => validateModel(null), /must be an object/);
  assert.throws(() => validateModel([1, 2]), /must be an object/);
});

test("validateModel throws on missing/empty id", () => {
  assert.throws(() => validateModel(validModelRecord({ id: "" })), /non-empty id/);
});

test("validateModel throws when kind is not \"model\"", () => {
  assert.throws(() => validateModel(validModelRecord({ kind: "constraint" })), /kind must be "model"/);
});

test("validateModel throws when schema_version is not 2", () => {
  assert.throws(() => validateModel(validModelRecord({ schema_version: 1 })), /schema_version must be 2/);
});

test("validateModel throws on missing/empty family", () => {
  assert.throws(() => validateModel(validModelRecord({ family: "" })), /non-empty family/);
});

test("validateModel throws when feature node is missing or not an object", () => {
  assert.throws(() => validateModel(validModelRecord({ feature: undefined })), /feature node/);
  assert.throws(() => validateModel(validModelRecord({ feature: "not-an-object" })), /feature node/);
});

test("validateModel throws when model node is missing or not an object", () => {
  assert.throws(() => validateModel(validModelRecord({ model: undefined })), /model node/);
  assert.throws(() => validateModel(validModelRecord({ model: "not-an-object" })), /model node/);
});

// --- Lock A: scalar threshold, byte-identical to v1 evaluateExpected --------------------------
//
// Reuses the "constraint.daemon.interval_ms.min" seed (a plain gte constraint) as the fixture
// source. The v2 model is built as threshold(latest(fact(...))) over the SAME `expected` object,
// and evaluateExpected is the exact function called under the hood on both paths -- so any value
// for which v1 and v2 disagree would indicate the v2 wiring introduced drift, not that the math
// itself differs.

const intervalSeed = SEED_CONSTRAINTS.find((c) => c.id === "constraint.daemon.interval_ms.min");

test("Lock A setup: the seed constraint exists and is the gte shape this lock assumes", () => {
  assert.ok(intervalSeed, "constraint.daemon.interval_ms.min seed must exist");
  assert.deepEqual(intervalSeed.expected, { comparator: "gte", value: 1000 });
});

test("Lock A: v2 threshold(latest(fact)) is byte-identical to v1 evaluateExpected over the seed's own fixtures", () => {
  const model = validModelRecord({
    id: "model.daemon.interval_ms.min",
    family: intervalSeed.family,
    feature: { op: "latest", of: { op: "fact", name: intervalSeed.target } },
    model: { op: "threshold", expected: intervalSeed.expected },
  });
  validateModel(model);

  for (const fixture of intervalSeed.fixtures) {
    const value = fixture.input.interval_ms;
    const v1 = evaluateExpected(intervalSeed.expected, value);
    const v2 = evaluateModel(model, { [intervalSeed.target]: value });

    assert.equal(v1.satisfied, fixture.expect_match, `sanity: v1 disagrees with the seed's own fixture for value=${value}`);
    assert.equal(v2.supported, v1.supported, `supported mismatch for value=${value}`);
    assert.equal(v2.satisfied, v1.satisfied, `satisfied mismatch for value=${value}`);
    assert.equal(v2.satisfied, fixture.expect_match, `v2 disagrees with the seed's own fixture for value=${value}`);
  }
});

test("Lock A: byte-identical to v1 across extra values beyond the seed fixtures (boundary, float, non-finite, string-numeric)", () => {
  const model = validModelRecord({
    id: "model.daemon.interval_ms.min",
    family: intervalSeed.family,
    feature: { op: "latest", of: { op: "fact", name: intervalSeed.target } },
    model: { op: "threshold", expected: intervalSeed.expected },
  });

  // NB: `undefined` is deliberately excluded here -- it is indistinguishable from "fact absent"
  // in this map-based contract (mirroring v1's own factLookup(target)===undefined "no fact, no
  // claim" skip in evaluateConstraints), and isn't a realistic fact value anyway (facts come from
  // JSON, which has no undefined). `null` IS included since JSON can hold it.
  const extraValues = [0, -1, 999, 999.9999, 1000.0001, 1e9, "1500", "not-a-number", NaN, Infinity, -Infinity, null];
  for (const value of extraValues) {
    const v1 = evaluateExpected(intervalSeed.expected, value);
    const v2 = evaluateModel(model, { [intervalSeed.target]: value });
    assert.equal(v2.supported, v1.supported, `supported mismatch for value=${String(value)}`);
    if (v1.supported) {
      assert.equal(v2.satisfied, v1.satisfied, `satisfied mismatch for value=${String(value)}`);
    }
  }
});

// --- Lock B: zscore(window(ms, fact)) golden-equals a direct foldWelford+computeZScore --------
//
// Proves the windowed/series contract composes the existing primitives without drift: the v2
// node folds exactly the same ts-filtered points, in the same order, through the same functions
// the direct computation below uses.

test("Lock B: zscore(window(ms, fact)) matches a direct foldWelford+computeZScore over the identical windowed points", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const ms = 10 * 60 * 1000; // 10 minutes
  const series = [
    { ts: "2026-09-03T00:00:00.000Z", value: 10 },
    { ts: "2026-09-03T00:02:00.000Z", value: 12 },
    { ts: "2026-09-03T00:04:00.000Z", value: 9 },
    { ts: "2026-09-03T00:06:00.000Z", value: 20 },
    { ts: "2026-09-03T00:09:00.000Z", value: 11 }, // latest point within window
    { ts: "2026-07-01T00:00:00.000Z", value: 999 }, // far outside window -- must be excluded
  ];
  const stddevFloor = 0.5;

  const model = validModelRecord({
    id: "model.test.zscore",
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.rate" }, ms },
      stddevFloor,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });

  const verdict = evaluateModel(model, { "metric.rate": series }, { now });
  assert.equal(verdict.supported, true);

  // Golden computation: the same window filter, folded through the same shared primitives.
  const windowed = series
    .filter((p) => {
      const t = Date.parse(p.ts);
      return t <= now && t >= now - ms;
    })
    .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  assert.equal(windowed.length, 5, "sanity: the far-outside-window point must be excluded");

  const stats = windowed.reduce((acc, p) => foldWelford(acc, p.value), emptyWelfordStats());
  const latest = windowed[windowed.length - 1];
  const expectedZ = computeZScore(latest.value, stats.mean, stats.stddev, stddevFloor);

  assert.equal(verdict.value, expectedZ);
  assert.equal(verdict.satisfied, expectedZ >= 0);
});

test("Lock B: a differently-ordered (unsorted) input series folds to the same golden z-score", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const ms = 10 * 60 * 1000;
  const orderedSeries = [
    { ts: "2026-09-03T00:00:00.000Z", value: 10 },
    { ts: "2026-09-03T00:02:00.000Z", value: 12 },
    { ts: "2026-09-03T00:04:00.000Z", value: 9 },
    { ts: "2026-09-03T00:06:00.000Z", value: 20 },
    { ts: "2026-09-03T00:09:00.000Z", value: 11 },
  ];
  const shuffledSeries = [orderedSeries[3], orderedSeries[0], orderedSeries[4], orderedSeries[1], orderedSeries[2]];
  const stddevFloor = 0.5;

  const model = validModelRecord({
    id: "model.test.zscore.unsorted",
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.rate" }, ms },
      stddevFloor,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });

  const ordered = evaluateModel(model, { "metric.rate": orderedSeries }, { now });
  const shuffled = evaluateModel(model, { "metric.rate": shuffledSeries }, { now });
  assert.equal(shuffled.supported, true);
  assert.equal(shuffled.value, ordered.value);
});

// --- Missing-input -> silence semantics ---------------------------------------------------------

test("missing-input: an absent fact name silences the whole model (no fabricated value)", () => {
  const model = validModelRecord();
  const verdict = evaluateModel(model, {}); // "test.fact" is not present at all
  assert.deepEqual(verdict, { supported: false });
});

test("missing-input: an empty series silences latest/window/zscore", () => {
  const latestModel = validModelRecord({
    feature: { op: "latest", of: { op: "fact", name: "metric.empty" } },
  });
  assert.equal(evaluateModel(latestModel, { "metric.empty": [] }).supported, false);

  const windowModel = validModelRecord({
    feature: { op: "window", of: { op: "fact", name: "metric.empty" }, ms: 60_000 },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  assert.equal(evaluateModel(windowModel, { "metric.empty": [] }, { now: Date.now() }).supported, false);

  const zscoreModel = validModelRecord({
    feature: { op: "zscore", of: { op: "window", of: { op: "fact", name: "metric.empty" }, ms: 60_000 }, stddevFloor: 0.5 },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  assert.equal(evaluateModel(zscoreModel, { "metric.empty": [] }, { now: Date.now() }).supported, false);
});

test("missing-input: a window with too few points for zscore (sub-threshold sample count) silences, not a fabricated z-score", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const series = [{ ts: "2026-09-03T00:09:00.000Z", value: 42 }]; // only 1 point in range
  const model = validModelRecord({
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.short" }, ms: 60_000 },
      stddevFloor: 0.5,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  const verdict = evaluateModel(model, { "metric.short": series }, { now });
  assert.deepEqual(verdict, { supported: false });
});

test("missing-input: a non-finite value inside the selected window silences the zscore node, never fabricates", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const series = [
    { ts: "2026-09-03T00:08:00.000Z", value: 10 },
    { ts: "2026-09-03T00:09:00.000Z", value: NaN },
  ];
  const model = validModelRecord({
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.degraded" }, ms: 60_000 },
      stddevFloor: 0.5,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  const verdict = evaluateModel(model, { "metric.degraded": series }, { now });
  assert.deepEqual(verdict, { supported: false });
});

test("missing-input: window() on a scalar (not a series) input is unsupported -- cannot window a scalar", () => {
  const model = validModelRecord({
    feature: { op: "window", of: { op: "fact", name: "metric.scalar" }, ms: 60_000 },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  assert.equal(evaluateModel(model, { "metric.scalar": 42 }).supported, false);
});

test("missing-input: threshold on an unsupported feature never fires -- no satisfied/fired keys fabricated", () => {
  const model = validModelRecord({ feature: { op: "fact", name: "absent" } });
  const verdict = evaluateModel(model, {});
  assert.equal(verdict.supported, false);
  assert.equal(verdict.satisfied, undefined);
  assert.equal(verdict.fired, undefined);
});

test("threshold fires (satisfied:false -> fired:true) exactly when the underlying comparator is violated", () => {
  const model = validModelRecord(); // gte 1000
  const violating = evaluateModel(model, { "test.fact": 500 });
  assert.equal(violating.supported, true);
  assert.equal(violating.satisfied, false);
  assert.equal(violating.fired, true);

  const satisfying = evaluateModel(model, { "test.fact": 5000 });
  assert.equal(satisfying.supported, true);
  assert.equal(satisfying.satisfied, true);
  assert.equal(satisfying.fired, false);
});

// --- Security hardening (adversarial-review fix-spec M1-M7) ------------------------------------

test("M1: fact op resolves OWN properties only -- an inherited prototype property (e.g. \"toString\") does not resolve", () => {
  const model = validModelRecord({ feature: { op: "fact", name: "toString" } });
  const verdict = evaluateModel(model, {}); // {} inherits `toString` from Object.prototype
  assert.deepEqual(verdict, { supported: false });
});

test("M1: a real OWN scalar fact sharing a prototype-property name still resolves normally (Lock A intact)", () => {
  const model = validModelRecord({ feature: { op: "fact", name: "toString" } });
  const verdict = evaluateModel(model, { toString: 5000 }); // own property named "toString"
  assert.equal(verdict.supported, true);
  assert.equal(verdict.value, 5000);
});

test("M2: latest() of a series whose last point lacks a value silences rather than returning value:undefined", () => {
  const model = validModelRecord({
    feature: { op: "latest", of: { op: "fact", name: "metric.novalue" } },
  });
  const series = [{ ts: "2026-09-03T00:00:00.000Z" }]; // no `value` key at all
  const verdict = evaluateModel(model, { "metric.novalue": series });
  assert.deepEqual(verdict, { supported: false });
});

test("M3: window() rejects a coercible-but-non-numeric point value (null/[]/\"\"/false) instead of coercing it to 0", () => {
  // NB: tested directly via evaluateFeatureNode, not through evaluateModel/threshold -- window()
  // itself returns a `series`, and threshold rejects any non-scalar feature regardless, so routing
  // this through threshold would pass vacuously without ever exercising window()'s own gate.
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  for (const badValue of [null, [], "", false]) {
    // ms is wide enough to keep the single point inside the window on its own (not a minSamples
    // artifact -- window() has no minSamples concept, but a too-narrow ms could still exclude the
    // point entirely and mask the coercion gate under test).
    const series = [{ ts: "2026-09-03T00:09:00.000Z", value: badValue }];
    const node = { op: "window", of: { op: "fact", name: "metric.coerce" }, ms: 60_000 };
    const result = evaluateFeatureNode(node, { "metric.coerce": series }, { now });
    assert.deepEqual(result, { supported: false }, `expected silence for value=${JSON.stringify(badValue)}`);
  }
});

test("M3: zscore() rejects a coercible-but-non-numeric point value (null/[]/\"\"/false) instead of coercing it to 0", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  for (const badValue of [null, [], "", false]) {
    // ms is wide enough that BOTH points land in the window (a too-narrow ms would drop the first
    // point, leaving 1 point below zscore's default minSamples=2 -- silencing for an unrelated
    // reason and masking the coercion gate under test).
    const series = [
      { ts: "2026-09-03T00:08:00.000Z", value: 10 },
      { ts: "2026-09-03T00:09:00.000Z", value: badValue },
    ];
    const model = validModelRecord({
      feature: { op: "zscore", of: { op: "window", of: { op: "fact", name: "metric.coerce2" }, ms: 120_000 }, stddevFloor: 0.5 },
      model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
    });
    const verdict = evaluateModel(model, { "metric.coerce2": series }, { now });
    assert.deepEqual(verdict, { supported: false }, `expected silence for value=${JSON.stringify(badValue)}`);
  }
});

test("M4: zscore minSamples must be an integer >= 2 -- a fractional/zero/negative/NaN minSamples silences rather than being accepted", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const series = [
    { ts: "2026-09-03T00:08:00.000Z", value: 10 },
    { ts: "2026-09-03T00:09:00.000Z", value: 12 },
  ];
  for (const badMinSamples of [0, -1, 1.5, NaN]) {
    const model = validModelRecord({
      feature: {
        op: "zscore",
        of: { op: "window", of: { op: "fact", name: "metric.minsamp" }, ms: 60_000 },
        stddevFloor: 0.5,
        minSamples: badMinSamples,
      },
      model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
    });
    const verdict = evaluateModel(model, { "metric.minsamp": series }, { now });
    assert.deepEqual(verdict, { supported: false }, `expected silence for minSamples=${JSON.stringify(badMinSamples)}`);
  }
});

test("M4: zscore never throws even when minSamples is invalid and the series resolves to zero points (empty-guard before array deref)", () => {
  const model = validModelRecord({
    feature: { op: "zscore", of: { op: "fact", name: "metric.emptyseries" }, stddevFloor: 0.5, minSamples: 0 },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  assert.doesNotThrow(() => evaluateModel(model, { "metric.emptyseries": [] }));
  assert.deepEqual(evaluateModel(model, { "metric.emptyseries": [] }), { supported: false });
});

test("M6: zscore silences instead of returning a non-finite (overflow) statistic", () => {
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  // Both points must land in the window (see the M3 zscore test's comment on ms width) for this to
  // exercise the overflow path rather than silencing early on an unrelated sub-minSamples reason.
  const series = [
    { ts: "2026-09-03T00:08:00.000Z", value: Number.MAX_VALUE },
    { ts: "2026-09-03T00:09:00.000Z", value: -Number.MAX_VALUE },
  ];
  const model = validModelRecord({
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.overflow" }, ms: 120_000 },
      stddevFloor: 1e-300,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  const verdict = evaluateModel(model, { "metric.overflow": series }, { now });
  assert.deepEqual(verdict, { supported: false });
});

test("M7: an extremely deep feature-node chain silences rather than crashing the process (stack overflow)", () => {
  let node = { op: "fact", name: "test.fact" };
  for (let i = 0; i < 100_000; i++) node = { op: "latest", of: node };
  assert.doesNotThrow(() => evaluateFeatureNode(node, { "test.fact": 5 }));
  assert.deepEqual(evaluateFeatureNode(node, { "test.fact": 5 }), { supported: false });
});

test("M7: an ordinary shallow feature-node chain still evaluates normally (the depth cap does not shadow real graphs)", () => {
  const node = { op: "latest", of: { op: "latest", of: { op: "fact", name: "test.fact" } } };
  assert.deepEqual(evaluateFeatureNode(node, { "test.fact": 5 }), { supported: true, kind: "scalar", value: 5 });
});

// --- Security hardening ROUND 2 (daybreak-blue re-gate fix-spec: R7-dupts/R8-welford/R8-latest/
// R9/R10-cheap M-rows) -----------------------------------------------------------------------

test("R8-latest: latest() of a series whose last point holds a non-admissible value (null/[]/\"\"/false/Infinity/-Infinity/NaN/object) silences, never fabricates", () => {
  const badValues = [null, [], "", false, Infinity, -Infinity, NaN, {}];
  for (const badValue of badValues) {
    const model = validModelRecord({
      feature: { op: "latest", of: { op: "fact", name: "metric.latestbad" } },
    });
    const series = [{ ts: "2026-09-03T00:09:00.000Z", value: badValue }];
    const verdict = evaluateModel(model, { "metric.latestbad": series });
    assert.deepEqual(verdict, { supported: false }, `expected silence for value=${JSON.stringify(badValue)}`);
  }
});

test("R8-latest: latest() of a series whose last point holds a finite number or a non-empty string still resolves normally (does not over-silence)", () => {
  const numberModel = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.latestnum" } } });
  const numSeries = [{ ts: "2026-09-03T00:09:00.000Z", value: 42 }];
  const numVerdict = evaluateModel(numberModel, { "metric.latestnum": numSeries });
  assert.equal(numVerdict.supported, true);
  assert.equal(numVerdict.value, 42);

  const stringModel = validModelRecord({
    feature: { op: "latest", of: { op: "fact", name: "metric.lateststr" } },
    model: { op: "threshold", expected: { comparator: "eq", value: "ok" } },
  });
  const strSeries = [{ ts: "2026-09-03T00:09:00.000Z", value: "ok" }];
  const strVerdict = evaluateModel(stringModel, { "metric.lateststr": strSeries });
  assert.equal(strVerdict.supported, true);
  assert.equal(strVerdict.satisfied, true);
});

test("R8-welford: an overflowed Welford running state (extreme-magnitude points) silences the zscore node instead of laundering into a finite z-score via computeZScore's non-finite-mean-to-0 fallback", () => {
  // The exact daybreak repro: [-Number.MAX_VALUE, Number.MAX_VALUE] with stddevFloor:1. Without
  // the state check, foldWelford's running mean overflows to +/-Infinity, but computeZScore
  // silently substitutes 0 for a non-finite meanBefore -- producing a plausible-looking FINITE
  // z-score (Number.MAX_VALUE) that the pre-existing M6 result-finiteness check never catches.
  const now = Date.parse("2026-09-03T00:10:00.000Z");
  const series = [
    { ts: "2026-09-03T00:08:00.000Z", value: -Number.MAX_VALUE },
    { ts: "2026-09-03T00:09:00.000Z", value: Number.MAX_VALUE },
  ];
  const model = validModelRecord({
    feature: {
      op: "zscore",
      of: { op: "window", of: { op: "fact", name: "metric.welfordoverflow" }, ms: 120_000 },
      stddevFloor: 1,
    },
    model: { op: "threshold", expected: { comparator: "gte", value: 0 } },
  });
  const verdict = evaluateModel(model, { "metric.welfordoverflow": series }, { now });
  assert.deepEqual(verdict, { supported: false });
});

test("R7-dupts: equal-ts points sort deterministically regardless of input array order -- latest() picks the same value either way", () => {
  const tiedTs = "2026-09-03T00:09:00.000Z";
  const a = { ts: tiedTs, value: 5 };
  const b = { ts: tiedTs, value: 50 };
  const model = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.tiedts" } } });

  const forward = evaluateModel(model, { "metric.tiedts": [a, b] });
  const reversed = evaluateModel(model, { "metric.tiedts": [b, a] });
  assert.equal(forward.supported, true);
  assert.equal(reversed.supported, true);
  assert.equal(forward.value, reversed.value, "the same duplicate-ts pair must resolve to the same latest value regardless of array order");
  assert.equal(forward.value, 50, "tie-break is by numeric value, not by array position");
});

test("R7-dupts: equal-ts points holding DIFFERENT string values also sort deterministically regardless of input array order (not just numeric values)", () => {
  const tiedTs = "2026-09-03T00:09:00.000Z";
  const a = { ts: tiedTs, value: "a" };
  const b = { ts: tiedTs, value: "b" };
  const model = validModelRecord({
    feature: { op: "latest", of: { op: "fact", name: "metric.tiedts.str" } },
    model: { op: "threshold", expected: { comparator: "eq", value: "b" } },
  });

  const forward = evaluateModel(model, { "metric.tiedts.str": [a, b] });
  const reversed = evaluateModel(model, { "metric.tiedts.str": [b, a] });
  assert.equal(forward.supported, true);
  assert.equal(reversed.supported, true);
  assert.equal(forward.satisfied, reversed.satisfied, "the same duplicate-ts string pair must resolve the same way regardless of array order");
  assert.equal(forward.satisfied, true, "lexicographic tie-break ('a' < 'b') deterministically picks 'b' as latest, not array position");
});

test("R10-cheap M-rows: a series longer than MAX_SERIES_POINTS silences rather than processing unboundedly", () => {
  const start = Date.parse("2026-09-03T00:00:00.000Z");
  const oversized = Array.from({ length: MAX_SERIES_POINTS + 1 }, (_, i) => ({ ts: start + i, value: i }));
  const model = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.huge" } } });
  assert.deepEqual(evaluateModel(model, { "metric.huge": oversized }), { supported: false });
});

test("R10-cheap M-rows: a series exactly AT the cap still evaluates normally -- the cap does not shadow a legitimate large series", () => {
  const start = Date.parse("2026-09-03T00:00:00.000Z");
  const atCap = Array.from({ length: MAX_SERIES_POINTS }, (_, i) => ({ ts: start + i, value: i }));
  const model = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.atcap" } } });
  const verdict = evaluateModel(model, { "metric.atcap": atCap });
  assert.equal(verdict.supported, true);
  assert.equal(verdict.value, MAX_SERIES_POINTS - 1);
});

test("C2 daybreak repro: a Proxy-backed points array whose `.length` answers MAX_SERIES_POINTS on the cap check then a larger REAL value on iteration cannot bypass the cap", () => {
  const start = Date.parse("2026-09-03T00:00:00.000Z");
  const real = Array.from({ length: MAX_SERIES_POINTS + 1 }, (_, i) => ({ ts: start + i, value: i }));
  let lengthReads = 0;
  const proxy = new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === "length") {
        lengthReads += 1;
        // First read (the cap check, under the OLD code) answers AT the cap -- passes it. Any
        // later read answers the REAL (larger) length, which the old code's `.filter()` call would
        // separately re-trigger, processing one point past the cap.
        return lengthReads === 1 ? MAX_SERIES_POINTS : Reflect.get(target, prop, receiver);
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const model = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.proxycap" } } });
  const verdict = evaluateModel(model, { "metric.proxycap": proxy });
  assert.equal(verdict.supported, true, "the capped-length snapshot still evaluates normally -- MAX_SERIES_POINTS is not itself over the cap");
  assert.equal(verdict.value, MAX_SERIES_POINTS - 1, "only the FIRST (captured) length's worth of points was ever read -- the real, larger array is never consulted again");
  assert.equal(lengthReads, 1, "`.length` is read exactly once, never re-invoked to bypass the cap");
});

test("C3 daybreak repro: a boolean `false` point and a numeric `0` point at the same ts no longer tie via Number() coercion -- both input orders resolve identically", () => {
  const tiedTs = "2026-09-03T00:09:00.000Z";
  const numPoint = { ts: tiedTs, value: 0 };
  const boolPoint = { ts: tiedTs, value: false };
  const model = validModelRecord({ feature: { op: "latest", of: { op: "fact", name: "metric.falsezero" } } });

  const forward = evaluateModel(model, { "metric.falsezero": [boolPoint, numPoint] });
  const reversed = evaluateModel(model, { "metric.falsezero": [numPoint, boolPoint] });
  assert.deepEqual(forward, reversed, "the same duplicate-ts false/0 pair must resolve identically regardless of array order");
  // Deterministic outcome: `typeof` ranks "number" before "boolean", so the number point is always
  // the earlier (lower) one and the boolean point is always latest -- which is not an admissible
  // latest() value (R8-latest), so this silences either way, consistently.
  assert.deepEqual(forward, { supported: false });
});

test("R9: validateModel rejects a numeric id -- id must be a literal string, not merely coercible to a non-empty one", () => {
  assert.throws(() => validateModel(validModelRecord({ id: 7 })), /non-empty id/);
});

// --- Dual-read routing (evaluateRecord) --------------------------------------------------------

test("evaluateRecord routes kind:\"constraint\" through the unchanged v1 evaluateExpected path", () => {
  const factLookup = (target) => (target === intervalSeed.target ? 500 : undefined);
  const v1 = evaluateExpected(intervalSeed.expected, 500);
  const routed = evaluateRecord(intervalSeed, { factLookup });

  assert.equal(routed.supported, v1.supported);
  assert.equal(routed.satisfied, v1.satisfied);
  assert.equal(routed.fired, !v1.satisfied);
});

test("evaluateRecord returns unsupported for a kind:\"constraint\" record when factLookup yields undefined (no fact, no claim)", () => {
  const routed = evaluateRecord(intervalSeed, { factLookup: () => undefined });
  assert.deepEqual(routed, { supported: false });
});

test("evaluateRecord routes kind:\"model\" through evaluateModel using inputs.factSeries", () => {
  const model = validModelRecord();
  const routed = evaluateRecord(model, { factSeries: { "test.fact": 5000 } });
  assert.equal(routed.supported, true);
  assert.equal(routed.satisfied, true);
});

test("evaluateRecord is unsupported for an unrecognized record kind", () => {
  assert.deepEqual(evaluateRecord({ kind: "mystery" }, {}), { supported: false });
});
