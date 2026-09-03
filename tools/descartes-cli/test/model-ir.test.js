import assert from "node:assert/strict";
import test from "node:test";
import { evaluateExpected } from "../src/constraint-eval.js";
import { SEED_CONSTRAINTS } from "../src/constraint-store.js";
import { computeZScore, emptyWelfordStats, foldWelford } from "../src/welford-stats.js";
import { evaluateModel, evaluateRecord, validateModel } from "../src/model-ir.js";

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
