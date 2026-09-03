import assert from "node:assert/strict";
import test from "node:test";
import { evaluateModel } from "../src/model-ir.js";
import { decideModelDemotion, decideModelPromotion, runOracle } from "../src/model-ladder.js";

// Slice-1 behavioral-model spike, step 4 PURE core (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 4): offline tests for the seeded-oracle shadow -> notify-only promote/demote ladder.
// Same node:test / assert style as the rest of this suite; the changepoint/stable series fixture
// pattern is borrowed from test/model-ir-cusum.test.js (a deterministic baseline + an injected
// level-shift = seeded-bad, the same baseline repeated with no shift = seeded-good) but built
// locally here so this file stays self-contained (no cross-test-file import).

// --- Shared CUSUM changepoint fixture data --------------------------------------------------

const BASELINE = [10, 11, 9, 10, 12, 8, 10, 11, 9, 10, 12, 8, 10, 11, 9, 10];
const SHIFT = [30, 31, 29, 30, 32, 28, 30, 31, 29, 30];
const CP_TARGET = 10;
const CP_K = 5;
const CP_H = 50; // decision interval: the statistic should stay <= h -- the lte/fired convention.
// NB: evaluateNumericComparator (constraint-eval.js) only implements gte/lte/eq -- there is no
// "lt" comparator in this codebase's vocabulary, despite the plan text's "lt|lte" phrasing. "lte
// h" is the one that actually implements "stay below h": a crossing (statistic > h) violates
// satisfied:(value<=h) -> fired:true. See the fired-convention lock below.
const START_MS = Date.parse("2026-09-03T00:00:00.000Z");
const STEP_MS = 60_000;
const WINDOW_MS = (BASELINE.length + SHIFT.length + 5) * STEP_MS; // comfortably covers either series

function seriesFrom(values) {
  return values.map((value, i) => ({ ts: START_MS + i * STEP_MS, value }));
}

const BAD_SERIES = seriesFrom([...BASELINE, ...SHIFT]); // seeded-bad: injected level shift
const GOOD_SERIES = seriesFrom([...BASELINE, ...BASELINE.slice(0, SHIFT.length)]); // seeded-good: stable, same length

function cusumFeature() {
  return {
    op: "cusum",
    of: { op: "window", of: { op: "fact", name: "metric.load" }, ms: WINDOW_MS },
    target: CP_TARGET,
    k: CP_K,
  };
}

// A model whose oracle carries one seeded-bad (must fire) and one seeded-good (must stay quiet)
// fixture, authored per the plan's step-4 decision: `threshold { comparator:"lte", value:h }` --
// "stay below h" -- so a changepoint crossing is a violation -> fired:true.
function competentModel(overrides = {}) {
  return {
    id: "model.test.cusum-ladder",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    status: "shadow",
    feature: cusumFeature(),
    model: { op: "threshold", expected: { comparator: "lte", value: CP_H } },
    oracle: {
      fixtures: [
        { input: { "metric.load": BAD_SERIES }, expect_fire: true },
        { input: { "metric.load": GOOD_SERIES }, expect_fire: false },
      ],
    },
    ...overrides,
  };
}

// --- runOracle: competence, not survivorship ------------------------------------------------

test("runOracle: a competent model fires on seeded-bad and stays quiet on seeded-good -- passes", () => {
  const oracle = runOracle(competentModel());
  assert.equal(oracle.passed, true);
  assert.equal(oracle.total, 2);
  assert.equal(oracle.fired_on_bad, 1);
  assert.equal(oracle.quiet_on_good, 1);
  assert.deepEqual(oracle.results.map((r) => r.ok), [true, true]);
});

test("runOracle: an empty oracle fixture set fails closed (no evidence of competence)", () => {
  assert.deepEqual(runOracle(competentModel({ oracle: { fixtures: [] } })), {
    passed: false,
    total: 0,
    fired_on_bad: 0,
    quiet_on_good: 0,
    results: [],
  });
});

test("runOracle: a missing oracle fails closed the same way as an empty one", () => {
  const { oracle, ...withoutOracle } = competentModel();
  void oracle;
  assert.equal(runOracle(withoutOracle).passed, false);
});

test("runOracle: a degenerate model that never fires fails -- quiet on seeded-good is not enough, it must also fire on seeded-bad", () => {
  const neverFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } } });
  const oracle = runOracle(neverFires);
  assert.equal(oracle.passed, false);
  assert.equal(oracle.fired_on_bad, 0, "never fires, including on the seeded-bad fixture");
  assert.equal(oracle.quiet_on_good, 1, "quiet on seeded-good alone does not make it competent");
});

test("runOracle: a model that fires on seeded-good (false positive) fails, even though it also fires on seeded-bad", () => {
  const falsePositive = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: -1 } } });
  const oracle = runOracle(falsePositive);
  assert.equal(oracle.passed, false);
  assert.equal(oracle.fired_on_bad, 1, "still correctly fires on the seeded-bad fixture");
  assert.equal(oracle.quiet_on_good, 0, "but also fires on seeded-good -- a caught false positive");
});

// --- Closing the fail-open hole: "every present fixture agreed" is NOT sufficient -- the oracle
// must contain BOTH a caught seeded-bad AND a correctly-quiet seeded-good, or a never-fires (or
// always-fires) model could trivially "pass" an oracle that only ever tests one half. -----------

test("runOracle: an oracle built ONLY of seeded-good fixtures cannot promote a never-fires model (no seeded-bad evidence)", () => {
  const neverFires = competentModel({
    model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } },
    oracle: { fixtures: [{ input: { "metric.load": GOOD_SERIES }, expect_fire: false }] },
  });
  const oracle = runOracle(neverFires);
  assert.equal(oracle.results.every((r) => r.ok), true, "every present fixture individually agrees (quiet on the only fixture)");
  assert.equal(oracle.passed, false, "but zero seeded-bad fixtures means zero evidence the model can ever fire at all");
  assert.equal(oracle.fired_on_bad, 0);
  assert.equal(oracle.quiet_on_good, 1);
});

test("runOracle: an oracle built ONLY of seeded-bad fixtures cannot promote an always-fires model (no seeded-good evidence)", () => {
  const alwaysFires = competentModel({
    model: { op: "threshold", expected: { comparator: "lte", value: -1 } },
    oracle: { fixtures: [{ input: { "metric.load": BAD_SERIES }, expect_fire: true }] },
  });
  const oracle = runOracle(alwaysFires);
  assert.equal(oracle.results.every((r) => r.ok), true, "every present fixture individually agrees (fires on the only fixture)");
  assert.equal(oracle.passed, false, "but zero seeded-good fixtures means zero evidence the model can ever stay quiet");
  assert.equal(oracle.fired_on_bad, 1);
  assert.equal(oracle.quiet_on_good, 0);
});

test("runOracle: a fixture with a malformed (non-boolean) expect_fire fails closed, never silently folded into 'seeded-good'", () => {
  const model = competentModel({
    oracle: {
      fixtures: [
        { input: { "metric.load": BAD_SERIES }, expect_fire: true },
        { input: { "metric.load": GOOD_SERIES } }, // expect_fire missing entirely
      ],
    },
  });
  const oracle = runOracle(model);
  assert.equal(oracle.passed, false, "the malformed fixture cannot be silently treated as an agreeing seeded-good");
  assert.equal(oracle.results[1].ok, false);
});

// --- The fired/lte convention, locked (not just documented in a comment) ----------------------

test("fired convention: a naive gte-h framing does NOT fire on the changepoint (documents why lte is required)", () => {
  const gteModel = competentModel({ model: { op: "threshold", expected: { comparator: "gte", value: CP_H } } });
  const verdict = evaluateModel(gteModel, { "metric.load": BAD_SERIES });
  assert.equal(verdict.supported, true);
  assert.equal(verdict.satisfied, true, "the statistic does cross h");
  assert.equal(verdict.fired, false, "but fired = !satisfied inverts this -- a gte framing masks the changepoint");
});

test("fired convention: the lte-h framing DOES fire on the same changepoint", () => {
  const verdict = evaluateModel(competentModel(), { "metric.load": BAD_SERIES });
  assert.equal(verdict.supported, true);
  assert.equal(verdict.satisfied, false, "the statistic crosses h, violating 'stay below h'");
  assert.equal(verdict.fired, true, "-- correctly flagged as a changepoint");
});

// --- decideModelPromotion ----------------------------------------------------------------------

test("decideModelPromotion: competence + clean soak promotes shadow -> notify-only", () => {
  const [updated] = decideModelPromotion([competentModel()], { soakClean: true, now: "2026-09-03T12:00:00.000Z" });
  assert.equal(updated.status, "notify-only");
  assert.equal(updated.promotion_history.length, 1);
  assert.equal(updated.promotion_history[0].ts, "2026-09-03T12:00:00.000Z");
  assert.equal(updated.promotion_history[0].from, "shadow");
  assert.equal(updated.promotion_history[0].to, "notify-only");
  assert.equal(updated.promotion_history[0].actor, "seeded-oracle-gate");
});

test("decideModelPromotion: a never-fires model does NOT promote (survivorship rejected)", () => {
  const neverFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } } });
  const [updated] = decideModelPromotion([neverFires], { soakClean: true });
  assert.equal(updated, neverFires, "unchanged by reference -- no-op");
});

test("decideModelPromotion: an empty-oracle model does NOT promote", () => {
  const noEvidence = competentModel({ oracle: { fixtures: [] } });
  const [updated] = decideModelPromotion([noEvidence], { soakClean: true });
  assert.equal(updated, noEvidence);
});

test("decideModelPromotion: soakClean:false blocks promotion even when the oracle passes", () => {
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { soakClean: false });
  assert.equal(updated, model);
});

test("decideModelPromotion: a false-positive-on-seeded-good model does NOT promote", () => {
  const falsePositive = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: -1 } } });
  const [updated] = decideModelPromotion([falsePositive], { soakClean: true });
  assert.equal(updated, falsePositive);
});

test("decideModelPromotion: idempotent no-op on non-shadow statuses (draft/notify-only/active/retired)", () => {
  const others = ["draft", "notify-only", "active", "retired"].map((status) => competentModel({ id: `model.${status}`, status }));
  const updated = decideModelPromotion(others, { soakClean: true });
  updated.forEach((model, i) => assert.equal(model, others[i], `status:${others[i].status} must pass through by reference, unchanged`));
});

test("decideModelPromotion: does not mutate its input array or any input model", () => {
  const models = [competentModel()];
  const snapshotJson = JSON.stringify(models);
  decideModelPromotion(models, { soakClean: true });
  assert.equal(JSON.stringify(models), snapshotJson);
});

test("decideModelPromotion: the promotion-decision `now` (stamped into promotion_history) does not leak into the oracle's fixture evaluation", () => {
  // A `now` far outside every fixture's own series range (fixtures span 2026-09-03T00:00-00:25)
  // would, if forwarded straight into evaluateModel, empty every windowed feature via window()'s
  // own ms-radius filter -- turning a genuinely competent model's oracle run into false silence.
  // This must promote exactly as if `now` were omitted.
  const [updated] = decideModelPromotion([competentModel()], { soakClean: true, now: "2099-01-01T00:00:00.000Z" });
  assert.equal(updated.status, "notify-only");
  assert.equal(updated.promotion_history[0].ts, "2099-01-01T00:00:00.000Z", "the promotion-history stamp still uses the caller's now");
});

test("decideModelPromotion: appends to an existing promotion_history rather than replacing it", () => {
  const priorEntry = { ts: "2026-01-01T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "seed" };
  const model = competentModel({ promotion_history: [priorEntry] });
  const [updated] = decideModelPromotion([model], { soakClean: true, now: "2026-09-03T12:00:00.000Z" });
  assert.deepEqual(updated.promotion_history[0], priorEntry);
  assert.equal(updated.promotion_history.length, 2);
  assert.equal(updated.promotion_history[1].to, "notify-only");
});

// --- decideModelDemotion (the loop's other half) -----------------------------------------------

test("decideModelDemotion: a notify-only model observed firing on a seeded-good (caught false positive) demotes to shadow", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true }];
  const [updated] = decideModelDemotion([model], observations, { now: "2026-09-04T00:00:00.000Z" });
  assert.equal(updated.status, "shadow");
  assert.equal(updated.promotion_history.length, 1);
  assert.equal(updated.promotion_history[0].ts, "2026-09-04T00:00:00.000Z");
  assert.equal(updated.promotion_history[0].from, "notify-only");
  assert.equal(updated.promotion_history[0].to, "shadow");
  assert.equal(updated.promotion_history[0].actor, "seeded-oracle-gate");
});

test("decideModelDemotion: a notify-only model with no caught false positive in observations is untouched", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [
    { model_id: model.id, expect_fire: true, fired: true },
    { model_id: model.id, expect_fire: false, fired: false },
  ];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model, "no regression observed -- unchanged by reference");
});

test("decideModelDemotion: observations for a DIFFERENT model id do not demote this one", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: "some-other-model", expect_fire: false, fired: true }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model);
});

test("decideModelDemotion: idempotent no-op on non-notify-only statuses", () => {
  const others = ["draft", "shadow", "active", "retired"].map((status) => competentModel({ id: `model.${status}`, status }));
  const observations = others.map((m) => ({ model_id: m.id, expect_fire: false, fired: true }));
  const updated = decideModelDemotion(others, observations);
  updated.forEach((model, i) => assert.equal(model, others[i]));
});

test("decideModelDemotion: does not mutate its inputs", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true }];
  const modelSnapshot = JSON.stringify(model);
  const obsSnapshot = JSON.stringify(observations);
  decideModelDemotion([model], observations);
  assert.equal(JSON.stringify(model), modelSnapshot);
  assert.equal(JSON.stringify(observations), obsSnapshot);
});

// --- The promote/demote loop, end to end --------------------------------------------------------

test("promote then demote: a model earns notify-only, then a caught false positive sends it back to shadow", () => {
  const promoted = decideModelPromotion([competentModel()], { soakClean: true });
  assert.equal(promoted[0].status, "notify-only");

  const observations = [{ model_id: promoted[0].id, expect_fire: false, fired: true }];
  const demoted = decideModelDemotion(promoted, observations);
  assert.equal(demoted[0].status, "shadow");
  assert.equal(demoted[0].promotion_history.length, 2);
  assert.deepEqual(
    demoted[0].promotion_history.map((e) => `${e.from}->${e.to}`),
    ["shadow->notify-only", "notify-only->shadow"],
  );
});
