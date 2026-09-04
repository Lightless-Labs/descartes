import assert from "node:assert/strict";
import test from "node:test";
import { evaluateModel } from "../src/model-ir.js";
import { MAX_ORACLE_FIXTURES, decideModelDemotion, decideModelPromotion, runOracle } from "../src/model-ladder.js";

// Slice-1 behavioral-model spike, step 4 PURE core (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 4): offline tests for the seeded-oracle shadow -> notify-only promote/demote ladder.
// Same node:test / assert style as the rest of this suite; the changepoint/stable series fixture
// pattern is borrowed from test/model-ir-cusum.test.js (a deterministic baseline + an injected
// level-shift = seeded-bad, the same baseline repeated with no shift = seeded-good) but built
// locally here so this file stays self-contained (no cross-test-file import).
//
// fix-spec L1 (trust boundary): fixtures are a CALLER-SUPPLIED, trusted argument -- never read off
// `model.oracle.fixtures`. `competentModel()` below therefore carries NO `oracle` field at all (a
// model.oracle, if present, would be inert noise here -- and leaving it out means any regression
// that reintroduces reading `model.oracle.fixtures` shows up as an immediate failure, not a
// silently-passing coincidence). `competentFixtures()` is the trusted fixture set every test passes
// explicitly, either straight into runOracle or wrapped in a `{ [model.id]: fixtures }` map into
// decideModelPromotion.

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

// A model with no `oracle` field at all -- per fix-spec L1, trust never comes from the record.
// Authored per the plan's step-4 decision: `threshold { comparator:"lte", value:h }` -- "stay
// below h" -- so a changepoint crossing is a violation -> fired:true.
function competentModel(overrides = {}) {
  return {
    id: "model.test.cusum-ladder",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    status: "shadow",
    feature: cusumFeature(),
    model: { op: "threshold", expected: { comparator: "lte", value: CP_H } },
    ...overrides,
  };
}

// The trusted fixture set a caller (operator/harness) would supply for `competentModel()`: one
// seeded-bad (must fire), one seeded-good (must stay quiet).
function competentFixtures() {
  return [
    { input: { "metric.load": BAD_SERIES }, expect_fire: true },
    { input: { "metric.load": GOOD_SERIES }, expect_fire: false },
  ];
}

// A simpler scalar-threshold model (no CUSUM machinery) -- used by the round-3 C1 daybreak-repro
// tests below, where the point is what `model.model.expected.value` HOLDS (a live SharedArrayBuffer
// view, a Date instance), not the feature graph around it.
function simpleLatestModel(overrides = {}) {
  return {
    id: "model.test.simple-latest",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    status: "shadow",
    feature: { op: "latest", of: { op: "fact", name: "metric.value" } },
    model: { op: "threshold", expected: { comparator: "lte", value: 5 } },
    ...overrides,
  };
}

// --- runOracle: competence, not survivorship ------------------------------------------------

test("runOracle: a competent model fires on seeded-bad and stays quiet on seeded-good -- passes", () => {
  const oracle = runOracle(competentModel(), competentFixtures());
  assert.equal(oracle.passed, true);
  assert.equal(oracle.total, 2);
  assert.equal(oracle.fired_on_bad, 1);
  assert.equal(oracle.quiet_on_good, 1);
  assert.deepEqual(oracle.results.map((r) => r.ok), [true, true]);
});

test("runOracle: an empty fixture set fails closed (no evidence of competence)", () => {
  assert.deepEqual(runOracle(competentModel(), []), {
    passed: false,
    total: 0,
    fired_on_bad: 0,
    quiet_on_good: 0,
    results: [],
  });
});

test("runOracle: a missing/undefined fixture argument fails closed the same way as an empty one", () => {
  assert.equal(runOracle(competentModel(), undefined).passed, false);
});

test("runOracle: a degenerate model that never fires fails -- quiet on seeded-good is not enough, it must also fire on seeded-bad", () => {
  const neverFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } } });
  const oracle = runOracle(neverFires, competentFixtures());
  assert.equal(oracle.passed, false);
  assert.equal(oracle.fired_on_bad, 0, "never fires, including on the seeded-bad fixture");
  assert.equal(oracle.quiet_on_good, 1, "quiet on seeded-good alone does not make it competent");
});

test("runOracle: a model that fires on seeded-good (false positive) fails, even though it also fires on seeded-bad", () => {
  const falsePositive = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: -1 } } });
  const oracle = runOracle(falsePositive, competentFixtures());
  assert.equal(oracle.passed, false);
  assert.equal(oracle.fired_on_bad, 1, "still correctly fires on the seeded-bad fixture");
  assert.equal(oracle.quiet_on_good, 0, "but also fires on seeded-good -- a caught false positive");
});

// --- Closing the fail-open hole: "every present fixture agreed" is NOT sufficient -- the oracle
// must contain BOTH a caught seeded-bad AND a correctly-quiet seeded-good, or a never-fires (or
// always-fires) model could trivially "pass" an oracle that only ever tests one half. -----------

test("runOracle: a fixture set with ONLY seeded-good fixtures cannot promote a never-fires model (no seeded-bad evidence)", () => {
  const neverFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } } });
  const oracle = runOracle(neverFires, [{ input: { "metric.load": GOOD_SERIES }, expect_fire: false }]);
  assert.equal(oracle.results.every((r) => r.ok), true, "every present fixture individually agrees (quiet on the only fixture)");
  assert.equal(oracle.passed, false, "but zero seeded-bad fixtures means zero evidence the model can ever fire at all");
  assert.equal(oracle.fired_on_bad, 0);
  assert.equal(oracle.quiet_on_good, 1);
});

test("runOracle: a fixture set with ONLY seeded-bad fixtures cannot promote an always-fires model (no seeded-good evidence)", () => {
  const alwaysFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: -1 } } });
  const oracle = runOracle(alwaysFires, [{ input: { "metric.load": BAD_SERIES }, expect_fire: true }]);
  assert.equal(oracle.results.every((r) => r.ok), true, "every present fixture individually agrees (fires on the only fixture)");
  assert.equal(oracle.passed, false, "but zero seeded-good fixtures means zero evidence the model can ever stay quiet");
  assert.equal(oracle.fired_on_bad, 1);
  assert.equal(oracle.quiet_on_good, 0);
});

test("runOracle: a fixture with a malformed (non-boolean) expect_fire fails closed, never silently folded into 'seeded-good'", () => {
  const model = competentModel();
  const fixtures = [
    { input: { "metric.load": BAD_SERIES }, expect_fire: true },
    { input: { "metric.load": GOOD_SERIES } }, // expect_fire missing entirely
  ];
  const oracle = runOracle(model, fixtures);
  assert.equal(oracle.passed, false, "the malformed fixture cannot be silently treated as an agreeing seeded-good");
  assert.equal(oracle.results[1].ok, false);
});

// --- L2: an unsupported verdict must never count as a silent "quiet" pass ----------------------

test("L2: an unsupported verdict on a seeded-good fixture must not count as a silent 'quiet' pass", () => {
  const model = competentModel();
  const fixtures = [
    { input: { "metric.load": BAD_SERIES }, expect_fire: true }, // real seeded-bad, fires
    { input: {}, expect_fire: false }, // seeded-good whose fact is absent -> unsupported, NOT quiet
  ];
  const oracle = runOracle(model, fixtures);
  assert.equal(oracle.results[1].supported, false, "the second fixture's verdict must be unsupported");
  assert.equal(
    oracle.results[1].ok,
    false,
    "an unsupported verdict is not a silent agree, even though fired=false happens to equal expect_fire=false",
  );
  assert.equal(oracle.quiet_on_good, 0, "quiet_on_good must only count SUPPORTED quiet verdicts");
  assert.equal(oracle.passed, false, "no real evidence the model stays quiet on an actual seeded-good input");
});

// --- L3: a throwing fixture must not crash the batch --------------------------------------------

test("L3: a fixture that throws during evaluation does not crash the batch -- other fixtures still evaluate, and the throwing one scores as failing (not silently passing)", () => {
  const model = competentModel();
  // Object.hasOwn (model-ir.js's M1 own-property gate on the `fact` op) triggers the Proxy's
  // getOwnPropertyDescriptor trap -- this is a realistic throw site inside the interpreter, not a
  // contrived one.
  const throwingInput = new Proxy({}, {
    getOwnPropertyDescriptor() {
      throw new Error("boom");
    },
  });
  const fixtures = [...competentFixtures(), { input: throwingInput, expect_fire: true }];

  assert.doesNotThrow(() => runOracle(model, fixtures));
  const oracle = runOracle(model, fixtures);
  assert.equal(oracle.total, 3);
  assert.equal(oracle.results[0].ok, true, "the real seeded-bad fixture still evaluates normally");
  assert.equal(oracle.results[1].ok, true, "the real seeded-good fixture still evaluates normally");
  assert.equal(oracle.results[2].ok, false, "the throwing fixture is scored as failing, not silently passing");
  assert.equal(oracle.results[2].supported, false);
});

// --- L1: the trust boundary itself, locked -- fixtures come from the caller, never the record --

test("L1: a forged model.oracle.fixtures that would self-certify is IGNORED -- runOracle only ever sees the trusted argument", () => {
  // A model author ships fixtures inside the record that would trivially "pass" (always fires,
  // and the only oracle fixture is seeded-bad) -- if runOracle read `model.oracle.fixtures`, this
  // model would self-certify. It must not: the caller's trusted fixtures below are what actually
  // gets evaluated, and against THOSE the always-fires model fails (fires on seeded-good too).
  const forged = competentModel({
    model: { op: "threshold", expected: { comparator: "lte", value: -1 } }, // always fires
    oracle: { fixtures: [{ input: { "metric.load": BAD_SERIES }, expect_fire: true }] }, // forged self-cert
  });
  const trustedFixtures = competentFixtures(); // includes a seeded-good the forged set omits
  const oracle = runOracle(forged, trustedFixtures);
  assert.equal(oracle.total, trustedFixtures.length, "runOracle used the trusted argument's fixture count, not the forged one's");
  assert.equal(oracle.passed, false, "against the TRUSTED fixtures, the always-fires model is caught (fires on seeded-good)");

  const [updated] = decideModelPromotion([forged], { [forged.id]: trustedFixtures }, { soakClean: true });
  assert.equal(updated, forged, "unchanged by reference -- the forged self-cert did not promote it");
});

test("L1: a model with NO oracle field at all still promotes on trusted fixtures alone (the record's own field is irrelevant either way)", () => {
  const model = competentModel(); // no `oracle` key
  assert.equal("oracle" in model, false, "sanity: this model carries no oracle field");
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated.status, "notify-only");
});

test("L1: a valid shadow model with no entry in fixturesByModelId does not promote (no evidence)", () => {
  const model = competentModel();
  const [updated] = decideModelPromotion([model], {}, { soakClean: true });
  assert.equal(updated, model, "unchanged by reference -- no evidence, no promotion");
});

test("L1: a model.id equal to an inherited Object.prototype property name does not resolve an inherited (non-own) fixture entry", () => {
  // Mirrors model-ir.js's M1 own-property gate on the `fact` op, applied to the NEW
  // fixturesByModelId map: `{}.toString` resolves to Object.prototype.toString (a function), not
  // an own "fixtures array" -- decideModelPromotion must not mistake that for real evidence.
  const model = competentModel({ id: "toString" });
  const [updated] = decideModelPromotion([model], {}, { soakClean: true });
  assert.equal(updated, model, "unchanged by reference -- an inherited property is not a trusted fixture entry");
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
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true, now: "2026-09-03T12:00:00.000Z" });
  assert.equal(updated.status, "notify-only");
  assert.equal(updated.promotion_history.length, 1);
  assert.equal(updated.promotion_history[0].ts, "2026-09-03T12:00:00.000Z");
  assert.equal(updated.promotion_history[0].from, "shadow");
  assert.equal(updated.promotion_history[0].to, "notify-only");
  assert.equal(updated.promotion_history[0].actor, "seeded-oracle-gate");
});

test("decideModelPromotion: a never-fires model does NOT promote (survivorship rejected)", () => {
  const neverFires = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: 1_000_000 } } });
  const [updated] = decideModelPromotion([neverFires], { [neverFires.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated, neverFires, "unchanged by reference -- no-op");
});

test("decideModelPromotion: an empty-fixtures model does NOT promote", () => {
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { [model.id]: [] }, { soakClean: true });
  assert.equal(updated, model);
});

test("decideModelPromotion: soakClean:false blocks promotion even when the oracle passes", () => {
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: false });
  assert.equal(updated, model);
});

test("decideModelPromotion: a false-positive-on-seeded-good model does NOT promote", () => {
  const falsePositive = competentModel({ model: { op: "threshold", expected: { comparator: "lte", value: -1 } } });
  const [updated] = decideModelPromotion([falsePositive], { [falsePositive.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated, falsePositive);
});

test("decideModelPromotion: idempotent no-op on non-shadow statuses (draft/notify-only/active/retired)", () => {
  const others = ["draft", "notify-only", "active", "retired"].map((status) => competentModel({ id: `model.${status}`, status }));
  const fixturesByModelId = Object.fromEntries(others.map((m) => [m.id, competentFixtures()]));
  const updated = decideModelPromotion(others, fixturesByModelId, { soakClean: true });
  updated.forEach((model, i) => assert.equal(model, others[i], `status:${others[i].status} must pass through by reference, unchanged`));
});

test("decideModelPromotion: does not mutate its input array or any input model", () => {
  const model = competentModel();
  const models = [model];
  const snapshotJson = JSON.stringify(models);
  decideModelPromotion(models, { [model.id]: competentFixtures() }, { soakClean: true });
  assert.equal(JSON.stringify(models), snapshotJson);
});

test("decideModelPromotion: the promotion-decision `now` (stamped into promotion_history) does not leak into the oracle's fixture evaluation", () => {
  // A `now` far outside every fixture's own series range (fixtures span 2026-09-03T00:00-00:25)
  // would, if forwarded straight into evaluateModel, empty every windowed feature via window()'s
  // own ms-radius filter -- turning a genuinely competent model's oracle run into false silence.
  // This must promote exactly as if `now` were omitted.
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true, now: "2099-01-01T00:00:00.000Z" });
  assert.equal(updated.status, "notify-only");
  assert.equal(updated.promotion_history[0].ts, "2099-01-01T00:00:00.000Z", "the promotion-history stamp still uses the caller's now");
});

test("decideModelPromotion: appends to an existing promotion_history rather than replacing it", () => {
  const priorEntry = { ts: "2026-01-01T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "seed" };
  const model = competentModel({ promotion_history: [priorEntry] });
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true, now: "2026-09-03T12:00:00.000Z" });
  assert.deepEqual(updated.promotion_history[0], priorEntry);
  assert.equal(updated.promotion_history.length, 2);
  assert.equal(updated.promotion_history[1].to, "notify-only");
});

// --- L5(a): validateModel gate -------------------------------------------------------------------

test("L5(a): an invalid record (missing id) is skipped by decideModelPromotion -- never promoted, never thrown", () => {
  const invalid = competentModel({ id: "" });
  assert.doesNotThrow(() => decideModelPromotion([invalid], { "": competentFixtures() }, { soakClean: true }));
  const [updated] = decideModelPromotion([invalid], { "": competentFixtures() }, { soakClean: true });
  assert.equal(updated, invalid);
});

test("L5(a): an invalid record (wrong kind) is skipped by decideModelPromotion", () => {
  const invalid = competentModel({ kind: "constraint" });
  const [updated] = decideModelPromotion([invalid], { [invalid.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated, invalid);
});

// --- L4: deep-clone on transition -- no aliasing with the input record ---------------------------

test("L4: the promoted record shares no mutable nested state with the input -- mutating one does not affect the other", () => {
  const model = competentModel();
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated.status, "notify-only");
  assert.notEqual(updated.feature, model.feature, "feature must not be the same reference");
  assert.notEqual(updated.model, model.model, "model node must not be the same reference");

  updated.feature.op = "MUTATED";
  assert.equal(model.feature.op, "cusum", "mutating the promoted record's feature must not affect the original");
});

// --- decideModelDemotion (the loop's other half) -----------------------------------------------

test("decideModelDemotion: a notify-only model observed firing on a seeded-good (caught false positive) demotes to shadow", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: true }];
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
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: true }];
  const modelSnapshot = JSON.stringify(model);
  const obsSnapshot = JSON.stringify(observations);
  decideModelDemotion([model], observations);
  assert.equal(JSON.stringify(model), modelSnapshot);
  assert.equal(JSON.stringify(observations), obsSnapshot);
});

// --- L5(b): valid-id requirement, both sides of the match -----------------------------------------

test("L5(b): a notify-only model with no id (undefined) is never demoted, even by an observation with a matching undefined model_id", () => {
  const model = competentModel({ status: "notify-only" });
  delete model.id;
  const observations = [{ model_id: undefined, expect_fire: false, fired: true }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model, "undefined===undefined must NOT be treated as a matching identity");
});

test("L5(b): a notify-only model with an empty-string id is never demoted", () => {
  const model = competentModel({ status: "notify-only", id: "" });
  const observations = [{ model_id: "", expect_fire: false, fired: true }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model);
});

test("L5(b): an observation whose model_id is not a non-empty string is ignored, even for a model with a valid id", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [
    { model_id: undefined, expect_fire: false, fired: true },
    { model_id: 42, expect_fire: false, fired: true },
    { model_id: "", expect_fire: false, fired: true },
  ];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model, "none of these malformed model_ids may match a real model");
});

// --- L6: the boiling-frog trigger -- a caught false-negative also demotes -------------------------

test("L6: a notify-only model observed failing to fire on a seeded-bad observation (caught false negative) demotes to shadow", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: true, fired: false, supported: true }];
  const [updated] = decideModelDemotion([model], observations, { now: "2026-09-04T00:00:00.000Z" });
  assert.equal(updated.status, "shadow");
  assert.equal(updated.promotion_history[0].from, "notify-only");
  assert.equal(updated.promotion_history[0].to, "shadow");
  assert.match(updated.promotion_history[0].note, /false.negative/i);
});

test("L6: a false-negative observation for a DIFFERENT model id does not demote this one", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: "some-other-model", expect_fire: true, fired: false }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model);
});

test("L6: when both a false-positive AND a false-negative are caught for the same model, the false-positive note takes precedence", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [
    { model_id: model.id, expect_fire: false, fired: true, supported: true }, // false positive
    { model_id: model.id, expect_fire: true, fired: false, supported: true }, // false negative
  ];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated.status, "shadow");
  assert.match(updated.promotion_history[0].note, /false.positive/i);
});

// --- L4: deep-clone on demotion transition too --------------------------------------------------

test("L4: the demoted record shares no mutable nested state with the input -- mutating one does not affect the other", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: true }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated.status, "shadow");
  assert.notEqual(updated.feature, model.feature, "feature must not be the same reference");

  updated.feature.op = "MUTATED";
  assert.equal(model.feature.op, "cusum", "mutating the demoted record's feature must not affect the original");
});

// --- The promote/demote loop, end to end --------------------------------------------------------

test("promote then demote: a model earns notify-only, then a caught false positive sends it back to shadow", () => {
  const model = competentModel();
  const promoted = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true });
  assert.equal(promoted[0].status, "notify-only");

  const observations = [{ model_id: promoted[0].id, expect_fire: false, fired: true, supported: true }];
  const demoted = decideModelDemotion(promoted, observations);
  assert.equal(demoted[0].status, "shadow");
  assert.equal(demoted[0].promotion_history.length, 2);
  assert.deepEqual(
    demoted[0].promotion_history.map((e) => `${e.from}->${e.to}`),
    ["shadow->notify-only", "notify-only->shadow"],
  );
});

// --- Security hardening ROUND 2 (daybreak-blue re-gate fix-spec: R1/R3-supported/R6/R9+dup-id/
// R10-cheap) ------------------------------------------------------------------------------------

// --- R1: the stateful-accessor TOCTOU, closed by canonicalizing to ONE snapshot up front --------

test("R1: a stateful getter on feature.op cannot pass the oracle as one op then promote as a different, blind object (TOCTOU)", () => {
  // Daybreak's exact repro shape: a getter that answers "latest" for the oracle's own reads, then
  // "unknown" on a LATER, separate read -- which is exactly what a second structuredClone() call
  // (made only to build the promoted record, after the oracle already ran on the original) would
  // trigger. With the fix, there is only ONE structuredClone read (up front), and the oracle grades
  // that same frozen snapshot -- so the getter is read exactly once, period.
  let reads = 0;
  const featureNode = { of: { op: "fact", name: "metric.load" } };
  Object.defineProperty(featureNode, "op", {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= 2 ? "latest" : "unknown";
    },
  });
  const model = {
    id: "model.toctou",
    kind: "model",
    schema_version: 2,
    family: "test-family",
    status: "shadow",
    feature: featureNode,
    model: { op: "threshold", expected: { comparator: "gte", value: 5 } },
  };
  const fixtures = [
    { input: { "metric.load": 10 }, expect_fire: false }, // latest(10) >= 5 -> satisfied -> quiet -- seeded-good
    { input: { "metric.load": 1 }, expect_fire: true }, // latest(1) >= 5 -> violated -> fired -- seeded-bad
  ];
  const [updated] = decideModelPromotion([model], { [model.id]: fixtures }, { soakClean: true });
  assert.equal(updated.status, "notify-only", "the oracle DOES pass -- both fixture evaluations see the SAME (single-read) op value");
  assert.equal(
    updated.feature.op,
    "latest",
    "the PROMOTED record's op must be the exact value the oracle actually graded, not a later, different getter read",
  );
});

// --- R1/R4: a bad record never aborts the whole batch -------------------------------------------
//
// NOTE (round-3 judgment call): round 2's "uncloneable" trigger was a function-valued field, which
// threw a structuredClone DataCloneError. Round 3 replaces structuredClone with a JSON round-trip
// (canonicalizePlain), which does NOT throw on a function-valued property -- JSON.stringify simply
// DROPS it and serializes everything else (see canonicalizePlain's doc comment in model-ladder.js).
// The genuine "cannot be canonicalized" trigger under a JSON round-trip is a CIRCULAR REFERENCE
// (JSON.stringify throws a TypeError), so the two tests below now use that instead -- see the
// dedicated test further down documenting the function-field-drop behavior explicitly.

test("C1: a circular-reference record (JSON.stringify throws) does not abort the promotion batch -- a sibling record still promotes normally", () => {
  const good = competentModel({ id: "model.good.circular.promo" });
  const circular = competentModel({ id: "model.circular.promo" });
  circular.extra = circular; // self-reference -- JSON.stringify throws "Converting circular structure to JSON"
  const fixturesByModelId = { [good.id]: competentFixtures(), [circular.id]: competentFixtures() };
  let updated;
  assert.doesNotThrow(() => {
    updated = decideModelPromotion([good, circular], fixturesByModelId, { soakClean: true });
  });
  assert.equal(updated[0].status, "notify-only", "the good record still promotes despite a circular sibling in the same batch");
  assert.equal(updated[1], circular, "the circular record itself is skipped, unchanged, by reference -- canonicalizePlain fails closed on a JSON.stringify throw");
});

test("R1/R4: a non-array promotion_history (a TypeError source at the [...history] spread) does not abort the promotion batch", () => {
  const good = competentModel({ id: "model.good.badhistory.promo" });
  const badHistory = competentModel({ id: "model.badhistory.promo", promotion_history: {} });
  const fixturesByModelId = { [good.id]: competentFixtures(), [badHistory.id]: competentFixtures() };
  let updated;
  assert.doesNotThrow(() => {
    updated = decideModelPromotion([good, badHistory], fixturesByModelId, { soakClean: true });
  });
  assert.equal(updated[0].status, "notify-only");
  assert.equal(updated[1], badHistory, "unchanged by reference -- a non-array promotion_history skips the record instead of throwing");
});

test("C1: decideModelDemotion does not abort the batch when sibling records have a circular reference or a non-array promotion_history", () => {
  const good = competentModel({ id: "model.good.demo", status: "notify-only" });
  const circular = competentModel({ id: "model.circular.demo", status: "notify-only" });
  circular.extra = circular;
  const badHistory = competentModel({ id: "model.badhistory.demo", status: "notify-only", promotion_history: {} });
  const observations = [
    { model_id: good.id, expect_fire: false, fired: true, supported: true },
    { model_id: circular.id, expect_fire: false, fired: true, supported: true },
    { model_id: badHistory.id, expect_fire: false, fired: true, supported: true },
  ];
  let updated;
  assert.doesNotThrow(() => {
    updated = decideModelDemotion([good, circular, badHistory], observations);
  });
  assert.equal(updated[0].status, "shadow");
  assert.equal(updated[1], circular, "unchanged by reference");
  assert.equal(updated[2], badHistory, "unchanged by reference");
});

test("C1 judgment call: a function-valued field is silently DROPPED by the JSON round-trip (not a throw) -- the record canonicalizes and promotes normally", () => {
  // Unlike structuredClone (round 2), which threw a DataCloneError on any function-valued field
  // anywhere in the record, JSON.stringify simply omits a function-valued property from its output
  // -- this is not a failure, just data loss for a field nothing here ever reads. A record that
  // happens to carry a function field (e.g. stray tooling metadata) must still promote normally,
  // not be treated as hostile/invalid.
  const model = competentModel({ extra: { fn() {}, keep: "value" } });
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true });
  assert.equal(updated.status, "notify-only", "a function-valued nested field must not block promotion -- it is silently dropped, not an error");
  assert.equal(updated.extra.keep, "value", "sibling plain-data fields survive the round-trip normally");
  assert.equal("fn" in updated.extra, false, "the function-valued property itself is gone after the JSON round-trip");
});

// --- R1: opts.note must be a literal string -- never a caller-aliased object --------------------

test("R1: opts.note for promotion must be a literal string -- a non-string note is never stored, the default note is used instead", () => {
  const model = competentModel();
  const noteObj = { toString: () => "malicious-alias" };
  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, { soakClean: true, note: noteObj });
  assert.equal(typeof updated.promotion_history[0].note, "string");
  assert.notEqual(updated.promotion_history[0].note, noteObj);
  assert.match(updated.promotion_history[0].note, /seeded oracle passed/);
});

test("R1: opts.note for demotion must be a literal string -- a non-string note is never stored, the default note is used instead", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: true }];
  const noteObj = { toString: () => "malicious-alias" };
  const [updated] = decideModelDemotion([model], observations, { note: noteObj });
  assert.equal(typeof updated.promotion_history[0].note, "string");
  assert.notEqual(updated.promotion_history[0].note, noteObj);
  assert.match(updated.promotion_history[0].note, /false.positive/i);
});

// --- R6: a throwing fixture-level getter never aborts the oracle batch --------------------------

test("R6: a throwing getter on a fixture's own expect_fire property does not abort the oracle batch -- other fixtures still evaluate, the throwing one scores as failing", () => {
  const model = competentModel();
  const throwingFixture = {};
  Object.defineProperty(throwingFixture, "expect_fire", {
    enumerable: true,
    get() {
      throw new Error("boom-expect-fire");
    },
  });
  const fixtures = [...competentFixtures(), throwingFixture];

  let oracle;
  assert.doesNotThrow(() => {
    oracle = runOracle(model, fixtures);
  });
  assert.equal(oracle.total, 3);
  assert.equal(oracle.results[0].ok, true, "the real seeded-bad fixture still evaluates normally");
  assert.equal(oracle.results[1].ok, true, "the real seeded-good fixture still evaluates normally");
  assert.equal(oracle.results[2].ok, false, "the throwing fixture is scored as failing, not silently passing");
  assert.equal(oracle.results[2].supported, false);
});

test("R6: a throwing getter on a fixture's own input property does not abort the oracle batch", () => {
  const model = competentModel();
  const throwingFixture = { expect_fire: true };
  Object.defineProperty(throwingFixture, "input", {
    enumerable: true,
    get() {
      throw new Error("boom-input");
    },
  });
  const fixtures = [...competentFixtures(), throwingFixture];

  let oracle;
  assert.doesNotThrow(() => {
    oracle = runOracle(model, fixtures);
  });
  assert.equal(oracle.total, 3);
  assert.equal(oracle.results[2].ok, false);
  assert.equal(oracle.results[2].supported, false);
});

// --- R9 + dup-id: numeric id already covered in model-ir.test.js; here, the duplicate-id gate ---

test("R9 dup-id: two models sharing the same id in one decideModelPromotion call are BOTH left untouched (a collision can never let one call act on more than one record)", () => {
  const dupId = "model.duplicate.promo";
  const modelA = competentModel({ id: dupId });
  const modelB = competentModel({ id: dupId });
  const [updatedA, updatedB] = decideModelPromotion([modelA, modelB], { [dupId]: competentFixtures() }, { soakClean: true });
  assert.equal(updatedA, modelA, "unchanged by reference -- colliding id, never acted on");
  assert.equal(updatedB, modelB, "unchanged by reference -- colliding id, never acted on");
});

test("R9 dup-id: two notify-only models sharing the same id are BOTH left untouched even when an observation matches that id (one observation must never quarantine multiple records)", () => {
  const dupId = "model.duplicate.demo";
  const modelA = competentModel({ id: dupId, status: "notify-only" });
  const modelB = competentModel({ id: dupId, status: "notify-only" });
  const observations = [{ model_id: dupId, expect_fire: false, fired: true, supported: true }];
  const [updatedA, updatedB] = decideModelDemotion([modelA, modelB], observations);
  assert.equal(updatedA, modelA);
  assert.equal(updatedB, modelB);
});

// --- R10-cheap: runOracle's fixture-count cap ----------------------------------------------------

test("R10-cheap: runOracle caps fixtures at MAX_ORACLE_FIXTURES -- beyond the cap it fails closed instead of doing unbounded work", () => {
  const model = competentModel();
  const oversized = Array.from({ length: MAX_ORACLE_FIXTURES + 1 }, () => ({ input: { "metric.load": BAD_SERIES }, expect_fire: true }));
  const oracle = runOracle(model, oversized);
  assert.deepEqual(oracle, { passed: false, total: 0, fired_on_bad: 0, quiet_on_good: 0, results: [] });
});

test("R10-cheap: runOracle at exactly MAX_ORACLE_FIXTURES still evaluates normally -- the cap does not shadow a legitimate large fixture set", () => {
  const model = competentModel();
  const fixtures = [
    { input: { "metric.load": BAD_SERIES }, expect_fire: true },
    ...Array.from({ length: MAX_ORACLE_FIXTURES - 2 }, () => ({ input: { "metric.load": GOOD_SERIES }, expect_fire: false })),
    { input: { "metric.load": GOOD_SERIES }, expect_fire: false },
  ];
  assert.equal(fixtures.length, MAX_ORACLE_FIXTURES);
  const oracle = runOracle(model, fixtures);
  assert.equal(oracle.passed, true);
});

test("C2 daybreak repro: a Proxy-backed fixtures array whose `.length` answers MAX_ORACLE_FIXTURES on the cap check then a larger REAL value on iteration cannot process more than the cap (model-ladder's fixtures-array analogue of model-ir.js's C2)", () => {
  const real = Array.from({ length: MAX_ORACLE_FIXTURES + 1 }, () => ({ input: { "metric.load": GOOD_SERIES }, expect_fire: false }));
  let lengthReads = 0;
  const proxy = new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === "length") {
        lengthReads += 1;
        return lengthReads === 1 ? MAX_ORACLE_FIXTURES : Reflect.get(target, prop, receiver);
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const model = competentModel();
  const oracle = runOracle(model, proxy);
  assert.equal(oracle.total, MAX_ORACLE_FIXTURES, "exactly the capped count is processed, never the underlying array's real (larger) length");
  assert.equal(lengthReads, 1, "fixtures.length is read exactly once, not re-read during iteration");
});

// --- R3-supported: an unsupported observation is never evidence for demotion --------------------

test("R3-supported: an unsupported observation (supported:false) does not count as a caught false-positive", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: false }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model, "unsupported observation is not evidence -- unchanged by reference");
});

test("R3-supported: an unsupported observation (supported:false) does not count as a caught false-negative", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: true, fired: false, supported: false }];
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model);
});

test("R3-supported: an observation missing `supported` entirely is treated the same as supported:false -- not evidence", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true }]; // no `supported` key at all
  const [updated] = decideModelDemotion([model], observations);
  assert.equal(updated, model);
});

// --- C1 daybreak repros (round 3): non-plain types and cross-read aliasing --------------------

test("C1 daybreak repro: a SharedArrayBuffer-backed expected.value can no longer numerically coerce past the oracle -- canonicalization runs BEFORE grading, so it fails closed instead of promoting on a live-memory alias (Blocker 1)", () => {
  const sab = new SharedArrayBuffer(4);
  const view = new Int32Array(sab);
  view[0] = 5; // would-be threshold at grading time
  const model = simpleLatestModel({
    id: "model.sab.repro",
    model: { op: "threshold", expected: { comparator: "lte", value: view } },
  });
  const fixtures = [
    { input: { "metric.value": 10 }, expect_fire: true }, // 10 > 5 -> fired
    { input: { "metric.value": 1 }, expect_fire: false }, // 1 <= 5 -> quiet
  ];
  const [updated] = decideModelPromotion([model], { [model.id]: fixtures }, { soakClean: true });
  assert.equal(
    updated,
    model,
    "unchanged by reference -- a live-memory-backed expected.value is canonicalized to inert plain data (an index-keyed object, not a number) BEFORE grading, so it can never numerically coerce its way to a passing oracle verdict",
  );

  // Sanity: the ORIGINAL (uncanonicalized) view really does coerce numerically -- this is exactly
  // what round 2's structuredClone-based canonicalization left in place after "cloning" (a
  // SharedArrayBuffer is explicitly NOT deep-copied by the structured-clone algorithm), letting a
  // later write on another thread flip a promoted record's evaluated behavior with no further
  // JS-level read of the "cloned" object at all.
  assert.equal(Number(view), 5);
  assert.equal(evaluateModel(model, { "metric.value": 10 }).fired, true, "the original record (never promoted here) still evaluates numerically -- only the ladder's own canonicalized snapshot is protected");
});

test("C1 daybreak repro: a Date-valued expected.value goes inert (a non-numeric ISO string) upon canonicalization -- the model fails closed rather than promoting on a value that would evaluate differently once actually persisted", () => {
  const model = simpleLatestModel({
    id: "model.date.repro",
    model: { op: "threshold", expected: { comparator: "lte", value: new Date(5) } },
  });
  const fixtures = [
    { input: { "metric.value": 10 }, expect_fire: true },
    { input: { "metric.value": 1 }, expect_fire: false },
  ];
  const [updated] = decideModelPromotion([model], { [model.id]: fixtures }, { soakClean: true });
  assert.equal(
    updated,
    model,
    "unchanged by reference -- once canonicalized to its persisted ISO-string form, a Date-valued expected.value no longer numerically coerces, so the oracle has zero evidence either way",
  );

  // Sanity: the ORIGINAL Date instance really does coerce numerically -- this is exactly what a
  // structuredClone-based canonicalization (which preserves Date instances as live Date objects)
  // would have graded against, only for that SAME record to go inert (a plain ISO string) the
  // moment it is actually persisted as JSON and reloaded -- a divergence between what was graded
  // and what the persisted record will actually evaluate as.
  assert.equal(Number(new Date(5)), 5);
  assert.equal(evaluateModel(model, { "metric.value": 10 }).fired, true);
});

test("C1 daybreak repro (Blocker 2): a model's own getter cannot rewrite its trusted fixture-map entry mid-batch to self-certify -- the fixture map is frozen ONCE, before any model's own fields are ever read", () => {
  const hostileId = "model.hostile.blocker2";
  const failingFixtures = [
    { input: { "metric.value": 1 }, expect_fire: false }, // seeded-good ONLY -- no seeded-bad evidence, can never pass on its own
  ];
  const passingFixtures = [
    { input: { "metric.value": 10 }, expect_fire: true },
    { input: { "metric.value": 1 }, expect_fire: false },
  ];
  const fixturesByModelId = { [hostileId]: failingFixtures };

  const hostileModel = simpleLatestModel({ id: hostileId });
  let statusReads = 0;
  Object.defineProperty(hostileModel, "status", {
    enumerable: true,
    get() {
      statusReads += 1;
      // A SIDE EFFECT fired during THIS model's own canonicalization (JSON.stringify reads every
      // enumerable own property, including this one, exactly once): rewrite the SAME fixture-map
      // entry this model itself will be graded against, swapping failing evidence for passing --
      // an attempted self-certification.
      fixturesByModelId[hostileId] = passingFixtures;
      return "shadow";
    },
  });

  const [updated] = decideModelPromotion([hostileModel], fixturesByModelId, { soakClean: true });
  assert.equal(
    updated,
    hostileModel,
    "unchanged by reference -- the fixture map was already canonicalized (frozen) before this model's own getter could ever run, so the poisoning attempt has no effect",
  );
  assert.equal(statusReads, 1, "the getter still runs (JSON.stringify reads every enumerable property once) -- it just runs too late to matter");
});

test("C1 daybreak repro: an observation's own model_id getter cannot answer 'decoy' for the eligibility filter and the victim's real id for the trigger set (TOCTOU) -- observations are canonicalized ONCE, before any field is read even once", () => {
  const victim = competentModel({ id: "model.obs.victim", status: "notify-only" });
  let modelIdReads = 0;
  const hostileObs = { expect_fire: false, fired: true, supported: true };
  Object.defineProperty(hostileObs, "model_id", {
    enumerable: true,
    get() {
      modelIdReads += 1;
      return modelIdReads === 1 ? "decoy-id-that-is-not-real" : victim.id;
    },
  });

  const [updated] = decideModelDemotion([victim], [hostileObs]);
  assert.equal(
    updated,
    victim,
    "unchanged by reference -- the getter's FIRST (and only) answer ('decoy') is the ONE consulted consistently for both the eligibility check and the trigger set",
  );
  assert.equal(modelIdReads, 1, "model_id is read exactly once (via the observations array's own JSON round-trip), not once per separate access site");
});

test("C1 daybreak repro: opts.note is read exactly once -- a getter cannot answer a real string for the type-check and something else for the stored value", () => {
  const model = competentModel();
  let noteReads = 0;
  const opts = { soakClean: true };
  Object.defineProperty(opts, "note", {
    enumerable: true,
    get() {
      noteReads += 1;
      return noteReads === 1 ? "first-read-note" : { poisoned: true };
    },
  });

  const [updated] = decideModelPromotion([model], { [model.id]: competentFixtures() }, opts);
  assert.equal(updated.promotion_history[0].note, "first-read-note", "the note actually stored must be exactly what the FIRST (and only) read returned");
  assert.equal(typeof updated.promotion_history[0].note, "string");
  assert.equal(noteReads, 1, "opts.note is read exactly once");
});

test("C1 daybreak repro: opts.note is read exactly once for demotion too", () => {
  const model = competentModel({ status: "notify-only" });
  const observations = [{ model_id: model.id, expect_fire: false, fired: true, supported: true }];
  let noteReads = 0;
  const opts = {};
  Object.defineProperty(opts, "note", {
    enumerable: true,
    get() {
      noteReads += 1;
      return noteReads === 1 ? "first-read-demotion-note" : { poisoned: true };
    },
  });

  const [updated] = decideModelDemotion([model], observations, opts);
  assert.equal(updated.promotion_history[0].note, "first-read-demotion-note");
  assert.equal(noteReads, 1);
});

test("LOW #5 (daybreak re-gate #3): a non-array top-level `models` fails closed to [], never throws at .map()", () => {
  for (const bad of [{}, null, undefined, 42, "x", true]) {
    assert.deepEqual(decideModelPromotion(bad, {}, { soakClean: true }), []);
    assert.deepEqual(decideModelDemotion(bad, [], {}), []);
  }
});
