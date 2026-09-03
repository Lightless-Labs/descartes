// Slice-1 behavioral-model spike, step 4 PURE core (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 4): the minimal seeded-oracle shadow -> notify-only promote/demote ladder for a v2
// MODEL record. Pure/offline -- no daemon, no VM, no persistence, no LLM, no I/O. Additive-only,
// mirroring constraint-store.js's pure promotion helpers (promoteDraftsToShadow /
// promoteShadowToReviewReady): immutable map-over-array, append a promotion_history entry,
// idempotent no-op on a non-matching status. Authority tiers for a MODEL in scope here: shadow ->
// notify-only only -- the additive-only ceiling; anything above notify-only is attestation-gated
// and OUT of scope (plan §2 item 3, §3). The daemon-wired end-to-end run, the real soak wiring
// against shadow-store.js, and the red-team are a later VM step -- NOT this file.
//
// -- The fired/lte convention (plan Progress note, "Decision for step 4") ------------------------
// evaluateModel (model-ir.js) sets `fired: !satisfied`. A bounded-statistic detector (CUSUM etc.)
// must therefore be authored as `model: { op:"threshold", expected:{ comparator:"lte", value:h
// } }` -- "the statistic should stay <= h" -- so a crossing (statistic > h) is a VIOLATION ->
// satisfied:false -> fired:true. (The plan text says "lt|lte", but evaluateNumericComparator in
// constraint-eval.js only implements gte/lte/eq -- there is no "lt" comparator in this
// codebase's vocabulary; "lte" is the one that actually exists and implements this invariant.)
// runOracle below checks `fired`, not `satisfied`; a naive `gte h` framing would invert it (see
// model-ladder.test.js's dedicated fired-convention lock).
//
// -- Competence, not survivorship (plan §1 item 2 / §5) -------------------------------------------
// The oracle demands EVIDENCE the model actually distinguishes seeded-bad from seeded-good: a
// degenerate model that never fires is trivially "quiet" on seeded-good but also fails to fire on
// seeded-bad, and an empty/missing oracle carries no evidence at all -- both are treated as a
// fail-closed non-pass, never promoted "by default" just because nothing contradicted it. This is
// why `passed` below requires BOTH >=1 caught seeded-bad AND >=1 correctly-quiet seeded-good, not
// merely "every present fixture agreed" -- an oracle built entirely of seeded-good fixtures would
// otherwise let a never-fires model "pass" trivially (every fixture individually ok:true), which
// is exactly the survivorship failure this module exists to reject; the empty-oracle rule is just
// the degenerate instance of this same requirement (plan §1 item 2: "catches seeded-bad AND stays
// quiet on seeded-good", not either alone).

import { evaluateModel } from "./model-ir.js";

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid model-ladder ${field}: ${ts}`);
  return date.toISOString();
}

/**
 * Runs a model's seeded-fixture oracle: `model.oracle.fixtures` is an array of
 * `{ input:<factSeriesInput>, expect_fire:boolean }` (`true` = seeded-BAD, must fire; `false` =
 * seeded-GOOD, must stay quiet). For each fixture, evaluates the model via evaluateModel and
 * checks `(verdict.supported && verdict.fired) === fixture.expect_fire`. A fixture whose
 * `expect_fire` is not literally a boolean is treated as `ok:false` -- fail-closed, never silently
 * folded into "seeded-good" by loose-equality. Returns
 * `{ passed, total, fired_on_bad, quiet_on_good, results }`, where `passed` requires every fixture
 * to agree AND at least one caught seeded-bad AND at least one correctly-quiet seeded-good (see
 * the header comment above -- this is what closes the "all-seeded-good oracle" survivorship hole).
 * An empty/missing fixture set returns `passed:false` by construction -- the anti-survivorship
 * rule: competence must be demonstrated, never assumed. Pure; `opts` is forwarded to evaluateModel
 * unchanged (e.g. `opts.now`).
 */
export function runOracle(model, opts = {}) {
  const fixtures = model?.oracle?.fixtures;
  if (!Array.isArray(fixtures) || fixtures.length === 0) {
    return { passed: false, total: 0, fired_on_bad: 0, quiet_on_good: 0, results: [] };
  }

  const results = fixtures.map((fixture) => {
    const expectFire = fixture?.expect_fire;
    const verdict = evaluateModel(model, fixture?.input, opts);
    const fired = verdict.supported === true && verdict.fired === true;
    // A malformed/missing expect_fire (not literally true or false) has no ground truth to check
    // against -- fail-closed (ok:false) rather than silently treating it as "expected quiet".
    if (typeof expectFire !== "boolean") return { expect_fire: expectFire, fired, ok: false };
    return { expect_fire: expectFire, fired, ok: fired === expectFire };
  });

  const firedOnBad = results.filter((r) => r.expect_fire === true && r.fired).length;
  const quietOnGood = results.filter((r) => r.expect_fire === false && !r.fired).length;

  return {
    passed: results.every((r) => r.ok) && firedOnBad >= 1 && quietOnGood >= 1,
    total: results.length,
    fired_on_bad: firedOnBad,
    quiet_on_good: quietOnGood,
    results,
  };
}

/**
 * Deterministic shadow -> notify-only gate -- the ONLY promotion transition in scope (plan §2
 * item 3). Flips every `status:"shadow"` model whose `runOracle(model, opts).passed` is true AND
 * `opts.soakClean` is true (a caller-supplied boolean standing in for a clean soak window -- the
 * real soak wiring is the later VM step) to `"notify-only"`, appending a `promotion_history`
 * entry `{ ts, from:"shadow", to:"notify-only", actor:"seeded-oracle-gate", note }`. Every other
 * model (non-shadow, oracle-failing, or soak-dirty) passes through completely unchanged -- by
 * reference, idempotent -- mirroring constraint-store.js's promoteDraftsToShadow. Pure, no I/O.
 */
export function decideModelPromotion(models, opts = {}) {
  const ts = normalizeIso(opts.now ?? new Date().toISOString(), "now");
  const soakClean = opts.soakClean === true;
  // `opts.now` above is the PROMOTION-DECISION clock (stamped into promotion_history) -- it must
  // NOT also become each fixture's window-evaluation reference point inside the oracle. Fixtures
  // are historical/synthetic series anchored to their OWN timestamps, unrelated to when the
  // promotion check happens to run; if the ordinary current-wall-clock `now` leaked through, it
  // would silently truncate or empty every windowed feature in every fixture (a fixture's series
  // rarely spans "right now"), turning a competent model's oracle run into false silence. Strip it
  // before forwarding the rest of `opts` to the oracle -- every fixture then defaults to its own
  // latest point, exactly like evaluateFeatureNode's own `opts.now`-absent convention. (No
  // separate "oracle evaluation clock" override is introduced here -- nothing in this spike's
  // scope consumes one; see repo doctrine, "no kernel without a live consumer".)
  const { now: _promotionClock, ...oracleOpts } = opts;
  return (models ?? []).map((model) => {
    if (!model || model.status !== "shadow") return model;
    if (!soakClean) return model;
    const oracle = runOracle(model, oracleOpts);
    if (!oracle.passed) return model;
    return {
      ...model,
      status: "notify-only",
      promotion_history: [
        ...(model.promotion_history ?? []),
        {
          ts,
          from: "shadow",
          to: "notify-only",
          actor: "seeded-oracle-gate",
          note: opts.note ?? `seeded oracle passed (${oracle.total} fixtures) + clean soak`,
        },
      ],
    };
  });
}

/**
 * Deterministic notify-only -> shadow demotion (auto-quarantine on regression -- plan §2 item 3,
 * "auto-demote on regression... promote and demote are one control loop"). `observations` is
 * caller-supplied: an array of `{ model_id, expect_fire, fired }` outcomes (the shape the later
 * VM-wired soak/shadow-store step will actually produce -- this function performs no I/O and does
 * not care where they came from). Flips every `status:"notify-only"` model back to `"shadow"`
 * when `observations` contains at least one record for that model's id with
 * `expect_fire:false, fired:true` -- a caught false-positive -- appending a `promotion_history`
 * entry. Every other model (non-notify-only, or no caught false-positive in observations) passes
 * through completely unchanged -- by reference, idempotent. Pure, no I/O.
 */
export function decideModelDemotion(models, observations, opts = {}) {
  const ts = normalizeIso(opts.now ?? new Date().toISOString(), "now");
  const falsePositiveModelIds = new Set(
    (observations ?? [])
      .filter((obs) => obs && obs.expect_fire === false && obs.fired === true)
      .map((obs) => obs.model_id),
  );

  return (models ?? []).map((model) => {
    if (!model || model.status !== "notify-only") return model;
    if (!falsePositiveModelIds.has(model.id)) return model;
    return {
      ...model,
      status: "shadow",
      promotion_history: [
        ...(model.promotion_history ?? []),
        {
          ts,
          from: "notify-only",
          to: "shadow",
          actor: "seeded-oracle-gate",
          note: opts.note ?? "fired on a seeded-good observation (caught false-positive) -- quarantined back to shadow",
        },
      ],
    };
  });
}
