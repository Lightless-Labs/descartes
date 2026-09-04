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
//
// -- The trust boundary (fix-spec L1, #1 "forge your own oracle") --------------------------------
// Fixtures are NEVER read off the model record (`model.oracle.fixtures` used to be the sole
// source -- a model author could ship their own seeded-good/seeded-bad fixtures and self-certify
// past the gate). runOracle/decideModelPromotion below instead take fixtures as a SEPARATE,
// caller-supplied argument: the operator/harness's own trusted seed set, never anything carried
// inside the model record itself. A model record's own `oracle` field (if present at all) is
// inert here -- it is not read, and forging it changes nothing. Full trusted fixture PROVISIONING
// (posture enforcement, an independent source, real soak evidence) is explicitly deferred to the
// later attestation-gated build-out; this module only owns the API boundary that makes that
// build-out possible without another signature change.

import { evaluateModel, validateModel } from "./model-ir.js";

// R10-cheap (fix-spec, round 2, minimal survivable count cap -- NOT the full runtime budget
// analyzer, which is explicitly deferred): a caller-supplied fixtures array is otherwise unbounded
// work (one evaluateModel call per fixture). Beyond this cap, runOracle fails closed exactly like
// an empty fixture set, before doing any of that work.
export const MAX_ORACLE_FIXTURES = 256;

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid model-ladder ${field}: ${ts}`);
  return date.toISOString();
}

// C1 (round-3 fix-spec, the root-cause fix superseding round-2's structuredClone-based approach
// below): canonicalizes ANY untrusted input -- a model record, a fixture map, an observations
// array, an opts.note -- to an INERT plain-JSON snapshot via a JSON round-trip. structuredClone was
// the wrong primitive here: it invokes every getter exactly once (good), but it does NOT strip two
// classes of non-plain type that diverge from the persisted/evaluated form --
//   - a `Date` instance survives structuredClone as a live Date, but goes inert (an ISO STRING)
//     the moment the record is actually written to disk as JSON -- grading against the live Date's
//     numeric epoch-ms value and grading against its eventual persisted string form can disagree.
//   - a typed array over a `SharedArrayBuffer` survives structuredClone as a LIVE VIEW over the
//     SAME underlying shared memory (SharedArrayBuffer is explicitly NOT deep-copied by the
//     structured-clone algorithm) -- a value read one way at grading time can flip via a write on
//     another thread, with no further JS-level read of the "cloned" object at all.
// `JSON.parse(JSON.stringify(x))` closes both: every getter along the way still runs EXACTLY ONCE
// (during stringify) and is then gone, and the result is ordinary plain data with no shared backing
// memory and no non-JSON types -- LITERALLY EQUAL to what persistence/replay/re-evaluation will
// see. That equality is what makes "the object graded" and "the object stored" the same object by
// construction, not by convention -- the same guarantee round 2's structuredClone call was reaching
// for, just with a primitive that actually delivers it. A throw (a circular reference) or a
// top-level non-container result is treated as invalid -- callers fail that record/input CLOSED
// rather than let a JSON.stringify throw escape uncaught. NOTE (documented judgment call): unlike
// structuredClone, JSON.stringify does not THROW on a function/Symbol/undefined-valued property --
// it silently DROPS that one property and serializes everything else. That is intentional and
// accepted here (the fix-spec's own "watch outs"), not a gap: a stray non-plain field nothing in
// this module ever reads (e.g. `model.extra.someHelperFn`) must not block an otherwise-valid
// record from promoting, so dropping it (rather than failing the whole record closed) is the
// correct, narrower behavior -- see the dedicated regression test documenting this explicitly.
function canonicalizePlain(value) {
  let json;
  try {
    json = JSON.stringify(value);
  } catch {
    return null; // circular reference etc -- fail this record/input CLOSED, never throw to the caller
  }
  if (json === undefined) return null; // a top-level function/undefined/symbol serializes to no JSON at all
  try {
    return JSON.parse(json);
  } catch {
    return null; // unreachable in practice (stringify's own output always reparses) -- defensive anyway
  }
}

// Canonicalizes ONE input model record to a plain-data snapshot, EXACTLY ONCE, for BOTH
// decideModelPromotion and decideModelDemotion below (see canonicalizePlain's doc comment above for
// the round-3 root-cause fix this now runs on). This is the single fix that closes a whole cluster
// of findings together:
//   - stateful-accessor TOCTOU: a getter/proxy-backed record could otherwise answer validation/the
//     oracle with one value, then hand the transition a DIFFERENT value on a later, separate read
//     (e.g. a second clone call made only to build the promoted/demoted record). Canonicalizing
//     once, up front, and reusing that same snapshot for every subsequent read (validation, oracle
//     grading, the transition itself) makes "the object graded" and "the object promoted" the same
//     object by construction, not by convention.
//   - batch-abort (R4): a canonicalization throw (a circular reference somewhere in the record), or
//     a validateModel throw, fails only THIS record -- never escapes to abort the caller's `.map()`
//     over every other record in the batch.
//   - a non-array `promotion_history` (e.g. `{}`) is rejected here too, before it can ever reach
//     the `[...history]` spread further down and throw a TypeError mid-batch.
// Returns the snapshot on success, or `null` if the record could not be canonicalized/validated --
// callers treat `null` as "skip this record, return the ORIGINAL input reference unchanged".
function canonicalizeModelRecord(model) {
  const snap = canonicalizePlain(model);
  if (!snap || typeof snap !== "object" || Array.isArray(snap)) {
    return null; // canonicalization failed, or the record isn't a plain object to begin with
  }
  try {
    validateModel(snap);
  } catch {
    return null; // L5(a): an invalid record carries no trustworthy identity -- skip
  }
  if (snap.promotion_history !== undefined && !Array.isArray(snap.promotion_history)) {
    return null; // a malformed history must never reach the `[...history]` spread below
  }
  return snap;
}

// R9 dup-id (fix-spec, round 2): builds a `{ id -> occurrence count }` map over a list of already-
// canonicalized snapshots (nullable entries -- invalid records carry no identity and are skipped).
// A Map (not a plain object) is used deliberately so a colliding id can never be mistaken for an
// inherited Object.prototype property (mirrors model-ir.js's own M1 own-property discipline).
function countIds(snaps) {
  const counts = new Map();
  for (const snap of snaps) {
    if (!snap) continue;
    counts.set(snap.id, (counts.get(snap.id) ?? 0) + 1);
  }
  return counts;
}

/**
 * Runs a model's seeded-fixture oracle. `fixtures` is a CALLER-SUPPLIED (trusted) array of
 * `{ input:<factSeriesInput>, expect_fire:boolean }` (`true` = seeded-BAD, must fire; `false` =
 * seeded-GOOD, must stay quiet) -- see the header comment above ("The trust boundary"): this is
 * NEVER read off `model.oracle.fixtures`. For each fixture, evaluates the model via evaluateModel
 * (wrapped in try/catch -- fix-spec L3: a throwing fixture must not crash the whole promotion
 * batch, it is scored as an unsupported/failing fixture instead) and checks
 * `verdict.supported && (verdict.fired === expect_fire)`. Fix-spec L2: an UNSUPPORTED verdict
 * carries no evidence and can never count as an agreeing "ok" fixture -- it used to score as
 * `ok:true` whenever `fired` (defaulting to falsy on unsupported) happened to equal a
 * seeded-good's `expect_fire:false`, i.e. an unsupported fixture was silently indistinguishable
 * from "quiet and correct". A fixture whose `expect_fire` is not literally a boolean is treated as
 * `ok:false` -- fail-closed, never silently folded into "seeded-good" by loose-equality. Returns
 * `{ passed, total, fired_on_bad, quiet_on_good, results }`, where `fired_on_bad`/`quiet_on_good`
 * are derived from SUPPORTED verdicts only (fix-spec L2), and `passed` requires every fixture to
 * agree AND at least one caught seeded-bad AND at least one correctly-quiet seeded-good (see the
 * header comment above -- this is what closes the "all-seeded-good oracle" survivorship hole). An
 * empty/missing fixture set returns `passed:false` by construction -- the anti-survivorship rule:
 * competence must be demonstrated, never assumed. Pure; `opts` is forwarded to evaluateModel
 * unchanged (e.g. `opts.now`).
 */
export function runOracle(model, fixtures, opts = {}) {
  if (!Array.isArray(fixtures)) {
    return { passed: false, total: 0, fired_on_bad: 0, quiet_on_good: 0, results: [] };
  }
  // C2 (round-3 fix-spec): `.length` is captured into ONE local (`n`) here, reused for BOTH the
  // empty/MAX_ORACLE_FIXTURES cap checks AND the snapshot loop below -- `fixtures.length` itself is
  // never read a second time. A Proxy-backed `fixtures` argument whose `length` getter answers
  // differently across separate reads (e.g. MAX_ORACLE_FIXTURES on the cap check, then a larger
  // REAL value once actually iterated -- the old code read `.length` up to three times: the empty
  // check, the cap check, and once more inside `.map()`) could otherwise let more fixtures get
  // processed than the cap intends. This is the fixtures-array analogue of the same single-capture
  // discipline C2 applies to `sortedValidPoints` in model-ir.js.
  const n = fixtures.length;
  if (n === 0 || n > MAX_ORACLE_FIXTURES) {
    // R10-cheap: cap the fixture count BEFORE doing any per-fixture work -- an oversized fixtures
    // array is otherwise unbounded evaluateModel work. Fails closed exactly like the empty-set case
    // (no evidence of competence), rather than "unbounded work, then maybe fail".
    return { passed: false, total: 0, fired_on_bad: 0, quiet_on_good: 0, results: [] };
  }
  const snapshot = new Array(n);
  for (let i = 0; i < n; i++) snapshot[i] = fixtures[i]; // indexed gets only -- `.length` never re-read

  const results = snapshot.map((fixture) => {
    // R6: fixture.expect_fire and fixture.input are now read INSIDE this try, alongside the
    // evaluateModel call -- a throwing getter on either property (a hostile/malformed fixture
    // object) used to be read OUTSIDE any try/catch, which would escape and abort the whole
    // `.map()` over every other fixture in the batch. Scoring this fixture as unsupported/failing,
    // exactly like L3's evaluateModel-throws case, keeps the rest of the batch intact.
    try {
      // C1 defense-in-depth (round-3): canonicalize EACH fixture INDIVIDUALLY here (not the whole
      // `fixtures` array in a single JSON.stringify call, which would let one hostile fixture's
      // throwing getter abort every sibling fixture's grading too -- exactly the batch-abort R6/L3
      // already guard against, one level up). Per-fixture canonicalization bakes in every nested
      // getter's answer exactly once -- `expect_fire`/`input` below are read from INERT plain data
      // even when runOracle is called directly (not through the ladder's own upstream
      // canonicalization in decideModelPromotion). A throw during THIS fixture's own canonicalize
      // (e.g. the same getOwnPropertyDescriptor-throws Proxy L3 already exercises) yields `null`,
      // which falls through the optional chains below to the same unsupported/failing verdict L3
      // already produced for a throwing fixture -- no behavior change for that case, just a
      // stronger guarantee for the getter-aliasing case.
      const canonicalFixture = canonicalizePlain(fixture);
      const expectFire = canonicalFixture?.expect_fire;
      let verdict;
      try {
        verdict = evaluateModel(model, canonicalFixture?.input, opts);
      } catch {
        // L3: a fixture that throws (a malformed input, an interpreter edge case) carries no
        // evidence either -- treat it exactly like an unsupported verdict, never let it propagate
        // and abort every other fixture's evaluation in the same batch.
        verdict = { supported: false };
      }
      const supported = verdict.supported === true;
      const fired = supported && verdict.fired === true;
      // A malformed/missing expect_fire (not literally true or false) has no ground truth to
      // check against -- fail-closed (ok:false) rather than silently treating it as "expected
      // quiet".
      if (typeof expectFire !== "boolean") return { expect_fire: expectFire, fired, ok: false, supported };
      // L2: ok requires a SUPPORTED verdict -- an unsupported fixture is never a silent "agree".
      return { expect_fire: expectFire, fired, ok: supported && fired === expectFire, supported };
    } catch {
      return { expect_fire: undefined, fired: false, ok: false, supported: false };
    }
  });

  // L2: derived from supported verdicts only -- an unsupported fixture contributes to neither
  // count, so it can never manufacture evidence of competence.
  const firedOnBad = results.filter((r) => r.supported && r.expect_fire === true && r.fired).length;
  const quietOnGood = results.filter((r) => r.supported && r.expect_fire === false && !r.fired).length;

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
 * item 3). `fixturesByModelId` is the caller-supplied (trusted) map `{ [model.id]: fixtures }` --
 * see runOracle's doc comment and the header comment above ("The trust boundary"): a model with no
 * entry in this map has no trusted evidence and is never promoted, regardless of what its own
 * `oracle` field (if any) claims. Flips every `status:"shadow"` model whose
 * `runOracle(snap, fixturesByModelId[snap.id], opts).passed` is true AND `opts.soakClean` is
 * true (a caller-supplied boolean standing in for a clean soak window -- the real soak wiring is
 * the later VM step) to `"notify-only"`, appending a `promotion_history` entry
 * `{ ts, from:"shadow", to:"notify-only", actor:"seeded-oracle-gate", note }`.
 *
 * C1/R1 (the root-cause fix, round 3 superseding round 2): every model record is first passed
 * through canonicalizeModelRecord (above) EXACTLY ONCE -- that single snapshot (`snap`) is what
 * gets validated, id-checked, graded by the oracle, AND promoted. This is what makes "the object
 * the oracle graded" and "the object that gets promoted" the SAME object by construction, closing
 * the stateful-accessor TOCTOU (a getter could otherwise answer the oracle one way and a later,
 * separate clone call a different way), the batch-abort on an uncanonicalizable/invalid record
 * (fails that one record, never the whole `.map()`), and the non-array-`promotion_history` crash
 * (rejected during canonicalization, before it can reach the `[...history]` spread). Fix-spec L4
 * (deep-clone, no aliasing with the input) falls out of this for free -- `snap` IS already a fresh
 * plain-JSON copy of the input, sharing no reference with it at any depth.
 *
 * C1 Blocker 2 (round 3): `fixturesByModelId`, the CALLER'S OWN trusted map, is canonicalized ONCE,
 * FIRST -- before any model (and any getter it might carry) is ever touched, see `fixturesSnap`
 * below. This closes a self-certification hole: a hostile model's own field getter, fired while
 * THAT model is being canonicalized, could otherwise mutate the shared `fixturesByModelId` object
 * as a side effect (e.g. swapping its own fixture-map entry from failing evidence to passing
 * evidence) before that entry is ever looked up. Freezing the whole map to inert plain JSON before
 * any model's own fields are read at all means no model's getter can ever run early enough to
 * matter -- the fixtures every model gets graded against are exactly the ones the caller supplied
 * at call time, period.
 *
 * R9 dup-id: a model whose id collides with another model's id in the SAME `models` array is left
 * completely untouched (skipped) -- see countIds's doc comment; a colliding id must never let one
 * call promote/act on more than one record under the same identity. Every other model (non-shadow,
 * oracle-failing, soak-dirty, invalid, or a colliding id) passes through completely unchanged -- by
 * reference, idempotent -- mirroring constraint-store.js's promoteDraftsToShadow. Pure, no I/O.
 */
export function decideModelPromotion(models, fixturesByModelId, opts = {}) {
  const ts = normalizeIso(opts.now ?? new Date().toISOString(), "now");
  const soakClean = opts.soakClean === true;
  // C1: opts.note is read into a local via canonicalizePlain EXACTLY ONCE -- the old
  // `typeof opts.note === "string" ? opts.note : undefined` read `opts.note` TWICE (once for the
  // type check, once more for the value actually stored), which let a getter-backed note answer
  // the type check with a real string and the stored value with something else entirely. A single
  // property read, captured before any further use, closes that -- see the dedicated regression
  // test. (canonicalizePlain also still rejects a non-string alias object exactly like before,
  // e.g. `{ toString: () => "..." }`: JSON.stringify drops its function-valued property, leaving
  // `{}`, which is not a string either.)
  const canonicalNote = canonicalizePlain(opts.note);
  const note = typeof canonicalNote === "string" ? canonicalNote : undefined;
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
  //
  // `oracleOpts` is built by copying only the OTHER keys `opts` carries, deliberately NOT via an
  // ordinary rest-destructure (`const { now, note, ...oracleOpts } = opts`) -- naming `note` on the
  // left of a destructure invokes ITS getter too, just to discard the result, which would silently
  // re-open the single-read guarantee just established above. `Object.keys` only lists property
  // NAMES (no `[[Get]]` triggered), so the loop below reads every key's VALUE at most once, total,
  // across this whole function -- `now` and `note` are skipped entirely (already read above);
  // nothing downstream (runOracle/evaluateModel) consumes either from `oracleOpts` anyway.
  const oracleOpts = {};
  for (const key of Object.keys(opts)) {
    if (key === "now" || key === "note") continue;
    oracleOpts[key] = opts[key];
  }

  // C1 Blocker 2: canonicalize the TRUSTED fixture map ONCE, FIRST -- see the doc comment above.
  // `Object.hasOwn` guards `fixturesSnap` itself the same M1-style way the lookup below always has
  // (a JSON.parse result never carries inherited properties either way, but the guard is kept
  // explicit rather than relying on that incidentally).
  const canonicalFixturesByModelId = canonicalizePlain(fixturesByModelId);
  const fixturesSnap =
    canonicalFixturesByModelId && typeof canonicalFixturesByModelId === "object" && !Array.isArray(canonicalFixturesByModelId)
      ? canonicalFixturesByModelId
      : {};

  const inputList = Array.isArray(models) ? models : []; // fail closed on a non-array top-level shape (daybreak re-gate #3, LOW #5) — never throw at .map()
  const snaps = inputList.map((model) => canonicalizeModelRecord(model)); // C1: ONE snapshot per record, reused below
  const idCounts = countIds(snaps); // R9 dup-id

  return inputList.map((model, i) => {
    const snap = snaps[i];
    if (!snap) return model; // L5(a)/C1: invalid or uncanonicalizable record -- skip, never mutate
    if ((idCounts.get(snap.id) ?? 0) > 1) return model; // R9 dup-id: colliding id, never act on it
    if (snap.status !== "shadow") return model;
    if (!soakClean) return model;
    // M1-style own-property gate (see model-ir.js's `fact` op): a model.id equal to an inherited
    // Object.prototype property name (e.g. "toString") must not resolve a fixture set that was
    // never actually seeded for it.
    const fixtures = Object.hasOwn(fixturesSnap, snap.id) ? fixturesSnap[snap.id] : undefined;
    const oracle = runOracle(snap, fixtures, oracleOpts); // graded on the SAME snapshot that gets promoted
    if (!oracle.passed) return model;
    return {
      ...snap,
      status: "notify-only",
      promotion_history: [
        ...(snap.promotion_history ?? []),
        {
          ts,
          from: "shadow",
          to: "notify-only",
          actor: "seeded-oracle-gate",
          note: note ?? `seeded oracle passed (${oracle.total} fixtures) + clean soak`,
        },
      ],
    };
  });
}

/**
 * Deterministic notify-only -> shadow demotion (auto-quarantine on regression -- plan §2 item 3,
 * "auto-demote on regression... promote and demote are one control loop"). `observations` is
 * caller-supplied: an array of `{ model_id, expect_fire, fired, supported }` outcomes (the shape
 * the later VM-wired soak/shadow-store step will actually produce -- this function performs no I/O
 * and does not care where they came from; `supported` is round-2's R3-supported addition, see
 * below). Flips every `status:"notify-only"` model back to `"shadow"` on
 * either of two triggers, each requiring at least one matching observation for that model's id:
 *   - a caught FALSE POSITIVE: `expect_fire:false, fired:true` -- the detector fired on
 *     seeded-good.
 *   - fix-spec L6, "boiling frog": a caught FALSE NEGATIVE on a notify-only model --
 *     `expect_fire:true, fired:false` -- the detector went blind on seeded-bad. A model that has
 *     already earned trust can still regress into silence rather than into false alarms; only
 *     checking for false positives would let that failure mode go undetected indefinitely.
 * Each trigger appends a `promotion_history` entry with a note distinguishing which one fired (if
 * both are present in the same observation batch, the false-positive note takes precedence -- it
 * is the more urgent failure mode and the one this ladder was originally built to catch).
 * Fix-spec L5(b): `model.id` must be a non-empty string, and an observation's `model_id` is
 * ignored unless it is also a non-empty string -- `model.id === undefined` matching
 * `obs.model_id === undefined` (both absent) used to mass-demote every notify-only model with no
 * id at all. Fix-spec R3-supported (round 2): an observation counts toward EITHER trigger only when
 * `obs.supported === true` -- an unsupported (or `fired`-without-`supported`) outcome carries no
 * evidence, the same "competence, not survivorship" discipline runOracle already applies to
 * fixtures. (Full observation AUTHENTICATION -- provenance, replay-once consumption, binding to the
 * evaluated model-content digest -- is explicitly deferred to the attestation-gated build-out; this
 * is only the pure-layer half: require the caller to have already marked it supported.)
 *
 * C1/R1: every model record is first passed through canonicalizeModelRecord (above) EXACTLY ONCE --
 * see decideModelPromotion's doc comment for the full TOCTOU/batch-abort/L4 reasoning, which
 * applies identically here.
 *
 * C1 (round 3): `observations` -- the caller's own trusted array -- is canonicalized ONCE, FIRST,
 * via `obsSnap` below, before a single field of a single observation is ever read. This closes a
 * decoy->victim identity-switch TOCTOU: the old code read `obs.model_id` in the eligibility filter
 * (`isNonEmptyString(obs.model_id)`), then read it AGAIN, separately, to build the false-positive/
 * false-negative trigger Sets -- a getter-backed `model_id` could answer an innocuous "decoy" id on
 * the first read (passing the eligibility check harmlessly) and the real target's id on the second
 * (quietly adding THAT model to a trigger set it was never actually observed for). A getter run
 * through JSON.stringify fires EXACTLY ONCE; every field every observation carries below is read
 * from that one inert snapshot, so there is no second read left for it to disagree with.
 *
 * R9 dup-id: a model whose id collides with another model's id in the SAME `models` array is left
 * completely untouched (skipped) -- one observation must never be able to quarantine more than one
 * record under a shared identity. Every other model (non-notify-only, invalid, a colliding id, or
 * no matching trigger) passes through completely unchanged -- by reference, idempotent. Pure, no
 * I/O.
 */
export function decideModelDemotion(models, observations, opts = {}) {
  const ts = normalizeIso(opts.now ?? new Date().toISOString(), "now");
  // C1: opts.note read once via canonicalizePlain -- see decideModelPromotion's matching comment.
  const canonicalNote = canonicalizePlain(opts.note);
  const note = typeof canonicalNote === "string" ? canonicalNote : undefined;

  // C1: canonicalize `observations` ONCE, FIRST -- see the doc comment above.
  const canonicalObservations = canonicalizePlain(observations);
  const obsSnap = Array.isArray(canonicalObservations) ? canonicalObservations : [];

  const validObservations = obsSnap.filter(
    (obs) => obs && isNonEmptyString(obs.model_id) && obs.supported === true, // R3-supported
  );
  const falsePositiveModelIds = new Set(
    validObservations.filter((obs) => obs.expect_fire === false && obs.fired === true).map((obs) => obs.model_id),
  );
  const falseNegativeModelIds = new Set(
    validObservations.filter((obs) => obs.expect_fire === true && obs.fired === false).map((obs) => obs.model_id),
  );

  const inputList = Array.isArray(models) ? models : []; // fail closed on a non-array top-level shape (daybreak re-gate #3, LOW #5) — never throw at .map()
  const snaps = inputList.map((model) => (model ? canonicalizeModelRecord(model) : null)); // C1
  const idCounts = countIds(snaps); // R9 dup-id

  return inputList.map((model, i) => {
    const snap = snaps[i];
    if (!snap) return model; // R1/L5(a): invalid or uncanonicalizable record -- skip, never mutate
    if (snap.status !== "notify-only") return model;
    if ((idCounts.get(snap.id) ?? 0) > 1) return model; // R9 dup-id: colliding id, never act on it

    const caughtFalsePositive = falsePositiveModelIds.has(snap.id);
    const caughtFalseNegative = falseNegativeModelIds.has(snap.id);
    if (!caughtFalsePositive && !caughtFalseNegative) return model;

    const defaultNote = caughtFalsePositive
      ? "fired on a seeded-good observation (caught false-positive) -- quarantined back to shadow"
      : "failed to fire on a seeded-bad observation (caught false-negative, boiling-frog trigger) -- quarantined back to shadow";

    return {
      ...snap,
      status: "shadow",
      promotion_history: [
        ...(snap.promotion_history ?? []),
        {
          ts,
          from: "notify-only",
          to: "shadow",
          actor: "seeded-oracle-gate",
          note: note ?? defaultNote,
        },
      ],
    };
  });
}
