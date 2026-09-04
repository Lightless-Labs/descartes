// Slice-1 behavioral-model spike, step 1 (docs/plans/2026-09-03-slice-1-behavioral-model-spike.md
// §8 item 1): a thin v2 behavioral-model IR + pure DAG interpreter. Additive-only, no I/O, no
// mining, no LLM, no daemon wiring -- a pure evaluation seam only, exactly like constraint-eval.js
// itself. Existing v1 records/files are untouched; v2 is a NEW, PARALLEL record kind that never
// migrates a v1 record in place (plan §2.1, "dual-read versioning").
//
// -- Record shape ------------------------------------------------------------------------------
// A v2 model record: { id, kind:"model", schema_version:2, family, feature:<FeatureNode>,
// model:<ModelNode>, ... } -- the rest of the envelope (provenance, fixtures, promotion_history,
// status, confidence, sensitivity, ...) mirrors constraint-store.js's v1 envelope but is not yet
// consumed by anything in this file; step 1 only needs kind/schema_version/family/feature/model.
// validateModel() below mirrors constraint-store.js's validateConstraint() throw-on-invalid style
// and is intentionally shallow -- it validates the ENVELOPE, not the node graph itself (deep
// admissibility, e.g. reference-resolution/arity/type checks on the DAG, is the authoring seam's
// job in a later spike step, plan §2 item 4). The interpreter below is therefore tolerant of a
// malformed node graph at evaluation time: an unknown op or missing/invalid node config degrades
// to `{ supported: false }` rather than throwing, mirroring evaluateExpected's own "deterministic
// code refuses to guess" contract (constraint-eval.js).
//
// -- Input contract -----------------------------------------------------------------------------
// The interpreter takes a `factSeriesInput`: a plain object map keyed by fact name, where each
// value is EITHER a bare scalar (number | string | boolean -- passed through untouched, matching
// v1's tolerance for whatever a fact happens to hold) OR an ordered-or-unordered array of
// `{ ts, value }` points (`ts` an epoch-ms number or an ISO-8601 string; `value` typically
// numeric for window/zscore). Series points do not need to be pre-sorted -- the interpreter sorts
// ascending by ts wherever order matters (latest-wins, windowing, folding) and silently drops any
// point whose `ts` does not parse (a corrupt timestamp excludes just that point, the way "no fact,
// no claim" excludes an absent one -- see sortedValidPoints()).
//
// -- Missing-input -> silence (plan §2.1 / §5, hard requirement) --------------------------------
// Every FeatureNode below returns `{ supported: false }` -- never a fabricated value -- when its
// input is missing, empty, too short, or (for window/zscore/cusum, the series ops) contains a
// non-finite value anywhere inside the selected window. That last rule is
// deliberately conservative: ONE degraded point silences the whole window rather than being
// quietly dropped, because folding partial/degraded data into a stat is itself a form of
// fabrication. This is a stricter contract than v1's evaluateExpected (which downgrades a
// non-finite *scalar* fact to `satisfied:false`, not silence) -- but "latest" + "threshold"
// (Lock A) never applies this stricter rule WHEN THE FACT ITSELF IS A BARE SCALAR (not a series):
// it passes that resolved scalar straight to evaluateExpected unchanged, which is what keeps Lock
// A byte-identical to v1 over ANY bare-scalar input, finite or not. This passthrough is narrower
// than it may look, though: when the fact is a SERIES and "latest" extracts a single point's value
// out of it, a stricter admissibility gate DOES apply (fix-spec R8-latest, round 2) -- only a
// finite number or a non-empty string may pass, because an arbitrary/adversarial series point
// (unlike an author-supplied bare scalar) has no such guarantee and would otherwise smuggle a
// fabricated verdict past threshold the same way an unguarded window/zscore point would. The
// stricter degrade-to-silence rule otherwise applies to window/zscore/cusum, the series ops the
// plan calls out explicitly (§2.1: "a windowed feature with too few / degraded points emits
// nothing, never a fabricated value").

import { evaluateExpected } from "./constraint-eval.js";
import { computeZScore, emptyWelfordStats, foldWelford } from "./welford-stats.js";

export const MODEL_KIND = "model";
export const MODEL_SCHEMA_VERSION = 2;

// zscore's minimum sample count before it will emit a value at all (a single point has variance
// 0 by construction -- not "wrong", but not meaningfully a z-score either). Overridable per-node
// via `node.minSamples`; kept as a named default rather than a magic number.
export const DEFAULT_MIN_ZSCORE_SAMPLES = 2;

// cusum's minimum sample count before it will emit a value at all (mirrors DEFAULT_MIN_ZSCORE_
// SAMPLES's reasoning -- a single point cannot show a changepoint). Overridable per-node via
// `node.minSamples`.
export const DEFAULT_MIN_CUSUM_SAMPLES = 2;

/**
 * Validates a v2 model-record ENVELOPE (kind, schema_version, id, family, feature/model node
 * presence). Mirrors constraint-store.js's validateConstraint(): throws a descriptive Error on
 * the first invalid/missing field, returns true otherwise. Deliberately shallow -- see the header
 * comment above for what it does NOT check (the node graph itself).
 */
export function validateModel(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Model record must be an object");
  }

  // R9 (round-2 fix-spec): id must be a literal string, not merely coercible to a non-empty one --
  // a numeric id (e.g. 7) used to pass this gate via String(7)="7", which let promotion/demotion
  // disagree on identity (one side comparing the number, the other a coerced string) and let a
  // numeric id promote at all. `String(record.id ?? "").trim()` is deliberately NOT used here
  // anymore for the type check (only for consistency of the trim/non-empty check below).
  if (typeof record.id !== "string" || record.id.trim().length === 0) {
    throw new Error("Model record requires a non-empty id");
  }

  if (record.kind !== MODEL_KIND) {
    throw new Error(`Model record kind must be "model", got: ${JSON.stringify(record.kind)}`);
  }

  if (Number(record.schema_version) !== MODEL_SCHEMA_VERSION) {
    throw new Error(`Model record schema_version must be 2, got: ${JSON.stringify(record.schema_version)}`);
  }

  const family = String(record.family ?? "").trim();
  if (!family) throw new Error("Model record requires a non-empty family");

  if (!record.feature || typeof record.feature !== "object" || Array.isArray(record.feature)) {
    throw new Error("Model record requires a feature node (object)");
  }

  if (!record.model || typeof record.model !== "object" || Array.isArray(record.model)) {
    throw new Error("Model record requires a model node (object)");
  }

  return true;
}

function toEpochMs(ts) {
  if (typeof ts === "number") return Number.isFinite(ts) ? ts : NaN;
  if (typeof ts === "string") {
    const parsed = Date.parse(ts);
    return Number.isNaN(parsed) ? NaN : parsed;
  }
  return NaN;
}

// M-rows (fix-spec R10-cheap, minimal survivable count cap -- NOT the full runtime budget
// analyzer, which is explicitly deferred): a factSeriesInput series is caller/fact-store supplied
// and could be adversarially (or just accidentally) huge. Checked BEFORE the filter/sort below, so
// an oversized series never pays the cost of sorting itself -- it degrades to an empty array,
// which every existing `sorted.length === 0` -> silence check downstream (latest/window/zscore/
// cusum) already handles correctly, so no separate cap is needed at each call site.
export const MAX_SERIES_POINTS = 10000;

// C2 (round-3 fix-spec): snapshots an array-like `points` argument into a REAL plain array from a
// SINGLE `.length` read, captured into the local `len` and never re-read afterward. The array
// itself is then filled by INDEXED gets (`points[i]` for `i` in `[0, len)`) rather than any method
// that re-invokes `.length` internally (`Array.from`, a spread, `.filter`/`.slice`/`.map` called
// directly on the original array-like all read `.length` at least once on their own, separately
// from any check a caller already made). A Proxy-backed `points` argument whose `length` getter
// answers DIFFERENTLY across separate reads -- e.g. a value at/under MAX_SERIES_POINTS on a first
// check, then a larger REAL value once something else re-reads it -- would otherwise bypass the cap
// below entirely: the cap check would see the small answer while a later, separate length-consuming
// read processed the large one. Capturing `.length` exactly once and indexing up to that ONE value
// closes that regardless of how many more times the getter might have answered differently.
function toPlainPointsArray(points) {
  if (!Array.isArray(points)) return null;
  const len = points.length; // the ONE read -- reused for both the cap check and every index below
  if (!Number.isInteger(len) || len < 0 || len > MAX_SERIES_POINTS) return null;
  const arr = new Array(len);
  for (let i = 0; i < len; i++) arr[i] = points[i];
  return arr;
}

// R7-dupts (round 3, type-aware -- see compareTiedPointValues below): equal-ts points must sort
// identically regardless of the INPUT array's order. `typeof` is ranked first, in a FIXED order
// independent of which type happens to appear first in the input array, so two points whose values
// are of DIFFERENT types can never collide onto the same comparison key -- see
// compareTiedPointValues's own doc comment for why this matters (`Number(false) === Number(0)`).
// Only within the SAME type does the comparison fall through to a same-type ordering, then finally
// to a String() fallback for anything still tied. Only a genuine full tie (same ts AND the same
// String(value), where the choice cannot change the outcome) falls through to the stable fallback.
const POINT_VALUE_TYPE_ORDER = ["number", "string", "boolean", "object", "undefined", "function", "symbol", "bigint"];

function pointValueTypeRank(value) {
  const idx = POINT_VALUE_TYPE_ORDER.indexOf(typeof value);
  return idx === -1 ? POINT_VALUE_TYPE_ORDER.length : idx;
}

// C3 (round-3 fix-spec, HIGH): the old tie-break compared `Number(a.value) - Number(b.value)` and
// RETURNED as soon as both sides were finite -- but `Number(false) === Number(0) === 0`, so a
// boolean `false` point and a numeric `0` point at the same ts compared as a genuine tie (both -> 0)
// and fell through to Array.prototype.sort's STABLE fallback, which preserves the pre-sort (i.e.
// caller-supplied) array order -- exactly the order-dependence R7-dupts exists to remove, just for
// a pair the old coercion-based check couldn't tell apart. Ranking by `typeof` FIRST (above) means
// two values of different types are NEVER compared via a lossy `Number()` coercion in the first
// place: they're ordered by type, deterministically, before value ever enters into it.
function compareTiedPointValues(a, b) {
  const ta = pointValueTypeRank(a);
  const tb = pointValueTypeRank(b);
  if (ta !== tb) return ta - tb;
  if (typeof a === "number" && typeof b === "number") {
    const aFinite = Number.isFinite(a);
    const bFinite = Number.isFinite(b);
    if (aFinite && bFinite) return a - b;
    if (aFinite !== bFinite) return aFinite ? -1 : 1;
    // both non-finite (NaN/Infinity/-Infinity) -- fall through to the String() fallback below
  } else if (typeof a === "string" && typeof b === "string") {
    if (a !== b) return a < b ? -1 : 1;
    return 0;
  }
  const sa = String(a);
  const sb = String(b);
  if (sa !== sb) return sa < sb ? -1 : 1;
  return 0; // genuine full tie -- stable fallback (Array.sort is stable, ES2019+)
}

// Drops any point without a parseable ts (a corrupt/missing timestamp excludes just that point --
// see the header comment) and returns the rest sorted ascending by ts. Used wherever "latest" or
// "the window" needs a well-defined order.
function sortedValidPoints(points) {
  const arr = toPlainPointsArray(points); // C2: single-length-read snapshot into a real array
  if (!arr) return [];
  return arr
    .filter((p) => p && typeof p === "object" && Number.isFinite(toEpochMs(p.ts)))
    .sort((a, b) => {
      const tsDiff = toEpochMs(a.ts) - toEpochMs(b.ts);
      if (tsDiff !== 0) return tsDiff;
      return compareTiedPointValues(a.value, b.value); // C3: type-aware tie-break
    });
}

// A point's value is admissible ONLY if it is an actual finite number -- not "coercible to one".
// `Number(null) === 0`, `Number([]) === 0`, `Number("") === 0`, `Number(false) === 0` are all
// finite under the old `Number(p.value)` coercion, which silently smuggled null/[]/""/false into
// the stat as a fabricated `0` instead of degrading to silence (fix-spec M3). typeof-gating first
// closes that hole while leaving genuinely-numeric points (including NaN/Infinity, still caught by
// Number.isFinite) untouched.
function isValidNumericValue(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function hasNonFiniteValue(points) {
  return points.some((p) => !isValidNumericValue(p.value));
}

// R8-latest (fix-spec, round 2): a value extracted from a SERIES point (as opposed to a bare
// scalar fact -- see the "latest" case below) is admissible only if it is a finite number or a
// non-empty string; anything else (null, [], "", false, Infinity, NaN, an object) silences rather
// than reaching threshold's evaluateExpected, which would otherwise fabricate a satisfied/violated
// verdict out of a degraded reading. Deliberately NOT applied to the scalar-passthrough branch --
// see this file's header comment ("Lock A ... passes the resolved scalar straight to
// evaluateExpected unchanged, which is what keeps Lock A byte-identical to v1 over ANY input,
// finite or not").
function isLatestAdmissibleValue(value) {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return value.length > 0;
  return false;
}

// M7 (fix-spec, #10 "minimal survivable depth cap"): evaluateFeatureNode recurses once per node
// on the way down its `of` chain with no depth limit -- an adversarial/malformed node graph (or
// just a very deep legitimate one) can exhaust the call stack (RangeError), which is a crash, not
// a silence -- and a crash is strictly worse than "no claim". This is the MINIMAL survivable cap
// only: a fixed ceiling that turns a stack overflow into an ordinary `{ supported: false }`. It is
// not the full runtime budget analyzer (node/row/fuel/timeout) the fix-spec explicitly defers.
const MAX_FEATURE_NODE_DEPTH = 64;

/**
 * Evaluates one FeatureNode against `factSeriesInput` (see the header comment for its shape).
 * Returns a discriminated union:
 *   { supported: false }
 *   { supported: true, kind: "scalar", value }
 *   { supported: true, kind: "series", points: [{ ts, value }, ...] }
 * Pure; no I/O. `opts.now` (epoch-ms number or ISO string) optionally overrides "window"'s
 * reference point -- when absent, "window" uses the latest ts present in its own input series,
 * which is what keeps this interpreter deterministic/testable without a wall-clock dependency.
 */
export function evaluateFeatureNode(node, factSeriesInput, opts = {}) {
  return evaluateFeatureNodeAtDepth(node, factSeriesInput, opts, 0);
}

// The actual recursive interpreter, threading a depth counter (M7) that never leaks into the
// public signature above -- every recursive call in this function MUST go through this depth-
// carrying helper (never the public `evaluateFeatureNode` wrapper), or the depth counter resets
// to 0 at that call site and the cap stops protecting that branch of the graph.
function evaluateFeatureNodeAtDepth(node, factSeriesInput, opts, depth) {
  if (depth > MAX_FEATURE_NODE_DEPTH) return { supported: false }; // M7: survivable depth cap
  if (!node || typeof node !== "object") return { supported: false };

  switch (node.op) {
    case "fact": {
      // M1 (fix-spec, #5a prototype pollution): resolve OWN properties only. A plain `[key]`
      // lookup also resolves INHERITED properties (`name:"toString"` over `{}` would otherwise
      // resolve `Object.prototype.toString`, a function, as if it were a real fact value) --
      // Object.hasOwn gates that out while a genuine own-property scalar/series still resolves
      // exactly as before (Lock A intact).
      if (!factSeriesInput || typeof factSeriesInput !== "object" || !Object.hasOwn(factSeriesInput, node.name)) {
        return { supported: false }; // no fact, no claim
      }
      const raw = factSeriesInput[node.name];
      if (raw === undefined) return { supported: false }; // no fact, no claim
      if (Array.isArray(raw)) return { supported: true, kind: "series", points: raw };
      return { supported: true, kind: "scalar", value: raw };
    }

    case "latest": {
      const of = evaluateFeatureNodeAtDepth(node.of, factSeriesInput, opts, depth + 1);
      if (!of.supported) return { supported: false };
      if (of.kind === "scalar") return of; // already latest-wins; passthrough, matches v1 exactly
      const sorted = sortedValidPoints(of.points);
      if (sorted.length === 0) return { supported: false };
      const last = sorted[sorted.length - 1];
      // M2 (fix-spec, #5b latest missing value) + R8-latest (fix-spec, round 2): a point that
      // lacks a `value` key, or whose value is not a finite number/non-empty string, silences
      // rather than fabricating a verdict out of a degraded series point -- see
      // isLatestAdmissibleValue's doc comment for why this gate is scoped to the series path only.
      if (!isLatestAdmissibleValue(last.value)) return { supported: false };
      return { supported: true, kind: "scalar", value: last.value };
    }

    case "window": {
      const of = evaluateFeatureNodeAtDepth(node.of, factSeriesInput, opts, depth + 1);
      if (!of.supported || of.kind !== "series") return { supported: false }; // cannot window a scalar

      const ms = Number(node.ms);
      if (!Number.isFinite(ms) || ms < 0) return { supported: false };

      const sorted = sortedValidPoints(of.points);
      if (sorted.length === 0) return { supported: false };

      const refTs = Number.isFinite(toEpochMs(opts.now)) ? toEpochMs(opts.now) : toEpochMs(sorted[sorted.length - 1].ts);
      const windowed = sorted.filter((p) => {
        const t = toEpochMs(p.ts);
        return t <= refTs && t >= refTs - ms;
      });
      if (windowed.length === 0) return { supported: false };
      if (hasNonFiniteValue(windowed)) return { supported: false }; // degraded window -> silence, never fabricate

      return { supported: true, kind: "series", points: windowed };
    }

    case "zscore": {
      const of = evaluateFeatureNodeAtDepth(node.of, factSeriesInput, opts, depth + 1);
      if (!of.supported || of.kind !== "series") return { supported: false };

      const stddevFloor = Number(node.stddevFloor);
      if (!Number.isFinite(stddevFloor) || stddevFloor < 0) return { supported: false };

      // M4 (fix-spec, #6 minSamples + empty guard): minSamples must coerce to an INTEGER >= 2, or
      // the node silences -- 0/negative/fractional values used to be accepted (finite was the only
      // check), which let `sorted.length < minSamples` pass even for an EMPTY sorted array (e.g.
      // minSamples=0), falling through to `sorted[sorted.length - 1]` === `sorted[-1]` ===
      // undefined and crashing on `.value`. The explicit `sorted.length === 0` check below is
      // redundant once minSamples>=2 is enforced (0 < 2 already fails the length check) but is
      // kept as a defensive, unconditional guard BEFORE any array deref -- no path here may throw.
      const minSamplesRaw = node.minSamples === undefined ? DEFAULT_MIN_ZSCORE_SAMPLES : Number(node.minSamples);
      if (!Number.isInteger(minSamplesRaw) || minSamplesRaw < 2) return { supported: false };
      const minSamples = minSamplesRaw;

      const sorted = sortedValidPoints(of.points);
      if (sorted.length === 0 || sorted.length < minSamples) return { supported: false }; // sub-threshold window length
      if (hasNonFiniteValue(sorted)) return { supported: false }; // degraded input -> silence, never fabricate

      // Fold EVERY selected point (including the latest one) through the shared Welford
      // primitive, then score the latest point against those stats. Deliberately INCLUSIVE --
      // unlike peer-baseline.js's self-dampening exclude-latest convention -- because Lock B's
      // contract is "golden-equals a direct foldWelford+computeZScore over the same windowed
      // points" (plan §5, "one baseline detector re-expressed byte-identically"). Whether v2's
      // real windowed detectors want inclusive or exclusive scoring is exactly the kind of
      // question the spike's go/no-go (plan §6, "IR shape") exists to answer -- not decided here.
      const stats = sorted.reduce((acc, p) => foldWelford(acc, Number(p.value)), emptyWelfordStats());
      // R8-welford (fix-spec, round 2): reject on a non-finite WELFORD STATE component BEFORE
      // calling computeZScore. Every input point already passed the finite-point gate above, but
      // the running fold itself can still overflow to +/-Infinity/NaN on extreme-magnitude inputs
      // (e.g. Number.MAX_VALUE paired with -Number.MAX_VALUE) -- and computeZScore silently
      // replaces a non-finite mean with 0 (`Number.isFinite(meanBefore) ? meanBefore : 0`), which
      // launders an overflowed state into a plausible-looking FINITE z-score that the M6 result
      // check below would never catch. Checking the state itself, not just the final result,
      // closes that laundering path.
      if (![stats.mean, stats.stddev, stats.variance, stats.m2].every(Number.isFinite)) {
        return { supported: false };
      }
      const latest = sorted[sorted.length - 1];
      const value = computeZScore(Number(latest.value), stats.mean, stats.stddev, stddevFloor);
      // M6 (fix-spec, #8 overflow): the computed statistic can itself be non-finite (arithmetic
      // overflow to +/-Infinity on extreme-magnitude inputs) even though every INPUT point passed
      // the finite-point gate above -- silence rather than emit an overflowed statistic. Kept as a
      // backstop even with the state check above (R8-welford guards the STATE, this guards the
      // RESULT -- belt and suspenders).
      if (!Number.isFinite(value)) return { supported: false };

      return { supported: true, kind: "scalar", value };
    }

    case "cusum": {
      // Slice-1 spike step 3 (plan §8 item 3): two-sided tabular CUSUM over a series, typically
      // `window(...)`'s already ts-filtered/sorted output -- but sorted defensively here too,
      // matching window/zscore's own defensive re-sort. `target` is the reference level (a finite
      // number, or the literal string "mean" -- the series' own Welford mean, reusing the SAME
      // shared primitive zscore uses, not a re-derived copy). `k` is the CUSUM allowance/slack
      // (fix-spec M5: `k` must be a non-negative finite number -- a negative `k` amplifies every
      // step instead of damping it, fabricating a changepoint out of ordinary noise). Emits the
      // scalar `value = max over the whole series of max(S_hi, S_lo)` (the peak accumulation) -- a
      // `threshold` model node then fires when this crosses the decision interval h. Missing-input
      // -> silence, same discipline as window/zscore: a non-series `of`, an empty/sub-minSamples
      // series (fix-spec M4, same integer->=2 + pre-deref empty guard as zscore), any non-finite
      // point (fix-spec M3), a non-finite or negative `k` (fix-spec M5), a `target` that is
      // neither a finite number nor "mean", a "mean" that isn't finite, or an overflowed resulting
      // statistic (fix-spec M6) all silence the whole node -- never a fabricated statistic.
      const of = evaluateFeatureNodeAtDepth(node.of, factSeriesInput, opts, depth + 1);
      if (!of.supported || of.kind !== "series") return { supported: false }; // cannot cusum a scalar

      const k = Number(node.k);
      if (!Number.isFinite(k) || k < 0) return { supported: false };

      const minSamplesRaw = node.minSamples === undefined ? DEFAULT_MIN_CUSUM_SAMPLES : Number(node.minSamples);
      if (!Number.isInteger(minSamplesRaw) || minSamplesRaw < 2) return { supported: false };
      const minSamples = minSamplesRaw;

      const sorted = sortedValidPoints(of.points);
      if (sorted.length === 0 || sorted.length < minSamples) return { supported: false }; // sub-threshold sample count
      if (hasNonFiniteValue(sorted)) return { supported: false }; // degraded input -> silence, never fabricate

      let target;
      if (node.target === "mean") {
        const stats = sorted.reduce((acc, p) => foldWelford(acc, Number(p.value)), emptyWelfordStats());
        if (!Number.isFinite(stats.mean)) return { supported: false };
        target = stats.mean;
      } else {
        target = Number(node.target);
        if (!Number.isFinite(target)) return { supported: false };
      }

      // Classic two-sided tabular CUSUM: S_hi/S_lo start at 0 and are clipped at 0 every step, so
      // both are always >= 0 by construction -- maxStat starting at 0 and tracking the running
      // max of both statistics IS "the max over the whole series of max(S_hi, S_lo)".
      let sHi = 0;
      let sLo = 0;
      let maxStat = 0;
      for (const p of sorted) {
        const x = Number(p.value);
        sHi = Math.max(0, sHi + (x - target - k));
        sLo = Math.max(0, sLo + (target - k - x));
        if (sHi > maxStat) maxStat = sHi;
        if (sLo > maxStat) maxStat = sLo;
      }
      // M6 (fix-spec, #8 overflow): see the matching guard in "zscore" above.
      if (!Number.isFinite(maxStat)) return { supported: false };

      return { supported: true, kind: "scalar", value: maxStat };
    }

    default:
      return { supported: false };
  }
}

function evaluateModelNode(node, featureResult) {
  if (!node || typeof node !== "object") return { supported: false };

  switch (node.op) {
    case "threshold": {
      if (!featureResult.supported || featureResult.kind !== "scalar") return { supported: false };
      // Reused EXACTLY -- this is what makes Lock A byte-identical by construction, not by a
      // re-derived copy of the comparator logic (see constraint-eval.js's own doc comment).
      const { supported, satisfied } = evaluateExpected(node.expected, featureResult.value);
      if (!supported) return { supported: false };
      return { supported: true, satisfied, fired: !satisfied, value: featureResult.value };
    }

    default:
      return { supported: false };
  }
}

/**
 * Evaluates a v2 model record's feature DAG, then its model node. Returns a verdict object
 * (loosely mirroring evaluateShadowConstraints' candidate shape):
 *   { supported: false }
 *   { supported: true, satisfied, fired: !satisfied, value }
 * Pure; no I/O. `opts` is forwarded to the feature interpreter (currently only `opts.now`, see
 * evaluateFeatureNode's doc comment).
 */
export function evaluateModel(record, factSeriesInput, opts = {}) {
  const featureResult = evaluateFeatureNode(record?.feature, factSeriesInput, opts);
  return evaluateModelNode(record?.model, featureResult);
}

/**
 * Dual-read routing (plan §2.1): `kind:"constraint"` records evaluate on the EXISTING v1 path
 * (evaluateExpected against `inputs.factLookup(record.target)`, unchanged -- same skip semantics
 * as evaluateConstraints: an undefined fact or unsupported `expected` shape is `{supported:false}`,
 * "no fact, no claim"), and `kind:"model"` records evaluate via evaluateModel against
 * `inputs.factSeries`. v1 records are NEVER migrated or reinterpreted through the v2 interpreter.
 */
export function evaluateRecord(record, inputs = {}, opts = {}) {
  if (!record || typeof record !== "object") return { supported: false };

  if (record.kind === "constraint") {
    const factLookup = inputs.factLookup;
    if (typeof factLookup !== "function") return { supported: false };
    const factValue = factLookup(record.target);
    if (factValue === undefined) return { supported: false };
    const { supported, satisfied } = evaluateExpected(record.expected, factValue);
    if (!supported) return { supported: false };
    return { supported: true, satisfied, fired: !satisfied, value: factValue };
  }

  if (record.kind === MODEL_KIND) {
    return evaluateModel(record, inputs.factSeries, opts);
  }

  return { supported: false };
}
