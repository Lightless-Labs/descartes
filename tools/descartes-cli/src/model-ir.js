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
// input is missing, empty, too short, or (for window/zscore, the genuinely new windowed-series
// surface) contains a non-finite value anywhere inside the selected window. That last rule is
// deliberately conservative: ONE degraded point silences the whole window rather than being
// quietly dropped, because folding partial/degraded data into a stat is itself a form of
// fabrication. This is a stricter contract than v1's evaluateExpected (which downgrades a
// non-finite *scalar* fact to `satisfied:false`, not silence) -- but "latest" + "threshold"
// (Lock A) never applies this stricter rule; it passes the resolved scalar straight to
// evaluateExpected unchanged, which is what keeps Lock A byte-identical to v1 over ANY input,
// finite or not. The stricter degrade-to-silence rule applies only to window/zscore, the new
// series surface the plan calls out explicitly (§2.1: "a windowed feature with too few / degraded
// points emits nothing, never a fabricated value").

import { evaluateExpected } from "./constraint-eval.js";
import { computeZScore, emptyWelfordStats, foldWelford } from "./welford-stats.js";

export const MODEL_KIND = "model";
export const MODEL_SCHEMA_VERSION = 2;

// zscore's minimum sample count before it will emit a value at all (a single point has variance
// 0 by construction -- not "wrong", but not meaningfully a z-score either). Overridable per-node
// via `node.minSamples`; kept as a named default rather than a magic number.
export const DEFAULT_MIN_ZSCORE_SAMPLES = 2;

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

  const id = String(record.id ?? "").trim();
  if (!id) throw new Error("Model record requires a non-empty id");

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

// Drops any point without a parseable ts (a corrupt/missing timestamp excludes just that point --
// see the header comment) and returns the rest sorted ascending by ts. Used wherever "latest" or
// "the window" needs a well-defined order.
function sortedValidPoints(points) {
  return points
    .filter((p) => p && typeof p === "object" && Number.isFinite(toEpochMs(p.ts)))
    .slice()
    .sort((a, b) => toEpochMs(a.ts) - toEpochMs(b.ts));
}

function hasNonFiniteValue(points) {
  return points.some((p) => !Number.isFinite(Number(p.value)));
}

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
  if (!node || typeof node !== "object") return { supported: false };

  switch (node.op) {
    case "fact": {
      const raw = factSeriesInput ? factSeriesInput[node.name] : undefined;
      if (raw === undefined) return { supported: false }; // no fact, no claim
      if (Array.isArray(raw)) return { supported: true, kind: "series", points: raw };
      return { supported: true, kind: "scalar", value: raw };
    }

    case "latest": {
      const of = evaluateFeatureNode(node.of, factSeriesInput, opts);
      if (!of.supported) return { supported: false };
      if (of.kind === "scalar") return of; // already latest-wins; passthrough, matches v1 exactly
      const sorted = sortedValidPoints(of.points);
      if (sorted.length === 0) return { supported: false };
      const last = sorted[sorted.length - 1];
      return { supported: true, kind: "scalar", value: last.value };
    }

    case "window": {
      const of = evaluateFeatureNode(node.of, factSeriesInput, opts);
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
      const of = evaluateFeatureNode(node.of, factSeriesInput, opts);
      if (!of.supported || of.kind !== "series") return { supported: false };

      const stddevFloor = Number(node.stddevFloor);
      if (!Number.isFinite(stddevFloor) || stddevFloor < 0) return { supported: false };

      const minSamples = Number.isFinite(Number(node.minSamples)) ? Number(node.minSamples) : DEFAULT_MIN_ZSCORE_SAMPLES;

      const sorted = sortedValidPoints(of.points);
      if (sorted.length < minSamples) return { supported: false }; // sub-threshold window length
      if (hasNonFiniteValue(sorted)) return { supported: false }; // degraded input -> silence, never fabricate

      // Fold EVERY selected point (including the latest one) through the shared Welford
      // primitive, then score the latest point against those stats. Deliberately INCLUSIVE --
      // unlike peer-baseline.js's self-dampening exclude-latest convention -- because Lock B's
      // contract is "golden-equals a direct foldWelford+computeZScore over the same windowed
      // points" (plan §5, "one baseline detector re-expressed byte-identically"). Whether v2's
      // real windowed detectors want inclusive or exclusive scoring is exactly the kind of
      // question the spike's go/no-go (plan §6, "IR shape") exists to answer -- not decided here.
      const stats = sorted.reduce((acc, p) => foldWelford(acc, Number(p.value)), emptyWelfordStats());
      const latest = sorted[sorted.length - 1];
      const value = computeZScore(Number(latest.value), stats.mean, stats.stddev, stddevFloor);

      return { supported: true, kind: "scalar", value };
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
