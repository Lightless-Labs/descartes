import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { evaluateConstraints, evaluateExpected, evaluateShadowConstraints } from "../src/constraint-eval.js";
import { SEED_CONSTRAINTS } from "../src/constraint-store.js";

function numericConstraint(overrides = {}) {
  return {
    id: "constraint.test.numeric",
    kind: "constraint",
    family: "test-family",
    target: "test.numeric.target",
    expected: { comparator: "gte", value: 1000 },
    status: "active",
    confidence: 1,
    schema_version: 1,
    ...overrides,
  };
}

function patternConstraint(overrides = {}) {
  return {
    id: "constraint.test.pattern",
    kind: "constraint",
    family: "test-pattern-family",
    target: "test.pattern.target",
    expected: { pattern: "ends_with:/descartes" },
    status: "active",
    confidence: 1,
    schema_version: 1,
    ...overrides,
  };
}

// Satisfies every seed constraint's `expected` shape (see constraint-store.js SEED_CONSTRAINTS).
function satisfyingFactLookup(target) {
  const facts = {
    "daemon.profile.interval_ms": 60_000,
    "paths.stateDir": "/home/alice/.local/state/descartes",
    "paths.configDir": "/home/alice/.config/descartes",
    "alert-store.DEFAULT_ALERT_COOLDOWN_MS": 15 * 60 * 1000,
  };
  return facts[target];
}

test("evaluateConstraints emits a constraint.violation.<family> candidate for a synthetic violating numeric constraint", () => {
  const constraint = numericConstraint();
  const candidates = evaluateConstraints([constraint], () => 500); // 500 < 1000 gte threshold

  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.rule_id, "constraint.violation.test-family");
  assert.match(candidate.id, /^alert_/);
  assert.equal(candidate.fingerprint, constraint.id);
  assert.equal(candidate.severity, "warning");
  assert.equal(typeof candidate.title, "string");
  assert.equal(typeof candidate.summary, "string");
  assert.deepEqual(candidate.evidence_refs, ["constraint-store"]);
  assert.equal(typeof candidate.diagnostics, "object");
  assert.equal(candidate.diagnostics.actual, 500);
});

test("evaluateConstraints/buildViolationCandidate: a hand-authored active constraint with a raw path as its id/target cannot leak the raw path into title/summary/fingerprint (Codex review Blocker 1, real part)", () => {
  const rawPath = "/Users/alice/.ssh/id_rsa";
  const constraint = {
    id: rawPath,
    kind: "constraint",
    family: "path-invariant",
    target: rawPath,
    expected: { pattern: "ends_with:/nonexistent" }, // never satisfied -> always violated
    status: "active",
    confidence: 1,
    schema_version: 1,
  };

  const candidates = evaluateConstraints([constraint], () => rawPath);
  assert.equal(candidates.length, 1);
  const [candidate] = candidates;

  assert.equal(candidate.title.includes("/Users"), false);
  assert.equal(candidate.summary.includes("/Users"), false);
  assert.equal(candidate.fingerprint.includes("/Users"), false);
  assert.equal(candidate.title.includes(rawPath), false);
  assert.equal(candidate.summary.includes(rawPath), false);
  assert.equal(candidate.fingerprint.includes(rawPath), false);

  // diagnostics stays routed through sanitizeDiagnostics — unaffected by, and unchanged by,
  // this fix.
  assert.equal(candidate.diagnostics.constraint_id.redacted, true);
  assert.equal(candidate.diagnostics.target.redacted, true);
});

test("evaluateConstraints emits a violation for a synthetic violating pattern constraint and sanitizes the raw actual value", () => {
  const constraint = patternConstraint();
  const candidates = evaluateConstraints([constraint], () => "/home/alice/.local/state"); // does not end with /descartes

  assert.equal(candidates.length, 1);
  const [candidate] = candidates;
  assert.equal(candidate.rule_id, "constraint.violation.test-pattern-family");
  // The raw path must never appear verbatim in diagnostics; sanitizeDiagnostics redacts it.
  assert.equal(candidate.diagnostics.actual.redacted, true);
  assert.equal(JSON.stringify(candidate.diagnostics).includes("/home/alice"), false);
});

test("evaluateConstraints emits nothing for the seed constraints given a satisfying factLookup", () => {
  const candidates = evaluateConstraints(SEED_CONSTRAINTS, satisfyingFactLookup);
  assert.deepEqual(candidates, []);
});

test("evaluateConstraints skips a constraint whose factLookup returns undefined (no fact, no claim)", () => {
  const constraint = numericConstraint();
  const candidates = evaluateConstraints([constraint], () => undefined);
  assert.deepEqual(candidates, []);
});

test("evaluateConstraints ignores non-active constraints", () => {
  const draft = numericConstraint({ status: "draft" });
  const shadow = numericConstraint({ id: "constraint.test.shadow", status: "shadow" });
  const candidates = evaluateConstraints([draft, shadow], () => 500);
  assert.deepEqual(candidates, []);
});

test("evaluateConstraints emits nothing when a constraint's expected shape is unsupported", () => {
  const constraint = numericConstraint({ expected: { comparator: "between", value: 10 } });
  const candidates = evaluateConstraints([constraint], () => 5);
  assert.deepEqual(candidates, []);
});

test("evaluateConstraints emits nothing when the numeric constraint is satisfied", () => {
  const constraint = numericConstraint();
  const candidates = evaluateConstraints([constraint], () => 60_000); // >= 1000
  assert.deepEqual(candidates, []);
});

test("evaluateConstraints is pure: repeated calls with the same input produce the same output", () => {
  const constraint = numericConstraint();
  const first = evaluateConstraints([constraint], () => 500);
  const second = evaluateConstraints([constraint], () => 500);
  assert.deepEqual(first, second);
});

// --- S7a prerequisite fix: evaluateExpected string-eq branch (categorical eq, plan §5) ---

function categoricalConstraint(overrides = {}) {
  return {
    id: "constraint.test.categorical",
    kind: "constraint",
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    status: "active",
    confidence: 1,
    schema_version: 1,
    ...overrides,
  };
}

test("evaluateConstraints: categorical eq (string value) is satisfied when the fact matches exactly, unsupported-shape numeric eq behavior unchanged", () => {
  // New string-eq branch: matching string -> satisfied -> no candidate.
  assert.deepEqual(evaluateConstraints([categoricalConstraint()], () => "true"), []);

  // New string-eq branch: non-matching string -> violated -> exactly one candidate whose
  // diagnostics.actual reflects the real (mismatching) value.
  const violating = evaluateConstraints([categoricalConstraint()], () => "false");
  assert.equal(violating.length, 1);
  assert.equal(violating[0].diagnostics.actual, "false");

  // Regression: numeric eq (both value and fact are numeric-looking) is untouched by the new
  // branch — the first (numeric) branch in evaluateExpected still handles this case exactly
  // as before, since Number("5432") is finite and short-circuits before the new branch.
  const numericEq = numericConstraint({ expected: { comparator: "eq", value: 5432 } });
  assert.deepEqual(evaluateConstraints([numericEq], () => 5432), []);
  assert.equal(evaluateConstraints([numericEq], () => 5433).length, 1);
});

test("evaluateConstraints: seed constraints (numeric gte + ends_with pattern) evaluate byte-identically after the categorical eq branch is added", () => {
  const candidates = evaluateConstraints(SEED_CONSTRAINTS, satisfyingFactLookup);
  assert.deepEqual(candidates, []);
});

// --- S7a: evaluateShadowConstraints (constraint-eval.js, plan §5) ---

function shadowConstraint(overrides = {}) {
  return categoricalConstraint({ id: "constraint.test.shadow", status: "shadow", ...overrides });
}

test("evaluateShadowConstraints filters strictly on status:\"shadow\" (ignores draft/active/review-ready/retired)", () => {
  const draft = shadowConstraint({ id: "c.draft", status: "draft" });
  const active = shadowConstraint({ id: "c.active", status: "active" });
  const shadow = shadowConstraint({ id: "c.shadow", status: "shadow" });
  const reviewReady = shadowConstraint({ id: "c.review-ready", status: "review-ready" });
  const retired = shadowConstraint({ id: "c.retired", status: "retired" });

  const records = evaluateShadowConstraints([draft, active, shadow, reviewReady, retired], () => "false", { ts: "2026-07-10T00:00:00.000Z" });
  assert.equal(records.length, 1);
  assert.equal(records[0].constraint_id, "c.shadow");
});

test("evaluateShadowConstraints returns fired:true on violation and fired:false when satisfied", () => {
  const constraint = shadowConstraint();
  const ts = "2026-07-10T00:00:00.000Z";

  const violated = evaluateShadowConstraints([constraint], () => "false", { ts });
  assert.deepEqual(violated, [{
    ts,
    constraint_id: "constraint.test.shadow",
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    actual: "false",
    fired: true,
  }]);

  const satisfied = evaluateShadowConstraints([constraint], () => "true", { ts });
  assert.equal(satisfied.length, 1);
  assert.equal(satisfied[0].fired, false);
});

test("evaluateShadowConstraints mirrors evaluateConstraints' skip semantics for undefined facts and unsupported expected shapes", () => {
  const constraint = shadowConstraint();
  assert.deepEqual(evaluateShadowConstraints([constraint], () => undefined), []);

  const unsupported = shadowConstraint({ expected: { comparator: "between", value: 10 } });
  assert.deepEqual(evaluateShadowConstraints([unsupported], () => 5), []);
});

test("evaluateShadowConstraints never produces an alert-candidate-shaped object (structural safety property)", () => {
  const constraint = shadowConstraint();
  const [record] = evaluateShadowConstraints([constraint], () => "false", { ts: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(Object.keys(record).sort(), ["actual", "constraint_id", "expected", "family", "fired", "target", "ts"].sort());
  for (const forbiddenKey of ["id", "rule_id", "fingerprint", "severity", "title", "summary", "diagnostics", "evidence_refs"]) {
    assert.equal(forbiddenKey in record, false, `shadow record must never carry alert-candidate key "${forbiddenKey}"`);
  }
});

test("evaluateShadowConstraints is pure: repeated calls with the same input produce the same output", () => {
  const constraint = shadowConstraint();
  const first = evaluateShadowConstraints([constraint], () => "false", { ts: "2026-07-10T00:00:00.000Z" });
  const second = evaluateShadowConstraints([constraint], () => "false", { ts: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(first, second);
});

// --- S14 (plan §5.3/§5.8): evaluateExpected export is byte-identical-behavior ---
// (the export-only change: constraint-eval.js's currently-private evaluateExpected gains an
// `export` keyword, zero logic change. Every test above already re-exercises evaluateConstraints/
// evaluateShadowConstraints, which call evaluateExpected internally, unmodified and still passing
// -- this section additionally exercises the newly-exported function DIRECTLY, since S14's
// backtestRetune (tuning-store.js) calls it as a library function.)

test("evaluateExpected is exported and usable directly (numeric gte/lte, categorical eq, ends_with pattern, unsupported shape)", () => {
  assert.deepEqual(evaluateExpected({ comparator: "gte", value: 1000 }, 1000), { supported: true, satisfied: true });
  assert.deepEqual(evaluateExpected({ comparator: "gte", value: 1000 }, 999), { supported: true, satisfied: false });
  assert.deepEqual(evaluateExpected({ comparator: "lte", value: 10 }, 10), { supported: true, satisfied: true });
  assert.deepEqual(evaluateExpected({ comparator: "lte", value: 10 }, 11), { supported: true, satisfied: false });
  assert.deepEqual(evaluateExpected({ comparator: "eq", value: "true" }, "true"), { supported: true, satisfied: true });
  assert.deepEqual(evaluateExpected({ pattern: "ends_with:/descartes" }, "/home/alice/.config/descartes"), { supported: true, satisfied: true });
  assert.deepEqual(evaluateExpected({ comparator: "between", value: 10 }, 5), { supported: false });
});

test("evaluateExpected export: source-level proof this is the SAME function evaluateConstraints/evaluateShadowConstraints already call internally (not a second, divergent copy)", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/constraint-eval.js"), "utf8");
  const defs = source.match(/\bfunction evaluateExpected\b/g) ?? [];
  assert.equal(defs.length, 1, "expected exactly one evaluateExpected definition in constraint-eval.js");
  assert.match(source, /export function evaluateExpected/);
});
