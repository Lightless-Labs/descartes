import assert from "node:assert/strict";
import test from "node:test";
import { evaluateConstraints } from "../src/constraint-eval.js";
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
