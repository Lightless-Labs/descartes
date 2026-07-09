// Pure, deterministic evaluator: active constraints + current facts -> alert-store
// candidate objects (Slice 2, plan §2/§4). No I/O, no mining, no LLM.
//
// evaluateConstraints() is not yet wired into the daemon loop (that is a later slice) —
// it is exposed here purely as a pipeline seam consumed by evaluateAndPersistAlerts'
// new `extraCandidates` option (see alert-store.js).

import { alertId } from "./alert-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";

function evaluateNumericComparator(comparator, factValue, expectedValue) {
  switch (comparator) {
    case "gte":
      return factValue >= expectedValue;
    case "lte":
      return factValue <= expectedValue;
    case "eq":
      return factValue === expectedValue;
    default:
      return undefined;
  }
}

/**
 * Checks `factValue` against `expected`, supporting the two seed shapes:
 *   - { comparator: "gte" | "lte" | "eq", value: <number> }
 *   - { pattern: "ends_with:<suffix>" }
 * Returns { supported: false } for any other/malformed shape (deterministic code refuses
 * to guess) and { supported: true, satisfied } otherwise.
 */
function evaluateExpected(expected, factValue) {
  if (!expected || typeof expected !== "object") return { supported: false };

  if (typeof expected.comparator === "string" && Number.isFinite(Number(expected.value))) {
    const numericFact = Number(factValue);
    if (!Number.isFinite(numericFact)) return { supported: true, satisfied: false };
    const satisfied = evaluateNumericComparator(expected.comparator, numericFact, Number(expected.value));
    if (satisfied === undefined) return { supported: false };
    return { supported: true, satisfied };
  }

  if (typeof expected.pattern === "string") {
    const match = expected.pattern.match(/^ends_with:(.*)$/);
    if (match) {
      const suffix = match[1];
      const satisfied = typeof factValue === "string" && factValue.endsWith(suffix);
      return { supported: true, satisfied };
    }
  }

  return { supported: false };
}

function buildViolationCandidate(constraint, factValue) {
  const ruleId = `constraint.violation.${constraint.family}`;
  const fingerprint = String(constraint.id ?? constraint.target ?? "global");
  const diagnostics = sanitizeDiagnostics({
    constraint_id: constraint.id,
    family: constraint.family,
    target: constraint.target,
    expected_comparator: constraint.expected?.comparator,
    expected_value: constraint.expected?.value,
    expected_pattern: constraint.expected?.pattern,
    actual: factValue,
  });
  return {
    id: alertId(ruleId, fingerprint),
    rule_id: ruleId,
    fingerprint,
    severity: "warning",
    title: `Constraint violated: ${constraint.id}`,
    summary: `Learned constraint "${constraint.id}" (family: ${constraint.family}) is violated for target "${constraint.target}".`,
    diagnostics,
    evidence_refs: ["constraint-store"],
  };
}

/**
 * Evaluates every `status:"active"` constraint against `factLookup(constraint.target)`.
 * - Non-active constraints are ignored entirely.
 * - If `factLookup` returns `undefined` for a target, that constraint is SKIPPED (no fact,
 *   no claim) rather than treated as a violation.
 * - Satisfied constraints and constraints with an unsupported `expected` shape emit nothing.
 * - Violations emit exactly one candidate, in the same shape alert-store's fixed rules
 *   already emit, with `diagnostics` routed through `sanitizeDiagnostics()`.
 */
export function evaluateConstraints(activeConstraints, factLookup) {
  const candidates = [];
  for (const constraint of activeConstraints ?? []) {
    if (!constraint || constraint.status !== "active") continue;

    const factValue = factLookup(constraint.target);
    if (factValue === undefined) continue;

    const { supported, satisfied } = evaluateExpected(constraint.expected, factValue);
    if (!supported || satisfied) continue;

    candidates.push(buildViolationCandidate(constraint, factValue));
  }
  return candidates;
}
