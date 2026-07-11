// Pure, deterministic evaluator: active constraints + current facts -> alert-store
// candidate objects (Slice 2, plan §2/§4). No I/O, no mining, no LLM.
//
// evaluateConstraints() is not yet wired into the daemon loop (that is a later slice) —
// it is exposed here purely as a pipeline seam consumed by evaluateAndPersistAlerts'
// new `extraCandidates` option (see alert-store.js).

import { alertId } from "./alert-store.js";
import { sanitizeDiagnostics, sanitizeIdentityString } from "./diagnostics-sanitizer.js";

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

  // Categorical string-equality branch (S7a prerequisite fix, plan §5): S6c's miner emits
  // {comparator:"eq", value:<string>} for non-numeric-looking categorical values (e.g.
  // "true"/"false" for service.presence, an owner process name for port-binding-identity).
  // Number(expected.value) is NaN for those, so the numeric branch above never matches them
  // — this branch is additive and only reachable in exactly that case (comparator "eq" with a
  // string value that failed the numeric-finite guard above). The existing numeric "eq"
  // branch (a numeric-looking value, e.g. a port number as a string) is untouched and
  // remains byte-identical, since it already short-circuits into the branch above.
  if (expected.comparator === "eq" && typeof expected.value === "string") {
    return { supported: true, satisfied: String(factValue) === expected.value };
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

  // Codex review Blocker 1 (real part): title/summary/fingerprint used to interpolate
  // constraint.id/family/target directly — only `diagnostics` was sanitized. A mined
  // constraint's id/target are already bounded/safe by construction (constraint-miner.js
  // routes them through sanitizeIdentityString/buildConstraintTarget at mining time), so
  // sanitizeIdentityString is a no-op on them here (idempotent on an already-safe string) —
  // mined/seed candidates are byte-identical to before this change. A HAND-AUTHORED active
  // constraint carries no such guarantee, so every one of these three fields is bounded and
  // sanitized here, exactly like diagnostics already is, before it can reach title/summary
  // (which alert-intelligence.js copies verbatim into its LLM prompt) or fingerprint (an
  // outward-facing alert-store field).
  const safeId = sanitizeIdentityString(constraint.id);
  const safeFamily = sanitizeIdentityString(constraint.family) ?? "unknown";
  const safeTarget = sanitizeIdentityString(constraint.target);
  const fingerprint = String(safeId ?? safeTarget ?? "global");

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
    title: `Constraint violated: ${safeId ?? "unknown"}`,
    summary: `Learned constraint "${safeId ?? "unknown"}" (family: ${safeFamily}) is violated for target "${safeTarget ?? "unknown"}".`,
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

/**
 * Shadow-mode counterpart to evaluateConstraints (Slice S7a, plan §5): evaluates every
 * status:"shadow" constraint (never "active") against `factLookup`, reusing evaluateExpected
 * internally, but returns a record shape that is STRUCTURALLY distinct from an alert
 * candidate: `{ ts, constraint_id, family, target, expected, actual, fired }` — no `id`, no
 * `rule_id`, no `fingerprint`, no `diagnostics`, no `evidence_refs`. This function never
 * calls alertId() or buildViolationCandidate(), so "a shadow fire can't accidentally become a
 * real alert" is a property of the type signature itself, not a runtime check someone could
 * get wrong. Same skip semantics as evaluateConstraints: an undefined fact (factLookup
 * returns undefined) or an unsupported `expected` shape produces no record at all — not even
 * a fired:false one — mirroring "no fact, no claim". Pure, no I/O; `options.ts` is the only
 * source of "current time" (defaults to `new Date().toISOString()` for a bare call).
 */
export function evaluateShadowConstraints(shadowConstraints, factLookup, options = {}) {
  const ts = options.ts ?? new Date().toISOString();
  const records = [];
  for (const constraint of shadowConstraints ?? []) {
    if (!constraint || constraint.status !== "shadow") continue;

    const factValue = factLookup(constraint.target);
    if (factValue === undefined) continue;

    const { supported, satisfied } = evaluateExpected(constraint.expected, factValue);
    if (!supported) continue;

    records.push({
      ts,
      constraint_id: constraint.id,
      family: constraint.family,
      target: constraint.target,
      expected: constraint.expected,
      actual: factValue,
      fired: !satisfied,
    });
  }
  return records;
}
