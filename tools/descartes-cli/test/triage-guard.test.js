import assert from "node:assert/strict";
import test from "node:test";
import {
  createEvidenceGuardState,
  evidenceGuardDiagnostics,
  evidenceRequiredRetryPrompt,
  markEvidenceGuardFallback,
  markEvidenceGuardRetry,
  markEvidenceGuardSatisfied,
  shouldFallbackForNoEvidence,
  shouldRetryForEvidence,
} from "../src/triage-guard.js";

test("evidence guard requests one retry for assistant text without collected evidence", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: true });

  assert.equal(shouldRetryForEvidence({ guard, assistantText: "Looks fine", evidence: [] }), true);
  markEvidenceGuardRetry(guard);
  assert.equal(guard.retry_count, 1);
  assert.equal(guard.outcome, "retry_requested");
  assert.equal(shouldRetryForEvidence({ guard, assistantText: "Still looks fine", evidence: [] }), false);
});

test("evidence guard is satisfied when retry collects evidence", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: true });
  markEvidenceGuardRetry(guard);
  markEvidenceGuardSatisfied(guard, [{ id: "system-overview" }]);

  assert.deepEqual(evidenceGuardDiagnostics(guard), {
    enabled: true,
    outcome: "satisfied_after_retry",
    retry_count: 1,
    fallback_reason: undefined,
  });
});

test("evidence guard exposes degraded fallback diagnostics after retry still has no evidence", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: true });
  markEvidenceGuardRetry(guard);

  assert.equal(shouldFallbackForNoEvidence({ guard, assistantText: "Unsupported diagnosis", evidence: [] }), true);
  markEvidenceGuardFallback(guard);

  assert.deepEqual(evidenceGuardDiagnostics(guard), {
    enabled: true,
    outcome: "fallback_precollected",
    retry_count: 1,
    fallback_reason: "no_evidence_after_retry",
  });
});

test("evidence guard falls back when assistant returns no text and no evidence", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: true });

  assert.equal(shouldRetryForEvidence({ guard, assistantText: "", evidence: [] }), false);
  assert.equal(shouldFallbackForNoEvidence({ guard, assistantText: "", evidence: [] }), true);
  markEvidenceGuardFallback(guard, "no_evidence_no_assistant_text");

  assert.deepEqual(evidenceGuardDiagnostics(guard), {
    enabled: true,
    outcome: "fallback_precollected",
    retry_count: 0,
    fallback_reason: "no_evidence_no_assistant_text",
  });
});

test("evidence retry prompt explicitly requires Descartes evidence tools", () => {
  const prompt = evidenceRequiredRetryPrompt("what is using CPU?", { json: true });

  assert.match(prompt, /must now call collect_triage_evidence/);
  assert.match(prompt, /targeted Descartes evidence tools/);
  assert.match(prompt, /return only valid JSON/);
});

test("evidence guard is disabled for no-investigate synthesis", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: false });

  assert.equal(shouldRetryForEvidence({ guard, assistantText: "Looks fine", evidence: [] }), false);
  assert.deepEqual(evidenceGuardDiagnostics(guard), {
    enabled: false,
    outcome: "disabled",
    retry_count: 0,
    fallback_reason: undefined,
  });
});
