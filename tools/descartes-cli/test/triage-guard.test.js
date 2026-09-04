import assert from "node:assert/strict";
import test from "node:test";
import {
  createEvidenceGuardState,
  evidenceGuardDiagnostics,
  evidenceRequiredRetryPrompt,
  hasCollectedEvidence,
  isUsableEvidence,
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

test("isUsableEvidence rejects failed-collector envelopes and accepts everything else", () => {
  assert.equal(isUsableEvidence({ id: "system-overview", status: "unable", confidence: 0 }), false);
  assert.equal(isUsableEvidence({ id: "system-overview", status: "ok" }), true);
  assert.equal(isUsableEvidence({ id: "containers", status: "unsupported" }), true);
  assert.equal(isUsableEvidence({ id: "vms", status: "unknown" }), true);
  assert.equal(isUsableEvidence({ id: "system-overview" }), true);
  assert.equal(isUsableEvidence(undefined), false);
  assert.equal(isUsableEvidence(null), false);
});

test("hasCollectedEvidence ignores unable-status entries but counts a single usable entry among them", () => {
  assert.equal(hasCollectedEvidence([{ id: "system-overview", status: "unable", confidence: 0 }]), false);
  assert.equal(hasCollectedEvidence([
    { id: "system-overview", status: "unable", confidence: 0 },
    { id: "disk-usage", status: "unable", confidence: 0 },
  ]), false);
  assert.equal(hasCollectedEvidence([
    { id: "system-overview", status: "unable", confidence: 0 },
    { id: "top-processes", status: "ok" },
  ]), true);
  assert.equal(hasCollectedEvidence([]), false);
});

test("evidence guard retries then falls back when every collected envelope is status unable across both rounds", () => {
  const guard = createEvidenceGuardState({ investigationEnabled: true });
  const failedEvidence = [{ id: "system-overview", status: "unable", confidence: 0 }];

  assert.equal(shouldRetryForEvidence({ guard, assistantText: "Looks fine", evidence: failedEvidence }), true);
  markEvidenceGuardRetry(guard);
  assert.equal(guard.retry_count, 1);

  // Second round still only produced failed envelopes.
  assert.equal(shouldRetryForEvidence({ guard, assistantText: "Still looks fine", evidence: failedEvidence }), false);
  markEvidenceGuardSatisfied(guard, failedEvidence);
  assert.equal(guard.outcome, "retry_requested", "must not be marked satisfied by unable-only evidence");
  assert.equal(shouldFallbackForNoEvidence({ guard, assistantText: "Still looks fine", evidence: failedEvidence }), true);
  markEvidenceGuardFallback(guard);

  assert.deepEqual(evidenceGuardDiagnostics(guard), {
    enabled: true,
    outcome: "fallback_precollected",
    retry_count: 1,
    fallback_reason: "no_evidence_after_retry",
  });
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
