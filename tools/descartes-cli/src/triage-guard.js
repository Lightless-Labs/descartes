export function createEvidenceGuardState({ investigationEnabled }) {
  return {
    enabled: Boolean(investigationEnabled),
    outcome: investigationEnabled ? "pending" : "disabled",
    retry_count: 0,
    fallback_reason: undefined,
  };
}

export function hasCollectedEvidence(evidence) {
  return Array.isArray(evidence) && evidence.length > 0;
}

export function shouldRetryForEvidence({ guard, assistantText, evidence, maxRetries = 1 }) {
  return Boolean(
    guard?.enabled &&
    typeof assistantText === "string" &&
    assistantText.trim() &&
    !hasCollectedEvidence(evidence) &&
    guard.retry_count < maxRetries
  );
}

export function shouldFallbackForNoEvidence({ guard, assistantText, evidence }) {
  const hasAssistantText = typeof assistantText === "string" && assistantText.trim().length > 0;
  return Boolean(
    guard?.enabled &&
    !hasCollectedEvidence(evidence) &&
    (!hasAssistantText || guard.retry_count >= 1)
  );
}

export function markEvidenceGuardRetry(guard) {
  guard.retry_count += 1;
  guard.outcome = "retry_requested";
  return guard;
}

export function markEvidenceGuardSatisfied(guard, evidence) {
  if (!guard.enabled) return guard;
  if (hasCollectedEvidence(evidence)) guard.outcome = guard.retry_count > 0 ? "satisfied_after_retry" : "satisfied";
  return guard;
}

export function markEvidenceGuardFallback(guard, reason = "no_evidence_after_retry") {
  guard.outcome = "fallback_precollected";
  guard.fallback_reason = reason;
  return guard;
}

export function evidenceRequiredRetryPrompt(userPrompt, { json = false } = {}) {
  const outputInstruction = json
    ? "After collecting evidence, return only valid JSON in the requested diagnosis shape."
    : "After collecting evidence, print the concise operator-facing report in the requested format.";
  return `The previous response did not include any Descartes evidence tool results. Do not diagnose from general knowledge.

You must now call collect_triage_evidence, or call targeted Descartes evidence tools that directly support the user's question, before giving a diagnosis.

User complaint: ${JSON.stringify(userPrompt)}

${outputInstruction}`;
}

export function evidenceGuardDiagnostics(guard) {
  return {
    enabled: guard.enabled,
    outcome: guard.outcome,
    retry_count: guard.retry_count,
    fallback_reason: guard.fallback_reason,
  };
}
