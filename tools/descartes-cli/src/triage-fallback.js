export function fallbackDiagnosis(prompt, evidence, findings, llmError) {
  const substantiveFindings = findings.filter((finding) => finding.id !== "insufficient_evidence");
  return {
    summary: substantiveFindings[0]?.summary ?? (llmError ? "Descartes collected evidence, but the LLM request failed." : "Descartes collected evidence, but the model returned no diagnosis text."),
    confidence: substantiveFindings.length > 0 ? "medium" : "low",
    explanation: substantiveFindings.length > 0
      ? `Fallback deterministic summary generated because the LLM-backed session produced no final text${llmError ? ` (${llmError})` : ""}. Review findings and evidence directly.`
      : `Fallback deterministic summary generated because the LLM-backed session produced no final text${llmError ? ` (${llmError})` : ""} and no obvious first-slice resource-pressure threshold was crossed.`,
    evidence_refs: [...new Set(findings.flatMap((finding) => finding.evidence_refs ?? []))].filter(Boolean).length > 0
      ? [...new Set(findings.flatMap((finding) => finding.evidence_refs ?? []))].filter(Boolean)
      : evidence.map((item) => item.id),
    next_checks: [
      "Re-run the command with --json and inspect evidence/tool traces.",
      "Check the top CPU and memory process lists for expected workload.",
      "If this repeats, update Descartes and report the empty model response as a bug.",
    ],
    avoid: ["Do not kill unknown system processes based only on this fallback summary."],
    actions_taken: [],
    fallback: true,
    llm_error: llmError,
  };
}
