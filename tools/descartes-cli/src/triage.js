import { createPrivateTriageSession, humanTriagePrompt, jsonTriagePrompt } from "./pi-harness.js";
import { collectAllEvidence } from "./tools/collect.js";

function parseTriageArgs(args) {
  const options = { json: false };
  const promptParts = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--json") options.json = true;
    else if (arg === "--model") options.modelPattern = args[++i];
    else if (arg === "--thinking") options.thinkingLevel = args[++i];
    else if (arg.startsWith("-")) throw new Error(`Unknown triage argument: ${arg}`);
    else promptParts.push(arg);
  }
  const prompt = promptParts.join(" ").trim();
  if (!prompt) throw new Error("Usage: descartes triage <PROMPT> [--json]");
  return { ...options, prompt };
}

function flattenEvidence(toolResults, precollected) {
  const evidenceById = new Map((precollected?.evidence ?? []).map((item) => [item.id, item]));
  const findingsById = new Map((precollected?.findings ?? []).map((item) => [item.id, item]));
  for (const entry of toolResults) {
    const details = entry.result?.details;
    if (!details) continue;
    if (details.id) evidenceById.set(details.id, details);
    if (Array.isArray(details.evidence)) {
      details.evidence.forEach((item) => evidenceById.set(item.id, item));
    }
    if (Array.isArray(details.findings)) {
      details.findings.forEach((item) => findingsById.set(item.id, item));
    }
  }
  return {
    evidence: [...evidenceById.values()],
    findings: [...findingsById.values()],
  };
}

export function lastAssistantTextFromEvents(events) {
  let text = "";
  for (const event of events) {
    if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
      text += event.assistantMessageEvent.delta;
    }
  }
  return text.trim();
}

function contentToText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      if (!block || typeof block !== "object") return "";
      if (block.type === "text" && typeof block.text === "string") return block.text;
      return "";
    })
    .join("");
}

export function lastAssistantTextFromMessages(messages) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message?.role === "assistant") {
      const text = contentToText(message.content).trim();
      if (text) return text;
    }
  }
  return "";
}

function parseDiagnosisJson(text) {
  const trimmed = text.trim();
  const unfenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1]?.trim() ?? trimmed;
  try {
    return JSON.parse(unfenced);
  } catch {
    const start = unfenced.indexOf("{");
    const end = unfenced.lastIndexOf("}");
    if (start !== -1 && end > start) {
      try {
        return JSON.parse(unfenced.slice(start, end + 1));
      } catch {
        // Fall through to raw text below.
      }
    }
    return { raw_text: text };
  }
}

function lastAssistantErrorFromMessages(messages) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message?.role === "assistant") {
      if (message.stopReason === "error" || message.errorMessage) {
        return message.errorMessage || "LLM provider returned an error without details.";
      }
      return undefined;
    }
  }
  return undefined;
}

function fallbackDiagnosis(prompt, evidence, findings, llmError) {
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

function renderFallbackHuman(prompt, diagnosis, evidence, findings) {
  const evidenceLines = findings.length > 0
    ? findings.map((finding) => `  - ${finding.summary} [${(finding.evidence_refs ?? []).join(", ")}]`)
    : evidence.map((item) => `  - ${item.id}: ${item.status}`);

  return `Descartes triage: ${prompt}

Most likely cause
  ${diagnosis.summary}

Confidence
  ${diagnosis.confidence}

Evidence
${evidenceLines.join("\n") || "  - No evidence was collected."}

Safe next checks
${diagnosis.next_checks.map((check, index) => `  ${index + 1}. ${check}`).join("\n")}

Avoid for now
${diagnosis.avoid.map((item) => `  - ${item}`).join("\n")}

No actions were taken.`;
}

export async function runTriage(paths, args) {
  const options = parseTriageArgs(args);
  const events = [];
  const toolResults = [];
  const precollected = await collectAllEvidence();
  const { session } = await createPrivateTriageSession(paths, {
    modelPattern: options.modelPattern,
    thinkingLevel: options.thinkingLevel,
    enableTools: false,
  });

  const unsubscribe = session.subscribe((event) => {
    events.push(event);
    if (event.type === "tool_execution_end") {
      toolResults.push({ toolName: event.toolName, toolCallId: event.toolCallId, result: event.result, isError: event.isError });
    }
  });

  let finalMessages = [];
  try {
    await session.prompt(options.json ? jsonTriagePrompt(options.prompt, precollected) : humanTriagePrompt(options.prompt, precollected));
    finalMessages = [...session.messages];
  } finally {
    unsubscribe();
    session.dispose();
  }

  const assistantText = lastAssistantTextFromMessages(finalMessages) || lastAssistantTextFromEvents(events);
  const llmError = lastAssistantErrorFromMessages(finalMessages);
  const { evidence, findings } = flattenEvidence(toolResults, precollected);
  const fallback = assistantText ? undefined : fallbackDiagnosis(options.prompt, evidence, findings, llmError);

  if (!options.json) {
    process.stdout.write(assistantText || renderFallbackHuman(options.prompt, fallback, evidence, findings));
    if (!(assistantText || "").endsWith("\n")) process.stdout.write("\n");
    return;
  }

  const diagnosis = fallback ?? parseDiagnosisJson(assistantText);

  process.stdout.write(JSON.stringify({
    prompt: options.prompt,
    diagnosis,
    evidence,
    findings,
    tool_traces: [
      ...precollected.evidence.map((item) => ({
        tool_name: item.trace?.tool,
        tool_call_id: "precollected",
        is_error: item.status === "unable",
        trace: item.trace,
      })),
      ...toolResults.map((item) => ({
        tool_name: item.toolName,
        tool_call_id: item.toolCallId,
        is_error: item.isError,
        trace: item.result?.details?.trace,
      })),
    ],
    actions_taken: [],
  }, null, 2));
  process.stdout.write("\n");
}
