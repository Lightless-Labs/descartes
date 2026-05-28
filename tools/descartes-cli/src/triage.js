import { createPrivateTriageSession, humanTriagePrompt, jsonTriagePrompt } from "./pi-harness.js";
import { buildHistorySummary, parseDurationMs, readDaemonStatus } from "./history-store.js";
import { collectAllEvidence } from "./tools/collect.js";
import { fallbackDiagnosis } from "./triage-fallback.js";
import { assistantErrorFromMessages, assistantStopReasonFromMessages, createToolCallRecorder, modelDiagnostic } from "./triage-diagnostics.js";
import {
  createEvidenceGuardState,
  evidenceGuardDiagnostics,
  evidenceRequiredRetryPrompt,
  markEvidenceGuardFallback,
  markEvidenceGuardRetry,
  markEvidenceGuardSatisfied,
  shouldFallbackForNoEvidence,
  shouldRetryForEvidence,
} from "./triage-guard.js";

export function parseTriageArgs(args) {
  const options = { json: false, investigate: true, historyMode: "auto", historyWindow: "24h" };
  let forcedHistorySeen = false;
  let disabledHistorySeen = false;
  const promptParts = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--json") options.json = true;
    else if (arg === "--no-investigate") options.investigate = false;
    else if (arg === "--use-history") {
      forcedHistorySeen = true;
      options.historyMode = "forced";
    } else if (arg === "--no-history") {
      disabledHistorySeen = true;
      options.historyMode = "disabled";
    } else if (arg === "--history-window") {
      const value = args[++i];
      if (!value) throw new Error("--history-window requires a value");
      options.historyWindow = value;
    } else if (arg === "--model") options.modelPattern = args[++i];
    else if (arg === "--thinking") options.thinkingLevel = args[++i];
    else if (arg.startsWith("-")) throw new Error(`Unknown triage argument: ${arg}`);
    else promptParts.push(arg);
  }
  if (forcedHistorySeen && disabledHistorySeen) throw new Error("Use either --use-history or --no-history, not both");
  const prompt = promptParts.join(" ").trim();
  if (!prompt) throw new Error("Usage: descartes triage <PROMPT> [--json] [--model <MODEL>] [--thinking <LEVEL>] [--no-investigate] [--use-history|--no-history] [--history-window <DURATION>]");
  parseDurationMs(options.historyWindow);
  return { ...options, useHistory: options.historyMode === "forced", prompt };
}

const DEFAULT_AUTO_HISTORY_MAX_AGE_MS = 5 * 60 * 1000;

function historyNewestMetricMs(summary) {
  const timestamps = (summary?.metrics ?? [])
    .map((metric) => new Date(metric.last_ts).getTime())
    .filter(Number.isFinite);
  if (timestamps.length === 0) return undefined;
  return Math.max(...timestamps);
}

export function evaluateHistorySelection({ mode = "auto", summary, daemonStatus, now = new Date() } = {}) {
  if (mode === "disabled") return { used: false, mode, skip_reason: "disabled" };
  const newestMetricMs = historyNewestMetricMs(summary);
  const nowMs = new Date(now).getTime();
  const intervalMs = Number(daemonStatus?.profile?.interval_ms);
  const maxAgeMs = Math.max(DEFAULT_AUTO_HISTORY_MAX_AGE_MS, Number.isFinite(intervalMs) ? intervalMs * 3 : 0);
  const freshness_ms = Number.isFinite(newestMetricMs) && Number.isFinite(nowMs) ? Math.max(0, nowMs - newestMetricMs) : undefined;

  if (mode === "forced") return { used: true, mode, freshness_ms, max_age_ms: maxAgeMs };
  if (!summary || summary.point_count === 0) return { used: false, mode, skip_reason: "no_points", freshness_ms, max_age_ms: maxAgeMs };
  if (!daemonStatus) return { used: false, mode, skip_reason: "no_daemon_status", freshness_ms, max_age_ms: maxAgeMs };
  if (daemonStatus.state !== "ok") return { used: false, mode, skip_reason: "daemon_status_not_ok", freshness_ms, max_age_ms: maxAgeMs };
  if (freshness_ms === undefined) return { used: false, mode, skip_reason: "no_recent_sample", max_age_ms: maxAgeMs };
  if (freshness_ms > maxAgeMs) return { used: false, mode, skip_reason: "stale", freshness_ms, max_age_ms: maxAgeMs };
  return { used: true, mode, freshness_ms, max_age_ms: maxAgeMs };
}

function sanitizeHistoryDaemonStatus(status) {
  if (!status) return undefined;
  return {
    state: status.state,
    mode: status.mode,
    ts: status.ts,
    interval_ms: status.profile?.interval_ms,
    points_written: status.points_written,
  };
}

export async function selectTriageHistory(paths, options = {}) {
  const mode = options.historyMode ?? "auto";
  const windowMs = parseDurationMs(options.historyWindow ?? "24h");
  if (mode === "disabled") {
    return { mode, used: false, skip_reason: "disabled", window_ms: windowMs };
  }

  const [summary, daemonStatus] = await Promise.all([
    buildHistorySummary(paths, { windowMs }),
    readDaemonStatus(paths),
  ]);
  const evaluation = evaluateHistorySelection({ mode, summary, daemonStatus, now: options.now });
  return {
    ...evaluation,
    window_ms: windowMs,
    summary,
    daemon_status: sanitizeHistoryDaemonStatus(daemonStatus),
  };
}

function historyEnvelope(summary) {
  if (!summary) return undefined;
  return {
    id: "history-summary",
    status: "ok",
    layer: "L0",
    source: "history_store",
    result: summary,
    confidence: 1,
    review_hint: summary.point_count > 0 ? "none" : "insufficient_evidence",
    trace: {
      tool: "summarize_history",
      target: `window_ms=${summary.window_ms}`,
      latency_ms: 0,
      ts: new Date().toISOString(),
    },
  };
}

function mergePrecollected(...bundles) {
  const evidence = [];
  const findings = [];
  for (const bundle of bundles) {
    if (!bundle) continue;
    evidence.push(...(bundle.evidence ?? []));
    findings.push(...(bundle.findings ?? []));
  }
  return evidence.length || findings.length ? { evidence, findings, actions_taken: [] } : undefined;
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
  const toolCallRecorder = createToolCallRecorder();
  const evidenceGuard = createEvidenceGuardState({ investigationEnabled: options.investigate });
  const historySelection = await selectTriageHistory(paths, options);
  const historySummary = historySelection.summary;
  const historyBundle = historySelection.used && historySummary ? { evidence: [historyEnvelope(historySummary)], findings: [], actions_taken: [] } : undefined;
  let precollected = mergePrecollected(options.investigate ? undefined : await collectAllEvidence(), historyBundle);
  const { session, selectedModel, selectedThinkingLevel, activeToolNames } = await createPrivateTriageSession(paths, {
    modelPattern: options.modelPattern,
    thinkingLevel: options.thinkingLevel,
    enableTools: options.investigate,
  });

  const unsubscribe = session.subscribe((event) => {
    events.push(event);
    toolCallRecorder.record(event);
    if (event.type === "tool_execution_end") {
      toolResults.push({ toolName: event.toolName, toolCallId: event.toolCallId, result: event.result, isError: event.isError });
    }
  });

  let finalMessages = [];
  let assistantTextForOutput;
  try {
    const promptOptions = { toolsEnabled: options.investigate };
    await session.prompt(options.json ? jsonTriagePrompt(options.prompt, precollected, promptOptions) : humanTriagePrompt(options.prompt, precollected, promptOptions));
    finalMessages = [...session.messages];

    assistantTextForOutput = lastAssistantTextFromMessages(finalMessages) || lastAssistantTextFromEvents(events);
    let collected = flattenEvidence(toolResults, precollected);
    if (shouldRetryForEvidence({ guard: evidenceGuard, assistantText: assistantTextForOutput, evidence: collected.evidence })) {
      markEvidenceGuardRetry(evidenceGuard);
      const messageStart = finalMessages.length;
      const eventStart = events.length;
      await session.prompt(evidenceRequiredRetryPrompt(options.prompt, { json: options.json }));
      finalMessages = [...session.messages];
      assistantTextForOutput = lastAssistantTextFromMessages(finalMessages.slice(messageStart)) || lastAssistantTextFromEvents(events.slice(eventStart));
      collected = flattenEvidence(toolResults, precollected);
    }

    markEvidenceGuardSatisfied(evidenceGuard, collected.evidence);
    if (shouldFallbackForNoEvidence({ guard: evidenceGuard, assistantText: assistantTextForOutput, evidence: collected.evidence })) {
      const fallbackReason = assistantTextForOutput?.trim() ? "no_evidence_after_retry" : "no_evidence_no_assistant_text";
      markEvidenceGuardFallback(evidenceGuard, fallbackReason);
      precollected = mergePrecollected(await collectAllEvidence(), historyBundle);
    }
  } finally {
    unsubscribe();
    session.dispose();
  }

  const assistantText = assistantTextForOutput ?? (lastAssistantTextFromMessages(finalMessages) || lastAssistantTextFromEvents(events));
  const llmError = assistantErrorFromMessages(finalMessages);
  const assistantStopReason = assistantStopReasonFromMessages(finalMessages);
  const { evidence, findings } = flattenEvidence(toolResults, precollected);
  const fallback = assistantText && evidenceGuard.outcome !== "fallback_precollected" ? undefined : fallbackDiagnosis(options.prompt, evidence, findings, evidenceGuard.fallback_reason ?? llmError);

  if (!options.json) {
    const outputText = fallback ? renderFallbackHuman(options.prompt, fallback, evidence, findings) : assistantText;
    process.stdout.write(outputText);
    if (!outputText.endsWith("\n")) process.stdout.write("\n");
    return;
  }

  const diagnosis = fallback ?? parseDiagnosisJson(assistantText);

  process.stdout.write(JSON.stringify({
    prompt: options.prompt,
    diagnosis,
    diagnostics: {
      selected_model: modelDiagnostic(selectedModel),
      thinking_level: selectedThinkingLevel,
      investigation_enabled: options.investigate,
      active_tools: activeToolNames,
      tool_calls: toolCallRecorder.calls,
      assistant_stop_reason: assistantStopReason,
      llm_error: llmError,
      fallback_used: Boolean(fallback),
      history_mode: historySelection.mode,
      history_used: historySelection.used,
      history_skip_reason: historySelection.skip_reason,
      history_window: options.historyWindow,
      history_freshness_ms: historySelection.freshness_ms,
      history_max_age_ms: historySelection.max_age_ms,
      history_daemon_status: historySelection.daemon_status,
      history_summary: historySummary ? {
        point_count: historySummary.point_count,
        matched_point_count: historySummary.matched_point_count,
        point_limit: historySummary.point_limit,
        truncated: historySummary.truncated,
        metric_names: historySummary.metrics.map((metric) => metric.metric_name),
        since: historySummary.since,
        until: historySummary.until,
        corrupt_count: historySummary.corrupt_count,
      } : undefined,
      evidence_guard: evidenceGuardDiagnostics(evidenceGuard),
    },
    evidence,
    findings,
    tool_traces: [
      ...(precollected?.evidence ?? []).map((item) => ({
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
