import { createPrivateTriageSession, humanTriagePrompt, jsonTriagePrompt } from "./pi-harness.js";

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

function flattenEvidence(toolResults) {
  const evidenceById = new Map();
  const findingsById = new Map();
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

function lastAssistantTextFromEvents(events) {
  let text = "";
  for (const event of events) {
    if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
      text += event.assistantMessageEvent.delta;
    }
  }
  return text;
}

export async function runTriage(paths, args) {
  const options = parseTriageArgs(args);
  const events = [];
  const toolResults = [];
  const { session } = await createPrivateTriageSession(paths, {
    thinkingLevel: options.thinkingLevel,
  });

  const unsubscribe = session.subscribe((event) => {
    events.push(event);
    if (event.type === "message_update" && event.assistantMessageEvent?.type === "text_delta" && !options.json) {
      process.stdout.write(event.assistantMessageEvent.delta);
    }
    if (event.type === "tool_execution_end") {
      toolResults.push({ toolName: event.toolName, toolCallId: event.toolCallId, result: event.result, isError: event.isError });
    }
  });

  try {
    await session.prompt(options.json ? jsonTriagePrompt(options.prompt) : humanTriagePrompt(options.prompt));
  } finally {
    unsubscribe();
    session.dispose();
  }

  const assistantText = lastAssistantTextFromEvents(events).trim();
  if (!options.json) {
    if (!assistantText.endsWith("\n")) process.stdout.write("\n");
    return;
  }

  const { evidence, findings } = flattenEvidence(toolResults);
  let diagnosis;
  try {
    diagnosis = JSON.parse(assistantText);
  } catch {
    diagnosis = { raw_text: assistantText };
  }

  process.stdout.write(JSON.stringify({
    prompt: options.prompt,
    diagnosis,
    evidence,
    findings,
    tool_traces: toolResults.map((item) => ({
      tool_name: item.toolName,
      tool_call_id: item.toolCallId,
      is_error: item.isError,
      trace: item.result?.details?.trace,
    })),
    actions_taken: [],
  }, null, 2));
  process.stdout.write("\n");
}
