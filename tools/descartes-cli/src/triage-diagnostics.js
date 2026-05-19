export function modelDiagnostic(model) {
  if (!model) return undefined;
  return {
    provider: model.provider,
    id: model.id,
    name: model.name,
    reasoning: Boolean(model.reasoning),
  };
}

export function assistantStopReasonFromMessages(messages) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message?.role === "assistant") return message.stopReason;
  }
  return undefined;
}

export function assistantErrorFromMessages(messages) {
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

export function createToolCallRecorder() {
  const calls = [];
  const indexById = new Map();

  return {
    calls,
    record(event) {
      if (event.type === "tool_execution_start") {
        const call = {
          tool_name: event.toolName,
          tool_call_id: event.toolCallId,
          args: event.args,
          status: "started",
        };
        indexById.set(event.toolCallId, calls.length);
        calls.push(call);
        return;
      }

      if (event.type === "tool_execution_end") {
        const existingIndex = indexById.get(event.toolCallId);
        const call = existingIndex === undefined
          ? { tool_name: event.toolName, tool_call_id: event.toolCallId, status: "completed" }
          : calls[existingIndex];
        call.status = event.isError ? "error" : "ok";
        call.is_error = Boolean(event.isError);
        call.result = event.result?.details;
        call.error = event.isError ? extractToolError(event.result) : undefined;
        if (existingIndex === undefined) calls.push(call);
      }
    },
  };
}

function extractToolError(result) {
  if (typeof result?.details?.error === "string") return result.details.error;
  const firstText = result?.content?.find?.((item) => item?.type === "text" && typeof item.text === "string")?.text;
  return firstText;
}
