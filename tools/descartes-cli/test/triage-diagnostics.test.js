import assert from "node:assert/strict";
import test from "node:test";
import { assistantErrorFromMessages, assistantStopReasonFromMessages, createToolCallRecorder, modelDiagnostic } from "../src/triage-diagnostics.js";

test("modelDiagnostic exposes provider/model metadata without auth state", () => {
  assert.deepEqual(modelDiagnostic({ provider: "anthropic", id: "claude-sonnet-4-6", name: "Claude Sonnet 4.6", reasoning: true }), {
    provider: "anthropic",
    id: "claude-sonnet-4-6",
    name: "Claude Sonnet 4.6",
    reasoning: true,
  });
});

test("assistant diagnostics report stop reason and provider errors", () => {
  const messages = [
    { role: "assistant", content: [{ type: "text", text: "partial" }], stopReason: "error", errorMessage: "provider rejected model" },
  ];

  assert.equal(assistantStopReasonFromMessages(messages), "error");
  assert.equal(assistantErrorFromMessages(messages), "provider rejected model");
});

test("tool call recorder captures start, result, and errors", () => {
  const recorder = createToolCallRecorder();
  recorder.record({ type: "tool_execution_start", toolName: "collect_system", toolCallId: "call-1", args: {} });
  recorder.record({ type: "tool_execution_end", toolName: "collect_system", toolCallId: "call-1", isError: false, result: { details: { id: "system-overview" } } });
  recorder.record({ type: "tool_execution_end", toolName: "collect_disks", toolCallId: "call-2", isError: true, result: { content: [{ type: "text", text: "disk probe failed" }] } });

  assert.deepEqual(recorder.calls, [
    { tool_name: "collect_system", tool_call_id: "call-1", args: {}, status: "ok", is_error: false, result: { id: "system-overview" }, error: undefined },
    { tool_name: "collect_disks", tool_call_id: "call-2", status: "error", is_error: true, result: undefined, error: "disk probe failed" },
  ]);
});
