import assert from "node:assert/strict";
import test from "node:test";
import { selectTriageModel } from "../src/model-selection.js";

const model = (provider, id, name = id, reasoning = true) => ({ provider, id, name, reasoning });

test("selectTriageModel prefers highest ChatGPT Codex GPT model with high reasoning", () => {
  const selected = selectTriageModel([
    model("openai-codex", "gpt-5.1", "GPT-5.1"),
    model("openai-codex", "gpt-5.4", "GPT-5.4"),
    model("openai-codex", "gpt-5.5", "GPT-5.5"),
  ]);

  assert.equal(selected.model.provider, "openai-codex");
  assert.equal(selected.model.id, "gpt-5.5");
  assert.equal(selected.thinkingLevel, "high");
});

test("selectTriageModel prefers newer major/minor versions over variant names", () => {
  const selected = selectTriageModel([
    model("openai-codex", "gpt-5.9-codex-max", "GPT-5.9 Codex Max"),
    model("openai-codex", "gpt-6.0", "GPT-6.0"),
    model("openai-codex", "gpt-5.10", "GPT-5.10"),
  ]);

  assert.equal(selected.model.id, "gpt-6.0");
});

test("selectTriageModel prefers highest Anthropic Sonnet over Haiku and Opus", () => {
  const selected = selectTriageModel([
    model("anthropic", "claude-3-5-haiku-20241022", "Claude Haiku 3.5", false),
    model("anthropic", "claude-opus-4-7", "Claude Opus 4.7", true),
    model("anthropic", "claude-sonnet-4-5", "Claude Sonnet 4.5", true),
    model("anthropic", "claude-sonnet-4-6", "Claude Sonnet 4.6", true),
  ]);

  assert.equal(selected.model.provider, "anthropic");
  assert.equal(selected.model.id, "claude-sonnet-4-6");
  assert.equal(selected.thinkingLevel, "high");
});

test("selectTriageModel handles old Anthropic Sonnet id format", () => {
  const selected = selectTriageModel([
    model("anthropic", "claude-3-5-sonnet-20241022", "Claude Sonnet 3.5 v2", false),
    model("anthropic", "claude-3-7-sonnet-20250219", "Claude Sonnet 3.7", true),
  ]);

  assert.equal(selected.model.id, "claude-3-7-sonnet-20250219");
});

test("selectTriageModel honors explicit model pattern", () => {
  const selected = selectTriageModel([
    model("openai-codex", "gpt-5.5", "GPT-5.5"),
    model("github-copilot", "gpt-5.5", "GPT-5.5"),
  ], { modelPattern: "github-copilot/gpt-5.5" });

  assert.equal(selected.model.provider, "github-copilot");
  assert.equal(selected.model.id, "gpt-5.5");
});

test("selectTriageModel throws on unavailable explicit model", () => {
  assert.throws(
    () => selectTriageModel([model("openai-codex", "gpt-5.5", "GPT-5.5")], { modelPattern: "openai-codex/gpt-9" }),
    /requested model/
  );
});
