import assert from "node:assert/strict";
import test from "node:test";
import { fallbackDiagnosis } from "../src/triage-fallback.js";

test("fallback diagnosis is marked as degraded mode and includes llm_error", () => {
  const diagnosis = fallbackDiagnosis(
    "my machine is slow",
    [{ id: "system-overview" }, { id: "top-processes" }],
    [{ id: "insufficient_evidence", evidence_refs: ["system-overview"] }],
    "provider rejected model"
  );

  assert.equal(diagnosis.fallback, true);
  assert.equal(diagnosis.llm_error, "provider rejected model");
  assert.match(diagnosis.summary, /LLM request failed/);
  assert.deepEqual(diagnosis.evidence_refs, ["system-overview"]);
});

test("fallback diagnosis preserves substantive deterministic evidence refs", () => {
  const diagnosis = fallbackDiagnosis(
    "my machine is slow",
    [{ id: "system-overview" }, { id: "top-processes" }],
    [{ id: "memory_pressure", summary: "Memory pressure is high", evidence_refs: ["system-overview"] }]
  );

  assert.equal(diagnosis.fallback, true);
  assert.equal(diagnosis.confidence, "medium");
  assert.equal(diagnosis.summary, "Memory pressure is high");
  assert.deepEqual(diagnosis.evidence_refs, ["system-overview"]);
});

test("fallback diagnosis does not claim evidence was collected when evidence is empty", () => {
  const diagnosis = fallbackDiagnosis("my machine is slow", [], []);

  assert.equal(diagnosis.fallback, true);
  assert.match(diagnosis.summary, /could not collect evidence/);
  assert.match(diagnosis.explanation, /no evidence was available/);
  assert.deepEqual(diagnosis.evidence_refs, []);
});
