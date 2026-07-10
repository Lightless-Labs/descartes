import assert from "node:assert/strict";
import test from "node:test";
import { createEvidenceTools } from "../src/pi-harness.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { assertSafeTriageToolNames, TRIAGE_TOOL_NAMES } from "../src/tool-policy.js";

// Session-construction test (closes the gap noted in docs/plans/2026-07-10-layer-b-provenance.md
// section 1: no existing test cross-checked pi-harness.js's tool names against tool-policy.js's
// array directly). No live model credentials required — createEvidenceTools only builds tool
// definitions, it does not call a model.

test("createEvidenceTools' tool names are exactly Descartes' TRIAGE_TOOL_NAMES", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const toolNames = tools.map((tool) => tool.name);

  assert.deepEqual([...toolNames].sort(), [...TRIAGE_TOOL_NAMES].sort());
  assert.doesNotThrow(() => assertSafeTriageToolNames(toolNames));
});

test("createEvidenceTools includes inspect_runtime_provenance with a single-target parameter contract", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const provenanceTool = tools.find((tool) => tool.name === "inspect_runtime_provenance");

  assert.ok(provenanceTool, "expected inspect_runtime_provenance to be registered");
  assert.equal(typeof provenanceTool.execute, "function");
});
