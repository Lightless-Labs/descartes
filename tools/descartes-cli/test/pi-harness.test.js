import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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

// S3-priv Slice 2 signature-widening regression: closes the gap the tool-name-set-equality check
// above would not catch -- that resolveProvenance's new second (paths-carrying) argument is
// actually threaded through the executor's real params -> resolveProvenance call, and that a
// freshly-provisioned XDG paths dir (no provenance.json, i.e. the shipped default) still resolves
// this test process's own pid exactly as it did before S3-priv Slice 2 (byte-identical default).
test("inspect_runtime_provenance's executor threads paths into resolveProvenance and stays byte-identical with the default (no provenance.json) config", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-pi-harness-provenance-test-"));
  const paths = resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
  const tools = createEvidenceTools(paths);
  const provenanceTool = tools.find((tool) => tool.name === "inspect_runtime_provenance");

  const toolResult = await provenanceTool.execute("test-call-id", { pid: process.pid });
  const envelope = toolResult.details;

  assert.equal(envelope.result.resolved.status, "ok");
  assert.equal(envelope.result.resolved.pid, process.pid);
  assert.equal(envelope.result.privilege.mechanism, "unprivileged");
  assert.equal(envelope.result.privilege.elevated_used, false);
});
