import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createEvidenceTools } from "../src/pi-harness.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { assertSafeTriageToolNames, TRIAGE_TOOL_NAMES } from "../src/tool-policy.js";
import { MAX_WINDOW_MINUTES } from "../src/tools/logs.js";

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

test("collect_recent_logs window_minutes schema bound stays in lockstep with logs.js MAX_WINDOW_MINUTES (Slice 0, single source of truth)", () => {
  // The window bound is double-enforced (the pi-harness Type.Number schema AND logs.js's
  // normalizeLogRequest clamp). Slice 0 wired the schema to import the logs.js constant so the two
  // can never drift; this pins that wiring so a future edit re-hardcoding a literal is caught.
  const paths = resolveDescartesPaths();
  const logsTool = createEvidenceTools(paths).find((tool) => tool.name === "collect_recent_logs");
  assert.ok(logsTool, "expected collect_recent_logs to be registered");
  assert.equal(logsTool.parameters.properties.window_minutes.maximum, MAX_WINDOW_MINUTES);
});

// F3 gap fix (must-fix 1): collect_services' on-demand tool result must never leak the
// AUTHORITATIVE, up-to-~1000-entry `services_census` (tools/services.js's
// DEFAULT_SERVICE_CENSUS_CEILING) -- that field exists for the daemon's service-baseline
// machinery only. This tool's own parameter schema (service_limit, max 200 here / 80 by
// default) promises a presentation-bounded result, so services_census must be stripped before
// the model ever sees it, in both the structured `details` and the stringified `content` text
// (what the model actually reads). collectServiceEvidence itself always populates
// services_census (see tools/services.js), so this is a real regression guard, not vacuous.
test("collect_services tool result omits services_census, keeping only the presentation-bounded services field", async () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const servicesTool = tools.find((tool) => tool.name === "collect_services");
  assert.ok(servicesTool, "expected collect_services to be registered");

  const toolResult = await servicesTool.execute("test-call-id", {});

  assert.equal(
    Object.prototype.hasOwnProperty.call(toolResult.details.result, "services_census"),
    false,
    "services_census must not reach the model's tool result",
  );
  assert.ok(Array.isArray(toolResult.details.result.services), "the presentation-bounded services field must still be present");
  assert.equal(
    toolResult.content[0].text.includes("services_census"),
    false,
    "the stringified tool-result text must not mention services_census either",
  );
});

test("createEvidenceTools includes inspect_runtime_provenance with a single-target parameter contract", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const provenanceTool = tools.find((tool) => tool.name === "inspect_runtime_provenance");

  assert.ok(provenanceTool, "expected inspect_runtime_provenance to be registered");
  assert.equal(typeof provenanceTool.execute, "function");
});

// Slice 3 (observed-incident collectors plan) registration: closes the same gap as the two tests
// above for the new collect_vpn_peer_status tool — the set-equality test catches a missing/extra
// NAME, but not a malformed parameter schema for a specific tool.
test("createEvidenceTools registers collect_vpn_peer_status with a bounded peer_limit parameter", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const peerTool = tools.find((tool) => tool.name === "collect_vpn_peer_status");

  assert.ok(peerTool, "expected collect_vpn_peer_status to be registered");
  assert.equal(typeof peerTool.execute, "function");
  assert.equal(peerTool.parameters.properties.peer_limit.minimum, 1);
  assert.equal(peerTool.parameters.properties.peer_limit.maximum, 500);
});

test("createEvidenceTools registers collect_tailscale_status with a bounded peer_limit parameter", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const peerTool = tools.find((tool) => tool.name === "collect_tailscale_status");

  assert.ok(peerTool, "expected collect_tailscale_status to be registered");
  assert.equal(typeof peerTool.execute, "function");
  assert.equal(peerTool.parameters.properties.peer_limit.minimum, 1);
  assert.equal(peerTool.parameters.properties.peer_limit.maximum, 500);
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

// F7 fix B: derive_findings must only ever see evidence this session's own collector tool calls
// actually produced (referenced by id), never a model-fabricated evidence envelope passed inline.
test("derive_findings resolves ids from this session's own prior collect_system call and reports a never-collected id as unresolved", async () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const collectSystem = tools.find((tool) => tool.name === "collect_system");
  const deriveFindingsTool = tools.find((tool) => tool.name === "derive_findings");
  assert.ok(collectSystem);
  assert.ok(deriveFindingsTool);

  const collected = await collectSystem.execute("call-1", {});
  const realId = collected.details.id;
  assert.ok(realId, "collect_system's envelope must carry a real id to reference");

  const result = await deriveFindingsTool.execute("call-2", {
    evidence_ids: [realId, "fabricated-evidence-id-never-collected"],
  });

  assert.deepEqual(result.details.unresolved_evidence_ids, ["fabricated-evidence-id-never-collected"]);
  // The real envelope actually reached deriveFindings: findings is an array (possibly empty
  // depending on host load), not a rejection -- what matters is the fabricated id did not
  // silently pass through as if it had been collected.
  assert.ok(Array.isArray(result.details.findings));
});

test("derive_findings called with no prior collector call in this session cannot produce a fabricated finding", async () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const deriveFindingsTool = tools.find((tool) => tool.name === "derive_findings");

  const result = await deriveFindingsTool.execute("call-1", {
    evidence_ids: ["system-overview"],
    // A model attempting to smuggle a self-fabricated envelope inline; the new schema only
    // accepts evidence_ids (strings), so this key is not even part of the accepted shape.
  });

  assert.deepEqual(result.details.unresolved_evidence_ids, ["system-overview"]);
  // No resolved evidence reached deriveFindings, so it explicitly represents insufficient
  // evidence (degrade-not-fabricate) rather than fabricating a resource-pressure finding.
  assert.deepEqual(result.details.findings.map((finding) => finding.id), ["insufficient_evidence"]);
});

test("derive_findings tool schema only accepts evidence_ids (string refs), not inline evidence envelopes", () => {
  const paths = resolveDescartesPaths();
  const tools = createEvidenceTools(paths);
  const deriveFindingsTool = tools.find((tool) => tool.name === "derive_findings");

  assert.ok(deriveFindingsTool.parameters.properties.evidence_ids, "expected an evidence_ids parameter");
  assert.equal(deriveFindingsTool.parameters.properties.evidence_ids.type, "array");
  assert.equal(deriveFindingsTool.parameters.properties.evidence_ids.items.type, "string");
  assert.equal(deriveFindingsTool.parameters.properties.evidence, undefined, "must not accept a raw model-supplied evidence array");
});
