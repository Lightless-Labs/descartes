import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createEvidenceTools } from "../src/pi-harness.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { enforceFactRetention } from "../src/fact-store.js";
import {
  DEFAULT_REASON,
  FREEZE_SNAPSHOT_TOOL_NAMES,
  MAX_REASON_LENGTH,
  SCHEMA_VERSION,
  buildEvidenceBundleFilename,
  computeBundleDigest,
  isFreezeSnapshotToolName,
  listEvidenceBundleFilenames,
  readEvidenceBundle,
  readEvidenceFreezeAudit,
  resolveEvidenceFreezePaths,
  runEvidenceFreeze,
  runIncident,
  sanitizeFreezeReason,
  verifyEvidenceBundleIntegrity,
} from "../src/evidence-freeze.js";

const SOURCE_PATH = fileURLToPath(new URL("../src/evidence-freeze.js", import.meta.url));
const FIXED_NOW = "2026-07-13T00:00:00.000Z";
const FILENAME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[0-9a-f]{16}-[0-9a-f]{16}\.json$/;

async function makeTempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-evidence-freeze-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function fakeEnvelope(status, overrides = {}) {
  return {
    id: "fake",
    status,
    layer: "L0",
    source: "fake",
    result: {},
    confidence: status === "ok" ? 1 : 0,
    review_hint: status === "ok" ? "none" : "missing_permission",
    trace: { tool: "fake", target: "fake", latency_ms: 0, ts: new Date().toISOString() },
    ...overrides,
  };
}

function okTool(name, invoked) {
  return {
    name,
    execute: async () => {
      invoked?.push(name);
      return { details: fakeEnvelope("ok", { id: name }) };
    },
  };
}

function degradedTool(name, invoked) {
  return {
    name,
    execute: async () => {
      invoked?.push(name);
      return { details: fakeEnvelope("unable", { id: name }) };
    },
  };
}

function throwingTool(name, invoked) {
  return {
    name,
    execute: async () => {
      invoked?.push(name);
      throw new Error(`${name} boom`);
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Load-bearing invariant: zero new execFile/spawn surface.
// ---------------------------------------------------------------------------------------------

function stripLineAndBlockComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

// Mirrors escalation-lint.test.js's own deliberately-broad callee net (any identifier
// substring-containing "exec"/"spawn", case-insensitive — so a wrapper like
// "runFixedExecFile"/"execFileAsync" is still caught even though "exec" isn't at the identifier's
// start). The ONE necessary exclusion is the literal identifier "execute" — this file legitimately
// calls the Tool interface's own `tool.execute(...)` method (pi-coding-agent's defineTool
// contract), which is not a child_process API and contains "exec" purely as an English-word
// coincidence. Nothing else is excluded.
function findExecLikeCallSites(source) {
  const stripped = stripLineAndBlockComments(source);
  const callRe = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
  const hits = [];
  let m;
  while ((m = callRe.exec(stripped))) {
    const name = m[1];
    if (name === "execute") continue;
    if (/exec|spawn/i.test(name)) hits.push(name);
  }
  return hits;
}

test("evidence-freeze.js contains zero execFile/spawn-shaped call sites of its own (static source scan)", () => {
  const source = readFileSync(SOURCE_PATH, "utf8");
  const hits = findExecLikeCallSites(source);
  assert.deepEqual(hits, [], `expected no exec/spawn-shaped call sites in evidence-freeze.js, found: ${hits.join(", ")}`);
  assert.doesNotMatch(source, /from\s+["']node:child_process["']/, "evidence-freeze.js must never import node:child_process directly");
});

test("evidence-freeze.js is not gated by learned.json (static check — on-demand action, not an inference artifact, by design)", () => {
  // Checked against comment-stripped source, and specifically against the GATE MECHANISM
  // (constraint-store.js's learned.json loader/writer), not the bare string "learned.json" —
  // the CLI help text legitimately *mentions* "learned.json" in prose (to tell the operator this
  // action is exempt from it), which must not itself trip this check; only an actual import of
  // the gate mechanism should.
  const code = stripLineAndBlockComments(readFileSync(SOURCE_PATH, "utf8"));
  assert.doesNotMatch(code, /from\s+["']\.\/constraint-store\.js["']/);
  assert.doesNotMatch(code, /loadLearnedConfig\(/);
  assert.doesNotMatch(code, /writeLearnedConfig\(/);
  assert.doesNotMatch(code, /normalizeLearnedConfig\(/);
});

test("evidence-freeze.js never reaches an LLM session/prompt (static check — bundle is a pure operator-facing artifact)", () => {
  // Same comment-stripping rationale as the learned.json check above.
  const code = stripLineAndBlockComments(readFileSync(SOURCE_PATH, "utf8"));
  for (const forbidden of [
    "createSession",
    "session.prompt",
    "compactAlert",
    "createPrivateAlertSession",
    "createPrivateTriageSession",
    "createAgentSession",
    "alert-intelligence.js",
  ]) {
    assert.ok(!code.includes(forbidden), `unexpected reference to ${forbidden} in evidence-freeze.js's real code`);
  }
});

test("runEvidenceFreeze only ever invokes registry entries matching the freeze snapshot tool-name rule", async () => {
  const paths = await makeTempPaths();
  const invoked = [];
  const tools = [
    okTool("collect_alpha", invoked),
    okTool("collect_beta", invoked),
    okTool("collect_triage_evidence", invoked), // deliberately excluded (redundant aggregate)
    okTool("derive_findings", invoked), // deliberately excluded (not a collector)
    okTool("inspect_process", invoked), // deliberately excluded (needs a pid target)
    okTool("not_a_collector", invoked), // not in the registered set's naming shape at all
  ];

  const result = await runEvidenceFreeze(paths, { tools, now: FIXED_NOW });

  assert.deepEqual([...invoked].sort(), ["collect_alpha", "collect_beta"]);
  assert.equal(result.bundle.source_count, 2);
});

test("FREEZE_SNAPSHOT_TOOL_NAMES matches the real registered collect_* tools minus collect_triage_evidence", () => {
  const paths = resolveDescartesPaths();
  const registered = createEvidenceTools(paths).map((tool) => tool.name).filter(isFreezeSnapshotToolName);

  assert.deepEqual([...registered].sort(), [...FREEZE_SNAPSHOT_TOOL_NAMES].sort());
  assert.ok(FREEZE_SNAPSHOT_TOOL_NAMES.length >= 10, "expected at least 10 broad snapshot collectors");
  assert.ok(!FREEZE_SNAPSHOT_TOOL_NAMES.includes("collect_triage_evidence"));
  assert.ok(!FREEZE_SNAPSHOT_TOOL_NAMES.includes("derive_findings"));
  assert.ok(!FREEZE_SNAPSHOT_TOOL_NAMES.includes("inspect_process"));
});

test("runEvidenceFreeze end-to-end with the real createEvidenceTools registry produces a valid, verifiable bundle", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { reason: "integration test", triggeredBy: "test-harness" });

  assert.equal(result.bundle.schema_version, SCHEMA_VERSION);
  assert.ok(result.bundle.source_count >= 10);
  assert.equal(verifyEvidenceBundleIntegrity(result.bundle), true);

  const stat = await fs.stat(result.bundlePath);
  assert.equal(stat.mode & 0o777, 0o600);
});

// ---------------------------------------------------------------------------------------------
// Atomic write, permissions, corrupt-tolerant read-back.
// ---------------------------------------------------------------------------------------------

test("evidence bundle is written atomically (no leftover tmp file) and read-back tolerates corruption/missing files", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_a"), okTool("collect_b")], now: FIXED_NOW });

  const { dir } = resolveEvidenceFreezePaths(paths);
  const entries = await fs.readdir(dir);
  assert.ok(!entries.some((name) => name.endsWith(".tmp")), "expected no leftover .tmp file after a successful freeze");

  const readBack = await readEvidenceBundle(paths, result.filename);
  assert.equal(readBack.missing, false);
  assert.equal(readBack.corrupt, false);
  assert.deepEqual(readBack.bundle, result.bundle);

  await fs.writeFile(result.bundlePath, "{not valid json", { mode: 0o600 });
  const corruptRead = await readEvidenceBundle(paths, result.filename);
  assert.equal(corruptRead.corrupt, true);
  assert.equal(corruptRead.bundle, undefined);

  const missingRead = await readEvidenceBundle(paths, "does-not-exist.json");
  assert.equal(missingRead.missing, true);
});

test("evidence dir is 0o700 and the bundle file is 0o600", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });

  const { dir } = resolveEvidenceFreezePaths(paths);
  const dirStat = await fs.stat(dir);
  const fileStat = await fs.stat(result.bundlePath);
  assert.equal(dirStat.mode & 0o777, 0o700);
  assert.equal(fileStat.mode & 0o777, 0o600);
});

// ---------------------------------------------------------------------------------------------
// sha256 integrity digest.
// ---------------------------------------------------------------------------------------------

test("sha256 integrity digest is recomputed correctly on read-back and flips when a byte is tampered", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });

  const { integrity, ...rest } = result.bundle;
  assert.equal(computeBundleDigest(rest), integrity.sha256);
  assert.equal(verifyEvidenceBundleIntegrity(result.bundle), true);

  const tampered = { ...result.bundle, reason: `${result.bundle.reason}_TAMPERED` };
  assert.equal(verifyEvidenceBundleIntegrity(tampered), false);
});

// ---------------------------------------------------------------------------------------------
// Collision safety.
// ---------------------------------------------------------------------------------------------

test("buildEvidenceBundleFilename produces the documented <timestamp>-<nonce>-<reasonHash>.json shape", () => {
  const filename = buildEvidenceBundleFilename({
    nowIso: "2026-07-13T00:00:00.000Z",
    nonceHex: "0123456789abcdef",
    reasonHash: "fedcba9876543210",
  });
  assert.equal(filename, "2026-07-13T00-00-00-000Z-0123456789abcdef-fedcba9876543210.json");
  assert.match(filename, FILENAME_RE);
});

test("two freezes within the same timestamp-resolution window produce distinct filenames via the random nonce", async () => {
  const paths = await makeTempPaths();
  const first = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });
  const second = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });

  assert.notEqual(first.filename, second.filename);
  const filenames = await listEvidenceBundleFilenames(paths);
  assert.equal(filenames.length, 2);
});

test("a forced same timestamp+nonce+reason collision fails LOUDLY and never overwrites the prior bundle", async () => {
  const paths = await makeTempPaths();
  const first = await runEvidenceFreeze(paths, {
    tools: [okTool("collect_x")],
    now: FIXED_NOW,
    nonce: "deadbeefdeadbeef",
    reason: "same-reason",
  });

  await assert.rejects(
    () => runEvidenceFreeze(paths, {
      tools: [throwingTool("collect_x")], // deliberately different content, to prove the FIRST bundle is untouched
      now: FIXED_NOW,
      nonce: "deadbeefdeadbeef",
      reason: "same-reason",
    }),
    /collision/i,
  );

  const { dir } = resolveEvidenceFreezePaths(paths);
  const entries = await fs.readdir(dir);
  assert.ok(!entries.some((name) => name.endsWith(".tmp")), "expected the failed attempt's tmp file to be cleaned up");

  const readBack = await readEvidenceBundle(paths, first.filename);
  assert.deepEqual(readBack.bundle, first.bundle);
  assert.equal(readBack.bundle.degraded_count, 0, "the persisted bundle must still reflect the FIRST (successful) attempt, not the failed second one");
});

// ---------------------------------------------------------------------------------------------
// Graceful partial-degrade.
// ---------------------------------------------------------------------------------------------

test("a failing or unavailable evidence source degrades gracefully; the freeze still succeeds and writes a bundle", async () => {
  const paths = await makeTempPaths();
  const tools = [okTool("collect_good"), throwingTool("collect_bad"), degradedTool("collect_unable")];

  const result = await runEvidenceFreeze(paths, { tools, now: FIXED_NOW });

  assert.equal(result.bundle.source_count, 3);
  assert.equal(result.bundle.succeeded_count, 1);
  assert.equal(result.bundle.degraded_count, 2);

  const byName = Object.fromEntries(result.bundle.sources.map((source) => [source.name, source]));
  assert.equal(byName.collect_good.status, "ok");
  assert.equal(byName.collect_bad.status, "degraded");
  assert.match(byName.collect_bad.error, /boom/);
  assert.equal(byName.collect_unable.status, "degraded");
  assert.equal(byName.collect_unable.envelope.status, "unable");
});

// ---------------------------------------------------------------------------------------------
// reason sanitization / bounding / hash-at-source.
// ---------------------------------------------------------------------------------------------

test("sanitizeFreezeReason hashes the sanitized reason and bounds the manifest field", () => {
  const { reason, reasonHash } = sanitizeFreezeReason("../../etc/passwd");
  assert.ok(!reason.includes("/"), "sanitized reason must never contain a path separator");
  assert.match(reasonHash, /^[0-9a-f]{16}$/);
});

test("a path-traversal-shaped reason cannot reach the filename and is charset-bounded in the manifest", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW, reason: "../../etc/passwd" });

  assert.match(result.filename, FILENAME_RE);
  assert.ok(!result.bundle.reason.includes("/"));
  assert.ok(!result.filename.includes("etc"));
  assert.ok(!result.filename.includes("passwd"));
});

test("an injection-shaped reason is charset-bounded in the manifest and the filename keeps its fixed shape", async () => {
  const paths = await makeTempPaths();
  const reason = "reason'; rm -rf / #$(whoami)`id`";
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW, reason });

  assert.match(result.bundle.reason, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
  assert.match(result.filename, FILENAME_RE);
});

test("a 500-char reason is bounded in the manifest, not carried through unbounded", async () => {
  const paths = await makeTempPaths();
  const longReason = "a".repeat(500);
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW, reason: longReason });

  assert.ok(result.bundle.reason.length <= MAX_REASON_LENGTH);
  assert.notEqual(result.bundle.reason.length, 500);
});

test("a missing/empty reason defaults to the safe, non-empty DEFAULT_REASON", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });
  assert.equal(result.bundle.reason, sanitizeFreezeReason(DEFAULT_REASON).reason);
});

// ---------------------------------------------------------------------------------------------
// Never subject to fact-store.js's retention cap.
// ---------------------------------------------------------------------------------------------

test("evidence bundles are never touched by fact-store.js's retention mechanism", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });

  // Deliberately aggressive retention sweep (0 retention window, 0 byte budget) against
  // fact-store.js's own, entirely disjoint store — must not reach stateDir/evidence/ at all.
  await enforceFactRetention(paths, { retentionMs: 0, maxBytes: 0, now: FIXED_NOW });

  const stillThere = await readEvidenceBundle(paths, result.filename);
  assert.equal(stillThere.missing, false);
  assert.deepEqual(stillThere.bundle, result.bundle);
});

// ---------------------------------------------------------------------------------------------
// Audit trail.
// ---------------------------------------------------------------------------------------------

test("every invocation appends an audit record with triggered_by/timestamp/per-source status", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, {
    tools: [okTool("collect_a"), throwingTool("collect_b")],
    now: FIXED_NOW,
    triggeredBy: "unit-test-agent",
  });

  const records = await readEvidenceFreezeAudit(paths);
  assert.equal(records.length, 1);
  const record = records[0];
  assert.equal(record.triggered_by, "unit-test-agent");
  assert.equal(record.ts, FIXED_NOW);
  assert.equal(record.bundle_filename, result.filename);
  assert.equal(record.integrity_sha256, result.bundle.integrity.sha256);
  assert.deepEqual(record.sources.map((source) => source.name).sort(), ["collect_a", "collect_b"]);
  assert.deepEqual(record.sources.find((source) => source.name === "collect_b").status, "degraded");
});

test("a missing triggeredBy defaults to 'operator' in both the manifest and the audit record", async () => {
  const paths = await makeTempPaths();
  const result = await runEvidenceFreeze(paths, { tools: [okTool("collect_x")], now: FIXED_NOW });

  assert.equal(result.bundle.triggered_by, "operator");
  const records = await readEvidenceFreezeAudit(paths);
  assert.equal(records.at(-1).triggered_by, "operator");
});

// ---------------------------------------------------------------------------------------------
// CLI dispatch.
// ---------------------------------------------------------------------------------------------

test("descartes incident freeze dispatches and produces a bundle (--json)", async () => {
  const paths = await makeTempPaths();
  const outputs = [];
  const result = await runIncident(paths, ["freeze", "--reason", "cli test", "--json"], { output: (line) => outputs.push(line) });

  assert.equal(outputs.length, 1);
  const parsed = JSON.parse(outputs[0]);
  assert.equal(parsed.bundle.reason, "cli_test");
  const readBack = await readEvidenceBundle(paths, parsed.filename);
  assert.equal(readBack.missing, false);
  assert.equal(result.bundle.reason, "cli_test");
});

test("descartes incident freeze without --json prints a human-readable summary", async () => {
  const paths = await makeTempPaths();
  const outputs = [];
  await runIncident(paths, ["freeze"], { output: (line) => outputs.push(line) });

  assert.equal(outputs.length, 1);
  assert.match(outputs[0], /Descartes evidence freeze: wrote/);
  assert.match(outputs[0], /Integrity: sha256:/);
});

test("descartes incident with no subcommand prints usage and does not freeze", async () => {
  const outputs = [];
  const result = await runIncident({}, [], { output: (line) => outputs.push(line) });

  assert.equal(result, undefined);
  assert.match(outputs[0], /descartes incident freeze/);
  assert.match(outputs[0], /READ-ONLY/);
});

test("descartes incident with an unknown subcommand throws", async () => {
  await assert.rejects(() => runIncident({}, ["bogus"], { output: () => {} }), /Unknown incident subcommand/);
});
