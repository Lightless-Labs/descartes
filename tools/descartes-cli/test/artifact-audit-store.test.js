import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ARTIFACT_AUDIT_RECORD_KINDS,
  appendArtifactAuditRecord,
  normalizeArtifactAuditRecord,
  readArtifactAuditRecords,
  resolveArtifactAuditPaths,
} from "../src/artifact-audit-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-artifact-audit-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("resolveArtifactAuditPaths points at stateDir/learned/artifact-audit.jsonl, no double-nesting", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveArtifactAuditPaths(paths);
  assert.equal(auditFile, path.join(paths.stateDir, "learned", "artifact-audit.jsonl"));
});

test("ARTIFACT_AUDIT_RECORD_KINDS is the closed set this file (S15) and S14 (tuning_proposal_mined/tuning_decision) share", () => {
  assert.deepEqual(ARTIFACT_AUDIT_RECORD_KINDS, ["calibration_report", "tuning_proposal_mined", "tuning_decision"]);
});

test("readArtifactAuditRecords returns [] when the file is missing (fresh install)", async () => {
  const paths = await tempPaths();
  assert.deepEqual(await readArtifactAuditRecords(paths), []);
});

test("append + read round-trip preserves counts-only fields", async () => {
  const paths = await tempPaths();
  const appended = await appendArtifactAuditRecord(paths, {
    ts: "2026-07-10T00:00:00.000Z",
    kind: "calibration_report",
    window: { since: null, until: null },
    artifact_count: 2,
    family_counts: { "session.count_drop": 1, "constraint.violation.x": 1 },
  });
  assert.equal(appended.schema_version, 1);

  const records = await readArtifactAuditRecords(paths);
  assert.equal(records.length, 1);
  assert.equal(records[0].kind, "calibration_report");
  assert.equal(records[0].artifact_count, 2);
  assert.deepEqual(records[0].family_counts, { "session.count_drop": 1, "constraint.violation.x": 1 });
});

test("appending twice produces two independent, append-only lines (never overwritten/deleted)", async () => {
  const paths = await tempPaths();
  await appendArtifactAuditRecord(paths, { ts: "2026-07-10T00:00:00.000Z", kind: "calibration_report", artifact_count: 0 });
  await appendArtifactAuditRecord(paths, { ts: "2026-07-10T00:05:00.000Z", kind: "calibration_report", artifact_count: 3 });
  const records = await readArtifactAuditRecords(paths);
  assert.equal(records.length, 2);
  assert.equal(records[0].artifact_count, 0);
  assert.equal(records[1].artifact_count, 3);
});

test("normalizeArtifactAuditRecord rejects an unrecognized kind (fail loud on a write-path programmer error)", () => {
  assert.throws(() => normalizeArtifactAuditRecord({ kind: "bogus" }), /Unsupported artifact-audit record kind/);
  assert.throws(() => normalizeArtifactAuditRecord({}), /Unsupported artifact-audit record kind/);
});

test("family_counts KEYS are sanitized -- unsafe-shaped characters (paths, whitespace) never survive verbatim (defense-in-depth, plan §4.4)", () => {
  const normalized = normalizeArtifactAuditRecord({
    kind: "calibration_report",
    family_counts: { "/etc/passwd or a raw hostname": 3 },
  });
  const keys = Object.keys(normalized.family_counts);
  assert.equal(keys.length, 1);
  const [safeKey] = keys;
  assert.equal(safeKey.includes("/"), false);
  assert.equal(safeKey.includes(" "), false);
  assert.match(safeKey, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
  // The count itself survives -- this is redaction of an identifier's shape, not data loss of the
  // metric. (The real confidentiality control, per plan §1 point 6, is that real family_counts
  // keys only ever come from the closed rule_id-family set to begin with, which never contains a
  // raw hostname/path -- this is defense-in-depth on top of that, not a substring-scrubber.)
  assert.equal(Object.values(normalized.family_counts).reduce((sum, n) => sum + n, 0), 3);
});

test("family_counts keys that are already safe (the real closed rule_id-family set) pass through unchanged", () => {
  const normalized = normalizeArtifactAuditRecord({
    kind: "calibration_report",
    family_counts: { "constraint.violation.daemon-config": 2, "session.count_drop": 1 },
  });
  assert.deepEqual(normalized.family_counts, { "constraint.violation.daemon-config": 2, "session.count_drop": 1 });
});

test("corrupt lines in artifact-audit.jsonl are skipped, never thrown -- append-only observability trail, never load-bearing", async () => {
  const paths = await tempPaths();
  const { auditFile } = resolveArtifactAuditPaths(paths);
  await fs.mkdir(path.dirname(auditFile), { recursive: true });
  await fs.writeFile(
    auditFile,
    `not-json\n${JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", kind: "calibration_report", artifact_count: 0, schema_version: 1 })}\n`,
  );
  const records = await readArtifactAuditRecords(paths);
  assert.equal(records.length, 1);
  assert.equal(records[0].artifact_count, 0);
});

test("no LLM anywhere: artifact-audit-store.js never imports pi-harness.js or alert-intelligence.js, never calls createSession", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/artifact-audit-store.js"), "utf8");
  // Real import syntax only -- a doc comment is free to name these files in prose without
  // tripping this check (it isn't a comment-stripping lint like escalation-lint.test.js; it
  // targets the actual import surface, which is the thing that matters for "does this module
  // pull in the LLM harness").
  assert.equal(/from\s*["'`]\.\/(pi-harness|alert-intelligence)\.js["'`]/.test(source), false);
  assert.equal(/import\(\s*["'`][^"'`]*(pi-harness|alert-intelligence)\.js["'`]\s*\)/.test(source), false);
  assert.equal(/\bcreateSession\s*\(/.test(source), false);
});
