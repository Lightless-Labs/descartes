import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { collectCanaryEvidence, MAX_CANARIES } from "../src/tools/canary.js";

async function fixtureDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "descartes-canary-"));
}

test("empty canary list is an ok no-op", async () => {
  const evidence = await collectCanaryEvidence([]);
  assert.equal(evidence.status, "ok");
  assert.equal(evidence.confidence, 0.9);
  assert.deepEqual(evidence.result.summary, { total_count: 0, ok_count: 0, absent_count: 0, unreadable_count: 0, execution_unknown_count: 0 });
  assert.deepEqual(evidence.result.canaries, []);
});

test("collects real file metadata and preserves the manifest watch list", async () => {
  const dir = await fixtureDir();
  try {
    const file = path.join(dir, "credential.bak");
    const sentinel = path.join(dir, "credential.bak.executed");
    await fs.writeFile(file, "fixture");
    await fs.writeFile(sentinel, "");
    const watch = ["mtime", "executed"];
    const evidence = await collectCanaryEvidence([{ id: "aws-backup", kind: "credential-file", path: file, watch, sentinel_path: sentinel }]);
    const entry = evidence.result.canaries[0];
    assert.equal(entry.status, "ok");
    assert.equal(typeof entry.atime, "string");
    assert.equal(typeof entry.mtime, "string");
    assert.equal(typeof entry.ino, "string");
    assert.equal(entry.size, "7");
    assert.equal(entry.executed, "true");
    assert.strictEqual(entry.watch, watch);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("missing files degrade to absent without warning", async () => {
  const evidence = await collectCanaryEvidence([{ id: "missing", kind: "suid-binary", path: "/no/such/canary", watch: ["atime"] }]);
  assert.equal(evidence.status, "ok");
  assert.deepEqual(evidence.result.canaries[0], { id: "missing", kind: "suid-binary", status: "absent" });
});

test("lstat permission errors degrade the envelope to warning", async () => {
  const evidence = await collectCanaryEvidence(
    [{ id: "blocked", kind: "sudoers-entry", path: "/restricted", watch: ["mtime"] }],
    { lstat: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; } },
  );
  assert.equal(evidence.status, "warning");
  assert.equal(evidence.confidence, 0.5);
  assert.equal(evidence.result.canaries[0].status, "unreadable");
});

test("execution sentinel uses access existence checks only", async () => {
  const calls = [];
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async (...args) => { calls.push(args); },
    },
  );
  assert.equal(evidence.result.canaries[0].executed, "true");
  assert.deepEqual(calls, [["/sentinel", 0]]);

  const absentSentinel = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async () => { const error = new Error("missing"); error.code = "ENOENT"; throw error; },
    },
  );
  assert.equal(absentSentinel.result.canaries[0].executed, "false");
});

test("a non-ENOENT access() failure (e.g. EACCES) degrades executed to unknown, never a fabricated false", async () => {
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; },
    },
  );
  assert.equal(evidence.result.canaries[0].executed, "unknown");

  // An error with no recognized code at all is equally NOT evidence of "false" — fail closed the
  // same way, rather than assuming ENOENT-shaped absence.
  const evidenceNoCode = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async () => { throw new Error("unspecified failure"); },
    },
  );
  assert.equal(evidenceNoCode.result.canaries[0].executed, "unknown");
});

test("P1 fix: a sentinel EACCES degrades the whole envelope to warning even though lstat succeeded", async () => {
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; },
    },
  );
  // lstat succeeded (no unreadable canary), yet a real execution-check failure occurred — the
  // envelope must still degrade to "warning", not silently report "ok" and lose the blackout.
  assert.equal(evidence.result.canaries[0].status, "ok");
  assert.equal(evidence.result.canaries[0].executed, "unknown");
  assert.equal(evidence.result.summary.unreadable_count, 0);
  assert.equal(evidence.result.summary.execution_unknown_count, 1);
  assert.equal(evidence.status, "warning");
  assert.equal(evidence.confidence, 0.5);
});

test("an executed-watch with no sentinel_path configured is a config error -> unknown, never a fabricated false", async () => {
  const evidence = await collectCanaryEvidence(
    [{ id: "misconfigured", kind: "scheduled-job", path: "/fixture", watch: ["executed"] }],
    {
      lstat: async () => ({ atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }),
      access: async () => { throw new Error("should never be called: no sentinel_path configured"); },
    },
  );
  const entry = evidence.result.canaries[0];
  assert.equal(entry.executed, "unknown");
  assert.notEqual(entry.executed, "false");
  // Same degrade-not-fabricate posture as the EACCES/unrecognized-error paths: the missing-check
  // must ALSO surface at the envelope level (warning + execution_unknown_count), not just in the
  // per-canary record, or a fully-misconfigured executed-watch canary would silently look like a
  // complete, healthy census.
  assert.equal(evidence.result.summary.execution_unknown_count, 1);
  assert.equal(evidence.status, "warning");
  assert.equal(evidence.confidence, 0.5);
});

test("bounds processing at MAX_CANARIES and does not import child_process", async () => {
  const source = await fs.readFile(new URL("../src/tools/canary.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /execFile|child_process/);
  let lstatCalls = 0;
  const canaries = Array.from({ length: MAX_CANARIES + 1 }, (_, index) => ({ id: `c${index}`, kind: "writable-directory", path: `/c${index}`, watch: ["mtime"] }));
  const evidence = await collectCanaryEvidence(canaries, {
    lstat: async () => { lstatCalls += 1; return { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 }; },
  });
  assert.equal(lstatCalls, MAX_CANARIES);
  assert.equal(evidence.result.canaries.length, MAX_CANARIES);
  assert.equal(evidence.result.truncated, true);
});
