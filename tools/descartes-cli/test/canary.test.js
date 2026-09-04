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

// Round-2 fix (positive-evidence re-gate, finding 4): "executed" is now determined by lstat-ing
// the SENTINEL path itself, never access()/stat() -- lstat never follows a final symlink
// component, so this cannot be fooled by a dangling sentinel symlink whose TARGET an attacker
// later creates (see the dedicated dangling-symlink test below). This test pinned the old,
// buggy access(F_OK) behavior; updated to the lstat-only semantics.
test("execution sentinel uses lstat existence checks only, never access()", async () => {
  const calls = [];
  const stubStat = { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 };
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async (targetPath) => { calls.push(targetPath); return stubStat; },
    },
  );
  assert.equal(evidence.result.canaries[0].executed, "true");
  assert.deepEqual(calls, ["/fixture", "/sentinel"]);

  const absentSentinel = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async (targetPath) => {
        if (targetPath === "/sentinel") { const error = new Error("missing"); error.code = "ENOENT"; throw error; }
        return stubStat;
      },
    },
  );
  assert.equal(absentSentinel.result.canaries[0].executed, "false");
});

test("a non-ENOENT lstat() failure on the sentinel (e.g. EACCES) degrades executed to unknown, never a fabricated false", async () => {
  const stubStat = { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 };
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async (targetPath) => {
        if (targetPath === "/sentinel") { const error = new Error("denied"); error.code = "EACCES"; throw error; }
        return stubStat;
      },
    },
  );
  assert.equal(evidence.result.canaries[0].executed, "unknown");

  // An error with no recognized code at all is equally NOT evidence of "false" — fail closed the
  // same way, rather than assuming ENOENT-shaped absence.
  const evidenceNoCode = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async (targetPath) => {
        if (targetPath === "/sentinel") throw new Error("unspecified failure");
        return stubStat;
      },
    },
  );
  assert.equal(evidenceNoCode.result.canaries[0].executed, "unknown");
});

// Round-2 fix (finding 4) dedicated regression: a dangling sentinel SYMLINK must report
// executed:"true" the moment it exists (its own lstat identity, unaffected by whether the target
// exists) and must NOT flip on account of the target appearing/disappearing later -- lstat never
// resolves the final symlink component, unlike the old access(F_OK), which followed it and would
// fabricate a false->true "executed" transition purely from the target being created.
test("[round-2 fix] a dangling sentinel symlink reports executed:'true' from lstat alone, unaffected by whether its target exists", async () => {
  const dir = await fixtureDir();
  try {
    const file = path.join(dir, "credential.bak");
    const sentinel = path.join(dir, "credential.bak.executed");
    const target = path.join(dir, "never-created-target");
    await fs.writeFile(file, "fixture");
    await fs.symlink(target, sentinel); // dangling: target does not exist
    const watch = ["mtime", "executed"];

    const before = await collectCanaryEvidence([{ id: "aws-backup", kind: "credential-file", path: file, watch, sentinel_path: sentinel }]);
    const beforeEntry = before.result.canaries[0];
    assert.equal(beforeEntry.executed, "true");
    const beforeSentinelLstat = await fs.lstat(sentinel);

    // The attacker (or anything else) creates ONLY the target -- the sentinel symlink itself is
    // untouched.
    await fs.writeFile(target, "now exists");

    const after = await collectCanaryEvidence([{ id: "aws-backup", kind: "credential-file", path: file, watch, sentinel_path: sentinel }]);
    const afterEntry = after.result.canaries[0];
    assert.equal(afterEntry.executed, "true");
    const afterSentinelLstat = await fs.lstat(sentinel);
    // The sentinel's OWN identity (ino/mtime) is unchanged -- no real event occurred at the
    // sentinel itself, only at its (irrelevant, per lstat-only semantics) target.
    assert.equal(afterSentinelLstat.ino, beforeSentinelLstat.ino);
    assert.equal(afterSentinelLstat.mtimeMs, beforeSentinelLstat.mtimeMs);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("P1 fix: a sentinel EACCES degrades the whole envelope to warning even though lstat succeeded", async () => {
  const stubStat = { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 };
  const evidence = await collectCanaryEvidence(
    [{ id: "sentinel", kind: "scheduled-job", path: "/fixture", watch: ["executed"], sentinel_path: "/sentinel" }],
    {
      lstat: async (targetPath) => {
        if (targetPath === "/sentinel") { const error = new Error("denied"); error.code = "EACCES"; throw error; }
        return stubStat;
      },
    },
  );
  // lstat succeeded for the canary's own path (no unreadable canary), yet a real execution-check
  // failure occurred on the sentinel — the envelope must still degrade to "warning", not silently
  // report "ok" and lose the blackout.
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
      lstat: async (targetPath) => {
        if (targetPath !== "/fixture") throw new Error("should never lstat anything but the canary's own path: no sentinel_path configured");
        return { atime: new Date(1), mtime: new Date(2), ino: 3, size: 4 };
      },
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
