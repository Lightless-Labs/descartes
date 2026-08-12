import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { loadCanaryManifest } from "../src/canary-manifest.js";

async function makePaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-manifest-"));
  return { root, paths: { configDir: root } };
}

test("missing manifest is an empty opt-in surface, marked as a successful read (legit decommission/never-configured)", async () => {
  const { root, paths } = await makePaths();
  try { assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], read_ok: true }); }
  finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("corrupt manifest fails closed AND is flagged as a read/parse FAILURE (read_ok:false), not an authoritative empty manifest", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), "{not json");
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], corrupt: true, read_ok: false });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// P1 fix (canary collector review round 2): a manifest that could not be READ at all (distinct
// from corrupt-but-readable JSON) must ALSO be flagged read_ok:false, not silently degraded to
// the same shape a genuine "no manifest configured" (ENOENT) produces. Directory trick (no fs
// mocking / no chmod, mirrors alerts.test.js's own EISDIR pattern): making the manifest path
// itself a directory makes fs.readFile fail with a real, non-ENOENT filesystem error regardless
// of the test runner's uid (chmod-based permission tricks are unreliable when running as root).
test("unreadable manifest (EISDIR) fails closed AND is flagged as a read FAILURE (read_ok:false)", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.mkdir(path.join(root, "canaries.json"), { recursive: true });
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], unreadable: true, read_ok: false });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// Tamper fix (canary v0 finalization): valid JSON that is NOT shaped like a manifest at all (no
// schema_version:1, or `canaries` missing/not-an-array) must be flagged read_ok:false, the same
// failure class as a parse/fs error -- NOT degraded to the identical `{canaries:[]}` shape a
// genuinely-authored empty manifest produces (see the "missing manifest"/legit-decommission test
// above, which stays read_ok:true).
test("schema-invalid manifest (valid JSON, wrong shape) fails closed AND is flagged read_ok:false, distinct from a legit empty manifest", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 2, canaries: [] }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], schema_invalid: true, read_ok: false });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("schema-invalid manifest (canaries not an array) fails closed AND is flagged read_ok:false", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries: "not-an-array" }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], schema_invalid: true, read_ok: false });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("schema-invalid manifest (a bare JSON array, not an object) fails closed AND is flagged read_ok:false", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify([]));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], schema_invalid: true, read_ok: false });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// A genuinely valid, genuinely empty manifest (the real legit-decommission shape) must NOT be
// caught by the schema-invalid check above.
test("a syntactically valid, genuinely empty manifest (schema_version:1, canaries:[]) is still a successful read_ok:true (legit decommission)", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries: [] }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [], read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("invalid entries are dropped while valid entries pass through", async () => {
  const { root, paths } = await makePaths();
  try {
    const valid = { id: "credential", kind: "credential-file", path: "/tmp/credential.bak", watch: ["mtime", "executed"], sentinel_path: "/tmp/credential.executed" };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [
        valid,
        { id: "missing-path", kind: "credential-file", watch: ["mtime"] },
        { id: "bad-kind", kind: "listener", path: "/tmp/x", watch: ["mtime"] },
        { id: "bad-watch", kind: "credential-file", path: "/tmp/x", watch: ["unknown"] },
      ],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [valid], read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
