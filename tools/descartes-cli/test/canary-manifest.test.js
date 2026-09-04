import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { loadCanaryManifest } from "../src/canary-manifest.js";
import { MAX_CANARIES } from "../src/tools/canary.js";

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

// Round-4 fix (positive-evidence isolation completeness, daybreak-blue finding 3): each of the
// three malformed entries below still carries a USABLE declared id -- unlike a pre-round-4 world
// where they were silently dropped with no operator-visible signal (and, worse, an established
// canary reusing one of these ids would have its genuine trip filtered out downstream at
// canary-baseline.js's currentCanaryIds gate), they must now be isolated (invalid_entries,
// reason: "schema_invalid") -- exactly like an entity_key_collision/manifest_oversized entry --
// rather than vanishing.
test("invalid entries with a usable declared id are isolated (schema_invalid) while valid entries pass through", async () => {
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
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [valid],
      invalid_entries: [
        { id: "missing-path", kind: "credential-file", reason: "schema_invalid" },
        { id: "bad-kind", kind: "listener", reason: "schema_invalid" },
        { id: "bad-watch", kind: "credential-file", reason: "schema_invalid" },
      ],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// Round-4 fix parity: an entry with NO usable declared id at all (missing id, or an id that
// sanitizes to nothing safe) can never resolve to a real canary_id downstream -- isolating it
// would be meaningless, so it stays a genuine silent drop, same as before this fix.
test("invalid entries with NO usable declared id are silently dropped, not isolated", async () => {
  const { root, paths } = await makePaths();
  try {
    const valid = { id: "credential", kind: "credential-file", path: "/tmp/credential.bak", watch: ["mtime"] };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [
        valid,
        { kind: "credential-file", path: "/tmp/no-id", watch: ["mtime"] },
        { id: "////", kind: "credential-file", watch: ["mtime"] },
      ],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [valid], read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// [BLOCKER fix] persistently-partial census: a watch:["executed"] entry with NO sentinel_path
// makes tools/canary.js's collectOneCanary emit executed:"unknown" EVERY tick (there is no
// sentinel to check) -- which forces fact-translators.js's census marker to "partial" forever,
// which drives canary-baseline.js's completeGroups below the two-COMPLETE-group floor
// PERMANENTLY, silently and collaterally killing canary.tripped/canary_vanished detection for
// EVERY canary in the manifest, not just this misconfigured one. The entry must be rejected
// outright at manifest-load time -- it can never produce a real observation either way.
// Round-4 fix parity: "misconfigured" carries a usable declared id, so once the executed-strip
// leaves its watch list empty it must be ISOLATED (schema_invalid), not silently dropped -- same
// treatment as any other usable-id validation failure.
test("[BLOCKER fix] an entry watching 'executed' with no sentinel_path is isolated as schema_invalid (would otherwise force every tick's census permanently 'partial')", async () => {
  const { root, paths } = await makePaths();
  try {
    const valid = { id: "credential", kind: "credential-file", path: "/tmp/credential.bak", watch: ["mtime"] };
    const noSentinel = { id: "misconfigured", kind: "credential-file", path: "/tmp/x", watch: ["executed"] };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [valid, noSentinel],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [valid],
      invalid_entries: [{ id: "misconfigured", kind: "credential-file", reason: "schema_invalid" }],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("[BLOCKER fix] a watch:['executed'] entry with a valid sentinel_path is NOT dropped by the new guard", async () => {
  const { root, paths } = await makePaths();
  try {
    const withSentinel = { id: "credential", kind: "credential-file", path: "/tmp/credential.bak", watch: ["executed"], sentinel_path: "/tmp/credential.executed" };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries: [withSentinel] }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries: [withSentinel], read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// Round-2 fix (positive-evidence re-gate, finding 1): round 1's guard dropped the WHOLE entry for
// ANY watch:[...,"executed",...] with no sentinel_path -- over-broad, since it also discarded any
// OTHER legit watch (mtime/atime) the same entry carried. The entry must survive with only
// "executed" surgically removed from its watch list.
test("[round-2 fix] a ['mtime','executed'] entry with no sentinel_path keeps its mtime watch (only 'executed' is stripped, the entry is NOT dropped)", async () => {
  const { root, paths } = await makePaths();
  try {
    const mixedNoSentinel = { id: "mixed", kind: "credential-file", path: "/tmp/mixed", watch: ["mtime", "executed"] };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries: [mixedNoSentinel] }));
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [{ id: "mixed", kind: "credential-file", path: "/tmp/mixed", watch: ["mtime"] }],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// [LOW-MEDIUM fix, round-2 revised] entity_key collision: canary-baseline.js's
// groupCanaryFactsByTick keys each tick's presence facts by the SANITIZED (not hashed) manifest id
// -- fact-translators.js's sanitizeEntityKey substitutes disallowed characters and truncates, so
// two distinct manifest ids can collapse onto the SAME entity_key (e.g. "prod/key" and "prod_key"
// both sanitize to "prod_key"). Left undetected, the later-written presence fact silently
// overwrites the earlier one in that tick's Map and one canary's evidence is lost with no signal
// at all. Round 1 fixed this by failing the WHOLE manifest closed (read_ok:false) -- over-broad:
// it also silenced every OTHER, unrelated canary's collection. Round 2: isolate instead -- only
// the colliding entries are pulled out (surfaced via invalid_entries so canary-baseline.js can
// still raise canary.tampered for each of them), read_ok stays true, and the manifest is otherwise
// authoritative.
test("[round-2 fix] two manifest ids that sanitize to the SAME entity_key are isolated (invalid_entries), NOT a whole-manifest read_ok:false failure", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [
        { id: "prod/key", kind: "credential-file", path: "/tmp/a", watch: ["mtime"] },
        { id: "prod_key", kind: "credential-file", path: "/tmp/b", watch: ["mtime"] },
      ],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [],
      invalid_entries: [
        { id: "prod/key", kind: "credential-file", reason: "entity_key_collision" },
        { id: "prod_key", kind: "credential-file", reason: "entity_key_collision" },
      ],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// Round-2 fix, finding 2's own repro: an unrelated, NON-colliding canary must keep collecting
// normally -- a collision between two OTHER entries must not empty the whole manifest.
test("[round-2 fix] an unrelated, non-colliding canary is unaffected by another pair's entity_key collision", async () => {
  const { root, paths } = await makePaths();
  try {
    const unrelated = { id: "unrelated", kind: "credential-file", path: "/tmp/unrelated", watch: ["mtime"] };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [
        unrelated,
        { id: "prod/key", kind: "credential-file", path: "/tmp/a", watch: ["mtime"] },
        { id: "prod_key", kind: "credential-file", path: "/tmp/b", watch: ["mtime"] },
      ],
    }));
    const result = await loadCanaryManifest(paths);
    assert.deepEqual(result.canaries, [unrelated]);
    assert.equal(result.read_ok, true);
    assert.deepEqual(result.invalid_entries, [
      { id: "prod/key", kind: "credential-file", reason: "entity_key_collision" },
      { id: "prod_key", kind: "credential-file", reason: "entity_key_collision" },
    ]);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("[LOW-MEDIUM fix] distinct ids that sanitize to distinct entity_keys do not collide and pass through normally", async () => {
  const { root, paths } = await makePaths();
  try {
    const canaries = [
      { id: "credential-a", kind: "credential-file", path: "/tmp/a", watch: ["mtime"] },
      { id: "credential-b", kind: "credential-file", path: "/tmp/b", watch: ["mtime"] },
    ];
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries, read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// [MEDIUM fix, finding 5] an id that sanitizes to NO safe entity_key (e.g. all-disallowed chars)
// bypassed collision handling entirely under the old `if (!entityKey) continue;` loop and silently
// lost its evidence downstream -- fact-translators.js's factPointsFromCanaryEvidence can't emit a
// presence fact with no entity_key, so the canary would be collected (lstat succeeds) but nothing
// is ever recorded, with no operator-visible signal at all. Routed the same way as a collision:
// isolated out of `canaries`, flagged via invalid_entries for a canary.tampered alert.
test("[round-2 fix] an id that sanitizes to an empty entity_key is isolated (invalid_entries: empty_entity_key), not silently dropped", async () => {
  const { root, paths } = await makePaths();
  try {
    const unrelated = { id: "unrelated", kind: "credential-file", path: "/tmp/unrelated", watch: ["mtime"] };
    const unsanitizable = { id: "////", kind: "credential-file", path: "/tmp/unsanitizable", watch: ["mtime"] };
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [unrelated, unsanitizable],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [unrelated],
      invalid_entries: [{ id: "////", kind: "credential-file", reason: "empty_entity_key" }],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// [round-2 fix, finding 3] persistently-partial census from manifest-size truncation: a manifest
// with MORE than MAX_CANARIES valid entries used to reach tools/canary.js's collector unbounded,
// which truncated it every tick (truncated:true forever) -> fact-translators.js's census marker
// permanently "partial" -> canary-baseline.js's completeGroups never reaches two -> ALL
// canary.tripped/canary_vanished detection dead, forever, for every canary including the ones well
// within the cap. Fixed at the loader (the root cause): cap `canaries` itself, in manifest order,
// at MAX_CANARIES, so the collector never sees more than the cap and never reports truncated.
// Beyond-cap entries are isolated (invalid_entries: manifest_oversized) rather than silently lost.
test("[round-2 fix] a manifest with more than MAX_CANARIES entries caps `canaries` at the loader (beyond-cap entries isolated as manifest_oversized)", async () => {
  const { root, paths } = await makePaths();
  try {
    const canaries = Array.from({ length: MAX_CANARIES + 1 }, (_, index) => (
      { id: `c${index}`, kind: "credential-file", path: `/tmp/c${index}`, watch: ["mtime"] }
    ));
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries }));
    const result = await loadCanaryManifest(paths);
    assert.equal(result.read_ok, true);
    assert.equal(result.canaries.length, MAX_CANARIES);
    assert.deepEqual(result.canaries, canaries.slice(0, MAX_CANARIES));
    assert.deepEqual(result.invalid_entries, [{ id: `c${MAX_CANARIES}`, kind: "credential-file", reason: "manifest_oversized" }]);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("[round-2 fix] a manifest with exactly MAX_CANARIES entries passes through untouched (no invalid_entries)", async () => {
  const { root, paths } = await makePaths();
  try {
    const canaries = Array.from({ length: MAX_CANARIES }, (_, index) => (
      { id: `c${index}`, kind: "credential-file", path: `/tmp/c${index}`, watch: ["mtime"] }
    ));
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({ schema_version: 1, canaries }));
    assert.deepEqual(await loadCanaryManifest(paths), { canaries, read_ok: true });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

// Round-4 fix (positive-evidence isolation completeness, daybreak-blue finding 3): a schema_invalid
// entry may itself have a missing/non-string `kind` -- that can be exactly WHY it was isolated
// (unlike entity_key_collision/manifest_oversized entries, whose source already passed full
// per-entry validation and so always carries a valid CANARY_KINDS string). `kind` must only be
// carried into invalid_entries when it actually IS a string, never fabricated.
test("[round-4 fix] a schema_invalid entry with a non-string kind omits `kind` from invalid_entries rather than fabricating it", async () => {
  const { root, paths } = await makePaths();
  try {
    await fs.writeFile(path.join(root, "canaries.json"), JSON.stringify({
      schema_version: 1,
      canaries: [{ id: "no-kind-at-all", path: "/tmp/x", watch: ["mtime"] }],
    }));
    assert.deepEqual(await loadCanaryManifest(paths), {
      canaries: [],
      invalid_entries: [{ id: "no-kind-at-all", reason: "schema_invalid" }],
      read_ok: true,
    });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
