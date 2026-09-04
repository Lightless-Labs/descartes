import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { computeStatDiffTripReason } from "../src/stat-diff.js";
import { resolveDefaultCredentialPaths } from "../src/tools/credential-access.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  CREDENTIAL_ACCESS_RULE_ID,
  buildCredentialAccessCandidates,
  computeCredentialAccessCandidates,
  createCredentialCollectionBreaker,
  detectCredentialAccess,
  isValidCredentialAccessBaselineStoreShape,
  loadCredentialAccessBaselineStore,
  resolveCredentialAccessBaselineStorePaths,
  writeCredentialAccessBaselineStore,
} from "../src/credential-access-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-credential-access-baseline-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function expectedHash(pathHash) {
  return createHash("sha256").update(`${CREDENTIAL_ACCESS_RULE_ID}:${pathHash}`).digest("hex").slice(0, 16);
}

const PATH_HASH_A = "0123456789abcdef";
const PATH_HASH_B = "fedcba9876543210";

function okEntry({ pathHash = PATH_HASH_A, category = "ssh_private_key", watch = ["mtime", "ino"], atime = 1000, mtime = 2000, ino = 42 } = {}) {
  return { category, path_hash: pathHash, watch, status: "ok", atime, mtime, ino, size: 7 };
}

// ---------------------------------------------------------------------------------------------
// Store I/O: exact-schema validation, whole-store-invalidation on any single bad entry.
// ---------------------------------------------------------------------------------------------

test("load/write credential-access baseline store is atomic (0o600, no tmp file left behind)", async () => {
  const paths = await tempPaths();
  await writeCredentialAccessBaselineStore(paths, { entries: { [PATH_HASH_A]: { atime: 1, mtime: 2, ino: 3 } } });
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  assert.equal((await fs.stat(storeFile)).mode & 0o777, 0o600);
  assert.equal((await fs.readdir(dir)).some((name) => name.endsWith(".tmp")), false);
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.deepEqual(loaded.entries, { [PATH_HASH_A]: { atime: 1, mtime: 2, ino: 3 } });
});

test("loadCredentialAccessBaselineStore: a missing store returns {}, corrupt:false, missing:true", async () => {
  const paths = await tempPaths();
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.deepEqual(loaded.entries, {});
  assert.equal(loaded.corrupt, false);
  assert.equal(loaded.missing, true);
});

test("loadCredentialAccessBaselineStore: unparseable JSON returns {}, corrupt:true", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.deepEqual(loaded.entries, {});
  assert.equal(loaded.corrupt, true);
});

test("isValidCredentialAccessBaselineStoreShape: version must be 1, entries must be a plain object, every key a 16-hex path_hash, every value exactly {atime,mtime,ino} as finite numbers", () => {
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: {} }), true);
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: { [PATH_HASH_A]: { atime: 1, mtime: 2, ino: 3 } } }), true);
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 2, entries: {} }), false, "wrong version");
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: {}, unexpected: true }), false, "unknown top-level key");
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: { "not-a-hash": { atime: 1, mtime: 2, ino: 3 } } }), false, "malformed path_hash key");
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: { [PATH_HASH_A]: { atime: "1", mtime: 2, ino: 3 } } }), false, "wrong-typed atime (string, not number)");
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: { [PATH_HASH_A]: { atime: 1, mtime: 2, ino: 3, extra: 4 } } }), false, "extra key on an entry value");
  assert.equal(isValidCredentialAccessBaselineStoreShape({ version: 1, entries: { [PATH_HASH_A]: { atime: 1, mtime: 2 } } }), false, "missing ino key");
  assert.equal(isValidCredentialAccessBaselineStoreShape(null), false);
  assert.equal(isValidCredentialAccessBaselineStoreShape([]), false);
});

test("[REVIEW must-fix] a schema-invalid-but-parseable store (a wrong-typed mtime under an otherwise-valid path_hash key) invalidates the WHOLE store, discarded and re-seeded -- never a per-entry skip that leaves the rest partially trusted", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const garbled = {
    version: 1,
    entries: {
      [PATH_HASH_A]: { atime: 1, mtime: "garbled-string", ino: 3 }, // wrong-typed mtime
      [PATH_HASH_B]: { atime: 4, mtime: 5, ino: 6 }, // otherwise perfectly valid entry
    },
  };
  await fs.writeFile(storeFile, JSON.stringify(garbled), { mode: 0o600 });
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.equal(loaded.corrupt, true);
  assert.deepEqual(loaded.entries, {}, "the WHOLE store is discarded, including PATH_HASH_B's otherwise-valid entry");
});

test("[REVIEW must-fix] an unknown key on an otherwise-valid store invalidates the whole store", async () => {
  const paths = await tempPaths();
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, JSON.stringify({ version: 1, entries: {}, rogue: "field" }), { mode: 0o600 });
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.equal(loaded.corrupt, true);
  assert.deepEqual(loaded.entries, {});
});

// ---------------------------------------------------------------------------------------------
// detectCredentialAccess: positive direct evidence, NOT completeness-gated. Pure, no I/O.
// ---------------------------------------------------------------------------------------------

test("first sight of a present path (no prior baseline) seeds silently -- no trip -- and the baseline is now seeded for next time", () => {
  const { findings, nextEntries } = detectCredentialAccess({}, [okEntry()]);
  assert.deepEqual(findings, []);
  assert.deepEqual(nextEntries[PATH_HASH_A], { atime: 1000, mtime: 2000, ino: 42 });
});

test("an mtime advance on an established path fires mtime_changed exactly once; a second unchanged tick does not re-fire", () => {
  const previous = { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } };
  const first = detectCredentialAccess(previous, [okEntry({ mtime: 3000 })]);
  assert.deepEqual(first.findings, [{ category: "ssh_private_key", path_hash: PATH_HASH_A, trip_reason: "mtime_changed" }]);

  // The baseline advanced unconditionally -- comparing the SAME (now-current) stat again does not
  // re-fire (edge-triggered).
  const second = detectCredentialAccess(first.nextEntries, [okEntry({ mtime: 3000 })]);
  assert.deepEqual(second.findings, []);
});

test("an ino change (file replaced) fires ino_changed", () => {
  const previous = { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } };
  const { findings } = detectCredentialAccess(previous, [okEntry({ mtime: 2000, ino: 99 })]);
  assert.deepEqual(findings, [{ category: "ssh_private_key", path_hash: PATH_HASH_A, trip_reason: "ino_changed" }]);
});

test("[O7] atime is disabled for every v1 entry: an atime advance alone (mtime/ino unchanged) never fires, because a real v1 entry's watch list is always ['mtime','ino'] — an injected fixture with watch:['atime'] IS the only way to reach that branch, proving it exists but is unreachable via any real v1 path", () => {
  const previous = { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } };
  const v1Shaped = detectCredentialAccess(previous, [okEntry({ atime: 9999, mtime: 2000, ino: 42, watch: ["mtime", "ino"] })]);
  assert.deepEqual(v1Shaped.findings, [], "a v1-shaped watch list (mtime/ino only) never trips on atime alone");

  assert.equal(computeStatDiffTripReason({ atime: 1000 }, { atime: 9999 }, ["atime"]), "atime_advanced", "the shared atime branch remains available for canary/future opt-in callers");
});

test("status:'absent'/'unreadable' entries are skipped entirely -- no comparison, no baseline update (the last-known-good baseline is left untouched)", () => {
  const previous = { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } };
  const { findings, nextEntries } = detectCredentialAccess(previous, [
    { category: "ssh_private_key", path_hash: PATH_HASH_A, watch: ["mtime", "ino"], status: "absent" },
    { category: "aws_credentials", path_hash: PATH_HASH_B, watch: ["mtime", "ino"], status: "unreadable" },
  ]);
  assert.deepEqual(findings, []);
  assert.deepEqual(nextEntries[PATH_HASH_A], { atime: 1000, mtime: 2000, ino: 42 }, "untouched, not reset");
  assert.equal(nextEntries[PATH_HASH_B], undefined, "never seeded from an unreadable observation");
});

test("invalid current entries are skipped without firing or corrupting the retained baseline, while valid entries in a warning snapshot still fire", () => {
  const previous = {
    [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 },
    [PATH_HASH_B]: { atime: 1000, mtime: 3000, ino: 43 },
  };
  const result = detectCredentialAccess(previous, [
    { ...okEntry({ pathHash: PATH_HASH_A, mtime: Number.NaN }), category: "prod-db.example.com" },
    okEntry({ pathHash: PATH_HASH_B, mtime: 4000, ino: 43 }),
  ]);
  assert.deepEqual(result.findings, [{ category: "ssh_private_key", path_hash: PATH_HASH_B, trip_reason: "mtime_changed" }]);
  assert.deepEqual(result.nextEntries[PATH_HASH_A], previous[PATH_HASH_A]);
  assert.deepEqual(result.nextEntries[PATH_HASH_B], { atime: 1000, mtime: 4000, ino: 43 });
});

test("garbled current path hash/category/watch/stat entries neither fire nor enter the baseline store", () => {
  const previous = { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } };
  const result = detectCredentialAccess(previous, [
    { ...okEntry({ pathHash: "not-a-hash", mtime: 9000 }) },
    { ...okEntry({ pathHash: PATH_HASH_A, mtime: 9000 }), category: "ssh.private_key" },
    { ...okEntry({ pathHash: PATH_HASH_B, mtime: 9000 }), watch: ["mtime"] },
    { ...okEntry({ pathHash: PATH_HASH_B, mtime: 9000 }), size: Number.NaN },
  ]);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.nextEntries, previous);
});

test("buildCredentialAccessCandidates: severity is ALWAYS 'warning', fingerprint/id are hashed, diagnostics carry only category/trip_reason/path_hash -- never a literal path", () => {
  const candidate = buildCredentialAccessCandidates([{ category: "aws_credentials", path_hash: PATH_HASH_A, trip_reason: "mtime_changed" }])[0];
  assert.equal(candidate.rule_id, CREDENTIAL_ACCESS_RULE_ID);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.fingerprint, expectedHash(PATH_HASH_A));
  assert.deepEqual(candidate.diagnostics, { category: "aws_credentials", trip_reason: "mtime_changed", path_hash: PATH_HASH_A });
  // Honest-claim wording lives in alert-intelligence.js's notification branch; the candidate
  // title/summary here must not claim a "read"/"access" either.
  assert.equal(/access|read/i.test(candidate.title + candidate.summary), false, "must not claim to detect a read/access — only a change");
});

// ---------------------------------------------------------------------------------------------
// computeCredentialAccessCandidates: kill-switch, NOT completeness-gated, fires on first eligible
// observation.
// ---------------------------------------------------------------------------------------------

test("computeCredentialAccessCandidates checks learned.json before any I/O", async () => {
  const paths = await tempPaths();
  let collectCalls = 0;
  let loadCalls = 0;
  const result = await computeCredentialAccessCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    collectCredentialAccessEvidence: async () => { collectCalls += 1; return { result: { entries: [] } }; },
    loadCredentialAccessBaselineStore: async () => { loadCalls += 1; return { entries: {} }; },
  });
  assert.deepEqual(result, []);
  assert.equal(collectCalls, 0);
  assert.equal(loadCalls, 0);
});

test("computeCredentialAccessCandidates: cold-start (no prior store) seeds silently -- zero candidates on the first tick", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry()] } }),
  });
  assert.deepEqual(result, []);
  const loaded = await loadCredentialAccessBaselineStore(paths);
  assert.deepEqual(loaded.entries[PATH_HASH_A], { atime: 1000, mtime: 2000, ino: 42 });
});

test("computeCredentialAccessCandidates: a real mtime change on the SECOND observation (after the store already has a baseline) fires exactly once end-to-end -- POSITIVE DIRECT EVIDENCE fires on the first eligible observation, unlike a novelty/absence claim", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeCredentialAccessBaselineStore(paths, { entries: { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } } });

  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 5000 })] } }),
  });
  assert.equal(result.length, 1);
  assert.equal(result[0].rule_id, CREDENTIAL_ACCESS_RULE_ID);
  assert.equal(result[0].diagnostics.trip_reason, "mtime_changed");

  // The store advanced unconditionally -- a second identical tick does not re-fire.
  const second = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 5000 })] } }),
  });
  assert.deepEqual(second, []);
});

test("computeCredentialAccessCandidates: NOT completeness-gated -- fires immediately on the observation right after a corrupt/invalid store re-seeds, given two REAL consecutive ticks (unlike the novelty detectors, there is no multi-tick cold-start lockout here)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(storeFile, "{this is not valid json", { mode: 0o600 });

  // Tick 1: corrupt store forces a whole-store re-seed -- silent, no trip (nothing to diff yet).
  const first = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 2000 })] } }),
  });
  assert.deepEqual(first, []);

  // Tick 2: a genuine mtime change against the tick-1 seed fires immediately -- no multi-tick
  // re-accumulation window required, because this is positive two-snapshot evidence, not an
  // absence/novelty claim over fact-history.
  const second = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 9000 })] } }),
  });
  assert.equal(second.length, 1);
  assert.equal(second[0].diagnostics.trip_reason, "mtime_changed");
});

test("kill-switch: learned.json disabled -> [], zero I/O", async () => {
  const paths = await tempPaths();
  let collectCalls = 0;
  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => { collectCalls += 1; return { result: { entries: [] } }; },
  });
  assert.deepEqual(result, []);
  assert.equal(collectCalls, 0);
});

// ---------------------------------------------------------------------------------------------
// [BLOCKER fix] store I/O failure must not discard an already-computed positive finding or abort
// the tick. Mirrors canary-baseline.js's own baseline-store discipline.
// ---------------------------------------------------------------------------------------------

test("[BLOCKER fix] a throwing loadCredentialAccessBaselineStore does not abort the tick: returns [] and does not write (no trustworthy baseline to diff against or fold onto)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  let writeCalled = false;
  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 9000 })] } }),
    loadCredentialAccessBaselineStore: async () => { const error = new Error("denied"); error.code = "EACCES"; throw error; },
    writeCredentialAccessBaselineStore: async () => { writeCalled = true; },
  });
  assert.deepEqual(result, []);
  assert.equal(writeCalled, false, "must not substitute an empty baseline and write -- that would clobber the real last-known-good baseline");
});

test("[BLOCKER fix] a throwing writeCredentialAccessBaselineStore does NOT discard the already-computed positive finding -- credential.access still fires", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeCredentialAccessBaselineStore(paths, { entries: { [PATH_HASH_A]: { atime: 1000, mtime: 2000, ino: 42 } } });

  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 9000 })] } }),
    writeCredentialAccessBaselineStore: async () => { const error = new Error("read-only filesystem"); error.code = "EROFS"; throw error; },
  });
  assert.equal(result.length, 1, "the positive finding, already computed before the write throws, must survive");
  assert.equal(result[0].rule_id, CREDENTIAL_ACCESS_RULE_ID);
  assert.equal(result[0].diagnostics.trip_reason, "mtime_changed");
});

test("[BLOCKER fix] end-to-end with the real loadCredentialAccessBaselineStore: an unreadable store on disk (EISDIR) does not abort the tick", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const { dir, storeFile } = resolveCredentialAccessBaselineStorePaths(paths);
  // Directory trick (mirrors canary-manifest.test.js's/canary-baseline.test.js's own pattern):
  // making the store path itself a directory forces a real, non-ENOENT fs.readFile failure
  // regardless of the test runner's uid.
  await fs.mkdir(storeFile, { recursive: true });
  const result = await computeCredentialAccessCandidates(paths, {
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry()] } }),
  });
  assert.deepEqual(result, []);
  assert.equal((await fs.stat(dir)).isDirectory(), true, "sanity: the state dir itself is untouched");
});

// ---------------------------------------------------------------------------------------------
// [HIGH fix] bounded per-tick collection deadline + in-memory circuit breaker: a single hung
// lstat pass must not stall every future daemon tick.
// ---------------------------------------------------------------------------------------------

test("[HIGH fix] a hung collector is bounded by a per-tick deadline: computeCredentialAccessCandidates returns [] without waiting for it, and does not write the store", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  let writeCalled = false;
  const start = Date.now();
  const result = await computeCredentialAccessCandidates(paths, {
    credentialCollectionDeadlineMs: 25,
    credentialCollectionBreaker: createCredentialCollectionBreaker(), // isolated instance -- must not arm the module's shared default breaker
    collectCredentialAccessEvidence: () => new Promise(() => {}), // never resolves
    writeCredentialAccessBaselineStore: async () => { writeCalled = true; },
  });
  const elapsedMs = Date.now() - start;
  assert.deepEqual(result, []);
  assert.equal(writeCalled, false);
  assert(elapsedMs < 2000, `expected collection to be bounded by its deadline, took ${elapsedMs}ms`);
});

test("[HIGH fix] a collector that resolves well within its deadline is unaffected by the deadline machinery", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const result = await computeCredentialAccessCandidates(paths, {
    credentialCollectionDeadlineMs: 5000,
    credentialCollectionBreaker: createCredentialCollectionBreaker(),
    collectCredentialAccessEvidence: async () => ({ status: "ok", result: { entries: [okEntry({ mtime: 9000 })] } }),
  });
  assert.deepEqual(result, [], "cold-start seed against an empty store -- no baseline to diff against yet");
});

test("[HIGH fix] in-memory circuit breaker: after a collection timeout, the next K ticks skip collection entirely (no new hung call, no new libuv thread leaked), then collection resumes", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const breaker = createCredentialCollectionBreaker();
  let collectCalls = 0;
  const hungCollector = () => { collectCalls += 1; return new Promise(() => {}); };

  // Tick 1: the collector hangs -> the deadline trips -> the breaker arms for the next 2 ticks.
  const first = await computeCredentialAccessCandidates(paths, {
    credentialCollectionDeadlineMs: 25,
    credentialCollectionBreakerTicks: 2,
    credentialCollectionBreaker: breaker,
    collectCredentialAccessEvidence: hungCollector,
  });
  assert.deepEqual(first, []);
  assert.equal(collectCalls, 1);

  // Ticks 2 and 3: the breaker is armed -> the collector is never even invoked.
  const second = await computeCredentialAccessCandidates(paths, { credentialCollectionBreaker: breaker, collectCredentialAccessEvidence: hungCollector });
  assert.deepEqual(second, []);
  assert.equal(collectCalls, 1, "the breaker must skip collection entirely, not re-race a fresh hang");

  const third = await computeCredentialAccessCandidates(paths, { credentialCollectionBreaker: breaker, collectCredentialAccessEvidence: hungCollector });
  assert.deepEqual(third, []);
  assert.equal(collectCalls, 1);

  // Tick 4: the breaker has cleared -> collection resumes normally.
  const fourth = await computeCredentialAccessCandidates(paths, {
    credentialCollectionBreaker: breaker,
    collectCredentialAccessEvidence: async () => { collectCalls += 1; return { status: "ok", result: { entries: [okEntry()] } }; },
  });
  assert.equal(collectCalls, 2);
  assert.deepEqual(fourth, []);
});

// ---------------------------------------------------------------------------------------------
// O6 churn-rate ceiling
// ---------------------------------------------------------------------------------------------

test("[O6] churn-rate ceiling: no v1-shipped path is drawn from the excluded high-churn set (gcloud/kube/docker/npmrc) -- for the recommended unsigned default (high-churn paths excluded entirely), this is the whole policy", () => {
  const entries = resolveDefaultCredentialPaths({ homeDir: "/home/op" });
  const excludedSubstrings = ["gcloud", ".kube", ".docker", ".npmrc"];
  for (const entry of entries) {
    for (const excluded of excludedSubstrings) {
      assert.equal(entry.path.includes(excluded), false, `v1 path list must not include a high-churn path (${excluded})`);
    }
  }
});

// ---------------------------------------------------------------------------------------------
// P9 fail-closed namespace pin
// ---------------------------------------------------------------------------------------------

test("[P9] CREDENTIAL_ACCESS_RULE_ID classifies to unknown_namespace -- structurally LLM-ineligible (full deterministic-delivery pin lives in test/alert-intelligence.test.js)", async () => {
  const { classifyAlertNamespace } = await import("../src/alert-intelligence.js");
  const classified = classifyAlertNamespace(CREDENTIAL_ACCESS_RULE_ID);
  assert.equal(classified.namespace, undefined);
  assert.equal(classified.hardExcluded, false);
});
