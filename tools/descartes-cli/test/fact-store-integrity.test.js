import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendFactPoints, enforceFactRetention, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import {
  buildCompleteness,
  createFactIntegrityLedger,
  isValidFactIntegrityLedger,
  prepareFactIntegrityLedger,
  readFactIntegrityLedger,
  resolveFactIntegrityPaths,
} from "../src/fact-store-integrity.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-integrity-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const NOW = "2026-08-21T00:00:00.000Z";

async function readLedger(paths) {
  const result = await readFactIntegrityLedger(paths);
  assert.ok(result.ledger, result.reason);
  return result.ledger;
}

test("the ledger is atomic, private, deterministic under injected now, and contains no fact identity", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "secret-service", attributes: { secret: "secret-value" } }),
    "not-json",
    "",
  ].join("\n"));

  assert.equal((await readFactIntegrityLedger(paths)).reason, "missing");
  await enforceFactRetention(paths, { now: NOW });
  const { integrityFile, dir } = resolveFactIntegrityPaths(paths);
  const ledgerBytes = await fs.readFile(integrityFile, "utf8");
  const ledger = JSON.parse(ledgerBytes);
  assert.equal(ledger.last_corrupt_ts, NOW);
  assert.equal(ledger.first_degraded_ts, NOW);
  assert(!ledgerBytes.includes("secret-service"));
  assert(!ledgerBytes.includes("secret-value"));
  assert(!ledgerBytes.includes("identity"));
  assert(!ledgerBytes.includes("entity_key"));
  assert(!ledgerBytes.includes("attributes"));
  assert.equal((await fs.stat(integrityFile)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(dir)).mode & 0o777, 0o700);
  assert(!ledgerBytes.includes(".tmp"));
});

test("readFactPoints never creates or changes the integrity ledger", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", attributes: {} }) + "\n");
  const { integrityFile } = resolveFactIntegrityPaths(paths);

  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.schema_invalid_count, 1);
  assert.equal(read.completeness.status, "unknown");
  await assert.rejects(() => fs.stat(integrityFile), { code: "ENOENT" });
});

test("age eviction alone leaves completeness intact", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [
    { ts: "2026-08-20T00:00:00.000Z", fact_name: "service.presence", entity_key: "old", attributes: {} },
    { ts: NOW, fact_name: "service.presence", entity_key: "fresh", attributes: {} },
  ], { now: NOW, retentionMs: 12 * 60 * 60 * 1000 });

  await enforceFactRetention(paths, { now: NOW, retentionMs: 12 * 60 * 60 * 1000 });
  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.completeness.status, "intact");
  assert.equal(read.completeness.age_evicted_total, 1);
  assert.equal(read.completeness.first_degraded_ts, null);
});

test("buildCompleteness does not degrade an intact read for a future ledger loss timestamp", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const ledger = await readLedger(paths);
  const futureLoss = "2026-08-21T00:00:10.000Z";
  ledger.corrupt_dropped_total = 1;
  ledger.last_corrupt_ts = futureLoss;
  const live = {
    record_count: 0,
    bytes: 0,
    raw_bytes: Buffer.alloc(0),
    exists: true,
    newest_ts: null,
  };

  assert.equal(
    buildCompleteness(ledger, live, Number.NEGATIVE_INFINITY, {}, Date.parse(NOW)).status,
    "intact",
  );
  assert.equal(
    buildCompleteness(ledger, live, Number.NEGATIVE_INFINITY, {}, Date.parse(futureLoss)).status,
    "degraded",
  );
});

test("buildCompleteness treats a future continuity break (continuity_ok:false) with an 'ok' observation as a rollback artifact, not a permanent 'unknown'", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const ledger = await readLedger(paths);
  const futureBreak = "2026-08-21T00:00:10.000Z";
  // Simulate a clock-rollback artifact: the ledger recorded a continuity break at a future
  // wall-clock time and left continuity_ok:false, but the live store currently observes "ok"
  // (matches the ledger's last-rewrite fields).
  ledger.continuity.continuity_ok = false;
  ledger.last_continuity_break_ts = futureBreak;
  const live = {
    record_count: 0,
    bytes: 0,
    raw_bytes: Buffer.alloc(0),
    exists: true,
    newest_ts: null,
  };

  // now is BEFORE the future break: the stale continuity_ok:false must NOT latch this read to
  // "unknown" — the live store is fine right now, so the read is intact.
  assert.equal(
    buildCompleteness(ledger, live, Number.NEGATIVE_INFINITY, {}, Date.parse(NOW)).status,
    "intact",
  );
  // Control: when the break is at/within the current epoch (not future), continuity_ok:false is a
  // real break -> degraded (unchanged behavior).
  assert.equal(
    buildCompleteness(ledger, live, Number.NEGATIVE_INFINITY, {}, Date.parse(futureBreak)).status,
    "degraded",
  );
});

test("two consecutive retention passes do not double-count an unchanged output", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, [
    JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "kept", attributes: {} }),
    JSON.stringify({ ts: NOW, fact_name: "service.presence", attributes: {} }),
    "not-json",
    "",
  ].join("\n"));

  await enforceFactRetention(paths, { now: NOW });
  const first = await readLedger(paths);
  await enforceFactRetention(paths, { now: NOW });
  const second = await readLedger(paths);
  assert.equal(second.corrupt_dropped_total, first.corrupt_dropped_total);
  assert.equal(second.schema_invalid_dropped_total, first.schema_invalid_dropped_total);
  assert.equal(second.bytecap_evicted_total, first.bytecap_evicted_total);
  assert.equal(second.age_evicted_total, first.age_evicted_total);
});

test("out-of-band truncation is retained as a continuity break and degrades the next read", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "kept", attributes: {} }], { now: NOW });
  await fs.writeFile(storePaths.factsFile, "");
  await enforceFactRetention(paths, { now: "2026-08-21T00:00:01.000Z" });

  const read = await readFactPoints(paths, { now: "2026-08-21T00:00:01.000Z" });
  assert.equal(read.completeness.status, "degraded");
  assert.equal(read.completeness.continuity_ok, false);
  assert.equal(read.completeness.last_continuity_break_ts, "2026-08-21T00:00:01.000Z");
});

test("missing or corrupt ledgers degrade reads to unknown without throwing", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "kept", attributes: {} }], { now: NOW });
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  await fs.unlink(integrityFile);
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  await fs.writeFile(integrityFile, "{broken");
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("retention cannot amnesty an unreadable ledger into intact", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "kept", attributes: {} }], { now: NOW });
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  await fs.writeFile(integrityFile, "{broken");
  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("both crash windows inspect materially different artifacts, retry, correct counters, and recover", async () => {
  for (const window of ["before", "after"]) {
    const paths = await tempPaths();
    const storePaths = resolveFactStorePaths(paths);
    await fs.mkdir(storePaths.dir, { recursive: true });
    await fs.writeFile(storePaths.factsFile, [
      JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }),
      JSON.stringify({ ts: "2026-08-21T00:00:01.000Z", fact_name: "service.presence", entity_key: "two", attributes: {} }),
      JSON.stringify({ ts: "2026-08-21T00:00:02.000Z", fact_name: "service.presence", entity_key: "three", attributes: {} }),
      "not-json",
      "",
    ].join("\n"));
    const beforeFacts = await fs.readFile(storePaths.factsFile, "utf8");
    let ledgerAtHook;
    let factsAtHook;
    const hook = async () => {
      ledgerAtHook = JSON.parse(await fs.readFile(resolveFactIntegrityPaths(paths).integrityFile, "utf8"));
      factsAtHook = await fs.readFile(storePaths.factsFile, "utf8");
      assert.equal(ledgerAtHook.continuity.pending_pass !== null, true);
      if (window === "before") assert.equal(factsAtHook, beforeFacts);
    };
    const options = {
      now: "2026-08-21T00:00:03.000Z",
      retentionMs: 60_000,
      maxBytes: 120,
      ...(window === "before" ? { beforeFactsRename: async () => { await hook(); throw new Error("simulated crash"); } } : { afterFactsRename: async () => { await hook(); throw new Error("simulated crash"); } }),
    };
    await assert.rejects(() => enforceFactRetention(paths, options), /simulated crash/);
    assert.equal(ledgerAtHook.corrupt_dropped_total, 1);
    assert.equal(ledgerAtHook.bytecap_evicted_total, 3);
    if (window === "after") assert.notEqual(factsAtHook, beforeFacts);
    assert.equal((await readFactPoints(paths, { now: options.now })).completeness.status, "unknown");

    await enforceFactRetention(paths, { now: options.now, retentionMs: options.retentionMs, maxBytes: options.maxBytes });
    const afterRetry = await readLedger(paths);
    assert.equal(afterRetry.corrupt_dropped_total, 1);
    assert.equal(afterRetry.bytecap_evicted_total, 3);
    assert.equal(afterRetry.continuity.continuity_ok, true);
    await enforceFactRetention(paths, { now: "2026-08-21T00:01:00.000Z", retentionMs: options.retentionMs, maxBytes: options.maxBytes });
    const recovered = await readFactPoints(paths, { now: "2026-08-21T01:00:00.000Z", windowMs: 1 });
    assert.equal(recovered.completeness.status, "intact");
    assert.equal(recovered.completeness.continuity_ok, true);
    assert.equal(recovered.completeness.last_corrupt_ts, options.now);
  }
});

test("a changed or truncated live file cannot recover a pending pass in either crash window", async () => {
  for (const window of ["before", "after"]) {
    const paths = await tempPaths();
    const storePaths = resolveFactStorePaths(paths);
    await fs.mkdir(storePaths.dir, { recursive: true });
    await fs.writeFile(storePaths.factsFile, [
      JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }),
      JSON.stringify({ ts: "2026-08-21T00:00:01.000Z", fact_name: "service.presence", entity_key: "two", attributes: {} }),
      JSON.stringify({ ts: "2026-08-21T00:00:02.000Z", fact_name: "service.presence", entity_key: "three", attributes: {} }),
      "",
    ].join("\n"));

    const crash = async () => {
      const pending = JSON.parse(await fs.readFile(resolveFactIntegrityPaths(paths).integrityFile, "utf8"));
      assert.notEqual(pending.continuity.pending_pass.output_digest, null);
      await fs.writeFile(storePaths.factsFile, "");
      throw new Error("simulated crash");
    };
    const options = {
      now: "2026-08-21T00:00:03.000Z",
      retentionMs: 60_000,
      maxBytes: 500,
      ...(window === "before" ? { beforeFactsRename: crash } : { afterFactsRename: crash }),
    };
    await assert.rejects(() => enforceFactRetention(paths, options), /simulated crash/);
    await enforceFactRetention(paths, { now: options.now, retentionMs: options.retentionMs, maxBytes: options.maxBytes });

    const ledger = await readLedger(paths);
    assert.equal(ledger.continuity.continuity_ok, false);
    assert.equal((await readFactPoints(paths, { now: options.now })).completeness.status === "intact", false);
  }
});

test("ledger validation rejects incoherent committed output fields", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  const invalid = await readLedger(paths);
  invalid.continuity.last_rewrite_newest_ts = null;
  assert.equal(isValidFactIntegrityLedger(invalid), false);
  await fs.writeFile(integrityFile, JSON.stringify(invalid));
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("ledger validation rejects pending output that disagrees with continuity", async () => {
  const fields = [
    "output_record_count",
    "output_newest_ts",
    "output_bytes",
    "output_digest",
  ];
  for (const field of fields) {
    const paths = await tempPaths();
    await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
    await enforceFactRetention(paths, { now: NOW });
    const { integrityFile } = resolveFactIntegrityPaths(paths);
    const invalid = await readLedger(paths);
    const pending = invalid.continuity.pending_pass;
    assert.equal(pending, null);

    invalid.continuity.pending_pass = {
      pass_id: invalid.continuity.last_committed_pass_id + 1,
      corrupt_count: 0,
      schema_invalid_count: 0,
      bytecap_evicted_count: 0,
      age_evicted_count: 0,
      output_record_count: invalid.continuity.last_rewrite_record_count,
      output_newest_ts: invalid.continuity.last_rewrite_newest_ts,
      output_bytes: invalid.continuity.last_rewrite_bytes,
      output_digest: invalid.continuity.output_digest,
    };
    if (field === "output_record_count") invalid.continuity.pending_pass[field] += 1;
    if (field === "output_newest_ts") invalid.continuity.pending_pass[field] = "2026-08-21T00:00:01.000Z";
    if (field === "output_bytes") invalid.continuity.pending_pass[field] += 1;
    if (field === "output_digest") invalid.continuity.pending_pass[field] = "0".repeat(64);

    assert.equal(isValidFactIntegrityLedger(invalid), false, field);
    await fs.writeFile(integrityFile, JSON.stringify(invalid));
    assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  }
});

test("invalid ledgers bootstrap empty stores into unknown", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, "");
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  await fs.writeFile(integrityFile, "{broken");

  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("an unreadable ledger with facts is unknown", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }) + "\n");
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  await fs.mkdir(integrityFile);

  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("ledger validation rejects impossible totals and identity-bearing extra keys, which are never reserialized", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const { integrityFile } = resolveFactIntegrityPaths(paths);
  const valid = await readLedger(paths);

  const impossible = structuredClone(valid);
  impossible.corrupt_dropped_total = 1;
  impossible.last_corrupt_ts = null;
  await fs.writeFile(integrityFile, JSON.stringify(impossible));
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");

  const extra = structuredClone(valid);
  extra.entity_key = "must-not-persist";
  await fs.writeFile(integrityFile, JSON.stringify(extra));
  assert.equal(isValidFactIntegrityLedger(extra), false);
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");
  await enforceFactRetention(paths, { now: NOW });
  const rewritten = await fs.readFile(integrityFile, "utf8");
  assert.equal(rewritten.includes("entity_key"), false);
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("read compatibility is additive: old points and corrupt_count remain a strict subset", async () => {
  const paths = await tempPaths();
  const expectedPoints = [{
    ts: NOW,
    fact_name: "service.presence",
    entity_key: "one",
    attributes: {},
    source_envelope_id: undefined,
    source_tool: undefined,
    sensitivity: "operational",
  }];
  await appendFactPoints(paths, [expectedPoints[0]], { now: NOW });
  const read = await readFactPoints(paths, { now: NOW });
  assert.deepEqual(read.points, expectedPoints);
  assert.deepEqual({ points: read.points, corrupt_count: read.corrupt_count }, {
    points: expectedPoints,
    corrupt_count: 0,
  });
  assert.equal(read.schema_invalid_count, 0);
  assert.equal(typeof read.completeness.status, "string");
});

// daybreak-blue security sweep (2026-09-04), fact-store BLOCKER #2: a malformed/negative
// windowMs (or non-finite now) made sinceMs NaN, which drops every point from BOTH the point
// filter AND buildCompleteness's asOfMs boundary -- reproduced against a PROVEN-intact store
// (>=2 retention passes, continuity_ok:true), windowMs:"garbage"/-1000 returned points:[]
// status:intact over a real 1-record store. Reject non-finite/negative windowMs and a
// non-finite now up front so sinceMs can never be NaN.
test("readFactPoints throws on a malformed/negative windowMs or non-finite now instead of silently returning an empty-but-intact read over a proven store", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "kept", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW }); // second pass -> continuity_ok:true (proven intact)

  const proven = await readFactPoints(paths, { now: NOW });
  assert.equal(proven.completeness.status, "intact");
  assert.equal(proven.points.length, 1);

  await assert.rejects(() => readFactPoints(paths, { now: NOW, windowMs: "garbage" }), /windowMs/);
  await assert.rejects(() => readFactPoints(paths, { now: NOW, windowMs: NaN }), /windowMs/);
  await assert.rejects(() => readFactPoints(paths, { now: NOW, windowMs: -1000 }), /windowMs/);
  await assert.rejects(() => readFactPoints(paths, { now: "garbage" }), /now/);
});

// daybreak-blue security sweep, fact-store HIGH #3: a hand-crafted ledger with
// continuity.last_committed_pass_id = 2^53 passed isValidFactIntegrityLedger under
// Number.isInteger (2^53 IS an integer, just not a SAFE one). The next retention pass then
// computed passId = max(2^53, 0) + 1 === 2^53 (float rounds back to the same value), the
// resulting pending_pass.pass_id <= last_committed_pass_id made the ledger fail its own
// validity check, and writeFactIntegrityLedger threw "Invalid fact-store integrity ledger"
// on every single pass -- a permanent crash loop. Post-fix, Number.isSafeInteger rejects the
// ledger on load, so retention bootstraps a fresh one instead of crash-looping.
test("an unsafe-integer pass_id (2^53) in a hand-crafted ledger fails validation and bootstraps rather than crash-looping retention writes", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, "");
  const { integrityFile } = resolveFactIntegrityPaths(paths);

  const unsafeLedger = {
    generation: "test-generation",
    schema_version: 1,
    corrupt_dropped_total: 0,
    schema_invalid_dropped_total: 0,
    bytecap_evicted_total: 0,
    age_evicted_total: 0,
    last_corrupt_ts: null,
    last_schema_invalid_ts: null,
    last_bytecap_evict_ts: null,
    last_continuity_break_ts: null,
    first_degraded_ts: null,
    continuity: {
      record_count_hwm: 0,
      oldest_ts: null,
      last_rewrite_record_count: 0,
      last_rewrite_newest_ts: null,
      last_rewrite_bytes: 0,
      output_digest: null,
      last_committed_pass_id: 2 ** 53,
      continuity_ok: null,
      pending_pass: null,
    },
  };
  assert.equal(isValidFactIntegrityLedger(unsafeLedger), false);
  await fs.writeFile(integrityFile, JSON.stringify(unsafeLedger));
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");

  // Pre-fix, this threw "Invalid fact-store integrity ledger" every time. Post-fix, the
  // poisoned ledger fails to load, so retention bootstraps a fresh ledger and succeeds.
  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("isValidFactIntegrityLedger rejects an unsafe-integer pending_pass.pass_id", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const ledger = await readLedger(paths);
  ledger.continuity.pending_pass = {
    pass_id: 2 ** 53,
    corrupt_count: 0,
    schema_invalid_count: 0,
    bytecap_evicted_count: 0,
    age_evicted_count: 0,
    output_record_count: ledger.continuity.last_rewrite_record_count,
    output_newest_ts: ledger.continuity.last_rewrite_newest_ts,
    output_bytes: ledger.continuity.last_rewrite_bytes,
    output_digest: ledger.continuity.output_digest,
  };
  assert.equal(isValidFactIntegrityLedger(ledger), false);
});

// daybreak-blue re-gate (2026-09-04), fact-store BLOCKER: bootstrapping straight over an
// INVALID (tampered/corrupt) ledger let the freshly-bootstrapped ledger's own first
// observation self-bless a possibly-shortened store. Repro: a proven-intact 1-record store is
// truncated out-of-band, then the ledger is tampered into INVALID (not merely missing/first
// run). Pass 1 (bootstrap over "invalid") correctly reads unknown, but pre-fix, pass 2 found
// the freshly-bootstrapped ledger's own "last rewrite" fields self-consistent with the still-
// empty live store and flipped continuity_ok:true with NO recorded loss -- Descartes re-signed
// its own shortened state as intact. Post-fix, the invalid-bootstrap pass stamps a now-loss
// marker so pass 2 degrades instead.
test("an invalid-ledger bootstrap over an out-of-band-truncated store degrades rather than re-blessing itself intact", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  const { integrityFile } = resolveFactIntegrityPaths(paths);

  // Build a proven-intact 1-record store (two retention passes).
  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const proven = await readLedger(paths);
  assert.equal(proven.continuity.continuity_ok, true);

  // Out-of-band truncation, then tamper the ledger into INVALID (last_committed_pass_id at an
  // unsafe integer -- fails isValidFactIntegrityLedger's Number.isSafeInteger check).
  await fs.writeFile(storePaths.factsFile, "");
  const tampered = structuredClone(proven);
  tampered.continuity.last_committed_pass_id = 2 ** 53;
  await fs.writeFile(integrityFile, JSON.stringify(tampered));
  assert.equal((await readFactIntegrityLedger(paths)).reason, "invalid");

  const pass1Now = "2026-08-21T00:00:01.000Z";
  await enforceFactRetention(paths, { now: pass1Now });
  assert.equal((await readFactPoints(paths, { now: pass1Now })).completeness.status, "unknown");

  const pass2Now = "2026-08-21T00:00:02.000Z";
  await enforceFactRetention(paths, { now: pass2Now });
  const afterPass2 = await readFactPoints(paths, { now: pass2Now });
  assert.equal(afterPass2.points.length, 0);
  assert.notEqual(afterPass2.completeness.status, "intact");
  assert.equal(afterPass2.completeness.status, "degraded");
});

// Control for the fix above: a genuinely-missing ledger (first-ever run, ledgerReason
// "missing") has nothing to distrust and must still reach intact after two clean passes -- the
// invalid-bootstrap loss marker must not fire for a legitimate absent-ledger bootstrap.
test("a legitimate brand-new store (missing ledger, not invalid) still reaches intact after two clean passes", async () => {
  const paths = await tempPaths();
  assert.equal((await readFactIntegrityLedger(paths)).reason, "missing");

  await appendFactPoints(paths, [{ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }], { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.completeness.status, "intact");
  assert.equal(read.completeness.last_continuity_break_ts, null);
});

// daybreak-blue re-gate (2026-09-04), fact-store HIGH #2: a total at Number.MAX_SAFE_INTEGER is
// itself a valid, safe integer, but incrementing it by a real (>0) delta overflows into an
// unsafe integer, which then fails writeFactIntegrityLedger's own validity gate and throws
// "Invalid fact-store integrity ledger" -- and because that throw happens before the facts
// rewrite is renamed into place, the offending delta source (a corrupt line) stays on disk, so
// the exact same overflow recurs on every future pass: a permanent crash loop.
test("a total at Number.MAX_SAFE_INTEGER saturates instead of crash-looping on every subsequent write", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, "not-json\n"); // a persistently-corrupt line
  const { integrityFile } = resolveFactIntegrityPaths(paths);

  const ledger = createFactIntegrityLedger();
  ledger.corrupt_dropped_total = Number.MAX_SAFE_INTEGER;
  ledger.last_corrupt_ts = NOW;
  ledger.first_degraded_ts = NOW;
  assert.equal(isValidFactIntegrityLedger(ledger), true);
  await fs.writeFile(integrityFile, JSON.stringify(ledger));

  // Pre-fix, this threw "Invalid fact-store integrity ledger" on every pass (crash loop).
  // Post-fix, the total saturates at MAX_SAFE_INTEGER and the pass succeeds.
  await enforceFactRetention(paths, { now: NOW });
  const afterFirst = await readLedger(paths);
  assert.equal(afterFirst.corrupt_dropped_total, Number.MAX_SAFE_INTEGER);
  assert.equal(afterFirst.last_corrupt_ts, NOW);

  // A second pass must also succeed (proves it's not a one-shot fluke).
  const secondNow = "2026-08-21T00:00:01.000Z";
  await enforceFactRetention(paths, { now: secondNow });
  const afterSecond = await readLedger(paths);
  assert.equal(afterSecond.corrupt_dropped_total, Number.MAX_SAFE_INTEGER);
});

// daybreak-blue re-gate (2026-09-04), fact-store HIGH (residual): a ledger whose
// continuity.last_committed_pass_id sits exactly at Number.MAX_SAFE_INTEGER is itself a VALID
// ledger -- Number.isSafeInteger(Number.MAX_SAFE_INTEGER) is true, so isValidFactIntegrityLedger
// accepts it -- but the next passId this function computes (+1) exceeds MAX_SAFE_INTEGER.
// Pre-fix, that was rejected by THROWING here, and because the throw happens before the facts
// rewrite is renamed into place, the on-disk ledger never advances past the poisoned
// last_committed_pass_id: the same throw recurred on every subsequent pass, a permanent
// fail-STUCK crash loop. Post-fix, pass_id exhaustion is routed through the same fail-closed
// bootstrap path an invalid/unreadable ledger already takes: a fresh ledger, continuity-break
// marker stamped, passId resets to 1 -- no throw, ever.
test("prepareFactIntegrityLedger routes passId exhaustion to a fail-closed bootstrap instead of throwing", () => {
  const ledger = createFactIntegrityLedger();
  ledger.continuity.last_committed_pass_id = Number.MAX_SAFE_INTEGER;
  assert.equal(isValidFactIntegrityLedger(ledger), true);

  const prepared = prepareFactIntegrityLedger({
    ledger,
    ledgerReason: null,
    nowIso: NOW,
    live: { record_count: 0, bytes: 0, raw_bytes: Buffer.alloc(0), exists: true, newest_ts: null },
    outputRecords: [],
    outputBytes: 0,
    outputDigest: null,
    counts: { corrupt_count: 0, schema_invalid_count: 0, bytecap_evicted_count: 0, age_evicted_count: 0 },
  });

  assert.equal(prepared.bootstrap, true);
  assert.equal(prepared.passId, 1);
  assert.equal(prepared.ledger.continuity.last_committed_pass_id, 0);
  assert.equal(prepared.ledger.last_continuity_break_ts, NOW);
});

// RED (pre-fix): reproduces the crash loop end-to-end through enforceFactRetention over a real
// store with a persistent corrupt line. Pre-fix, the first call already threw "fact-store
// integrity ledger pass_id would exceed Number.MAX_SAFE_INTEGER" and every subsequent call threw
// the same way forever. Post-fix, both passes succeed and fail closed (never "intact").
test("a pass_id-exhausted ledger (last_committed_pass_id at Number.MAX_SAFE_INTEGER) fails closed instead of crash-looping retention writes", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, "not-json\n"); // a persistently-corrupt line
  const { integrityFile } = resolveFactIntegrityPaths(paths);

  const ledger = createFactIntegrityLedger();
  ledger.continuity.last_committed_pass_id = Number.MAX_SAFE_INTEGER;
  assert.equal(isValidFactIntegrityLedger(ledger), true);
  await fs.writeFile(integrityFile, JSON.stringify(ledger));
  assert.equal((await readFactIntegrityLedger(paths)).reason, null);

  await enforceFactRetention(paths, { now: NOW });
  assert.notEqual((await readFactPoints(paths, { now: NOW })).completeness.status, "intact");

  // A second pass must also succeed (proves it's not a one-shot fluke, i.e. no crash loop) and
  // must still not read intact -- fail-closed, not a silent recovery to trusted.
  const secondNow = "2026-08-21T00:00:01.000Z";
  await enforceFactRetention(paths, { now: secondNow });
  assert.notEqual((await readFactPoints(paths, { now: secondNow })).completeness.status, "intact");
});
