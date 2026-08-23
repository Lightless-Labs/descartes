import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendFactPoints, enforceFactRetention, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { buildCompleteness, isValidFactIntegrityLedger, readFactIntegrityLedger, resolveFactIntegrityPaths } from "../src/fact-store-integrity.js";
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
