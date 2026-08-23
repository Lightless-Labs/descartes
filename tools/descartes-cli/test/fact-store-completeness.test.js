import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { enforceFactRetention, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { factHistoryTrustworthy } from "../src/fact-store-completeness.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-completeness-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const NOW = "2026-08-21T00:00:00.000Z";

const LOSS_CHANNELS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

function cleanReadResult(overrides = {}) {
  const { completeness: completenessOverrides, ...readOverrides } = overrides;
  return {
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness: {
      status: "intact",
      ...Object.fromEntries(LOSS_CHANNELS.map((channel) => [channel, null])),
      ...completenessOverrides,
    },
    ...readOverrides,
  };
}

test("factHistoryTrustworthy applies the fixed precedence and fails closed across loss channels", () => {
  const anchorTs = "2026-08-21T00:00:10.000Z";
  const after = "2026-08-21T00:00:11.000Z";
  const before = "2026-08-21T00:00:09.000Z";
  const cases = [
    ["clean history", cleanReadResult(), {}, { trust: true, reason: "ok" }],
    ["corrupt facts take precedence", cleanReadResult({ corrupt_count: 1, schema_invalid_count: 2 }), { anchorTs }, { trust: false, reason: "corrupt_facts_this_tick" }],
    ["schema-invalid facts are second", cleanReadResult({ schema_invalid_count: 1 }), { anchorTs }, { trust: false, reason: "schema_invalid_this_tick" }],
    ["unknown history is third", cleanReadResult({ completeness: { status: "unknown" } }), { anchorTs }, { trust: false, reason: "history_unknown" }],
    ...LOSS_CHANNELS.map((channel) => [
      `${channel} after anchor degrades history`,
      cleanReadResult({ completeness: { [channel]: after } }),
      { anchorTs },
      { trust: false, reason: "history_degraded" },
    ]),
    ...LOSS_CHANNELS.map((channel) => [
      `${channel} at or before anchor is already accounted for`,
      cleanReadResult({ completeness: { status: "degraded", [channel]: before } }),
      { anchorTs },
      { trust: false, reason: "history_degraded" },
    ]),
    ...LOSS_CHANNELS.map((channel) => [
      `${channel} is a lockout without an anchor`,
      cleanReadResult({ completeness: { [channel]: before } }),
      { anchorTs: undefined },
      { trust: false, reason: "history_degraded" },
    ]),
    ["stateless reads use their already-scoped intact status", cleanReadResult({ completeness: { last_corrupt_ts: before } }), {}, { trust: true, reason: "ok" }],
    ["stateless degraded status is not trusted", cleanReadResult({ completeness: { status: "degraded", last_corrupt_ts: before } }), {}, { trust: false, reason: "history_degraded" }],
  ];

  for (const [name, readResult, opts, expected] of cases) {
    assert.deepEqual(factHistoryTrustworthy(readResult, opts), expected, name);
  }
});

test("factHistoryTrustworthy never trusts a legacy or malformed read shape", () => {
  const legacy = { corrupt_count: 0, schema_invalid_count: 0 };
  assert.doesNotThrow(() => factHistoryTrustworthy(legacy));
  assert.deepEqual(factHistoryTrustworthy(legacy), { trust: false, reason: "history_unknown" });
  assert.deepEqual(factHistoryTrustworthy(null), { trust: false, reason: "history_unknown" });
  assert.deepEqual(factHistoryTrustworthy({
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness: { status: "not-a-status" },
  }), { trust: false, reason: "history_unknown" });
  assert.deepEqual(factHistoryTrustworthy({
    corrupt_count: 0,
    schema_invalid_count: 0,
    completeness: { status: "degraded" },
  }, { anchorTs: NOW }), { trust: false, reason: "history_degraded" });
});

test("factHistoryTrustworthy permits recovery after a transient loss and blocks sustained loss", () => {
  const lossTs = "2026-08-21T00:00:01.000Z";
  const recovered = cleanReadResult({
    completeness: { status: "intact", last_bytecap_evict_ts: lossTs },
  });
  assert.deepEqual(factHistoryTrustworthy(recovered, { anchorTs: "2026-08-21T00:00:02.000Z" }), { trust: true, reason: "ok" });

  const sustained = cleanReadResult({
    completeness: { status: "degraded", last_bytecap_evict_ts: "2026-08-21T00:00:03.000Z" },
  });
  assert.deepEqual(factHistoryTrustworthy(sustained, { anchorTs: "2026-08-21T00:00:02.000Z" }), { trust: false, reason: "history_degraded" });
});

test("factHistoryTrustworthy ignores future loss timestamps for the current rollback window but still blocks an in-window loss", () => {
  const anchorMs = Date.parse(NOW);
  const futureLoss = new Date(anchorMs + 100_000).toISOString();
  const currentLoss = new Date(anchorMs + 1_000).toISOString();
  const opts = { anchorTs: NOW, nowMs: anchorMs + 10_000 };

  assert.deepEqual(
    factHistoryTrustworthy(cleanReadResult({ completeness: { last_corrupt_ts: futureLoss } }), opts),
    { trust: true, reason: "ok" },
  );
  assert.deepEqual(
    factHistoryTrustworthy(cleanReadResult({ completeness: { last_corrupt_ts: currentLoss } }), opts),
    { trust: false, reason: "history_degraded" },
  );
  assert.deepEqual(
    factHistoryTrustworthy(cleanReadResult({ completeness: { last_corrupt_ts: "not-a-timestamp" } }), opts),
    { trust: false, reason: "history_degraded" },
    "malformed loss timestamps remain fail-closed",
  );
});

test("retention records corrupt-line loss durably and the next read is degraded", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, [
    JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    "not-json",
    "",
  ].join("\n"));

  const retention = await enforceFactRetention(paths, { now: NOW });
  assert.equal(retention.corrupt_dropped_count, 1);
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  await enforceFactRetention(paths, { now: NOW });
  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.corrupt_count, 0);
  assert.equal(read.completeness.status, "degraded");
  assert.equal(read.completeness.corrupt_dropped_total, 1);
  assert.equal(read.completeness.last_corrupt_ts, NOW);
});

test("retention classifies parseable schema-invalid records and read reports this-read schema loss", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", attributes: {} }) + "\n");

  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  await enforceFactRetention(paths, { now: NOW });
  const read = await readFactPoints(paths, { now: NOW });
  assert.deepEqual(read.points, []);
  assert.equal(read.corrupt_count, 0);
  assert.equal(read.schema_invalid_count, 0);
  assert.equal(read.completeness.status, "degraded");
  assert.equal(read.completeness.schema_invalid_dropped_total, 1);
  assert.equal(read.completeness.last_schema_invalid_ts, NOW);
});

test("retention classifies byte-cap eviction separately and degrades completeness", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, [
    JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "one", attributes: {} }),
    JSON.stringify({ ts: "2026-08-21T00:00:01.000Z", fact_name: "service.presence", entity_key: "two", attributes: {} }),
    "",
  ].join("\n"));

  const retention = await enforceFactRetention(paths, { now: NOW, maxBytes: 120 });
  assert(retention.dropped_count >= 1);
  assert.equal(retention.bytecap_evicted_count, 2);
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  await enforceFactRetention(paths, { now: NOW });
  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.completeness.status, "degraded");
  assert.equal(read.completeness.bytecap_evicted_total, 2);
  assert.equal(read.completeness.last_bytecap_evict_ts, NOW);
});

test("retention classifies an invalid timestamp as schema-invalid, not age-evicted", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, JSON.stringify({ ts: "not-a-timestamp", fact_name: "service.presence", entity_key: "bad", attributes: {} }) + "\n");

  const retention = await enforceFactRetention(paths, { now: NOW });
  assert.equal(retention.dropped_count, 1);
  assert.equal(retention.corrupt_dropped_count, 0);
  assert.equal(retention.schema_invalid_dropped_count, 1);
  assert.equal(retention.age_evicted_count, 0);
  const read = await readFactPoints(paths, { now: NOW });
  assert.equal(read.completeness.schema_invalid_dropped_total, 1);
});

test("missing-ledger bootstrap stays unknown until a later clean retention pass", async () => {
  const paths = await tempPaths();
  const { dir, factsFile } = resolveFactStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }) + "\n");

  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "intact");
});

test("this-read corruption cannot be reported as intact against a clean committed ledger", async () => {
  const cases = [
    ["corrupt", "not-json", "corrupt_count"],
    ["schema-invalid", JSON.stringify({ ts: NOW, fact_name: "service.presence", attributes: {} }), "schema_invalid_count"],
  ];
  for (const [, line, field] of cases) {
    const paths = await tempPaths();
    await fs.mkdir(resolveFactStorePaths(paths).dir, { recursive: true });
    await fs.writeFile(resolveFactStorePaths(paths).factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }) + "\n");
    await enforceFactRetention(paths, { now: NOW });
    await enforceFactRetention(paths, { now: NOW });
    await fs.appendFile(resolveFactStorePaths(paths).factsFile, `${line}\n`);
    const read = await readFactPoints(paths, { now: NOW });
    assert.equal(read[field], 1);
    assert.notEqual(read.completeness.status, "intact");
  }
});

test("same-count same-newest byte replacement breaks continuity", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }) + "\n");
  await enforceFactRetention(paths, { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  await fs.writeFile(storePaths.factsFile, JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: { changed: "bytes" } }) + "\n");
  const read = await readFactPoints(paths, { now: NOW });
  assert.notEqual(read.completeness.status, "intact");
  assert.equal(read.completeness.continuity_ok, null);
});

test("same-count same-size content replacement is not intact", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  const committed = JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }) + "\n";
  const replacement = JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "mysql", attributes: {} }) + "\n";
  assert.equal(Buffer.byteLength(replacement), Buffer.byteLength(committed));
  await fs.writeFile(storePaths.factsFile, committed);
  await enforceFactRetention(paths, { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  await fs.writeFile(storePaths.factsFile, replacement);

  const read = await readFactPoints(paths, { now: NOW });
  assert.notEqual(read.completeness.status, "intact");
});

test("replacement of the committed prefix plus an appended record is not intact", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  const committed = JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "nginx", attributes: {} }) + "\n";
  const replacement = JSON.stringify({ ts: NOW, fact_name: "service.presence", entity_key: "mysql", attributes: {} }) + "\n";
  const appended = JSON.stringify({ ts: "2026-08-21T00:00:01.000Z", fact_name: "service.presence", entity_key: "redis", attributes: {} }) + "\n";
  await fs.writeFile(storePaths.factsFile, committed);
  await enforceFactRetention(paths, { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  await fs.writeFile(storePaths.factsFile, replacement + appended);

  const read = await readFactPoints(paths, { now: NOW });
  assert.notEqual(read.completeness.status, "intact");
});

test("missing and null stored timestamps are schema-invalid and never become ledger timestamps", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ fact_name: "service.presence", entity_key: "missing", attributes: {} }),
    JSON.stringify({ ts: null, fact_name: "service.presence", entity_key: "null", attributes: {} }),
    "",
  ].join("\n"));
  const retention = await enforceFactRetention(paths, { now: NOW });
  assert.equal(retention.schema_invalid_dropped_count, 2);
  const ledgerBytes = await fs.readFile(path.join(storePaths.dir, "integrity.json"), "utf8");
  const ledger = JSON.parse(ledgerBytes);
  assert.equal(ledger.continuity.oldest_ts, null);
  assert.equal(ledger.continuity.last_rewrite_newest_ts, null);
  assert.equal(ledger.last_schema_invalid_ts, NOW);
});

test("a missing committed empty facts file is unknown, while a present empty file is intact", async () => {
  const paths = await tempPaths();
  const { factsFile } = resolveFactStorePaths(paths);

  await enforceFactRetention(paths, { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "intact");

  await fs.unlink(factsFile);
  assert.equal((await readFactPoints(paths, { now: NOW })).completeness.status, "unknown");
});

test("a truncated history suppresses a novelty-style absence claim", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: NOW, fact_name: "peer.seen", entity_key: "known-peer", attributes: {} }),
    JSON.stringify({ ts: "2026-08-21T00:00:01.000Z", fact_name: "peer.seen", entity_key: "other-peer", attributes: {} }),
    "",
  ].join("\n"));
  await enforceFactRetention(paths, { now: NOW });
  await enforceFactRetention(paths, { now: NOW });
  await fs.writeFile(storePaths.factsFile, JSON.stringify({ ts: NOW, fact_name: "peer.seen", entity_key: "known-peer", attributes: {} }) + "\n");
  const read = await readFactPoints(paths, { now: NOW });
  const noveltyGate = (candidate) => read.completeness.status === "intact" && !read.points.some((point) => point.entity_key === candidate);
  assert.equal(noveltyGate("missing-peer"), false);
});
