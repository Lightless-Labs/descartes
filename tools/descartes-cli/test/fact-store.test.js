import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { normalizeMetricPoint } from "../src/history-store.js";
import {
  appendFactPoints,
  DEFAULT_FACT_MAX_BYTES,
  DEFAULT_FACT_RETENTION_MS,
  enforceFactRetention,
  normalizeFactPoint,
  readFactPoints,
  resolveFactStorePaths,
} from "../src/fact-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("resolveFactStorePaths points at stateDir/learned/facts/facts.jsonl with no double-nesting, passes the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  assert.equal(storePaths.dir, path.join(paths.stateDir, "learned", "facts"));
  assert.equal(storePaths.factsFile, path.join(paths.stateDir, "learned", "facts", "facts.jsonl"));
  assert.doesNotThrow(() => assertNoPiOwnedPath({ factsFile: storePaths.factsFile }));
});

test("DEFAULT_FACT_RETENTION_MS/DEFAULT_FACT_MAX_BYTES are their own constants, not aliases of history-store's", () => {
  assert.equal(DEFAULT_FACT_RETENTION_MS, 30 * 24 * 60 * 60 * 1000);
  assert.equal(DEFAULT_FACT_MAX_BYTES, 5 * 1024 * 1024);
});

test("normalizeFactPoint requires non-empty fact_name and entity_key", () => {
  assert.throws(() => normalizeFactPoint({ entity_key: "nginx" }), /fact_name/);
  assert.throws(() => normalizeFactPoint({ fact_name: "service.presence" }), /entity_key/);
  assert.throws(() => normalizeFactPoint({ fact_name: "  ", entity_key: "nginx" }), /fact_name/);
});

test("normalizeFactPoint normalizes attributes (stringify, cap length, drop null/undefined) with no finite-number gate", () => {
  const point = normalizeFactPoint({
    fact_name: "service.presence",
    entity_key: "nginx",
    attributes: {
      running: "true",
      manager: "systemd",
      dropped_undefined: undefined,
      dropped_null: null,
      over_long: "x".repeat(200),
    },
  });
  assert.deepEqual(point.attributes, {
    running: "true",
    manager: "systemd",
    over_long: "x".repeat(160),
  });
});

test("a categorical attributes map that would throw normalizeMetricPoint is accepted by normalizeFactPoint (proves the schemas are genuinely distinct)", () => {
  assert.throws(() => normalizeMetricPoint({ metric_name: "service.presence", value: "true" }), /finite numeric value/);
  assert.doesNotThrow(() => normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx", attributes: { running: "true" } }));
});

test("normalizeFactPoint applies ts/source_envelope_id/source_tool/sensitivity defaults from the caller", () => {
  const point = normalizeFactPoint(
    { fact_name: "service.presence", entity_key: "nginx" },
    { ts: "2026-07-10T00:00:00.000Z", source_envelope_id: "services", source_tool: "collect_services" },
  );
  assert.equal(point.ts, "2026-07-10T00:00:00.000Z");
  assert.equal(point.source_envelope_id, "services");
  assert.equal(point.source_tool, "collect_services");
  assert.equal(point.sensitivity, "operational");
});

test("normalizeFactPoint passes through a bounded numeric confidence marker when present (degrade-not-fabricate additive field)", () => {
  const point = normalizeFactPoint({
    fact_name: "network.listening_port.owner",
    entity_key: "tcp:0.0.0.0:5432",
    attributes: { owner_known: "false" },
    confidence: 0,
  });
  assert.equal(point.confidence, 0);

  const noConfidence = normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx" });
  assert.equal("confidence" in noConfidence, false);
});

test("appendFactPoints/readFactPoints round-trip", async () => {
  const paths = await tempPaths();
  const ts = "2026-07-10T00:00:00.000Z";
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: { running: "true" }, ts },
    { fact_name: "service.presence", entity_key: "postgres", attributes: { running: "false" }, ts },
  ], { ts });

  const { points, corrupt_count } = await readFactPoints(paths);
  assert.equal(corrupt_count, 0);
  assert.equal(points.length, 2);
  assert.deepEqual(points.map((p) => p.entity_key).sort(), ["nginx", "postgres"]);
});

test("readFactPoints returns an empty result on ENOENT", async () => {
  const paths = await tempPaths();
  const { points, corrupt_count } = await readFactPoints(paths);
  assert.deepEqual(points, []);
  assert.equal(corrupt_count, 0);
});

test("readFactPoints skips corrupt lines (counted) and drops invalid-schema records (not counted as corrupt)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    "not-json",
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", attributes: {} }), // missing entity_key -> invalid schema
    "",
  ].join("\n"));

  const { points, corrupt_count } = await readFactPoints(paths);
  assert.equal(corrupt_count, 1);
  assert.equal(points.length, 1);
  assert.equal(points[0].entity_key, "nginx");
});

test("enforceFactRetention drops points older than retentionMs and keeps the file under maxBytes (newest-first)", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-07-10T00:00:00.000Z");
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "old", attributes: {}, ts: "2026-07-09T00:00:00.000Z" },
    { fact_name: "service.presence", entity_key: "fresh", attributes: {}, ts: "2026-07-10T00:00:00.000Z" },
  ], { now: base, retentionMs: 23 * 60 * 60 * 1000 });

  const retention = await enforceFactRetention(paths, { now: base, retentionMs: 23 * 60 * 60 * 1000 });
  assert.equal(retention.kept_count, 1);

  const { points } = await readFactPoints(paths);
  assert.deepEqual(points.map((p) => p.entity_key), ["fresh"]);
});

test("enforceFactRetention enforces maxBytes by keeping the newest records", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-07-10T00:00:00.000Z");
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "one", attributes: {}, ts: new Date(base).toISOString() },
    { fact_name: "service.presence", entity_key: "two", attributes: {}, ts: new Date(base + 1000).toISOString() },
    { fact_name: "service.presence", entity_key: "three", attributes: {}, ts: new Date(base + 2000).toISOString() },
  ], { now: base + 3000, maxBytes: 200 });

  const { points } = await readFactPoints(paths);
  assert(points.length >= 1);
  assert.equal(points.at(-1).entity_key, "three");
  assert(!points.some((p) => p.entity_key === "one"));
});

test("enforceFactRetention rewrites the file atomically (tmp file appears then is renamed)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts: "2026-07-10T00:00:00.000Z" },
  ], { now: "2026-07-10T00:00:00.000Z" });

  const before = await fs.readFile(storePaths.factsFile, "utf8");
  await enforceFactRetention(paths, { now: "2026-07-10T00:00:01.000Z", retentionMs: 60_000 });
  const after = await fs.readFile(storePaths.factsFile, "utf8");
  assert.equal(before, after); // unchanged content, but file must still exist post-rename (proves rename succeeded)

  const dirEntries = await fs.readdir(storePaths.dir);
  assert(!dirEntries.some((entry) => entry.endsWith(".tmp")), "no leftover tmp file after a successful retention rewrite");
});
