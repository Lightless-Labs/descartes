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
  MAX_FACT_ATTRIBUTE_COUNT,
  MAX_FACT_ATTRIBUTE_KEY_LENGTH,
  MAX_FACT_ENTITY_KEY_LENGTH,
  MAX_FACT_NAME_LENGTH,
  MAX_FACT_SENSITIVITY_LENGTH,
  MAX_FACT_SOURCE_LENGTH,
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
  const now = "2026-07-10T00:01:00.000Z"; // pin retention to the fixture, not wall-clock (avoids a 30-day time-bomb)
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: { running: "true" }, ts },
    { fact_name: "service.presence", entity_key: "postgres", attributes: { running: "false" }, ts },
  ], { ts, now });

  const { points, corrupt_count } = await readFactPoints(paths, { now });
  assert.equal(corrupt_count, 0);
  assert.equal(points.length, 2);
  assert.deepEqual(points.map((p) => p.entity_key).sort(), ["nginx", "postgres"]);
});

test("appendFactPoints uses injected now as the explicit timestamp default", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ fact_name: "service.presence", entity_key: "nginx", attributes: {} }], { now: "2026-07-10T00:00:00.000Z" });
  const { points } = await readFactPoints(paths, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(points[0].ts, "2026-07-10T00:00:00.000Z");
});

test("readFactPoints returns an empty result on ENOENT", async () => {
  const paths = await tempPaths();
  const { points, corrupt_count } = await readFactPoints(paths);
  assert.deepEqual(points, []);
  assert.equal(corrupt_count, 0);
});

test("readFactPoints skips corrupt lines and counts parseable schema-invalid records separately", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    "not-json",
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", attributes: {} }), // missing entity_key -> invalid schema
    "",
  ].join("\n"));

  const { points, corrupt_count, schema_invalid_count } = await readFactPoints(paths);
  assert.equal(corrupt_count, 1);
  assert.equal(schema_invalid_count, 1);
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

// daybreak-blue security sweep (2026-09-04), fact-store BLOCKER #1: a malformed retentionMs
// (e.g. "garbage" -> NaN cutoff) made every valid record satisfy neither the age-evicted nor
// the kept/candidate branch, so it was silently dropped -- the rewrite committed as an empty,
// status:intact store. Reject non-finite/negative retentionMs/maxBytes up front instead of
// letting them flow into arithmetic that can silently erase history. Zero is a legitimate,
// fully-accounted degenerate case (evict-everything/keep-nothing -- see
// evidence-freeze.test.js's deliberate 0-retention/0-byte isolation sweep against this same
// function), so it stays valid; only non-finite/negative values are rejected.
test("enforceFactRetention throws on a non-finite/negative retentionMs or maxBytes instead of silently erasing history", async () => {
  const paths = await tempPaths();
  const ts = "2026-07-10T00:00:00.000Z";
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts },
  ], { ts, now: ts });

  await assert.rejects(() => enforceFactRetention(paths, { now: ts, retentionMs: "garbage" }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { now: ts, retentionMs: NaN }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { now: ts, retentionMs: -1 }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { now: ts, maxBytes: NaN }), /maxBytes/);
  await assert.rejects(() => enforceFactRetention(paths, { now: ts, maxBytes: -1 }), /maxBytes/);

  // None of the rejected calls may have touched the store -- no silent erasure.
  const { points } = await readFactPoints(paths, { now: ts });
  assert.equal(points.length, 1);

  // Zero remains valid (a deliberate evict-everything/keep-nothing sweep), fully accounted.
  const retention = await enforceFactRetention(paths, { now: ts, retentionMs: 0, maxBytes: 0 });
  assert.equal(retention.kept_count, 0);
});

// daybreak-blue security sweep, fact-store HIGH #4: normalizeTimestamp's error reflected the
// raw supplied ts value verbatim -- the only reflecting throw in the file. Errors/logs must
// never echo raw (potentially sensitive) field values.
test("normalizeFactPoint's invalid-timestamp error does not reflect the raw supplied value", () => {
  const sensitive = "/Users/alice/.ssh/id_ed25519";
  assert.throws(
    () => normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx", ts: sensitive }),
    (error) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message.includes(sensitive), false, "error message must not include the raw invalid timestamp value");
      return true;
    },
  );
});

// daybreak-blue security sweep, fact-store HIGH #5 (cheap-caps portion): attribute-key count,
// key length, and fact_name/entity_key/source_* lengths were unbounded -- a fact point with
// hundreds of thousands of keys was fully built before any cap applied. Over-cap input must be
// REJECTED (observable batch abort / schema_invalid), never silently truncated.
test("normalizeFactPoint rejects an attributes object with too many keys instead of silently building it", () => {
  const attributes = Object.fromEntries(Array.from({ length: MAX_FACT_ATTRIBUTE_COUNT + 1 }, (_, i) => [`key${i}`, "v"]));
  assert.throws(
    () => normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx", attributes }),
    /attribute/i,
  );
});

test("normalizeFactPoint rejects an over-long attribute key instead of silently accepting it", () => {
  assert.throws(
    () => normalizeFactPoint({
      fact_name: "service.presence",
      entity_key: "nginx",
      attributes: { [`k${"x".repeat(MAX_FACT_ATTRIBUTE_KEY_LENGTH)}`]: "v" },
    }),
    /attribute key/i,
  );
});

test("normalizeFactPoint rejects over-long fact_name/entity_key/source_envelope_id/source_tool instead of silently accepting them", () => {
  assert.throws(() => normalizeFactPoint({ fact_name: "x".repeat(MAX_FACT_NAME_LENGTH + 1), entity_key: "nginx" }), /fact_name/);
  assert.throws(() => normalizeFactPoint({ fact_name: "service.presence", entity_key: "x".repeat(MAX_FACT_ENTITY_KEY_LENGTH + 1) }), /entity_key/);
  assert.throws(
    () => normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx", source_envelope_id: "x".repeat(MAX_FACT_SOURCE_LENGTH + 1) }),
    /source_envelope_id/,
  );
  assert.throws(
    () => normalizeFactPoint({ fact_name: "service.presence", entity_key: "nginx", source_tool: "x".repeat(MAX_FACT_SOURCE_LENGTH + 1) }),
    /source_tool/,
  );
});

// daybreak-blue re-gate (2026-09-04), fact-store HIGH #3: fact_name/entity_key were trimmed
// BEFORE their length check, so a whitespace-padded raw value well over the cap (e.g. 258
// chars: 257 spaces + "x") normalized down to "x" and sailed through -- the cap only ever
// looked at the post-trim string. Assert the RAW length is what gets checked.
test("normalizeFactPoint rejects a whitespace-padded fact_name/entity_key whose RAW length is over cap even though it trims down under it", () => {
  const paddedName = `${" ".repeat(MAX_FACT_NAME_LENGTH + 1)}x`;
  assert.equal(paddedName.length, MAX_FACT_NAME_LENGTH + 2);
  assert.equal(paddedName.trim().length, 1); // trims down to "x" -- must not be what's checked
  assert.throws(
    () => normalizeFactPoint({ fact_name: paddedName, entity_key: "nginx" }),
    /fact_name/,
  );

  const paddedEntityKey = `${" ".repeat(MAX_FACT_ENTITY_KEY_LENGTH + 1)}x`;
  assert.equal(paddedEntityKey.trim().length, 1);
  assert.throws(
    () => normalizeFactPoint({ fact_name: "service.presence", entity_key: paddedEntityKey }),
    /entity_key/,
  );
});

// daybreak-blue re-gate (2026-09-04), fact-store MEDIUM: sensitivity was an uncapped string --
// a multi-megabyte value was accepted unchanged into every stored fact point.
test("normalizeFactPoint rejects an over-cap sensitivity value instead of silently accepting it", () => {
  assert.throws(
    () => normalizeFactPoint({
      fact_name: "service.presence",
      entity_key: "nginx",
      sensitivity: "x".repeat(MAX_FACT_SENSITIVITY_LENGTH + 1),
    }),
    /sensitivity/,
  );
  assert.doesNotThrow(() => normalizeFactPoint({
    fact_name: "service.presence",
    entity_key: "nginx",
    sensitivity: "x".repeat(MAX_FACT_SENSITIVITY_LENGTH),
  }));
});

test("appendFactPoints propagates an over-cap point as a whole-batch abort (mirrors the documented atomic-reject convention)", async () => {
  const paths = await tempPaths();
  const ts = "2026-07-10T00:00:00.000Z";
  await assert.rejects(() => appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts },
    { fact_name: "x".repeat(MAX_FACT_NAME_LENGTH + 1), entity_key: "postgres", attributes: {}, ts },
  ], { ts, now: ts }));

  const { points } = await readFactPoints(paths, { now: ts });
  assert.equal(points.length, 0); // neither point in the batch was written
});

test("readFactPoints counts a disk record with over-cap attributes as schema_invalid rather than throwing or silently accepting it", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  const oversizedAttributes = Object.fromEntries(Array.from({ length: MAX_FACT_ATTRIBUTE_COUNT + 1 }, (_, i) => [`key${i}`, "v"]));
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", fact_name: "service.presence", entity_key: "oversized", attributes: oversizedAttributes }),
  ].join("\n"));

  const { points, schema_invalid_count } = await readFactPoints(paths);
  assert.equal(schema_invalid_count, 1);
  assert.equal(points.length, 1);
  assert.equal(points[0].entity_key, "nginx");
});

// ---------------------------------------------------------------------------------------------
// Finding F4-B2 (daybreak-blue BLOCKER), mirrors history-store.test.js: enforceFactRetention runs
// AFTER appendFactPoints' own fs.appendFile has already durably succeeded. Before this fix, a
// retention-only failure propagated straight out of appendFactPoints -- so daemon.js's
// throw-fallback reported a fabricated written_count:0 even though the records genuinely reached
// facts.jsonl, and the retention error itself was discarded entirely. Retention must be
// non-fatal: the real written_count is reported, and a retention failure surfaces as an honestly-
// named retention_error instead of an escaping throw.
// ---------------------------------------------------------------------------------------------

test("F4-B2: a retention failure after a successful append does not throw -- appendFactPoints reports the real written_count plus a retention_error, and the records genuinely reached disk", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });

  // enforceFactRetention's own fs.writeFile(tmpFile, ...) (fact-store.js:~309-310) runs BEFORE it
  // ever touches the integrity ledger -- so pre-creating a DIRECTORY at that exact
  // `${factsFile}.${process.pid}.tmp` path forces a genuine EISDIR right there, with no torn
  // ledger state. Deterministic real fs failure, no DI seam needed.
  const retentionTmpFile = `${storePaths.factsFile}.${process.pid}.tmp`;
  await fs.mkdir(retentionTmpFile);

  const ts = "2026-07-10T00:00:00.000Z";
  const factPoints = [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
    { fact_name: "service.presence", entity_key: "postgres.service", attributes: { running: "true" } },
  ];

  const result = await appendFactPoints(paths, factPoints, { ts, now: ts });

  assert.equal(result.written_count, 2, "the append genuinely succeeded before retention ran -- the real count must be reported, never a fabricated 0");
  assert.equal(result.retention, undefined, "no genuine retention outcome exists on this failure -- must not synthesize one");
  assert.match(result.retention_error, /EISDIR/);

  // The records really are on disk -- readFactPoints reads facts.jsonl directly, unaffected by
  // (and not blocked by) the still-failing retention tmp path.
  const { points } = await readFactPoints(paths, { now: ts });
  assert.equal(points.length, 2);
});
