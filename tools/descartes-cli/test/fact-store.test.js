import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { normalizeMetricPoint } from "../src/history-store.js";
import {
  appendFactPoints,
  appendFactPointsByFamily,
  factStoreExists,
  DEFAULT_FACT_MAX_BYTES,
  DEFAULT_FACT_RETENTION_MS,
  enforceFactRetention,
  FUTURE_FACT_TOLERANCE_MS,
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
import { readFactIntegrityLedger } from "../src/fact-store-integrity.js";
import { FACT_FAMILY_IDS } from "../src/fact-families.js";
import { certifiedReadWindowOk, factHistoryTrustworthy } from "../src/fact-store-completeness.js";

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

test("resolveFactStorePaths points at stateDir/learned/facts/<family>/facts.jsonl (S4 per-family stores), passes the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths, "service");
  assert.equal(storePaths.dir, path.join(paths.stateDir, "learned", "facts", "service"));
  assert.equal(storePaths.factsFile, path.join(paths.stateDir, "learned", "facts", "service", "facts.jsonl"));
  assert.doesNotThrow(() => assertNoPiOwnedPath({ factsFile: storePaths.factsFile }));
  assert.equal(resolveFactStorePaths(paths, "peer").factsFile, path.join(paths.stateDir, "learned", "facts", "peer", "facts.jsonl"));
});

// T12 (fact-store capacity plan §8, I7): no legacy single-store default -- a call with no family, or
// an unknown one, throws instead of silently reading/writing a store nobody else uses.
test("T12: readFactPoints / appendFactPoints / enforceFactRetention / the path helpers throw with no family or an unknown family", async () => {
  const paths = await tempPaths();
  const point = { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts: "2026-07-10T00:00:00.000Z" };
  for (const bad of [undefined, "", "facts", "../service", "seen-sets"]) {
    const family = bad === undefined ? {} : { family: bad };
    await assert.rejects(() => readFactPoints(paths, { ...family }), /famil/);
    await assert.rejects(() => appendFactPoints(paths, [point], { ...family }), /famil/);
    await assert.rejects(() => enforceFactRetention(paths, { ...family }), /famil/);
    assert.throws(() => resolveFactStorePaths(paths, bad), /famil/);
  }
  await assert.rejects(() => readFactPoints(paths, { family: "service", families: ["service"] }), /exactly one/);
  await assert.rejects(() => readFactPoints(paths, { families: [] }), /non-empty/);
  await assert.rejects(() => readFactPoints(paths, { families: ["service", "nope"] }), /unknown fact family/);
  // Nothing was created by any of the refused calls.
  await assert.rejects(() => fs.stat(path.join(paths.stateDir, "learned", "facts")), { code: "ENOENT" });
});

test("T12: appendFactPoints refuses (before any write) an unregistered fact_name or a point of another family", async () => {
  const paths = await tempPaths();
  const ts = "2026-07-10T00:00:00.000Z";
  await assert.rejects(() => appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts },
    { fact_name: "peer.seen", entity_key: "x", attributes: {}, ts },
  ], { family: "service", now: ts }), /unregistered fact_name/);
  await assert.rejects(() => appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts },
    { fact_name: "network.listening_port.owner", entity_key: "tcp:22", attributes: {}, ts },
  ], { family: "service", now: ts }), /cannot be appended to the service store/);
  await assert.rejects(() => fs.stat(resolveFactStorePaths(paths, "service").dir), { code: "ENOENT" });
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
  ], { family: "service", ts, now });

  const { points, corrupt_count } = await readFactPoints(paths, { family: "service", now });
  assert.equal(corrupt_count, 0);
  assert.equal(points.length, 2);
  assert.deepEqual(points.map((p) => p.entity_key).sort(), ["nginx", "postgres"]);
});

test("appendFactPoints uses injected now as the explicit timestamp default", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [{ fact_name: "service.presence", entity_key: "nginx", attributes: {} }], { family: "service", now: "2026-07-10T00:00:00.000Z" });
  const { points } = await readFactPoints(paths, { family: "service", now: "2026-07-10T00:00:00.000Z" });
  assert.equal(points[0].ts, "2026-07-10T00:00:00.000Z");
});

test("readFactPoints returns an empty result on ENOENT", async () => {
  const paths = await tempPaths();
  const { points, corrupt_count } = await readFactPoints(paths, { family: "service" });
  assert.deepEqual(points, []);
  assert.equal(corrupt_count, 0);
});

test("readFactPoints skips corrupt lines and counts parseable schema-invalid records separately", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths, "service");
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    "not-json",
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", attributes: {} }), // missing entity_key -> invalid schema
    "",
  ].join("\n"));

  const { points, corrupt_count, schema_invalid_count } = await readFactPoints(paths, { family: "service" });
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
  ], { family: "service", now: base, retentionMs: 23 * 60 * 60 * 1000 });

  const retention = await enforceFactRetention(paths, { family: "service", now: base, retentionMs: 23 * 60 * 60 * 1000 });
  assert.equal(retention.kept_count, 1);

  const { points } = await readFactPoints(paths, { family: "service" });
  assert.deepEqual(points.map((p) => p.entity_key), ["fresh"]);
});

test("enforceFactRetention enforces maxBytes by keeping the newest records", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-07-10T00:00:00.000Z");
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "one", attributes: {}, ts: new Date(base).toISOString() },
    { fact_name: "service.presence", entity_key: "two", attributes: {}, ts: new Date(base + 1000).toISOString() },
    { fact_name: "service.presence", entity_key: "three", attributes: {}, ts: new Date(base + 2000).toISOString() },
  ], { family: "service", now: base + 3000, maxBytes: 200 });

  const { points } = await readFactPoints(paths, { family: "service" });
  assert(points.length >= 1);
  assert.equal(points.at(-1).entity_key, "three");
  assert(!points.some((p) => p.entity_key === "one"));
});

test("enforceFactRetention rewrites the file atomically (tmp file appears then is renamed)", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths, "service");
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx", attributes: {}, ts: "2026-07-10T00:00:00.000Z" },
  ], { family: "service", now: "2026-07-10T00:00:00.000Z" });

  const before = await fs.readFile(storePaths.factsFile, "utf8");
  await enforceFactRetention(paths, { family: "service", now: "2026-07-10T00:00:01.000Z", retentionMs: 60_000 });
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
  ], { family: "service", ts, now: ts });

  await assert.rejects(() => enforceFactRetention(paths, { family: "service", now: ts, retentionMs: "garbage" }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { family: "service", now: ts, retentionMs: NaN }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { family: "service", now: ts, retentionMs: -1 }), /retentionMs/);
  await assert.rejects(() => enforceFactRetention(paths, { family: "service", now: ts, maxBytes: NaN }), /maxBytes/);
  await assert.rejects(() => enforceFactRetention(paths, { family: "service", now: ts, maxBytes: -1 }), /maxBytes/);

  // None of the rejected calls may have touched the store -- no silent erasure.
  const { points } = await readFactPoints(paths, { family: "service", now: ts });
  assert.equal(points.length, 1);

  // Zero remains valid (a deliberate evict-everything/keep-nothing sweep), fully accounted.
  const retention = await enforceFactRetention(paths, { family: "service", now: ts, retentionMs: 0, maxBytes: 0 });
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
  ], { family: "service", ts, now: ts }));

  const { points } = await readFactPoints(paths, { family: "service", now: ts });
  assert.equal(points.length, 0); // neither point in the batch was written
});

test("readFactPoints counts a disk record with over-cap attributes as schema_invalid rather than throwing or silently accepting it", async () => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths, "service");
  await fs.mkdir(storePaths.dir, { recursive: true });
  const oversizedAttributes = Object.fromEntries(Array.from({ length: MAX_FACT_ATTRIBUTE_COUNT + 1 }, (_, i) => [`key${i}`, "v"]));
  await fs.writeFile(storePaths.factsFile, [
    JSON.stringify({ ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", entity_key: "nginx", attributes: {} }),
    JSON.stringify({ ts: "2026-07-10T00:00:01.000Z", fact_name: "service.presence", entity_key: "oversized", attributes: oversizedAttributes }),
  ].join("\n"));

  const { points, schema_invalid_count } = await readFactPoints(paths, { family: "service" });
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
  const storePaths = resolveFactStorePaths(paths, "service");
  await fs.mkdir(storePaths.dir, { recursive: true });

  const ts = "2026-07-10T00:00:00.000Z";
  // LOW-1/LOW-4 (review fold): a missing ledger now also runs a retention pass BEFORE
  // appendFactPoints' own append (fact-store.js), so this store must already have an established
  // ledger before the EISDIR trap is set up below -- otherwise the trap would catch that pre-pass
  // instead, and the whole call would throw before any append happens at all (a different,
  // separately-covered failure mode: no append means no fabricated written_count to guard
  // against). A no-op append (empty factPoints) is enough to run one clean retention pass and
  // establish a valid ledger with nothing in it.
  await appendFactPoints(paths, [], { family: "service", ts, now: ts });

  // enforceFactRetention's own fs.writeFile(tmpFile, ...) (fact-store.js:~309-310) runs BEFORE it
  // ever touches the integrity ledger -- so pre-creating a DIRECTORY at that exact
  // `${factsFile}.${process.pid}.tmp` path forces a genuine EISDIR right there, with no torn
  // ledger state. Deterministic real fs failure, no DI seam needed.
  const retentionTmpFile = `${storePaths.factsFile}.${process.pid}.tmp`;
  await fs.mkdir(retentionTmpFile);

  const factPoints = [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
    { fact_name: "service.presence", entity_key: "postgres.service", attributes: { running: "true" } },
  ];

  const result = await appendFactPoints(paths, factPoints, { family: "service", ts, now: ts });

  assert.equal(result.written_count, 2, "the append genuinely succeeded before retention ran -- the real count must be reported, never a fabricated 0");
  assert.equal(result.retention, undefined, "no genuine retention outcome exists on this failure -- must not synthesize one");
  assert.match(result.retention_error, /EISDIR/);

  // The records really are on disk -- readFactPoints reads facts.jsonl directly, unaffected by
  // (and not blocked by) the still-failing retention tmp path.
  const { points } = await readFactPoints(paths, { family: "service", now: ts });
  assert.equal(points.length, 2);
});

// ---------------------------------------------------------------------------------------------
// daybreak-blue re-gate BLOCKER, mirrors history-store.test.js: the F4-B2 catch above captured
// `error.message` directly -- an EMPTY-message Error (e.g. `new Error()`) coalesced to
// `retentionError = ""`, which is FALSY, so `...(retentionError ? { retention_error:
// retentionError } : {})` silently omitted the key entirely -- the exact "retention error
// discarded, never surfaced anywhere" fabrication F4-B2 closes, but only for the empty-message
// edge. The fix coalesces an empty message to "unknown retention error" at the point of capture.
// There is no DI seam for enforceFactRetention itself, so this mocks `fs.writeFile` directly (the
// same singleton `node:fs/promises` module object src imports) to fail with an EMPTY-message
// Error only for enforceFactRetention's own `${factsFile}.${process.pid}.tmp` write -- every other
// writeFile call (the integrity ledger, appendFactPoints' own fs.appendFile is a different method
// entirely) passes through to the real implementation untouched.
// ---------------------------------------------------------------------------------------------

test("F4-B2 empty-message edge: a retention failure with NO message still surfaces a non-empty retention_error -- appendFactPoints reports the real written_count and the records genuinely reached disk", async (t) => {
  const paths = await tempPaths();
  const storePaths = resolveFactStorePaths(paths, "service");
  await fs.mkdir(storePaths.dir, { recursive: true });

  const ts = "2026-07-10T00:00:00.000Z";
  // LOW-1/LOW-4 (review fold): establish a valid ledger first -- see the identical comment in the
  // EISDIR test above. Otherwise the mock below would also fail appendFactPoints' own pre-append
  // pass (ledger still missing at this point), and the whole call would throw before any append.
  await appendFactPoints(paths, [], { family: "service", ts, now: ts });

  const retentionTmpFile = `${storePaths.factsFile}.${process.pid}.tmp`;
  const originalWriteFile = fs.writeFile.bind(fs);
  t.mock.method(fs, "writeFile", async (file, data, opts) => {
    if (String(file) === retentionTmpFile) throw new Error();
    return originalWriteFile(file, data, opts);
  });

  const factPoints = [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
    { fact_name: "service.presence", entity_key: "postgres.service", attributes: { running: "true" } },
  ];

  const result = await appendFactPoints(paths, factPoints, { family: "service", ts, now: ts });

  assert.equal(result.written_count, 2, "the append genuinely succeeded before retention ran -- the real count must be reported, never a fabricated 0");
  assert.equal(result.retention, undefined, "no genuine retention outcome exists on this failure -- must not synthesize one");
  assert.ok(
    typeof result.retention_error === "string" && result.retention_error.length > 0,
    `expected a non-empty retention_error even from an empty-message throw, got: ${JSON.stringify(result.retention_error)}`,
  );

  // The records really are on disk -- readFactPoints reads facts.jsonl directly, unaffected by
  // (and not blocked by) the still-failing retention tmp path.
  const { points } = await readFactPoints(paths, { family: "service", now: ts });
  assert.equal(points.length, 2);
});

// ---------------------------------------------------------------------------------------------
// Fix 0 (trusted-state step-1 revision, "R1 made signable"): the future-fact continuity wedge.
// enforceFactRetention drops a fact whose ts exceeds nowMs + FUTURE_FACT_TOLERANCE_MS from
// candidates BEFORE it can ever contaminate last_rewrite_newest_ts, counts it, and stamps a new
// last_future_fact_ts loss marker with the pass's REAL now -- never the record's own claimed ts.
// ---------------------------------------------------------------------------------------------

test("enforceFactRetention drops a future-dated fact (beyond FUTURE_FACT_TOLERANCE_MS), counts it, and stamps last_future_fact_ts at real now", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const nowMs = Date.parse(now);
  const future = new Date(nowMs + FUTURE_FACT_TOLERANCE_MS + 60_000).toISOString();

  // A brand-new store's ledger only reaches continuity_ok:true after a SECOND clean pass (the
  // bootstrap pass itself commits continuity_ok:null -- pre-existing behavior, unrelated to fix
  // 0; see fact-store-integrity.test.js's "reaches intact after two clean passes"). Establish a
  // provably-continuous baseline FIRST so the assertions below isolate fix 0's own effect rather
  // than this unrelated first-run ambiguity.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "baseline", attributes: {}, ts: now },
  ], { family: "service", now });
  await enforceFactRetention(paths, { family: "service", now });

  const written = await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "real", attributes: {}, ts: now },
    { fact_name: "service.presence", entity_key: "future", attributes: {}, ts: future },
  ], { family: "service", now });
  assert.equal(written.written_count, 2, "both records genuinely reach disk on append -- the wedge fix is a RETENTION-time drop, not an append-time rejection");
  assert.equal(written.retention.future_fact_dropped_count, 1);
  assert.equal(written.retention.kept_count, 2); // baseline (prior pass) + real
  assert.equal(written.retention.dropped_count, 1);

  // "fresh incident, post-fix" shape (plan §"Fix 0", "Recovery shape this produces"): the future
  // fact never reaches last_rewrite_newest_ts, so there is no wedge at all -- the read degrades
  // immediately via the new loss channel, not "unknown".
  const read = await readFactPoints(paths, { family: "service", now });
  assert.deepEqual(read.points.map((p) => p.entity_key).sort(), ["baseline", "real"]);
  assert.equal(read.completeness.status, "degraded");
  assert.equal(read.completeness.degraded_reason, "future_fact");
  assert.equal(read.completeness.last_future_fact_ts, now);
  assert.equal(read.completeness.future_fact_dropped_total, 1);
  assert.deepEqual(read.completeness.future_loss_fields, []); // stamped at real now, not itself future

  const { ledger } = await readFactIntegrityLedger(paths, "service");
  assert.equal(ledger.future_fact_dropped_total, 1);
  assert.equal(ledger.last_future_fact_ts, now);
  assert.equal(ledger.continuity.last_rewrite_newest_ts, now, "the dropped future record must never reach the continuity anchor");
});

test("enforceFactRetention's sum-invariant holds across kept + age-evicted + bytecap-evicted + future-dropped", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const nowMs = Date.parse(now);
  const retentionMs = 24 * 60 * 60 * 1000;
  const old = new Date(nowMs - retentionMs - 60_000).toISOString(); // age-evicted
  const kept = now; // kept
  const future = new Date(nowMs + FUTURE_FACT_TOLERANCE_MS + 60_000).toISOString(); // future-dropped

  const written = await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "old", attributes: {}, ts: old },
    { fact_name: "service.presence", entity_key: "kept", attributes: {}, ts: kept },
    { fact_name: "service.presence", entity_key: "future", attributes: {}, ts: future },
  ], { family: "service", now, retentionMs });

  const retention = written.retention;
  assert.equal(retention.kept_count + retention.age_evicted_count + retention.bytecap_evicted_count + retention.future_fact_dropped_count, 3);
  assert.equal(retention.age_evicted_count, 1);
  assert.equal(retention.future_fact_dropped_count, 1);
  assert.equal(retention.kept_count, 1);
});

test("a record within FUTURE_FACT_TOLERANCE_MS of now is NOT treated as a future-fact drop (generous tolerance, not a hair-trigger)", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const nowMs = Date.parse(now);
  const withinTolerance = new Date(nowMs + FUTURE_FACT_TOLERANCE_MS - 60_000).toISOString();

  // See the preceding test's comment: a brand-new store needs a second clean pass before
  // continuity_ok resolves to true, independent of fix 0.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "baseline", attributes: {}, ts: now },
  ], { family: "service", now });
  await enforceFactRetention(paths, { family: "service", now });

  const written = await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "near-future", attributes: {}, ts: withinTolerance },
  ], { family: "service", now });
  assert.equal(written.retention.future_fact_dropped_count, 0);
  assert.equal(written.retention.kept_count, 2); // baseline (prior pass) + near-future

  const read = await readFactPoints(paths, { family: "service", now });
  assert.equal(read.completeness.status, "intact");
  assert.equal(read.completeness.degraded_reason, "none");
});

// The realistic daemon-shaped incident: a forward-clock tick writes a future fact with ts===now
// (daemon.js derives both from the same stepped-forward wall clock, so the fix-0 write-path drop
// above does NOT catch it at write time -- tsMs is not beyond nowMs+tol relative to ITS OWN
// tick's nowMs). The wedge only becomes visible once the clock is restored to real time and a
// LATER append-triggering pass evaluates the same on-disk future fact against a real nowMs.
// Pin the ACTUAL bounded recovery shape here rather than the plan's simplified prose: the FIRST
// post-incident append-triggering pass computed by comparing the pre-rewrite live disk state
// (which still holds the poisoned future fact) against the antecedent pass's own poisoned
// last_rewrite_newest_ts observes continuityObservation:"unknown" for ITS OWN commit -- so a read
// performed strictly BETWEEN that pass and the next one reads "unknown" (honest, not "intact",
// but also not yet "degraded" -- the plan's "resolves the same pass" framing does not hold for
// this ts===now incident shape; see this test's own trailing note). The pass's own COMMITTED
// output is nonetheless future-fact-free (last_rewrite_newest_ts is clean), so the FOLLOWING
// append-triggering pass's OWN observation is unambiguous ("ok", genuinely, not via any
// recovery/promotion special-case) and a read after THAT pass shows "degraded" via the new
// last_future_fact_ts channel -- bounded to exactly two append-triggering passes from incident
// start to "resolved, honestly degraded, not permanently wedged".
test("a pre-existing (ts===now) future-fact incident wedges continuity for exactly one transitional append-pass, then resolves to a real (not permanently-stuck) degraded read", async () => {
  const paths = await tempPaths();
  const t0 = "2026-07-10T00:00:00.000Z";
  const tFutureIncident = new Date(Date.parse(t0) + 400 * 24 * 60 * 60 * 1000).toISOString(); // clock stepped ~1yr forward
  const tReal = "2026-07-10T00:05:00.000Z"; // clock restored; well beyond tFutureIncident's tolerance window
  const tReal2 = "2026-07-10T00:10:00.000Z";

  // Pass A: baseline real fact.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "baseline", attributes: {}, ts: t0 },
  ], { family: "service", now: t0 });

  // Pass A2 (the poisoning tick): daemon.js derives BOTH ts and now from the same stepped-forward
  // clock, so fix 0's write-time filter does not catch this -- tsMs === nowMs, never beyond
  // nowMs+tol relative to its own (poisoned) now.
  const poisoned = await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "poisoned", attributes: {}, ts: tFutureIncident },
  ], { family: "service", now: tFutureIncident });
  assert.equal(poisoned.retention.future_fact_dropped_count, 0, "ts===now this tick -- fix 0's write-time filter cannot catch a same-tick clock excursion");
  const { ledger: afterPoison } = await readFactIntegrityLedger(paths, "service");
  assert.equal(afterPoison.continuity.last_rewrite_newest_ts, tFutureIncident, "the poisoned future fact IS committed as the continuity anchor by this pass -- this is the wedge fix 0's recovery path must resolve");

  // Pass B (transitional): clock restored to real time. This append-triggering pass's OWN
  // continuity observation compares the pre-rewrite live disk (still holding the poisoned fact)
  // against the antecedent pass's poisoned last_rewrite_newest_ts -> "unknown" for THIS pass's
  // commit, even though this pass's fix-0 filter DOES drop the now-far-future record from its
  // own output (tReal + tol is nowhere near tFutureIncident).
  const transitional = await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "recovery-b", attributes: {}, ts: tReal },
  ], { family: "service", now: tReal });
  assert.equal(transitional.retention.future_fact_dropped_count, 1, "this pass's real nowMs now catches the far-future record");

  const readAfterB = await readFactPoints(paths, { family: "service", now: tReal });
  // Honest, bounded-but-not-yet-resolved: NOT "intact" (a real loss occurred and is not yet
  // provably continuous), and the plan's own simplified "resolves the same pass" framing does
  // not hold for this incident shape -- this is a deviation from the plan's prose, not from its
  // governing invariant (never fabricate intact; never stay wedged forever). See deviations_from_spec.
  assert.equal(readAfterB.completeness.status, "unknown");
  assert.notEqual(readAfterB.completeness.status, "intact");
  const { ledger: afterB } = await readFactIntegrityLedger(paths, "service");
  assert.equal(afterB.last_future_fact_ts, tReal, "the marker is stamped at THIS pass's real now, never the record's own claimed future ts");
  assert.equal(afterB.continuity.last_rewrite_newest_ts, tReal, "pass B's OWN committed output is future-fact-free -- the anchor is no longer poisoned going forward");

  // Pass C (the following append-triggering pass): this pass's own continuity observation
  // compares pre-rewrite live disk (pass B's clean output + this new fact) against pass B's
  // now-clean last_rewrite_newest_ts -- genuinely "ok", not via any recovery special-case.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "recovery-c", attributes: {}, ts: tReal2 },
  ], { family: "service", now: tReal2 });

  const readAfterC = await readFactPoints(paths, { family: "service", now: tReal2 });
  assert.equal(readAfterC.completeness.continuity_ok, true);
  assert.equal(readAfterC.completeness.status, "degraded"); // the future-fact loss is real and within window
  assert.equal(readAfterC.completeness.degraded_reason, "future_fact");
  assert.notEqual(readAfterC.completeness.status, "unknown", "must not stay permanently wedged -- this is the bug fix 0 exists to close");
});

// ---------------------------------------------------------------------------------------------
// Fix 1 (trusted-state step-1 revision, "R1 made signable"): the bounded-blind retention-time
// clamp in prepareFactIntegrityLedger. A forward-dated loss MARKER (not just the future-fact
// wedge fix 0 handles) is pulled down to nowIso on the next append-triggering pass, turning an
// unbounded fail-STUCK blind into a bounded, one-window blind -- WITHOUT ever erasing the loss
// itself (the total counters are untouched; only the timestamp moves).
// ---------------------------------------------------------------------------------------------

test("Fix 1: a forward-dated last_corrupt_ts marker (stamped alongside the same-tick future-fact incident) is clamped to real now on the next pass, ages out for a windowed read, and stays degraded unwindowed -- without erasing the loss", async () => {
  const paths = await tempPaths();
  const t0 = "2026-07-10T00:00:00.000Z";
  const tFutureIncident = new Date(Date.parse(t0) + 400 * 24 * 60 * 60 * 1000).toISOString(); // clock stepped ~1yr forward
  const tReal = "2026-07-10T00:05:00.000Z"; // clock restored
  const tReal2 = "2026-07-10T00:10:00.000Z";

  // Baseline: one real fact, two clean passes -> continuity_ok:true.
  await appendFactPoints(paths, [
    { ts: t0, fact_name: "service.presence", entity_key: "baseline", attributes: {} },
  ], { family: "service", now: t0 });
  await enforceFactRetention(paths, { family: "service", now: t0 });

  // The poisoning tick: BOTH anomalies land in the SAME forward-clock pass -- a genuine corrupt
  // line already on disk (manually injected, simulating an unrelated concurrent loss) AND a
  // future-dated fact whose ts===now this pass (so fix 0's write-time filter cannot catch it,
  // exactly like the plain future-fact wedge test above). This pass's own nowIso is itself the
  // poisoned tFutureIncident, so last_corrupt_ts gets stamped at that SAME forward-dated value.
  const storePaths = resolveFactStorePaths(paths, "service");
  await fs.appendFile(storePaths.factsFile, [
    "not-json",
    JSON.stringify({ ts: tFutureIncident, fact_name: "service.presence", entity_key: "poisoned", attributes: {} }),
  ].join("\n") + "\n");
  await enforceFactRetention(paths, { family: "service", now: tFutureIncident });
  const afterPoison = await readFactIntegrityLedger(paths, "service");
  assert.equal(afterPoison.ledger.last_corrupt_ts, tFutureIncident, "the corrupt-loss marker is genuinely stamped at the poisoned nowIso this pass");
  assert.equal(afterPoison.ledger.corrupt_dropped_total, 1);
  assert.equal(afterPoison.ledger.continuity.last_rewrite_newest_ts, tFutureIncident);

  // Transitional pass (clock restored to real time): fix 0's write-time filter now drops the
  // still-on-disk future fact (real nowMs, far past its tolerance window). No NEW corrupt line
  // lands this pass, so last_corrupt_ts is not freshly re-stamped by the ordinary
  // corruptDelta>0 path -- it is carried forward from the prior pass UNLESS the clamp acts on
  // it. This is precisely the case the clamp exists for.
  await appendFactPoints(paths, [
    { ts: tReal, fact_name: "service.presence", entity_key: "recovery-b", attributes: {} },
  ], { family: "service", now: tReal });
  const afterClampPass = await readFactIntegrityLedger(paths, "service");
  assert.equal(afterClampPass.ledger.last_corrupt_ts, tReal, "Fix 1: the forward-dated marker is clamped down to THIS pass's real nowIso");
  assert.equal(afterClampPass.ledger.last_future_fact_ts, tReal);
  // Never-fabricate / never-erase: the loss itself (the totals) must be completely unaffected by
  // the clamp -- only the TIMESTAMP moved, nothing about "a loss occurred" was rewritten away.
  assert.equal(afterClampPass.ledger.corrupt_dropped_total, 1, "the clamp must NEVER erase a genuine loss -- only pull its marker forward-of-now down to nowIso");
  assert.equal(afterClampPass.ledger.future_fact_dropped_total, 1);

  const readAfterClampPass = await readFactPoints(paths, { family: "service", now: tReal });
  assert.equal(readAfterClampPass.completeness.status, "unknown"); // one transitional pass, as in the plain wedge test above

  // The following append-triggering pass resolves continuity genuinely (not via any
  // recovery/promotion special-case -- see the plain wedge test's own commentary).
  await appendFactPoints(paths, [
    { ts: tReal2, fact_name: "service.presence", entity_key: "recovery-c", attributes: {} },
  ], { family: "service", now: tReal2 });

  const readAfterC = await readFactPoints(paths, { family: "service", now: tReal2 });
  assert.equal(readAfterC.completeness.continuity_ok, true);
  assert.equal(readAfterC.completeness.status, "degraded"); // both clamped/stamped markers (tReal) are real, in-window losses
  // Both markers are now real (non-future) timestamps relative to tReal2 -- no future_loss_fields.
  assert.deepEqual(readAfterC.completeness.future_loss_fields, []);

  // Acceptance #10: bounded to one window for a WINDOWED read, once the clock is corrected and
  // that read's own asOfMs advances past the clamped timestamp plus the window.
  const shortWindowMs = 1000;
  const stillWithinWindow = await readFactPoints(paths, { family: "service", now: new Date(Date.parse(tReal) + shortWindowMs).toISOString(), windowMs: shortWindowMs });
  assert.equal(stillWithinWindow.completeness.status, "degraded");
  const agedOut = await readFactPoints(paths, { family: "service", now: new Date(Date.parse(tReal) + shortWindowMs + 1).toISOString(), windowMs: shortWindowMs });
  assert.equal(agedOut.completeness.status, "intact", "bounded to exactly one window once the clamped timestamp ages out of a WINDOWED read");

  // Acceptance #9/#12 (corrected from the plan's simplified prose): the CLI's unwindowed path
  // (no windowMs, asOfMs=-Infinity) has no upper age bound on any loss channel -- this stays
  // "degraded" indefinitely across further passes, with no ledger reset. This is honest
  // (unrelated to and unchanged by this revision), not a self-recovery claim.
  const unwindowedFarFuture = await readFactPoints(paths, { family: "service", now: new Date(Date.parse(tReal) + 365 * 24 * 60 * 60 * 1000).toISOString() });
  assert.equal(unwindowedFarFuture.completeness.status, "degraded");
});


// ---------------------------------------------------------------------------------------------
// S4 (fact-store capacity plan §4.3, T12): routed append, the registry-driven retention sweep, and
// multi-family reads.
// ---------------------------------------------------------------------------------------------

const S4_TS = "2026-07-10T00:00:00.000Z";
const servicePoint = (key, ts = S4_TS) => ({ fact_name: "service.presence", entity_key: key, attributes: {}, ts });
const networkPoint = (key, ts = S4_TS) => ({ fact_name: "network.listening_port.owner", entity_key: key, attributes: {}, ts });

test("S4: appendFactPointsByFamily routes each point to its own family store, with its own ledger", async () => {
  const paths = await tempPaths();
  const result = await appendFactPointsByFamily(paths, [servicePoint("nginx"), networkPoint("tcp:22"), servicePoint("sshd")], { now: S4_TS });
  assert.equal(result.written_count, 3);
  assert.deepEqual(Object.keys(result.families).sort(), ["network", "service"]);
  assert.equal(result.families.service.written_count, 2);
  assert.equal(result.families.service.budget_bytes, 18 * 1024 * 1024);
  assert.ok(result.families.service.appended_bytes > 0);
  const service = await readFactPoints(paths, { family: "service", now: S4_TS });
  const network = await readFactPoints(paths, { family: "network", now: S4_TS });
  assert.deepEqual(service.points.map((point) => point.entity_key).sort(), ["nginx", "sshd"]);
  assert.deepEqual(network.points.map((point) => point.entity_key), ["tcp:22"]);
  const serviceLedger = (await readFactIntegrityLedger(paths, "service")).ledger;
  const networkLedger = (await readFactIntegrityLedger(paths, "network")).ledger;
  assert.notEqual(serviceLedger.generation, networkLedger.generation, "each family store has its own ledger lineage");
  for (const family of ["session", "peer", "canary", "process_lineage", "scheduled_job", "provenance"]) {
    assert.equal(await factStoreExists(paths, family), false, `${family}: a family with no points is never created`);
  }
});

test("S4/T12: an unregistered fact_name anywhere in the batch throws before ANY family store is written", async () => {
  const paths = await tempPaths();
  await assert.rejects(() => appendFactPointsByFamily(paths, [servicePoint("nginx"), { fact_name: "peer.seen", entity_key: "x", attributes: {}, ts: S4_TS }], { now: S4_TS }), /unregistered fact_name/);
  for (const family of FACT_FAMILY_IDS) assert.equal(await factStoreExists(paths, family), false);
});

test("S4/T12: a family store with no new points still age-evicts (the sweep), and one family's append failure is reported while the others persist", async () => {
  const paths = await tempPaths();
  const day = 24 * 60 * 60 * 1000;
  const t0 = Date.parse(S4_TS);
  await appendFactPointsByFamily(paths, [servicePoint("old", new Date(t0).toISOString()), networkPoint("tcp:22", new Date(t0).toISOString())], { now: new Date(t0).toISOString() });
  // 31 days later only the service family produces points; the network store must still age-evict.
  const later = new Date(t0 + 31 * day).toISOString();
  const swept = await appendFactPointsByFamily(paths, [servicePoint("new", later)], { now: later });
  assert.equal(swept.families.network.written_count, 0);
  assert.equal(swept.families.network.retention.age_evicted_count, 1, "network had no new points but was still age-evicted");
  assert.equal((await readFactPoints(paths, { family: "network", now: later })).points.length, 0);
  // Break the network store's append (its facts.jsonl becomes a directory): service still persists.
  const networkFile = resolveFactStorePaths(paths, "network").factsFile;
  await fs.rm(networkFile, { force: true });
  await fs.mkdir(path.join(networkFile, "blocker"), { recursive: true });
  const partial = await appendFactPointsByFamily(paths, [servicePoint("after", later), networkPoint("tcp:80", later)], { now: later });
  assert.match(partial.append_error, /^network: /);
  assert.equal(partial.families.network.written_count, 0);
  assert.equal(partial.families.service.written_count, 1);
  assert.ok((await readFactPoints(paths, { family: "service", now: later })).points.some((point) => point.entity_key === "after"));
});

test("S4/T12: a directory under learned/facts/ that is not a registry family is ignored by the sweep and by every read", async () => {
  const paths = await tempPaths();
  const bogusDir = path.join(paths.stateDir, "learned", "facts", "bogus");
  await fs.mkdir(bogusDir, { recursive: true });
  const bogusLine = `${JSON.stringify(servicePoint("planted"))}\n`;
  await fs.writeFile(path.join(bogusDir, "facts.jsonl"), bogusLine);
  await appendFactPointsByFamily(paths, [servicePoint("nginx")], { now: S4_TS });
  const swept = await appendFactPointsByFamily(paths, [], { now: S4_TS });
  assert.deepEqual(Object.keys(swept.families), ["service"]);
  assert.equal(await fs.readFile(path.join(bogusDir, "facts.jsonl"), "utf8"), bogusLine, "never touched");
  const all = await readFactPoints(paths, { families: [...FACT_FAMILY_IDS], now: S4_TS });
  assert.deepEqual(all.points.map((point) => point.entity_key), ["nginx"]);
  assert.deepEqual(Object.keys(all.family_reads).sort(), [...FACT_FAMILY_IDS].sort());
});

test("S4: a multi-family read merges points, reports each family's own read, and a never-created store reads store_exists:false", async () => {
  const paths = await tempPaths();
  await appendFactPointsByFamily(paths, [servicePoint("nginx", "2026-07-10T00:00:02.000Z"), networkPoint("tcp:22", "2026-07-10T00:00:01.000Z")], { now: "2026-07-10T00:00:02.000Z" });
  await appendFactPointsByFamily(paths, [], { now: "2026-07-10T00:00:02.000Z" });
  const read = await readFactPoints(paths, { families: ["service", "network", "peer"], now: "2026-07-10T00:00:02.000Z" });
  assert.deepEqual(read.points.map((point) => point.entity_key), ["tcp:22", "nginx"], "merged and ts-sorted");
  assert.equal(read.family_reads.service.completeness.status, "intact");
  assert.equal(read.family_reads.peer.store_exists, false);
  assert.equal(read.family_reads.peer.completeness.status, "unknown");
  // The combined summary is over the stores that EXIST (a never-created one is reported per family as
  // absent, not folded in as "unknown"), and a never-created store holds no history to vouch for, so
  // it is left out of the trust AND as well.
  assert.equal(read.completeness.status, "intact");
  assert.equal(factHistoryTrustworthy(read).trust, true);
  // Trust holds only if EVERY existing family read is trusted: corrupt the network store.
  await fs.appendFile(resolveFactStorePaths(paths, "network").factsFile, "not-json\n");
  const degraded = await readFactPoints(paths, { families: ["service", "network", "peer"], now: "2026-07-10T00:00:02.000Z" });
  assert.equal(degraded.family_reads.service.completeness.status, "intact");
  assert.equal(factHistoryTrustworthy(degraded).trust, false);
  assert.notEqual(degraded.completeness.status, "intact", "combined: the worst existing family status");
  assert.equal(degraded.completeness.status, degraded.family_reads.network.completeness.status);
  // Every family absent: nothing to vouch for -> fail closed.
  const none = await readFactPoints(paths, { families: ["peer", "canary"], now: "2026-07-10T00:00:02.000Z" });
  assert.equal(factHistoryTrustworthy(none).trust, false);
  assert.equal(none.completeness.status, "unknown");
});

test("S4: multi-family predicates AND over each family's own completeness -- one family's newer age floor never masks another family's byte-cap floor", () => {
  const nowMs = Date.parse("2026-08-10T00:00:00.000Z");
  const familyRead = (completeness) => ({ corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact", ...completeness } });
  // service: byte-cap floor 10 d ago, age floor 31 d ago (an unbounded read sees the floor);
  // network: age floor 5 d ago. Combined floors (newest each) would read bytecap <= age and PASS.
  const service = familyRead({ coverage: "narrowed", bytecap_floor_ts: new Date(nowMs - 10 * 86_400_000).toISOString(), age_floor_ts: new Date(nowMs - 31 * 86_400_000).toISOString() });
  const network = familyRead({ coverage: "narrowed", bytecap_floor_ts: null, age_floor_ts: new Date(nowMs - 5 * 86_400_000).toISOString() });
  const combinedOnly = { corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact", coverage: "narrowed", bytecap_floor_ts: service.completeness.bytecap_floor_ts, age_floor_ts: network.completeness.age_floor_ts } };
  assert.equal(certifiedReadWindowOk(combinedOnly, { nowMs }), true, "precondition: the combined floors alone would pass");
  const multi = { ...combinedOnly, family_reads: { service, network } };
  assert.equal(certifiedReadWindowOk(multi, { nowMs }), false, "per-family AND refuses");
  assert.equal(certifiedReadWindowOk({ ...combinedOnly, family_reads: { network } }, { nowMs }), true);
  // Malformed family_reads fails closed.
  for (const bad of [null, [], {}, { service: null }, { service: { family_reads: {} } }]) {
    assert.equal(certifiedReadWindowOk({ ...combinedOnly, family_reads: bad }, { nowMs }), false);
    assert.equal(factHistoryTrustworthy({ ...combinedOnly, family_reads: bad }).trust, false);
  }
});

// S4 sweep x I4 (external truncation stays a continuity break): the sweep now runs retention over a
// family store with NO new points, so a facts.jsonl deleted under a ledger that had committed records
// must not be re-certified as an empty intact store two passes later -- it is a lineage break
// (stamped, degraded for the window), exactly like an external truncation caught by the prefix check.
test("S4/I4: a family facts.jsonl deleted under a ledger that committed records is a continuity break on the next sweep -- never re-certified intact", async () => {
  const paths = await tempPaths();
  const t0 = "2026-07-10T00:00:00.000Z";
  await appendFactPointsByFamily(paths, [servicePoint("nginx", t0), networkPoint("tcp:22", t0)], { now: t0 });
  await appendFactPointsByFamily(paths, [], { now: t0 });
  assert.equal((await readFactPoints(paths, { family: "network", now: t0 })).completeness.status, "intact");
  await fs.rm(resolveFactStorePaths(paths, "network").factsFile);
  const t1 = "2026-07-10T01:00:00.000Z";
  await appendFactPointsByFamily(paths, [servicePoint("nginx", t1)], { now: t1 });
  for (let pass = 0; pass < 2; pass += 1) await appendFactPointsByFamily(paths, [], { now: t1 });
  const read = await readFactPoints(paths, { family: "network", now: t1 });
  assert.notEqual(read.completeness.status, "intact", "deleted history is never re-certified");
  assert.equal(read.completeness.last_continuity_break_ts, t1);
  assert.equal((await readFactPoints(paths, { family: "service", now: t1 })).completeness.status, "intact", "the other family is unaffected");
});
