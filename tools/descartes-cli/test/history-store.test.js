import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  appendMetricPoints,
  buildHistorySummary,
  enforceHistoryRetention,
  parseDurationMs,
  readDaemonStatus,
  readMetricPoints,
  resolveHistoryStorePaths,
  writeDaemonStatus,
} from "../src/history-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-history-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("duration parser accepts bounded history window suffixes", () => {
  assert.equal(parseDurationMs("500ms"), 500);
  assert.equal(parseDurationMs("2s"), 2000);
  assert.equal(parseDurationMs("3m"), 180000);
  assert.equal(parseDurationMs("1h"), 3600000);
  assert.equal(parseDurationMs("1d"), 86400000);
  assert.throws(() => parseDurationMs("forever"), /Invalid duration/);
});

test("history store appends metrics and summarizes rollups", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-05-24T00:00:00.000Z");
  await appendMetricPoints(paths, [
    { ts: new Date(base).toISOString(), metric_name: "system.load.1m", value: 1, unit: "load_average" },
    { ts: new Date(base + 1000).toISOString(), metric_name: "system.load.1m", value: 3, unit: "load_average" },
    { ts: new Date(base + 2000).toISOString(), metric_name: "system.memory.used_fraction", value: 0.5, unit: "fraction" },
  ], { now: new Date(base + 3000).toISOString() });

  const summary = await buildHistorySummary(paths, {
    now: new Date(base + 3000).toISOString(),
    windowMs: 60_000,
  });

  assert.equal(summary.point_count, 3);
  assert.equal(summary.matched_point_count, 3);
  assert.equal(summary.point_limit, 10000);
  assert.equal(summary.truncated, false);
  const load = summary.metrics.find((metric) => metric.metric_name === "system.load.1m");
  assert.equal(load.count, 2);
  assert.equal(load.min, 1);
  assert.equal(load.max, 3);
  assert.equal(load.mean, 2);
  assert.equal(load.last, 3);
});

test("history retention drops old and corrupt records", async () => {
  const paths = await tempPaths();
  const storePaths = resolveHistoryStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  await fs.writeFile(storePaths.metricsFile, [
    JSON.stringify({ ts: "2026-05-23T00:00:00.000Z", metric_name: "old", value: 1 }),
    "not-json",
    JSON.stringify({ ts: "2026-05-24T00:00:00.000Z", metric_name: "fresh", value: 2 }),
    "",
  ].join("\n"));

  const retention = await enforceHistoryRetention(paths, {
    now: "2026-05-24T00:00:01.000Z",
    retentionMs: 60_000,
    maxBytes: 1024,
  });
  assert.equal(retention.kept_count, 1);
  assert.equal(retention.corrupt_dropped_count, 1);

  const { points, corrupt_count } = await readMetricPoints(paths);
  assert.equal(corrupt_count, 0);
  assert.deepEqual(points.map((point) => point.metric_name), ["fresh"]);
});

test("history summary exposes truncation diagnostics when point limit is hit", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-05-24T00:00:00.000Z");
  await appendMetricPoints(paths, [
    { ts: new Date(base).toISOString(), metric_name: "metric.one", value: 1 },
    { ts: new Date(base + 1000).toISOString(), metric_name: "metric.two", value: 2 },
    { ts: new Date(base + 2000).toISOString(), metric_name: "metric.three", value: 3 },
  ], { now: new Date(base + 3000).toISOString() });

  const summary = await buildHistorySummary(paths, {
    now: new Date(base + 3000).toISOString(),
    windowMs: 60_000,
    limit: 2,
  });

  assert.equal(summary.point_count, 2);
  assert.equal(summary.matched_point_count, 3);
  assert.equal(summary.point_limit, 2);
  assert.equal(summary.truncated, true);
  assert.deepEqual(summary.metrics.map((metric) => metric.metric_name), ["metric.three", "metric.two"]);
});

test("history retention enforces maximum bytes by keeping newest records", async () => {
  const paths = await tempPaths();
  const base = Date.parse("2026-05-24T00:00:00.000Z");
  await appendMetricPoints(paths, [
    { ts: new Date(base).toISOString(), metric_name: "metric.one", value: 1 },
    { ts: new Date(base + 1000).toISOString(), metric_name: "metric.two", value: 2 },
    { ts: new Date(base + 2000).toISOString(), metric_name: "metric.three", value: 3 },
  ], { now: new Date(base + 3000).toISOString(), maxBytes: 220 });

  const { points } = await readMetricPoints(paths);
  assert(points.length >= 1);
  assert.equal(points.at(-1).metric_name, "metric.three");
  assert(!points.some((point) => point.metric_name === "metric.one"));
});

// ---------------------------------------------------------------------------------------------
// Finding F4 fix: both writeDaemonStatus (daemon-status.json, a single JSON object -- a torn
// write is NOT self-healing, unlike metrics.jsonl's line-oriented format) and
// enforceHistoryRetention's metrics.jsonl rewrite now use the same tmp+rename idiom already used
// elsewhere in the codebase (constraint-store.js, fact-store.js, daemon.js's own
// writeStructuralCheckpoint), instead of a direct fs.writeFile that a process crash mid-write can
// leave truncated.
// ---------------------------------------------------------------------------------------------

test("F4: writeDaemonStatus round-trips through readDaemonStatus", async () => {
  const paths = await tempPaths();
  const written = await writeDaemonStatus(paths, { ts: "2026-05-24T00:00:00.000Z", state: "ok", mode: "foreground" });
  assert.equal(written.state, "ok");

  const read = await readDaemonStatus(paths);
  assert.deepEqual(read, written);
});

test("F4: writeDaemonStatus writes atomically -- an interruption before the rename leaves the live status file untouched", async () => {
  const paths = await tempPaths();
  await writeDaemonStatus(paths, { ts: "2026-05-24T00:00:00.000Z", state: "ok", mode: "foreground" });
  const beforeInterrupt = await readDaemonStatus(paths);

  const storePaths = resolveHistoryStorePaths(paths);

  // Simulate a process death after the tmp file is written but before the rename commits it --
  // mirroring fact-store.js's beforeFactsRename/afterFactsRename DI-hook convention.
  await assert.rejects(
    writeDaemonStatus(paths, { ts: "2026-05-24T00:01:00.000Z", state: "ok", mode: "foreground" }, {
      beforeStatusRename: async () => {
        throw new Error("simulated crash before rename");
      },
    }),
    /simulated crash before rename/,
  );

  // The live file was never touched by the interrupted write -- reading it back gives the OLD
  // status, not a torn/partial one and not the new one either. (The `.tmp` file itself is left
  // behind on this failure path -- same no-cleanup-on-failure idiom as writeStructuralCheckpoint /
  // fact-store.js's enforceFactRetention; nothing in this codebase cleans it up on a thrown
  // beforeFactsRename/beforeStatusRename hook, so we don't assert its absence.)
  const afterInterrupt = await readDaemonStatus(paths);
  assert.deepEqual(afterInterrupt, beforeInterrupt);

  const dirEntries = await fs.readdir(storePaths.dir);
  assert.ok(dirEntries.includes(path.basename(storePaths.statusFile)), "the live status file must still be present");
  assert.ok(
    dirEntries.some((name) => name.startsWith(`${path.basename(storePaths.statusFile)}.`) && name.endsWith(".tmp")),
    "the tmp file from the interrupted write is left behind, not renamed over the live file",
  );
});

test("F4: readDaemonStatus fails loudly (never fabricates) on a status file corrupted by something other than writeDaemonStatus itself -- degrade-not-fabricate means an unreadable status must not be silently reported as absent or healthy", async () => {
  const paths = await tempPaths();
  const storePaths = resolveHistoryStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });
  // A truncated JSON object -- e.g. a torn write from BEFORE this fix, or filesystem corruption
  // unrelated to writeDaemonStatus's own (now-atomic) operation.
  await fs.writeFile(storePaths.statusFile, '{"ts":"2026-05-24T00:00:00.000Z","state":"ok"', "utf8");

  await assert.rejects(readDaemonStatus(paths), SyntaxError);
});

// ---------------------------------------------------------------------------------------------
// Finding F4-B2 (daybreak-blue BLOCKER): enforceHistoryRetention runs AFTER appendMetricPoints'
// own fs.appendFile has already durably succeeded. Before this fix, a retention-only failure (a
// throw from enforceHistoryRetention) propagated straight out of appendMetricPoints -- so
// daemon.js's throw-fallback reported a fabricated written_count:0 even though the records
// genuinely reached metrics.jsonl, and the retention error itself was discarded entirely (never
// surfaced anywhere). Retention must be non-fatal: the real written_count is reported, and a
// retention failure surfaces as an honestly-named retention_error instead of an escaping throw.
// ---------------------------------------------------------------------------------------------

test("F4-B2: a retention failure after a successful append does not throw -- appendMetricPoints reports the real written_count plus a retention_error, and the records genuinely reached disk", async () => {
  const paths = await tempPaths();
  const storePaths = resolveHistoryStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });

  // enforceHistoryRetention writes its kept-records output via a `${metricsFile}.${process.pid}.tmp`
  // tmp+rename. Pre-creating a DIRECTORY at that exact path forces its own `fs.writeFile(tmpFile,
  // ...)` to fail with a genuine EISDIR -- a deterministic real fs failure, no DI seam needed
  // (appendMetricPoints/enforceHistoryRetention take none for this).
  const retentionTmpFile = `${storePaths.metricsFile}.${process.pid}.tmp`;
  await fs.mkdir(retentionTmpFile);

  const points = [
    { ts: "2026-05-24T00:00:00.000Z", metric_name: "system.load.1m", value: 1, unit: "load_average" },
    { ts: "2026-05-24T00:00:01.000Z", metric_name: "system.load.1m", value: 2, unit: "load_average" },
  ];

  const result = await appendMetricPoints(paths, points, { now: "2026-05-24T00:00:02.000Z" });

  assert.equal(result.written_count, 2, "the append genuinely succeeded before retention ran -- the real count must be reported, never a fabricated 0");
  assert.equal(result.retention, undefined, "no genuine retention outcome exists on this failure -- must not synthesize one");
  assert.match(result.retention_error, /EISDIR/);

  // The records really are on disk -- readMetricPoints reads metricsFile directly, unaffected by
  // (and not blocked by) the still-failing retention tmp path.
  const read = await readMetricPoints(paths);
  assert.equal(read.points.length, 2);
});

// ---------------------------------------------------------------------------------------------
// daybreak-blue re-gate BLOCKER: the F4-B2 catch above captured `error.message` directly -- an
// EMPTY-message Error (e.g. `new Error()`) coalesced to `retentionError = ""`, which is FALSY, so
// the `...(retentionError ? { retention_error: retentionError } : {})` spread silently omitted
// the key entirely -- the exact "retention error discarded, never surfaced anywhere" fabrication
// F4-B2 closes, but only for the empty-message edge. The fix coalesces an empty message to
// "unknown retention error" at the point of capture, so the spread condition is always truthy on
// a genuine retention failure. There is no DI seam for enforceHistoryRetention itself, so this
// mocks `fs.writeFile` directly (the same singleton `node:fs/promises` module object src imports)
// to fail with an EMPTY-message Error only for enforceHistoryRetention's own tmp+rename write --
// appendMetricPoints' earlier fs.appendFile call is a different method, untouched.
// ---------------------------------------------------------------------------------------------

test("F4-B2 empty-message edge: a retention failure with NO message still surfaces a non-empty retention_error -- appendMetricPoints reports the real written_count and the records genuinely reached disk", async (t) => {
  const paths = await tempPaths();
  const storePaths = resolveHistoryStorePaths(paths);
  await fs.mkdir(storePaths.dir, { recursive: true });

  const retentionTmpFile = `${storePaths.metricsFile}.${process.pid}.tmp`;
  const originalWriteFile = fs.writeFile.bind(fs);
  t.mock.method(fs, "writeFile", async (file, data, opts) => {
    if (String(file) === retentionTmpFile) throw new Error();
    return originalWriteFile(file, data, opts);
  });

  const points = [
    { ts: "2026-05-24T00:00:00.000Z", metric_name: "system.load.1m", value: 1, unit: "load_average" },
    { ts: "2026-05-24T00:00:01.000Z", metric_name: "system.load.1m", value: 2, unit: "load_average" },
  ];

  const result = await appendMetricPoints(paths, points, { now: "2026-05-24T00:00:02.000Z" });

  assert.equal(result.written_count, 2, "the append genuinely succeeded before retention ran -- the real count must be reported, never a fabricated 0");
  assert.equal(result.retention, undefined, "no genuine retention outcome exists on this failure -- must not synthesize one");
  assert.ok(
    typeof result.retention_error === "string" && result.retention_error.length > 0,
    `expected a non-empty retention_error even from an empty-message throw, got: ${JSON.stringify(result.retention_error)}`,
  );

  // The records really are on disk -- readMetricPoints reads metricsFile directly, unaffected by
  // (and not blocked by) the still-failing retention tmp path.
  const read = await readMetricPoints(paths);
  assert.equal(read.points.length, 2);
});
