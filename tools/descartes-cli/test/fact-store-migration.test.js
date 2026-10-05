// S5 (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §4.6 M2/M3, operator Q3/Q4):
// per-family stores start FRESH, and the legacy single store -- learned/facts/facts.jsonl, its
// integrity.json, and the pre-S4 seen-sets/ directory -- is quarantined OUTSIDE the facts tree
// (learned/facts-legacy-<iso>/), idempotently per file (a marker records the target directory, so a
// half-done move resumes into the same place), and deleted 31 days later. No trust path ever reads it
// again.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  LEGACY_QUARANTINE_RETENTION_MS,
  migrateLegacyFactStore,
  resolveLegacyFactStorePaths,
} from "../src/fact-store-migration.js";
import { resolveDescartesPaths } from "../src/paths.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = "2026-10-05T12:00:00.000Z";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-migration-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

async function exists(file) {
  try {
    await fs.lstat(file);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function seedLegacy(paths) {
  const { factsRootDir } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(path.join(factsRootDir, "seen-sets"), { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), "{\"legacy\":true}\n");
  await fs.writeFile(path.join(factsRootDir, "integrity.json"), "{\"schema_version\":1}\n");
  await fs.writeFile(path.join(factsRootDir, "seen-sets", "service.json"), "{}\n");
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl.4242.tmp"), "partial\n");
  // A live per-family store next to them must be left alone.
  await fs.mkdir(path.join(factsRootDir, "service"), { recursive: true });
  await fs.writeFile(path.join(factsRootDir, "service", "facts.jsonl"), "{\"family\":true}\n");
}

test("M3: no legacy store -> nothing happens (no marker, nothing created)", async () => {
  const paths = await tempPaths();
  const result = await migrateLegacyFactStore(paths, { now: NOW });
  assert.equal(result.status, "none");
  const { markerFile, learnedDir } = resolveLegacyFactStorePaths(paths);
  assert.equal(await exists(markerFile), false);
  assert.equal(await exists(learnedDir), false);
});

test("M3: the legacy facts.jsonl, integrity.json, seen-sets/ and stray tmp files move OUTSIDE learned/facts/ into one quarantine directory; per-family stores are untouched; a second run is a no-op", async () => {
  const paths = await tempPaths();
  await seedLegacy(paths);
  const { factsRootDir, learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const result = await migrateLegacyFactStore(paths, { now: NOW });
  assert.equal(result.status, "quarantined");
  assert.match(result.quarantine_dir, /^facts-legacy-2026-10-05T12-00-00-000Z$/);
  const quarantine = path.join(learnedDir, result.quarantine_dir);
  assert.equal(path.dirname(quarantine), learnedDir, "outside the facts tree, beside it");
  for (const item of ["facts.jsonl", "integrity.json", "seen-sets", "facts.jsonl.4242.tmp"]) {
    assert.equal(await exists(path.join(factsRootDir, item)), false, `${item} left the facts tree`);
    assert.equal(await exists(path.join(quarantine, item)), true, `${item} is in quarantine`);
  }
  assert.equal(await fs.readFile(path.join(factsRootDir, "service", "facts.jsonl"), "utf8"), "{\"family\":true}\n");
  const marker = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(marker.in_progress, null);
  assert.deepEqual(marker.quarantines, [{ dir: result.quarantine_dir, quarantined_ts: NOW }]);
  const again = await migrateLegacyFactStore(paths, { now: NOW });
  assert.equal(again.status, "none");
  assert.deepEqual(JSON.parse(await fs.readFile(markerFile, "utf8")), marker);
});

test("M3 idempotent per file: a half-done move (marker in progress, one file already moved) resumes into the SAME directory -- the half-moved state is never treated as a live store", async () => {
  const paths = await tempPaths();
  await seedLegacy(paths);
  const { factsRootDir, learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const dir = "facts-legacy-2026-10-04T00-00-00-000Z";
  await fs.mkdir(path.join(learnedDir, dir), { recursive: true });
  await fs.rename(path.join(factsRootDir, "facts.jsonl"), path.join(learnedDir, dir, "facts.jsonl"));
  await fs.writeFile(markerFile, JSON.stringify({ schema_version: 1, in_progress: { dir, started_ts: "2026-10-04T00:00:00.000Z" }, quarantines: [] }));
  const result = await migrateLegacyFactStore(paths, { now: NOW });
  assert.equal(result.status, "resumed");
  assert.equal(result.quarantine_dir, dir);
  for (const item of ["facts.jsonl", "integrity.json", "seen-sets"]) {
    assert.equal(await exists(path.join(learnedDir, dir, item)), true, `${item} completed into the same directory`);
    assert.equal(await exists(path.join(factsRootDir, item)), false);
  }
  const marker = JSON.parse(await fs.readFile(markerFile, "utf8"));
  assert.equal(marker.in_progress, null);
  assert.deepEqual(marker.quarantines, [{ dir, quarantined_ts: "2026-10-04T00:00:00.000Z" }]);
});

test("Q4: a quarantine is deleted 31 days after it was taken -- not a moment before -- and only directories the marker lists, by a validated name", async () => {
  const paths = await tempPaths();
  await seedLegacy(paths);
  const { learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const { quarantine_dir: dir } = await migrateLegacyFactStore(paths, { now: NOW });
  const almost = new Date(Date.parse(NOW) + LEGACY_QUARANTINE_RETENTION_MS - 1).toISOString();
  assert.equal(LEGACY_QUARANTINE_RETENTION_MS, 31 * DAY_MS);
  assert.deepEqual((await migrateLegacyFactStore(paths, { now: almost })).deleted, []);
  assert.equal(await exists(path.join(learnedDir, dir)), true);
  const due = new Date(Date.parse(NOW) + LEGACY_QUARANTINE_RETENTION_MS).toISOString();
  const result = await migrateLegacyFactStore(paths, { now: due });
  assert.deepEqual(result.deleted, [dir]);
  assert.equal(await exists(path.join(learnedDir, dir)), false);
  assert.deepEqual(JSON.parse(await fs.readFile(markerFile, "utf8")).quarantines, []);
});

test("Q4 (same-UID-writable marker): a marker naming anything but a facts-legacy-* directory is never deleted from; an unparseable marker deletes nothing", async () => {
  const paths = await tempPaths();
  const { learnedDir, factsRootDir, markerFile } = resolveLegacyFactStorePaths(paths);
  await fs.mkdir(path.join(factsRootDir, "service"), { recursive: true });
  await fs.mkdir(path.join(learnedDir, "facts-legacy-keep"), { recursive: true });
  const old = "2026-01-01T00:00:00.000Z";
  await fs.writeFile(markerFile, JSON.stringify({ schema_version: 1, in_progress: null, quarantines: [
    { dir: "facts", quarantined_ts: old },
    { dir: "../../config", quarantined_ts: old },
    { dir: "facts-legacy-../facts", quarantined_ts: old },
  ] }));
  const result = await migrateLegacyFactStore(paths, { now: NOW });
  assert.deepEqual(result.deleted, []);
  assert.equal(await exists(path.join(factsRootDir, "service")), true);
  await fs.writeFile(markerFile, "{not json");
  const garbled = await migrateLegacyFactStore(paths, { now: NOW });
  assert.deepEqual(garbled.deleted, []);
  assert.equal(await exists(path.join(learnedDir, "facts-legacy-keep")), true);
});

test("M3: a legacy file that reappears after a completed quarantine (downgrade, then upgrade) goes to a NEW quarantine directory; the first is kept until its own deadline", async () => {
  const paths = await tempPaths();
  await seedLegacy(paths);
  const { factsRootDir, learnedDir, markerFile } = resolveLegacyFactStorePaths(paths);
  const first = await migrateLegacyFactStore(paths, { now: NOW });
  await fs.writeFile(path.join(factsRootDir, "facts.jsonl"), "{\"downgraded\":true}\n");
  const later = new Date(Date.parse(NOW) + DAY_MS).toISOString();
  const second = await migrateLegacyFactStore(paths, { now: later });
  assert.equal(second.status, "quarantined");
  assert.notEqual(second.quarantine_dir, first.quarantine_dir);
  assert.equal(await fs.readFile(path.join(learnedDir, second.quarantine_dir, "facts.jsonl"), "utf8"), "{\"downgraded\":true}\n");
  assert.equal(await exists(path.join(learnedDir, first.quarantine_dir, "facts.jsonl")), true);
  assert.equal(JSON.parse(await fs.readFile(markerFile, "utf8")).quarantines.length, 2);
});

test("daemon wiring: a tick with a tier on quarantines the legacy store before any per-family write and reports it; with both tiers off nothing is touched (no I/O when disabled)", async () => {
  const { runDaemonIteration } = await import("../src/daemon.js");
  const { writeWatchConfig } = await import("../src/watch-store.js");
  const { writeLearnedConfig } = await import("../src/constraint-store.js");
  const profile = { interval_ms: 60_000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } };
  const env = (id, tool, result) => ({ id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: NOW } });
  const collectors = {
    system: async () => env("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => env("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => env("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };

  const off = await tempPaths();
  await seedLegacy(off);
  await writeWatchConfig(off, { enabled: false });
  await writeLearnedConfig(off, { enabled: false });
  const offResult = await runDaemonIteration(off, { profile, collectors, ts: NOW, now: NOW });
  assert.equal(offResult.status.fact_store_legacy, undefined);
  assert.equal(await exists(path.join(resolveLegacyFactStorePaths(off).factsRootDir, "facts.jsonl")), true, "untouched while both tiers are off");

  const on = await tempPaths();
  await seedLegacy(on);
  const onResult = await runDaemonIteration(on, { profile, collectors, ts: NOW, now: NOW });
  assert.equal(onResult.status.fact_store_legacy.status, "quarantined");
  assert.equal(await exists(path.join(resolveLegacyFactStorePaths(on).factsRootDir, "facts.jsonl")), false);
  assert.equal(onResult.status.fact_store_legacy.pending[0].delete_after_ts, new Date(Date.parse(NOW) + LEGACY_QUARANTINE_RETENTION_MS).toISOString());
  const failing = await runDaemonIteration(on, { profile, collectors, ts: NOW, now: NOW, migrateLegacyFactStore: async () => { throw new Error("EACCES simulated"); } });
  assert.deepEqual(failing.status.fact_store_legacy, { status: "error", error: "EACCES simulated" });
});
