import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { DEFAULT_FACT_MAX_BYTES } from "../src/fact-store.js";
import {
  loadWatchConfig,
  normalizeWatchConfig,
  resolveWatchStorePaths,
  writeWatchConfig,
} from "../src/watch-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-watch-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// --- The one deliberate inversion (plan §3.1): ENOENT -> {enabled: true}, not false. ---

test("watch enablement switch defaults to ENABLED when watch.json is absent (the one deliberate inversion vs. learned.json)", async () => {
  const paths = await tempPaths();
  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, true);
});

test("watch.json path lives at configDir/watch.json, independent of learned.json", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveWatchStorePaths(paths);
  assert.equal(configFile, path.join(paths.configDir, "watch.json"));
});

test("watch enablement switch reads back a present watch.json", async () => {
  const paths = await tempPaths();
  const written = await writeWatchConfig(paths, { enabled: false });
  assert.equal(written.enabled, false);

  const reread = await loadWatchConfig(paths);
  assert.equal(reread.enabled, false);
});

test("watch enablement switch round-trips an explicit enabled:true the same as the default", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true });
  const reread = await loadWatchConfig(paths);
  assert.equal(reread.enabled, true);
});

test("loadWatchConfig fails CLOSED to the ENABLED default (does not throw) when watch.json contains malformed JSON, and marks corrupt:true", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveWatchStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, "{ not json", { mode: 0o600 });

  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, true, "malformed watch.json must fail closed to this store's SAFE state, which is enabled");
  assert.equal(config.corrupt, true);
});

// --- fact_store_max_bytes / updated_at: normalizeWatchConfig mirrors normalizeLearnedConfig's
// shape exactly (plan §12.3 fact 3), so the daemon's structural-append path can source
// options.maxBytes from watchConfig instead of learnedConfig. ---

test("normalizeWatchConfig accepts a valid finite positive fact_store_max_bytes override", () => {
  const config = normalizeWatchConfig({ fact_store_max_bytes: 1024 });
  assert.equal(config.fact_store_max_bytes, 1024);
});

test("normalizeWatchConfig fails closed to DEFAULT_FACT_MAX_BYTES when fact_store_max_bytes is missing", () => {
  const config = normalizeWatchConfig({});
  assert.equal(config.fact_store_max_bytes, DEFAULT_FACT_MAX_BYTES);
});

for (const badValue of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0, "garbage", null]) {
  test(`normalizeWatchConfig fails closed to DEFAULT_FACT_MAX_BYTES on invalid fact_store_max_bytes: ${String(badValue)}`, () => {
    const config = normalizeWatchConfig({ fact_store_max_bytes: badValue });
    assert.equal(config.fact_store_max_bytes, DEFAULT_FACT_MAX_BYTES);
  });
}

test("writeWatchConfig/loadWatchConfig round-trip a valid fact_store_max_bytes override", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_max_bytes: 2048 });

  const reread = await loadWatchConfig(paths);
  assert.equal(reread.fact_store_max_bytes, 2048);
});

test("writeWatchConfig fails closed to DEFAULT_FACT_MAX_BYTES when given an invalid fact_store_max_bytes", async () => {
  const paths = await tempPaths();
  const written = await writeWatchConfig(paths, { enabled: true, fact_store_max_bytes: -5 });
  assert.equal(written.fact_store_max_bytes, DEFAULT_FACT_MAX_BYTES);

  const reread = await loadWatchConfig(paths);
  assert.equal(reread.fact_store_max_bytes, DEFAULT_FACT_MAX_BYTES);
});

test("writeWatchConfig stamps updated_at and normalizeWatchConfig round-trips a valid ISO updated_at", async () => {
  const paths = await tempPaths();
  const written = await writeWatchConfig(paths, { enabled: true }, { now: "2026-09-15T00:00:00.000Z" });
  assert.equal(written.updated_at, "2026-09-15T00:00:00.000Z");

  const reread = await loadWatchConfig(paths);
  assert.equal(reread.updated_at, "2026-09-15T00:00:00.000Z");
});

test("writeWatchConfig is atomic (tmp+rename) and 0o600, mirroring writeLearnedConfig's own discipline", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: false });
  const { configFile } = resolveWatchStorePaths(paths);
  const stat = await fs.stat(configFile);
  assert.equal(stat.mode & 0o777, 0o600);
  // No leftover tmp file.
  const dirEntries = await fs.readdir(path.dirname(configFile));
  assert.deepEqual(dirEntries.filter((name) => name.endsWith(".tmp")), []);
});
