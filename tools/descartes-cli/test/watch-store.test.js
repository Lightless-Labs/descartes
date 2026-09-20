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

// --- Schema-malformed-but-syntactically-valid JSON (LOW, daybreak-blue re-gate): the file parses
// fine as JSON, but its shape isn't a valid watch.json -- this must still be flagged corrupt:true
// for diagnostic honesty, even though it happens to normalize to the same safe default either
// way. Distinct from the malformed-JSON case above (a JSON.parse syntax failure). ---

test("loadWatchConfig marks corrupt:true for a syntactically-valid but schema-invalid array root ([]), while still failing closed to enabled:true", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveWatchStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, "[]", { mode: 0o600 });

  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, true);
  assert.equal(config.corrupt, true, "an array root is not a valid watch.json shape and must be flagged, even though it still normalizes to the safe default");
});

test("loadWatchConfig marks corrupt:true when enabled is present but not a boolean (e.g. the string \"false\"), while still failing closed to enabled:true", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveWatchStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, JSON.stringify({ enabled: "false" }), { mode: 0o600 });

  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, true, "a non-boolean enabled value is not the literal false, so it still normalizes to this store's safe default");
  assert.equal(config.corrupt, true, "a string \"false\" is an operator typo, not a valid boolean -- must be flagged, not silently accepted");
});

test("loadWatchConfig does NOT mark corrupt:true for a genuinely valid { enabled: false }", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveWatchStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile, JSON.stringify({ enabled: false }), { mode: 0o600 });

  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, false);
  assert.equal(config.corrupt, undefined, "a genuinely valid schema must not be flagged corrupt");
});

test("loadWatchConfig on ENOENT (file absent) still does not mark corrupt:true -- unchanged by the schema-validation addition", async () => {
  const paths = await tempPaths();
  const config = await loadWatchConfig(paths);
  assert.equal(config.enabled, true);
  assert.equal(config.corrupt, undefined);
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
