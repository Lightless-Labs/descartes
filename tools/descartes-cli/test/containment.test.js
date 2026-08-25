import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { runContainment } from "../src/containment.js";
import { readContainmentRecommendConfig, resolveContainmentRecommendPaths } from "../src/containment-recommend.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-containment-cli-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("descartes containment recommend status: default OFF with no config file, JSON output carries no raw identifiers", async () => {
  const paths = await tempPaths();
  const outputs = [];
  const result = await runContainment(paths, ["recommend", "status", "--json"], { output: (line) => outputs.push(JSON.parse(line)) });
  assert.equal(result.enabled, false);
  assert.equal(outputs[0].containment_recommend.enabled, false);
  // updated_at is undefined (never configured) and JSON.stringify drops undefined keys.
  assert.deepEqual(Object.keys(outputs[0].containment_recommend).sort(), ["config_path", "enabled"]);
});

test("descartes containment recommend enable: refuses honestly when learned.json monitoring is OFF, config unchanged", async () => {
  const paths = await tempPaths();
  await assert.rejects(
    () => runContainment(paths, ["recommend", "enable"], { output: () => {} }),
    /'descartes learned' monitoring is OFF/,
  );
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, false);
});

test("descartes containment recommend enable: succeeds once learned.json monitoring is ON; does not itself enable monitoring or any execution", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const outputs = [];
  await runContainment(paths, ["recommend", "enable"], { output: (line) => outputs.push(line) });
  assert.match(outputs[0], /Containment recommend-only surface: enabled/);
  assert.match(outputs[0], /never executes a containment action/);
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, true);
});

test("descartes containment recommend: enable/disable round-trip", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await runContainment(paths, ["recommend", "enable"], { output: () => {} });
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, true);

  await runContainment(paths, ["recommend", "disable"], { output: () => {} });
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, false);
});

test("descartes containment recommend: a corrupt-config marker blocks enable/disable writes", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const { configFile } = resolveContainmentRecommendPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{ corrupt", "utf8");

  await assert.rejects(() => runContainment(paths, ["recommend", "enable"], { output: () => {} }), /could not be safely read/);
  await assert.rejects(() => runContainment(paths, ["recommend", "disable"], { output: () => {} }), /could not be safely read/);
});

test("descartes containment recommend status: surfaces a corrupt config as disabled with a warning, never throws", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveContainmentRecommendPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{ corrupt", "utf8");

  const outputs = [];
  await runContainment(paths, ["recommend", "status"], { output: (line) => outputs.push(line) });
  assert.match(outputs[0], /Containment recommend-only surface: disabled/);
  assert.match(outputs[0], /WARNING: containment-recommend\.json was corrupt/);
});

test("descartes containment: unknown subcommand throws, --help prints usage without throwing", async () => {
  const paths = await tempPaths();
  await assert.rejects(() => runContainment(paths, ["bogus"], { output: () => {} }), /Unknown containment subcommand/);
  await assert.rejects(() => runContainment(paths, ["recommend", "bogus"], { output: () => {} }), /Unknown containment recommend subcommand/);

  const outputs = [];
  await runContainment(paths, [], { output: (line) => outputs.push(line) });
  assert.match(outputs[0], /descartes containment recommend/);
});
