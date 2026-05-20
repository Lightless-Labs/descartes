import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  aggregateSamples,
  normalizeSamplingRequest,
  readSamplingArtifactEvidence,
  sampleDimensionEvidence,
  samplingArtifactPath,
  writeSamplingArtifact,
} from "../src/tools/sampling.js";

test("normalizeSamplingRequest clamps duration, interval, top_n, and unsupported dimensions", () => {
  const normalized = normalizeSamplingRequest({
    dimension: "disk_io",
    duration_seconds: 999,
    interval_seconds: 0.1,
    top_n: 999,
    aggregation: "summary_and_timeseries_ref",
  });

  assert.equal(normalized.dimension, "load_memory_swap");
  assert.equal(normalized.duration_seconds, 60);
  assert.equal(normalized.interval_seconds, 1);
  assert.equal(normalized.top_n, 20);
  assert.equal(normalized.sample_count, 61);
  assert.equal(normalized.aggregation, "summary_and_timeseries_ref");
  assert.equal(normalized.clamped.dimension, true);
  assert.equal(normalized.clamped.duration_seconds, true);
  assert.equal(normalized.clamped.interval_seconds, true);
  assert.equal(normalized.clamped.top_n, true);
});

test("aggregateSamples summarizes process CPU contributors", () => {
  const summary = aggregateSamples("cpu_processes", [
    { top_cpu: [{ pid: 1, command: "node", args: "node a.js", cpu_percent: 50, memory_percent: 1, rss_bytes: 100 }] },
    { top_cpu: [{ pid: 1, command: "node", args: "node a.js", cpu_percent: 150, memory_percent: 2, rss_bytes: 200 }] },
    { top_cpu: [{ pid: 2, command: "python", args: "python b.py", cpu_percent: 250, memory_percent: 1, rss_bytes: 100 }] },
  ], 2);

  assert.deepEqual(summary.top_contributors_by_average_cpu.map((item) => [item.pid, item.average_cpu_percent, item.peak_cpu_percent, item.observations]), [
    [2, 250, 250, 1],
    [1, 100, 150, 2],
  ]);
});

test("sampleDimensionEvidence collects bounded samples and writes Descartes-owned artifact refs", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "descartes-sampling-test-"));
  try {
    const paths = { cacheDir: path.join(temp, "cache", "descartes") };
    let called = 0;
    const envelope = await sampleDimensionEvidence({
      dimension: "load_memory_swap",
      duration_seconds: 2,
      interval_seconds: 1,
      aggregation: "summary_and_timeseries_ref",
    }, paths, {
      sleepFn: async () => {},
      collectSample: async () => ({
        load_average: [called += 1, 1, 1],
        memory: { used_fraction: called / 10 },
        swap: { used_bytes: called * 1024 },
      }),
    });

    assert.equal(envelope.status, "ok");
    assert.equal(envelope.id, "sample-load_memory_swap");
    assert.equal(envelope.result.sample_count, 3);
    assert.equal(envelope.result.summary.load_1m.max, 3);
    assert.match(envelope.result.artifact.artifact_id, /^sampling-.*\.json$/);
    assert(envelope.result.artifact.path.startsWith(paths.cacheDir));

    const read = await readSamplingArtifactEvidence({ artifact_id: envelope.result.artifact.artifact_id, max_samples: 2 }, paths);
    assert.equal(read.status, "ok");
    assert.equal(read.result.total_samples, 3);
    assert.equal(read.result.returned_samples, 2);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("samplingArtifactPath rejects non-Descartes artifact IDs", () => {
  const paths = { cacheDir: path.join(os.tmpdir(), "descartes-cache") };

  assert.throws(() => samplingArtifactPath(paths, "../../etc/passwd"), /Invalid sampling artifact id/);
  assert.throws(() => samplingArtifactPath(paths, "sampling-not-json.txt"), /Invalid sampling artifact id/);
});

test("writeSamplingArtifact enforces Descartes-owned cache path", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "descartes-sampling-test-"));
  try {
    const artifact = await writeSamplingArtifact({ cacheDir: path.join(temp, "cache", "descartes") }, { samples: [] });
    assert(artifact.path.startsWith(path.join(temp, "cache", "descartes", "sampling")));
    assert.equal(artifact.artifact_id.endsWith(".json"), true);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
