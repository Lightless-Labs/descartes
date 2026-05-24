import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { metricPointsFromEvidence, runDaemonIteration } from "../src/daemon.js";
import { buildHistorySummary, readDaemonStatus } from "../src/history-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

function envelope(id, tool, result, status = "ok") {
  return {
    id,
    status,
    layer: "L0",
    source: "test",
    result,
    confidence: 1,
    review_hint: "none",
    trace: { tool, target: null, latency_ms: 0, ts: "2026-05-24T00:00:00.000Z" },
  };
}

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-daemon-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

test("daemon metric extraction keeps compact metrics instead of raw process args", () => {
  const evidence = [
    envelope("system-overview", "collect_system", {
      load_average: [1.5, 1.25, 1],
      uptime_seconds: 100,
      memory: { used_fraction: 0.75, free_bytes: 1024 },
      swap: { used_bytes: 2048 },
    }),
    envelope("top-processes", "collect_processes", {
      top_cpu: [{ command: "node", args: "node --token=secret", cpu_percent: 20, memory_percent: 4, rss_bytes: 1000 }],
      top_memory: [{ command: "postgres", args: "postgres --password secret", cpu_percent: 2, memory_percent: 10, rss_bytes: 5000 }],
    }),
    envelope("disk-usage", "collect_disks", {
      filesystems: [
        { filesystem: "/dev/disk1", mount_point: "/", classification: "apfs_system", pressure_relevant: true, used_fraction: 0.8, available_bytes: 1000 },
        { filesystem: "devfs", mount_point: "/dev", classification: "virtual", pressure_relevant: false, used_fraction: 1, available_bytes: 0 },
      ],
      inodes: [{ filesystem: "/dev/disk1", mount_point: "/", classification: "apfs_system", pressure_relevant: true, used_fraction: 0.2 }],
    }),
  ];

  const points = metricPointsFromEvidence(evidence, { ts: "2026-05-24T00:00:00.000Z" });
  assert(points.some((point) => point.metric_name === "system.load.1m" && point.value === 1.5));
  assert(points.some((point) => point.metric_name === "process.cpu_percent" && point.dimensions.command === "node"));
  assert(points.some((point) => point.metric_name === "process.memory_percent" && point.dimensions.command === "postgres"));
  assert(points.some((point) => point.metric_name === "disk.used_fraction" && point.dimensions.mount_point === "/"));
  assert(!points.some((point) => JSON.stringify(point).includes("--token=secret")));
  assert(!points.some((point) => point.dimensions.mount_point === "/dev"));
});

test("foreground daemon iteration writes metric history and daemon status", async () => {
  const paths = await tempPaths();
  const ts = "2026-05-24T00:00:00.000Z";
  const collectors = {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0.1, 0.2, 0.3],
      uptime_seconds: 10,
      memory: { used_fraction: 0.4, free_bytes: 1234 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };

  const result = await runDaemonIteration(paths, { collectors, ts, now: ts });
  assert(result.points.length >= 5);
  assert.equal(result.status.state, "ok");

  const status = await readDaemonStatus(paths);
  assert.equal(status.points_written, result.points.length);
  assert.deepEqual(status.collector_statuses.map((collector) => collector.id), ["system-overview", "top-processes", "disk-usage"]);

  const summary = await buildHistorySummary(paths, { now: "2026-05-24T00:01:00.000Z", windowMs: 5 * 60 * 1000 });
  assert(summary.metrics.some((metric) => metric.metric_name === "system.memory.used_fraction"));
});
