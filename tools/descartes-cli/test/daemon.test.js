import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  daemonServiceStatus,
  installDaemonService,
  metricPointsFromEvidence,
  startDaemonService,
  stopDaemonService,
  resolveDaemonServiceSpec,
  runDaemonIteration,
  uninstallDaemonService,
} from "../src/daemon.js";
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

function fakeRunner(responses, calls = []) {
  return async (command, args) => {
    calls.push([command, ...args]);
    const response = responses.shift() ?? { stdout: "", stderr: "" };
    if (response.error) {
      const error = new Error(response.stderr ?? "command failed");
      error.stdout = response.stdout ?? "";
      error.stderr = response.stderr ?? "";
      error.code = response.code ?? 1;
      throw error;
    }
    return { stdout: response.stdout ?? "", stderr: response.stderr ?? "" };
  };
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

test("daemon install is idempotent for launchd user agents", async () => {
  const paths = await tempPaths();
  const env = { HOME: path.dirname(path.dirname(paths.stateDir)) };
  const options = { platform: "darwin", env, nodePath: "/usr/local/bin/node", cliPath: "/opt/descartes/index.js" };

  const first = await installDaemonService(paths, options);
  const second = await installDaemonService(paths, options);
  assert.equal(first.status, "installed");
  assert.equal(second.status, "unchanged");
  assert.equal(first.install_path, second.install_path);
  assert.match(await fs.readFile(first.install_path, "utf8"), /com\.lightless-labs\.descartes\.daemon/);

  const status = await daemonServiceStatus(paths, options);
  assert.equal(status.status, "installed");
  assert.equal(status.content_matches, true);
});

test("daemon install updates drifted systemd user unit and uninstall is idempotent", async () => {
  const paths = await tempPaths();
  const options = {
    platform: "linux",
    env: {
      XDG_CONFIG_HOME: path.dirname(paths.configDir),
      XDG_DATA_HOME: path.dirname(paths.dataDir),
      XDG_STATE_HOME: path.dirname(paths.stateDir),
      XDG_CACHE_HOME: path.dirname(paths.cacheDir),
    },
    nodePath: "/usr/bin/node",
    cliPath: "/opt/descartes/index.js",
  };

  const spec = resolveDaemonServiceSpec(paths, options);
  await fs.mkdir(path.dirname(spec.install_path), { recursive: true });
  await fs.writeFile(spec.install_path, "drifted");

  assert.equal((await daemonServiceStatus(paths, options)).status, "drifted");
  const updated = await installDaemonService(paths, options);
  assert.equal(updated.status, "updated");
  assert.match(await fs.readFile(spec.install_path, "utf8"), /ExecStart='\/usr\/bin\/node' '\/opt\/descartes\/index\.js' 'daemon' 'run' '--foreground'/);
  assert.match(await fs.readFile(spec.install_path, "utf8"), /Environment="XDG_STATE_HOME=/);

  const uninstallOptions = {
    ...options,
    runner: fakeRunner([{ stderr: "Unit descartes.service not loaded.", error: true, code: 1 }]),
  };
  const removed = await uninstallDaemonService(paths, uninstallOptions);
  assert.equal(removed.status, "removed");
  assert.equal(removed.stop.status, "not_running");
  assert.equal((await uninstallDaemonService(paths, uninstallOptions)).status, "not_installed");
});

test("daemon start and stop use idempotent launchd user lifecycle commands", async () => {
  const paths = await tempPaths();
  const env = { HOME: path.dirname(path.dirname(paths.stateDir)) };
  const calls = [];
  const options = {
    platform: "darwin",
    env,
    uid: 501,
    nodePath: "/usr/local/bin/node",
    cliPath: "/opt/descartes/index.js",
    runner: fakeRunner([
      { stderr: "Bootstrap failed: 5: Input/output error: Service is already loaded", error: true, code: 5 },
      { stderr: "Boot-out failed: 3: No such process", error: true, code: 3 },
    ], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "already_running");
  assert.deepEqual(calls[0], ["launchctl", "bootstrap", "gui/501", started.install_path]);

  const stopped = await stopDaemonService(paths, options);
  assert.equal(stopped.status, "not_running");
  assert.deepEqual(calls[1], ["launchctl", "bootout", "gui/501/com.lightless-labs.descartes.daemon"]);
});

test("daemon start, stop, and runtime status use systemd user lifecycle commands", async () => {
  const paths = await tempPaths();
  const calls = [];
  const options = {
    platform: "linux",
    env: {
      XDG_CONFIG_HOME: path.dirname(paths.configDir),
      XDG_DATA_HOME: path.dirname(paths.dataDir),
      XDG_STATE_HOME: path.dirname(paths.stateDir),
      XDG_CACHE_HOME: path.dirname(paths.cacheDir),
    },
    nodePath: "/usr/bin/node",
    cliPath: "/opt/descartes/index.js",
    runner: fakeRunner([
      {},
      {},
      { stdout: "active\n" },
      { stdout: "enabled\n" },
      {},
    ], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "started");
  assert.equal(started.install_status, "installed");
  assert.equal(started.running, true);
  assert.deepEqual(calls[0], ["systemctl", "--user", "daemon-reload"]);
  assert.deepEqual(calls[1], ["systemctl", "--user", "enable", "--now", "descartes.service"]);

  const status = await daemonServiceStatus(paths, options);
  assert.equal(status.running, true);
  assert.equal(status.enabled, true);
  assert.deepEqual(calls[2], ["systemctl", "--user", "is-active", "descartes.service"]);
  assert.deepEqual(calls[3], ["systemctl", "--user", "is-enabled", "descartes.service"]);

  const stopped = await stopDaemonService(paths, options);
  assert.equal(stopped.status, "stopped");
  assert.equal(stopped.running, false);
  assert.deepEqual(calls[4], ["systemctl", "--user", "disable", "--now", "descartes.service"]);
});
