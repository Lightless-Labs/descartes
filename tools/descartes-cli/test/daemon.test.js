import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  collectDaemonEvidence,
  collectStructuralEvidence,
  daemonServiceStatus,
  defaultDaemonProfile,
  DEFAULT_STRUCTURAL_INTERVAL_MS,
  DEFAULT_STRUCTURAL_TICK_DEADLINE_MS,
  installDaemonService,
  metricPointsFromEvidence,
  parseLaunchdPrintState,
  readStructuralCheckpoint,
  resolveStructuralCheckpointPath,
  startDaemonService,
  stopDaemonService,
  renderDaemonResult,
  resolveDaemonServiceSpec,
  runDaemonIteration,
  runForegroundDaemonLoop,
  uninstallDaemonService,
  validateDaemonProfile,
  writeStructuralCheckpoint,
} from "../src/daemon.js";
import { buildConstraintTarget, writeConstraints, writeLearnedConfig } from "../src/constraint-store.js";
import { appendFactPoints, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { buildHistorySummary, readDaemonStatus } from "../src/history-store.js";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { readAlertRecords } from "../src/alert-store.js";
import { readShadowRecords, resolveShadowStorePaths } from "../src/shadow-store.js";
import { DELETED_EXE_RULE_ID, PUBLIC_BIND_RULE_ID } from "../src/tools/provenance-warnings.js";
import { UNKNOWN_IDENTITY_RULE_ID, reconcileSignatures, writeSignatureStore } from "../src/provenance-store.js";

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
  assert.equal(first.content, undefined);
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

test("launchd print state parser extracts runtime state", () => {
  assert.equal(parseLaunchdPrintState("\tstate = running\n"), "running");
  assert.equal(parseLaunchdPrintState("state = SIGTERMed\n"), "SIGTERMed");
  assert.equal(parseLaunchdPrintState("no state here"), undefined);
});

test("daemon start treats an already running launchd service as idempotent before bootstrap", async () => {
  const paths = await tempPaths();
  const env = { HOME: path.dirname(path.dirname(paths.stateDir)) };
  const calls = [];
  const options = {
    platform: "darwin",
    env,
    uid: 501,
    nodePath: "/usr/local/bin/node",
    cliPath: "/opt/descartes/index.js",
    runner: fakeRunner([{ stdout: "state = running\n" }], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "already_running");
  assert.deepEqual(calls, [["launchctl", "print", "gui/501/com.lightless-labs.descartes.daemon"]]);
});

test("daemon start clears stale non-running launchd state before bootstrap", async () => {
  const paths = await tempPaths();
  const env = { HOME: path.dirname(path.dirname(paths.stateDir)) };
  const calls = [];
  const options = {
    platform: "darwin",
    env,
    uid: 501,
    nodePath: "/usr/local/bin/node",
    cliPath: "/opt/descartes/index.js",
    sleep: async () => {},
    runner: fakeRunner([
      { stdout: "state = SIGTERMed\n" },
      {},
      { stderr: "Could not find service", error: true, code: 113 },
      {},
    ], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "started");
  assert.deepEqual(calls.map((call) => call.slice(0, 2)), [
    ["launchctl", "print"],
    ["launchctl", "bootout"],
    ["launchctl", "print"],
    ["launchctl", "bootstrap"],
  ]);
});

test("daemon start recognizes generic launchd bootstrap I/O errors when the service is running", async () => {
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
      { stderr: "Could not find service", error: true, code: 113 },
      { stderr: "Bootstrap failed: 5: Input/output error", error: true, code: 5 },
      { stdout: "state = running\n" },
    ], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "already_running");
  assert.equal(started.running, true);
  assert.deepEqual(calls.map((call) => call.slice(0, 2)), [
    ["launchctl", "print"],
    ["launchctl", "bootstrap"],
    ["launchctl", "print"],
  ]);
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
      { stderr: "Could not find service", error: true, code: 113 },
      { stderr: "Bootstrap failed: 5: Input/output error: Service is already loaded", error: true, code: 5 },
      { stdout: "state = running\n" },
      { stderr: "Boot-out failed: 3: No such process", error: true, code: 3 },
    ], calls),
  };

  const started = await startDaemonService(paths, options);
  assert.equal(started.status, "already_running");
  assert.deepEqual(calls[1], ["launchctl", "bootstrap", "gui/501", started.install_path]);

  const stopped = await stopDaemonService(paths, options);
  assert.equal(stopped.status, "not_running");
  assert.deepEqual(calls[3], ["launchctl", "bootout", "gui/501/com.lightless-labs.descartes.daemon"]);
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

test("foreground daemon loop schedules repeated iterations without waiting on real time", async () => {
  const paths = await tempPaths();
  const sleeps = [];
  const outputs = [];
  let iterations = 0;

  await runForegroundDaemonLoop(paths, {
    intervalMs: 1234,
    iterate: async (iterationPaths, iterationOptions) => {
      assert.equal(iterationPaths, paths);
      assert.equal(iterationOptions.mode, "foreground");
      iterations += 1;
      return {
        points: Array.from({ length: iterations }),
        status: { ts: `2026-05-24T00:00:0${iterations}.000Z` },
      };
    },
    sleep: async (ms, _value, sleepOptions) => {
      sleeps.push({ ms, ref: sleepOptions.ref });
    },
    shouldStop: () => iterations >= 3,
    output: (line) => outputs.push(JSON.parse(line)),
  });

  assert.equal(iterations, 3);
  assert.deepEqual(sleeps, [{ ms: 1234, ref: true }, { ms: 1234, ref: true }]);
  assert.deepEqual(outputs.map((output) => output.points_written), [1, 2, 3]);
});

test("daemon lifecycle renderer is human-readable and omits service file content", () => {
  const output = renderDaemonResult("install", {
    status: "installed",
    service_manager: "launchd-user",
    label: "com.lightless-labs.descartes.daemon",
    install_path: "/Users/alice/Library/LaunchAgents/com.lightless-labs.descartes.daemon.plist",
    log_dir: "/Users/alice/.local/state/descartes/daemon",
    content: "<plist>should never be printed</plist>",
  });
  assert.match(output, /Descartes daemon installed\./);
  assert.match(output, /Service manager: launchd-user/);
  assert.match(output, /Next: run `descartes daemon start`/);
  assert(!output.includes("<plist>"));
});

// --- Slice S6a: structural (services/network/scheduled-jobs) collection cadence ---

function fastCollectorFakes() {
  return {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0, 0, 0],
      uptime_seconds: 1,
      memory: { used_fraction: 0.1, free_bytes: 1 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

function structuralCollectorFakes(calls = []) {
  return {
    services: async () => {
      calls.push("services");
      return envelope("services", "collect_services", { manager: "systemd", services: [] });
    },
    network: async () => {
      calls.push("network");
      return envelope("network-basics", "collect_network", { listening_sockets: [] });
    },
    "scheduled-jobs": async () => {
      calls.push("scheduled-jobs");
      return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] });
    },
  };
}

function structuralCollectorFakesWithFacts(calls = []) {
  return {
    services: async () => {
      calls.push("services");
      return envelope("services", "collect_services", {
        manager: "systemd",
        services: [{ name: "nginx.service", running: true }],
      });
    },
    network: async () => {
      calls.push("network");
      return envelope("network-basics", "collect_network", {
        listening_sockets: [{ protocol: "tcp", state: "LISTEN", local_address: "0.0.0.0", local_port: 8080 }],
      });
    },
    "scheduled-jobs": async () => {
      calls.push("scheduled-jobs");
      return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] });
    },
  };
}

function structuralProfile(overrides = {}) {
  return {
    interval_ms: 60000,
    collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
    structural: {
      interval_ms: 3600000,
      collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true } },
      ...overrides,
    },
  };
}

test("defaultDaemonProfile includes an hourly structural cadence with the documented default collectors", () => {
  const profile = defaultDaemonProfile();
  assert.equal(profile.structural.interval_ms, DEFAULT_STRUCTURAL_INTERVAL_MS);
  assert.equal(DEFAULT_STRUCTURAL_INTERVAL_MS, 60 * 60 * 1000);
  assert.equal(DEFAULT_STRUCTURAL_TICK_DEADLINE_MS, 45 * 1000);
  assert.deepEqual(Object.keys(profile.structural.collectors).sort(), ["network", "provenance", "scheduled-jobs", "services", "sessions"]);
  assert(profile.structural.collectors.services.enabled);
  assert(profile.structural.collectors.network.enabled);
  assert(profile.structural.collectors["scheduled-jobs"].enabled);
  // Slice S4 sibling-default consistency (plan section 4): provenance defaults true, matching
  // its three siblings exactly — still gated end-to-end by the outer learned.json kill switch.
  assert(profile.structural.collectors.provenance.enabled);
  // Slice 1 (observed-incident collectors plan) sibling-default consistency: sessions defaults
  // true, matching its siblings exactly — still gated end-to-end by the outer learned.json kill
  // switch, and this collector itself never emits an alert candidate (pure L0 fact source).
  assert(profile.structural.collectors.sessions.enabled);
});

test("validateDaemonProfile accepts default and structural-less profiles, rejects malformed ones", () => {
  assert.doesNotThrow(() => validateDaemonProfile(defaultDaemonProfile()));

  const structuralLess = { interval_ms: 60000, collectors: { system: { enabled: true } } };
  assert.doesNotThrow(() => validateDaemonProfile(structuralLess));

  assert.throws(() => validateDaemonProfile({ collectors: {} }), /interval_ms/);
  assert.throws(() => validateDaemonProfile({ interval_ms: "60000", collectors: {} }), /interval_ms/);
  assert.throws(() => validateDaemonProfile({ interval_ms: 60000, collectors: null }), /collectors/);
  assert.throws(() => validateDaemonProfile({ interval_ms: 60000, collectors: [] }), /collectors/);
  assert.throws(
    () => validateDaemonProfile({ interval_ms: 60000, collectors: {}, structural: { collectors: {} } }),
    /structural\.interval_ms/,
  );
  assert.throws(
    () => validateDaemonProfile({ interval_ms: 60000, collectors: {}, structural: { interval_ms: 3600000, collectors: null } }),
    /structural\.collectors/,
  );
  assert.throws(
    () => validateDaemonProfile({
      interval_ms: 60000,
      collectors: {},
      structural: { interval_ms: 3600000, collectors: {}, deadline_ms: -1 },
    }),
    /structural\.deadline_ms/,
  );
});

test("collectStructuralEvidence calls only enabled structural collectors in a stable order", async () => {
  const calls = [];
  const collectors = structuralCollectorFakes(calls);

  const evidence = await collectStructuralEvidence(
    { collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true } } },
    collectors,
  );
  assert.deepEqual(calls, ["services", "network", "scheduled-jobs"]);
  assert.deepEqual(evidence.map((e) => e.id), ["services", "network-basics", "scheduled-jobs"]);

  calls.length = 0;
  const noneEnabled = await collectStructuralEvidence({}, collectors);
  assert.deepEqual(calls, []);
  assert.deepEqual(noneEnabled, []);

  calls.length = 0;
  const onlyNetwork = await collectStructuralEvidence(
    { collectors: { services: { enabled: false }, network: { enabled: true }, "scheduled-jobs": { enabled: false } } },
    collectors,
  );
  assert.deepEqual(calls, ["network"]);
  assert.deepEqual(onlyNetwork.map((e) => e.id), ["network-basics"]);
});

test("collectDaemonEvidence and metricPointsFromEvidence remain untouched by structural additions", async () => {
  const calls = [];
  const collectors = {
    system: async () => { calls.push("system"); return fastCollectorFakes().system(); },
    processes: async () => { calls.push("processes"); return fastCollectorFakes().processes(); },
    disks: async () => { calls.push("disks"); return fastCollectorFakes().disks(); },
  };
  const evidence = await collectDaemonEvidence(defaultDaemonProfile(), collectors);
  assert.deepEqual(calls, ["system", "processes", "disks"]);
  assert.deepEqual(evidence.map((e) => e.id), ["system-overview", "top-processes", "disk-usage"]);
  const points = metricPointsFromEvidence(evidence, { ts: "2026-05-24T00:00:00.000Z" });
  assert(points.some((point) => point.metric_name === "system.load.1m"));
});

test("structural checkpoint path stays under stateDir/daemon and passes the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const checkpointFile = resolveStructuralCheckpointPath(paths);
  assert.equal(checkpointFile, path.join(paths.stateDir, "daemon", "structural-checkpoint.json"));
  assert.doesNotThrow(() => assertNoPiOwnedPath({ structuralCheckpointFile: checkpointFile }));
});

test("structural checkpoint round-trips, defaults on ENOENT, and tolerates corruption", async () => {
  const paths = await tempPaths();

  const missing = await readStructuralCheckpoint(paths);
  assert.equal(missing.last_structural_run_ms, undefined);

  const written = await writeStructuralCheckpoint(paths, { last_structural_run_ms: 123456, now: "2026-05-24T00:00:00.000Z" });
  assert.equal(written.last_structural_run_ms, 123456);
  assert.equal(written.updated_at, "2026-05-24T00:00:00.000Z");

  const readBack = await readStructuralCheckpoint(paths);
  assert.equal(readBack.last_structural_run_ms, 123456);

  const file = resolveStructuralCheckpointPath(paths);
  await fs.writeFile(file, "{not json", { mode: 0o600 });
  const corrupt = await readStructuralCheckpoint(paths);
  assert.equal(corrupt.last_structural_run_ms, undefined);
});

test("runDaemonIteration with a structural-less profile writes no structural checkpoint and no structural status key", async () => {
  const paths = await tempPaths();
  const ts = "2026-05-24T00:00:00.000Z";
  const profile = { interval_ms: 60000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } };

  const result = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), ts, now: ts, evaluateAlerts: false });
  assert(!("structural_collector_statuses" in result.status));
  assert.equal(result.structuralEvidence, undefined);

  await assert.rejects(() => fs.access(resolveStructuralCheckpointPath(paths)));
});

test("default profile's structural block is inert without the learned.json kill switch (byte-identical fast path)", async () => {
  const paths = await tempPaths();
  const ts = "2026-05-24T00:00:00.000Z";
  const neverCallStructural = {
    services: async () => { throw new Error("structural collector must not run when the kill switch is off"); },
    network: async () => { throw new Error("structural collector must not run when the kill switch is off"); },
    "scheduled-jobs": async () => { throw new Error("structural collector must not run when the kill switch is off"); },
  };

  const result = await runDaemonIteration(paths, {
    collectors: fastCollectorFakes(),
    structuralCollectors: neverCallStructural,
    ts,
    now: ts,
    evaluateAlerts: false,
  });

  assert(!("structural_collector_statuses" in result.status));
  assert.equal(result.structuralEvidence, undefined);
  assert.deepEqual(
    Object.keys(result.status).sort(),
    ["collector_statuses", "mode", "points_written", "profile", "retention", "state", "ts"].sort(),
  );

  await assert.rejects(() => fs.access(resolveStructuralCheckpointPath(paths)));
});

test("structural collection runs only when wall-clock due, using an injected checkpoint store", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];
  let storedCheckpoint;
  const baseOptions = {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakes(structuralCalls),
    evaluateAlerts: false,
    readStructuralCheckpoint: async () => storedCheckpoint ?? { last_structural_run_ms: undefined },
    writeStructuralCheckpoint: async (_paths, checkpoint) => {
      storedCheckpoint = { last_structural_run_ms: checkpoint.last_structural_run_ms };
      return storedCheckpoint;
    },
    loadLearnedConfig: async () => ({ enabled: true }),
  };

  // First tick: no checkpoint yet -> due, runs structural collection.
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T00:00:00.000Z", now: 0 });
  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs"]);
  assert.equal(storedCheckpoint.last_structural_run_ms, 0);

  // Second tick, well under the structural interval -> not due, no structural calls.
  structuralCalls.length = 0;
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T00:00:30.000Z", now: 30000 });
  assert.deepEqual(structuralCalls, []);
  assert.equal(storedCheckpoint.last_structural_run_ms, 0);

  // Repeated calls within the same sub-threshold window still don't re-run (monotonic checkpoint).
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T00:00:31.000Z", now: 31000 });
  assert.deepEqual(structuralCalls, []);

  // Third tick, at/after the structural interval -> due again, runs exactly once.
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T01:00:00.000Z", now: 3600000 });
  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs"]);
  assert.equal(storedCheckpoint.last_structural_run_ms, 3600000);
});

test("a large wall-clock gap triggers exactly one catch-up structural collection, not a backlog storm", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];
  let storedCheckpoint = { last_structural_run_ms: 0 };
  const baseOptions = {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakes(structuralCalls),
    evaluateAlerts: false,
    readStructuralCheckpoint: async () => storedCheckpoint,
    writeStructuralCheckpoint: async (_paths, checkpoint) => {
      storedCheckpoint = { last_structural_run_ms: checkpoint.last_structural_run_ms };
      return storedCheckpoint;
    },
    loadLearnedConfig: async () => ({ enabled: true }),
  };

  // Simulate the process being "down" for 3x the structural interval.
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T03:00:00.000Z", now: 3 * 3600000 });
  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs"]);
  assert.equal(storedCheckpoint.last_structural_run_ms, 3 * 3600000);

  // The very next tick a minute later must not re-run (checkpoint caught up to "now", not to a backlog of missed slots).
  structuralCalls.length = 0;
  await runDaemonIteration(paths, { ...baseOptions, ts: "2026-05-24T03:01:00.000Z", now: 3 * 3600000 + 60000 });
  assert.deepEqual(structuralCalls, []);
});

test("writeDaemonStatus includes structural_collector_statuses only on a structural-due tick, with the correct shape", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakes(),
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 0,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.deepEqual(result.status.structural_collector_statuses, [
    { id: "services", status: "ok", tool: "collect_services" },
    { id: "network-basics", status: "ok", tool: "collect_network" },
    { id: "scheduled-jobs", status: "ok", tool: "collect_scheduled_jobs" },
  ]);
});

test("a hung structural collector is bounded by its deadline, marked unable, and still advances the checkpoint", async () => {
  const paths = await tempPaths();
  const structuralCollectors = {
    services: async () => envelope("services", "collect_services", { manager: "systemd", services: [] }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: [] }),
    "scheduled-jobs": () => new Promise(() => {}), // never resolves
  };
  let storedCheckpoint;

  const start = Date.now();
  const result = await runDaemonIteration(paths, {
    profile: structuralProfile({ deadline_ms: 25 }),
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 1000,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async (_paths, checkpoint) => {
      storedCheckpoint = checkpoint;
      return checkpoint;
    },
    loadLearnedConfig: async () => ({ enabled: true }),
  });
  const elapsedMs = Date.now() - start;

  assert(elapsedMs < 2000, `expected the structural tick to be bounded by its deadline, took ${elapsedMs}ms`);
  assert.deepEqual(result.status.structural_collector_statuses, [
    { status: "unable", error: "structural_tick_deadline_exceeded" },
  ]);
  assert.equal(result.structuralEvidence, undefined);
  assert.equal(storedCheckpoint.last_structural_run_ms, 1000);
});

test("a structural tick that completes well within its deadline is unaffected by the deadline machinery", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: structuralProfile({ deadline_ms: 5000 }),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakes(),
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 0,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.equal(result.status.structural_collector_statuses.length, 3);
  assert(result.status.structural_collector_statuses.every((entry) => entry.status === "ok"));
});

test("kill switch: structural collection is skipped entirely while learned.json enabled is false, even when due", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];

  // Force "due" unambiguously via a real (uninjected) checkpoint far in the past.
  await writeStructuralCheckpoint(paths, { last_structural_run_ms: 0, now: "2026-05-24T00:00:00.000Z" });

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakes(structuralCalls),
    evaluateAlerts: false,
    ts: "2026-05-25T00:00:00.000Z",
    now: 24 * 3600000,
    // loadLearnedConfig intentionally not injected: defaults to real constraint-store.js
    // behavior, which is enabled:false when configDir/learned.json is absent.
  });

  assert.deepEqual(structuralCalls, []);
  assert.equal(result.structuralEvidence, undefined);
  assert(!("structural_collector_statuses" in result.status));

  const checkpointAfter = await readStructuralCheckpoint(paths);
  assert.equal(checkpointAfter.last_structural_run_ms, 0, "checkpoint must not advance while the kill switch is off");
});

// --- Slice S6b, additive follow-up: structural evidence -> fact-points -> facts.jsonl ---

test("S6b wiring: structural evidence is translated into fact-points and persisted to facts.jsonl only when structural collection succeeds and the kill switch is enabled", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    // Non-zero `now`: history-store.js-style retention helpers treat `options.now ? … :
    // Date.now()` as falsy-zero-means-"not provided" (mirrored verbatim in fact-store.js's
    // enforceFactRetention) — `now: 0` would fall back to the real wall clock and age these
    // fixture facts out of the default 30-day retention window immediately.
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.notEqual(result.structuralFacts, undefined);
  assert.equal(result.structuralFacts.written_count, 2);

  const { points } = await readFactPoints(paths);
  assert.equal(points.length, 2);
  assert(points.some((point) => point.fact_name === "service.presence" && point.entity_key === "nginx.service"));
  assert(points.some((point) => point.fact_name === "network.listening_port.owner" && point.entity_key === "tcp:0.0.0.0:8080"));
});

test("S6b wiring: no fact-points are persisted while the learned.json kill switch is off, even with populated structural evidence available", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    ts: "2026-05-24T00:00:00.000Z",
    now: 0,
    evaluateAlerts: false,
    // loadLearnedConfig intentionally not injected: defaults to real constraint-store.js
    // behavior, which is enabled:false when configDir/learned.json is absent.
  });

  assert.equal(result.structuralFacts, undefined);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

test("S6b wiring: a timed-out structural tick discards its evidence entirely — no fact-points are persisted for a partial/timed-out tick", async () => {
  const paths = await tempPaths();
  const structuralCollectors = {
    services: async () => envelope("services", "collect_services", {
      manager: "systemd",
      services: [{ name: "nginx.service", running: true }],
    }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: [] }),
    "scheduled-jobs": () => new Promise(() => {}), // never resolves
  };

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile({ deadline_ms: 25 }),
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 1000,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.equal(result.structuralEvidence, undefined);
  assert.equal(result.structuralFacts, undefined);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

test("S6b wiring: no fact-points are persisted when profile.structural is absent (regression, matches S6a's byte-identical-fast-path guarantee)", async () => {
  const paths = await tempPaths();
  const ts = "2026-05-24T00:00:00.000Z";
  const profile = { interval_ms: 60000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } };

  const result = await runDaemonIteration(paths, { profile, collectors: fastCollectorFakes(), ts, now: ts, evaluateAlerts: false });
  assert.equal(result.structuralFacts, undefined);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

// --- Slice S7a, additive: evaluateAndLogShadowConstraints wired into the structural tick ---

function shadowConstraintFixture(overrides = {}) {
  return {
    id: "constraint.mined.service-presence.deadbeefdeadbeef",
    kind: "constraint",
    family: "service-presence",
    target: buildConstraintTarget("service.presence", "nginx.service"),
    expected: { comparator: "eq", value: "true" },
    status: "shadow",
    confidence: 1,
    provenance: { window: "7d", samples: 5, source_collectors: ["services"], mined_at: "2026-05-24T00:00:00.000Z" },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [{ ts: "2026-05-24T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" }],
    first_observed: "2026-05-24T00:00:00.000Z",
    last_verified: "2026-05-24T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

test("S7a wiring: with zero shadow constraints, a structural tick produces no shadow-violations.jsonl file (cheap no-op, byte-identical to pre-S7a)", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.equal(result.shadowEvaluation.evaluated_count, 0);
  assert.equal(result.shadowEvaluation.appended_count, 0);
  await assert.rejects(() => fs.access(resolveShadowStorePaths(paths).shadowViolationsFile));
});

test("S7a wiring: with one shadow constraint and a matching fact, exactly one shadow-violations.jsonl record is appended per structural tick", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [shadowConstraintFixture()]);

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(), // service "nginx.service" running:true
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.equal(result.shadowEvaluation.evaluated_count, 1);
  assert.equal(result.shadowEvaluation.appended_count, 1);
  assert.equal(result.shadowEvaluation.fired_count, 0); // running:"true" matches expected "true" -> satisfied, not fired

  const { records } = await readShadowRecords(paths);
  assert.equal(records.length, 1);
  assert.equal(records[0].constraint_id, "constraint.mined.service-presence.deadbeefdeadbeef");
  assert.equal(records[0].fired, false);
});

test("S7a wiring: reuses the S6a structural-tick gate (structuralDue, kill switch) — no shadow evaluation runs while the kill switch is off, even with a shadow constraint present", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [shadowConstraintFixture()]);

  const result = await runDaemonIteration(paths, {
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    evaluateAlerts: false,
    // loadLearnedConfig intentionally not injected: defaults to real constraint-store.js
    // behavior, which is enabled:false when configDir/learned.json is absent.
  });

  assert.equal(result.shadowEvaluation, undefined);
  await assert.rejects(() => fs.access(resolveShadowStorePaths(paths).shadowViolationsFile));
});

test("S7a wiring: shadow evaluation only runs on a successful (non-timed-out) structural tick", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [shadowConstraintFixture()]);
  const structuralCollectors = {
    services: async () => envelope("services", "collect_services", { manager: "systemd", services: [] }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: [] }),
    "scheduled-jobs": () => new Promise(() => {}), // never resolves
  };

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile({ deadline_ms: 25 }),
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 1000,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.equal(result.shadowEvaluation, undefined);
  await assert.rejects(() => fs.access(resolveShadowStorePaths(paths).shadowViolationsFile));
});

test("S7a wiring: over N simulated structural ticks spanning multiple days, one shadow coverage record accrues per tick (daily observation coverage, no human action required)", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [shadowConstraintFixture()]);

  const profile = structuralProfile({ interval_ms: 24 * 3600000 }); // one structural tick per day
  let simulatedNowMs = 0;
  for (let tick = 0; tick < 3; tick += 1) {
    await runDaemonIteration(paths, {
      profile,
      collectors: fastCollectorFakes(),
      structuralCollectors: structuralCollectorFakesWithFacts(),
      evaluateAlerts: false,
      ts: new Date(simulatedNowMs).toISOString(),
      now: simulatedNowMs,
      loadLearnedConfig: async () => ({ enabled: true }),
    });
    simulatedNowMs += profile.structural.interval_ms;
  }

  const { records } = await readShadowRecords(paths);
  assert.equal(records.length, 3, "one shadow-violations.jsonl record must accrue per structural tick, unattended");
});

test("S7a load-bearing safety regression: a shadow constraint that would obviously fire never produces an alert candidate, never touches alerts.json", async () => {
  const paths = await tempPaths();
  // A shadow constraint whose fixed rule is obviously violated by the fixture facts below
  // (running:"false" vs expected "true") — if shadow evaluation were ever mis-wired into the
  // real alert pipeline, this would show up as an alert.
  await writeConstraints(paths, [shadowConstraintFixture({ target: buildConstraintTarget("service.presence", "nginx.service") })]);
  const structuralCollectorsViolating = {
    services: async () => envelope("services", "collect_services", {
      manager: "systemd",
      services: [{ name: "nginx.service", running: false }],
    }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: [] }),
    "scheduled-jobs": async () => envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] }),
  };

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorsViolating,
    evaluateAlerts: true, // deliberately exercise the real alert pipeline, not bypass it
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  // The shadow record itself does fire (proves the fixture is meaningful, not a false negative).
  assert.equal(result.shadowEvaluation.fired_count, 1);
  const { records } = await readShadowRecords(paths);
  assert.equal(records[0].fired, true);

  // ...but it structurally cannot reach the real alert pipeline: zero alert candidates
  // reference the constraint, and the persisted alert store contains nothing derived from it.
  assert.equal(result.alerts.candidates.length, 0);
  const persistedAlerts = await readAlertRecords(paths);
  assert.equal(persistedAlerts.length, 0);
});

test("runForegroundDaemonLoop performs structural collection at the expected cadence across many iterations", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const structuralCalls = [];
  const profile = structuralProfile({ interval_ms: 5 * 60000 });
  let simulatedNowMs = 0;
  let fastTicks = 0;
  const outputs = [];

  await runForegroundDaemonLoop(paths, {
    intervalMs: profile.interval_ms,
    sleep: async () => {},
    shouldStop: () => fastTicks >= 12,
    output: (line) => outputs.push(JSON.parse(line)),
    iterate: async (iterationPaths) => {
      fastTicks += 1;
      const ts = new Date(simulatedNowMs).toISOString();
      const result = await runDaemonIteration(iterationPaths, {
        profile,
        collectors: fastCollectorFakes(),
        structuralCollectors: structuralCollectorFakes(structuralCalls),
        evaluateAlerts: false,
        ts,
        now: simulatedNowMs,
      });
      simulatedNowMs += profile.interval_ms;
      return result;
    },
  });

  // 12 fast ticks at 60s each span 0..660000ms; structural (every 300000ms) is due at ticks
  // 1 (now=0, no checkpoint), 6 (now=300000), and 11 (now=600000) -> exactly 3 structural runs.
  assert.equal(fastTicks, 12);
  assert.equal(outputs.length, 12);
  assert.equal(structuralCalls.filter((call) => call === "services").length, 3);
  assert.equal(structuralCalls.length, 9);
});

// --- Slice S-live-1, additive: active constraints wired into the real (evaluateAndPersistAlerts) path ---

function activeConstraintFixture(overrides = {}) {
  return {
    id: "constraint.mined.service-presence.cafebabecafebabe",
    kind: "constraint",
    family: "service-presence",
    target: buildConstraintTarget("service.presence", "nginx.service"),
    expected: { comparator: "eq", value: "true" },
    status: "active",
    confidence: 1,
    provenance: { window: "7d", samples: 5, source_collectors: ["services"], mined_at: "2026-05-24T00:00:00.000Z" },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [
      { ts: "2026-05-22T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" },
      { ts: "2026-05-23T00:00:00.000Z", from: "shadow", to: "review-ready", actor: "deterministic-gate", note: "soak complete" },
      { ts: "2026-05-24T00:00:00.000Z", from: "review-ready", to: "active", actor: "human:alice", note: "approved" },
    ],
    first_observed: "2026-05-22T00:00:00.000Z",
    last_verified: "2026-05-24T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

const S_LIVE_1_TICK_TS = "2026-05-24T00:00:00.000Z";

// A structural-less profile (mirrors the pre-existing "structural-less profile" tests above):
// keeps this slice's assertions decoupled from the S6a structural-tick cadence entirely, since
// the design requires active-constraint evaluation to run every daemon tick, not just on a
// structural-due tick.
function slice6Profile() {
  return { interval_ms: 60000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } } };
}

function runIsolatedDaemonTick(paths, ts = S_LIVE_1_TICK_TS) {
  return runDaemonIteration(paths, { profile: slice6Profile(), collectors: fastCollectorFakes(), ts, now: ts });
}

test("S-live-1: byte-identical real alerts when the learned kill switch is off, even with a violated active constraint and a matching current fact present", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withConstraintPaths = await tempPaths();
  await writeConstraints(withConstraintPaths, [activeConstraintFixture()]);
  await appendFactPoints(withConstraintPaths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });
  // configDir/learned.json intentionally never written here -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the pre-S-live-1 baseline above.
  const withConstraint = await runIsolatedDaemonTick(withConstraintPaths);

  assert.deepEqual(withConstraint.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withConstraint.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withConstraint.alerts.notification_due_ids, baseline.alerts.notification_due_ids);

  const persisted = await readAlertRecords(withConstraintPaths);
  assert.equal(persisted.some((alert) => alert.rule_id.startsWith("constraint.violation.")), false);
});

test("S-live-1: byte-identical real alerts when learned is enabled but there are zero active constraints", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const enabledPaths = await tempPaths();
  await writeLearnedConfig(enabledPaths, { enabled: true });
  // No constraints.json written at all -> loadConstraints() resolves { constraints: [] }.
  const enabled = await runIsolatedDaemonTick(enabledPaths);

  assert.deepEqual(enabled.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(enabled.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(enabled.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
});

test("S-live-1: an active constraint violated by a current fact produces a real alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  const constraintAlert = result.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "expected a real alert for the violated active constraint");
  assert.equal(constraintAlert.status, "active");
  assert.equal(constraintAlert.fingerprint, activeConstraintFixture().id);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((alert) => alert.id === constraintAlert.id && alert.status === "active"));
});

test("S-live-1: an active constraint whose target has no current fact does not fire (no fact, no claim)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  // No facts.jsonl at all -> readFactPoints returns an empty set -> factLookup(target) is undefined.

  const result = await runIsolatedDaemonTick(paths);
  assert.equal(result.alerts.alerts.some((alert) => alert.rule_id === "constraint.violation.service-presence"), false);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

test("S-live-1: a satisfied active constraint does not fire", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "true" } }, // satisfies expected "true"
  ], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  assert.equal(result.alerts.alerts.some((alert) => alert.rule_id === "constraint.violation.service-presence"), false);
  const persisted = await readAlertRecords(paths);
  assert.equal(persisted.some((alert) => alert.rule_id.startsWith("constraint.violation.")), false);
});

test("S-live-1: draft, shadow, and review-ready constraints are never evaluated for real alerts here, even when violated and learned is enabled", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [
    activeConstraintFixture({ id: "constraint.mined.service-presence.draft00000000", status: "draft" }),
    activeConstraintFixture({ id: "constraint.mined.service-presence.shadow0000000", status: "shadow" }),
    activeConstraintFixture({ id: "constraint.mined.service-presence.reviewready00", status: "review-ready" }),
  ]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } }, // violates all three, if evaluated
  ], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  assert.equal(result.alerts.alerts.some((alert) => alert.rule_id === "constraint.violation.service-presence"), false);
  const persisted = await readAlertRecords(paths);
  assert.equal(persisted.some((alert) => alert.rule_id.startsWith("constraint.violation.")), false);
});

test("S-live-1: a fixed-rule alert and an active-constraint alert coexist across daemon iterations without spuriously recovering each other (Slice 2 cross-recovery pattern, driven end-to-end)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: "2026-05-24T00:00:00.000Z" });

  // Sustained high memory across >=2 samples is required for system.memory.sustained_high to
  // fire (alert-store.js's thresholds.minSustainedSamples); fastCollectorFakes() reports a low,
  // non-alerting used_fraction, so a dedicated high-memory collector fake is used here instead.
  const highMemoryCollectors = {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0, 0, 0],
      uptime_seconds: 1,
      memory: { used_fraction: 0.95, free_bytes: 1 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
  const profile = slice6Profile();

  await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z" });
  const second = await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z" });

  const fixedSecond = second.alerts.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const constraintSecond = second.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(fixedSecond, "expected the fixed-rule alert to be active after 2 sustained high-memory samples");
  assert.equal(fixedSecond.status, "active");
  assert.ok(constraintSecond, "expected the constraint alert to remain active");
  assert.equal(constraintSecond.status, "active");

  // Third iteration: the fact now satisfies the constraint (service recovered) — the constraint
  // alert must recover, while the still-sustained-high-memory fixed alert must NOT be
  // spuriously recovered by the constraint source disappearing from extraCandidates.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "true" } },
  ], { now: "2026-05-24T00:02:00.000Z" });
  const third = await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:02:00.000Z", now: "2026-05-24T00:02:00.000Z" });

  const fixedThird = third.alerts.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const constraintThird = third.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.equal(fixedThird.status, "active", "the fixed-rule alert must not be spuriously recovered by the constraint source clearing");
  assert.equal(constraintThird.status, "recovered");
});

// --- Slice S4, additive: provenance-warning candidates wired into the real
// (evaluateAndPersistAlerts) path via computeProvenanceWarningCandidates, structurally
// mirroring S-live-1's own computeActiveConstraintCandidates wiring above. ---

function publicBindWarningFactFixture(overrides = {}) {
  return {
    fact_name: "provenance.warning",
    entity_key: "public_bind_no_supervisor.socket.tcp.8080.ipv4_any",
    attributes: {
      rule_id: "public_bind_no_supervisor",
      active: "true",
      protocol: "tcp",
      local_port: "8080",
      bind_address_family: "ipv4_any",
      source_type: "unknown",
      confidence: "0.8",
      severity: "medium",
      ...overrides,
    },
  };
}

function deletedExeWarningFactFixture(overrides = {}) {
  return {
    fact_name: "provenance.warning",
    entity_key: "deleted_exe_running.process.4821",
    attributes: {
      rule_id: "deleted_exe_running",
      active: "true",
      pid: "4821",
      executable_path_hash: "abc0123456789def",
      source_type: "shell",
      confidence: "1",
      severity: "high",
      ...overrides,
    },
  };
}

test("S4: byte-identical real alerts when the learned kill switch is off, even with an active provenance-warning fact present, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withWarningPaths = await tempPaths();
  await appendFactPoints(withWarningPaths, [publicBindWarningFactFixture(), deletedExeWarningFactFixture()], { now: S_LIVE_1_TICK_TS });
  // configDir/learned.json intentionally never written here -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the pre-S4 baseline above — computeProvenanceWarningCandidates
  // must short-circuit to [] before ever calling readFactPoints.
  let readFactsCalled = false;
  const withWarning = await runDaemonIteration(withWarningPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
  });

  assert.deepEqual(withWarning.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withWarning.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withWarning.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withWarningPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === PUBLIC_BIND_RULE_ID || alert.rule_id === DELETED_EXE_RULE_ID), false);
});

test("S4: an active public_bind_no_supervisor provenance-warning fact produces a real, sanitized alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, [publicBindWarningFactFixture()], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  const alert = result.alerts.alerts.find((a) => a.rule_id === PUBLIC_BIND_RULE_ID);
  assert.ok(alert, "expected a real alert for the active public_bind_no_supervisor warning");
  assert.equal(alert.status, "active");
  assert.equal(alert.diagnostics.local_port, 8080);
  assert.equal(alert.diagnostics.protocol, "tcp");

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));
});

test("S4: an active deleted_exe_running provenance-warning fact produces a real, sanitized alert record with a hashed (never raw) executable path", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, [deletedExeWarningFactFixture()], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  const alert = result.alerts.alerts.find((a) => a.rule_id === DELETED_EXE_RULE_ID);
  assert.ok(alert, "expected a real alert for the active deleted_exe_running warning");
  assert.equal(alert.status, "active");
  assert.equal(alert.diagnostics.pid, 4821);
  assert.equal(alert.diagnostics.executable_path_hash, "abc0123456789def");
  assert.equal(Object.keys(alert.diagnostics).sort().join(","), "confidence,executable_path_hash,pid,source_type");
  assert.equal(JSON.stringify(alert.diagnostics).includes("/"), false, "no raw path separator should ever reach persisted provenance diagnostics");
});

test("S4: a cleared (active:\"false\") provenance-warning fact does not fire", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await appendFactPoints(paths, [publicBindWarningFactFixture({ active: "false" })], { now: S_LIVE_1_TICK_TS });

  const result = await runIsolatedDaemonTick(paths);
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === PUBLIC_BIND_RULE_ID), false);
});

test("S4: a provenance-warning fact whose target has no fact at all does not fire (no fact, no claim)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // No facts.jsonl at all.
  const result = await runIsolatedDaemonTick(paths);
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === PUBLIC_BIND_RULE_ID || a.rule_id === DELETED_EXE_RULE_ID), false);
});

test("S4 structural wiring: the provenance sub-collector runs on a structural-due tick alongside its siblings, and its warnings are translated into fact-points", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];
  const structuralCollectors = {
    services: async () => {
      structuralCalls.push("services");
      return envelope("services", "collect_services", { manager: "systemd", services: [] });
    },
    network: async () => {
      structuralCalls.push("network");
      return envelope("network-basics", "collect_network", { listening_sockets: [] });
    },
    "scheduled-jobs": async () => {
      structuralCalls.push("scheduled-jobs");
      return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] });
    },
    provenance: async () => {
      structuralCalls.push("provenance");
      return envelope("provenance-warnings", "collect_provenance_warnings", {
        platform: "darwin",
        checked_socket_count: 1,
        narrowed_candidate_count: 1,
        warnings: [
          { rule_id: "public_bind_no_supervisor", active: true, severity: "medium", confidence: 0.8, source_type: "unknown", protocol: "tcp", local_port: 8080, bind_address_family: "ipv4_any" },
        ],
      });
    },
  };
  const profile = structuralProfile({ collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, provenance: { enabled: true } } });

  const result = await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs", "provenance"]);
  assert.deepEqual(result.status.structural_collector_statuses, [
    { id: "services", status: "ok", tool: "collect_services" },
    { id: "network-basics", status: "ok", tool: "collect_network" },
    { id: "scheduled-jobs", status: "ok", tool: "collect_scheduled_jobs" },
    { id: "provenance-warnings", status: "ok", tool: "collect_provenance_warnings" },
  ]);

  const { points } = await readFactPoints(paths);
  const warningPoint = points.find((point) => point.fact_name === "provenance.warning");
  assert.ok(warningPoint, "expected the structural provenance warning to be translated into a fact-point");
  assert.equal(warningPoint.attributes.rule_id, "public_bind_no_supervisor");
  assert.equal(warningPoint.attributes.active, "true");
});

test("S4 structural wiring: a timed-out structural tick (provenance hangs) discards its evidence entirely — no provenance fact-points are persisted", async () => {
  const paths = await tempPaths();
  const structuralCollectors = {
    services: async () => envelope("services", "collect_services", { manager: "systemd", services: [] }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: [] }),
    "scheduled-jobs": async () => envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] }),
    provenance: () => new Promise(() => {}), // never resolves
  };
  const profile = structuralProfile({ deadline_ms: 25, collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, provenance: { enabled: true } } });

  const result = await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: 1000,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async (_paths, checkpoint) => checkpoint,
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.deepEqual(result.status.structural_collector_statuses, [{ status: "unable", error: "structural_tick_deadline_exceeded" }]);
  assert.equal(result.structuralEvidence, undefined);
  assert.equal(result.structuralFacts, undefined);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

// ---------------------------------------------------------------------------------------------
// Slice 1 (observed-incident collectors plan): session-census structural wiring. Pure L0 fact
// source — this collector deliberately has NO extraCandidates counterpart (unlike S4/S5 above),
// so its own coverage here is limited to the structural evidence -> fact-point path, the
// byte-identical-when-disabled path, and an explicit day-1 no-storm assertion.
// ---------------------------------------------------------------------------------------------

test("Slice 1: the sessions sub-collector runs on a structural-due tick alongside its siblings, and its census is translated into a hashed, bucketed fact-point", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];
  const structuralCollectors = {
    services: async () => { structuralCalls.push("services"); return envelope("services", "collect_services", { manager: "systemd", services: [] }); },
    network: async () => { structuralCalls.push("network"); return envelope("network-basics", "collect_network", { listening_sockets: [] }); },
    "scheduled-jobs": async () => { structuralCalls.push("scheduled-jobs"); return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] }); },
    sessions: async () => {
      structuralCalls.push("sessions");
      return envelope("sessions", "collect_sessions", {
        platform: "darwin",
        multiplexers: [{ multiplexer: "tmux", status: "ok" }, { multiplexer: "screen", status: "absent" }],
        any_binary_available: true,
        total_count: 1,
        sessions: [{ multiplexer: "tmux", session_name: "deploy-worker", attached: true, window_count: 2, created_at_epoch_seconds: 1720000000 }],
        truncated: false,
        cap: 200,
      });
    },
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, sessions: { enabled: true } },
  });

  const result = await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs", "sessions"]);
  assert(result.status.structural_collector_statuses.some((entry) => entry.id === "sessions" && entry.status === "ok" && entry.tool === "collect_sessions"));

  const { points } = await readFactPoints(paths);
  const sessionPoint = points.find((point) => point.fact_name === "session.presence");
  assert.ok(sessionPoint, "expected the structural session census to be translated into a fact-point");
  assert.match(sessionPoint.entity_key, /^session\.tmux\.[0-9a-f]{16}$/);
  assert.equal(sessionPoint.entity_key.includes("deploy-worker"), false, "raw session name must never reach persisted fact-history");
  assert.equal(JSON.stringify(points).includes("deploy-worker"), false, "raw session name must never reach persisted fact-history");
  assert.equal(sessionPoint.attributes.attached, "true");
  assert.equal(sessionPoint.attributes.window_count_bucket, "2-4");
});

test("Slice 1: no session fact-points are persisted while the learned.json kill switch is off, even with populated session evidence available (byte-identical fast path)", async () => {
  const paths = await tempPaths();
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    sessions: async () => envelope("sessions", "collect_sessions", {
      any_binary_available: true,
      total_count: 1,
      sessions: [{ multiplexer: "tmux", session_name: "deploy-worker", attached: true, window_count: 2, created_at_epoch_seconds: 1720000000 }],
      truncated: false,
      cap: 200,
    }),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, sessions: { enabled: true } },
  });

  const result = await runDaemonIteration(paths, {
    collectors: fastCollectorFakes(),
    structuralCollectors,
    profile,
    ts: "2026-05-24T00:00:00.000Z",
    now: 0,
    evaluateAlerts: false,
    // loadLearnedConfig intentionally not injected: defaults to real constraint-store.js
    // behavior, which is enabled:false when configDir/learned.json is absent.
  });

  assert.equal(result.structuralFacts, undefined);
  await assert.rejects(() => fs.access(resolveFactStorePaths(paths).factsFile));
});

test("Slice 1 day-1 no-storm: the first-ever session observation seeds fact-history and emits no alert (this collector has no alert-candidate path at all)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    sessions: async () => envelope("sessions", "collect_sessions", {
      any_binary_available: true,
      total_count: 1,
      sessions: [{ multiplexer: "tmux", session_name: "first-ever-session", attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 }],
      truncated: false,
      cap: 200,
    }),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, sessions: { enabled: true } },
  });

  const result = await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
  });

  const { points } = await readFactPoints(paths);
  assert(points.some((point) => point.fact_name === "session.presence"), "expected fact-history to be seeded on first observation");
  assert.equal((result.alerts?.alerts ?? []).some((alert) => String(alert.rule_id).includes("session")), false, "Slice 1 must never emit a session-related alert candidate");
});

test("S4 load-bearing: a fixed-rule alert, an active-constraint alert, and a provenance-warning alert coexist across daemon iterations without any one spuriously recovering another (S2 cross-recovery pattern extended to a third source)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
    publicBindWarningFactFixture(),
  ], { now: "2026-05-24T00:00:00.000Z" });

  const highMemoryCollectors = {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0, 0, 0],
      uptime_seconds: 1,
      memory: { used_fraction: 0.95, free_bytes: 1 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
  const profile = slice6Profile();

  await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z" });
  const second = await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z" });

  const fixedSecond = second.alerts.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const constraintSecond = second.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  const provenanceSecond = second.alerts.alerts.find((alert) => alert.rule_id === PUBLIC_BIND_RULE_ID);
  assert.ok(fixedSecond, "expected the fixed-rule alert to be active after 2 sustained high-memory samples");
  assert.equal(fixedSecond.status, "active");
  assert.ok(constraintSecond, "expected the constraint alert to remain active");
  assert.equal(constraintSecond.status, "active");
  assert.ok(provenanceSecond, "expected the provenance-warning alert to remain active");
  assert.equal(provenanceSecond.status, "active");

  // Third iteration: the service-presence fact now satisfies the constraint (recovered), and
  // the provenance-warning fact clears (active:"false") — the constraint and provenance-warning
  // alerts must both recover, while the still-sustained-high-memory fixed alert must NOT be
  // spuriously recovered by either of the other two sources disappearing from extraCandidates,
  // and neither of the two learned sources may spuriously recover the other.
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "true" } },
    publicBindWarningFactFixture({ active: "false" }),
  ], { now: "2026-05-24T00:02:00.000Z" });
  const third = await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:02:00.000Z", now: "2026-05-24T00:02:00.000Z" });

  const fixedThird = third.alerts.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const constraintThird = third.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  const provenanceThird = third.alerts.alerts.find((alert) => alert.rule_id === PUBLIC_BIND_RULE_ID);
  assert.equal(fixedThird.status, "active", "the fixed-rule alert must not be spuriously recovered by either learned source clearing");
  assert.equal(constraintThird.status, "recovered");
  assert.equal(provenanceThird.status, "recovered");
});

// ---------------------------------------------------------------------------------------------
// Slice S5: identity-baseline deviation candidates wired into the same extraCandidates
// concatenation. Full unit coverage (day-1 no-storm, grace-window boundary, UID-scoping,
// identity_drift, CLI idempotency) lives in test/provenance-store.test.js and
// test/provenance-identity.test.js; these tests confirm the daemon.js wiring itself: the third
// source lands in the same array, is byte-identical when disabled, and coexists without
// cross-recovering the other two sources.
// ---------------------------------------------------------------------------------------------

async function seedConfirmedUnknownIdentity(paths, ts) {
  const observation = {
    executablePath: "/opt/acme/bin/worker",
    sourceClassification: "shell",
    owningUser: "0",
    portTargetKeys: ["tcp.9500"],
  };
  // Two distinct iterations, three total samples -- crosses the S5 grace window
  // (DEFAULT_STABLE_SAMPLE_THRESHOLD=3, DEFAULT_STABLE_ITERATION_THRESHOLD=2) directly via the
  // pure reconciliation helper, without needing several real daemon ticks.
  let store = { version: 1, signatures: {} };
  store = reconcileSignatures(store, [observation], { ts, iterationKey: "seed-t1" });
  store = reconcileSignatures(store, [observation], { ts, iterationKey: "seed-t2" });
  store = reconcileSignatures(store, [observation], { ts, iterationKey: "seed-t2" });
  // bootstrapped_at + a fresh last_reconciled_at (== ts) mean computeProvenanceIdentityCandidates
  // finds a baseline already established and is not due for fresh host I/O this tick -- pure
  // re-derive only, so this test needs no collector fakes for the identity path.
  await writeSignatureStore(paths, { ...store, bootstrapped_at: ts, last_reconciled_at: ts });
}

test("S5: byte-identical real alerts when the learned kill switch is off, even with a confirmed-unknown identity baseline present, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withIdentityPaths = await tempPaths();
  await seedConfirmedUnknownIdentity(withIdentityPaths, S_LIVE_1_TICK_TS);
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the pre-S5 baseline above.
  const withIdentity = await runIsolatedDaemonTick(withIdentityPaths);

  assert.deepEqual(withIdentity.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withIdentity.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withIdentity.alerts.notification_due_ids, baseline.alerts.notification_due_ids);

  const persisted = await readAlertRecords(withIdentityPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === UNKNOWN_IDENTITY_RULE_ID), false);
});

test("S5: a confirmed-unknown identity (grace window crossed, no snapshot baseline acceptance) produces a real, sanitized unknown_identity alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await seedConfirmedUnknownIdentity(paths, S_LIVE_1_TICK_TS);

  const result = await runIsolatedDaemonTick(paths);
  const alert = result.alerts.alerts.find((a) => a.rule_id === UNKNOWN_IDENTITY_RULE_ID);
  assert.ok(alert, "expected a real alert for the confirmed-unknown identity");
  assert.equal(alert.status, "active");
  assert.match(alert.diagnostics.identity_hash, /^[0-9a-f]{16}$/);
  assert.equal(JSON.stringify(alert.diagnostics).includes("/opt/acme"), false, "no raw path should ever reach a persisted identity diagnostics");

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));
});

test("S5 load-bearing: a fixed-rule alert and a confirmed-unknown-identity alert coexist across daemon iterations without either spuriously recovering the other", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await seedConfirmedUnknownIdentity(paths, "2026-05-24T00:00:00.000Z");

  const highMemoryCollectors = {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0, 0, 0],
      uptime_seconds: 1,
      memory: { used_fraction: 0.95, free_bytes: 1 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
  const profile = slice6Profile();

  await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z" });
  const second = await runDaemonIteration(paths, { profile, collectors: highMemoryCollectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z" });

  const fixedSecond = second.alerts.alerts.find((alert) => alert.rule_id === "system.memory.sustained_high");
  const identitySecond = second.alerts.alerts.find((alert) => alert.rule_id === UNKNOWN_IDENTITY_RULE_ID);
  assert.ok(fixedSecond, "expected the fixed-rule alert to be active after 2 sustained high-memory samples");
  assert.equal(fixedSecond.status, "active");
  assert.ok(identitySecond, "expected the identity alert to remain active");
  assert.equal(identitySecond.status, "active");
});
