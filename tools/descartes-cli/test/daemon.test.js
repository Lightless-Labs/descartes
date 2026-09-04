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
import { appendFactPoints, enforceFactRetention, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { buildHistorySummary, readDaemonStatus } from "../src/history-store.js";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { readAlertRecords } from "../src/alert-store.js";
import { readShadowRecords, resolveShadowStorePaths } from "../src/shadow-store.js";
import { DELETED_EXE_RULE_ID, PUBLIC_BIND_RULE_ID } from "../src/tools/provenance-warnings.js";
import { UNKNOWN_IDENTITY_RULE_ID, reconcileSignatures, resolveSignatureStorePaths, writeSignatureStore } from "../src/provenance-store.js";
import { computeProvenanceIdentityCandidates } from "../src/tools/provenance-identity.js";
import { resolvePeerSignatureStorePaths } from "../src/peer-signature-store.js";
import {
  PEER_CENSUS_MARKER_ENTITY_KEY,
  SCHEDULED_JOB_CENSUS_FACT_NAME,
  SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY,
  SCHEDULED_JOB_PRESENCE_FACT_NAME,
  SERVICE_CENSUS_FACT_NAME,
  SERVICE_CENSUS_MARKER_ENTITY_KEY,
  SESSION_CENSUS_MARKER_ENTITY_KEY,
  buildScheduledJobEntityKey,
} from "../src/fact-translators.js";
import { SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID, loadSessionBaselineStore, writeSessionBaselineStore } from "../src/session-baseline.js";
import { CORRELATION_RULE_ID } from "../src/incident-correlation.js";
import { readContainmentRecommendConfig, writeContainmentRecommendConfig } from "../src/containment-recommend.js";
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID, loadPeerBaselineStore, writePeerBaselineStore } from "../src/peer-baseline.js";
import { SERVICE_APPEARED_RULE_ID, SERVICE_DISAPPEARED_RULE_ID, loadServiceAppearanceBaselineStore, loadServiceBaselineStore, writeServiceAppearanceBaselineStore, writeServiceBaselineStore } from "../src/service-baseline.js";
import { PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, loadProcessLineageBaselineStore, writeProcessLineageBaselineStore } from "../src/process-lineage-baseline.js";
import { SCHEDULED_JOB_APPEARED_RULE_ID, loadPersistenceBaselineStore, writePersistenceBaselineStore } from "../src/persistence-baseline.js";
import { CREDENTIAL_ACCESS_RULE_ID, loadCredentialAccessBaselineStore, writeCredentialAccessBaselineStore } from "../src/credential-access-baseline.js";

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
      return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [], summary: { unavailable_count: 0 }, truncated: false });
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
      return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [], summary: { unavailable_count: 0 }, truncated: false });
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
  assert.deepEqual(Object.keys(profile.structural.collectors).sort(), ["canary", "network", "process-lineage", "provenance", "scheduled-jobs", "services", "sessions", "tailscale-status", "vpn-peer-status"]);
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
  // Slice 3 (observed-incident collectors plan) sibling-default consistency: vpn-peer-status
  // defaults true, matching its siblings exactly — same outer learned.json kill switch, and this
  // collector ALSO never emits an alert candidate (pure L0 fact source, RESOLVED option 1).
  assert(profile.structural.collectors["vpn-peer-status"].enabled);
  assert(profile.structural.collectors["tailscale-status"].enabled);
  assert(profile.structural.collectors["process-lineage"].enabled);
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

test("collectStructuralEvidence runs the process-lineage collector only when enabled", async () => {
  const calls = [];
  const evidence = await collectStructuralEvidence({
    collectors: { "process-lineage": { enabled: true } },
  }, {
    "process-lineage": async () => {
      calls.push("process-lineage");
      return envelope("process-lineage-edges", "collect_process_lineage", { edges: [], edge_count: 0, truncated: false });
    },
  });
  assert.deepEqual(calls, ["process-lineage"]);
  assert.deepEqual(evidence.map((item) => item.id), ["process-lineage-edges"]);
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
  // 1 service + 1 network + 1 Slice C service census marker (always appended on a successful
  // services envelope) + 1 Persistence-baseline Slice A scheduled_job census marker (always
  // appended on a successful, even zero-job, scheduled-jobs envelope) = 4.
  assert.equal(result.structuralFacts.written_count, 4);

  const { points } = await readFactPoints(paths);
  assert.equal(points.length, 4);
  assert(points.some((point) => point.fact_name === "service.presence" && point.entity_key === "nginx.service"));
  assert(points.some((point) => point.fact_name === "network.listening_port.owner" && point.entity_key === "tcp:0.0.0.0:8080"));
  assert(points.some((point) => point.fact_name === SERVICE_CENSUS_FACT_NAME && point.entity_key === SERVICE_CENSUS_MARKER_ENTITY_KEY && point.attributes.census_state === "complete"));
  assert(points.some((point) => point.fact_name === SCHEDULED_JOB_CENSUS_FACT_NAME && point.entity_key === SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY && point.attributes.census_state === "complete"));
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

// Slice 9 fixture setup: first-touch fact ledgers are intentionally unknown until a clean
// follow-up retention pass. Commit that follow-up after each fixture append so these wiring
// tests exercise normal intact shadow evaluation rather than bootstrap suppression.
async function appendFactPointsAndCommit(paths, points, options = {}) {
  const result = await appendFactPoints(paths, points, options);
  await enforceFactRetention(paths, { now: options.now !== undefined ? options.now : options.ts });
  return result;
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

// Finding F2-Tier1: the configured learned-config fact_store_max_bytes must reach the live
// appendFactPoints call site as options.maxBytes, so an operator has an actual lever to stop
// routine bytecap eviction (previously hardcoded to fact-store.js's DEFAULT_FACT_MAX_BYTES with
// no override surface at all).
test("structural fact-persist threads learned-config fact_store_max_bytes into appendFactPoints as options.maxBytes", async () => {
  const paths = await tempPaths();
  const seenOptions = [];
  const spyAppendFactPoints = async (spyPaths, points, options) => {
    seenOptions.push(options);
    return appendFactPointsAndCommit(spyPaths, points, options);
  };

  await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true, fact_store_max_bytes: 123456 }),
    appendFactPoints: spyAppendFactPoints,
  });

  assert.equal(seenOptions.length, 1);
  assert.equal(seenOptions[0].maxBytes, 123456);
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
    appendFactPoints: appendFactPointsAndCommit,
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
      appendFactPoints: appendFactPointsAndCommit,
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
    appendFactPoints: appendFactPointsAndCommit,
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

// --- Slice B (Codex-hardening): eval-side freshness bound (stale fact ≠ live claim) ---

test("Slice B: an active constraint whose only fact is older than 3× the structural interval is STALE → skipped, not fired (a vanished service no longer reads as a live violation for up to 30 days)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } }, // would VIOLATE if it were fresh
  ], { ts: S_LIVE_1_TICK_TS, now: S_LIVE_1_TICK_TS }); // stamp ts old (options.ts), now=ts so append-time retention keeps it

  // now = fact ts + 4h; freshnessMs = 3 × DEFAULT_STRUCTURAL_INTERVAL_MS (1h) = 3h → 4h is stale.
  // factWindowMs is deliberately WIDE (30d) so the old fact IS read — proving the LOOKUP staleness
  // bound (not merely the read-window bound) is what suppresses it.
  const staleNow = new Date(Date.parse(S_LIVE_1_TICK_TS) + 4 * 60 * 60 * 1000).toISOString();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: staleNow,
    now: staleNow,
    factWindowMs: 30 * 24 * 60 * 60 * 1000,
  });
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === "constraint.violation.service-presence"), false, "a 4h-stale fact must not drive a live constraint");
});

test("Slice B (must-fix guard): freshness is pinned to the STRUCTURAL interval, NOT the fast tick — a 1h-old fact (>>3× the 60s fast tick) is still fresh within the 3h window and fires", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { ts: S_LIVE_1_TICK_TS, now: S_LIVE_1_TICK_TS }); // stamp ts old (options.ts), now=ts so append-time retention keeps it

  // 1h old: if freshness were (wrongly) 3× the 60s fast tick = 180s, this would be stale and skip.
  // Pinned to 3× the 1h structural interval = 3h, it is fresh → the violation still fires.
  const freshNow = new Date(Date.parse(S_LIVE_1_TICK_TS) + 60 * 60 * 1000).toISOString();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: freshNow,
    now: freshNow,
  });
  assert.ok(result.alerts.alerts.some((a) => a.rule_id === "constraint.violation.service-presence"), "a 1h-old fact within the 3h structural window still fires");
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

// ---------------------------------------------------------------------------------------------
// Slice 3 (observed-incident collectors plan): VPN/SSH peer-status structural wiring. Pure L0
// fact source — mirrors Slice 1's own coverage shape exactly (structural evidence -> fact-point,
// byte-identical-when-disabled, day-1 no-storm), PLUS the two must-fix-4 "no alert candidates"
// pinned tests (store-separation, miner-inertness-adjacent) the plan requires specifically for
// this slice.
// ---------------------------------------------------------------------------------------------

function vpnPeerStatusEnvelopeFixture(overrides = {}) {
  return envelope("vpn-peer-status", "collect_vpn_peer_status", {
    platform: "darwin",
    sources: {
      ssh_who: { status: "ok" },
      ssh_last: { status: "ok", requested_n: 50 },
      wireguard: { status: "ok", elevation_candidate: false, interfaces: [] },
      vpn_services: { status: "ok" },
      established_inbound: { status: "ok" },
    },
    any_source_available: true,
    total_count: 1,
    peers: [{ source_type: "ssh", presence_state: "observed_active", remote_user: "alice", remote_host: "203.0.113.5", origin: "who" }],
    truncated: false,
    cap: 200,
    ...overrides,
  });
}

function tailscaleStatusEnvelopeFixture(overrides = {}) {
  return envelope("tailscale-status", "collect_tailscale_status", {
    backend_state: "Running",
    total_count: 1,
    peers: [{
      source_type: "tailscale",
      presence_state: "observed_active",
      node_public_key: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=",
      is_exit_node_active: true,
      is_exit_node_option: true,
      latest_handshake_epoch_seconds: 0,
    }],
    truncated: false,
    cap: 200,
    ...overrides,
  });
}

test("collectStructuralEvidence gates tailscale-status independently and preserves sibling ordering", async () => {
  const calls = [];
  const evidence = await collectStructuralEvidence({ collectors: {
    "vpn-peer-status": { enabled: false },
    "tailscale-status": { enabled: true },
  } }, {
    "tailscale-status": async () => { calls.push("tailscale-status"); return tailscaleStatusEnvelopeFixture(); },
  });
  assert.deepEqual(calls, ["tailscale-status"]);
  assert.deepEqual(evidence.map((entry) => entry.id), ["tailscale-status"]);
});

test("tailscale structural wiring persists hashed peer facts and adds no new alert family", async () => {
  const paths = await tempPaths();
  const profile = structuralProfile({
    collectors: {
      services: { enabled: false },
      network: { enabled: false },
      "scheduled-jobs": { enabled: false },
      "tailscale-status": { enabled: true },
    },
  });
  const result = await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors: { "tailscale-status": async () => tailscaleStatusEnvelopeFixture() },
    evaluateAlerts: true, // was false — with alerts disabled the "no new alert family" assertion below was vacuous (sol review)
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  const { points } = await readFactPoints(paths);
  const peerPoint = points.find((point) => point.fact_name === "peer.presence");
  assert.ok(peerPoint);
  assert.match(peerPoint.entity_key, /^peer\.tailscale\.[0-9a-f]{16}$/);
  assert.equal(peerPoint.attributes.source_type, "tailscale");
  assert.equal(peerPoint.attributes.exit_node_role, "in_use");
  assert.equal((result.alerts?.alerts ?? []).some((alert) => ![PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID].includes(alert.rule_id)), false);
});

test("Slice 3: the vpn-peer-status sub-collector runs on a structural-due tick alongside its siblings, and its census is translated into a hashed, bucketed fact-point", async () => {
  const paths = await tempPaths();
  const structuralCalls = [];
  const structuralCollectors = {
    services: async () => { structuralCalls.push("services"); return envelope("services", "collect_services", { manager: "systemd", services: [] }); },
    network: async () => { structuralCalls.push("network"); return envelope("network-basics", "collect_network", { listening_sockets: [] }); },
    "scheduled-jobs": async () => { structuralCalls.push("scheduled-jobs"); return envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs: [] }); },
    "vpn-peer-status": async () => { structuralCalls.push("vpn-peer-status"); return vpnPeerStatusEnvelopeFixture(); },
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, "vpn-peer-status": { enabled: true } },
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

  assert.deepEqual(structuralCalls, ["services", "network", "scheduled-jobs", "vpn-peer-status"]);
  assert(result.status.structural_collector_statuses.some((entry) => entry.id === "vpn-peer-status" && entry.status === "ok" && entry.tool === "collect_vpn_peer_status"));

  const { points } = await readFactPoints(paths);
  const peerPoint = points.find((point) => point.fact_name === "peer.presence");
  assert.ok(peerPoint, "expected the structural peer census to be translated into a fact-point");
  assert.match(peerPoint.entity_key, /^peer\.ssh\.[0-9a-f]{16}$/);
  assert.equal(peerPoint.entity_key.includes("alice"), false, "raw remote_user must never reach persisted fact-history");
  assert.equal(peerPoint.entity_key.includes("203.0.113.5"), false, "raw remote_host must never reach persisted fact-history");
  assert.equal(JSON.stringify(points).includes("alice"), false, "raw remote_user must never reach persisted fact-history");
  assert.equal(JSON.stringify(points).includes("203.0.113.5"), false, "raw remote_host must never reach persisted fact-history");
  assert.equal(peerPoint.attributes.source_type, "ssh");
  assert.equal(peerPoint.attributes.presence_state, "observed_active");
});

test("Slice 3: no peer fact-points are persisted while the learned.json kill switch is off, even with populated peer evidence available (byte-identical fast path)", async () => {
  const paths = await tempPaths();
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    "vpn-peer-status": async () => vpnPeerStatusEnvelopeFixture(),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, "vpn-peer-status": { enabled: true } },
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

test("Slice 3 day-1 no-storm: the first-ever peer observation seeds fact-history and emits no alert (this collector has no alert-candidate path at all)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    "vpn-peer-status": async () => vpnPeerStatusEnvelopeFixture(),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, "vpn-peer-status": { enabled: true } },
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
  assert(points.some((point) => point.fact_name === "peer.presence"), "expected fact-history to be seeded on first observation");
  assert.equal((result.alerts?.alerts ?? []).some((alert) => String(alert.rule_id).includes("peer")), false, "Slice 3 must never emit a peer-related alert candidate");
});

// MUST-FIX 4 (Fable review 2026-07-13), part (a): store-separation. Peer observations must NEVER
// write signatures.json (the shipped process-identity store), and computeProvenanceIdentityCandidates
// (already wired into this same daemon.js's extraCandidates) must emit ZERO candidates after a
// tick that only ever observed peer facts — proving the "no alert candidates" claim isn't merely
// a missing extraCandidates edit, but that the peer path genuinely never touches the process store.
test("Slice 3 MUST-FIX 4(a) store-separation: peer ticks never write signatures.json, and computeProvenanceIdentityCandidates emits ZERO candidates afterward", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    "vpn-peer-status": async () => vpnPeerStatusEnvelopeFixture({
      peers: [
        { source_type: "wireguard", presence_state: "observed_active", interface: "wg0", public_key: "keyA", endpoint: "203.0.113.10:51820", latest_handshake_epoch_seconds: 1720000000 },
        { source_type: "ssh", presence_state: "observed_active", remote_user: "bob", remote_host: "198.51.100.7", origin: "who" },
      ],
      total_count: 2,
    }),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, "vpn-peer-status": { enabled: true } },
  });

  await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
  });

  // (1) signatures.json (the process-identity store) was never written by the peer path.
  const processStorePaths = resolveSignatureStorePaths(paths);
  await assert.rejects(() => fs.access(processStorePaths.signaturesFile), "signatures.json must not exist after a tick that only observed peer facts");

  // (2) peer-signatures.json (this slice's OWN, separate store) was also never written — this
  // slice does not wire any reconcile call into the daemon loop at all (see peer-signature-
  // store.js's SCOPE NOTE): there is no code path here that could produce alert-shaped output.
  const peerStorePaths = resolvePeerSignatureStorePaths(paths);
  await assert.rejects(() => fs.access(peerStorePaths.peerSignaturesFile), "peer-signatures.json must not be written by this slice's daemon wiring either");

  // (3) computeProvenanceIdentityCandidates (already wired into daemon.js's extraCandidates)
  // emits zero candidates from peer-only fact-history — the day-1 gate alone guarantees this
  // (signatures.json was never bootstrapped), independent of anything peer-shaped ever appearing.
  const identityCandidates = await computeProvenanceIdentityCandidates(paths, { now: Date.parse("2026-05-24T00:00:00.000Z") });
  assert.deepEqual(identityCandidates, []);
});

test("Tailscale-only peer ticks never write signatures.json or peer-signatures.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const profile = structuralProfile({
    collectors: {
      services: { enabled: false },
      network: { enabled: false },
      "scheduled-jobs": { enabled: false },
      "tailscale-status": { enabled: true },
    },
  });

  await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors: { "tailscale-status": async () => tailscaleStatusEnvelopeFixture() },
    evaluateAlerts: false,
    ts: "2026-05-24T00:00:00.000Z",
    now: Date.parse("2026-05-24T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
  });

  await assert.rejects(() => fs.access(resolveSignatureStorePaths(paths).signaturesFile));
  await assert.rejects(() => fs.access(resolvePeerSignatureStorePaths(paths).peerSignaturesFile));
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

// ---------------------------------------------------------------------------------------------
// Slice 4 (observed-incident collectors plan): session-count anomaly signature wiring
// (computeSessionBaselineCandidates as the fourth extraCandidates entry) + Decision 2b's
// deterministic, non-LLM local delivery branch (emitSessionAlertSignals) wired in the daemon tick.
// ---------------------------------------------------------------------------------------------

function sessionFactPoint(ts, entityKey, fingerprint = "abababababababab") {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: entityKey,
    attributes: { multiplexer: "tmux", attached: "true", window_count_bucket: "1", created_at_fingerprint: fingerprint },
    source_envelope_id: "sessions",
    source_tool: "collect_sessions",
    sensitivity: "operational",
  };
}

function censusMarkerFactPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: "session.presence",
    entity_key: SESSION_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "sessions",
    source_tool: "collect_sessions",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeSessionTick(ts, count, entityPrefix = "e") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(sessionFactPoint(ts, `${entityPrefix}-${i}`));
  points.push(censusMarkerFactPoint(ts, "complete"));
  return points;
}

function hour(index) {
  return new Date(Date.parse("2026-06-10T00:00:00.000Z") + index * 60 * 60 * 1000).toISOString();
}

test("Slice 4: byte-identical real alerts when the learned kill switch is off, even with session fact-history present that would otherwise deviate, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withSessionsPaths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(withSessionsPaths, ticks, { now: hour(30) });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the baseline above — computeSessionBaselineCandidates must
  // short-circuit to [] before ever calling readFactPoints.
  let readFactsCalled = false;
  const withSessions = await runDaemonIteration(withSessionsPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
  });

  assert.deepEqual(withSessions.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withSessions.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withSessions.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withSessionsPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === SESSION_COUNT_DROP_RULE_ID || alert.rule_id === SESSION_CHURN_RULE_ID), false);
});

test("Slice 4 wiring: computeSessionBaselineCandidates is the daemon's fourth extraCandidates entry — a pre-seeded mass-drop fact-history produces a real, sanitized session.count_drop alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4) gave session-baseline.js its own persistent
  // cold-start lockout, mirroring process-lineage-baseline.js's — see the "Process-lineage wiring"
  // test above for the identical rationale. Pre-establish the store (this wiring test is about the
  // daemon pipeline, not the lockout, which has its own dedicated coverage in
  // session-baseline.test.js) and confirm the shared integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const result = await runIsolatedDaemonTick(paths, hour(30));
  const alert = result.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(alert, "expected a real alert for the session-count mass drop");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "critical");
  assert.equal(alert.diagnostics.observed_count, 0);
  assert.equal(alert.diagnostics.mean_before, 20);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));
});

test("Slice 4 wiring: a fingerprint change on the latest tick-group produces a real session.churn alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment above for the identical rationale) and confirm the
  // shared integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [
    sessionFactPoint(hour(0), "session.tmux.aaaaaaaaaaaaaaaa", "1111111111111111"),
    censusMarkerFactPoint(hour(0), "complete"),
    sessionFactPoint(hour(1), "session.tmux.aaaaaaaaaaaaaaaa", "2222222222222222"),
    censusMarkerFactPoint(hour(1), "complete"),
  ];
  await appendFactPoints(paths, ticks, { now: hour(1) });
  await appendFactPoints(paths, [], { now: hour(1) });

  const result = await runIsolatedDaemonTick(paths, hour(1));
  const alert = result.alerts.alerts.find((a) => a.rule_id === SESSION_CHURN_RULE_ID);
  assert.ok(alert, "expected a real alert for the churned entity");
  assert.equal(alert.diagnostics.entity_key, "session.tmux.aaaaaaaaaaaaaaaa");
  assert.equal(alert.diagnostics.prior_fingerprint, "1111111111111111");
  assert.equal(alert.diagnostics.current_fingerprint, "2222222222222222");
});

test("Slice 4 ts-cohesion (integration): every session.* fact point emitted within one structural-tick iteration — including the new census marker — shares a byte-identical ts", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    sessions: async () => envelope("sessions", "collect_sessions", {
      platform: "darwin",
      multiplexers: [{ multiplexer: "tmux", status: "ok" }, { multiplexer: "screen", status: "absent" }],
      any_binary_available: true,
      total_count: 2,
      sessions: [
        { multiplexer: "tmux", session_name: "alpha", attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 },
        { multiplexer: "tmux", session_name: "beta", attached: false, window_count: 2, created_at_epoch_seconds: 1720000001 },
      ],
      truncated: false,
      cap: 200,
    }),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, sessions: { enabled: true } },
  });

  await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    ts: "2026-06-11T00:00:00.000Z",
    now: Date.parse("2026-06-11T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
  });

  const { points } = await readFactPoints(paths);
  const sessionPoints = points.filter((point) => point.fact_name === "session.presence");
  assert.ok(sessionPoints.length >= 3, "expected 2 session facts + 1 census marker");
  const distinctTimestamps = new Set(sessionPoints.map((point) => point.ts));
  assert.equal(distinctTimestamps.size, 1, `expected every session.* fact point to share one ts, got ${JSON.stringify([...distinctTimestamps])}`);
  assert.equal([...distinctTimestamps][0], "2026-06-11T00:00:00.000Z");
  assert(sessionPoints.some((point) => point.entity_key === SESSION_CENSUS_MARKER_ENTITY_KEY), "expected the census marker fact point to be present and share the same ts");
});

test("Slice 4, Decision 2b: a due session.count_drop is delivered through the deterministic local delivery branch wired into the daemon tick, and never reaches the LLM path", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment for the identical rationale) and confirm the shared
  // integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });

  assert.ok(result.sessionAlertDelivery, "expected a sessionAlertDelivery result on the daemon iteration");
  const sessionDeliveries = deliveries.filter((entry) => entry.opts.ruleId === SESSION_COUNT_DROP_RULE_ID);
  assert.equal(sessionDeliveries.length, 1, "expected exactly one deterministic delivery for the due session.count_drop candidate");
  assert.equal(sessionDeliveries[0].decision.notify, true);
  assert.equal(sessionDeliveries[0].decision.severity, "critical");

  // Never via the LLM path: session.* is unknown_namespace, so adjudicateAlertNotifications must
  // never have constructed a session for it (alert-intelligence.json defaults to disabled anyway,
  // giving a doubly-enforced guarantee here).
  assert.equal(result.alertIntelligence.status, "disabled");
});

test("Slice 4, Decision 2b: the deterministic delivery respects cooldown — a second daemon tick within the cooldown window does not re-deliver the same session.count_drop", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment for the identical rationale) and confirm the shared
  // integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; };

  await runDaemonIteration(paths, { profile: slice6Profile(), collectors: fastCollectorFakes(), ts: hour(30), now: hour(30), deliverNotification });
  const afterFirst = deliveries.filter((entry) => entry.ruleId === SESSION_COUNT_DROP_RULE_ID).length;
  assert.equal(afterFirst, 1);

  // A second tick moments later (same fact-history, no new tick-group) — well within the default
  // 15-minute alert cooldown.
  const secondTs = new Date(Date.parse(hour(30)) + 60 * 1000).toISOString();
  await runDaemonIteration(paths, { profile: slice6Profile(), collectors: fastCollectorFakes(), ts: secondTs, now: secondTs, deliverNotification });
  const afterSecond = deliveries.filter((entry) => entry.ruleId === SESSION_COUNT_DROP_RULE_ID).length;
  assert.equal(afterSecond, 1, "must not re-deliver within the cooldown window");
});

test("Slice 4, Decision 2b: deliverSessionAlerts:false opts the daemon tick out of the deterministic delivery branch entirely (no sessionAlertDelivery, no deliverNotification call for session.*)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment for the identical rationale) and confirm the shared
  // integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    deliverSessionAlerts: false,
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; },
  });

  assert.equal(result.sessionAlertDelivery, undefined);
  assert.equal(deliveries.some((entry) => entry.ruleId === SESSION_COUNT_DROP_RULE_ID), false);
  // The candidate is still persisted (visible via `descartes alerts`) -- only active delivery is skipped.
  const alert = result.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(alert);
});

// ---------------------------------------------------------------------------------------------
// Finding F6: core resource ("metric" namespace: daemon./system./disk.) alerts must deliver
// deterministically when notification delivery is enabled, regardless of the separate
// alert-intelligence (LLM) opt-in — mirrors the Slice 4 session.*/peer.* deterministic-delivery
// wiring immediately above, via the new sibling emitMetricAlertFallbackSignals branch.
// ---------------------------------------------------------------------------------------------

function highMemoryCollectors() {
  return {
    system: async () => envelope("system-overview", "collect_system", {
      load_average: [0, 0, 0],
      uptime_seconds: 1,
      memory: { used_fraction: 0.95, free_bytes: 1 },
      swap: { used_bytes: 0 },
    }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

test("F6: a due system.memory.sustained_high is delivered through the deterministic metric-alert fallback when alert-intelligence is at its default (disabled) state", async () => {
  const paths = await tempPaths();
  const profile = slice6Profile();
  const collectors = highMemoryCollectors();
  const deliveries = [];
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; };

  // Two sustained high-memory ticks are required for system.memory.sustained_high to fire (see
  // alert-store.js's thresholds.minSustainedSamples, and the identical rationale at the S-live-1
  // "fixed-rule alert and an active-constraint alert coexist" test above).
  await runDaemonIteration(paths, { profile, collectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z", deliverNotification });
  const result = await runDaemonIteration(paths, { profile, collectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z", deliverNotification });

  const memoryAlert = result.alerts.alerts.find((a) => a.rule_id === "system.memory.sustained_high");
  assert.ok(memoryAlert, "expected system.memory.sustained_high to be active after 2 sustained high-memory samples");

  const memoryDeliveries = deliveries.filter((entry) => entry.opts.ruleId === "system.memory.sustained_high");
  assert.equal(memoryDeliveries.length, 1, "expected exactly one deterministic delivery for the due metric alert");
  assert.equal(memoryDeliveries[0].decision.notify, true);

  // Simultaneously: alert-intelligence (the LLM route) is untouched and reports its own default
  // "disabled" status — proving delivery happened WITHOUT the LLM opt-in, the literal F6 repro.
  assert.equal(result.alertIntelligence.status, "disabled");
  assert.ok(result.metricAlertFallback, "expected a metricAlertFallback result on the daemon iteration");
});

test("F6: an operator who has opted into alert-intelligence keeps the LLM's exclusive judgment — the fallback does not also deliver a raw notification when the (fake) LLM route returns notify:false", async () => {
  const paths = await tempPaths();
  const profile = slice6Profile();
  const collectors = highMemoryCollectors();
  const deliveries = [];
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; };
  // Fake adjudicateAlertNotifications standing in for a real LLM call that judged this alert
  // not worth notifying — the DI seam already used by the "S13 I/O hardening" tests above.
  const adjudicateAlertNotificationsFake = async (descartesPaths, evaluation, options) => ({
    status: "ok",
    decisions: (evaluation.alerts ?? [])
      .filter((a) => (evaluation.notification_due_ids ?? []).includes(a.id))
      .map((a) => ({ alert_id: a.id, notify: false })),
  });

  await runDaemonIteration(paths, {
    profile, collectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z",
    deliverNotification,
    alertIntelligenceConfig: { enabled: true },
    adjudicateAlertNotifications: adjudicateAlertNotificationsFake,
  });
  const result = await runDaemonIteration(paths, {
    profile, collectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z",
    deliverNotification,
    alertIntelligenceConfig: { enabled: true },
    adjudicateAlertNotifications: adjudicateAlertNotificationsFake,
  });

  const memoryAlert = result.alerts.alerts.find((a) => a.rule_id === "system.memory.sustained_high");
  assert.ok(memoryAlert, "expected system.memory.sustained_high to be active after 2 sustained high-memory samples");

  assert.deepEqual(result.metricAlertFallback, { fired: [], skipped: "intelligence_enabled" }, "the fallback must not run at all once alert-intelligence is enabled");
  const memoryDeliveries = deliveries.filter((entry) => entry.opts.ruleId === "system.memory.sustained_high");
  assert.equal(memoryDeliveries.length, 0, "no raw notification for this rule_id: the LLM's own notify:false decision governs, undisturbed by the fallback");
});

test("F6: options.deliverMetricAlertFallback === false opts the daemon tick out of the new branch entirely (no metricAlertFallback, no deliverNotification call for the metric alert)", async () => {
  const paths = await tempPaths();
  const profile = slice6Profile();
  const collectors = highMemoryCollectors();
  const deliveries = [];
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; };

  await runDaemonIteration(paths, { profile, collectors, ts: "2026-05-24T00:00:00.000Z", now: "2026-05-24T00:00:00.000Z", deliverNotification, deliverMetricAlertFallback: false });
  const result = await runDaemonIteration(paths, { profile, collectors, ts: "2026-05-24T00:01:00.000Z", now: "2026-05-24T00:01:00.000Z", deliverNotification, deliverMetricAlertFallback: false });

  const memoryAlert = result.alerts.alerts.find((a) => a.rule_id === "system.memory.sustained_high");
  assert.ok(memoryAlert, "the candidate is still persisted — only active delivery is skipped");
  assert.equal(result.metricAlertFallback, undefined);
  assert.equal(deliveries.some((entry) => entry.ruleId === "system.memory.sustained_high"), false);
});

test("Slice 4: computeSessionBaselineCandidates candidate shape matches the existing extraCandidates sources (byte-identical structural key set)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment for the identical rationale) and confirm the shared
  // integrity ledger to 'intact' before the tick.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const result = await runIsolatedDaemonTick(paths, hour(30));
  const alert = result.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(alert);
  assert.equal(typeof alert.id, "string");
  assert.equal(typeof alert.diagnostics, "object");
  assert.equal(JSON.stringify(alert.diagnostics).includes("redacted"), false);

  const { state } = await loadSessionBaselineStore(paths);
  assert.equal(state.confidence_state, "established");
  assert.equal(state.stats.count, 31);
});

// ---------------------------------------------------------------------------------------------
// Slice 6 (observed-incident collectors plan): L2 incident-correlation wiring
// (computeCorrelationCandidates as the daemon's fifth extraCandidates entry).
// ---------------------------------------------------------------------------------------------

function peerFactPoint(ts, entityKey, { hourBucket = "02", sourceType = "wireguard" } = {}) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: entityKey,
    attributes: {
      source_type: sourceType,
      presence_state: "observed_active",
      login_hour_bucket: hourBucket,
      handshake_age_bucket: sourceType === "wireguard" ? "lt_1h" : "n/a",
    },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
  };
}

function correlationFixtureFactPoints() {
  const sessionTicks = [];
  for (let i = 0; i < 30; i += 1) sessionTicks.push(...completeSessionTick(hour(i), 20));
  sessionTicks.push(...completeSessionTick(hour(30), 0));
  // A "regular" peer observed daily at an ordinary hour establishes stream-wide maturity (the
  // must-fix 4 cold-start gate) without itself ever qualifying as odd-hour/novel.
  const peerTicks = [];
  for (let day = 0; day < 5; day += 1) {
    const ts = new Date(Date.parse(hour(30)) - day * 24 * 60 * 60 * 1000).toISOString();
    peerTicks.push(peerFactPoint(ts, "peer.ssh.1111111111111111", { hourBucket: "12", sourceType: "ssh" }));
  }
  // The rare/odd-hour peer, observed exactly at the anchor's own tick.
  peerTicks.push(peerFactPoint(hour(30), "peer.wireguard.9999999999999999"));
  return [...sessionTicks, ...peerTicks];
}

test("Slice 6 wiring: computeCorrelationCandidates is the daemon's fifth extraCandidates entry — once the session.count_drop anchor has been persisted by a prior tick, a following tick joins it against an odd-hour/novel peer login and produces a real, sanitized correlation.login_kill_proximity alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 4) gave session-baseline.js its own persistent
  // cold-start lockout. This test's session.count_drop "anchor" is a session-baseline candidate
  // (the correlation alert itself belongs to incident-correlation.js, Slice 8, out of this
  // module's scope) — pre-establish the store and confirm the shared integrity ledger to 'intact'
  // so the anchor fires as this test already expects, same as the SESSION-specific fixtures above.
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, correlationFixtureFactPoints(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  // Tick 1: computeSessionBaselineCandidates first derives and PERSISTS the session.count_drop
  // anchor. computeCorrelationCandidates reads alert-HISTORY from disk independently (Decision 1)
  // — it never sees this same tick's own in-memory candidate array — so no correlation candidate
  // exists yet after this first tick alone (an intentional, documented one-tick lag, off by at
  // most one structural-tick cadence, per the plan's Decision 1).
  const tick1 = await runIsolatedDaemonTick(paths, hour(30));
  const anchor = tick1.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(anchor, "expected the session.count_drop anchor to fire on tick 1");
  assert.equal(tick1.alerts.alerts.some((a) => a.rule_id === CORRELATION_RULE_ID), false, "no correlation candidate yet — the anchor was only just persisted by this same tick");

  // Tick 2, a few minutes later: the now-persisted anchor is visible to computeCorrelationCandidates'
  // own readAlertRecords call, and the join fires.
  const tick2Ts = new Date(Date.parse(hour(30)) + 5 * 60 * 1000).toISOString();
  const tick2 = await runIsolatedDaemonTick(paths, tick2Ts);
  const persistedAnchor = tick2.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(persistedAnchor, "expected the session.count_drop anchor to still be active on tick 2");

  const correlation = tick2.alerts.alerts.find((a) => a.rule_id === CORRELATION_RULE_ID);
  assert.ok(correlation, "expected a real correlation.login_kill_proximity alert record on tick 2");
  assert.equal(correlation.status, "active");
  assert.equal(correlation.severity, "warning", "stored severity is capped at warning even for a critical anchor");
  assert.equal(correlation.diagnostics.peer_entity_key, "peer.wireguard.9999999999999999");
  assert.equal(correlation.diagnostics.anchor_severity, persistedAnchor.severity);
  assert.equal(JSON.stringify(correlation.diagnostics).includes("redacted"), false);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === correlation.id && a.status === "active"));
});

test("Slice 6: byte-identical real alerts when the learned kill switch is off, even with peer/session fact-history present that would otherwise correlate, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withHistoryPaths = await tempPaths();
  await appendFactPoints(withHistoryPaths, correlationFixtureFactPoints(), { now: hour(30) });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the baseline above — computeCorrelationCandidates must
  // short-circuit to [] before ever calling readFactPoints/readAlertRecords.
  let readFactsCalled = false;
  let readAlertsCalled = false;
  const withHistory = await runDaemonIteration(withHistoryPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
    readAlertRecords: async (...args) => {
      readAlertsCalled = true;
      return readAlertRecords(...args);
    },
  });

  assert.deepEqual(withHistory.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withHistory.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withHistory.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");
  assert.equal(readAlertsCalled, false, "readAlertRecords (the correlation module's own hook) must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withHistoryPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === CORRELATION_RULE_ID), false);
});

// ---------------------------------------------------------------------------------------------
// Slice 4b (observed-incident collectors plan): peer-count SPIKE deviation
// (computePeerBaselineCandidates as the daemon's sixth extraCandidates entry).
// ---------------------------------------------------------------------------------------------

function completePeerTick(ts, count, entityPrefix = "peer.ssh.e") {
  const points = [];
  for (let i = 0; i < count; i += 1) points.push(peerFactPoint(ts, `${entityPrefix}-${i}`, { sourceType: "ssh" }));
  return points;
}

test("Slice 4b: byte-identical real alerts when the learned kill switch is off, even with peer fact-history present that would otherwise deviate, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withPeersPaths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTick(hour(i), 2));
  ticks.push(...completePeerTick(hour(30), 8));
  await appendFactPoints(withPeersPaths, ticks, { now: hour(30) });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the baseline above — computePeerBaselineCandidates must
  // short-circuit to [] before ever calling readFactPoints.
  let readFactsCalled = false;
  const withPeers = await runDaemonIteration(withPeersPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
  });

  assert.deepEqual(withPeers.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withPeers.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withPeers.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withPeersPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === PEER_COUNT_SPIKE_RULE_ID), false);
});

test("Slice 4b wiring: computePeerBaselineCandidates is the daemon's sixth extraCandidates entry — a pre-seeded odd-hour peer-login burst produces a real, sanitized peer.count_spike alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5) gave peer-baseline.js its own persistent
  // cold-start lockout, mirroring process-lineage-baseline.js's/session-baseline.js's own — see
  // the "Process-lineage wiring" test's comment for the identical rationale. Pre-establish the
  // store (this wiring test is about the daemon pipeline, not the lockout, which has its own
  // dedicated coverage in peer-baseline.test.js) and confirm the shared integrity ledger to
  // 'intact' before the tick.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTick(hour(i), 2));
  ticks.push(...completePeerTick(hour(30), 8));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const result = await runIsolatedDaemonTick(paths, hour(30));
  const alert = result.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(alert, "expected a real alert for the peer-count burst");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning", "stored severity is capped at warning even for an extreme z (MUST-FIX 1)");
  assert.equal(alert.diagnostics.observed_count, 8);
  assert.equal(alert.diagnostics.mean_before, 2);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));

  const { state } = await loadPeerBaselineStore(paths);
  assert.equal(state.confidence_state, "established");
  assert.equal(state.stats.count, 31);
});

test("Slice 4b, Decision 3b: a due peer.count_spike is delivered through the deterministic local delivery branch wired into the daemon tick, and never reaches the LLM path", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment above for the identical rationale) and confirm the
  // shared integrity ledger to 'intact' before the tick.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTick(hour(i), 2));
  ticks.push(...completePeerTick(hour(30), 8));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });

  assert.ok(result.sessionAlertDelivery, "expected a sessionAlertDelivery result on the daemon iteration");
  const peerDeliveries = deliveries.filter((entry) => entry.opts.ruleId === PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(peerDeliveries.length, 1, "expected exactly one deterministic delivery for the due peer.count_spike candidate");
  assert.equal(peerDeliveries[0].decision.notify, true);
  assert.equal(peerDeliveries[0].decision.severity, "warning");

  // Never via the LLM path: peer.* is unknown_namespace, so adjudicateAlertNotifications must
  // never have constructed a session for it (alert-intelligence.json defaults to disabled anyway,
  // giving a doubly-enforced guarantee here).
  assert.equal(result.alertIntelligence.status, "disabled");
});

// ---------------------------------------------------------------------------------------------
// Slice 4c (observed-incident collectors plan): peer-count DROP deviation (peer.count_drop).
// No daemon.js code change is required for this direction -- computePeerBaselineCandidates
// already returns BOTH spike and drop candidates from the SAME sixth extraCandidates entry (see
// plan §5, "No-change files"). These tests confirm that wiring holds for the drop direction too.
// Unlike completePeerTick above (legacy, marker-less fixtures -- kept unmodified for the existing
// spike tests' own backward-compat coverage), peer.count_drop requires the Slice 4c census marker
// on every tick to ever leave "provisional".
// ---------------------------------------------------------------------------------------------

function completePeerTickWithMarker(ts, count, signature = "v1:ok-ok-ok-ok-ok", entityPrefix = "peer.ssh.e") {
  return [
    ...completePeerTick(ts, count, entityPrefix),
    {
      ts,
      fact_name: "peer.presence",
      entity_key: PEER_CENSUS_MARKER_ENTITY_KEY,
      attributes: { availability_signature: signature },
      source_envelope_id: "vpn-peer-status",
      source_tool: "collect_vpn_peer_status",
      sensitivity: "operational",
      confidence: 0,
    },
  ];
}

test("Slice 4c wiring: computePeerBaselineCandidates' drop direction flows through the daemon's EXISTING sixth extraCandidates entry with NO daemon.js code change -- a pre-seeded mass peer drop produces a real, sanitized peer.count_drop alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment above for the identical rationale) and confirm the
  // shared integrity ledger to 'intact' before the tick.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTickWithMarker(hour(i), 10));
  ticks.push(...completePeerTickWithMarker(hour(30), 1));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const result = await runIsolatedDaemonTick(paths, hour(30));
  const alert = result.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_DROP_RULE_ID);
  assert.ok(alert, "expected a real alert for the peer-count drop");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning", "stored severity is capped at warning even for an extreme z (Decision 0)");
  assert.equal(alert.diagnostics.observed_count, 1);
  assert.equal(alert.diagnostics.mean_before, 10);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));

  const { state } = await loadPeerBaselineStore(paths);
  assert.equal(state.drop.confidence_state, "established");
});

test("Slice 4c, delivery: a due peer.count_drop is delivered through the deterministic local delivery branch wired into the daemon tick, and never reaches the LLM path", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 5): pre-establish the cold-start lockout (see the
  // "Process-lineage wiring" test's comment above for the identical rationale) and confirm the
  // shared integrity ledger to 'intact' before the tick.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTickWithMarker(hour(i), 10));
  ticks.push(...completePeerTickWithMarker(hour(30), 1));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });

  assert.ok(result.sessionAlertDelivery, "expected a sessionAlertDelivery result on the daemon iteration");
  const peerDropDeliveries = deliveries.filter((entry) => entry.opts.ruleId === PEER_COUNT_DROP_RULE_ID);
  assert.equal(peerDropDeliveries.length, 1, "expected exactly one deterministic delivery for the due peer.count_drop candidate");
  assert.equal(peerDropDeliveries[0].decision.notify, true);
  assert.equal(peerDropDeliveries[0].decision.severity, "warning");

  // Never via the LLM path: peer.* is unknown_namespace, so adjudicateAlertNotifications must
  // never have constructed a session for it (alert-intelligence.json defaults to disabled anyway,
  // giving a doubly-enforced guarantee here).
  assert.equal(result.alertIntelligence.status, "disabled");
});

test("Slice 4c: byte-identical real alerts when the learned kill switch is off, even with marker-bearing peer fact-history present that would otherwise drop-deviate, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withPeersPaths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTickWithMarker(hour(i), 10));
  ticks.push(...completePeerTickWithMarker(hour(30), 1));
  await appendFactPoints(withPeersPaths, ticks, { now: hour(30) });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false } -- computePeerBaselineCandidates must short-circuit to [] (both
  // directions) before ever calling readFactPoints.
  let readFactsCalled = false;
  const withPeers = await runDaemonIteration(withPeersPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
  });

  assert.deepEqual(withPeers.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withPeers.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withPeers.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withPeersPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === PEER_COUNT_DROP_RULE_ID), false);
});

test("Slice 4b ts-cohesion (integration): peer.presence fact points share the same ts as session.presence fact points emitted within the same structural-tick iteration", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const structuralCollectors = {
    ...structuralCollectorFakes(),
    sessions: async () => envelope("sessions", "collect_sessions", {
      platform: "darwin",
      multiplexers: [{ multiplexer: "tmux", status: "ok" }, { multiplexer: "screen", status: "absent" }],
      any_binary_available: true,
      total_count: 1,
      sessions: [{ multiplexer: "tmux", session_name: "alpha", attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 }],
      truncated: false,
      cap: 200,
    }),
    "vpn-peer-status": async () => vpnPeerStatusEnvelopeFixture(),
  };
  const profile = structuralProfile({
    collectors: { services: { enabled: true }, network: { enabled: true }, "scheduled-jobs": { enabled: true }, sessions: { enabled: true }, "vpn-peer-status": { enabled: true } },
  });

  await runDaemonIteration(paths, {
    profile,
    collectors: fastCollectorFakes(),
    structuralCollectors,
    ts: "2026-06-11T00:00:00.000Z",
    now: Date.parse("2026-06-11T00:00:00.000Z"),
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    writeStructuralCheckpoint: async () => ({}),
  });

  const { points } = await readFactPoints(paths);
  const sessionPoints = points.filter((point) => point.fact_name === "session.presence");
  const peerPoints = points.filter((point) => point.fact_name === "peer.presence");
  assert.ok(sessionPoints.length > 0 && peerPoints.length > 0);
  const distinctTimestamps = new Set([...sessionPoints, ...peerPoints].map((point) => point.ts));
  assert.equal(distinctTimestamps.size, 1, `expected every session.*/peer.* fact point to share one ts, got ${JSON.stringify([...distinctTimestamps])}`);
  assert.equal([...distinctTimestamps][0], "2026-06-11T00:00:00.000Z");
});

// ---------------------------------------------------------------------------------------------
// Service-disappearance ALERT (docs/plans/2026-07-23-service-disappearance-alert.md): residual
// daemon-wiring regression test the plan committed to (Wave 1 left it out of that task's file
// scope). computeServiceBaselineCandidates is the daemon's SEVENTH extraCandidates entry (src/
// daemon.js), threading the SAME activeFreshnessMs already resolved once per tick for
// computeActiveConstraintCandidates. Mirrors the Slice 4 session wiring test above and the Slice
// 4b/4c peer wiring tests above it, adapted for service.disappeared's set-diff shape.
// ---------------------------------------------------------------------------------------------

function servicePresenceFactPoint(ts, entityKey) {
  return {
    ts,
    fact_name: "service.presence",
    entity_key: entityKey,
    attributes: { running: "true", manager: "launchd" },
    source_envelope_id: "services",
    source_tool: "collect_services",
    sensitivity: "operational",
  };
}

function serviceCensusMarkerFactPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: SERVICE_CENSUS_FACT_NAME,
    entity_key: SERVICE_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "services",
    source_tool: "collect_services",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeServiceTick(ts, entityKeys) {
  return [...entityKeys.map((key) => servicePresenceFactPoint(ts, key)), serviceCensusMarkerFactPoint(ts, "complete")];
}

function lineageEdgeFactPoint(ts, entityKey) {
  return {
    ts,
    fact_name: "process.lineage_edge",
    entity_key: entityKey,
    attributes: {},
    source_envelope_id: "process-lineage-edges",
    source_tool: "collect_process_lineage",
    sensitivity: "operational",
  };
}

function lineageCensusMarkerFactPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: "process.lineage_edge.census",
    entity_key: "process.lineage_edge.census-marker.v1",
    attributes: { census_state: state },
    source_envelope_id: "process-lineage-edges",
    source_tool: "collect_process_lineage",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeLineageTick(ts, entityKeys) {
  return [...entityKeys.map((key) => lineageEdgeFactPoint(ts, key)), lineageCensusMarkerFactPoint(ts)];
}

function lineageNoveltyFixtureFactPoints() {
  const establishedEdge = "5:shellnode";
  const novelEdge = "5:shellpython";
  const ticks = [];
  for (let i = 0; i < 6; i += 1) ticks.push(...completeLineageTick(hour(i), [establishedEdge]));
  ticks.push(...completeLineageTick(hour(6), [establishedEdge, novelEdge]));
  return ticks;
}

test("Process-lineage wiring: a novel edge flows through the daemon's alert pipeline as a warning", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Prime the baseline store as already-established: process-lineage-baseline.js's persistent
  // cold-start lockout (a corrupt/missing/reset store must re-accumulate minHistoryTickCount
  // genuinely new ticks before trusting the live fact window, never self-heal-and-immediately-
  // fire) would otherwise gate this single-tick fixture to zero regardless of how much history
  // it already contains — that lockout has its own dedicated coverage in
  // process-lineage-baseline.test.js. This wiring test is about the daemon pipeline, not the
  // lockout. A genuinely-established store must carry a valid last_folded_ts (the process-
  // lineage-baseline.js exact-schema fix rejects an established store without one), so an
  // arbitrary before-the-fixture anchor is supplied here.
  await writeProcessLineageBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  // The fact-store completeness gate (Slice 3) cold-starts process-lineage novelty while the
  // integrity ledger reads 'unknown'. A fresh ledger's FIRST retention pass is deliberately
  // 'unknown' (the bootstrap anti-laundering rule — a first/unconfirmed ledger cannot be
  // trusted); a SECOND independent clean pass confirms it to 'intact'. A genuinely-established
  // store has had many structural ticks, so its ledger is 'intact' and novelty fires. Mirror
  // that here: append the fixture ONCE (the bootstrap pass), then trigger one more clean
  // retention pass with no new facts (appendFactPoints still runs enforceFactRetention) to
  // confirm the ledger to 'intact'. NB: re-appending the fixture facts instead would leave the
  // ledger 'unknown' — duplicated facts share the latest fact ts, and excess records that don't
  // advance newest_ts are treated as unprovable/tampered (an intended continuity guard), not a
  // benign append.
  await appendFactPoints(paths, lineageNoveltyFixtureFactPoints(), { now: hour(6) });
  await appendFactPoints(paths, [], { now: hour(6) });

  const result = await runIsolatedDaemonTick(paths, hour(6));
  const alert = result.alerts.alerts.find((candidate) => candidate.rule_id === PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID);
  assert.ok(alert, "expected a real alert for the novel process lineage edge");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning");
  assert.equal(typeof alert.diagnostics.entity_key_hash, "string");
  assert.equal(JSON.stringify(alert).includes("shellpython"), false, "edge identity must not be emitted in cleartext");

  const { state } = await loadProcessLineageBaselineStore(paths);
  assert.equal(state.last_folded_ts, hour(6));
  assert.equal(state.novel_edge_event_count, 1);
  assert.equal(state.skipped_partial_tick_count, 0);
});

// ---------------------------------------------------------------------------------------------
// Persistence baseline, Slice B (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md):
// scheduled_job.appeared. Mirrors the "Process-lineage wiring" test immediately above exactly —
// same absence/novelty gate discipline (DEFAULT_SCHEDULED_JOB_MIN_HISTORY_TICK_COUNT is 6, same
// as process-lineage's own default).
// ---------------------------------------------------------------------------------------------

function scheduledJobPresenceFactPoint(ts, entityKey) {
  return {
    ts,
    fact_name: SCHEDULED_JOB_PRESENCE_FACT_NAME,
    entity_key: entityKey,
    attributes: { kind: "systemd_timer", source: "systemd_timers" },
    source_envelope_id: "scheduled-jobs",
    source_tool: "collect_scheduled_jobs",
    sensitivity: "operational",
  };
}

function scheduledJobCensusMarkerFactPoint(ts, state = "complete") {
  return {
    ts,
    fact_name: SCHEDULED_JOB_CENSUS_FACT_NAME,
    entity_key: SCHEDULED_JOB_CENSUS_MARKER_ENTITY_KEY,
    attributes: { census_state: state },
    source_envelope_id: "scheduled-jobs",
    source_tool: "collect_scheduled_jobs",
    sensitivity: "operational",
    confidence: 0,
  };
}

function completeScheduledJobTick(ts, entityKeys) {
  return [...entityKeys.map((key) => scheduledJobPresenceFactPoint(ts, key)), scheduledJobCensusMarkerFactPoint(ts, "complete")];
}

function scheduledJobNoveltyFixtureFactPoints() {
  const establishedKey = buildScheduledJobEntityKey("systemd_timer", "systemd_timers", "backup.timer");
  const novelKey = buildScheduledJobEntityKey("systemd_timer", "systemd_timers", "exfil.timer");
  const ticks = [];
  for (let i = 0; i < 6; i += 1) ticks.push(...completeScheduledJobTick(hour(i), [establishedKey]));
  ticks.push(...completeScheduledJobTick(hour(6), [establishedKey, novelKey]));
  return { ticks, establishedKey, novelKey };
}

test("Scheduled-job persistence wiring: computeScheduledJobBaselineCandidates reaches the daemon's extraCandidates array — a novel scheduled job flows through the alert pipeline as a warning, gated by its own completeness lockout (absence/novelty claim)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Prime the baseline store as already-established (same rationale as the process-lineage wiring
  // test above): this wiring test is about the daemon pipeline, not the lockout itself, which has
  // its own dedicated coverage in persistence-baseline.test.js.
  await writePersistenceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const { ticks, novelKey } = scheduledJobNoveltyFixtureFactPoints();
  await appendFactPoints(paths, ticks, { now: hour(6) });
  await appendFactPoints(paths, [], { now: hour(6) }); // confirm the shared integrity ledger to 'intact'

  const result = await runIsolatedDaemonTick(paths, hour(6));
  const alert = result.alerts.alerts.find((candidate) => candidate.rule_id === SCHEDULED_JOB_APPEARED_RULE_ID);
  assert.ok(alert, "expected a real alert for the novel scheduled job");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning");
  assert.equal(typeof alert.diagnostics.entity_key_hash, "string");
  assert.equal(JSON.stringify(alert).includes(novelKey), false, "job identity must not be emitted in cleartext (O1 hash-only default)");

  const { state } = await loadPersistenceBaselineStore(paths);
  assert.equal(state.last_folded_ts, hour(6));
  assert.equal(state.appeared_event_count, 1);
});

test("Scheduled-job persistence: byte-identical real alerts when the learned kill switch is off, even with scheduled-job fact-history present that would otherwise appear-fire, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withJobsPaths = await tempPaths();
  const { ticks } = scheduledJobNoveltyFixtureFactPoints();
  await appendFactPoints(withJobsPaths, ticks, { now: hour(6) });
  let readFactsCalled = false;
  const withJobs = await runDaemonIteration(withJobsPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(6),
    now: hour(6),
    readFactPoints: async (...args) => { readFactsCalled = true; return readFactPoints(...args); },
  });

  assert.deepEqual(withJobs.alerts.alerts, baseline.alerts.alerts);
  assert.equal(withJobs.alerts.alerts.some((a) => a.rule_id === SCHEDULED_JOB_APPEARED_RULE_ID), false);
  assert.equal(readFactsCalled, false, "computeScheduledJobBaselineCandidates must short-circuit before ever calling readFactPoints while the kill switch is off");
});

// 30 complete censuses in which "worker.service" is present (establishing it -- the default
// minEstablishedCount is 3), then a 31st complete census in which it is missing.
function serviceDisappearanceFixtureFactPoints({ presentEntity = "worker.service" } = {}) {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeServiceTick(hour(i), [presentEntity]));
  ticks.push(...completeServiceTick(hour(30), []));
  return ticks;
}

test("Service-disappearance wiring: computeServiceBaselineCandidates is the daemon's seventh extraCandidates entry — a pre-seeded service census with a service missing from the latest complete census produces a real, sanitized service.disappeared alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Fact-store completeness hardening (Slice 6) gave service-baseline.js its own persistent
  // cold-start lockout, mirroring process-lineage-baseline.js's/session-baseline.js's/
  // peer-baseline.js's — see the "Process-lineage wiring" test above for the identical rationale.
  // Pre-establish the store (this wiring test is about the daemon pipeline, not the lockout, which
  // has its own dedicated coverage in service-baseline.test.js) and confirm the shared integrity
  // ledger to 'intact' before the tick.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, serviceDisappearanceFixtureFactPoints(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const result = await runIsolatedDaemonTick(paths, hour(30));
  const alert = result.alerts.alerts.find((a) => a.rule_id === SERVICE_DISAPPEARED_RULE_ID);
  assert.ok(alert, "expected a real alert for the disappeared service");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning");
  assert.equal(typeof alert.diagnostics, "object");
  assert.equal(typeof alert.diagnostics.entity_key_hash, "string");
  assert.equal(alert.diagnostics.service_name, "worker.service", "service.disappeared names the service (sanitized cleartext) in diagnostics.service_name — operator decision 2026-07-24");
  assert.notEqual(alert.fingerprint, "worker.service", "fingerprint must be the hash, never the raw entity_key");
  assert.equal(JSON.stringify(alert).includes("redacted"), false);

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));

  const { state } = await loadServiceBaselineStore(paths);
  assert.equal(state.last_folded_ts, hour(30));
  assert.equal(state.disappearance_event_count, 1);
  assert.equal(state.skipped_partial_tick_count, 0);
});

test("Service-disappearance: byte-identical real alerts when the learned kill switch is off, even with service fact-history present that would otherwise produce a disappearance, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withServicesPaths = await tempPaths();
  await appendFactPoints(withServicesPaths, serviceDisappearanceFixtureFactPoints(), { now: hour(30) });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false }, exactly like the baseline above — computeServiceBaselineCandidates must
  // short-circuit to [] before ever calling readFactPoints.
  let readFactsCalled = false;
  const withServices = await runDaemonIteration(withServicesPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return readFactPoints(...args);
    },
  });

  assert.deepEqual(withServices.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withServices.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withServices.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while the learned.json kill switch is off");

  const persisted = await readAlertRecords(withServicesPaths);
  assert.equal(persisted.some((alert) => alert.rule_id === SERVICE_DISAPPEARED_RULE_ID), false);
});

// Single-source-of-truth wiring proof: computeServiceBaselineCandidates is threaded the SAME
// activeFreshnessMs computeActiveConstraintCandidates already receives (src/daemon.js ~L565,
// "Threads the SAME activeFreshnessMs already resolved above"). Rather than reaching into
// daemon.js's private per-call args (neither function is options-overridable), this pins BOTH
// sources to fact-history that shares the exact same latest ts (hour(30)) and drives ONE daemon
// iteration per boundary side, mirroring Slice B's own two freshness tests
// ("an active constraint whose only fact is older than 3× the structural interval is STALE" /
// "freshness is pinned to the STRUCTURAL interval, NOT the fast tick") — but now asserting BOTH
// the constraint-violation alert AND the service.disappeared alert flip identically at the exact
// same 3h boundary within the SAME iteration. If either source resolved a different
// activeFreshnessMs value, this pair of assertions would diverge at one of the two boundaries.
test("Service-disappearance wiring, single-source-of-truth: a service.disappeared transition older than 3× the structural interval is STALE, using the identical activeFreshnessMs boundary computeActiveConstraintCandidates already applies to a violated active constraint in the SAME iteration", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout and confirm
  // the shared integrity ledger to 'intact' (see the "Service-disappearance wiring" test above for
  // the identical rationale) — this pair of tests is about the shared activeFreshnessMs boundary,
  // not the lockout.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [
    ...serviceDisappearanceFixtureFactPoints(),
    { ts: hour(30), fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ];
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  // now = shared latest ts (hour(30)) + 4h; activeFreshnessMs = 3 × DEFAULT_STRUCTURAL_INTERVAL_MS
  // (1h) = 3h (slice6Profile carries no `structural.interval_ms`, so runDaemonIteration resolves
  // the SAME default both sources consume) -> 4h is stale for BOTH in this one daemon tick.
  const staleNow = new Date(Date.parse(hour(30)) + 4 * 60 * 60 * 1000).toISOString();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: staleNow,
    now: staleNow,
  });

  assert.equal(result.alerts.alerts.some((a) => a.rule_id === "constraint.violation.service-presence"), false, "a 4h-stale constraint fact must not drive a live violation");
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === SERVICE_DISAPPEARED_RULE_ID), false, "a 4h-stale service-census transition must not drive a live disappearance alert, using the SAME freshness boundary");
});

test("Service-disappearance wiring, single-source-of-truth: a 1h-old service.disappeared transition is still fresh within the shared 3h activeFreshnessMs window and fires, in the SAME iteration a 1h-old violated active constraint also fires", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  // Fact-store completeness hardening (Slice 6): pre-establish the cold-start lockout and confirm
  // the shared integrity ledger to 'intact' (see the "Service-disappearance wiring" test above for
  // the identical rationale) — this pair of tests is about the shared activeFreshnessMs boundary,
  // not the lockout.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [
    ...serviceDisappearanceFixtureFactPoints(),
    { ts: hour(30), fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ];
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const freshNow = new Date(Date.parse(hour(30)) + 60 * 60 * 1000).toISOString();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: freshNow,
    now: freshNow,
  });

  assert.ok(result.alerts.alerts.some((a) => a.rule_id === "constraint.violation.service-presence"), "expected the 1h-old constraint violation to still fire within the shared freshness window");
  assert.ok(result.alerts.alerts.some((a) => a.rule_id === SERVICE_DISAPPEARED_RULE_ID), "expected the 1h-old service.disappeared transition to still fire, sharing the SAME activeFreshnessMs as the constraint above");
});

// ---------------------------------------------------------------------------------------------
// Persistence baseline, Slice C: service.appeared — the appearance-direction twin of
// service.disappeared, wired as its own extraCandidates entry with its own SEPARATE store (O3).
// ---------------------------------------------------------------------------------------------

test("Service-appearance wiring: computeServiceAppearanceCandidates reaches the daemon's extraCandidates array — a new service unit in the latest complete census produces a real, sanitized service.appeared alert record in alerts.json", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // Prime BOTH stores as already-established: computeServiceAppearanceCandidates has its OWN
  // persistent cold-start lockout, separate from the disappearance path's store (O3) — this
  // wiring test is about the daemon pipeline, not the lockout itself.
  await writeServiceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await writeServiceAppearanceBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 3; i += 1) ticks.push(...completeServiceTick(hour(i), ["worker.service"]));
  ticks.push(...completeServiceTick(hour(3), ["worker.service", "new-backdoor.service"]));
  await appendFactPoints(paths, ticks, { now: hour(3) });
  await appendFactPoints(paths, [], { now: hour(3) });

  const result = await runIsolatedDaemonTick(paths, hour(3));
  const alert = result.alerts.alerts.find((candidate) => candidate.rule_id === SERVICE_APPEARED_RULE_ID);
  assert.ok(alert, "expected a real alert for the newly-appeared service");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning");
  assert.equal(typeof alert.diagnostics.entity_key_hash, "string");
  assert.equal(alert.diagnostics.service_name, undefined, "service.appeared is hash-only by default (O1) -- deliberately NOT service.disappeared's cleartext-name exception");
  assert.equal(JSON.stringify(alert).includes("new-backdoor.service"), false);

  const { state } = await loadServiceAppearanceBaselineStore(paths);
  assert.equal(state.last_folded_ts, hour(3));
  assert.equal(state.appeared_event_count, 1);
});

test("Service-appearance: byte-identical real alerts when the learned kill switch is off, even with service fact-history present that would otherwise appear-fire, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withServicesPaths = await tempPaths();
  const ticks = [];
  for (let i = 0; i < 3; i += 1) ticks.push(...completeServiceTick(hour(i), ["worker.service"]));
  ticks.push(...completeServiceTick(hour(3), ["worker.service", "new-backdoor.service"]));
  await appendFactPoints(withServicesPaths, ticks, { now: hour(3) });
  const withServices = await runIsolatedDaemonTick(withServicesPaths, hour(3));

  assert.deepEqual(withServices.alerts.alerts, baseline.alerts.alerts);
  assert.equal(withServices.alerts.alerts.some((a) => a.rule_id === SERVICE_APPEARED_RULE_ID), false);
});

// ---------------------------------------------------------------------------------------------
// Credential-file-access signal, Slice D: credential.access — a per-path lstat mtime/ino diff,
// NOT gated by any fact-store completeness lockout (positive direct evidence, P7 own store).
// ---------------------------------------------------------------------------------------------

test("evaluateAlerts:false skips detector I/O and leaves the credential baseline unchanged, while the default evaluates it", async () => {
  const initialEntries = { "0123456789abcdef": { atime: 1000, mtime: 2000, ino: 42 } };
  const changedEvidence = {
    status: "ok",
    result: {
      entries: [{
        category: "ssh_private_key",
        path_hash: "0123456789abcdef",
        watch: ["mtime", "ino"],
        status: "ok",
        atime: 1000,
        mtime: 9999,
        ino: 42,
        size: 7,
      }],
    },
  };

  async function seededPaths() {
    const paths = await tempPaths();
    await writeLearnedConfig(paths, { enabled: true });
    await writeCredentialAccessBaselineStore(paths, { entries: initialEntries });
    return paths;
  }

  const disabledPaths = await seededPaths();
  let detectorIoCalls = 0;
  let disabledCollectCalled = false;
  const disabled = await runDaemonIteration(disabledPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(0),
    now: hour(0),
    evaluateAlerts: false,
    collectCredentialAccessEvidence: async () => {
      disabledCollectCalled = true;
      return changedEvidence;
    },
    loadCredentialAccessBaselineStore: async (...args) => {
      detectorIoCalls += 1;
      return loadCredentialAccessBaselineStore(...args);
    },
    writeCredentialAccessBaselineStore: async (...args) => {
      detectorIoCalls += 1;
      return writeCredentialAccessBaselineStore(...args);
    },
  });

  assert.equal(disabled.alerts, undefined);
  assert.equal(disabledCollectCalled, false);
  assert.equal(detectorIoCalls, 0);
  assert.deepEqual((await loadCredentialAccessBaselineStore(disabledPaths)).entries, initialEntries);

  const enabledPaths = await seededPaths();
  let enabledCollectCalled = false;
  const enabled = await runDaemonIteration(enabledPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(0),
    now: hour(0),
    collectCredentialAccessEvidence: async () => {
      enabledCollectCalled = true;
      return changedEvidence;
    },
  });

  assert.equal(enabledCollectCalled, true);
  assert.notDeepEqual((await loadCredentialAccessBaselineStore(enabledPaths)).entries, initialEntries);
  assert.equal(enabled.alerts.alerts.find((candidate) => candidate.rule_id === CREDENTIAL_ACCESS_RULE_ID)?.status, "active");
});

test("Credential-file-access wiring: computeCredentialAccessCandidates reaches the daemon's extraCandidates array — a real mtime change against a pre-seeded per-path baseline produces a real, sanitized credential.access alert record in alerts.json, firing on the FIRST eligible observation (not completeness-gated)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeCredentialAccessBaselineStore(paths, { entries: { "0123456789abcdef": { atime: 1000, mtime: 2000, ino: 42 } } });

  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(0),
    now: hour(0),
    collectCredentialAccessEvidence: async () => ({
      status: "ok",
      result: {
        entries: [{ category: "ssh_private_key", path_hash: "0123456789abcdef", watch: ["mtime", "ino"], status: "ok", atime: 1000, mtime: 9999, ino: 42, size: 7 }],
      },
    }),
  });

  const alert = result.alerts.alerts.find((candidate) => candidate.rule_id === CREDENTIAL_ACCESS_RULE_ID);
  assert.ok(alert, "expected a real alert for the credential-file mtime change");
  assert.equal(alert.status, "active");
  assert.equal(alert.severity, "warning");
  assert.equal(alert.diagnostics.trip_reason, "mtime_changed");
  assert.equal(alert.diagnostics.category, "ssh_private_key");
  assert.equal(alert.diagnostics.path_hash, "0123456789abcdef");
  assert.equal(JSON.stringify(alert).includes("/"), false, "no literal filesystem path ever reaches the alert record");

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === alert.id && a.status === "active"));
});

test("Credential-file-access: byte-identical real alerts when the learned kill switch is off, even with a real mtime change present that would otherwise trip, and no lstat is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withChangePaths = await tempPaths();
  await writeCredentialAccessBaselineStore(withChangePaths, { entries: { "0123456789abcdef": { atime: 1000, mtime: 2000, ino: 42 } } });
  let collectCalled = false;
  const withChange = await runDaemonIteration(withChangePaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(0),
    now: hour(0),
    collectCredentialAccessEvidence: async () => {
      collectCalled = true;
      return { status: "ok", result: { entries: [{ category: "ssh_private_key", path_hash: "0123456789abcdef", watch: ["mtime", "ino"], status: "ok", atime: 1000, mtime: 9999, ino: 42, size: 7 }] } };
    },
  });

  assert.deepEqual(withChange.alerts.alerts, baseline.alerts.alerts);
  assert.equal(withChange.alerts.alerts.some((a) => a.rule_id === CREDENTIAL_ACCESS_RULE_ID), false);
  assert.equal(collectCalled, false, "computeCredentialAccessCandidates must short-circuit before ever collecting lstat evidence while the kill switch is off");
});

// ---------------------------------------------------------------------------------------------
// S13 I/O hardening: the daemon.js call site (runDaemonIteration ~L531) is defense-in-depth --
// adjudicateAlertNotifications is now fail-closed internally at every I/O point, but this call
// site previously had NO try/catch up the stack at all, so an unhandled rejection here would kill
// the daemon process outright.
// ---------------------------------------------------------------------------------------------

test("S13 I/O hardening: an injected adjudicateAlertNotifications throw does not crash runDaemonIteration -- it resolves with a {status:'error'}-shaped alertIntelligence result", async () => {
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

  const result = await runDaemonIteration(paths, {
    collectors,
    ts,
    now: ts,
    adjudicateAlertNotifications: async () => {
      throw new Error("simulated unexpected adjudicateAlertNotifications failure");
    },
  });

  // The call resolved (did not reject/throw) -- proving the daemon tick did not crash.
  assert.equal(result.status.state, "ok");
  assert.equal(result.alertIntelligence.status, "error");
  assert.match(result.alertIntelligence.error, /simulated unexpected adjudicateAlertNotifications failure/);
});

// ---------------------------------------------------------------------------------------------
// Slice 7.2 (recommend-only containment surface plan, docs/plans/
// 2026-08-21-slice-7.2-recommend-only-containment-surface.md): computeContainmentRecommendationCandidates
// as the daemon's NINTH extraCandidates entry. Reuses peer.count_spike as the real trigger (it is
// re-derived fresh from persisted fact-history every tick, so it stays genuinely active across
// consecutive ticks without any further seeding -- exactly what the opt-in-toggle test below
// needs to isolate "only the containment opt-in changed" from "the trigger itself cleared").
// ---------------------------------------------------------------------------------------------

function containmentPeerSpikeTicks() {
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completePeerTick(hour(i), 2));
  ticks.push(...completePeerTick(hour(30), 8));
  return ticks;
}

test("Slice 7.2 wiring: containment is a post-evaluation phase — a current active-and-due peer.count_spike produces a same-tick recommendation delivered with the RECOMMEND-ONLY label and no raw identifier, never reaching the LLM", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeContainmentRecommendConfig(paths, { enabled: true });
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, containmentPeerSpikeTicks(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const deliveries = [];
  const tick1 = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });
  const peerAlert = tick1.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(peerAlert, "expected peer.count_spike to fire on tick 1");
  const recommendation = tick1.alerts.alerts.find((a) => a.rule_id === "containment.recommend.block");
  assert.ok(recommendation, "expected a real containment.recommend.block record");
  assert.equal(recommendation.status, "active");
  assert.equal(recommendation.diagnostics.trigger_rule_id, PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(recommendation.diagnostics.verb, "block");
  assert.equal(recommendation.diagnostics.target_repr, "global");
  assert.equal(JSON.stringify(recommendation).includes("redacted"), false);

  const recDeliveries = deliveries.filter((entry) => entry.opts.ruleId === "containment.recommend.block");
  assert.equal(recDeliveries.length, 1, "expected exactly one deterministic delivery for the due recommendation");
  assert.match(recDeliveries[0].decision.body, /RECOMMEND-ONLY/);
  assert.ok(recDeliveries[0].decision.body.startsWith("RECOMMEND-ONLY"), "the label must survive any downstream truncation, so it must be first");
  assert.equal(recDeliveries[0].decision.body.includes("peer.ssh"), false, "no raw peer identity in the delivered body");

  // Never via the LLM: containment.* is hard-excluded regardless of enabled_namespaces, and
  // alert-intelligence.json defaults to disabled anyway, giving a doubly-enforced guarantee.
  assert.equal(tick1.alertIntelligence.status, "disabled");

  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((a) => a.id === recommendation.id && a.status === "active"));
});

test("Slice 7.2 wiring: the containment opt-in OFF ⇒ zero recommendations, even with a persisted trigger and learned.json ON, and no I/O beyond the two gate reads is attempted", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  // containment-recommend.json intentionally never written -> readContainmentRecommendConfig
  // defaults to { enabled: false } — the same fail-closed default the config module itself pins.
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, containmentPeerSpikeTicks(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  await runIsolatedDaemonTick(paths, hour(30));
  const tick2Ts = new Date(Date.parse(hour(30)) + 60 * 1000).toISOString();
  const tick2 = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: tick2Ts,
    now: tick2Ts,
  });

  assert.equal((await readContainmentRecommendConfig(paths)).enabled, false);
  assert.equal(tick2.alerts.alerts.some((a) => a.rule_id === "containment.recommend.block"), false);
  const persisted = await readAlertRecords(paths);
  assert.equal(persisted.some((a) => a.rule_id === "containment.recommend.block"), false);
});

test("Slice 7.2 wiring: learned.json OFF ⇒ zero recommendations even with the containment opt-in ON and a trigger present, and no I/O is attempted for it", async () => {
  const paths = await tempPaths();
  await writeContainmentRecommendConfig(paths, { enabled: true });
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false } -- computeContainmentRecommendationCandidates must short-circuit to []
  // before ever calling readAlertRecords, exactly like every sibling extraCandidates source.
  await appendFactPoints(paths, containmentPeerSpikeTicks(), { now: hour(30) });

  let readAlertsCalled = false;
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: hour(30),
    now: hour(30),
    readAlertRecords: async (...args) => { readAlertsCalled = true; return readAlertRecords(...args); },
  });

  assert.equal(result.alerts.alerts.some((a) => a.rule_id === "containment.recommend.block"), false);
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID), false, "learned.json OFF also gates the underlying peer-baseline detector itself");
  assert.equal(readAlertsCalled, false, "readAlertRecords (containment-recommend's own hook, passed through daemon options) must never be called while learned.json is OFF");
});

test("Slice 7.2 wiring: no trigger present ⇒ zero recommendations (no storm on the first tick), even with both gates ON", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeContainmentRecommendConfig(paths, { enabled: true });

  const result = await runIsolatedDaemonTick(paths, hour(0));
  assert.equal(result.alerts.alerts.some((a) => String(a.rule_id).startsWith("containment.recommend.")), false);
});

test("Slice 7.2 wiring, THE LOAD-BEARING FAIL-CLOSED TRANSITION (Definition of Done): toggling the containment opt-in OFF recovers a same-tick recommendation on the next tick, and it stays recovered/not-due while the trigger remains active", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeContainmentRecommendConfig(paths, { enabled: true });
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, containmentPeerSpikeTicks(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const tick1 = await runIsolatedDaemonTick(paths, hour(30));
  const active = tick1.alerts.alerts.find((a) => a.rule_id === "containment.recommend.block");
  assert.ok(active, "expected the recommendation to be active on tick 1");
  assert.equal(active.status, "active");
  assert.ok(tick1.alerts.notification_due_ids.includes(active.id));

  // Toggle the opt-in OFF while the underlying trigger is STILL present — the peer fact-history is
  // unchanged, so peer.count_spike keeps re-deriving as active every tick regardless of this
  // module's own opt-in. This is the ONLY thing that changes between tick 2 and tick 3.
  await writeContainmentRecommendConfig(paths, { enabled: false });

  const tick2Ts = new Date(Date.parse(hour(30)) + 60 * 1000).toISOString();
  const tick2 = await runIsolatedDaemonTick(paths, tick2Ts);
  const peerStillActive = tick2.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(peerStillActive && peerStillActive.status === "active", "the underlying trigger must genuinely still be active on tick 2 — only the opt-in changed");

  const recovered = tick2.alerts.alerts.find((a) => a.rule_id === "containment.recommend.block");
  assert.ok(recovered, "the previously-active recommendation record must still be PRESENT (recovered), not silently deleted");
  assert.equal(recovered.status, "recovered");
  assert.equal(tick2.alerts.notification_due_ids.includes(recovered.id), false);

  // Stays recovered/not-due on a further tick while the opt-in stays OFF and the trigger never
  // clears -- not merely a one-tick blip.
  const tick3Ts = new Date(Date.parse(tick2Ts) + 60 * 1000).toISOString();
  const tick3 = await runIsolatedDaemonTick(paths, tick3Ts);
  const stillRecovered = tick3.alerts.alerts.find((a) => a.id === recovered.id);
  assert.ok(stillRecovered);
  assert.equal(stillRecovered.status, "recovered");
  assert.equal(tick3.alerts.notification_due_ids.includes(recovered.id), false);
  assert.ok(tick3.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID)?.status === "active", "the trigger itself is still active on tick 3 -- confirms this is the opt-in's own doing, not the trigger clearing");
});

test("Slice 7.2 wiring: byte-identical real alerts when BOTH the learned kill switch and the containment opt-in are off, even with peer fact-history present that would otherwise trigger a recommendation, and no I/O is attempted for it", async () => {
  const baselinePaths = await tempPaths();
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const withHistoryPaths = await tempPaths();
  await appendFactPoints(withHistoryPaths, containmentPeerSpikeTicks(), { now: hour(30) });
  // Neither learned.json nor containment-recommend.json is ever written here -> both default OFF,
  // exactly like the baseline above.
  const withHistory = await runIsolatedDaemonTick(withHistoryPaths, hour(30));

  assert.deepEqual(withHistory.alerts.alerts, baseline.alerts.alerts);
  assert.deepEqual(withHistory.alerts.candidates, baseline.alerts.candidates);
  assert.deepEqual(withHistory.alerts.notification_due_ids, baseline.alerts.notification_due_ids);
});

// ---------------------------------------------------------------------------------------------
// Cross-cutting SURVIVABILITY fix (docs/reviews/2026-09-04-daybreak-security-sweep.md): before
// this fix, `mainExtraCandidates` (~daemon.js L594-630) was one array literal spreading all
// twelve detector calls -- if ANY one threw, the whole array build threw and aborted the entire
// daemon tick, blinding every OTHER detector for that tick. The separate
// computeContainmentRecommendationCandidates call and the emitSessionAlertSignals call site had
// the identical exposure. Each call site is now wrapped in safeCandidates(), which degrades a
// throw to a safe fallback (logged, never silent) for THAT producer THIS tick only. Each detector
// (and the containment/delivery call sites) now also has a DI seam (options.<fn> ?? <fn>,
// mirroring the file's existing pattern for e.g. adjudicateAlertNotifications) so a test can
// inject a throw into exactly one producer without disturbing the rest.
// ---------------------------------------------------------------------------------------------

test("Cross-cutting SURVIVABILITY fix: one throwing detector degrades to zero candidates for itself only, and does not blind the OTHER detectors' candidates for the tick -- with a warning logged naming it", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let withThrow;
  try {
    withThrow = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: S_LIVE_1_TICK_TS,
      now: S_LIVE_1_TICK_TS,
      computeCorrelationCandidates: async () => {
        throw new Error("simulated computeCorrelationCandidates failure");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // The tick completed -- one detector throwing did not crash the daemon.
  assert.equal(withThrow.status.state, "ok");

  // A completely different detector's real alert (the violated active constraint) still made it
  // through to persistence -- the throw did not blind the other eleven detectors.
  const constraintAlert = withThrow.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "expected the active-constraint alert to still fire even though a sibling detector threw");
  assert.equal(constraintAlert.status, "active");
  const persisted = await readAlertRecords(paths);
  assert.ok(persisted.some((alert) => alert.id === constraintAlert.id && alert.status === "active"));

  // A warning was logged naming the failing detector.
  assert.ok(
    warnings.some((w) => w.includes("correlation") && w.includes("simulated computeCorrelationCandidates failure")),
    `expected a warning naming the failing detector, got: ${JSON.stringify(warnings)}`,
  );

  // Differential check: the throwing detector contributed EXACTLY zero candidates -- byte-
  // identical to the same tick with that detector overridden to succeed with none.
  const emptyPaths = await tempPaths();
  await writeLearnedConfig(emptyPaths, { enabled: true });
  await writeConstraints(emptyPaths, [activeConstraintFixture()]);
  await appendFactPoints(emptyPaths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });
  const withEmptySuccess = await runDaemonIteration(emptyPaths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    computeCorrelationCandidates: async () => [],
  });
  assert.deepEqual(withThrow.alerts.alerts, withEmptySuccess.alerts.alerts);
  assert.deepEqual(withThrow.alerts.candidates, withEmptySuccess.alerts.candidates);
});

test("Cross-cutting SURVIVABILITY fix: an injected computeContainmentRecommendationCandidates throw does not crash the tick and does not clobber the main evaluation's real alerts -- it degrades to no containment recommendation, with a warning logged", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeContainmentRecommendConfig(paths, { enabled: true });
  await writePeerBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  await appendFactPoints(paths, containmentPeerSpikeTicks(), { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: hour(30),
      now: hour(30),
      computeContainmentRecommendationCandidates: async () => {
        throw new Error("simulated computeContainmentRecommendationCandidates failure");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(result.status.state, "ok");
  const peerAlert = result.alerts.alerts.find((a) => a.rule_id === PEER_COUNT_SPIKE_RULE_ID);
  assert.ok(peerAlert && peerAlert.status === "active", "the main evaluation's real peer.count_spike alert must survive a containment-phase throw");
  assert.equal(result.alerts.alerts.some((a) => a.rule_id === "containment.recommend.block"), false, "the containment candidate itself degrades to none when its producer throws");
  assert.ok(
    warnings.some((w) => w.includes("containment-recommendation") && w.includes("simulated computeContainmentRecommendationCandidates failure")),
    `expected a warning naming the failing containment producer, got: ${JSON.stringify(warnings)}`,
  );
});

test("Cross-cutting SURVIVABILITY fix: an injected emitSessionAlertSignals throw does not crash the tick and does not clobber the already-persisted alerts -- sessionAlertDelivery degrades to undefined, with a warning logged", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeSessionBaselineStore(paths, { cold_start_pending: false, last_folded_ts: hour(-1) });
  const ticks = [];
  for (let i = 0; i < 30; i += 1) ticks.push(...completeSessionTick(hour(i), 20));
  ticks.push(...completeSessionTick(hour(30), 0));
  await appendFactPoints(paths, ticks, { now: hour(30) });
  await appendFactPoints(paths, [], { now: hour(30) });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: hour(30),
      now: hour(30),
      emitSessionAlertSignals: async () => {
        throw new Error("simulated emitSessionAlertSignals failure");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(result.status.state, "ok");
  const sessionAlert = result.alerts.alerts.find((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID);
  assert.ok(sessionAlert, "the underlying session.count_drop alert (persisted before delivery runs) must survive a delivery-phase throw");
  assert.equal(result.sessionAlertDelivery, undefined, "delivery degrades to undefined, matching the existing 'no delivery this tick' shape, rather than crashing the tick");
  assert.ok(
    warnings.some((w) => w.includes("session-alert-delivery") && w.includes("simulated emitSessionAlertSignals failure")),
    `expected a warning naming the failing delivery producer, got: ${JSON.stringify(warnings)}`,
  );
});

// ---------------------------------------------------------------------------------------------
// Finding F4 fix: before this fix, the metric-persist call (appendMetricPoints), the structural
// fact-persist call (appendFactPoints), writeStructuralCheckpoint, and writeDaemonStatus were all
// unguarded I/O sitting BEFORE evaluateAndPersistAlerts in the tick -- a throw from any one of
// them (ENOSPC/EACCES/EROFS on a disk-pressure host) aborted the ENTIRE tick, so
// evaluateAndPersistAlerts (and therefore the daemon's own daemon.status.*/daemon.samples.* dead-
// daemon detection) never ran. These tests extend the same safeCandidates()-isolation discipline
// already proven above one layer earlier (persistence-before-evaluation), and separately prove the
// writeDaemonStatus fabrication trap is avoided: a storage-write failure must never make the
// in-memory status silently look healthy (no hardcoded state, no synthesized retention).
// ---------------------------------------------------------------------------------------------

test("F4: a throwing appendMetricPoints degrades the metric-persist step to an honest zero-write result instead of aborting the tick -- evaluateAndPersistAlerts still runs, with a warning logged", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: S_LIVE_1_TICK_TS,
      now: S_LIVE_1_TICK_TS,
      appendMetricPoints: async () => {
        throw new Error("simulated appendMetricPoints failure (ENOSPC)");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // The tick completed -- a metric-persist throw did not crash the daemon.
  // Finding F4-B1 re-gate: a genuine append failure is now surfaced as state:"error" (it used to
  // be hardcoded "ok", which is the exact fabrication F4-B1 closes -- see the fresh assertions
  // below).
  assert.equal(result.status.state, "error");
  assert.equal(result.status.storage_write_error, "simulated appendMetricPoints failure (ENOSPC)");

  // Honest degraded shape: zero written this tick, retention state unknown -- never a guessed
  // plausible-looking retention object.
  assert.deepEqual(result.write, { written_count: 0, retention: undefined });

  // evaluateAndPersistAlerts was still reached this tick -- a completely unrelated detector's real
  // alert (the violated active constraint) still made it through to persistence.
  const constraintAlert = result.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "expected the active-constraint alert to still fire even though metric-persist threw");
  assert.equal(constraintAlert.status, "active");

  // THE ACTUAL F4 THESIS, proven directly: this tick's own metric points genuinely never reached
  // metrics.jsonl (the write threw), so historySummary.point_count is genuinely 0 for this window
  // -- alert-store.js's EXISTING daemon.samples.missing rule (alert-store.js:112-119) fires from
  // that real, honest evidence. Before this fix, evaluateAndPersistAlerts was never reached at all
  // on this failure, so this "daemon is dark" signal could never surface. No fabricated metric
  // value is claimed anywhere -- only the honest "samples missing" family fires.
  const samplesMissing = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.samples.missing");
  assert.ok(samplesMissing, "expected the existing daemon.samples.missing watchdog rule to fire from the genuine zero-point-count evidence");
  assert.equal(samplesMissing.status, "active");
  assert.equal(samplesMissing.diagnostics.point_count, 0);

  // F4-B1: the now-genuinely-"error" status.state itself reaches alert-store.js's existing
  // daemon.status.not_ok rule -- the watchdog that a hardcoded state:"ok" made permanently unable
  // to fire from a persistence failure.
  const notOk = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.status.not_ok");
  assert.ok(notOk, "expected daemon.status.not_ok to fire now that state genuinely reflects the persist failure");
  assert.equal(notOk.status, "active");

  assert.ok(
    warnings.some((w) => w.includes("metric-persist") && w.includes("simulated appendMetricPoints failure (ENOSPC)")),
    `expected a warning naming the failing metric-persist step, got: ${JSON.stringify(warnings)}`,
  );
});

test("F4: a throwing appendFactPoints during a structural-due tick degrades the structural fact-persist step instead of aborting the tick, with a warning logged", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: structuralProfile(),
      collectors: fastCollectorFakes(),
      structuralCollectors: structuralCollectorFakesWithFacts(),
      ts: "2026-05-24T00:00:00.000Z",
      now: 0,
      readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
      loadLearnedConfig: async () => ({ enabled: true }),
      appendFactPoints: async () => {
        throw new Error("simulated appendFactPoints failure (EROFS)");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // The tick completed -- a structural fact-persist throw did not crash the daemon.
  // Finding F4-B1 re-gate: a genuine append failure now surfaces as state:"error" (previously
  // hardcoded "ok" regardless).
  assert.equal(result.status.state, "error");
  assert.equal(result.status.storage_write_error, "simulated appendFactPoints failure (EROFS)");
  // Honest degraded shape, matching appendFactPoints' real success shape (fact-store.js).
  assert.deepEqual(result.structuralFacts, { written_count: 0, retention: undefined });
  // The structural collection itself (evidence collection, independent of the fact-persist call)
  // still completed and is reflected in status -- only the persist step degraded. The collector
  // statuses themselves are still genuinely "ok" -- state:"error" here comes from the persist
  // failure, not from any collector.
  assert.equal(result.status.structural_collector_statuses.length, 3);
  assert(result.status.structural_collector_statuses.every((entry) => entry.status === "ok"));

  assert.ok(
    warnings.some((w) => w.includes("simulated appendFactPoints failure (EROFS)")),
    `expected a warning naming the failing structural fact-persist step, got: ${JSON.stringify(warnings)}`,
  );
});

test("F4: a throwing writeStructuralCheckpoint degrades instead of aborting the tick -- the checkpoint simply stays unadvanced (already-tolerated retry-next-tick behaviour), with a warning logged", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: structuralProfile(),
      collectors: fastCollectorFakes(),
      structuralCollectors: structuralCollectorFakes(),
      ts: "2026-05-24T00:00:00.000Z",
      now: 0,
      readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
      loadLearnedConfig: async () => ({ enabled: true }),
      writeStructuralCheckpoint: async () => {
        throw new Error("simulated writeStructuralCheckpoint failure (EACCES)");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // The tick completed -- a checkpoint-write throw did not crash the daemon, and structural
  // collection itself still ran and is reflected in status.
  assert.equal(result.status.state, "ok");
  assert.equal(result.status.structural_collector_statuses.length, 3);

  // The on-disk checkpoint genuinely was not advanced (readStructuralCheckpoint still reports no
  // prior run) -- this is the same, already-tolerated "retry next tick" behaviour the file's own
  // comment documents for the timeout case, not a new risk.
  const checkpoint = await readStructuralCheckpoint(paths);
  assert.equal(checkpoint.last_structural_run_ms, undefined);

  assert.ok(
    warnings.some((w) => w.includes("simulated writeStructuralCheckpoint failure (EACCES)")),
    `expected a warning naming the failing checkpoint-persist step, got: ${JSON.stringify(warnings)}`,
  );
});

test("F4 fabrication trap: a throwing writeDaemonStatus does NOT crash the tick and does NOT fabricate a healthy status -- the in-memory status handed downstream carries the genuine collector-derived state plus an honest storage_write_error field, byte-identical to a successful write otherwise", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  // Baseline: the same tick, same inputs, with writeDaemonStatus succeeding for real.
  const baselinePaths = await tempPaths();
  await writeLearnedConfig(baselinePaths, { enabled: true });
  await writeConstraints(baselinePaths, [activeConstraintFixture()]);
  await appendFactPoints(baselinePaths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });
  const baseline = await runIsolatedDaemonTick(baselinePaths);

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: S_LIVE_1_TICK_TS,
      now: S_LIVE_1_TICK_TS,
      writeDaemonStatus: async () => {
        throw new Error("simulated writeDaemonStatus failure (ENOSPC)");
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // The tick completed -- a status-write throw did not crash the daemon.
  assert.ok(result.status, "an in-memory status must still exist for this tick even though the disk write failed");

  // THE FABRICATION TRAP, F4-B1 re-gate: writeDaemonStatus failing IS itself a genuine
  // persistence failure this tick, so `state` must become "error" -- never silently disconnected
  // from what actually happened (the old hardcoded "ok" made a write failure invisible to
  // daemon.status.not_ok). Every OTHER field stays the genuine, already-computed collector-derived
  // value (byte-identical to the successful-write baseline) -- nothing else is a hardcoded
  // fallback.
  assert.equal(result.status.state, "error");
  assert.equal(baseline.status.state, "ok", "the baseline tick had no genuine failure, so its state is the real 'ok'");
  assert.equal(result.status.mode, baseline.status.mode);
  assert.deepEqual(result.status.collector_statuses, baseline.status.collector_statuses);
  assert.equal(result.status.points_written, baseline.status.points_written);
  assert.deepEqual(result.status.retention, baseline.status.retention);

  // The only OTHER difference from a successful write is the new, honestly-named field.
  assert.equal(result.status.storage_write_error, "simulated writeDaemonStatus failure (ENOSPC)");
  assert.equal(baseline.status.storage_write_error, undefined);

  // Everything downstream of the status write still ran unconditionally: evaluateAndPersistAlerts
  // was reached and received this exact in-memory status.
  assert.ok(result.alerts, "evaluateAndPersistAlerts must still run even though writeDaemonStatus threw");
  const constraintAlert = result.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "a real alert must still fire this tick even though the status write failed");

  assert.ok(
    warnings.some((w) => w.includes("writeDaemonStatus") && w.includes("simulated writeDaemonStatus failure (ENOSPC)")),
    `expected a warning naming the writeDaemonStatus failure, got: ${JSON.stringify(warnings)}`,
  );

  // The on-disk status file was never written for this tick (the write genuinely failed) -- a
  // reader hitting the stale prior file, not a fabricated fresh-looking one, is the honest outcome.
  const onDisk = await readDaemonStatus(paths);
  assert.equal(onDisk, undefined, "no prior status existed and the failed write must not have produced one");
});

// ---------------------------------------------------------------------------------------------
// Finding F4-B1 (daybreak-blue CONFIRMED BLOCKER): status.state used to be HARDCODED to "ok",
// unconditionally -- so neither a genuine collector error NOR a genuine persistence failure could
// ever be reflected in it, and alert-store.js's existing daemon.status.not_ok rule (which fires
// whenever state is not "ok"/"stopped") could never fire from either. These tests prove state is
// now genuinely derived: from real collector-reported "error" status (never from the benign
// "unable" a platform-inapplicable collector reports), and from a genuine metric/structural-fact
// persistence failure (an append error, or a non-fatal retention_error -- Finding F4-B2, see
// history-store.js/fact-store.js).
// ---------------------------------------------------------------------------------------------

test("F4-B1: a collector reporting status \"error\" makes status.state \"error\" (never the old hardcoded \"ok\"), and daemon.status.not_ok fires from it", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: {
      system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0] }, "error"),
      processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
      disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
    },
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
  });

  assert.equal(result.status.state, "error");
  const notOk = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.status.not_ok");
  assert.ok(notOk, "expected daemon.status.not_ok to fire from a genuine collector error");
  assert.equal(notOk.status, "active");
});

test("F4-B1: a collector reporting status \"unable\" (e.g. platform-inapplicable) does NOT flip status.state to \"error\" -- only a genuine \"error\" does, avoiding daemon.status.not_ok over-firing every tick", async () => {
  const paths = await tempPaths();
  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: {
      system: async () => envelope("system-overview", "collect_system", {}, "unable"),
      processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
      disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
    },
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
  });

  assert.equal(result.status.state, "ok");
  const notOk = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.status.not_ok");
  assert.equal(notOk, undefined, "an 'unable' (platform-inapplicable) collector must not be treated as a failure");
});

test("F4-B2: a non-fatal retention_error from the metric-persist writer surfaces into status.state \"error\" and status.retention_error, while the real written_count is preserved (never a fabricated zero)", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  const result = await runDaemonIteration(paths, {
    profile: slice6Profile(),
    collectors: fastCollectorFakes(),
    ts: S_LIVE_1_TICK_TS,
    now: S_LIVE_1_TICK_TS,
    // Mirrors appendMetricPoints' real F4-B2 success-with-retention_error shape (history-store.js):
    // the append genuinely succeeded (written_count: 7), only retention failed.
    appendMetricPoints: async () => ({ written_count: 7, retention: undefined, retention_error: "simulated enforceHistoryRetention failure (EISDIR)" }),
  });

  assert.equal(result.status.state, "error");
  assert.equal(result.status.points_written, 7, "the real written_count must be reported, never fabricated to 0 just because retention failed");
  assert.equal(result.write.written_count, 7);
  assert.equal(result.status.retention_error, "simulated enforceHistoryRetention failure (EISDIR)");
  assert.equal(result.status.storage_write_error, undefined, "a retention-only failure is not an append failure -- must not be misreported as one");

  const constraintAlert = result.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "a completely unrelated real alert must still fire this tick");
  const notOk = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.status.not_ok");
  assert.ok(notOk, "expected daemon.status.not_ok to fire from the genuine retention failure");
});

test("F4-B2: a non-fatal retention_error from the structural fact-persist writer surfaces into status.state \"error\" and status.retention_error", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });

  const result = await runDaemonIteration(paths, {
    profile: structuralProfile(),
    collectors: fastCollectorFakes(),
    structuralCollectors: structuralCollectorFakesWithFacts(),
    ts: "2026-05-24T00:00:00.000Z",
    now: 0,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: undefined }),
    loadLearnedConfig: async () => ({ enabled: true }),
    // Mirrors appendFactPoints' real F4-B2 success-with-retention_error shape (fact-store.js): the
    // append genuinely succeeded, only retention failed.
    appendFactPoints: async () => ({ written_count: 3, retention: undefined, retention_error: "simulated enforceFactRetention failure (EISDIR)" }),
  });

  assert.equal(result.status.state, "error");
  assert.equal(result.structuralFacts.written_count, 3);
  assert.equal(result.status.retention_error, "simulated enforceFactRetention failure (EISDIR)");
  assert.equal(result.status.storage_write_error, undefined, "a retention-only failure is not an append failure -- must not be misreported as one");
  // The structural collectors themselves genuinely succeeded -- state:"error" here comes from the
  // persist step's retention_error, not from any collector.
  assert(result.status.structural_collector_statuses.every((entry) => entry.status === "ok"));
});

// ---------------------------------------------------------------------------------------------
// daybreak-blue re-gate BLOCKER: metricPersistError/structuralFactPersistError captured
// `error.message` directly -- an EMPTY-message Error (e.g. `new Error()`, which some fs/EISDIR-
// style failures surface as) coalesced storageWriteError back to `undefined` via combineErrors'
// `filter(Boolean)`, which drops falsy entries including "". That silently resurrected the exact
// F4-B1 fabrication (state:"ok", daemon.status.not_ok never firing) the message-bearing tests
// above already close, but only for the empty-message edge. The fix coalesces an empty message to
// a non-empty fallback string at the point of capture, so combineErrors' filter(Boolean) can never
// drop it. Pre-fix, this test's `assert.equal(result.status.state, "error")` would have read "ok".
// ---------------------------------------------------------------------------------------------

test("F4-B1 empty-message edge: a throwing appendMetricPoints with NO message still surfaces state:\"error\", a non-empty storage_write_error, and daemon.status.not_ok firing", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, [activeConstraintFixture()]);
  await appendFactPoints(paths, [
    { fact_name: "service.presence", entity_key: "nginx.service", attributes: { running: "false" } },
  ], { now: S_LIVE_1_TICK_TS });

  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map(String).join(" ")); };
  let result;
  try {
    result = await runDaemonIteration(paths, {
      profile: slice6Profile(),
      collectors: fastCollectorFakes(),
      ts: S_LIVE_1_TICK_TS,
      now: S_LIVE_1_TICK_TS,
      appendMetricPoints: async () => {
        throw new Error();
      },
    });
  } finally {
    console.warn = originalWarn;
  }

  // THE THESIS: an empty-message throw must not be silently dropped back to a healthy-looking
  // status. state must genuinely reflect the persist failure, exactly as it does for a
  // message-bearing throw.
  assert.equal(result.status.state, "error");
  assert.ok(
    typeof result.status.storage_write_error === "string" && result.status.storage_write_error.length > 0,
    `expected a non-empty storage_write_error, got: ${JSON.stringify(result.status.storage_write_error)}`,
  );

  assert.deepEqual(result.write, { written_count: 0, retention: undefined });

  // A completely unrelated real alert still fires this tick -- evaluateAndPersistAlerts still ran.
  const constraintAlert = result.alerts.alerts.find((alert) => alert.rule_id === "constraint.violation.service-presence");
  assert.ok(constraintAlert, "expected the active-constraint alert to still fire even though metric-persist threw with an empty message");

  // The watchdog rule that a hardcoded/dropped-to-undefined state made permanently unable to fire.
  const notOk = result.alerts.alerts.find((alert) => alert.rule_id === "daemon.status.not_ok");
  assert.ok(notOk, "expected daemon.status.not_ok to fire from the genuine empty-message persist failure");
  assert.equal(notOk.status, "active");

  assert.ok(
    warnings.some((w) => w.includes("metric-persist")),
    `expected a warning naming the failing metric-persist step even with an empty error message, got: ${JSON.stringify(warnings)}`,
  );
});
