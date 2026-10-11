// Context plan C2 daemon wiring (docs/plans/2026-10-06-context-aware-learned-baselines.md §4, §8):
// the C2 facts, tick_summary and the statistics skeleton ride the completed structural tick, AFTER
// the incumbent census, and never change an incumbent fact, alert or the daemon's health state.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { runDaemonIteration } from "../src/daemon.js";
import { readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import { DERIVED_FAMILIES, FACT_FAMILY_IDS } from "../src/fact-families.js";
import { finalizeContextC2, prepareContextC2 } from "../src/context-c2-daemon.js";
import { resolveStatsStatePath, resolveSummaryChainPath, verifyTickSummaryChain } from "../src/context-summary.js";

const T0 = Date.parse("2026-10-11T08:00:00.000Z");
const HOUR = 3_600_000;
const BOOT = "11111111-2222-3333-4444-555555555555";
const INCUMBENT_FAMILIES = ["service", "process_lineage", "scheduled_job", "session", "peer", "canary", "network", "provenance"];

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-c2-daemon-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function envelope(id, tool, result, status = "ok") {
  return { id, status, layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: "2026-10-11T08:00:00.000Z" } };
}

function fastCollectorFakes() {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

function harness(paths, overrides = {}) {
  const state = { checkpoint: undefined, sessions: { work: 1_000_100 }, tz: "Europe/Paris", offset: 120, nowMs: T0 };
  const probe = () => ({
    platform: "darwin",
    status: "ok",
    boot: { boot_id: BOOT, boot_id_source: "kern.bootsessionuuid", boot_time_s: 1_000_000, os_build: "25C56", os_release: "25.2.0" },
    clocks: { wall_ms: state.nowMs, uv_hrtime_ns: "1", uv_version: "1.52.1", os_uptime_ms: state.nowMs - 1_000_000_000, kern_waketime_s: 0, kern_sleeptime_s: 0, kern_monotonicclock_usecs: "1 2", machdep_wake_abstime: "0", machdep_wake_conttime: "0", tz_id: state.tz, utc_offset_min: state.offset },
  });
  const run = async (nowMs, extra = {}) => {
    state.nowMs = nowMs;
    return runDaemonIteration(paths, {
      profile: {
        interval_ms: 60000,
        collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
        structural: {
          interval_ms: HOUR,
          collectors: { sessions: { enabled: true }, "vpn-peer-status": { enabled: true }, "host-lifecycle": { enabled: true }, "tmux-clients": { enabled: true } },
        },
      },
      collectors: fastCollectorFakes(),
      structuralCollectors: {
        sessions: async () => envelope("sessions", "collect_sessions", {
          multiplexers: [{ multiplexer: "tmux", status: "ok", binary_provenance: { requested_binary: "tmux", trust_verdict: "trusted", resolved_path: "/usr/bin/tmux", same_uid_writable_components: [] } }],
          sessions: Object.entries(state.sessions).map(([name, created]) => ({ multiplexer: "tmux", session_name: name, window_count: 1, attached: true, created_at_epoch_seconds: created })),
          total_count: Object.keys(state.sessions).length,
          truncated: false,
        }),
        "vpn-peer-status": async () => envelope("vpn-peer-status", "collect_vpn_peer_status", {
          sources: Object.fromEntries(["ssh_who", "ssh_last", "wireguard", "vpn_services", "established_inbound"].map((k) => [k, { status: "ok" }])),
          peers: [{ source_type: "ssh", presence_state: "observed_active", remote_user: "u", remote_host: "h1", origin: "who" }],
          census_status: "ok",
          truncated: false,
          total_count: 1,
        }),
        "host-lifecycle": async () => ({ ...envelope("host-lifecycle", "collect_host_lifecycle", probe()), observation: { start_ms: nowMs + 10, end_ms: nowMs + 20 } }),
        "tmux-clients": async () => ({ ...envelope("tmux-clients", "collect_tmux_clients", { status: "ok", clients: [{ tty: "ttys001", session_name: "work" }], total_count: 1 }), observation: { start_ms: nowMs + 20, end_ms: nowMs + 30 } }),
      },
      hostLifecycleProbe: async () => probe(),
      daemonInstance: { nonce: "daemon-a", start_ms: T0 - HOUR },
      evaluateAlerts: false,
      ts: new Date(nowMs).toISOString(),
      now: nowMs,
      readStructuralCheckpoint: async () => ({ last_structural_run_ms: state.checkpoint }),
      writeStructuralCheckpoint: async (_paths, checkpoint) => {
        state.checkpoint = checkpoint.last_structural_run_ms;
        return checkpoint;
      },
      loadLearnedConfig: async () => ({ enabled: false }),
      loadWatchConfig: async () => ({ enabled: true }),
      ...overrides,
      ...extra,
    });
  };
  return { state, run };
}

async function incumbentFiles(paths) {
  const out = {};
  for (const family of INCUMBENT_FAMILIES) {
    try {
      out[family] = await fs.readFile(resolveFactStorePaths(paths, family).factsFile, "utf8");
    } catch {
      out[family] = null;
    }
  }
  return out;
}

test("C2 wiring: each completed structural tick appends one chained, certified tick_summary record, the C2 context facts and the statistics; their state files are stamped", async () => {
  const paths = await tempPaths();
  const { state, run } = harness(paths);
  await run(T0);
  state.sessions = { work: 1_000_100, other: 1_000_200 };
  await run(T0 + HOUR);
  state.tz = "America/New_York";
  state.offset = -240;
  const status = await run(T0 + 2 * HOUR);
  const now = new Date(T0 + 2 * HOUR).toISOString();
  const summaries = (await readFactPoints(paths, { family: "tick_summary", now })).points;
  assert.equal(summaries.length, 3);
  assert.deepEqual(summaries.map((p) => p.attributes.chain), ["started", "continued", "continued"]);
  assert.deepEqual(summaries.map((p) => p.attributes.cert), ["certified", "certified", "certified"]);
  assert.deepEqual(verifyTickSummaryChain(summaries).losses, []);
  assert.deepEqual(summaries.map((p) => [p.attributes.sa, p.attributes.sd]), [["unknown", "unknown"], ["1", "0"], ["0", "0"]]);
  assert.equal(summaries[2].attributes.ev, "zo");
  assert.equal(status.status?.context_c2?.summary ?? status.context_c2?.summary, "committed");
  const network = (await readFactPoints(paths, { family: "network_context", now })).points;
  assert.deepEqual(network.filter((p) => p.fact_name === "context.transition").map((p) => p.attributes.dimension).sort(), ["timezone", "utc_offset"]);
  const sessionContext = (await readFactPoints(paths, { family: "session_context", now })).points;
  assert.ok(sessionContext.some((p) => p.fact_name === "session.attachment"));
  assert.ok(sessionContext.some((p) => p.fact_name === "session.created_vs_boot" && p.attributes.basis === "no_boundary_observed"));
  const host = (await readFactPoints(paths, { family: "host_lifecycle", now })).points;
  assert.equal(host.filter((p) => p.fact_name === "host.daemon_gap").length, 3);
  const collector = (await readFactPoints(paths, { family: "collector_state", now })).points;
  assert.ok(collector.some((p) => p.attributes.binary === "tmux" && p.attributes.state === "resolved"));
  const stats = (await readFactPoints(paths, { family: "context_stats", now })).points;
  assert.equal(stats.length, 0, "no episode (no boot/wake/network change) and no closed day yet");
  await fs.access(resolveSummaryChainPath(paths));
  await fs.access(resolveStatsStatePath(paths));
});

test("C2 isolation: the incumbent families are byte-identical with the C2 phase on, off, or failing; a C2 failure never changes the daemon's health state", async () => {
  const runAll = async (overrides) => {
    const paths = await tempPaths();
    const { state, run } = harness(paths, overrides);
    const statuses = [];
    statuses.push(await run(T0));
    state.sessions = { other: 1_000_200 };
    statuses.push(await run(T0 + HOUR));
    return { paths, statuses, files: await incumbentFiles(paths) };
  };
  const on = await runAll({});
  const off = await runAll({ contextC2: false });
  const failing = await runAll({ prepareContextC2: async () => { throw new Error("c2 boom"); } });
  const failingFinal = await runAll({ finalizeContextC2: async () => { throw new Error("c2 final boom"); } });
  assert.ok(on.files.session && on.files.peer, "the incumbent families were written");
  assert.deepEqual(on.files, off.files);
  assert.deepEqual(failing.files, off.files);
  assert.deepEqual(failingFinal.files, off.files);
  const statusOf = (result) => result.status ?? result;
  for (const [index, result] of failing.statuses.entries()) {
    assert.equal(statusOf(result).context_c2?.error, "c2 boom");
    assert.equal(statusOf(result).state, statusOf(off.statuses[index]).state, "a C2 failure is not daemon health");
  }
  assert.equal(statusOf(failingFinal.statuses[0]).context_c2?.error, "c2 final boom");
  const offSummaries = await readFactPoints(off.paths, { family: "tick_summary", now: new Date(T0 + HOUR).toISOString() });
  assert.equal(offSummaries.points.length, 0);
  const onSummaries = await readFactPoints(on.paths, { family: "tick_summary", now: new Date(T0 + HOUR).toISOString() });
  assert.equal(onSummaries.points.length, 2, "the C2 phase did run in the comparison");
  assert.equal(onSummaries.points[1].attributes.sd, "1");
  // The C2 families are derived or context families: never an incumbent family.
  for (const family of DERIVED_FAMILIES) assert.ok(!INCUMBENT_FAMILIES.includes(family) && FACT_FAMILY_IDS.includes(family));
});

test("C2 finalize: a summary whose pass did not commit leaves the chain state unadvanced, so the next tick restarts the chain (unknown transitions), never continues it", async () => {
  const paths = await tempPaths();
  const ts = new Date(T0).toISOString();
  const prepared = await prepareContextC2({ descartesPaths: paths, evidence: [], basePoints: [], ts, daemonIntervalMs: 60000 });
  const result = await finalizeContextC2({
    descartesPaths: paths,
    prepared,
    factPoints: [],
    structuralFacts: { families: {} },
    ts,
    deps: { appendFactPoints: async () => ({ written_count: 1, retention_error: "disk full" }) },
  });
  assert.equal(result.summary, "appended_unstamped");
  assert.equal(result.error, "disk full");
  await assert.rejects(fs.access(resolveSummaryChainPath(paths)));
  const next = await prepareContextC2({ descartesPaths: paths, evidence: [], basePoints: [], ts: new Date(T0 + HOUR).toISOString(), daemonIntervalMs: 60000 });
  assert.equal(next.context.chainRead.status, "missing");
  assert.equal(next.context.transitions.events, undefined);
});
