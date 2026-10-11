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
import { readLoginSeen } from "../src/login-seen.js";
import { evaluateAlertRules, RETENTION_FAILURE_RULE_ID } from "../src/alert-store.js";

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
  assert.equal(summaries[2].attributes.ev, "--u-u-zo", "positional: no tailscale or net-config collector in this harness");
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
  // A C2 point the shared pass would reject (an unregistered name refuses the whole batch; a point
  // routed to an incumbent family) never joins it: the incumbents persist exactly as without C2.
  const rogue = (point) => ({ prepareContextC2: async () => ({ points: [point], context: {} }), finalizeContextC2: async () => ({}) });
  const unregistered = await runAll(rogue({ ts: new Date(T0).toISOString(), fact_name: "not.registered", entity_key: "x", attributes: {} }));
  const intoIncumbent = await runAll(rogue({ ts: new Date(T0).toISOString(), fact_name: "session.presence", entity_key: "session.tmux.ffffffffffffffff", attributes: {} }));
  const badSchema = await runAll(rogue({ ts: new Date(T0).toISOString(), fact_name: "host.daemon_gap", entity_key: "host.daemon_gap", attributes: { bogus: "1" } }));
  for (const result of [unregistered, intoIncumbent, badSchema]) {
    assert.deepEqual(result.files, off.files);
    assert.match((result.statuses[0].status ?? result.statuses[0]).context_c2?.error ?? "", /context C2 point|closed schema/);
  }
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

// C2 review M1: a reboot/shutdown row is marked seen only when its host.lifecycle_record reached the
// fact history (C2 admitted and host_lifecycle persisted): never a consumed row with no fact.
test("C2 host.lifecycle_record: a row is consumed only when its fact persisted; a failed or disabled C2 step offers it again", async () => {
  const lifecycleRow = { kind: "reboot", start_text: "Fri Sep 4 16:10", end_state: "none", duration_text: "none", os_release: "none", identity: ["lifecycle", "reboot", "Fri Sep 4 16:10", "none"].join("\u0000") };
  const withLogin = (paths, overrides = {}) => {
    const { state, run } = harness(paths, overrides);
    const login = async () => ({
      ...envelope("login-sessions", "collect_login_sessions", { platform: "darwin", status: "ok", sources: { who: "ok", last: "ok", console: "not_applicable", loginctl: "not_applicable" }, records: [], history: [], presence: { screen_locked: "unknown", idle_hint: "unknown", source: "none" }, truncated: false, lifecycle: { state: "ok", rows: [lifecycleRow] } }),
      observation: { start_ms: state.nowMs + 20, end_ms: state.nowMs + 30 },
    });
    const runWith = (nowMs, extra = {}) => run(nowMs, {
      profile: { interval_ms: 60000, collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } }, structural: { interval_ms: HOUR, collectors: { sessions: { enabled: true }, "host-lifecycle": { enabled: true }, "login-sessions": { enabled: true } } } },
      structuralCollectors: {
        sessions: async () => envelope("sessions", "collect_sessions", { multiplexers: [{ multiplexer: "tmux", status: "ok" }], sessions: [], total_count: 0, truncated: false }),
        "host-lifecycle": async () => ({ ...envelope("host-lifecycle", "collect_host_lifecycle", { platform: "darwin", status: "ok", boot: { boot_id: BOOT, boot_time_s: 1_000_000 }, clocks: { wall_ms: nowMs, os_uptime_ms: nowMs - 1_000_000_000 } }), observation: { start_ms: nowMs + 10, end_ms: nowMs + 20 } }),
        "login-sessions": login,
      },
      ...extra,
    });
    return runWith;
  };
  const records = async (paths) => (await readFactPoints(paths, { family: "host_lifecycle", now: new Date(T0 + 2 * HOUR).toISOString() })).points.filter((p) => p.fact_name === "host.lifecycle_record");
  const lifecycleSeen = async (paths) => Object.keys((await readLoginSeen(paths)).seen?.lifecycle ?? {}).length;
  // Control: recorded once, then deduped.
  {
    const paths = await tempPaths();
    const run = withLogin(paths);
    await run(T0);
    await run(T0 + HOUR);
    assert.equal((await records(paths)).length, 1);
    assert.equal(await lifecycleSeen(paths), 1);
  }
  for (const [label, firstTick] of [
    ["prepare failed", { prepareContextC2: async () => { throw new Error("transient c2 failure"); } }],
    ["C2 off", { contextC2: false }],
    ["host_lifecycle not persisted", { appendFactPoints: async (descartesPaths, points, options) => {
      const { appendFactPointsByFamily } = await import("../src/fact-store.js");
      const result = await appendFactPointsByFamily(descartesPaths, points.filter((p) => !p.fact_name.startsWith("host.")), options);
      return { ...result, families: { ...result.families, host_lifecycle: { append_error: "simulated" } } };
    } }],
  ]) {
    const paths = await tempPaths();
    const run = withLogin(paths);
    await run(T0, firstTick);
    assert.equal(await lifecycleSeen(paths), 0, `${label}: the row is not marked seen`);
    await run(T0 + HOUR);
    const written = await records(paths);
    assert.equal(written.length, 1, `${label}: the row reaches the fact history on the next tick`);
    assert.equal(await lifecycleSeen(paths), 1);
  }
});

// C2 review M2: a derived family's size or retention never enters the daemon's health state or the
// incumbent retention-failing alert (deviation 9); it is shown for sizing only, and its own pass's
// outcome is on context_c2.
test("C2 derived families: an oversize tick_summary store never turns the daemon state to error or raises the retention alert", async () => {
  const paths = await tempPaths();
  const { run } = harness(paths, { finalizeContextC2: async () => ({ summary: "simulated_failed_pass" }) });
  const statusOf = (result) => result.status ?? result;
  const before = statusOf(await run(T0));
  const file = resolveFactStorePaths(paths, "tick_summary").factsFile;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, "x".repeat(4 * 1024 * 1024));
  const after = statusOf(await run(T0 + HOUR));
  assert.equal(before.state, "ok");
  assert.equal(after.state, "ok", "a derived family is not daemon health");
  const entry = after.fact_store_budgets.families.tick_summary;
  assert.equal(entry.bytes, 4 * 1024 * 1024, "still shown for sizing");
  assert.equal(entry.derived_oversize, true, "the oversize is shown");
  assert.equal(entry.retention_failing, undefined);
  assert.equal(entry.retention_error, undefined);
  const retentionCandidate = (status) => evaluateAlertRules({ metrics: [] }, status, {}).some((c) => c.rule_id === RETENTION_FAILURE_RULE_ID && c.fingerprint === "tick_summary");
  assert.equal(retentionCandidate(after), false);
  // Control: the incumbent rule does fire on such an entry, so the absence above is the fix.
  const flagged = { ...after, fact_store_budgets: { families: { ...after.fact_store_budgets.families, tick_summary: { ...entry, retention_failing: true } } } };
  assert.equal(retentionCandidate(flagged), true);
  // The incumbent families' budget entries are the same as with C2 off.
  const offPaths = await tempPaths();
  const offRun = harness(offPaths, { contextC2: false }).run;
  await offRun(T0);
  const off = statusOf(await offRun(T0 + HOUR));
  for (const family of INCUMBENT_FAMILIES) {
    const strip = ({ bytes: _b, last_tick_bytes: _l, ...rest }) => rest;
    assert.deepEqual(strip(after.fact_store_budgets.families[family]), strip(off.fact_store_budgets.families[family]), family);
  }
});

// C2 review M7: wiping one derived family's whole directory is loss, not a first run, while the other
// derived family survives (§8.2: wiping the store is never cheaper than a volume attack).
test("C2 derived families: a wiped context_stats or tick_summary directory beside a surviving sibling is loss, never a first run", async () => {
  const statusOf = (result) => result.status ?? result;
  {
    const paths = await tempPaths();
    const { run } = harness(paths);
    await run(T0);
    await run(T0 + HOUR);
    await fs.rm(resolveFactStorePaths(paths, "context_stats").dir, { recursive: true, force: true });
    const c2 = statusOf(await run(T0 + 2 * HOUR)).context_c2;
    assert.equal(c2.stats.memory_lost, true, "context_stats wiped while tick_summary survives: memory lost");
    assert.equal(c2.stats.memory_lost_count, 1);
    assert.equal(c2.chain, "continued");
  }
  {
    const paths = await tempPaths();
    const { run } = harness(paths);
    await run(T0);
    const second = statusOf(await run(T0 + HOUR)).context_c2;
    await fs.rm(resolveFactStorePaths(paths, "tick_summary").dir, { recursive: true, force: true });
    const c2 = statusOf(await run(T0 + 2 * HOUR)).context_c2;
    assert.equal(c2.chain, "restarted", "tick_summary wiped while context_stats survives: a restart (loss), never started");
    assert.ok(c2.seq > second.seq, "seq keeps increasing from the statistics' last seq (no episode id reuse)");
    const summaries = (await readFactPoints(paths, { family: "tick_summary", now: new Date(T0 + 2 * HOUR).toISOString() })).points;
    assert.deepEqual(verifyTickSummaryChain(summaries).losses.map((l) => l.reason), ["restarted"]);
  }
  {
    // Control: a genuine first run (neither store) is a first run.
    const paths = await tempPaths();
    const c2 = statusOf(await harness(paths).run(T0)).context_c2;
    assert.equal(c2.chain, "started");
    assert.equal(c2.stats.memory_lost, false);
  }
});

// C2 review L2: an interval whose host.daemon_gap fact was not written (C2 failed or off) is carried
// into the next interval's accumulator, never silently dropped.
test("C2 host.daemon_gap: an interval the C2 step could not record folds into the next record, never lost", async () => {
  const gaps = async (overridesAt) => {
    const paths = await tempPaths();
    const { run } = harness(paths);
    for (const [index, nowMs] of [T0, T0 + HOUR, T0 + 2 * HOUR].entries()) await run(nowMs, overridesAt[index] ?? {});
    return (await readFactPoints(paths, { family: "host_lifecycle", now: new Date(T0 + 2 * HOUR).toISOString() })).points
      .filter((p) => p.fact_name === "host.daemon_gap").map((p) => p.attributes);
  };
  const control = await gaps({});
  const failed = await gaps({ 1: { prepareContextC2: async () => { throw new Error("transient c2 failure"); } } });
  assert.equal(control.length, 3);
  assert.equal(failed.length, 2, "tick 2 wrote no gap fact");
  const observations = (attrs) => Number(attrs.observations);
  assert.equal(observations(failed[1]), observations(control[1]) + observations(control[2]), "the unrecorded interval's observations are carried");
  assert.equal(failed[1].max_gap_s, String(Math.max(Number(control[1].max_gap_s), Number(control[2].max_gap_s))));
});
