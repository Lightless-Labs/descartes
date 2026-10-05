import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { runLearnedConfigCommand } from "../src/constraint-store.js";
import {
  buildBaselineInspect,
  buildBaselineStatus,
  runBaseline,
} from "../src/baseline.js";
import { alertId } from "../src/alert-store.js";
import { loadWatchConfig, resolveWatchStorePaths, writeWatchConfig } from "../src/watch-store.js";
import { writeDaemonStatus } from "../src/history-store.js";
import { SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID, computeSessionBaselineCandidates, writeSessionBaselineStore } from "../src/session-baseline.js";
import { computePeerBaselineCandidates, writePeerBaselineStore } from "../src/peer-baseline.js";
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "../src/peer-baseline.js";

// ---------------------------------------------------------------------------------------------
// A1 (2026-10 calibration review) fixtures: status-vs-detector consistency. `baseline status` must
// never say "watching" for a domain whose detector, run over the SAME fact-history, store and
// clock, reports no coverage (evaluatedAlertKeys = []).
// ---------------------------------------------------------------------------------------------

const A1_BASE_MS = Date.parse("2026-09-01T00:00:00.000Z");
const A1_HOUR_MS = 60 * 60 * 1000;
const a1Ts = (hour) => new Date(A1_BASE_MS + hour * A1_HOUR_MS).toISOString();

function a1SessionTick(hour, count) {
  const ts = a1Ts(hour);
  const points = [];
  for (let i = 0; i < count; i += 1) {
    const entityKey = `session.tmux.${i.toString(16).padStart(16, "0")}`;
    points.push({
      ts,
      fact_name: "session.presence",
      entity_key: entityKey,
      attributes: { created_at_fingerprint: i === 0 ? `fingerprint-${hour}` : "stable" },
    });
  }
  points.push({ ts, fact_name: "session.presence", entity_key: "session.census-marker.v1", attributes: { census_state: "complete" } });
  return points;
}

function a1PeerTick(hour, count) {
  const ts = a1Ts(hour);
  const points = [];
  for (let i = 0; i < count; i += 1) {
    points.push({ ts, fact_name: "peer.presence", entity_key: `peer.ssh.e-${i}`, attributes: { source_type: "ssh", presence_state: "observed_active" } });
  }
  points.push({ ts, fact_name: "peer.presence", entity_key: "peer.census-marker.v1", attributes: { availability_signature: "v1:ok-ok-ok-ok-ok" } });
  return points;
}

function a1Points(tickCount) {
  const points = [];
  for (let hour = 0; hour < tickCount; hour += 1) points.push(...a1SessionTick(hour, 5), ...a1PeerTick(hour, 5));
  return points;
}

const A1_ESTABLISHED_STORE = { cold_start_pending: false, last_folded_ts: a1Ts(-1) };

const A1_SCENARIOS = [
  {
    // The reported bug: a still-pending lockout with >= 6 post-anchor complete ticks read as
    // "watching" while the detector (gating on the pre-update store) evaluates nothing.
    name: "cold start still pending, 7 complete ticks after the anchor",
    store: { cold_start_pending: true, cold_start_reason: "history_lost", cold_start_since_ts: new Date(A1_BASE_MS + 23 * A1_HOUR_MS + 1).toISOString(), last_folded_ts: a1Ts(30) },
    tickCount: 31,
    nowHour: 30.5,
    completeness: { status: "intact" },
    expectWatching: false,
  },
  {
    name: "established store but fact history degraded (detector would re-arm the lockout)",
    store: A1_ESTABLISHED_STORE,
    tickCount: 31,
    nowHour: 30.5,
    completeness: { status: "degraded", last_bytecap_evict_ts: a1Ts(29) },
    expectWatching: false,
  },
  {
    name: "established store but the latest complete census is stale (structural ticks failing)",
    store: A1_ESTABLISHED_STORE,
    tickCount: 31,
    nowHour: 34,
    completeness: { status: "intact" },
    expectWatching: false,
  },
  {
    name: "established store, fresh and trusted, but the count baseline is still provisional (10 of 30)",
    store: A1_ESTABLISHED_STORE,
    tickCount: 10,
    nowHour: 9.5,
    completeness: { status: "intact" },
    expectWatching: false,
    expectSessionWatching: true,
  },
  {
    name: "established store but corrupt fact lines this read (detector would re-arm the lockout)",
    store: A1_ESTABLISHED_STORE,
    tickCount: 31,
    nowHour: 30.5,
    completeness: { status: "intact" },
    corruptCount: 1,
    expectWatching: false,
  },
  {
    name: "established store whose last_folded_ts is in the future (clock rollback)",
    store: { cold_start_pending: false, last_folded_ts: a1Ts(40) },
    tickCount: 31,
    nowHour: 30.5,
    completeness: { status: "intact" },
    expectWatching: false,
  },
  {
    name: "established, fresh, trusted, count baseline established (positive control)",
    store: A1_ESTABLISHED_STORE,
    tickCount: 31,
    nowHour: 30.5,
    completeness: { status: "intact" },
    expectWatching: true,
  },
];

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-baseline-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function capture() {
  const values = [];
  return { values, output: (value) => values.push(value) };
}

test("baseline status on a fresh install is watch-on and reports every domain still learning", async () => {
  const paths = await tempPaths();
  const result = await buildBaselineStatus(paths, { now: "2026-09-27T12:00:00.000Z" });

  assert.equal(result.watch_config.enabled, true);
  assert.deepEqual(result.domains.map((domain) => domain.domain), [
    "service",
    "session",
    "peer",
    "scheduled-job",
    "process-lineage",
  ]);
  for (const domain of result.domains) {
    // R2: session/peer show the binding 30-sample count requirement (see the dedicated R2 test).
    assert.equal(domain.phase, domain.domain === "session" || domain.domain === "peer" ? "still learning — 0 of 30" : "still learning — 0 of 6");
    assert.equal(domain.cold_start_reason, "initial_baseline");
  }
});

test("baseline status renders human and JSON forms", async () => {
  const paths = await tempPaths();
  const human = capture();
  await runBaseline(paths, ["status"], { output: human.output, now: "2026-09-27T12:00:00.000Z" });
  assert.match(human.values[0], /Structural watching: enabled/);
  assert.match(human.values[0], /service: still learning — 0 of 6/);
  assert.match(human.values[0], /process-lineage: still learning — 0 of 6/);

  const json = capture();
  await runBaseline(paths, ["status", "--json"], { output: json.output, now: "2026-09-27T12:00:00.000Z" });
  const parsed = JSON.parse(json.values[0]);
  assert.equal(parsed.watch_config.enabled, true);
  assert.equal(parsed.domains[0].phase, "still learning — 0 of 6");
});

test("baseline inspect is live, supports a domain filter, and exposes the recomputation note", async () => {
  const paths = await tempPaths();
  const point = (ts, entity_key) => ({
    ts,
    fact_name: "service.presence",
    entity_key,
    attributes: {},
  });
  const census = (ts) => ({
    ts,
    fact_name: "service.census",
    entity_key: "service.census-marker.v1",
    attributes: { census_state: "complete" },
  });
  const points = [];
  for (let index = 0; index < 4; index += 1) {
    const ts = `2026-09-27T0${index}:00:00.000Z`;
    points.push(census(ts), point(ts, "service.example"));
  }

  const readFactPoints = async () => ({
    points,
    corrupt_count: 0,
    completeness: { status: "intact" },
  });
  const result = await buildBaselineInspect(paths, {
    now: "2026-09-27T12:00:00.000Z",
    readFactPoints,
    domain: "service",
  });
  assert.equal(result.domains.length, 1);
  assert.deepEqual(result.domains[0].established, ["service.example"]);
  assert.equal(result.recomputed_live, true);
  assert.match(result.note, /recomputed live/i);

  const human = capture();
  await runBaseline(paths, ["inspect", "--domain", "service"], { output: human.output, now: "2026-09-27T12:00:00.000Z", readFactPoints });
  assert.match(human.values[0], /Established \(1\): service\.example/);

  const json = capture();
  await runBaseline(paths, ["inspect", "--domain", "service", "--json"], { output: json.output, now: "2026-09-27T12:00:00.000Z", readFactPoints });
  assert.deepEqual(JSON.parse(json.values[0]).domains[0].established, ["service.example"]);
});

test("baseline inspect (R8): tailscale peers are not listed as established for the peer-count baseline that excludes them", async () => {
  const paths = await tempPaths();
  const points = [];
  for (let index = 0; index < 31; index += 1) {
    const ts = new Date(Date.parse("2026-09-26T00:00:00.000Z") + index * 3600000).toISOString();
    points.push(
      { ts, fact_name: "peer.presence", entity_key: "peer.ssh.aaaaaaaaaaaaaaaa", attributes: { source_type: "ssh", presence_state: "observed_active" } },
      { ts, fact_name: "peer.presence", entity_key: "peer.tailscale.bbbbbbbbbbbbbbbb", attributes: { source_type: "tailscale", presence_state: "observed_active" } },
      { ts, fact_name: "peer.presence", entity_key: "peer.census-marker.v1", attributes: { availability_signature: "v1:ok-ok-ok-ok-ok" } },
    );
  }
  const readFactPoints = async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } });
  const result = await buildBaselineInspect(paths, { now: "2026-09-27T07:00:00.000Z", readFactPoints, domain: "peer" });
  assert.deepEqual(result.domains[0].established, ["peer.ssh.aaaaaaaaaaaaaaaa"]);
});

test("R8: baseline inspect keeps Tailscale-only peers in the established peer set", async () => {
  const paths = await tempPaths();
  const points = [];
  for (let index = 0; index < 31; index += 1) {
    const ts = new Date(Date.parse("2026-09-26T00:00:00.000Z") + index * 3600000).toISOString();
    points.push({
      ts,
      fact_name: "peer.presence",
      entity_key: "peer.tailscale.bbbbbbbbbbbbbbbb",
      attributes: { source_type: "tailscale", presence_state: "observed_active" },
    });
  }
  const readFactPoints = async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } });
  const result = await buildBaselineInspect(paths, { now: "2026-09-27T07:00:00.000Z", readFactPoints, domain: "peer" });
  assert.deepEqual(result.domains[0].established, ["peer.tailscale.bbbbbbbbbbbbbbbb"]);
});

test("baseline status uses the persisted daemon structural interval for freshness", async () => {
  const paths = await tempPaths();
  await writeSessionBaselineStore(paths, A1_ESTABLISHED_STORE);
  await writeDaemonStatus(paths, { profile: { structural: { interval_ms: 2 * A1_HOUR_MS } } });
  const points = a1Points(31);
  const readFactPoints = async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } });
  const result = await buildBaselineStatus(paths, { now: a1Ts(34), readFactPoints });
  assert.equal(result.domains.find((domain) => domain.domain === "session").phase, "watching");
});

test("baseline status keeps rule coverage honest on overflow ticks", async () => {
  const paths = await tempPaths();
  await writeSessionBaselineStore(paths, A1_ESTABLISHED_STORE);
  await writePeerBaselineStore(paths, A1_ESTABLISHED_STORE);
  const points = [...a1Points(30)];
  const sessionTs = a1Ts(30);
  points.push(...a1SessionTick(30, 5), { ts: sessionTs, fact_name: "session.presence", entity_key: "session.overflow-marker.v1", attributes: { overflow: "true" } });
  const peerTs = a1Ts(31);
  points.push(
    ...a1PeerTick(31, 40),
    { ts: peerTs, fact_name: "peer.presence", entity_key: "peer.overflow-marker.v1", source_envelope_id: "vpn-peer-status", attributes: { overflow: "true" } },
    { ts: peerTs, fact_name: "peer.presence", entity_key: "peer.census-marker.v1", source_envelope_id: "vpn-peer-status", attributes: { availability_signature: "v1:ok-ok-ok-ok-ok" } },
  );
  const readFactPoints = async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } });
  const result = await buildBaselineStatus(paths, { now: a1Ts(31.5), readFactPoints });
  const session = result.domains.find((domain) => domain.domain === "session");
  const peer = result.domains.find((domain) => domain.domain === "peer");
  assert.ok(session.watching_rules.includes(SESSION_CHURN_RULE_ID), "session churn still evaluates on a complete overflow tick");
  assert.ok(peer.watching_rules.includes(PEER_COUNT_SPIKE_RULE_ID), "peer spike still scores a capped overflow tick");
});

for (const scenario of A1_SCENARIOS) {
  test(`A1 status-vs-detector consistency (${scenario.name}): status says "watching" iff the detector reports coverage`, async () => {
    const paths = await tempPaths();
    await writeSessionBaselineStore(paths, scenario.store);
    await writePeerBaselineStore(paths, scenario.store);
    const points = a1Points(scenario.tickCount);
    const readFactPoints = async () => ({ points, corrupt_count: scenario.corruptCount ?? 0, schema_invalid_count: 0, completeness: scenario.completeness });
    const now = new Date(A1_BASE_MS + scenario.nowHour * A1_HOUR_MS).toISOString();

    const status = await buildBaselineStatus(paths, { now, readFactPoints });
    const noWrite = async () => {};
    const detectors = {
      session: await computeSessionBaselineCandidates(paths, { now, readFactPoints, writeSessionBaselineStore: noWrite }),
      peer: await computePeerBaselineCandidates(paths, { now, readFactPoints, writePeerBaselineStore: noWrite }),
    };
    for (const domain of ["session", "peer"]) {
      const reported = status.domains.find((entry) => entry.domain === domain);
      const expectedKeys = new Set(detectors[domain].evaluatedAlertKeys);
      const statusKeys = new Set(reported.evaluated_alert_keys);
      assert.deepEqual(statusKeys, expectedKeys, `${domain}: status per-rule coverage must mirror detector evaluatedAlertKeys`);
      const ruleKeys = domain === "session"
        ? {
            [SESSION_COUNT_DROP_RULE_ID]: alertId(SESSION_COUNT_DROP_RULE_ID, "global"),
            [SESSION_CHURN_RULE_ID]: alertId(SESSION_CHURN_RULE_ID, "session.tmux.0000000000000000"),
          }
        : {
            [PEER_COUNT_SPIKE_RULE_ID]: alertId(PEER_COUNT_SPIKE_RULE_ID, "global"),
            [PEER_COUNT_DROP_RULE_ID]: alertId(PEER_COUNT_DROP_RULE_ID, "global"),
          };
      for (const [ruleId, key] of Object.entries(ruleKeys)) {
        assert.equal(
          reported.watching_rules.includes(ruleId),
          expectedKeys.has(key),
          `${domain}: status watching claim for ${ruleId} must agree with evaluatedAlertKeys=${JSON.stringify([...expectedKeys])}`,
        );
      }
      const hasCoverage = expectedKeys.size > 0;
      const expectedWatching = domain === "session" ? (scenario.expectSessionWatching ?? scenario.expectWatching) : scenario.expectWatching;
      assert.equal(hasCoverage, expectedWatching, `sanity: ${domain} detector coverage for this scenario`);
      if (scenario.name.includes("count baseline is still provisional") && domain === "session") {
        assert.match(reported.phase, /^watching \(churn\); count baseline still learning — 10 of 30$/);
      }
    }
  });
}

test("A1: a still-pending lockout that has accumulated its post-anchor ticks says so honestly, with the cold-start reason", async () => {
  const paths = await tempPaths();
  const [scenario] = A1_SCENARIOS;
  await writeSessionBaselineStore(paths, scenario.store);
  const points = a1Points(scenario.tickCount);
  const readFactPoints = async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: scenario.completeness });
  const status = await buildBaselineStatus(paths, { now: new Date(A1_BASE_MS + scenario.nowHour * A1_HOUR_MS).toISOString(), readFactPoints });
  const session = status.domains.find((entry) => entry.domain === "session");
  assert.equal(session.cold_start_pending, true);
  assert.equal(session.cold_start_reason, "history_lost");
  assert.match(session.phase, /^still learning — 6 of 6, lockout clears on the next daemon tick$/);
});

test("A1: untrustworthy history and a stale census each report their own reason, never 'watching'", async () => {
  const degradedPaths = await tempPaths();
  await writeSessionBaselineStore(degradedPaths, A1_ESTABLISHED_STORE);
  const points = a1Points(31);
  const degraded = await buildBaselineStatus(degradedPaths, {
    now: a1Ts(30.5),
    readFactPoints: async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "degraded", last_bytecap_evict_ts: a1Ts(29) } }),
  });
  const degradedSession = degraded.domains.find((entry) => entry.domain === "session");
  assert.equal(degradedSession.phase, "locked out — fact history untrustworthy (history_degraded)");
  assert.equal(degradedSession.history_trust, "history_degraded");

  const stalePaths = await tempPaths();
  await writeSessionBaselineStore(stalePaths, A1_ESTABLISHED_STORE);
  const stale = await buildBaselineStatus(stalePaths, {
    now: a1Ts(34),
    readFactPoints: async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } }),
  });
  assert.match(stale.domains.find((entry) => entry.domain === "session").phase, /^stale — /);
});

test("A1: corrupt facts, a clock rollback, an incomplete latest census and an empty window each get their own non-watching phase", async () => {
  const points = a1Points(31);
  const statusOf = async (store, { corruptCount = 0, extraPoints = [], readPoints = [...points, ...extraPoints], nowHour = 30.5 } = {}) => {
    const paths = await tempPaths();
    await writeSessionBaselineStore(paths, store);
    const result = await buildBaselineStatus(paths, {
      now: a1Ts(nowHour),
      readFactPoints: async () => ({ points: readPoints, corrupt_count: corruptCount, schema_invalid_count: 0, completeness: { status: "intact" } }),
    });
    return result.domains.find((entry) => entry.domain === "session");
  };

  const corrupt = await statusOf(A1_ESTABLISHED_STORE, { corruptCount: 1 });
  assert.equal(corrupt.phase, "locked out — fact history untrustworthy (corrupt_facts_this_tick)");

  const rollback = await statusOf({ cold_start_pending: false, last_folded_ts: a1Ts(40) });
  assert.equal(rollback.phase, "locked out — fact history untrustworthy (clock_rollback)");

  const partialLatest = await statusOf(A1_ESTABLISHED_STORE, {
    extraPoints: [{ ts: a1Ts(30.25), fact_name: "session.presence", entity_key: "session.census-marker.v1", attributes: { census_state: "partial" } }],
  });
  assert.equal(partialLatest.phase, "watching");

  const empty = await statusOf(A1_ESTABLISHED_STORE, { readPoints: [] });
  assert.equal(empty.phase, "stale — no complete census in the fact-history window");
});

test("R2: on a fresh install the count rules (session, peer) show progress toward the 30-sample count baseline, the binding requirement; the census domains keep N of 6", async () => {
  const paths = await tempPaths();
  const result = await buildBaselineStatus(paths, { now: "2026-09-27T12:00:00.000Z" });
  for (const domain of result.domains) {
    const countRule = domain.domain === "session" || domain.domain === "peer";
    assert.equal(domain.phase, countRule ? "still learning — 0 of 30" : "still learning — 0 of 6", domain.domain);
    assert.equal(domain.required_ticks, countRule ? 30 : 6, domain.domain);
  }
});

test("R2: during a lockout the count rules show whichever requirement has more ticks remaining", async () => {
  const pendingStore = (anchorHour) => ({
    cold_start_pending: true,
    cold_start_reason: "history_lost",
    cold_start_since_ts: new Date(A1_BASE_MS + anchorHour * A1_HOUR_MS + 1).toISOString(),
    last_folded_ts: a1Ts(anchorHour),
  });
  const statusFor = async (tickCount, anchorHour) => {
    const paths = await tempPaths();
    await writeSessionBaselineStore(paths, pendingStore(anchorHour));
    await writePeerBaselineStore(paths, pendingStore(anchorHour));
    const points = a1Points(tickCount);
    const result = await buildBaselineStatus(paths, {
      now: a1Ts(tickCount - 0.5),
      readFactPoints: async () => ({ points, corrupt_count: 0, schema_invalid_count: 0, completeness: { status: "intact" } }),
    });
    return Object.fromEntries(result.domains.map((domain) => [domain.domain, domain]));
  };

  // 10 complete ticks, 3 after the anchor: lockout needs 3 more, the count baseline 20 more.
  const countBinding = await statusFor(10, 6);
  for (const domain of ["session", "peer"]) {
    assert.equal(countBinding[domain].phase, "still learning — 10 of 30", domain);
    assert.equal(countBinding[domain].required_ticks, 30, domain);
  }
  // 31 complete ticks (count baseline already met), 2 after the anchor: the lockout binds.
  const lockoutBinding = await statusFor(31, 28);
  for (const domain of ["session", "peer"]) {
    assert.equal(lockoutBinding[domain].phase, "still learning — 2 of 6", domain);
    assert.equal(lockoutBinding[domain].required_ticks, 6, domain);
  }
});

test("baseline enable and disable write only watch.json", async () => {
  const paths = await tempPaths();
  await writeWatchConfig(paths, { enabled: true, fact_store_max_bytes: 2048 }, { now: "2026-09-27T11:00:00.000Z" });
  const disabled = capture();
  await runBaseline(paths, ["disable"], { output: disabled.output, now: "2026-09-27T12:00:00.000Z" });
  assert.match(disabled.values[0], /Structural watching: disabled/);
  assert.equal((await loadWatchConfig(paths)).enabled, false);
  assert.equal((await loadWatchConfig(paths)).fact_store_max_bytes, 2048);

  const enabled = capture();
  await runBaseline(paths, ["enable", "--json"], { output: enabled.output, now: "2026-09-27T12:00:00.000Z" });
  assert.equal(JSON.parse(enabled.values[0]).watch_config.enabled, true);
  assert.equal((await loadWatchConfig(paths)).enabled, true);
  assert.equal((await fs.stat(resolveWatchStorePaths(paths).configFile)).isFile(), true);
});

test("an explicit learned disable does not disable default-on watch", async () => {
  const paths = await tempPaths();
  const output = capture();
  await runLearnedConfigCommand(paths, "disable", ["--json"], { output: output.output, now: "2026-09-27T12:00:00.000Z" });
  assert.equal(JSON.parse(output.values[0]).learned_config.enabled, false);
  assert.equal((await loadWatchConfig(paths)).enabled, true);

  const status = await buildBaselineStatus(paths, { now: "2026-09-27T12:00:00.000Z" });
  assert.equal(status.watch_config.enabled, true);
  assert.match(status.domains[0].phase, /^still learning/);
});
