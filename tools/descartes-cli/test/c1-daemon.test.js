// Context plan C1: daemon integration of the alert foundations (transition log; later the label
// ingestion, the pending journal and the digest). These steps are audit/foundation only: they never
// change which alerts fire or when they notify.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDaemonIteration } from "../src/daemon.js";
import { readAlertRecords } from "../src/alert-store.js";
import { readAlertTransitions } from "../src/alert-transitions.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { resolveNotificationDeliveryPaths } from "../src/notification-delivery.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-c1-daemon-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: "2026-10-12T00:00:00.000Z" } };
}

function collectorsWithMemory(usedFraction) {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0.1, 0.1, 0.1], uptime_seconds: 10, memory: { used_fraction: usedFraction, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes: async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] }),
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

export async function runTicks(paths, fractions, { startMinute = 0, extra = {} } = {}) {
  const results = [];
  for (const [index, fraction] of fractions.entries()) {
    const ts = new Date(Date.UTC(2026, 9, 12, 0, startMinute + index)).toISOString();
    results.push(await runDaemonIteration(paths, { collectors: collectorsWithMemory(fraction), ts, now: ts, alertWindowMs: 90_000, deliverNotification: async () => ({ status: "cli_only" }), ...extra }));
  }
  return results;
}

test("the daemon appends activated and recovered transitions for a firing fixed rule", async () => {
  const paths = await tempPaths();
  const results = await runTicks(paths, [0.95, 0.95, 0.95, 0.2, 0.2, 0.2]);
  const memory = (await readAlertRecords(paths)).find((alert) => alert.rule_id === "system.memory.sustained_high");
  assert.ok(memory, "the memory alert fired");
  const log = await readAlertTransitions(paths);
  assert.equal(log.status, "valid");
  const forMemory = log.records.filter((record) => record.alert_id === memory.id).map((record) => record.kind);
  assert.ok(forMemory.includes("activated"));
  assert.ok(forMemory.includes("recovered"));
  assert.ok(results.every((result) => result.alertTransitions?.status === "ok"));
});

test("a transition-log failure never affects alerting", async () => {
  const paths = await tempPaths();
  const results = await runTicks(paths, [0.95, 0.95, 0.95], { extra: { recordAlertTransitions: async () => { throw new Error("ENOSPC: no space left"); } } });
  assert.equal(results.at(-1).alertTransitions.status, "error");
  assert.ok((await readAlertRecords(paths)).some((alert) => alert.rule_id === "system.memory.sustained_high" && alert.status === "active"));
});

test("an unreadable notification outbox leaves the tick warning and the path unchanged", async () => {
  const paths = await tempPaths();
  const { pendingFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(pendingFile), { recursive: true });
  await fs.mkdir(pendingFile);
  const result = await runDaemonIteration(paths, {
    collectors: collectorsWithMemory(0.1),
    ts: "2026-10-12T00:00:00.000Z",
    now: "2026-10-12T00:00:00.000Z",
    deliverNotification: async () => ({ status: "cli_only" }),
  });
  assert.equal(result.notificationOutbox.status, "warning");
  assert.equal(result.notificationOutbox.error.code, "EISDIR");
  assert.equal(result.status.state, "error");
  assert.equal((await fs.stat(pendingFile)).isDirectory(), true);
});

test("closure integrity audit is recorded before a delivery exception", async () => {
  const paths = await tempPaths();
  let captured;
  const ts = "2026-10-12T00:00:00.000Z";
  const result = await runDaemonIteration(paths, {
    collectors: collectorsWithMemory(0.1),
    ts,
    now: ts,
    deliverNotification: async () => { throw new Error("malformed notifications.json"); },
    reconcileAlertClosures: async () => ({
      alerts: await readAlertRecords(paths),
      changes: [{ digest: "a".repeat(64) }],
      audit: [{ kind: "unattributed_change", alert_id: "alert_test", incident_key: "k", digest: "a".repeat(64) }],
      notices: [{ notify: true, severity: "critical", title: "Integrity", body: "State changed." }],
    }),
    recordAlertTransitions: async (_paths, options) => {
      captured = options;
      return { status: "ok" };
    },
  });
  assert.equal(result.alertTransitions.status, "ok");
  assert.ok(captured.extraRecords.some((record) => record.kind === "unattributed_change"), "the audit is durable before notification delivery runs");
});

// ------------------------------------------------------------------------------------------------
// C1.4: the pending journal rides every completed structural tick.
// ------------------------------------------------------------------------------------------------
import { inspectPendingJournal, resolvePendingJournalPaths } from "../src/pending-journal.js";
import { readFactIntegrityLedger } from "../src/fact-store-integrity.js";

const HOUR = 3_600_000;
const T0 = Date.parse("2026-10-11T08:00:00.000Z");
const BOOT = "11111111-2222-3333-4444-555555555555";

function structuralHarness(paths) {
  const state = { checkpoint: undefined, sessions: { work: 1_000_100 } };
  const probe = (nowMs) => ({
    platform: "darwin",
    status: "ok",
    boot: { boot_id: BOOT, boot_id_source: "kern.bootsessionuuid", boot_time_s: 1_000_000, os_build: "25C56", os_release: "25.2.0" },
    clocks: { wall_ms: nowMs, uv_hrtime_ns: "1", uv_version: "1.52.1", os_uptime_ms: nowMs - 1_000_000_000, kern_waketime_s: 0, kern_sleeptime_s: 0, kern_monotonicclock_usecs: "1 2", machdep_wake_abstime: "0", machdep_wake_conttime: "0", tz_id: "Europe/Paris", utc_offset_min: 120 },
  });
  const run = async (nowMs, extra = {}) => runDaemonIteration(paths, {
    profile: {
      interval_ms: 60000,
      collectors: { system: { enabled: true }, processes: { enabled: true }, disks: { enabled: true } },
      structural: { interval_ms: HOUR, collectors: { sessions: { enabled: true }, "host-lifecycle": { enabled: true } } },
    },
    collectors: collectorsWithMemory(0.1),
    structuralCollectors: {
      sessions: async () => envelope("sessions", "collect_sessions", {
        multiplexers: [{ multiplexer: "tmux", status: "ok", binary_provenance: { requested_binary: "tmux", trust_verdict: "trusted", resolved_path: "/usr/bin/tmux", same_uid_writable_components: [] } }],
        sessions: Object.entries(state.sessions).map(([name, created]) => ({ multiplexer: "tmux", session_name: name, window_count: 1, attached: true, created_at_epoch_seconds: created })),
        total_count: Object.keys(state.sessions).length,
        truncated: false,
      }),
      "host-lifecycle": async () => ({ ...envelope("host-lifecycle", "collect_host_lifecycle", probe(nowMs)), observation: { start_ms: nowMs + 10, end_ms: nowMs + 20 } }),
    },
    hostLifecycleProbe: async () => probe(nowMs),
    daemonInstance: { nonce: "daemon-a", start_ms: T0 - HOUR },
    ts: new Date(nowMs).toISOString(),
    now: nowMs,
    readStructuralCheckpoint: async () => ({ last_structural_run_ms: state.checkpoint }),
    writeStructuralCheckpoint: async (_paths, checkpoint) => {
      state.checkpoint = checkpoint.last_structural_run_ms;
      return checkpoint;
    },
    loadLearnedConfig: async () => ({ enabled: false }),
    loadWatchConfig: async () => ({ enabled: true }),
    deliverNotification: async () => ({ status: "cli_only" }),
    ...extra,
  });
  return { state, run };
}

test("each structural tick maps the session pass and advances its watermark, after alerts and transitions", async () => {
  const paths = await tempPaths();
  const { run } = structuralHarness(paths);
  let result;
  for (let tick = 0; tick < 3; tick += 1) result = await run(T0 + tick * HOUR);
  assert.equal(result.pendingJournal.session.status, "ok");
  const { ledger } = await readFactIntegrityLedger(paths, "session");
  const inspected = await inspectPendingJournal(paths, "session", { ledger });
  assert.equal(inspected.status, "valid");
  assert.equal(inspected.state.watermark, ledger.continuity.last_committed_pass_id);
  assert.equal(inspected.state.passes[inspected.state.watermark].observation_ts, new Date(T0 + 2 * HOUR).toISOString());
  const log = await readAlertTransitions(paths);
  assert.ok(log.records.some((record) => record.kind === "pending_journal_created" && record.family === "session"));
});

test("a pass whose alerts were not persisted is never scored: the next tick excludes it as unadjudicated", async () => {
  const paths = await tempPaths();
  const { run } = structuralHarness(paths);
  await run(T0);
  await run(T0 + HOUR, { evaluateAlerts: false });
  await run(T0 + 2 * HOUR);
  const { ledger } = await readFactIntegrityLedger(paths, "session");
  const inspected = await inspectPendingJournal(paths, "session", { ledger });
  assert.ok(inspected.state.ranges.some((range) => range.reason === "unadjudicated" && range.observation_ts_from === new Date(T0 + HOUR).toISOString()));
  const log = await readAlertTransitions(paths);
  assert.ok(log.records.some((record) => record.kind === "excluded_unadjudicated" && record.family === "session"));
});

test("pending_truncation_never_stops_detection: a wiped journal is a witnessed discontinuity, notified once, re-certified next tick", async () => {
  const paths = await tempPaths();
  const { run } = structuralHarness(paths);
  const notices = [];
  const deliverNotification = async (_paths, decision, meta) => {
    notices.push(meta?.ruleId);
    return { status: "cli_only" };
  };
  await run(T0, { deliverNotification });
  await run(T0 + HOUR, { deliverNotification });
  await fs.rm(resolvePendingJournalPaths(paths, "session").dir, { recursive: true });
  const broken = await run(T0 + 2 * HOUR, { deliverNotification });
  assert.equal(broken.pendingJournal.session.discontinuity.cause, "journal_and_checkpoint_missing");
  assert.equal(broken.pendingJournal.session.admission.suspended, true);
  assert.equal(notices.filter((id) => id === "integrity.pending_discontinuity").length, 1);
  assert.equal(broken.status.state, "ok", "detection and the daemon's health are unaffected");
  const next = await run(T0 + 3 * HOUR, { deliverNotification });
  assert.equal(next.pendingJournal.session.open_epoch, null);
  assert.equal(next.pendingJournal.session.admission.suspended, false);
  assert.equal(notices.filter((id) => id === "integrity.pending_discontinuity").length, 1, "one notice per epoch");
  const log = await readAlertTransitions(paths);
  assert.ok(log.records.some((record) => record.kind === "recertified" && record.family === "session"));
});

test("a pending-journal failure never fails the tick or touches alerting", async () => {
  const paths = await tempPaths();
  const { run } = structuralHarness(paths);
  const result = await run(T0, { runPendingJournalPrePass: async () => { throw new Error("EACCES"); } });
  assert.equal(result.pendingJournal, undefined);
  assert.equal(result.status.state, "ok");
});

// ------------------------------------------------------------------------------------------------
// C1.3: the daemon ingests CLI labels after delivery and before the transition log.
// ------------------------------------------------------------------------------------------------
import { appendAlertLabel } from "../src/alert-labels.js";

test("a CLI label is ingested by the daemon's next tick, logged and notified; it never changes what fires", async () => {
  const paths = await tempPaths();
  await runTicks(paths, [0.95, 0.95, 0.95]);
  const memory = (await readAlertRecords(paths)).find((alert) => alert.rule_id === "system.memory.sustained_high");
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: memory.id }, now: "2026-10-12T00:02:30.000Z" });
  const notices = [];
  const [result] = await runTicks(paths, [0.95], { startMinute: 3, extra: { deliverNotification: async (_p, decision, meta) => { notices.push(meta?.ruleId); return { status: "cli_only" }; } } });
  assert.equal(result.labelIngestion.ingested.length, 1);
  assert.equal(result.labelIngestion.ingested[0].effect, "undeclared_kind", "a fixed resource rule has no declared stream kind: recorded, never closed");
  assert.ok(notices.includes("descartes.labels"));
  const after = (await readAlertRecords(paths)).find((alert) => alert.id === memory.id);
  assert.equal(after.status, "active");
  const log = await readAlertTransitions(paths);
  assert.ok(log.records.some((record) => record.kind === "label_ingested" && record.alert_id === memory.id));
});

// ------------------------------------------------------------------------------------------------
// C1.5: the digest rides the end of the tick.
// ------------------------------------------------------------------------------------------------
test("the daemon starts the digest clock and evaluates it once per period, pushing nothing when empty", async () => {
  const paths = await tempPaths();
  const pushes = [];
  const extra = { deliverNotification: async (_p, _d, meta) => { pushes.push(meta?.ruleId); return { status: "cli_only" }; } };
  const [first] = await runTicks(paths, [0.2], { extra });
  assert.equal(first.alertDigest.status, "started");
  const [later] = await runTicks(paths, [0.2], { startMinute: 25 * 60, extra });
  assert.equal(later.alertDigest.status, "empty");
  assert.equal(pushes.includes("descartes.digest"), false);
});
