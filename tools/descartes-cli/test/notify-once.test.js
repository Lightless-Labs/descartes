import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  applyAlertCandidates,
  confirmAlertDelivery,
  recordAlertDeliveryFailure,
  writeAlertRecords,
  readAlertRecords,
} from "../src/alert-store.js";
import { emitMetricAlertFallbackSignals, emitSessionAlertSignals } from "../src/alert-intelligence.js";
import { buildChurnCandidates } from "../src/session-baseline.js";
import { buildCredentialAccessCandidates } from "../src/credential-access-baseline.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-notify-once-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

function candidate(incidentKey, severity = "warning") {
  return {
    id: "alert_shared",
    rule_id: "provenance.port.new_public_bind",
    fingerprint: "port.tcp.443",
    incident_key: incidentKey,
    severity,
    title: "New public bind",
    summary: "A new identity owns 443.",
    diagnostics: {},
  };
}

test("one alert id represents simultaneous incidents as a set and notifies each key once", async () => {
  const paths = await tempPaths();
  const first = applyAlertCandidates([], [candidate("identity-a"), candidate("identity-b")], { now: "2026-10-06T00:00:00.000Z" });
  assert.deepEqual(first.notification_due_ids, ["alert_shared"]);
  assert.deepEqual(first.notification_due_incidents.map((entry) => entry.incident_key).sort(), ["identity-a", "identity-b"]);
  assert.deepEqual(Object.keys(first.alerts[0].incidents).sort(), ["identity-a", "identity-b"]);
  await writeAlertRecords(paths, first.alerts);
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:01:00.000Z", incidentKey: "identity-a" });

  const second = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-a"), candidate("identity-b")], { now: "2026-10-06T00:02:00.000Z" });
  assert.deepEqual(second.notification_due_ids, ["alert_shared"], "identity B remains due after identity A is confirmed");
  assert.deepEqual(second.notification_due_incidents.map((entry) => entry.incident_key), ["identity-b"]);
  await writeAlertRecords(paths, second.alerts);
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:03:00.000Z", incidentKey: "identity-b" });
  const quiet = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-b"), candidate("identity-a")], { now: "2026-10-06T00:04:00.000Z" });
  assert.deepEqual(quiet.notification_due_ids, []);
  assert.deepEqual((quiet.alerts[0].notified_incident_keys ?? []).sort(), ["identity-a", "identity-b"]);
  assert.equal(quiet.alerts[0].incidents["identity-a"].confirmed_at, "2026-10-06T00:01:00.000Z");
  assert.equal(quiet.alerts[0].incidents["identity-b"].confirmed_at, "2026-10-06T00:03:00.000Z");
});

test("candidate ordering cannot change per-incident state or current payload", () => {
  const candidates = [candidate("identity-a", "warning"), { ...candidate("identity-b", "critical"), summary: "B" }];
  const forward = applyAlertCandidates([], candidates, { now: "2026-10-06T00:00:00.000Z" });
  const reverse = applyAlertCandidates([], [...candidates].reverse(), { now: "2026-10-06T00:00:00.000Z" });
  assert.deepEqual(reverse.alerts, forward.alerts);
  assert.deepEqual(reverse.notification_due_incidents, forward.notification_due_incidents);
});

test("delivery iterates every due incident under one alert id", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [{ ...candidate("identity-a"), rule_id: "system.memory.sustained_high" }, { ...candidate("identity-b"), rule_id: "system.memory.sustained_high" }], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  const delivered = [];
  await emitMetricAlertFallbackSignals(paths, applied, {
    now: "2026-10-06T00:01:00.000Z",
    config: { enabled: false, enabled_namespaces: ["metric"] },
    deliverNotification: async (_paths, _decision, metadata) => {
      delivered.push(metadata.episodeKey);
      return { status: "cli_only" };
    },
  });
  assert.deepEqual(delivered, ["identity-a", "identity-b"]);
  const persisted = (await readAlertRecords(paths))[0];
  assert.equal(persisted.incidents["identity-a"].confirmed_at !== null, true);
  assert.equal(persisted.incidents["identity-b"].confirmed_at !== null, true);
});

test("a persisted failed incident is retried when its key is absent from a later tick", async () => {
  const paths = await tempPaths();
  const first = applyAlertCandidates([], [candidate("identity-a"), candidate("identity-b")], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, first.alerts);
  await recordAlertDeliveryFailure(paths, "alert_shared", { now: "2026-10-06T00:00:00.000Z", incidentKey: "identity-a" });
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:00:01.000Z", incidentKey: "identity-b" });

  const beforeBackoff = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-b")], { now: "2026-10-06T00:00:30.000Z" });
  assert.deepEqual(beforeBackoff.notification_due_incidents, []);
  const afterBackoff = applyAlertCandidates(beforeBackoff.alerts, [candidate("identity-b")], { now: "2026-10-06T00:01:01.000Z" });
  assert.deepEqual(afterBackoff.notification_due_incidents, [{ alert_id: "alert_shared", incident_key: "identity-a" }]);
});

test("a failed storm notification is retried after backoff without another overflow", async () => {
  const paths = await tempPaths();
  const candidates = Array.from({ length: 257 }, (_, index) => candidate(`identity-${index}`));
  const storm = applyAlertCandidates([], candidates, { now: "2026-10-06T00:00:00.000Z" });
  assert.deepEqual(storm.notification_due_incidents.map((entry) => entry.incident_key), ["__incident_storm__"]);
  await writeAlertRecords(paths, storm.alerts);
  await recordAlertDeliveryFailure(paths, "alert_shared", { now: "2026-10-06T00:00:00.000Z", incidentKey: "__incident_storm__" });

  const beforeBackoff = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-0")], { now: "2026-10-06T00:00:30.000Z" });
  assert.deepEqual(beforeBackoff.notification_due_incidents, []);
  const afterBackoff = applyAlertCandidates(beforeBackoff.alerts, [candidate("identity-0")], { now: "2026-10-06T00:01:01.000Z" });
  assert.deepEqual(afterBackoff.notification_due_incidents, [{ alert_id: "alert_shared", incident_key: "__incident_storm__", storm: true, incident_count: 257 }]);
});

test("confirmed incidents are retained and a 257th identity enters a one-notification storm state", async () => {
  const paths = await tempPaths();
  let alerts = [];
  for (let index = 0; index < 256; index += 1) {
    const key = `identity-${index}`;
    const applied = applyAlertCandidates(alerts, [{ ...candidate(key), rule_id: "session.churn" }], { now: `2026-10-06T00:${String(Math.floor(index / 60)).padStart(2, "0")}:${String(index % 60).padStart(2, "0")}.000Z` });
    alerts = applied.alerts;
    await writeAlertRecords(paths, alerts);
    await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-07T00:00:00.000Z", incidentKey: key });
    alerts = await readAlertRecords(paths);
  }
  const overflow = applyAlertCandidates(alerts, [{ ...candidate("identity-256"), rule_id: "session.churn" }], { now: "2026-10-08T00:00:00.000Z" });
  assert.equal(overflow.alerts[0].incident_state, "incident_storm");
  assert.equal(Object.keys(overflow.alerts[0].incidents).length, 256);
  assert.equal(overflow.alerts[0].incidents["identity-0"].confirmed_at !== null, true);
  assert.deepEqual(overflow.notification_due_incidents.map((entry) => entry.incident_key), ["__incident_storm__"]);
  await writeAlertRecords(paths, overflow.alerts);
  const delivered = [];
  await emitSessionAlertSignals(paths, overflow, {
    now: "2026-10-08T00:01:00.000Z",
    config: { enabled: false, enabled_namespaces: ["metric"] },
    deliverNotification: async (_paths, _decision, metadata) => {
      delivered.push(metadata.episodeKey);
      return { status: "cli_only" };
    },
  });
  assert.deepEqual(delivered, ["__incident_storm__"]);
  const replay = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-0")], { now: "2026-10-08T00:02:00.000Z" });
  assert.deepEqual(replay.notification_due_incidents, []);
});

test("a lost confirmation write causes redelivery, never silence", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate("identity-a")], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:01:00.000Z", incidentKey: "identity-a" });
  // Simulate the confirmation write being lost after the external notification succeeded.
  await writeAlertRecords(paths, applied.alerts);
  const replay = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-a")], { now: "2026-10-06T00:02:00.000Z" });
  assert.deepEqual(replay.notification_due_incidents.map((entry) => entry.incident_key), ["identity-a"]);
});

test("a legacy active record without episode metadata is not notified", () => {
  const legacy = {
    id: "alert_legacy_no_episode",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    severity: "warning",
    title: "Memory high",
    first_seen: "2026-10-01T00:00:00.000Z",
    last_seen: "2026-10-01T00:00:00.000Z",
  };
  const result = applyAlertCandidates([legacy], [{ ...legacy, incident_key: "default" }], { now: "2026-10-06T00:00:00.000Z" });
  assert.deepEqual(result.notification_due_incidents, []);
});

test("a stale second evaluation cannot deliver an already-confirmed notification", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [{ ...candidate("identity-a"), rule_id: "system.memory.sustained_high" }], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, applied.alerts);
  const evaluation = { alerts: applied.alerts, notification_due_ids: ["alert_shared"] };
  let deliveries = 0;
  const options = {
    now: "2026-10-06T00:01:00.000Z",
    config: { enabled: false, enabled_namespaces: ["metric"] },
    deliverNotification: async () => { deliveries += 1; return { status: "cli_only" }; },
  };
  await emitMetricAlertFallbackSignals(paths, evaluation, options);
  await emitMetricAlertFallbackSignals(paths, evaluation, options);
  assert.equal(deliveries, 1);
});

test("new incidents and severity escalation bypass delivery backoff, including rollback", async () => {
  const paths = await tempPaths();
  const initial = applyAlertCandidates([], [candidate("identity-a")], { now: "2026-10-06T00:00:00.000Z" });
  await writeAlertRecords(paths, initial.alerts);
  await recordAlertDeliveryFailure(paths, "alert_shared", { now: "2026-10-06T00:00:00.000Z", episodeKey: "identity-a" });
  const warningRetry = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-a")], { now: "2026-10-06T00:00:30.000Z" });
  assert.deepEqual(warningRetry.notification_due_ids, []);
  const newIncident = applyAlertCandidates(warningRetry.alerts, [candidate("identity-b")], { now: "2026-10-06T00:00:31.000Z" });
  assert.deepEqual(newIncident.notification_due_ids, ["alert_shared"]);
  const escalated = applyAlertCandidates(warningRetry.alerts, [candidate("identity-a", "critical")], { now: "2026-10-06T00:00:32.000Z" });
  assert.deepEqual(escalated.notification_due_ids, ["alert_shared"]);
  const rollback = applyAlertCandidates([{ ...warningRetry.alerts[0], last_attempt_at: "2099-01-01T00:00:00.000Z", backoff_delay_ms: 3_600_000 }], [candidate("identity-a")], { now: "2026-10-06T00:00:33.000Z" });
  assert.deepEqual(rollback.notification_due_ids, ["alert_shared"]);
});

test("session churn and credential metadata changes carry distinct incident keys", () => {
  const [ab] = buildChurnCandidates([{ entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" }]);
  const [bc] = buildChurnCandidates([{ entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "2222222222222222", current_fingerprint: "3333333333333333" }]);
  assert.notEqual(ab.incident_key, bc.incident_key);
  const [credentialA] = buildCredentialAccessCandidates([{ category: "ssh_private_key", path_hash: "0123456789abcdef", trip_reason: "mtime_changed", change_identity: "aaaaaaaaaaaaaaaa" }]);
  const [credentialB] = buildCredentialAccessCandidates([{ category: "ssh_private_key", path_hash: "0123456789abcdef", trip_reason: "mtime_changed", change_identity: "bbbbbbbbbbbbbbbb" }]);
  assert.notEqual(credentialA.incident_key, credentialB.incident_key);
});
