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
import { emitMetricAlertFallbackSignals } from "../src/alert-intelligence.js";
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
  await writeAlertRecords(paths, first.alerts);
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:01:00.000Z", incidentKey: "identity-a", episodeKey: "identity-b" });

  const second = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-a"), candidate("identity-b")], { now: "2026-10-06T00:02:00.000Z" });
  assert.deepEqual(second.notification_due_ids, ["alert_shared"], "identity B remains due after identity A is confirmed");
  await writeAlertRecords(paths, second.alerts);
  await confirmAlertDelivery(paths, "alert_shared", { now: "2026-10-06T00:03:00.000Z", incidentKey: "identity-b", episodeKey: "identity-b" });
  const quiet = applyAlertCandidates(await readAlertRecords(paths), [candidate("identity-b"), candidate("identity-a")], { now: "2026-10-06T00:04:00.000Z" });
  assert.deepEqual(quiet.notification_due_ids, []);
  assert.deepEqual((quiet.alerts[0].notified_incident_keys ?? []).sort(), ["identity-a", "identity-b"]);
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
