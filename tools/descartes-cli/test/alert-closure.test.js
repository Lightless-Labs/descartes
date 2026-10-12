// Context plan C1.1 (§6.0, §6.1, CC3-E, CC7, I63, I73): `closed(reason)` status, closure never
// cancelling an undelivered incident, tombstones, storm exit/escalation, and the CC3-E recovery set.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  acknowledgeAlert,
  ALERT_CLOSURE_REASONS,
  applyAlertCandidates,
  confirmAlertDelivery,
  episodeRecoveryIncidentKeys,
  incidentDelivered,
  INCIDENT_STORM_KEY,
  MAX_INCIDENT_TOMBSTONES,
  MAX_LIVE_INCIDENTS,
  normalizeAlertRecord,
  readAlertRecords,
  recordAlertDeliveryFailure,
  recordAlertDeliveryOutcomes,
  requestAlertClosure,
  writeAlertRecords,
} from "../src/alert-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alert-closure-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const ID = "alert_closure0000001";

function candidate(key, severity = "warning", extra = {}) {
  return { id: ID, rule_id: "session.churn", fingerprint: "global", incident_key: key, severity, title: "Churn", summary: "s", diagnostics: {}, ...extra };
}

function t(minute) {
  return new Date(Date.UTC(2026, 9, 12, 0, minute)).toISOString();
}

async function deliveredAlert(paths, keys, severity = "warning", extra = {}) {
  const applied = applyAlertCandidates([], keys.map((key) => candidate(key, severity, extra)), { now: t(0) });
  await writeAlertRecords(paths, applied.alerts);
  for (const key of keys) await confirmAlertDelivery(paths, ID, { now: t(1), incidentKey: key });
  return (await readAlertRecords(paths))[0];
}

test("closed round-trips on alerts and incidents only with a valid reason; a malformed closure reads as active", () => {
  const base = { id: ID, rule_id: "session.churn", fingerprint: "global", first_seen: t(0), last_seen: t(0), episode_started_at: t(0) };
  const closed = normalizeAlertRecord({
    ...base,
    status: "closed",
    closed_reason: "label",
    closed_at: t(5),
    closed_by: { kind: "label", ref: "lbl-1" },
    incidents: { a: { status: "closed", closed_reason: "event_delivered", closed_at: t(4), severity_max: "warning", payload: {} } },
  });
  assert.equal(closed.status, "closed");
  assert.equal(closed.closed_reason, "label");
  assert.deepEqual(closed.closed_by, { kind: "label", ref: "lbl-1" });
  assert.equal(closed.incidents.a.status, "closed");
  assert.equal(closed.incidents.a.closed_reason, "event_delivered");
  const bogus = normalizeAlertRecord({
    ...base,
    status: "closed",
    closed_reason: "because",
    incidents: { a: { status: "closed", closed_reason: "nope", closed_at: t(4), severity_max: "warning", payload: {} } },
  });
  assert.equal(bogus.status, "active", "an unknown closure reason never hides the alert");
  assert.equal(bogus.incidents.a.status, "active");
  assert.deepEqual([...ALERT_CLOSURE_REASONS].sort(), ["admitted_earned", "admitted_unexplained", "event_delivered", "explained_context", "label", "replaced", "superseded"]);
});

test("label_closure_never_cancels_undelivered: a closure on an undelivered incident defers until delivery", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate("a")], { now: t(0) });
  assert.deepEqual(applied.notification_due_incidents, [{ alert_id: ID, incident_key: "a" }]);
  const request = requestAlertClosure(applied.alerts[0], { incidentKeys: ["a"], reason: "label", now: t(1), by: { kind: "label", ref: "lbl-1" }, closeAlert: true });
  assert.deepEqual(request.deferred, ["a"]);
  assert.deepEqual(request.closed, []);
  assert.equal(request.alert.incidents.a.status, "active");
  assert.equal(request.alert.status, "active");
  // Still due on the next tick: the request cancels nothing.
  const replay = applyAlertCandidates([request.alert], [candidate("a")], { now: t(2) });
  assert.deepEqual(replay.notification_due_incidents, [{ alert_id: ID, incident_key: "a" }]);
  await writeAlertRecords(paths, replay.alerts);
  await confirmAlertDelivery(paths, ID, { now: t(3), incidentKey: "a" });
  const [after] = await readAlertRecords(paths);
  assert.equal(after.incidents.a.status, "closed");
  assert.equal(after.incidents.a.closed_reason, "label");
  assert.equal(after.status, "closed", "the alert-level closure settles once nothing is live");
});

test("a deferred closure keeps a failed delivery in the retry scan", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate("a")], { now: t(0) });
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertDeliveryFailure(paths, ID, { now: t(0), incidentKey: "a", reason: "unavailable" });
  const [failed] = await readAlertRecords(paths);
  const request = requestAlertClosure(failed, { incidentKeys: ["a"], reason: "label", now: t(1) });
  assert.deepEqual(request.deferred, ["a"]);
  const retry = applyAlertCandidates([request.alert], [], { now: t(5), coveredAlertIds: new Set() });
  assert.deepEqual(retry.notification_due_incidents, [{ alert_id: ID, incident_key: "a" }]);
});

test("a closure applies immediately to a delivered incident, and the closed key never re-notifies at or below its severity", async () => {
  const paths = await tempPaths();
  const alert = await deliveredAlert(paths, ["a", "b"]);
  assert.equal(incidentDelivered(alert.incidents.a), true);
  const request = requestAlertClosure(alert, { incidentKeys: ["a"], reason: "label", now: t(2) });
  assert.deepEqual(request.closed, ["a"]);
  assert.equal(request.alert.incidents.a.status, "closed");
  assert.equal(request.alert.status, "active", "an incident closure alone leaves the alert open");
  const replay = applyAlertCandidates([request.alert], [candidate("a"), candidate("b")], { now: t(3) });
  assert.deepEqual(replay.notification_due_incidents, []);
  assert.equal(replay.alerts[0].incidents.a.status, "closed");
});

test("a closed key re-emitted at a higher severity re-opens and notifies (never silence an escalation)", async () => {
  const paths = await tempPaths();
  const alert = await deliveredAlert(paths, ["a"]);
  const closed = requestAlertClosure(alert, { reason: "label", now: t(2), closeAlert: true }).alert;
  assert.equal(closed.status, "closed");
  const escalated = applyAlertCandidates([closed], [candidate("a", "critical")], { now: t(3) });
  assert.deepEqual(escalated.notification_due_incidents, [{ alert_id: ID, incident_key: "a" }]);
  assert.equal(escalated.alerts[0].status, "active");
  assert.equal(escalated.alerts[0].incidents.a.status, "active");
  assert.equal(escalated.alerts[0].incidents.a.reopened_at, t(3));
});

test("a closed alert stays closed on re-emitted tombstones, re-arms on a new key, and recovers on a covered absence", async () => {
  const paths = await tempPaths();
  const alert = await deliveredAlert(paths, ["a"]);
  const closed = requestAlertClosure(alert, { reason: "label", now: t(2), closeAlert: true }).alert;
  const tombstoneOnly = applyAlertCandidates([closed], [candidate("a")], { now: t(3) });
  assert.equal(tombstoneOnly.alerts[0].status, "closed");
  assert.deepEqual(tombstoneOnly.notification_due_incidents, []);
  const absent = applyAlertCandidates([closed], [], { now: t(4) });
  assert.equal(absent.alerts[0].status, "recovered", "a covered absence ends a closed alert like any other: the next recurrence is a new episode");
  const uncovered = applyAlertCandidates([closed], [], { now: t(4), coveredAlertIds: new Set() });
  assert.equal(uncovered.alerts[0].status, "closed", "without coverage nothing is recovered");
  const rearmed = applyAlertCandidates([closed], [candidate("a"), candidate("b")], { now: t(5) });
  assert.equal(rearmed.alerts[0].status, "active");
  assert.equal(rearmed.alerts[0].episode_started_at, t(5), "a closed alert re-arms with a new episode");
  assert.deepEqual(rearmed.notification_due_incidents, [{ alert_id: ID, incident_key: "b" }]);
  assert.equal(rearmed.alerts[0].incidents.a.status, "closed", "tombstones carry over into the new episode");
  await writeAlertRecords(paths, [closed]);
  const acked = await acknowledgeAlert(paths, ID, { now: t(6) });
  assert.equal(acked.status, "closed", "acknowledgement never re-opens a closure");
});

// Adversarial review B1: a whole-alert closure must never be absorbing. Default-keyed rules capped at
// warning (service.disappeared, service.appeared, scheduled_job.appeared, process.lineage.novel_edge)
// can neither present a new key nor a higher severity, so only a covered absence can end the closure.
test("a closed alert recovers on a covered absence and every later recurrence notifies (closure is never absorbing)", async () => {
  const SVC = "alert_5e7c000000000001";
  const svc = () => ({ id: SVC, rule_id: "service.disappeared", fingerprint: "abcdef0123456789", severity: "warning", title: "Service disappeared", summary: "s", diagnostics: {} });
  const covered = new Set([SVC]);
  const paths = await tempPaths();
  const raised = applyAlertCandidates([], [svc()], { now: t(0), coveredAlertIds: covered });
  assert.deepEqual(raised.notification_due_incidents.map((entry) => entry.incident_key), ["default"]);
  await writeAlertRecords(paths, raised.alerts);
  await confirmAlertDelivery(paths, SVC, { now: t(1), incidentKey: "default" });
  const closed = requestAlertClosure((await readAlertRecords(paths))[0], { reason: "label", now: t(2), closeAlert: true }).alert;
  assert.equal(closed.status, "closed");
  let current = applyAlertCandidates([closed], [], { now: t(5), coveredAlertIds: covered }).alerts;
  assert.equal(current[0].status, "recovered");
  assert.equal(current[0].close_requested, null, "no alert-level closure request rides into the next episode");
  for (const minute of [10 * 24 * 60, 40 * 24 * 60]) {
    const recurrence = applyAlertCandidates(current, [svc()], { now: t(minute), coveredAlertIds: covered });
    assert.deepEqual(recurrence.notification_due_incidents.map((entry) => entry.incident_key), ["default"], "every recurrence after a covered absence notifies");
    assert.equal(recurrence.alerts[0].status, "active");
    current = applyAlertCandidates(recurrence.alerts, [], { now: t(minute + 5), coveredAlertIds: covered }).alerts;
  }
});

test("event_incident_closes_on_delivery: a producer-declared close-on-delivery incident closes once delivered; the alert stays active", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate("ev-1", "warning", { close_on_delivery: true })], { now: t(0) });
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertDeliveryOutcomes(paths, [{ alertId: ID, incidentKey: "ev-1", status: "success" }], { now: t(1) });
  const [after] = await readAlertRecords(paths);
  assert.equal(after.incidents["ev-1"].status, "closed");
  assert.equal(after.incidents["ev-1"].closed_reason, "event_delivered");
  assert.equal(after.status, "active", "delivery closure is bookkeeping; the EVENT alert stays open");
  const replay = applyAlertCandidates([after], [candidate("ev-1", "warning", { close_on_delivery: true })], { now: t(2) });
  assert.deepEqual(replay.notification_due_incidents, [], "a re-emitted delivered key does not re-notify");
});

test("cc_e_delivered_incident_quiet_interval_no_clear: delivered EVENT incidents stay in the recovery set; no report, no recovery", async () => {
  const paths = await tempPaths();
  const applied = applyAlertCandidates([], [candidate("dep-1", "warning", { close_on_delivery: true })], { now: t(0) });
  await writeAlertRecords(paths, applied.alerts);
  await confirmAlertDelivery(paths, ID, { now: t(1), incidentKey: "dep-1" });
  const [delivered] = await readAlertRecords(paths);
  assert.equal(delivered.incidents["dep-1"].status, "closed");
  assert.deepEqual(episodeRecoveryIncidentKeys(delivered), ["dep-1"], "the delivered incident is still in the authoritative recovery set");
  // A quiet interval: the producer emits nothing and does NOT report the alert evaluated.
  const quiet = applyAlertCandidates([delivered], [], { now: t(2), coveredAlertIds: new Set() });
  assert.equal(quiet.alerts[0].status, "active", "a closed-by-delivery episode is not vacuously recovered");
  // A label closure is not part of the recovery set.
  const labelled = requestAlertClosure(normalizeAlertRecord({ ...delivered, incidents: { ...delivered.incidents, other: { ...delivered.incidents["dep-1"], status: "active", closed_reason: null, closed_at: null } } }), { incidentKeys: ["other"], reason: "label", now: t(3) }).alert;
  assert.deepEqual(episodeRecoveryIncidentKeys(labelled), ["dep-1"]);
});

test("closed incidents leave the live cap: closures free capacity without a storm", async () => {
  const keys = Array.from({ length: MAX_LIVE_INCIDENTS }, (_, index) => `k-${index}`);
  let applied = applyAlertCandidates([], keys.map((key) => candidate(key)), { now: t(0) });
  let [alert] = applied.alerts;
  // Mark all delivered, then close them by label.
  alert = normalizeAlertRecord({ ...alert, incidents: Object.fromEntries(Object.entries(alert.incidents).map(([key, incident]) => [key, { ...incident, confirmed_at: t(1), notified_severity: "warning" }])) });
  alert = requestAlertClosure(alert, { reason: "label", now: t(2) }).alert;
  applied = applyAlertCandidates([alert], [candidate("fresh")], { now: t(3) });
  assert.equal(applied.alerts[0].incident_state, "normal");
  assert.deepEqual(applied.notification_due_incidents, [{ alert_id: ID, incident_key: "fresh" }]);
});

test("storm_escalation_notifies: a storm never swallows a severity escalation of an existing incident", async () => {
  const paths = await tempPaths();
  const keys = Array.from({ length: MAX_LIVE_INCIDENTS }, (_, index) => `k-${index}`);
  const first = applyAlertCandidates([], keys.map((key) => candidate(key)), { now: t(0) });
  await writeAlertRecords(paths, first.alerts);
  for (const key of keys.slice(0, 3)) await confirmAlertDelivery(paths, ID, { now: t(1), incidentKey: key });
  const storm = applyAlertCandidates(await readAlertRecords(paths), [...keys.map((key) => candidate(key)), candidate("overflow")], { now: t(2) });
  assert.equal(storm.alerts[0].incident_state, "incident_storm");
  assert.deepEqual(storm.notification_due_incidents.map((entry) => entry.incident_key), [INCIDENT_STORM_KEY]);
  const escalation = applyAlertCandidates(storm.alerts, [candidate("k-0", "critical"), candidate("overflow")], { now: t(3) });
  assert.equal(escalation.alerts[0].incident_state, "incident_storm");
  assert.deepEqual(escalation.notification_due_incidents.map((entry) => entry.incident_key).sort(), [INCIDENT_STORM_KEY, "k-0"].sort());
  // A failed escalation delivery is retried inside the storm.
  await writeAlertRecords(paths, escalation.alerts);
  await recordAlertDeliveryFailure(paths, ID, { now: t(3), incidentKey: "k-0", reason: "unavailable" });
  const retry = applyAlertCandidates(await readAlertRecords(paths), [], { now: t(10), coveredAlertIds: new Set() });
  assert.ok(retry.notification_due_incidents.some((entry) => entry.incident_key === "k-0"));
});

test("storm_exits_below_cap: the storm exits once live incidents fall below the cap with no overflow; covered incidents stay quiet", async () => {
  const paths = await tempPaths();
  const keys = Array.from({ length: MAX_LIVE_INCIDENTS }, (_, index) => `k-${index}`);
  const storm = applyAlertCandidates([], [...keys, "overflow"].map((key) => candidate(key)), { now: t(0) });
  assert.equal(storm.alerts[0].incident_state, "incident_storm");
  await writeAlertRecords(paths, storm.alerts);
  await confirmAlertDelivery(paths, ID, { now: t(1), incidentKey: INCIDENT_STORM_KEY });
  // Ten incidents were individually delivered earlier and are now closed by a label.
  let [alert] = await readAlertRecords(paths);
  alert = normalizeAlertRecord({ ...alert, incidents: Object.fromEntries(Object.entries(alert.incidents).map(([key, incident]) => [key, Number(key.slice(2)) < 10 ? { ...incident, confirmed_at: t(1), notified_severity: "warning" } : incident])) });
  alert = requestAlertClosure(alert, { incidentKeys: keys.slice(0, 10), reason: "label", now: t(2) }).alert;
  const exited = applyAlertCandidates([alert], [candidate("k-20"), candidate("brand-new")], { now: t(3) });
  assert.equal(exited.alerts[0].incident_state, "normal");
  assert.deepEqual(exited.notification_due_incidents, [{ alert_id: ID, incident_key: "brand-new" }], "storm-covered incidents stay quiet; a genuinely new one notifies");
  assert.equal(exited.alerts[0].incidents["k-20"].storm_covered_at, t(1));
  const escalated = applyAlertCandidates(exited.alerts, [candidate("k-20", "critical")], { now: t(4) });
  assert.deepEqual(escalated.notification_due_incidents, [{ alert_id: ID, incident_key: "k-20" }]);
});

// Adversarial review H2: an incident that joined a storm after its notification was delivered is not
// covered by it; on storm exit it must become due even when the exit tick does not re-emit it.
test("storm exit makes every live, undelivered, uncovered incident due, not only the keys re-emitted on the exit tick", async () => {
  const paths = await tempPaths();
  const covered = new Set();
  const keys = Array.from({ length: MAX_LIVE_INCIDENTS }, (_, index) => `k${index}`);
  let applied = applyAlertCandidates([], keys.map((key) => candidate(key)), { now: t(0), coveredAlertIds: covered });
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertDeliveryOutcomes(paths, applied.notification_due_incidents.map((entry) => ({ alertId: entry.alert_id, incidentKey: entry.incident_key, status: "success" })), { now: t(1) });
  applied = applyAlertCandidates(await readAlertRecords(paths), [candidate("overflow1")], { now: t(2), coveredAlertIds: covered });
  assert.equal(applied.alerts[0].incident_state, "incident_storm");
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertDeliveryOutcomes(paths, applied.notification_due_incidents.map((entry) => ({ alertId: entry.alert_id, incidentKey: entry.incident_key, status: "success" })), { now: t(3) });
  const freed = requestAlertClosure((await readAlertRecords(paths))[0], { incidentKeys: ["k0", "k1"], reason: "label", now: t(4) });
  assert.deepEqual(freed.closed, ["k0", "k1"]);
  // "late" joins under the cap while other keys overflow: the storm continues, nothing individual is due.
  applied = applyAlertCandidates([freed.alert], [candidate("late"), candidate("zz-overflow2"), candidate("zz-overflow3")], { now: t(5), coveredAlertIds: covered });
  assert.equal(applied.alerts[0].incident_state, "incident_storm");
  assert.equal(applied.alerts[0].incidents.late.status, "active");
  const freedAgain = requestAlertClosure(applied.alerts[0], { incidentKeys: ["k2", "k3", "k4"], reason: "label", now: t(5) });
  // The exit tick re-emits only k5 (delivered long ago).
  const exited = applyAlertCandidates([freedAgain.alert], [candidate("k5")], { now: t(6), coveredAlertIds: covered });
  assert.equal(exited.alerts[0].incident_state, "normal");
  assert.equal(exited.alerts[0].incidents.late.storm_covered_at ?? null, null, "late post-dates the storm notification: never covered by it");
  // zz-overflow2 also took a freed slot after the storm notification; zz-overflow3 overflowed (never admitted).
  assert.deepEqual(exited.notification_due_incidents, [{ alert_id: ID, incident_key: "late" }, { alert_id: ID, incident_key: "zz-overflow2" }], "the post-notification incidents are due on the exit tick; nothing delivered or covered is re-notified");
  assert.ok(exited.adjudication_due_incidents.some((entry) => entry.incident_key === "late"));
  // A failed attempt is then retried by the retry scan even though "late" is never re-emitted.
  await writeAlertRecords(paths, exited.alerts);
  await recordAlertDeliveryFailure(paths, ID, { now: t(6), incidentKey: "late", reason: "unavailable" });
  await confirmAlertDelivery(paths, ID, { now: t(6), incidentKey: "zz-overflow2" });
  const retried = applyAlertCandidates(await readAlertRecords(paths), [candidate("k5")], { now: t(90), coveredAlertIds: covered });
  assert.deepEqual(retried.notification_due_incidents, [{ alert_id: ID, incident_key: "late" }]);
});

test("tombstone_cap_visible: tombstones are bounded per alert and drops are counted", () => {
  const incidents = {};
  for (let index = 0; index < MAX_INCIDENT_TOMBSTONES + 3; index += 1) {
    incidents[`c-${String(index).padStart(5, "0")}`] = { status: "closed", closed_reason: "event_delivered", closed_at: new Date(Date.UTC(2026, 9, 1, 0, 0, index)).toISOString(), severity_max: "warning", confirmed_at: t(0), notified_severity: "warning", payload: {} };
  }
  incidents.live = { status: "active", severity_max: "warning", payload: {}, first_seen: t(0), last_seen: t(0) };
  const alert = normalizeAlertRecord({ id: ID, rule_id: "session.churn", fingerprint: "global", first_seen: t(0), last_seen: t(0), episode_started_at: t(0), incidents });
  const applied = applyAlertCandidates([alert], [candidate("live")], { now: t(1) });
  const after = applied.alerts[0];
  assert.equal(Object.values(after.incidents).filter((incident) => incident.status === "closed").length, MAX_INCIDENT_TOMBSTONES);
  assert.equal(after.tombstones_dropped_total, 3);
  assert.equal(after.incidents["c-00000"], undefined, "the oldest closure is dropped first");
});

test("storm_escalation_notifies: an escalation of a never-delivered incident whose delivery failed is retried inside the storm and never covered", async () => {
  const paths = await tempPaths();
  const keys = Array.from({ length: MAX_LIVE_INCIDENTS }, (_, index) => `k-${index}`);
  const storm = applyAlertCandidates([], [...keys, "overflow"].map((key) => candidate(key)), { now: t(0) });
  assert.equal(storm.alerts[0].incident_state, "incident_storm");
  await writeAlertRecords(paths, storm.alerts);
  await confirmAlertDelivery(paths, ID, { now: t(1), incidentKey: INCIDENT_STORM_KEY });
  const escalated = applyAlertCandidates(await readAlertRecords(paths), [candidate("k-0", "critical"), candidate("overflow")], { now: t(2) });
  assert.ok(escalated.notification_due_incidents.some((entry) => entry.incident_key === "k-0"));
  await writeAlertRecords(paths, escalated.alerts);
  await recordAlertDeliveryFailure(paths, ID, { now: t(2), incidentKey: "k-0", reason: "unavailable" });
  const reemitted = applyAlertCandidates(await readAlertRecords(paths), [candidate("k-0", "critical"), candidate("overflow")], { now: t(10) });
  assert.ok(reemitted.notification_due_incidents.some((entry) => entry.incident_key === "k-0"), "re-emitted after backoff, still due inside the storm");
  const scanned = applyAlertCandidates(await readAlertRecords(paths), [], { now: t(10), coveredAlertIds: new Set() });
  assert.ok(scanned.notification_due_incidents.some((entry) => entry.incident_key === "k-0"), "the retry scan finds it inside the storm");
  // Storm exit: a label closes ten delivered incidents; k-0's escalation is not covered.
  let [alert] = await readAlertRecords(paths);
  alert = normalizeAlertRecord({ ...alert, incidents: Object.fromEntries(Object.entries(alert.incidents).map(([key, incident]) => [key, ["k-1", "k-2", "k-3", "k-4", "k-5", "k-6", "k-7", "k-8", "k-9", "k-10"].includes(key) ? { ...incident, confirmed_at: t(1), notified_severity: "warning" } : incident])) });
  alert = requestAlertClosure(alert, { incidentKeys: ["k-1", "k-2", "k-3", "k-4", "k-5", "k-6", "k-7", "k-8", "k-9", "k-10"], reason: "label", now: t(11) }).alert;
  const exited = applyAlertCandidates([alert], [candidate("k-0", "critical")], { now: t(20) });
  assert.equal(exited.alerts[0].incident_state, "normal");
  assert.equal(exited.alerts[0].incidents["k-0"].storm_covered_at, null);
  assert.ok(exited.notification_due_incidents.some((entry) => entry.incident_key === "k-0"));
});
