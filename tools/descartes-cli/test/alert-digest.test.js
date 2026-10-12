// Context plan C1.5 (§12, I75): the digest.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { applyAlertCandidates, confirmAlertDelivery, MAX_LIVE_INCIDENTS, readAlertRecords, writeAlertRecords } from "../src/alert-store.js";
import { appendAlertLabel, ingestAlertLabels } from "../src/alert-labels.js";
import { recordAlertTransitions } from "../src/alert-transitions.js";
import { buildAlertDigest, DIGEST_PERIOD_MS, DIGEST_RULE_ID, maybeSendAlertDigest, renderAlertDigest, resolveAlertDigestPaths } from "../src/alert-digest.js";
import { runAlerts } from "../src/alerts.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alert-digest-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const T0 = Date.UTC(2026, 9, 12);
const HOUR = 60 * 60 * 1000;
function iso(ms) {
  return new Date(T0 + ms).toISOString();
}
const EVENT_ID = "alert_e000000000000001";
const LEVEL_ID = "alert_1000000000000001";

async function apply(paths, candidates, at) {
  const applied = applyAlertCandidates(await readAlertRecords(paths), candidates, { now: iso(at) });
  await writeAlertRecords(paths, applied.alerts);
  for (const entry of applied.notification_due_incidents) await confirmAlertDelivery(paths, entry.alert_id, { now: iso(at + 1), incidentKey: entry.incident_key });
  await recordAlertTransitions(paths, { now: iso(at + 2) });
}

test("digest_lists_every_closure_and_label, open EVENT alerts and open LEVEL episodes with their running extreme", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: iso(0) });
  await apply(paths, [
    { id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k1", severity: "warning", title: "t", summary: "s", diagnostics: {} },
    { id: LEVEL_ID, rule_id: "peer.count_drop", fingerprint: "f", incident_key: "lvl:r:4", severity: "warning", title: "t", summary: "s", diagnostics: {} },
  ], 1000);
  await apply(paths, [
    { id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k2", severity: "warning", title: "t", summary: "s", diagnostics: {} },
    { id: LEVEL_ID, rule_id: "peer.count_drop", fingerprint: "f", incident_key: "lvl:r:0", severity: "warning", title: "t", summary: "s", diagnostics: {} },
  ], HOUR);
  const label = await appendAlertLabel(paths, { label: "expected", scope: { kind: "alert", alert_id: EVENT_ID, incident_keys: ["k1"] }, now: iso(2 * HOUR) });
  const ingested = await ingestAlertLabels(paths, { now: iso(2 * HOUR + 1) });
  await recordAlertTransitions(paths, { now: iso(2 * HOUR + 2), extraRecords: ingested.audit });
  const digest = await buildAlertDigest(paths, { now: iso(3 * HOUR), since: iso(0) });
  assert.equal(digest.empty, false);
  assert.equal(digest.closures.length, 1);
  assert.deepEqual(digest.closures[0].source, { kind: "label", ref: label.id });
  assert.equal(digest.labels.ingested[0].label_id, label.id);
  assert.deepEqual(digest.open_event_alerts.map((entry) => entry.alert_id), [EVENT_ID]);
  assert.equal(digest.open_level_episodes[0].alert_id, LEVEL_ID);
  assert.equal(digest.open_level_episodes[0].running_extreme, 0);
  assert.match(renderAlertDigest(digest), /closed alert_e000000000000001\/k1 \(label, label /);
});

test("digest_pushed_not_throttled: one push per period, only when not empty; the first run starts the clock", async () => {
  const paths = await tempPaths();
  const pushes = [];
  const deliverNotification = async (_paths, decision, meta) => {
    pushes.push({ decision, meta });
    return { status: "cli_only" };
  };
  assert.equal((await maybeSendAlertDigest(paths, { now: iso(0), deliverNotification })).status, "started");
  assert.equal((await maybeSendAlertDigest(paths, { now: iso(HOUR), deliverNotification })).status, "not_due");
  assert.equal((await maybeSendAlertDigest(paths, { now: iso(DIGEST_PERIOD_MS), deliverNotification })).status, "empty", "an empty period pushes nothing");
  assert.equal(pushes.length, 0);
  await apply(paths, [{ id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k1", severity: "warning", title: "t", summary: "s", diagnostics: {} }], DIGEST_PERIOD_MS + HOUR);
  const sent = await maybeSendAlertDigest(paths, { now: iso(2 * DIGEST_PERIOD_MS), deliverNotification });
  assert.equal(sent.status, "sent");
  assert.equal(pushes.length, 1);
  assert.equal(pushes[0].meta.ruleId, DIGEST_RULE_ID);
  assert.ok(pushes[0].decision.body.length <= 240);
  const files = await fs.readdir(resolveAlertDigestPaths(paths).digestsDir);
  assert.equal(files.length, 1);
});

test("a failed digest push is retried, never dropped", async () => {
  const paths = await tempPaths();
  await maybeSendAlertDigest(paths, { now: iso(0) });
  await apply(paths, [{ id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k1", severity: "warning", title: "t", summary: "s", diagnostics: {} }], HOUR);
  const failing = async () => ({ status: "error", error: "spawn failed" });
  assert.equal((await maybeSendAlertDigest(paths, { now: iso(DIGEST_PERIOD_MS), deliverNotification: failing })).status, "delivery_failed");
  assert.equal((await maybeSendAlertDigest(paths, { now: iso(DIGEST_PERIOD_MS + 60_000), deliverNotification: failing })).status, "retry_pending");
  const ok = await maybeSendAlertDigest(paths, { now: iso(DIGEST_PERIOD_MS + 2 * HOUR), deliverNotification: async () => ({ status: "cli_only" }) });
  assert.equal(ok.status, "sent");
});

test("disabled_digest_stays_pending_and_period_does_not_advance", async () => {
  const paths = await tempPaths();
  await maybeSendAlertDigest(paths, { now: iso(0) });
  await apply(paths, [{ id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k1", severity: "warning", title: "t", summary: "s", diagnostics: {} }], HOUR);
  const result = await maybeSendAlertDigest(paths, { now: iso(DIGEST_PERIOD_MS), deliverNotification: async () => ({ status: "disabled" }) });
  assert.equal(result.status, "delivery_pending");
  const state = JSON.parse(await fs.readFile(resolveAlertDigestPaths(paths).stateFile, "utf8"));
  assert.equal(state.last_period_end, iso(0));
  const { readPendingNotifications } = await import("../src/notification-delivery.js");
  assert.equal((await readPendingNotifications(paths)).pending.length, 1);
});

test("storm_listed_in_digest with its count", async () => {
  const paths = await tempPaths();
  await recordAlertTransitions(paths, { now: iso(0) });
  const flood = Array.from({ length: MAX_LIVE_INCIDENTS + 1 }, (_, index) => ({ id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: `k${index}`, severity: "warning", title: "t", summary: "s", diagnostics: {} }));
  const applied = applyAlertCandidates([], flood, { now: iso(1000) });
  await writeAlertRecords(paths, applied.alerts);
  await recordAlertTransitions(paths, { now: iso(2000) });
  const digest = await buildAlertDigest(paths, { now: iso(HOUR), since: iso(0) });
  assert.equal(digest.storms.active[0].incident_count, MAX_LIVE_INCIDENTS + 1);
  assert.equal(digest.storms.entered.length, 1);
});

test("alerts digest CLI is read-only", async () => {
  const paths = await tempPaths();
  await apply(paths, [{ id: EVENT_ID, rule_id: "session.churn", fingerprint: "f", incident_key: "k1", severity: "warning", title: "t", summary: "s", diagnostics: {} }], 1000);
  const out = [];
  await runAlerts(paths, ["digest", "--json"], { output: (line) => out.push(line), now: iso(HOUR) });
  assert.equal(JSON.parse(out[0]).digest.open_event_alerts.length, 1);
  await assert.rejects(fs.access(resolveAlertDigestPaths(paths).stateFile));
});
