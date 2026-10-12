// Context plan C1.3 (§9, I27, I62; open item 15): the optional label log, daemon ingestion, the
// coverage-charged label budget and the label-poisoning bound.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { applyAlertCandidates, confirmAlertDelivery, readAlertRecords, resolveAlertStorePaths, writeAlertRecords } from "../src/alert-store.js";
import { appendAlertLabel, ingestAlertLabels, LABEL_BUDGET_UNITS, normalizeLabelRecord, readAlertLabels } from "../src/alert-labels.js";
import { runAlerts } from "../src/alerts.js";
import { createFactIntegrityLedger } from "../src/fact-store-integrity.js";
import { appendPendingEntries, inspectPendingJournal, openPendingJournal, pendingItemId } from "../src/pending-journal.js";
import { resolveDescartesPaths } from "../src/paths.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alert-labels-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_STATE_HOME: path.join(root, "state"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const EVENT_ID = "alert_e000000000000001";
const LEVEL_ID = "alert_1000000000000001";
const NOVELTY_ID = "alert_a000000000000001";
const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.UTC(2026, 9, 12);
function iso(ms) {
  return new Date(T0 + ms).toISOString();
}
function candidate(id, ruleId, key, severity = "warning") {
  return { id, rule_id: ruleId, fingerprint: "f", incident_key: key, severity, title: "t", summary: "s", diagnostics: {} };
}

async function seed(paths, candidates, { deliver = true } = {}) {
  const applied = applyAlertCandidates(await readAlertRecords(paths), candidates, { now: iso(0) });
  await writeAlertRecords(paths, applied.alerts);
  if (deliver) for (const entry of applied.notification_due_incidents) await confirmAlertDelivery(paths, entry.alert_id, { now: iso(1000), incidentKey: entry.incident_key });
}

test("label records are strictly validated: no free text, closed label set, well-formed scope", () => {
  const base = { v: 1, id: "123e4567-e89b-12d3-a456-426614174000", ts: iso(0), label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, note: "drop me", source: { kind: "cli", uid: 501 } };
  const normalized = normalizeLabelRecord(base);
  assert.equal(normalized.note, undefined);
  assert.deepEqual(normalized.scope, { kind: "alert", alert_id: EVENT_ID });
  assert.equal(normalizeLabelRecord({ ...base, label: "fine" }), null);
  assert.equal(normalizeLabelRecord({ ...base, scope: { kind: "alert", alert_id: "not-an-alert" } }), null);
  assert.equal(normalizeLabelRecord({ ...base, scope: { kind: "alert", alert_id: EVENT_ID, incident_keys: ["bad key!"] } }), null);
  assert.equal(normalizeLabelRecord({ ...base, scope: { kind: "pending_window", family: "canary", from_ts: iso(0), to_ts: iso(1) } }), null, "only journaled families");
});

test("the CLI only appends to the label log: alerts.json is byte-unchanged; an unknown alert id is refused", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")]);
  const before = await fs.readFile(resolveAlertStorePaths(paths).alertsFile, "utf8");
  const out = [];
  await runAlerts(paths, ["label", EVENT_ID, "benign", "--incident", "k1", "--json"], { output: (line) => out.push(line) });
  assert.equal(JSON.parse(out[0]).label.label, "benign");
  assert.equal(await fs.readFile(resolveAlertStorePaths(paths).alertsFile, "utf8"), before);
  assert.equal((await readAlertLabels(paths)).labels.length, 1);
  await assert.rejects(runAlerts(paths, ["label", "alert_ffffffffffffffff", "benign"], { output: () => {} }), /Alert not found/);
});

test("label_ingested_once_by_daemon and label_notified_on_ingest: an EVENT label closes the delivered episode once", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1"), candidate(EVENT_ID, "session.churn", "k2")]);
  const label = await appendAlertLabel(paths, { label: "expected", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  const first = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(first.ingested.length, 1);
  assert.equal(first.ingested[0].closed, 2);
  assert.equal(first.notice.title, "Descartes: labels ingested");
  const ingestedRecord = first.audit.find((record) => record.kind === "label_ingested");
  assert.equal(ingestedRecord.label_id, label.id);
  assert.ok(first.audit.some((record) => record.kind === "pending_journal_created" && record.family === "session"), "a journal the ingestion creates is witnessed");
  const [alert] = await readAlertRecords(paths);
  assert.equal(alert.status, "closed");
  assert.equal(alert.incidents.k1.closed_by.ref, label.id, "every closure names its label");
  const second = await ingestAlertLabels(paths, { now: iso(4000) });
  assert.equal(second.ingested.length, 0);
  assert.equal(second.notice, undefined);
});

test("label_closure_never_cancels_undelivered: a label on an undelivered incident waits for delivery", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")], { deliver: false });
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.ingested[0].deferred, 1);
  const [pending] = await readAlertRecords(paths);
  assert.equal(pending.incidents.k1.status, "active");
  const replay = applyAlertCandidates([pending], [candidate(EVENT_ID, "session.churn", "k1")], { now: iso(4000) });
  assert.deepEqual(replay.notification_due_incidents, [{ alert_id: EVENT_ID, incident_key: "k1" }], "the notification is still due");
  await writeAlertRecords(paths, replay.alerts);
  await confirmAlertDelivery(paths, EVENT_ID, { now: iso(5000), incidentKey: "k1" });
  assert.equal((await readAlertRecords(paths))[0].incidents.k1.status, "closed");
});

test("label_quarantine_keeps_present_condition_active: LEVEL never closes; a quarantined NOVELTY stays active; benign NOVELTY closes", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(LEVEL_ID, "session.count_drop", "lvl:r:2"), candidate(NOVELTY_ID, "service.appeared", "svc")]);
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: LEVEL_ID }, now: iso(2000) });
  await appendAlertLabel(paths, { label: "suspicious", scope: { kind: "alert", alert_id: NOVELTY_ID }, now: iso(2001) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.deepEqual(report.ingested.map((entry) => entry.effect), ["level_episode_stays_open", "present_condition_stays_open"]);
  for (const alert of await readAlertRecords(paths)) assert.equal(alert.status, "active");
  await appendAlertLabel(paths, { label: "mine", scope: { kind: "alert", alert_id: NOVELTY_ID }, now: iso(4000) });
  await ingestAlertLabels(paths, { now: iso(5000) });
  assert.equal((await readAlertRecords(paths)).find((alert) => alert.id === NOVELTY_ID).status, "closed");
});

test("missed_incident admits and closes nothing (recall only)", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")]);
  await appendAlertLabel(paths, { label: "missed_incident", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.ingested[0].effect, "recall_only");
  assert.equal((await readAlertRecords(paths))[0].status, "active");
});

test("label_burst_held_pending (item 15): the budget charges coverage; a bulk label is held whole and released when it fits", async () => {
  const paths = await tempPaths();
  const keys = Array.from({ length: 30 }, (_, index) => `k${index}`);
  await seed(paths, [
    ...keys.map((key) => candidate(EVENT_ID, "session.churn", key)),
    ...keys.map((key) => candidate("alert_e000000000000002", "session.churn", key)),
  ]);
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: "alert_e000000000000002" }, now: iso(2001) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.ingested.length, 1);
  assert.equal(report.ingested[0].charge, 30, "one label covering 30 incidents costs 30, not 1");
  assert.equal(report.held.length, 1);
  assert.equal(report.held[0].charge, 30);
  assert.equal(report.notice.title, "Descartes: label budget exceeded");
  const second = (await readAlertRecords(paths)).find((alert) => alert.id === "alert_e000000000000002");
  assert.equal(Object.values(second.incidents).every((incident) => incident.status === "active"), true, "a held label is never partially applied");
  const stillHeld = await ingestAlertLabels(paths, { now: iso(DAY) });
  assert.equal(stillHeld.ingested.length, 0);
  const released = await ingestAlertLabels(paths, { now: iso(8 * DAY) });
  assert.deepEqual(released.released.length, 1);
  assert.equal((await readAlertRecords(paths)).find((alert) => alert.id === "alert_e000000000000002").status, "closed");
});

test("label_log_tamper_bounded_by_label_budget: a forged flood applies at most the budget's coverage", async () => {
  const paths = await tempPaths();
  const ids = Array.from({ length: 80 }, (_, index) => `alert_e0000000000${String(index).padStart(5, "0")}`.slice(0, 22));
  await seed(paths, ids.map((id) => candidate(id, "session.churn", "k")));
  for (const id of ids) await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: id }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.ingested.length, LABEL_BUDGET_UNITS);
  assert.equal(report.held.length, 80 - LABEL_BUDGET_UNITS);
  assert.equal((await readAlertRecords(paths)).filter((alert) => alert.status === "closed").length, LABEL_BUDGET_UNITS);
});

test("a quarantining label quarantines the alert's pending journal items; an admissible one only marks them", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(LEVEL_ID, "session.count_drop", "lvl:r:2")]);
  const ledger = createFactIntegrityLedger();
  ledger.continuity = { ...ledger.continuity, last_committed_pass_id: 1, continuity_ok: true, pending_pass: null };
  const handle = await openPendingJournal(paths, "session", { ledger, now: iso(0) });
  const item = { alert_id: LEVEL_ID, episode: iso(0), incident_key: "lvl:r:2" };
  await appendPendingEntries(paths, handle, [{ kind: "opened", item, item_id: pendingItemId(item), scored_pass_id: 1 }], { ledger, now: iso(0) });
  await appendAlertLabel(paths, { label: "confirmed_incident", scope: { kind: "alert", alert_id: LEVEL_ID }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000), handles: { session: handle } });
  assert.equal(report.ingested[0].journal, 1);
  const inspected = await inspectPendingJournal(paths, "session", { ledger });
  assert.equal(inspected.state.items[pendingItemId(item)].state, "quarantined");
  assert.equal((await readAlertRecords(paths))[0].status, "active", "the LEVEL episode itself stays open");
});

test("an epoch opened by label ingestion (no pre-pass handle) is audited and re-certifies at the next clean pass", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(LEVEL_ID, "session.count_drop", "lvl:r:2")]);
  const ledgerAt = (pass) => {
    const ledger = createFactIntegrityLedger();
    ledger.generation = "gen-a";
    ledger.continuity = { ...ledger.continuity, last_committed_pass_id: pass, continuity_ok: true, pending_pass: null };
    return ledger;
  };
  const { journalCommittedPass, resolvePendingJournalPaths } = await import("../src/pending-journal.js");
  const passResult = (pass) => ({ written_count: 2, retention: { pass_id: pass, ledger_generation: "gen-a", pass_time_ms: T0 + pass * 1000 } });
  await journalCommittedPass(paths, "session", { passResult: passResult(1), ledger: ledgerAt(1), ts: iso(1000) });
  const { journalFile } = resolvePendingJournalPaths(paths, "session");
  await fs.writeFile(journalFile, `${(await fs.readFile(journalFile, "utf8")).replace("pass_committed", "pass_tampered")}`);
  await appendAlertLabel(paths, { label: "confirmed_incident", scope: { kind: "alert", alert_id: LEVEL_ID }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.discontinuities.length, 1);
  assert.ok(report.audit.some((record) => record.kind === "pending_discontinuity" && record.family === "session" && record.opened_by === "label_ingestion"));
  const { report: next } = await journalCommittedPass(paths, "session", { passResult: passResult(2), ledger: ledgerAt(2), ts: iso(4000) });
  assert.equal(next.recertified, report.discontinuities[0].epoch, "the label-opened epoch is not suspended forever");
});

// Adversarial review M1: deleting (or emptying) labels.state.json must not reset the label budget or
// re-ingest labels: consumption is rebuilt from the transition log's chained label_ingested records.
import { recordAlertTransitions } from "../src/alert-transitions.js";
import { resolveAlertLabelPaths } from "../src/alert-labels.js";

async function daemonIngest(paths, now) {
  const report = await ingestAlertLabels(paths, { now });
  await recordAlertTransitions(paths, { now, extraRecords: report.audit });
  return report;
}

test("label_log_tamper_bounded_by_label_budget: deleting the label state never resets the budget", async () => {
  const paths = await tempPaths();
  const ids = Array.from({ length: 120 }, (_, index) => `alert_e0000000000${String(index).padStart(5, "0")}`.slice(0, 22));
  await seed(paths, ids.map((id) => candidate(id, "session.churn", "k")));
  for (const id of ids) await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: id }, now: iso(2000) });
  const first = await daemonIngest(paths, iso(3000));
  assert.equal(first.ingested.length, LABEL_BUDGET_UNITS);
  const { logFile, stateFile } = resolveAlertLabelPaths(paths);
  const applied = new Set(first.ingested.map((entry) => entry.id));
  const kept = (await fs.readFile(logFile, "utf8")).split("\n").filter((line) => line && !applied.has(JSON.parse(line).id));
  await fs.writeFile(logFile, `${kept.join("\n")}\n`);
  await fs.rm(stateFile);
  const second = await daemonIngest(paths, iso(4000));
  assert.equal(second.state, "missing");
  assert.equal(second.ingested.length, 0, "the budget consumed in the window is rebuilt from the transition log");
  assert.ok(second.audit.some((record) => record.kind === "label_state_rebuilt" && record.state === "missing" && record.rebuilt_from_witness === LABEL_BUDGET_UNITS));
  assert.match(second.notice?.body ?? "", /label state/);
  assert.equal((await readAlertRecords(paths)).filter((alert) => alert.status === "closed").length, LABEL_BUDGET_UNITS);
});

test("label_charge_edit_is_ignored: the transition witness wins over a forged charge", async () => {
  const paths = await tempPaths();
  const firstId = "alert_e000000000000010";
  const secondId = "alert_e000000000000011";
  await seed(paths, [
    ...Array.from({ length: 50 }, (_, index) => candidate(firstId, "session.churn", `k-${index}`)),
    candidate(secondId, "session.churn", "k"),
  ]);
  const firstLabel = await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: firstId }, now: iso(2000) });
  const first = await daemonIngest(paths, iso(3000));
  assert.equal(first.ingested[0].charge, 50);
  const { stateFile } = resolveAlertLabelPaths(paths);
  const forged = JSON.parse(await fs.readFile(stateFile, "utf8"));
  forged.ingested[firstLabel.id].charge = 0;
  await fs.writeFile(stateFile, JSON.stringify(forged));
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: secondId }, now: iso(4000) });
  const second = await daemonIngest(paths, iso(5000));
  assert.ok(second.audit.some((entry) => entry.kind === "unattributed_change" && entry.field === "charge"));
  assert.equal(second.ingested.length, 0, "the second label is rejected over budget because the first witness charge is authoritative");
  assert.equal(second.held.length, 1);
  assert.equal(JSON.parse(await fs.readFile(stateFile, "utf8")).ingested[firstLabel.id].charge, 50);
});

test("label_quarantine_write_is_transactional: journal failure leaves the label un-ingested and the alert open for retry", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(LEVEL_ID, "session.count_drop", "lvl:r:2")]);
  const handle = await openPendingJournal(paths, "session", { now: iso(1000) });
  const item = { alert_id: LEVEL_ID, episode: iso(0), incident_key: "lvl:r:2" };
  handle.state.items[pendingItemId(item)] = { item, state: "pending", opened_ts: iso(0), disposition_seq: 0 };
  await appendAlertLabel(paths, { label: "confirmed_incident", scope: { kind: "alert", alert_id: LEVEL_ID }, now: iso(2000) });
  const failed = await ingestAlertLabels(paths, {
    now: iso(3000),
    handles: { session: handle },
    deps: { appendPendingEntries: async () => { throw new Error("journal is unwritable"); } },
  });
  assert.equal(failed.ingested.length, 0);
  assert.ok(failed.audit.some((entry) => entry.kind === "label_retry_failed"));
  assert.equal((await readAlertRecords(paths)).find((alert) => alert.id === LEVEL_ID).status, "active");
  const retry = await ingestAlertLabels(paths, { now: iso(4000), handles: { session: handle } });
  assert.equal(retry.ingested.length, 1);
});

test("hostile_label_read_is_capped_at_read_time_and_visible", async () => {
  const paths = await tempPaths();
  const { logFile } = resolveAlertLabelPaths(paths);
  await fs.mkdir(path.dirname(logFile), { recursive: true });
  await fs.writeFile(logFile, `${"x".repeat(1024 * 1024 + 1)}\n`);
  const read = await readAlertLabels(paths);
  assert.equal(read.tamper.kind, "label_log_read_cap");
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.tamper.kind, "label_log_read_cap");
  assert.ok(report.audit.some((entry) => entry.kind === "unattributed_change"));
});

test("an ingested label is never re-ingested after the label state is lost", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")]);
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  assert.equal((await daemonIngest(paths, iso(3000))).ingested.length, 1);
  await fs.rm(resolveAlertLabelPaths(paths).stateFile);
  const again = await daemonIngest(paths, iso(4000));
  assert.equal(again.ingested.length, 0);
});

// Adversarial review L5: a label applies only to the episode that existed when it was written, so a
// held label released later (or any label) never closes a later episode the labeller never saw.
test("a label never closes an episode that started after it was written", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")]);
  const label = await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(2000) });
  // The episode recovers and a new one starts before the daemon ingests the label.
  let alerts = applyAlertCandidates(await readAlertRecords(paths), [], { now: iso(2500) }).alerts;
  alerts = applyAlertCandidates(alerts, [candidate(EVENT_ID, "session.churn", "k1")], { now: iso(2600) }).alerts;
  await writeAlertRecords(paths, alerts);
  await confirmAlertDelivery(paths, EVENT_ID, { now: iso(2700), incidentKey: "k1" });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(report.ingested[0].effect, "predates_episode");
  assert.equal(report.ingested[0].closed, 0);
  const [alert] = await readAlertRecords(paths);
  assert.equal(alert.status, "active", "the later episode stays open");
  assert.equal(label.ts, iso(2000));
});

test("a future-dated label waits until its time; it is never ingested early", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(EVENT_ID, "session.churn", "k1")]);
  await appendAlertLabel(paths, { label: "benign", scope: { kind: "alert", alert_id: EVENT_ID }, now: iso(10 * DAY) });
  const early = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.equal(early.ingested.length, 0);
  assert.equal((await readAlertRecords(paths))[0].status, "active");
});

// Adversarial review M3 (label path): a journal opened by label ingestion consults the same witness
// as the pre-pass, so a double wipe is never turned into a fresh journal there.
test("label ingestion opening a wiped, witnessed journal opens a discontinuity, never a fresh journal", async () => {
  const paths = await tempPaths();
  await seed(paths, [candidate(LEVEL_ID, "session.count_drop", "lvl:r:2")]);
  const { resolvePendingJournalPaths } = await import("../src/pending-journal.js");
  await openPendingJournal(paths, "session", { ledger: null, now: iso(0) });
  await recordAlertTransitions(paths, { now: iso(0), extraRecords: [{ kind: "pending_journal_created", family: "session" }] });
  await fs.rm(resolvePendingJournalPaths(paths, "session").dir, { recursive: true });
  await appendAlertLabel(paths, { label: "confirmed_incident", scope: { kind: "alert", alert_id: LEVEL_ID }, now: iso(2000) });
  const report = await ingestAlertLabels(paths, { now: iso(3000) });
  assert.deepEqual(report.discontinuities.map((entry) => entry.cause), ["journal_and_checkpoint_missing"]);
  assert.ok(!report.audit.some((record) => record.kind === "pending_journal_created"));
});
