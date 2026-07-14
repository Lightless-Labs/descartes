import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION,
  DEFAULT_ENABLED_NAMESPACES,
  KNOWN_ALERT_NAMESPACES,
  adjudicateAlertNotifications,
  alertIntelligencePrompt,
  classifyAlertNamespace,
  emitSessionAlertSignals,
  normalizeAlertNotificationDecision,
  readAlertIntelligenceAudit,
  readAlertIntelligenceConfig,
  resolveAlertIntelligencePaths,
  writeAlertIntelligenceConfig,
} from "../src/alert-intelligence.js";
import { CORRELATION_RULE_ID } from "../src/incident-correlation.js";
import { readNotificationDeliveryAudit } from "../src/notification-delivery.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { PEER_COUNT_SPIKE_RULE_ID } from "../src/peer-baseline.js";
import {
  DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
} from "../src/session-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-alert-intelligence-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function alert(overrides = {}) {
  return {
    id: "alert_memory",
    rule_id: "system.memory.sustained_high",
    fingerprint: "global",
    status: "active",
    severity: "warning",
    title: "Sustained high memory pressure",
    summary: "Memory used stayed high.",
    evidence_refs: ["history-summary"],
    first_seen: "2026-05-28T00:00:00.000Z",
    last_seen: "2026-05-28T00:01:00.000Z",
    last_notified: "2026-05-28T00:01:00.000Z",
    cooldown_until: "2026-05-28T00:16:00.000Z",
    acknowledged_at: null,
    diagnostics: { min: 0.91, threshold: 0.9 },
    ...overrides,
  };
}

// Frozen, byte-for-byte copy of the pre-S13 alertIntelligencePrompt implementation (including the
// exact context key order and helper field selection), used ONLY as a golden reference for the
// byte-identity test below. Do not "clean up" to reuse alert-intelligence.js internals -- the point
// is to catch an accidental format drift in the new dispatcher's metric branch.
function preS13AlertIntelligencePrompt({ alerts, historySummary, daemonStatus }) {
  const compactAlertLocal = (alertRecord) => ({
    id: alertRecord.id,
    rule_id: alertRecord.rule_id,
    status: alertRecord.status,
    severity: alertRecord.severity,
    title: alertRecord.title,
    summary: alertRecord.summary,
    first_seen: alertRecord.first_seen,
    last_seen: alertRecord.last_seen,
    diagnostics: alertRecord.diagnostics,
  });
  const compactHistoryLocal = (summary) => {
    if (!summary) return undefined;
    return {
      id: "history-summary",
      window_ms: summary.window_ms,
      since: summary.since,
      until: summary.until,
      point_count: summary.point_count,
      truncated: summary.truncated,
      metrics: (summary.metrics ?? []).slice(0, 32).map((metric) => ({
        metric_name: metric.metric_name,
        unit: metric.unit,
        count: metric.count,
        min: metric.min,
        max: metric.max,
        mean: metric.mean,
        last: metric.last,
        p95: metric.p95,
        dimensions_seen: metric.dimensions_seen,
      })),
    };
  };
  return `You are Descartes alert intelligence. A deterministic local monitoring rule woke you up.

Decide whether the user should receive a notification now and write the exact bounded notification content.

Hard rules:
- Use only the alert records and summaries in this prompt.
- Do not claim facts not present here.
- Do not recommend or imply that any remediation action was taken.
- Prefer not notifying for stale/low-confidence/noisy alerts unless the user likely needs attention.
- Keep notification title <= 80 chars and body <= 240 chars.

Context:
${JSON.stringify({
  alerts: alerts.map(compactAlertLocal),
  history_summary: compactHistoryLocal(historySummary),
  daemon_status: daemonStatus ? {
    ts: daemonStatus.ts,
    state: daemonStatus.state,
    mode: daemonStatus.mode,
    interval_ms: daemonStatus.profile?.interval_ms,
    points_written: daemonStatus.points_written,
  } : null,
}, null, 2)}

Return only valid JSON with this shape:
{
  "notify": boolean,
  "severity": "info" | "warning" | "critical",
  "title": string,
  "body": string,
  "reason": string,
  "evidence_refs": string[],
  "next_check_hint": string
}`;
}

function fakeSession(prompts, decision) {
  return {
    messages: [],
    async prompt(promptText) {
      prompts.push(promptText);
      this.messages.push({ role: "assistant", content: [{ type: "text", text: JSON.stringify(decision) }] });
    },
    dispose() {},
  };
}

function fakeCreateSession(prompts, decision) {
  return async () => ({
    selectedModel: { provider: "test", id: "model" },
    selectedThinkingLevel: "low",
    session: fakeSession(prompts, decision),
  });
}

test("alert intelligence config is disabled by default and persists explicit opt-in", async () => {
  const paths = await tempPaths();
  assert.equal((await readAlertIntelligenceConfig(paths)).enabled, false);

  const written = await writeAlertIntelligenceConfig(paths, {
    enabled: true,
    model_pattern: "openai-codex/gpt-5.5",
    thinking_level: "high",
    max_calls_per_hour: 2,
  }, { now: "2026-05-28T00:00:00.000Z" });
  assert.equal(written.enabled, true);
  assert.equal(written.max_calls_per_hour, 2);
  assert.equal(written.updated_at, "2026-05-28T00:00:00.000Z");

  const pathsInfo = resolveAlertIntelligencePaths(paths);
  assert.equal(path.dirname(pathsInfo.configFile), paths.configDir);
  assert.deepEqual(await readAlertIntelligenceConfig(paths), written);
});

test("notification decisions are bounded and normalized", () => {
  const decision = normalizeAlertNotificationDecision({
    notify: true,
    severity: "critical",
    title: "x".repeat(200),
    body: "body ".repeat(100),
    reason: "because",
    evidence_refs: Array.from({ length: 20 }, (_, index) => `ref-${index}`),
  });
  assert.equal(decision.notify, true);
  assert.equal(decision.severity, "critical");
  assert(decision.title.length <= 81);
  assert(decision.body.length <= 241);
  assert.equal(decision.evidence_refs.length, 12);
});

test("alert intelligence prompt contains bounded alert context and no action authority", () => {
  const prompt = alertIntelligencePrompt({
    alerts: [alert()],
    historySummary: { window_ms: 900000, since: "a", until: "b", point_count: 2, metrics: [] },
    daemonStatus: { ts: "2026-05-28T00:01:00.000Z", state: "ok", mode: "foreground", profile: { interval_ms: 60000 } },
  });
  assert.match(prompt, /deterministic local monitoring rule woke you up/);
  assert.match(prompt, /Do not recommend or imply that any remediation action was taken/);
  assert.match(prompt, /system\.memory\.sustained_high/);
  assert.match(prompt, /Return only valid JSON/);
});

test("disabled alert intelligence does not create LLM sessions", async () => {
  const paths = await tempPaths();
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
  }, {
    createSession: async () => {
      throw new Error("should not create a session while disabled");
    },
  });
  assert.equal(result.status, "disabled");
});

test("enabled alert intelligence wakes fake LLM and records audited decision", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 3 }, { now: "2026-05-28T00:00:00.000Z" });
  const prompts = [];

  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
    history_summary: { window_ms: 900000, since: "a", until: "b", point_count: 2, metrics: [] },
    daemon_status: { ts: "2026-05-28T00:01:00.000Z", state: "ok", profile: { interval_ms: 60000 } },
  }, {
    now: "2026-05-28T00:02:00.000Z",
    createSession: async () => ({
      selectedModel: { provider: "test", id: "model" },
      selectedThinkingLevel: "low",
      session: {
        messages: [],
        async prompt(prompt) {
          prompts.push(prompt);
          this.messages.push({ role: "assistant", content: [{ type: "text", text: JSON.stringify({
            notify: true,
            severity: "warning",
            title: "Memory pressure is high",
            body: "Memory has stayed above the configured threshold.",
            reason: "The deterministic memory rule is active.",
            evidence_refs: ["history-summary", "alert:alert_memory"],
            next_check_hint: "Open Descartes alerts for details.",
          }) }] });
        },
        dispose() {},
      },
    }),
  });

  assert.equal(result.status, "ok");
  assert.equal(prompts.length, 1);
  const audit = await readAlertIntelligenceAudit(paths);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].status, "ok");
  assert.equal(audit[0].decision.notify, true);
  assert.equal(audit[0].decision.title, "Memory pressure is high");
});

test("alert intelligence respects max calls per hour", async () => {
  const paths = await tempPaths();
  // critical_reservation:0 preserves the pre-S13 "plain max_calls_per_hour enforcement" behavior
  // this test exercises; the default reservation (1) would starve this non-critical alert at
  // max_calls_per_hour:1, which is exercised separately by the budget-invariant tests below.
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 1, critical_reservation: 0 }, { now: "2026-05-28T00:00:00.000Z" });

  const evaluation = { alerts: [alert()], notification_due_ids: ["alert_memory"] };
  const createSession = async () => ({
    session: {
      messages: [],
      async prompt() {
        this.messages.push({ role: "assistant", content: [{ type: "text", text: "{\"notify\":false}" }] });
      },
      dispose() {},
    },
  });

  assert.equal((await adjudicateAlertNotifications(paths, evaluation, { now: "2026-05-28T00:02:00.000Z", createSession })).status, "ok");
  const limited = await adjudicateAlertNotifications(paths, evaluation, { now: "2026-05-28T00:03:00.000Z", createSession });
  assert.equal(limited.status, "rate_limited");
});

// --- S13 must-fix 6: metric prompt byte-identity ---------------------------------------------

test("metric alert prompt is byte-identical to the pre-S13 builder for a fixed input", () => {
  const input = {
    alerts: [alert()],
    historySummary: {
      window_ms: 900000,
      since: "a",
      until: "b",
      point_count: 2,
      truncated: false,
      metrics: [{ metric_name: "system.memory.used_fraction", unit: "fraction", count: 2, min: 0.9, max: 0.95, mean: 0.92, last: 0.93, p95: 0.94, dimensions_seen: 1 }],
    },
    daemonStatus: { ts: "2026-05-28T00:01:00.000Z", state: "ok", mode: "foreground", profile: { interval_ms: 60000 }, points_written: 3 },
  };
  assert.equal(alertIntelligencePrompt(input), preS13AlertIntelligencePrompt(input));
});

// --- S13 must-fix 1: closed-map namespace classification / eligibility ------------------------

test("un-consented learned-namespace alert never reaches the model (default enabled_namespaces excludes it)", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-01T00:00:00.000Z" });
  const provenanceAlert = alert({ id: "alert_provenance", rule_id: "provenance.process.unknown_identity", severity: "warning", diagnostics: { identity_hash: "abc123" } });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [provenanceAlert],
    notification_due_ids: ["alert_provenance"],
  }, {
    now: "2026-06-01T00:01:00.000Z",
    createSession: async () => { throw new Error("must not create a session for an un-consented namespace"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.not_consented, 1);
  assert.equal((await readAlertIntelligenceAudit(paths)).length, 0);
});

test("missing or garbage enabled_namespaces normalizes to the metric-only default", async () => {
  const paths = await tempPaths();
  assert.deepEqual((await readAlertIntelligenceConfig(paths)).enabled_namespaces, ["metric"]);

  const garbageType = await writeAlertIntelligenceConfig(paths, { enabled: true, enabled_namespaces: "nonsense" });
  assert.deepEqual(garbageType.enabled_namespaces, ["metric"]);

  const allInvalidEntries = await writeAlertIntelligenceConfig(paths, { enabled: true, enabled_namespaces: ["bogus", "learned", 123] });
  assert.deepEqual(allInvalidEntries.enabled_namespaces, ["metric"]);

  const validDeduped = await writeAlertIntelligenceConfig(paths, { enabled: true, enabled_namespaces: ["provenance", "provenance"] });
  assert.deepEqual(validDeduped.enabled_namespaces, ["provenance"]);
});

test("learned.* alerts are hard-excluded from LLM adjudication even when explicitly opted in", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, enabled_namespaces: ["metric", "learned"] }, { now: "2026-06-02T00:00:00.000Z" });
  const learnedAlert = alert({ id: "alert_learned", rule_id: "learned.audit.regression", severity: "warning" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [learnedAlert],
    notification_due_ids: ["alert_learned"],
  }, {
    now: "2026-06-02T00:01:00.000Z",
    createSession: async () => { throw new Error("must never create a session for a learned.* self-audit finding"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.hard_excluded_learned, 1);
});

test("unrecognized rule_id prefix is excluded from LLM adjudication (fail closed, not a generic fallback)", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-03T00:00:00.000Z" });
  const weirdAlert = alert({ id: "alert_weird", rule_id: "weird.thing", severity: "warning" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [weirdAlert],
    notification_due_ids: ["alert_weird"],
  }, {
    now: "2026-06-03T00:01:00.000Z",
    createSession: async () => { throw new Error("must never create a session for an unrecognized namespace"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.unknown_namespace, 1);
});

// --- S13 must-fix 2: budget arithmetic invariants ----------------------------------------------

test("budget invariant: total calls never exceed max_calls_per_hour under a critical burst", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 2, critical_reservation: 1 }, { now: "2026-06-04T00:00:00.000Z" });
  const criticals = ["a", "b", "c"].map((suffix) => alert({ id: `alert_crit_${suffix}`, rule_id: "system.memory.sustained_high", severity: "critical" }));
  const prompts = [];
  const result = await adjudicateAlertNotifications(paths, {
    alerts: criticals,
    notification_due_ids: criticals.map((entry) => entry.id),
  }, {
    now: "2026-06-04T00:01:00.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 2);
  assert.equal(result.dropped_total, 1);
  assert.equal(result.dropped_critical, 1);
  assert.equal((await readAlertIntelligenceAudit(paths)).length, 2);
});

test("critical_reservation is clamped to [0, max_calls_per_hour]", async () => {
  const paths = await tempPaths();
  const over = await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 2, critical_reservation: 10 });
  assert.equal(over.critical_reservation, 2);
  const negative = await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 2, critical_reservation: -5 });
  assert.equal(negative.critical_reservation, 0);
  const zeroMax = await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 0, critical_reservation: 1 });
  assert.equal(zeroMax.critical_reservation, 0);
});

test("historical audit records without alert_severity count as non-critical (conservative)", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 2, critical_reservation: 1 }, { now: "2026-06-05T00:00:00.000Z" });
  const { auditFile } = resolveAlertIntelligencePaths(paths);
  await fs.mkdir(path.dirname(auditFile), { recursive: true });
  // Pre-S13-shaped record: no alert_severity field at all.
  await fs.appendFile(auditFile, `${JSON.stringify({ ts: "2026-06-05T00:00:30.000Z", alert_id: "legacy", rule_id: "system.memory.sustained_high", status: "ok" })}\n`);

  // non-critical budget = max(0, 2 - 1) = 1, already consumed by the legacy (non-critical-counted)
  // record above -> a new non-critical alert must be refused even though total(1) < max(2).
  const prompts = [];
  const warningAlert = alert({ id: "alert_warning_after_legacy", rule_id: "system.memory.sustained_high", severity: "warning" });
  const warningResult = await adjudicateAlertNotifications(paths, {
    alerts: [warningAlert],
    notification_due_ids: [warningAlert.id],
  }, {
    now: "2026-06-05T00:01:00.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 0);
  assert.equal(warningResult.dropped_total, 1);
});

test("a critical alert is admitted even when the non-critical budget is exhausted, as long as total < max", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 3, critical_reservation: 1 }, { now: "2026-06-06T00:00:00.000Z" });
  const prompts = [];
  // non-critical budget = max(0, 3 - 1) = 2; consume it with two non-critical alerts in one tick.
  const nonCriticals = ["x", "y"].map((suffix) => alert({ id: `alert_noncrit_${suffix}`, rule_id: "system.memory.sustained_high", severity: "warning" }));
  await adjudicateAlertNotifications(paths, {
    alerts: nonCriticals,
    notification_due_ids: nonCriticals.map((entry) => entry.id),
  }, {
    now: "2026-06-06T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 2);

  // total_so_far is now 2 (< max 3); a critical alert must still be admitted even though the
  // non-critical budget (2) is fully spent.
  const criticalAlert = alert({ id: "alert_crit_after_noncrit", rule_id: "system.memory.sustained_high", severity: "critical" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [criticalAlert],
    notification_due_ids: [criticalAlert.id],
  }, {
    now: "2026-06-06T00:00:20.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(result.status, "ok");
  assert.equal(prompts.length, 3);
});

test("a non-critical alert is refused once non_critical_so_far reaches max - reservation, even though total < max", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 3, critical_reservation: 1 }, { now: "2026-06-07T00:00:00.000Z" });
  const prompts = [];
  const nonCriticals = ["x", "y"].map((suffix) => alert({ id: `alert_noncrit2_${suffix}`, rule_id: "system.memory.sustained_high", severity: "warning" }));
  await adjudicateAlertNotifications(paths, {
    alerts: nonCriticals,
    notification_due_ids: nonCriticals.map((entry) => entry.id),
  }, {
    now: "2026-06-07T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 2);

  // total_so_far is now 2 (< max 3) but non_critical_so_far (2) == max - reservation (2): refused.
  const thirdNonCritical = alert({ id: "alert_noncrit2_z", rule_id: "system.memory.sustained_high", severity: "warning" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [thirdNonCritical],
    notification_due_ids: [thirdNonCritical.id],
  }, {
    now: "2026-06-07T00:00:20.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(result.status, "rate_limited");
  assert.equal(prompts.length, 2);
  assert.equal(result.dropped_total, 1);
});

// --- S13 must-fix 3: deterministic budget_exhausted signal -------------------------------------

test("budget_exhausted fires once per invocation with a counts-only body (no dropped title/diagnostics)", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 1, critical_reservation: 0 }, { now: "2026-06-08T00:00:00.000Z" });
  const prompts = [];
  const deliveries = [];
  const secretTitleOne = "TOP SECRET DIAGNOSTIC TITLE ONE";
  const secretTitleTwo = "TOP SECRET DIAGNOSTIC TITLE TWO";
  const dueAlerts = [
    alert({ id: "alert_bx_1", rule_id: "system.memory.sustained_high", severity: "warning", title: secretTitleOne }),
    alert({ id: "alert_bx_2", rule_id: "disk.space.high_used_fraction", severity: "warning", title: secretTitleTwo }),
  ];
  const result = await adjudicateAlertNotifications(paths, {
    alerts: dueAlerts,
    notification_due_ids: dueAlerts.map((entry) => entry.id),
  }, {
    now: "2026-06-08T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
    deliverNotification: async (descartesPaths, decision, opts) => {
      deliveries.push({ decision, opts });
      return { status: "recorded" };
    },
  });
  assert.equal(prompts.length, 1);
  assert.equal(result.dropped_total, 1);
  const budgetDeliveries = deliveries.filter((entry) => entry.opts.ruleId === "adjudication.budget_exhausted");
  assert.equal(budgetDeliveries.length, 1);
  assert.equal(budgetDeliveries[0].decision.notify, true);
  assert.equal(budgetDeliveries[0].decision.severity, "warning");
  assert.doesNotMatch(budgetDeliveries[0].decision.body, new RegExp(secretTitleOne));
  assert.doesNotMatch(budgetDeliveries[0].decision.body, new RegExp(secretTitleTwo));
  assert.match(budgetDeliveries[0].decision.body, /1 alert \(0 critical\) not adjudicated this hour/);
});

test("budget_exhausted does not fire when alert intelligence is disabled", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
  }, {
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); },
  });
  assert.equal(result.status, "disabled");
  assert.equal(deliveries.length, 0);
});

test("budget_exhausted does not fire for namespace-only (consent) drops", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-09T00:00:00.000Z" });
  const deliveries = [];
  const provenanceAlert = alert({ id: "alert_prov_only", rule_id: "provenance.process.unknown_identity", severity: "critical" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [provenanceAlert],
    notification_due_ids: ["alert_prov_only"],
  }, {
    now: "2026-06-09T00:00:10.000Z",
    createSession: async () => { throw new Error("should not be reached"); },
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(deliveries.length, 0);
});

test("budget_exhausted has its own cross-tick cooldown, suppressing a second signal within the hour", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 0 }, { now: "2026-06-10T00:00:00.000Z" });
  const dueAlert = alert({ id: "alert_cooldown", rule_id: "system.memory.sustained_high", severity: "warning" });

  await adjudicateAlertNotifications(paths, { alerts: [dueAlert], notification_due_ids: [dueAlert.id] }, {
    now: "2026-06-10T00:00:10.000Z",
    createSession: async () => { throw new Error("max_calls_per_hour:0 must never call the LLM"); },
  });
  await adjudicateAlertNotifications(paths, { alerts: [dueAlert], notification_due_ids: [dueAlert.id] }, {
    now: "2026-06-10T00:05:00.000Z",
    createSession: async () => { throw new Error("max_calls_per_hour:0 must never call the LLM"); },
  });

  const notificationAudit = await readNotificationDeliveryAudit(paths);
  const budgetSignals = notificationAudit.filter((record) => record.payload?.rule_id === "adjudication.budget_exhausted");
  assert.equal(budgetSignals.length, 1);
});

test("budget_exhausted severity is critical iff a critical alert was dropped", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 0 }, { now: "2026-06-11T00:00:00.000Z" });
  const deliveries = [];
  const criticalAlert = alert({ id: "alert_crit_bx", rule_id: "system.memory.sustained_high", severity: "critical" });
  await adjudicateAlertNotifications(paths, { alerts: [criticalAlert], notification_due_ids: [criticalAlert.id] }, {
    now: "2026-06-11T00:00:10.000Z",
    createSession: async () => { throw new Error("should not be reached"); },
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); },
  });
  const budgetDelivery = deliveries.find((entry) => entry.opts.ruleId === "adjudication.budget_exhausted");
  assert.equal(budgetDelivery.decision.severity, "critical");
});

// --- S13 must-fix 4: eligibility filter runs before rate-limit accounting ----------------------

test("when alerts are due but none are LLM-eligible, status is a distinct no_eligible_alerts, never rate_limited", async () => {
  const paths = await tempPaths();
  // max_calls_per_hour:0 would ALSO cause a "nothing admitted" outcome if eligibility ran after
  // budget accounting -- pinning namespace-exclusion to its own status proves the filter runs
  // first (must-fix 4), not merely that a distinct status exists for some other cause.
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 0 }, { now: "2026-06-12T00:00:00.000Z" });
  const provenanceAlert = alert({ id: "alert_prov_status", rule_id: "provenance.process.unknown_identity", severity: "warning" });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [provenanceAlert],
    notification_due_ids: ["alert_prov_status"],
  }, {
    now: "2026-06-12T00:00:10.000Z",
    createSession: async () => { throw new Error("should not be reached"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.notEqual(result.status, "rate_limited");
});

// --- S13 must-fix 2: critical-first ordering -----------------------------------------------------

test("critical due alerts are processed before non-critical ones within a tick", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, critical_reservation: 1 }, { now: "2026-06-13T00:00:00.000Z" });
  const order = [];
  const nonCritical = alert({ id: "alert_order_noncrit", rule_id: "system.memory.sustained_high", severity: "warning" });
  const critical = alert({ id: "alert_order_crit", rule_id: "disk.space.high_used_fraction", severity: "critical" });
  await adjudicateAlertNotifications(paths, {
    alerts: [nonCritical, critical],
    notification_due_ids: [nonCritical.id, critical.id],
  }, {
    now: "2026-06-13T00:00:10.000Z",
    createSession: async () => ({
      session: {
        messages: [],
        async prompt(promptText) {
          order.push(promptText.includes(critical.id) ? "critical" : "non-critical");
          this.messages.push({ role: "assistant", content: [{ type: "text", text: JSON.stringify({ notify: false }) }] });
        },
        dispose() {},
      },
    }),
  });
  assert.deepEqual(order, ["critical", "non-critical"]);
});

// --- S13 must-fix 6 (single-alert-per-prompt invariant) -----------------------------------------

test("each LLM prompt contains exactly one alert, never mixing consented alerts across calls", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-14T00:00:00.000Z" });
  const first = alert({ id: "alert_single_a", rule_id: "system.memory.sustained_high", severity: "warning" });
  const second = alert({ id: "alert_single_b", rule_id: "disk.space.high_used_fraction", severity: "warning" });
  const prompts = [];
  await adjudicateAlertNotifications(paths, {
    alerts: [first, second],
    notification_due_ids: [first.id, second.id],
  }, {
    now: "2026-06-14T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 2);
  const parsedContexts = prompts.map((promptText) => JSON.parse(promptText.match(/Context:\n([\s\S]*?)\n\nReturn only valid JSON/)[1]));
  for (const context of parsedContexts) assert.equal(context.alerts.length, 1);
  assert.notEqual(parsedContexts[0].alerts[0].id, parsedContexts[1].alerts[0].id);
  assert.ok(!prompts[0].includes(second.id));
  assert.ok(!prompts[1].includes(first.id));
});

// --- S13 nice-to-have: prompt hash / template version / alert_severity audit fields -------------

test("audit records carry alert_severity, prompt_hash, and prompt_template_version on both ok and error paths", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-15T00:00:00.000Z" });

  const okAlert = alert({ id: "alert_audit_ok", rule_id: "system.memory.sustained_high", severity: "critical" });
  await adjudicateAlertNotifications(paths, { alerts: [okAlert], notification_due_ids: [okAlert.id] }, {
    now: "2026-06-15T00:00:10.000Z",
    createSession: fakeCreateSession([], { notify: false }),
  });

  const errorAlert = alert({ id: "alert_audit_error", rule_id: "disk.space.high_used_fraction", severity: "warning" });
  await adjudicateAlertNotifications(paths, { alerts: [errorAlert], notification_due_ids: [errorAlert.id] }, {
    now: "2026-06-15T00:00:20.000Z",
    createSession: async () => { throw new Error("boom"); },
  });

  const audit = await readAlertIntelligenceAudit(paths);
  const okRecord = audit.find((record) => record.alert_id === okAlert.id);
  const errorRecord = audit.find((record) => record.alert_id === errorAlert.id);

  assert.equal(okRecord.status, "ok");
  assert.equal(okRecord.alert_severity, "critical");
  assert.equal(typeof okRecord.prompt_hash, "string");
  assert.equal(okRecord.prompt_hash.length, 64);
  assert.equal(okRecord.prompt_template_version, ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION);

  assert.equal(errorRecord.status, "error");
  assert.equal(errorRecord.alert_severity, "warning");
  assert.equal(typeof errorRecord.prompt_hash, "string");
  assert.equal(errorRecord.prompt_hash.length, 64);
  assert.equal(errorRecord.prompt_template_version, ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION);
});

// --- S13 must-fix 5: include_history_summary / include_daemon_status wiring --------------------

test("include_history_summary:false and include_daemon_status:false omit those sections from the prompt", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, {
    enabled: true, max_calls_per_hour: 5, include_history_summary: false, include_daemon_status: false,
  }, { now: "2026-06-16T00:00:00.000Z" });
  const prompts = [];
  const dueAlert = alert({ id: "alert_wiring_off", rule_id: "system.memory.sustained_high", severity: "warning" });
  await adjudicateAlertNotifications(paths, {
    alerts: [dueAlert],
    notification_due_ids: [dueAlert.id],
    history_summary: { window_ms: 900000, since: "a", until: "b", point_count: 2, metrics: [{ metric_name: "distinctive_history_marker" }] },
    daemon_status: { ts: "2026-06-16T00:00:05.000Z", state: "ok", profile: { interval_ms: 60000 }, points_written: 999 },
  }, {
    now: "2026-06-16T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(prompts.length, 1);
  assert.doesNotMatch(prompts[0], /distinctive_history_marker/);
  assert.doesNotMatch(prompts[0], /999/);
  // compactHistory(undefined) returns undefined, which JSON.stringify omits entirely (not a
  // "history_summary": null key); daemonStatusContext(undefined) explicitly returns null.
  assert.doesNotMatch(prompts[0], /history_summary/);
  assert.match(prompts[0], /"daemon_status": null/);
});

test("include_history_summary and include_daemon_status default true and include those sections", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-06-17T00:00:00.000Z" });
  const prompts = [];
  const dueAlert = alert({ id: "alert_wiring_on", rule_id: "system.memory.sustained_high", severity: "warning" });
  await adjudicateAlertNotifications(paths, {
    alerts: [dueAlert],
    notification_due_ids: [dueAlert.id],
    history_summary: { window_ms: 900000, since: "a", until: "b", point_count: 2, metrics: [{ metric_name: "distinctive_history_marker_2" }] },
    daemon_status: { ts: "2026-06-17T00:00:05.000Z", state: "ok", profile: { interval_ms: 60000 }, points_written: 42 },
  }, {
    now: "2026-06-17T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.match(prompts[0], /distinctive_history_marker_2/);
  assert.match(prompts[0], /"points_written": 42/);
});

// --- S13 nice-to-have: corrupt-tolerant fail-closed config load --------------------------------

test("corrupt alert-intelligence.json is treated as disabled and does not throw", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveAlertIntelligencePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{not valid json", "utf8");

  const config = await readAlertIntelligenceConfig(paths);
  assert.equal(config.enabled, false);
  assert.equal(config.corrupt, true);

  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
  }, {
    createSession: async () => { throw new Error("must not create a session when config is corrupt"); },
  });
  assert.equal(result.status, "disabled");
});

// --- S13 remediation: budget_exhausted emit is guarded against uncaught I/O failure -------------

test("emitBudgetExhaustedSignal I/O failure degrades gracefully: adjudicate resolves, budget_exhausted records the error, and the per-alert path is unaffected", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 1, critical_reservation: 0 }, { now: "2026-07-13T00:00:00.000Z" });
  const prompts = [];
  const deliveries = [];
  const dueAlerts = [
    alert({ id: "alert_emitfail_1", rule_id: "system.memory.sustained_high", severity: "warning" }),
    alert({ id: "alert_emitfail_2", rule_id: "disk.space.high_used_fraction", severity: "warning" }),
  ];
  // The first (admitted) alert's LLM decision says notify:true so its own deliverNotification call
  // exercises the SAME injected function the emitter uses -- proving the emitter's throw (gated on
  // its distinct budget_exhausted ruleId, mirroring how the real module threads one
  // options.deliverNotification through both call sites) doesn't take the per-alert path down with it.
  const result = await adjudicateAlertNotifications(paths, {
    alerts: dueAlerts,
    notification_due_ids: dueAlerts.map((entry) => entry.id),
  }, {
    now: "2026-07-13T00:00:10.000Z",
    createSession: fakeCreateSession(prompts, { notify: true, severity: "warning", title: "Memory pressure", body: "Elevated." }),
    deliverNotification: async (descartesPaths, decision, opts) => {
      if (opts.ruleId === "adjudication.budget_exhausted") {
        throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
      }
      deliveries.push({ decision, opts });
      return { status: "recorded" };
    },
  });

  // adjudicate RESOLVES (does not reject/throw) despite the emitter's deliverNotification throwing.
  assert.equal(result.status, "ok");
  assert.equal(result.dropped_total, 1);
  assert.deepEqual(result.budget_exhausted, {
    fired: false,
    reason: "error",
    error: "ENOSPC: no space left on device",
  });

  // The per-alert decision/status is unaffected by the emit failure: the one admitted alert still
  // delivered its own notification and recorded an "ok" audit entry.
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].opts.ruleId, "system.memory.sustained_high");
  const audit = await readAlertIntelligenceAudit(paths);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].status, "ok");
  assert.equal(audit[0].decision.notify, true);
});

// ---------------------------------------------------------------------------------------------
// S13 I/O hardening: fail-closed audit/config I/O (closes the DEFERRED residual from S13's own
// remediation pass -- see the tracking todo / plan addendum for this pass).
// ---------------------------------------------------------------------------------------------

test("S13 I/O hardening: a non-ENOENT config read failure (config path is a directory -> EISDIR) fails closed -- unavailable:true, adjudicate returns disabled, ZERO createSession calls", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveAlertIntelligencePaths(paths);
  // The directory trick (no fs mocking / no chmod): making the config path itself a directory
  // makes fs.readFile fail with EISDIR -- a real, non-ENOENT filesystem error.
  await fs.mkdir(configFile, { recursive: true });

  const config = await readAlertIntelligenceConfig(paths);
  assert.equal(config.enabled, false);
  assert.equal(config.unavailable, true);

  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
  }, {
    createSession: async () => { throw new Error("must not create a session when the config is unavailable"); },
  });
  assert.equal(result.status, "disabled");
});

test("S13 I/O hardening: a non-ENOENT budget-seed audit read failure (audit path is a directory -> EISDIR) returns audit_unavailable, ZERO createSession calls, and never throws", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 3 }, { now: "2026-07-14T00:00:00.000Z" });
  const { auditFile } = resolveAlertIntelligencePaths(paths);
  await fs.mkdir(auditFile, { recursive: true });

  const result = await adjudicateAlertNotifications(paths, {
    alerts: [alert()],
    notification_due_ids: ["alert_memory"],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async () => { throw new Error("must not create a session when the audit read fails"); },
  });
  assert.equal(result.status, "audit_unavailable");
  assert.deepEqual(result.decisions, []);
});

test("S13 I/O hardening: an appendAuditRecord failure does not crash adjudicate, BREAKS after the first failure (does not continue to a second due alert), and surfaces audit_write_degraded (never 'ok')", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, critical_reservation: 0 }, { now: "2026-07-14T00:00:00.000Z" });
  const dueAlerts = [
    alert({ id: "alert_break_1", rule_id: "system.memory.sustained_high", severity: "warning" }),
    alert({ id: "alert_break_2", rule_id: "disk.space.high_used_fraction", severity: "warning" }),
  ];
  let createSessionCalls = 0;
  const result = await adjudicateAlertNotifications(paths, {
    alerts: dueAlerts,
    notification_due_ids: dueAlerts.map((entry) => entry.id),
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async (...args) => {
      createSessionCalls += 1;
      return fakeCreateSession([], { notify: false })(...args);
    },
    appendAuditRecord: async () => {
      throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
    },
  });
  assert.equal(createSessionCalls, 1, "expected the loop to break after the first append failure, never reaching the second due alert");
  assert.equal(result.status, "audit_write_degraded");
  assert.deepEqual(result.decisions, []);
});

test("S13 I/O hardening -- THE LATCH invariant: sustained reads-succeed-writes-fail (ENOSPC-shaped) across MULTIPLE invocations is bounded to <=1 total createSession call, NOT ~1 per tick", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, critical_reservation: 0 }, { now: "2026-07-14T00:00:00.000Z" });
  let createSessionCalls = 0;
  const options = {
    createSession: async (...args) => {
      createSessionCalls += 1;
      return fakeCreateSession([], { notify: false })(...args);
    },
    // Reads succeed (the real readAuditRecords sees no file -> []); writes always fail -- the
    // canonical ENOSPC shape the in-process latch exists for.
    appendAuditRecord: async () => {
      throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
    },
  };
  const dueAlertFor = (n) => alert({ id: `alert_latch_${n}`, rule_id: "system.memory.sustained_high", severity: "warning" });

  const first = await adjudicateAlertNotifications(paths, {
    alerts: [dueAlertFor(1)],
    notification_due_ids: ["alert_latch_1"],
  }, { now: "2026-07-14T00:01:00.000Z", ...options });
  assert.equal(first.status, "audit_write_degraded");
  assert.equal(createSessionCalls, 1, "the first (failing) tick is allowed its one already-made call");

  for (let tick = 2; tick <= 5; tick += 1) {
    const result = await adjudicateAlertNotifications(paths, {
      alerts: [dueAlertFor(tick)],
      notification_due_ids: [`alert_latch_${tick}`],
    }, { now: `2026-07-14T00:0${tick}:00.000Z`, ...options });
    assert.equal(result.status, "audit_write_degraded", `tick ${tick} expected to stay latched`);
    assert.deepEqual(result.decisions, []);
  }
  // Across 5 total invocations (1 initial failure + 4 subsequent latched ticks, each of which
  // attempts only a cheap probe append, never an LLM call), exactly ONE createSession call was
  // EVER made -- a break-only design (no latch) would have made one PER tick (5 total).
  assert.equal(createSessionCalls, 1, "the in-process latch must hold across ticks 2-5 -- total calls must not scale with tick count");
});

test("S13 I/O hardening -- probe-heal: once appendAuditRecord starts succeeding again, a later invocation's probe clears the latch and resumes adjudicating the SAME tick", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, critical_reservation: 0 }, { now: "2026-07-14T00:00:00.000Z" });
  let appendShouldFail = true;
  const appendedRecords = [];
  let createSessionCalls = 0;
  const appendAuditRecordFake = async (descartesPaths, record) => {
    if (appendShouldFail) throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
    appendedRecords.push(record);
    return record;
  };
  const createSessionFake = async (...args) => {
    createSessionCalls += 1;
    return fakeCreateSession([], { notify: false })(...args);
  };

  const first = await adjudicateAlertNotifications(paths, {
    alerts: [alert({ id: "alert_heal_1", rule_id: "system.memory.sustained_high", severity: "warning" })],
    notification_due_ids: ["alert_heal_1"],
  }, { now: "2026-07-14T00:01:00.000Z", createSession: createSessionFake, appendAuditRecord: appendAuditRecordFake });
  assert.equal(first.status, "audit_write_degraded");
  assert.equal(createSessionCalls, 1);

  const second = await adjudicateAlertNotifications(paths, {
    alerts: [alert({ id: "alert_heal_2", rule_id: "system.memory.sustained_high", severity: "warning" })],
    notification_due_ids: ["alert_heal_2"],
  }, { now: "2026-07-14T00:02:00.000Z", createSession: createSessionFake, appendAuditRecord: appendAuditRecordFake });
  assert.equal(second.status, "audit_write_degraded");
  assert.equal(createSessionCalls, 1, "still latched -- zero further LLM calls while writes remain broken");

  appendShouldFail = false; // writes heal

  const third = await adjudicateAlertNotifications(paths, {
    alerts: [alert({ id: "alert_heal_3", rule_id: "system.memory.sustained_high", severity: "warning" })],
    notification_due_ids: ["alert_heal_3"],
  }, { now: "2026-07-14T00:03:00.000Z", createSession: createSessionFake, appendAuditRecord: appendAuditRecordFake });
  assert.equal(third.status, "ok");
  assert.equal(createSessionCalls, 2, "the probe succeeded, the latch cleared, and adjudication resumed within this same tick");
  assert.equal(appendedRecords.some((record) => record.status === "audit_probe"), true, "expected the heal probe's own record to have been appended");
  assert.equal(appendedRecords.some((record) => record.alert_id === "alert_heal_3" && record.status === "ok"), true, "expected the resumed tick's real decision to also be appended");
});

test("S13 I/O hardening: the latch is keyed by the resolved audit-file path -- two different temp audit paths do not share latch state (one latched must not zero out the other)", async () => {
  const pathsA = await tempPaths();
  const pathsB = await tempPaths();
  await writeAlertIntelligenceConfig(pathsA, { enabled: true, max_calls_per_hour: 5, critical_reservation: 0 }, { now: "2026-07-14T00:00:00.000Z" });
  await writeAlertIntelligenceConfig(pathsB, { enabled: true, max_calls_per_hour: 5, critical_reservation: 0 }, { now: "2026-07-14T00:00:00.000Z" });

  let createSessionCallsA = 0;
  const resultA = await adjudicateAlertNotifications(pathsA, {
    alerts: [alert({ id: "alert_pathA", rule_id: "system.memory.sustained_high", severity: "warning" })],
    notification_due_ids: ["alert_pathA"],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async (...args) => { createSessionCallsA += 1; return fakeCreateSession([], { notify: false })(...args); },
    appendAuditRecord: async () => { throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" }); },
  });
  assert.equal(resultA.status, "audit_write_degraded");
  assert.equal(createSessionCallsA, 1);

  // pathsB uses the REAL (unmocked) appendAuditRecord and must be entirely unaffected by pathsA's
  // now-latched degraded state.
  const prompts = [];
  const resultB = await adjudicateAlertNotifications(pathsB, {
    alerts: [alert({ id: "alert_pathB", rule_id: "system.memory.sustained_high", severity: "warning" })],
    notification_due_ids: ["alert_pathB"],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: fakeCreateSession(prompts, { notify: false }),
  });
  assert.equal(resultB.status, "ok");
  assert.equal(prompts.length, 1, "pathsB's own audit file must be writable and unaffected by pathsA's latch");
});

// --- S13 remediation: alertIntelligencePrompt enforces the single-alert-per-prompt invariant internally --

test("alertIntelligencePrompt throws when given zero alerts", () => {
  assert.throws(() => alertIntelligencePrompt({ alerts: [] }), /requires exactly one alert, got 0/);
});

test("alertIntelligencePrompt throws when given more than one alert", () => {
  const first = alert({ id: "alert_multi_a", rule_id: "system.memory.sustained_high" });
  const second = alert({ id: "alert_multi_b", rule_id: "disk.space.high_used_fraction" });
  assert.throws(() => alertIntelligencePrompt({ alerts: [first, second] }), /requires exactly one alert, got 2/);
});

test("alertIntelligencePrompt still returns a string for exactly one valid metric alert", () => {
  const prompt = alertIntelligencePrompt({ alerts: [alert()] });
  assert.equal(typeof prompt, "string");
  assert.match(prompt, /Return only valid JSON/);
});

// ---------------------------------------------------------------------------------------------
// Slice 4 (observed-incident collectors plan) — Decision 2, must-fix 6: strengthened fail-closed
// namespace regression tests for the session.* rule_ids.
// ---------------------------------------------------------------------------------------------

test("(a) classifyAlertNamespace returns undefined (not 'baseline' or any other known namespace) for both session.* rule_ids", () => {
  assert.deepEqual(classifyAlertNamespace(SESSION_COUNT_DROP_RULE_ID), { namespace: undefined, hardExcluded: false });
  assert.deepEqual(classifyAlertNamespace(SESSION_CHURN_RULE_ID), { namespace: undefined, hardExcluded: false });
});

test("(b') a full adjudicateAlertNotifications run, with ALL of KNOWN_ALERT_NAMESPACES enabled and one due session.count_drop, is no_eligible_alerts / excluded.unknown_namespace / zero LLM calls", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, enabled_namespaces: [...KNOWN_ALERT_NAMESPACES] }, { now: "2026-07-14T00:00:00.000Z" });
  const sessionAlert = alert({ id: "alert_session_count_drop", rule_id: SESSION_COUNT_DROP_RULE_ID, severity: "critical", diagnostics: { observed_count: 0, mean_before: 20, stddev_before: 0.5, z_score: -40, confidence_state: "established" } });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [sessionAlert],
    notification_due_ids: [sessionAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async () => { throw new Error("must never create a session for session.count_drop — it is unknown_namespace, fail-closed"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.unknown_namespace, 1);
  assert.equal((await readAlertIntelligenceAudit(paths)).length, 0);
});

test("(b') the same holds separately for a due session.churn alert", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, enabled_namespaces: [...KNOWN_ALERT_NAMESPACES] }, { now: "2026-07-14T00:00:00.000Z" });
  const churnAlert = alert({ id: "alert_session_churn", rule_id: SESSION_CHURN_RULE_ID, severity: "warning", diagnostics: { entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" } });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [churnAlert],
    notification_due_ids: [churnAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async () => { throw new Error("must never create a session for session.churn — it is unknown_namespace, fail-closed"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.unknown_namespace, 1);
});

test("(c) invariant: every exported SESSION_*_RULE_ID classifies to namespace undefined — a future session-family rule_id inherits fail-closed by construction", () => {
  for (const ruleId of [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]) {
    const { namespace, hardExcluded } = classifyAlertNamespace(ruleId);
    assert.equal(namespace, undefined, `expected ${ruleId} to classify as unknown_namespace`);
    assert.equal(hardExcluded, false);
  }
});

// ---------------------------------------------------------------------------------------------
// Slice 4, Decision 2b / must-fix 3 — emitSessionAlertSignals: deterministic, non-LLM local
// delivery for the fail-closed session.* rule_ids.
// ---------------------------------------------------------------------------------------------

test("emitSessionAlertSignals delivers a due session.count_drop through deliverNotificationDecision with a counts/hash-only body, never via a session/LLM", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const sessionAlert = alert({
    id: "alert_session_count_drop",
    rule_id: SESSION_COUNT_DROP_RULE_ID,
    severity: "critical",
    diagnostics: { observed_count: 0, mean_before: 20, stddev_before: 0.5, z_score: -40, confidence_state: "established" },
  });
  const result = await emitSessionAlertSignals(paths, { alerts: [sessionAlert], notification_due_ids: [sessionAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, [sessionAlert.id]);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].opts.ruleId, SESSION_COUNT_DROP_RULE_ID);
  assert.equal(deliveries[0].opts.alertId, sessionAlert.id);
  assert.equal(deliveries[0].decision.notify, true);
  assert.equal(deliveries[0].decision.severity, "critical");
  assert.equal(/deploy-worker|first-ever-session/.test(JSON.stringify(deliveries[0].decision)), false, "no raw session name in the delivered body");
  assert.match(deliveries[0].decision.body, /^Session count 0 vs baseline mean 20/);
});

test("emitSessionAlertSignals delivers a due session.churn through deliverNotificationDecision with a hash-only body", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const churnAlert = alert({
    id: "alert_session_churn",
    rule_id: SESSION_CHURN_RULE_ID,
    severity: "warning",
    diagnostics: { entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" },
  });
  const result = await emitSessionAlertSignals(paths, { alerts: [churnAlert], notification_due_ids: [churnAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, [churnAlert.id]);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].opts.ruleId, SESSION_CHURN_RULE_ID);
  assert.match(deliveries[0].decision.body, /session\.tmux\.aaaaaaaaaaaaaaaa/);
  assert.match(deliveries[0].decision.body, /1{16}/);
  assert.match(deliveries[0].decision.body, /2{16}/);
});

test("emitSessionAlertSignals fires ONLY for session.* rule_ids — a due non-session alert (even if present alongside a due session alert) is never delivered by this branch", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const sessionAlert = alert({ id: "alert_session_count_drop", rule_id: SESSION_COUNT_DROP_RULE_ID, severity: "warning", diagnostics: { observed_count: 5, mean_before: 20, stddev_before: 0.5, z_score: -4, confidence_state: "established" } });
  const metricAlert = alert({ id: "alert_memory", rule_id: "system.memory.sustained_high", severity: "warning" });
  const result = await emitSessionAlertSignals(paths, { alerts: [sessionAlert, metricAlert], notification_due_ids: [sessionAlert.id, metricAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, [sessionAlert.id]);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].ruleId, SESSION_COUNT_DROP_RULE_ID);
});

test("emitSessionAlertSignals respects cooldown: an alert absent from notification_due_ids (a second tick within the cooldown window, per applyAlertCandidates) does not re-deliver", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const sessionAlert = alert({ id: "alert_session_count_drop", rule_id: SESSION_COUNT_DROP_RULE_ID, severity: "warning", diagnostics: { observed_count: 5, mean_before: 20, stddev_before: 0.5, z_score: -4, confidence_state: "established" } });
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; };

  const first = await emitSessionAlertSignals(paths, { alerts: [sessionAlert], notification_due_ids: [sessionAlert.id] }, { now: "2026-07-14T00:01:00.000Z", deliverNotification });
  assert.deepEqual(first.fired, [sessionAlert.id]);

  // A second tick within cooldown: applyAlertCandidates would NOT include this id in
  // notification_due_ids again (see alert-store.js's notificationDue) — simulated here directly.
  const second = await emitSessionAlertSignals(paths, { alerts: [sessionAlert], notification_due_ids: [] }, { now: "2026-07-14T00:05:00.000Z", deliverNotification });
  assert.deepEqual(second.fired, []);
  assert.equal(deliveries.length, 1, "must not re-deliver within the cooldown window");
});

test("emitSessionAlertSignals: last_notified/cooldown_until being present on the alert record is NOT itself treated as delivery evidence — only an actual deliverNotification call counts", async () => {
  const paths = await tempPaths();
  let deliverCalled = false;
  // An alert record that ALREADY carries last_notified/cooldown_until (as applyAlertCandidates
  // stamps on every processed candidate, whether or not anything was actually delivered) but is
  // NOT present in notification_due_ids for this tick.
  const sessionAlert = alert({
    id: "alert_session_count_drop",
    rule_id: SESSION_COUNT_DROP_RULE_ID,
    severity: "warning",
    last_notified: "2026-07-14T00:00:00.000Z",
    cooldown_until: "2026-07-14T00:15:00.000Z",
    diagnostics: { observed_count: 5, mean_before: 20, stddev_before: 0.5, z_score: -4, confidence_state: "established" },
  });
  const result = await emitSessionAlertSignals(paths, { alerts: [sessionAlert], notification_due_ids: [] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async () => { deliverCalled = true; return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, []);
  assert.equal(deliverCalled, false, "a stamped last_notified/cooldown_until must not be mistaken for delivery");
});

test("emitSessionAlertSignals: zero due ids -> [] with no deliverNotification call at all", async () => {
  const paths = await tempPaths();
  let deliverCalled = false;
  const result = await emitSessionAlertSignals(paths, { alerts: [], notification_due_ids: [] }, {
    deliverNotification: async () => { deliverCalled = true; },
  });
  assert.deepEqual(result, { fired: [] });
  assert.equal(deliverCalled, false);
});

test("DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS matches the two session rule_ids exactly, both classifying to unknown_namespace", () => {
  assert.deepEqual(DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]);
  for (const ruleId of DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS) {
    assert.equal(classifyAlertNamespace(ruleId).namespace, undefined);
  }
});

// ---------------------------------------------------------------------------------------------
// Slice 4b (observed-incident collectors plan) — Decision 3 fail-closed namespace regression
// tests + Decision 3b widened deterministic-delivery tests, for peer.count_spike.
// ---------------------------------------------------------------------------------------------

test("(a) classifyAlertNamespace('peer.count_spike') returns {namespace: undefined, hardExcluded: false} -- not 'baseline', not any other known namespace", () => {
  assert.deepEqual(classifyAlertNamespace(PEER_COUNT_SPIKE_RULE_ID), { namespace: undefined, hardExcluded: false });
});

test("(b') a full adjudicateAlertNotifications run, with ALL of KNOWN_ALERT_NAMESPACES enabled and one due peer.count_spike, is no_eligible_alerts / excluded.unknown_namespace / zero LLM calls", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, enabled_namespaces: [...KNOWN_ALERT_NAMESPACES] }, { now: "2026-07-14T00:00:00.000Z" });
  const peerAlert = alert({ id: "alert_peer_count_spike", rule_id: PEER_COUNT_SPIKE_RULE_ID, severity: "warning", diagnostics: { observed_count: 8, mean_before: 2, stddev_before: 0.5, z_score: 12, confidence_state: "established" } });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [peerAlert],
    notification_due_ids: [peerAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async () => { throw new Error("must never create a session for peer.count_spike — it is unknown_namespace, fail-closed"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.unknown_namespace, 1);
  assert.equal((await readAlertIntelligenceAudit(paths)).length, 0);
});

test("(c) invariant: every exported PEER_*_RULE_ID classifies to namespace undefined -- a future peer-family rule_id inherits fail-closed by construction", () => {
  for (const ruleId of [PEER_COUNT_SPIKE_RULE_ID]) {
    const { namespace, hardExcluded } = classifyAlertNamespace(ruleId);
    assert.equal(namespace, undefined, `expected ${ruleId} to classify as unknown_namespace`);
    assert.equal(hardExcluded, false);
  }
});

test("emitSessionAlertSignals delivers a due peer.count_spike through deliverNotificationDecision with a counts/hash-only body, never via a session/LLM", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const peerAlert = alert({
    id: "alert_peer_count_spike",
    rule_id: PEER_COUNT_SPIKE_RULE_ID,
    severity: "warning",
    diagnostics: { observed_count: 8, mean_before: 2, stddev_before: 0.5, z_score: 12, confidence_state: "established" },
  });
  const result = await emitSessionAlertSignals(paths, { alerts: [peerAlert], notification_due_ids: [peerAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, [peerAlert.id]);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].opts.ruleId, PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(deliveries[0].opts.alertId, peerAlert.id);
  assert.equal(deliveries[0].decision.notify, true);
  assert.equal(deliveries[0].decision.severity, "warning");
  assert.match(deliveries[0].decision.body, /^Peer count 8 vs baseline mean 2/);
  assert.equal(/203\.0\.113|alice|peer\.ssh\./.test(JSON.stringify(deliveries[0].decision)), false, "no raw peer host/IP/pubkey in the delivered body");
});

test("emitSessionAlertSignals: even a wildly extreme z, a due peer.count_spike still delivers with stored severity 'warning' (never 'critical' in v0, MUST-FIX 1)", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const peerAlert = alert({
    id: "alert_peer_count_spike",
    rule_id: PEER_COUNT_SPIKE_RULE_ID,
    severity: "warning", // peer-baseline.js's own candidate builder never stores "critical" in v0
    diagnostics: { observed_count: 100, mean_before: 2, stddev_before: 0.5, z_score: 196, confidence_state: "established" },
  });
  await emitSessionAlertSignals(paths, { alerts: [peerAlert], notification_due_ids: [peerAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });
  assert.equal(deliveries[0].decision.severity, "warning");
});

test("emitSessionAlertSignals fires for the WIDENED allowlist: a mix of due session.count_drop/session.churn/peer.count_spike alongside a due non-allowlisted metric alert delivers exactly the three allowlisted ones, without cross-contaminating each other's body text", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const dropAlert = alert({ id: "alert_drop", rule_id: SESSION_COUNT_DROP_RULE_ID, severity: "critical", diagnostics: { observed_count: 0, mean_before: 20, stddev_before: 0.5, z_score: -40, confidence_state: "established" } });
  const churnAlert = alert({ id: "alert_churn", rule_id: SESSION_CHURN_RULE_ID, severity: "warning", diagnostics: { entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" } });
  const peerAlert = alert({ id: "alert_peer", rule_id: PEER_COUNT_SPIKE_RULE_ID, severity: "warning", diagnostics: { observed_count: 8, mean_before: 2, stddev_before: 0.5, z_score: 12, confidence_state: "established" } });
  const metricAlert = alert({ id: "alert_metric", rule_id: "system.memory.sustained_high", severity: "warning" });

  const result = await emitSessionAlertSignals(paths, {
    alerts: [dropAlert, churnAlert, peerAlert, metricAlert],
    notification_due_ids: [dropAlert.id, churnAlert.id, peerAlert.id, metricAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push({ decision, opts }); return { status: "recorded" }; },
  });

  assert.deepEqual(new Set(result.fired), new Set([dropAlert.id, churnAlert.id, peerAlert.id]));
  assert.equal(deliveries.length, 3, "the non-allowlisted metric alert must never be delivered by this branch");
  assert.equal(deliveries.some((d) => d.opts.ruleId === "system.memory.sustained_high"), false);

  const byRuleId = Object.fromEntries(deliveries.map((d) => [d.opts.ruleId, d.decision.body]));
  assert.match(byRuleId[SESSION_COUNT_DROP_RULE_ID], /^Session count 0 vs baseline mean 20/);
  assert.match(byRuleId[SESSION_CHURN_RULE_ID], /session\.tmux\.aaaaaaaaaaaaaaaa/);
  assert.match(byRuleId[PEER_COUNT_SPIKE_RULE_ID], /^Peer count 8 vs baseline mean 2/);
  // No cross-contamination: the peer body never carries session-shaped text and vice versa.
  assert.equal(/session\.tmux/.test(byRuleId[PEER_COUNT_SPIKE_RULE_ID]), false);
  assert.equal(/Peer count/.test(byRuleId[SESSION_COUNT_DROP_RULE_ID]), false);
});

test("emitSessionAlertSignals fires ONLY for the allowlisted rule_ids — a due peer.count_spike-shaped rule_id typo is never delivered by this branch", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const typoAlert = alert({ id: "alert_typo", rule_id: "peer.count_spikes", severity: "warning" }); // deliberately NOT the real rule_id
  const result = await emitSessionAlertSignals(paths, { alerts: [typoAlert], notification_due_ids: [typoAlert.id] }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; },
  });
  assert.deepEqual(result.fired, []);
  assert.equal(deliveries.length, 0);
});

test("emitSessionAlertSignals respects cooldown for peer.count_spike too: an alert absent from notification_due_ids does not re-deliver", async () => {
  const paths = await tempPaths();
  const deliveries = [];
  const peerAlert = alert({ id: "alert_peer_count_spike", rule_id: PEER_COUNT_SPIKE_RULE_ID, severity: "warning", diagnostics: { observed_count: 8, mean_before: 2, stddev_before: 0.5, z_score: 12, confidence_state: "established" } });
  const deliverNotification = async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; };

  const first = await emitSessionAlertSignals(paths, { alerts: [peerAlert], notification_due_ids: [peerAlert.id] }, { now: "2026-07-14T00:01:00.000Z", deliverNotification });
  assert.deepEqual(first.fired, [peerAlert.id]);

  const second = await emitSessionAlertSignals(paths, { alerts: [peerAlert], notification_due_ids: [] }, { now: "2026-07-14T00:05:00.000Z", deliverNotification });
  assert.deepEqual(second.fired, []);
  assert.equal(deliveries.length, 1, "must not re-deliver within the cooldown window");
});

test("Fable review MUST-FIX 4: the widened ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS constant used by delivery is composed of session-baseline.js's own two-id export PLUS PEER_COUNT_SPIKE_RULE_ID (companion to the two shipped allowlist tests at session-baseline.test.js:677-678 and this file's own two-id test above, neither of which is widened)", async () => {
  // There is no direct export of the module-private ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS
  // constant (deliberately private to alert-intelligence.js) -- pin its effective composition via
  // the same public seam every other test in this section already uses: a single
  // emitSessionAlertSignals call carrying one due alert per candidate id, asserting each is
  // delivered, PLUS the unchanged two-id session-baseline.js export used to derive the expected
  // three-id set here (so this test breaks loudly if a future edit widens or shrinks either side).
  const expectedIds = [...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, PEER_COUNT_SPIKE_RULE_ID];
  assert.deepEqual(expectedIds, [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID, PEER_COUNT_SPIKE_RULE_ID]);

  const paths = await tempPaths();
  const deliveries = [];
  const alerts = expectedIds.map((ruleId, index) => alert({ id: `alert_${index}`, rule_id: ruleId, severity: "warning", diagnostics: { observed_count: 1, mean_before: 1, stddev_before: 0.5, z_score: 1, confidence_state: "established", entity_key: "session.tmux.aaaaaaaaaaaaaaaa", prior_fingerprint: "1111111111111111", current_fingerprint: "2222222222222222" } }));
  const result = await emitSessionAlertSignals(paths, { alerts, notification_due_ids: alerts.map((a) => a.id) }, {
    now: "2026-07-14T00:01:00.000Z",
    deliverNotification: async (descartesPaths, decision, opts) => { deliveries.push(opts); return { status: "recorded" }; },
  });
  assert.deepEqual(new Set(result.fired), new Set(alerts.map((a) => a.id)));
  assert.equal(deliveries.length, expectedIds.length, "every id in the composed three-id constant must actually be delivered by this branch");
});

// ---------------------------------------------------------------------------------------------
// Slice 6 (observed-incident collectors plan) — the new, real, default-off "correlation"
// namespace. Unlike session.*'s permanent unknown_namespace, "correlation" is a genuine,
// registered, consentable namespace: classified, but excluded by DEFAULT_ENABLED_NAMESPACES
// until the operator explicitly opts in.
// ---------------------------------------------------------------------------------------------

function extractPromptContext(promptText) {
  const match = promptText.match(/Context:\n([\s\S]*?)\n\nReturn only valid JSON/);
  assert.ok(match, "expected a Context JSON block in the prompt");
  return JSON.parse(match[1]);
}

test("classifyAlertNamespace('correlation.login_kill_proximity') classifies as the new, real 'correlation' namespace (not hard-excluded, not unknown)", () => {
  assert.deepEqual(classifyAlertNamespace(CORRELATION_RULE_ID), { namespace: "correlation", hardExcluded: false });
});

test("KNOWN_ALERT_NAMESPACES gained 'correlation'; DEFAULT_ENABLED_NAMESPACES stays exactly ['metric'] — structural default-off, not a documentation promise", () => {
  assert.ok(KNOWN_ALERT_NAMESPACES.includes("correlation"));
  assert.deepEqual(DEFAULT_ENABLED_NAMESPACES, ["metric"]);
});

test("Slice 6: with default config (metric-only), a due correlation.* candidate is NOT LLM-eligible — status not_consented, zero sessions, zero audit records", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5 }, { now: "2026-07-14T00:00:00.000Z" });
  const correlationAlert = alert({
    id: "alert_correlation",
    rule_id: CORRELATION_RULE_ID,
    severity: "warning",
    diagnostics: {
      kill_rule_id: SESSION_COUNT_DROP_RULE_ID,
      anchor_fingerprint: "global",
      peer_entity_key: "peer.wireguard.9999999999999999",
      peer_source_type: "wireguard",
      peer_observed_hour_bucket: "02",
      proximity_seconds: 60,
      peer_novelty_prior_tick_count: 0,
      candidate_pool_size: 1,
      anchor_severity: "critical",
    },
  });
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [correlationAlert],
    notification_due_ids: [correlationAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async () => { throw new Error("must not create a session for an un-consented correlation candidate"); },
  });
  assert.equal(result.status, "no_eligible_alerts");
  assert.equal(result.excluded.not_consented, 1);
  assert.equal((await readAlertIntelligenceAudit(paths)).length, 0);
});

test("Slice 6: only after enable-namespace correlation (enabled_namespaces includes 'correlation') does a due correlation.* candidate become LLM-eligible, adjudicated exactly once via buildCorrelationAlertPrompt", async () => {
  const paths = await tempPaths();
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 5, enabled_namespaces: ["metric", "correlation"] }, { now: "2026-07-14T00:00:00.000Z" });
  const correlationAlert = alert({
    id: "alert_correlation",
    rule_id: CORRELATION_RULE_ID,
    severity: "warning",
    diagnostics: {
      kill_rule_id: SESSION_COUNT_DROP_RULE_ID,
      anchor_fingerprint: "global",
      peer_entity_key: "peer.wireguard.9999999999999999",
      peer_source_type: "wireguard",
      peer_observed_hour_bucket: "02",
      proximity_seconds: 60,
      peer_novelty_prior_tick_count: 0,
      candidate_pool_size: 3,
      anchor_severity: "critical",
    },
  });
  const prompts = [];
  let sessionCreateCount = 0;
  const result = await adjudicateAlertNotifications(paths, {
    alerts: [correlationAlert],
    notification_due_ids: [correlationAlert.id],
  }, {
    now: "2026-07-14T00:01:00.000Z",
    createSession: async (...args) => {
      sessionCreateCount += 1;
      return fakeCreateSession(prompts, { notify: false })(...args);
    },
  });
  assert.equal(result.status, "ok");
  assert.equal(sessionCreateCount, 1, "exactly one session must be constructed");
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /"correlation" learned-artifact family woke you up/);
  assert.match(prompts[0], /DETERMINISTIC TEMPORAL CORRELATION/);
  assert.match(prompts[0], /"namespace": "correlation"/);
  const audit = await readAlertIntelligenceAudit(paths);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].namespace, "correlation");
  assert.equal(audit[0].status, "ok");
});

test("Slice 6: buildCorrelationAlertPrompt's hard rules cover causation, the novelty-count's real meaning, and the observed-hour-bucket-is-not-a-login-instant distinction (must-fixes 2/6, prompt-side)", () => {
  const correlationAlert = alert({ id: "alert_correlation", rule_id: CORRELATION_RULE_ID, severity: "warning" });
  const prompt = alertIntelligencePrompt({ alerts: [correlationAlert] });
  assert.match(prompt, /DETERMINISTIC TEMPORAL CORRELATION/);
  assert.match(prompt, /not proof of a causal/);
  assert.match(prompt, /causally connected\./);
  assert.match(prompt, /candidate_pool_size in the context indicates/);
  assert.match(prompt, /RARELY OBSERVED RECENTLY/);
  assert.match(prompt, /"unauthenticated," "unauthorized,"/);
  assert.match(prompt, /attribution" -- describe it only as infrequently observed/);
  assert.match(prompt, /OBSERVATION TICK/);
  assert.match(prompt, /Describe it as "observed at/);
  assert.match(prompt, /NEVER as "logged in at hour X\."/);
  assert.match(prompt, /Treat the value "unknown" as no signal at all/);
});

test("Slice 6: single-alert-per-prompt guard still holds for the correlation namespace", () => {
  const first = alert({ id: "alert_correlation_a", rule_id: CORRELATION_RULE_ID, fingerprint: "one" });
  const second = alert({ id: "alert_correlation_b", rule_id: CORRELATION_RULE_ID, fingerprint: "two" });
  assert.throws(() => alertIntelligencePrompt({ alerts: [first, second] }), /requires exactly one alert, got 2/);
});

// ---------------------------------------------------------------------------------------------
// Slice 6, Decision 3 / Fable review must-fix 1: compactAlert's defense-in-depth
// sanitizeDiagnostics() re-run. NOT a no-op for every existing family — see the corrected fixtures
// below (undefined-value, already-redacted-marker), and the one true no-op case (already-safe
// values, including an ISO-8601 timestamp).
// ---------------------------------------------------------------------------------------------

test("Slice 6 must-fix 1: compactAlert's re-sanitization round-trips an already-safe diagnostics object (numbers, closed-enum strings, a hex hash, and an ISO-8601 newest_sample_ts) byte-identical — the one true no-op case", () => {
  const staleAlert = alert({
    id: "alert_stale",
    rule_id: "daemon.samples.stale",
    severity: "warning",
    diagnostics: {
      newest_sample_ts: "2026-05-28T00:01:00.000Z",
      stale_ms: 300000,
      age_ms: 900000,
      confidence_state: "established",
      short_hash: "a3f2b8c9d1e4f567",
    },
  });
  const prompt = alertIntelligencePrompt({ alerts: [staleAlert] });
  const context = extractPromptContext(prompt);
  assert.deepEqual(context.alerts[0].diagnostics, staleAlert.diagnostics);
});

test("Slice 6 must-fix 1: compactAlert's re-sanitization surfaces a NEW redaction marker for an undefined-valued diagnostics key (daemon.samples.missing's real window_ms:undefined shape) — documented as a real behavior change, not a no-op", () => {
  const missingAlert = alert({
    id: "alert_missing",
    rule_id: "daemon.samples.missing",
    severity: "warning",
    diagnostics: { window_ms: undefined, point_count: 0 },
  });
  const prompt = alertIntelligencePrompt({ alerts: [missingAlert] });
  const context = extractPromptContext(prompt);
  assert.equal(context.alerts[0].diagnostics.window_ms.redacted, true);
  assert.equal(context.alerts[0].diagnostics.window_ms.reason, "unsupported_type");
  assert.equal(context.alerts[0].diagnostics.point_count, 0);
});

test("Slice 6 must-fix 1(ii): compactAlert's re-sanitization passes an already-well-formed redaction marker through UNCHANGED, preserving its original reason and original_length rather than rewriting it to a generic unsupported_type marker", () => {
  const alreadyRedacted = { redacted: true, reason: "unsafe_string_shape", original_length: 12 };
  const hostnameAlert = alert({
    id: "alert_identity",
    rule_id: "provenance.process.unknown_identity",
    severity: "warning",
    diagnostics: { owner: alreadyRedacted, identity_hash: "abc123def4567890" },
  });
  const prompt = alertIntelligencePrompt({ alerts: [hostnameAlert] });
  const context = extractPromptContext(prompt);
  assert.deepEqual(context.alerts[0].diagnostics.owner, alreadyRedacted);
  assert.equal(context.alerts[0].diagnostics.identity_hash, "abc123def4567890");
});

test("Slice 6, Decision 3 negative test: compactAlert's re-sanitization redacts an unsafe (space/slash-shaped) diagnostics value that bypassed write-time sanitization, before it would ever reach the rendered prompt text", () => {
  const unsafeValue = "rm -rf /tmp/data --force --user=alice";
  const leakyAlert = alert({
    id: "alert_leaky",
    rule_id: "provenance.process.unknown_identity",
    severity: "warning",
    diagnostics: { args: unsafeValue },
  });
  const prompt = alertIntelligencePrompt({ alerts: [leakyAlert] });
  assert.equal(prompt.includes(unsafeValue), false, "the raw unsafe value must never reach the rendered prompt text");
  const context = extractPromptContext(prompt);
  assert.equal(context.alerts[0].diagnostics.args.redacted, true);
});
