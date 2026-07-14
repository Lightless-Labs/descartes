import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION,
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
import { readNotificationDeliveryAudit } from "../src/notification-delivery.js";
import { resolveDescartesPaths } from "../src/paths.js";
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
