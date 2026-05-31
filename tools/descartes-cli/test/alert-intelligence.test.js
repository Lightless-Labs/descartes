import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  adjudicateAlertNotifications,
  alertIntelligencePrompt,
  normalizeAlertNotificationDecision,
  readAlertIntelligenceAudit,
  readAlertIntelligenceConfig,
  resolveAlertIntelligencePaths,
  writeAlertIntelligenceConfig,
} from "../src/alert-intelligence.js";
import { resolveDescartesPaths } from "../src/paths.js";

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
  await writeAlertIntelligenceConfig(paths, { enabled: true, max_calls_per_hour: 1 }, { now: "2026-05-28T00:00:00.000Z" });

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
