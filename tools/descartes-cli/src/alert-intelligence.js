import fs from "node:fs/promises";
import path from "node:path";

export const DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR = 3;

export function resolveAlertIntelligencePaths(descartesPaths) {
  return {
    configFile: path.join(descartesPaths.configDir, "alert-intelligence.json"),
    auditFile: path.join(descartesPaths.stateDir, "alerts", "llm-decisions.jsonl"),
  };
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid alert intelligence ${field}: ${ts}`);
  return date.toISOString();
}

export function normalizeAlertIntelligenceConfig(config = {}) {
  const maxCallsPerHour = Number(config.max_calls_per_hour ?? DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR);
  return {
    enabled: config.enabled === true,
    model_pattern: config.model_pattern ? String(config.model_pattern) : undefined,
    thinking_level: config.thinking_level ? String(config.thinking_level) : undefined,
    max_calls_per_hour: Number.isFinite(maxCallsPerHour) && maxCallsPerHour >= 0 ? Math.floor(maxCallsPerHour) : DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR,
    include_history_summary: config.include_history_summary !== false,
    include_daemon_status: config.include_daemon_status !== false,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

export async function readAlertIntelligenceConfig(descartesPaths) {
  const { configFile } = resolveAlertIntelligencePaths(descartesPaths);
  try {
    return normalizeAlertIntelligenceConfig(JSON.parse(await fs.readFile(configFile, "utf8")));
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeAlertIntelligenceConfig();
    throw error;
  }
}

export async function writeAlertIntelligenceConfig(descartesPaths, config, options = {}) {
  const { configFile } = resolveAlertIntelligencePaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeAlertIntelligenceConfig({ ...config, updated_at: options.now ?? new Date().toISOString() });
  const tmp = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmp, configFile);
  return normalized;
}

function clampString(value, max = 320) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function normalizeAlertNotificationDecision(decision = {}) {
  return {
    notify: decision.notify === true,
    severity: ["info", "warning", "critical"].includes(decision.severity) ? decision.severity : "info",
    title: clampString(decision.title, 80) || "Descartes alert",
    body: clampString(decision.body, 240) || "Descartes noticed a local system alert.",
    reason: clampString(decision.reason, 500) || "No reason provided.",
    evidence_refs: Array.isArray(decision.evidence_refs) ? decision.evidence_refs.map(String).slice(0, 12) : [],
    next_check_hint: clampString(decision.next_check_hint, 160),
  };
}

function parseDecisionJson(text) {
  const trimmed = String(text ?? "").trim();
  const unfenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1]?.trim() ?? trimmed;
  try {
    return JSON.parse(unfenced);
  } catch {
    const start = unfenced.indexOf("{");
    const end = unfenced.lastIndexOf("}");
    if (start !== -1 && end > start) return JSON.parse(unfenced.slice(start, end + 1));
    throw new Error("Alert intelligence response was not valid JSON");
  }
}

function contentToText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((block) => block?.type === "text" && typeof block.text === "string" ? block.text : "").join("");
}

function lastAssistantText(messages = []) {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (message?.role === "assistant") {
      const text = contentToText(message.content).trim();
      if (text) return text;
    }
  }
  return "";
}

async function readAuditRecords(descartesPaths) {
  const { auditFile } = resolveAlertIntelligencePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(auditFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const records = [];
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      // Ignore corrupt local audit lines rather than breaking daemon alerting.
    }
  }
  return records;
}

export async function readAlertIntelligenceAudit(descartesPaths) {
  return readAuditRecords(descartesPaths);
}

async function appendAuditRecord(descartesPaths, record) {
  const { auditFile } = resolveAlertIntelligencePaths(descartesPaths);
  await ensureParent(auditFile);
  await fs.appendFile(auditFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return record;
}

function recentCallCount(records, now, windowMs = 60 * 60 * 1000) {
  const nowMs = new Date(now).getTime();
  return records.filter((record) => {
    const tsMs = new Date(record.ts).getTime();
    return Number.isFinite(tsMs) && nowMs - tsMs >= 0 && nowMs - tsMs < windowMs;
  }).length;
}

function compactAlert(alert) {
  return {
    id: alert.id,
    rule_id: alert.rule_id,
    status: alert.status,
    severity: alert.severity,
    title: alert.title,
    summary: alert.summary,
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    diagnostics: alert.diagnostics,
  };
}

function compactHistory(summary) {
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
}

export function alertIntelligencePrompt({ alerts, historySummary, daemonStatus }) {
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
  alerts: alerts.map(compactAlert),
  history_summary: compactHistory(historySummary),
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

export async function adjudicateAlertNotifications(descartesPaths, evaluation, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const config = options.config ?? await readAlertIntelligenceConfig(descartesPaths);
  const dueIds = evaluation?.notification_due_ids ?? [];
  if (!config.enabled) return { status: "disabled", decisions: [] };
  if (dueIds.length === 0) return { status: "no_due_alerts", decisions: [] };

  const audit = await readAuditRecords(descartesPaths);
  const currentCalls = recentCallCount(audit, now);
  const remaining = Math.max(0, config.max_calls_per_hour - currentCalls);
  if (remaining <= 0) {
    return { status: "rate_limited", decisions: [], max_calls_per_hour: config.max_calls_per_hour };
  }

  const dueAlerts = (evaluation.alerts ?? []).filter((alert) => dueIds.includes(alert.id)).slice(0, remaining);
  const createSession = options.createSession ?? (await import("./pi-harness.js")).createPrivateAlertSession;
  const records = [];

  for (const alert of dueAlerts) {
    let session;
    const startedAt = new Date().toISOString();
    try {
      const result = await createSession(descartesPaths, {
        modelPattern: config.model_pattern,
        thinkingLevel: config.thinking_level,
      });
      session = result.session;
      await session.prompt(alertIntelligencePrompt({ alerts: [alert], historySummary: evaluation.history_summary, daemonStatus: evaluation.daemon_status }));
      const rawText = lastAssistantText(session.messages);
      const decision = normalizeAlertNotificationDecision(parseDecisionJson(rawText));
      const deliverNotification = options.deliverNotification ?? (await import("./notification-delivery.js")).deliverNotificationDecision;
      const delivery = decision.notify
        ? await deliverNotification(descartesPaths, decision, { now, alertId: alert.id, ruleId: alert.rule_id })
        : undefined;
      records.push(await appendAuditRecord(descartesPaths, {
        ts: now,
        alert_id: alert.id,
        rule_id: alert.rule_id,
        status: "ok",
        selected_model: result.selectedModel ? { provider: result.selectedModel.provider, id: result.selectedModel.id ?? result.selectedModel.name } : undefined,
        thinking_level: result.selectedThinkingLevel,
        prompt_started_at: startedAt,
        decision,
        delivery,
      }));
    } catch (error) {
      records.push(await appendAuditRecord(descartesPaths, {
        ts: now,
        alert_id: alert.id,
        rule_id: alert.rule_id,
        status: "error",
        error: error instanceof Error ? error.message : String(error),
      }));
    } finally {
      session?.dispose?.();
    }
  }

  return { status: "ok", decisions: records };
}
