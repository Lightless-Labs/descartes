import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { buildHistorySummary, readDaemonStatus } from "./history-store.js";

export const DEFAULT_ALERT_COOLDOWN_MS = 15 * 60 * 1000;
export const DEFAULT_ALERT_WINDOW_MS = 15 * 60 * 1000;

export function resolveAlertStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "alerts");
  return {
    dir,
    alertsFile: path.join(dir, "alerts.json"),
  };
}

async function ensureAlertDir(descartesPaths) {
  await fs.mkdir(resolveAlertStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, fieldName = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid alert ${fieldName}: ${ts}`);
  return date.toISOString();
}

function alertId(ruleId, fingerprint = "global") {
  const digest = crypto.createHash("sha256").update(`${ruleId}\0${fingerprint}`).digest("hex").slice(0, 16);
  return `alert_${digest}`;
}

function metricByName(summary) {
  return new Map((summary?.metrics ?? []).map((metric) => [metric.metric_name, metric]));
}

function newestMetricTimestamp(summary) {
  const timestamps = (summary?.metrics ?? [])
    .map((metric) => new Date(metric.last_ts).getTime())
    .filter(Number.isFinite);
  return timestamps.length > 0 ? Math.max(...timestamps) : undefined;
}

function formatPercent(value) {
  return `${(Number(value) * 100).toFixed(0)}%`;
}

function pushCandidate(candidates, candidate) {
  const fingerprint = candidate.fingerprint ?? "global";
  candidates.push({
    id: alertId(candidate.rule_id, fingerprint),
    fingerprint,
    evidence_refs: ["history-summary"],
    ...candidate,
  });
}

export function evaluateAlertRules(historySummary, daemonStatus, options = {}) {
  const now = new Date(options.now ?? historySummary?.until ?? Date.now());
  const nowMs = now.getTime();
  const thresholds = {
    memoryUsedFraction: 0.9,
    loadPerCpu: 1.5,
    diskWarningFraction: 0.9,
    diskCriticalFraction: 0.95,
    minSustainedSamples: 2,
    daemonDefaultStaleMs: 5 * 60 * 1000,
    ...options.thresholds,
  };
  const candidates = [];
  const metrics = metricByName(historySummary);
  const intervalMs = Number(daemonStatus?.profile?.interval_ms);
  const staleMs = Math.max(thresholds.daemonDefaultStaleMs, Number.isFinite(intervalMs) ? intervalMs * 3 : 0);
  const newestMetricMs = newestMetricTimestamp(historySummary);
  const daemonStatusMs = daemonStatus?.ts ? new Date(daemonStatus.ts).getTime() : undefined;

  if (!daemonStatus) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.missing",
      severity: "warning",
      title: "Daemon status is missing",
      summary: "No local history daemon status record is available.",
      diagnostics: { reason: "missing_daemon_status" },
    });
  } else if (daemonStatus.state && !["ok", "stopped"].includes(daemonStatus.state)) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.not_ok",
      severity: "warning",
      title: "Daemon status is not ok",
      summary: `Local history daemon reported state ${daemonStatus.state}.`,
      diagnostics: { state: daemonStatus.state },
    });
  }

  if ((historySummary?.point_count ?? 0) === 0) {
    pushCandidate(candidates, {
      rule_id: "daemon.samples.missing",
      severity: "warning",
      title: "No recent metric samples",
      summary: "No local metric history points are available in the alert evaluation window.",
      diagnostics: { window_ms: historySummary?.window_ms, point_count: historySummary?.point_count ?? 0 },
    });
  } else if (Number.isFinite(newestMetricMs) && nowMs - newestMetricMs > staleMs) {
    pushCandidate(candidates, {
      rule_id: "daemon.samples.stale",
      severity: "warning",
      title: "Metric samples are stale",
      summary: `Newest local metric sample is older than ${Math.round(staleMs / 1000)}s.`,
      diagnostics: { newest_sample_ts: new Date(newestMetricMs).toISOString(), stale_ms: staleMs, age_ms: nowMs - newestMetricMs },
    });
  } else if (Number.isFinite(daemonStatusMs) && nowMs - daemonStatusMs > staleMs) {
    pushCandidate(candidates, {
      rule_id: "daemon.status.stale",
      severity: "warning",
      title: "Daemon status is stale",
      summary: `Local history daemon status is older than ${Math.round(staleMs / 1000)}s.`,
      diagnostics: { daemon_status_ts: new Date(daemonStatusMs).toISOString(), stale_ms: staleMs, age_ms: nowMs - daemonStatusMs },
    });
  }

  const memory = metrics.get("system.memory.used_fraction");
  if (memory?.count >= thresholds.minSustainedSamples && memory.min >= thresholds.memoryUsedFraction) {
    pushCandidate(candidates, {
      rule_id: "system.memory.sustained_high",
      severity: memory.min >= 0.95 ? "critical" : "warning",
      title: "Sustained high memory pressure",
      summary: `Memory used stayed at or above ${formatPercent(thresholds.memoryUsedFraction)} for ${memory.count} samples.`,
      diagnostics: { min: memory.min, mean: memory.mean, max: memory.max, count: memory.count, threshold: thresholds.memoryUsedFraction },
    });
  }

  const load = metrics.get("system.load.1m");
  const cpuCount = metrics.get("system.cpu.count")?.last;
  if (load?.count >= thresholds.minSustainedSamples && Number.isFinite(cpuCount) && cpuCount > 0) {
    const threshold = Number(cpuCount) * thresholds.loadPerCpu;
    if (load.min >= threshold) {
      pushCandidate(candidates, {
        rule_id: "system.load.sustained_high",
        severity: load.min >= threshold * 2 ? "critical" : "warning",
        title: "Sustained high system load",
        summary: `1m load stayed above ${threshold.toFixed(2)} (${thresholds.loadPerCpu}× CPU count) for ${load.count} samples.`,
        diagnostics: { min: load.min, mean: load.mean, max: load.max, count: load.count, cpu_count: cpuCount, threshold },
      });
    }
  }

  const disk = metrics.get("disk.used_fraction");
  if (disk?.max >= thresholds.diskWarningFraction) {
    const critical = disk.max >= thresholds.diskCriticalFraction;
    pushCandidate(candidates, {
      rule_id: "disk.space.high_used_fraction",
      severity: critical ? "critical" : "warning",
      title: critical ? "Critical disk pressure" : "High disk pressure",
      summary: `At least one pressure-relevant filesystem reached ${formatPercent(disk.max)} used.`,
      diagnostics: { max: disk.max, mean: disk.mean, dimensions_seen: disk.dimensions_seen, threshold: critical ? thresholds.diskCriticalFraction : thresholds.diskWarningFraction },
    });
  }

  return candidates;
}

export function normalizeAlertRecord(record) {
  if (!record || typeof record !== "object") throw new Error("Alert record must be an object");
  const ruleId = String(record.rule_id ?? "").trim();
  if (!ruleId) throw new Error("Alert record requires rule_id");
  const fingerprint = String(record.fingerprint ?? "global");
  const firstSeen = normalizeIso(record.first_seen ?? record.last_seen ?? new Date().toISOString(), "first_seen");
  const lastSeen = normalizeIso(record.last_seen ?? firstSeen, "last_seen");
  return {
    id: String(record.id ?? alertId(ruleId, fingerprint)),
    rule_id: ruleId,
    fingerprint,
    status: ["active", "recovered", "acknowledged", "suppressed"].includes(record.status) ? record.status : "active",
    severity: ["info", "warning", "critical"].includes(record.severity) ? record.severity : "warning",
    title: String(record.title ?? ruleId),
    summary: String(record.summary ?? ""),
    evidence_refs: Array.isArray(record.evidence_refs) ? record.evidence_refs.map(String).slice(0, 16) : [],
    first_seen: firstSeen,
    last_seen: lastSeen,
    last_notified: record.last_notified ? normalizeIso(record.last_notified, "last_notified") : null,
    cooldown_until: record.cooldown_until ? normalizeIso(record.cooldown_until, "cooldown_until") : null,
    acknowledged_at: record.acknowledged_at ? normalizeIso(record.acknowledged_at, "acknowledged_at") : null,
    diagnostics: record.diagnostics && typeof record.diagnostics === "object" && !Array.isArray(record.diagnostics) ? record.diagnostics : {},
  };
}

export async function readAlertRecords(descartesPaths) {
  const { alertsFile } = resolveAlertStorePaths(descartesPaths);
  try {
    const parsed = JSON.parse(await fs.readFile(alertsFile, "utf8"));
    const rawAlerts = Array.isArray(parsed) ? parsed : parsed.alerts;
    return (rawAlerts ?? []).map(normalizeAlertRecord);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

export async function writeAlertRecords(descartesPaths, alerts) {
  await ensureAlertDir(descartesPaths);
  const { alertsFile } = resolveAlertStorePaths(descartesPaths);
  const normalized = alerts.map(normalizeAlertRecord).sort((left, right) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    if ((severityOrder[left.severity] ?? 9) !== (severityOrder[right.severity] ?? 9)) return (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
    return right.last_seen.localeCompare(left.last_seen);
  });
  const payload = JSON.stringify({ version: 1, alerts: normalized }, null, 2);
  const tmpFile = `${alertsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, alertsFile);
  return normalized;
}

function notificationDue(alert, nowMs) {
  if (["acknowledged", "suppressed", "recovered"].includes(alert.status)) return false;
  if (!alert.last_notified) return true;
  const cooldownMs = alert.cooldown_until ? new Date(alert.cooldown_until).getTime() : undefined;
  return Number.isFinite(cooldownMs) ? nowMs >= cooldownMs : false;
}

export function applyAlertCandidates(existingAlerts, candidates, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const nowMs = new Date(now).getTime();
  const cooldownMs = options.cooldownMs ?? DEFAULT_ALERT_COOLDOWN_MS;
  const byId = new Map(existingAlerts.map((alert) => [alert.id, normalizeAlertRecord(alert)]));
  const activeCandidateIds = new Set(candidates.map((candidate) => candidate.id));
  const notificationDueIds = [];

  for (const candidate of candidates) {
    const current = byId.get(candidate.id);
    const base = current ?? normalizeAlertRecord({
      ...candidate,
      status: "active",
      first_seen: now,
      last_seen: now,
    });
    const nextStatus = base.status === "acknowledged" || base.status === "suppressed" ? base.status : "active";
    const next = normalizeAlertRecord({
      ...base,
      ...candidate,
      status: nextStatus,
      first_seen: base.first_seen,
      last_seen: now,
      acknowledged_at: nextStatus === "acknowledged" ? base.acknowledged_at : null,
      last_notified: base.last_notified,
      cooldown_until: base.cooldown_until,
    });
    if (notificationDue(next, nowMs)) {
      next.last_notified = now;
      next.cooldown_until = new Date(nowMs + cooldownMs).toISOString();
      notificationDueIds.push(next.id);
    }
    byId.set(next.id, next);
  }

  for (const [id, alert] of byId) {
    if (!activeCandidateIds.has(id) && ["active", "acknowledged"].includes(alert.status)) {
      byId.set(id, normalizeAlertRecord({
        ...alert,
        status: "recovered",
        last_seen: now,
      }));
    }
  }

  return {
    alerts: [...byId.values()],
    notification_due_ids: notificationDueIds,
  };
}

export async function evaluateAndPersistAlerts(descartesPaths, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const [historySummary, daemonStatus, existing] = await Promise.all([
    options.historySummary ? Promise.resolve(options.historySummary) : buildHistorySummary(descartesPaths, { now, windowMs: options.windowMs ?? DEFAULT_ALERT_WINDOW_MS, limit: options.limit }),
    options.daemonStatus ? Promise.resolve(options.daemonStatus) : readDaemonStatus(descartesPaths),
    readAlertRecords(descartesPaths),
  ]);
  const candidates = evaluateAlertRules(historySummary, daemonStatus, { now, thresholds: options.thresholds });
  const applied = applyAlertCandidates(existing, candidates, { now, cooldownMs: options.cooldownMs });
  const alerts = await writeAlertRecords(descartesPaths, applied.alerts);
  return { alerts, candidates, history_summary: historySummary, daemon_status: daemonStatus ?? null, notification_due_ids: applied.notification_due_ids };
}

export async function acknowledgeAlert(descartesPaths, alertId, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let found = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertId) return alert;
    found = true;
    return normalizeAlertRecord({ ...alert, status: "acknowledged", acknowledged_at: now });
  });
  if (!found) throw new Error(`Alert not found: ${alertId}`);
  return (await writeAlertRecords(descartesPaths, updated)).find((alert) => alert.id === alertId);
}
