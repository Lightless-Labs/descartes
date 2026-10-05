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

export function alertId(ruleId, fingerprint = "global") {
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

// The complete, static set of rule_ids evaluateAlertRules() can ever produce. Used to scope
// applyAlertCandidates' recovery eligibility (see coveredAlertIds below) for callers — like the
// CLI's read-only alerts list/watch view — that only ever compute THIS subset of candidates and
// must never be treated as authoritative over a detector family (canary.*, credential.access,
// session.*, peer.*, service.*, provenance.*, correlation.*, scheduled_job.*, service_appearance.*,
// containment.*, learned.*) they did not themselves evaluate this call. Keep in sync with the
// rule_id literals pushed inside evaluateAlertRules below.
export const FIXED_ALERT_RULE_IDS = new Set([
  "daemon.status.missing",
  "daemon.status.not_ok",
  "daemon.samples.missing",
  "daemon.samples.stale",
  "daemon.status.stale",
  "system.memory.sustained_high",
  "system.load.sustained_high",
  "disk.space.high_used_fraction",
  // Fact-store capacity plan §4.2/I12 (step S3): HISTORY_HORIZON_SHORT_RULE_ID (fact-families.js),
  // kept as a literal here like its siblings; alert-store.test.js pins the two equal.
  "daemon.fact_history.horizon_short",
  "daemon.fact_store.retention_failing",
]);

// Detector-reported recovery coverage (§8.A): coverage is now keyed on alert IDENTITY
// (alertId(rule_id, fingerprint)), not rule_id, so a caller can authorize recovery per persisted
// alert rather than per family. Every fixed rule pushes its candidate with the default "global"
// fingerprint (pushCandidate above), so its identity is alertId(ruleId) — this helper is the
// identity-keyed analog of "the fixed rules I have full visibility into", handed to
// coveredAlertIds by the CLI read-only path and folded into the daemon's per-tick covered set.
export function fixedAlertIds() {
  return new Set([...FIXED_ALERT_RULE_IDS].map((ruleId) => alertId(ruleId)));
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

  // Fact-store capacity plan §4.2/§4.4, I12 (step S3): a history-dependent rule horizon-ineligible
  // for longer than the daemon's threshold (HISTORY_HORIZON_SHORT_ALERT_TICKS structural intervals,
  // computed and written by the daemon) is reported, never silent: a sustained short horizon on a
  // novelty rule is a novelty-ABSORBING window (§5 N5), not a fail-closed one. Driven purely by the
  // status record, so the CLI's read-only view agrees with the daemon. A malformed block raises
  // nothing (it cannot vouch for anything); a well-formed one with a long-short rule always fires.
  const horizonShort = daemonStatus?.history_horizon_short;
  const horizonThresholdMs = Number(horizonShort?.threshold_ms);
  if (horizonShort && typeof horizonShort === "object" && Number.isFinite(horizonThresholdMs) && horizonThresholdMs > 0
    && horizonShort.rules && typeof horizonShort.rules === "object" && !Array.isArray(horizonShort.rules)) {
    const overdue = Object.entries(horizonShort.rules)
      .map(([ruleId, entry]) => ({ ruleId, sinceMs: Date.parse(entry?.since_ts) }))
      .filter(({ sinceMs }) => Number.isFinite(sinceMs) && nowMs - sinceMs >= horizonThresholdMs)
      .sort((left, right) => left.ruleId.localeCompare(right.ruleId));
    if (overdue.length > 0) {
      pushCandidate(candidates, {
        rule_id: "daemon.fact_history.horizon_short",
        severity: "warning",
        title: "Detector history horizon is short",
        summary: `${overdue.length} history-dependent rule(s) have had too little certified fact history to evaluate for at least ${Math.round(horizonThresholdMs / 3600000)}h; novelty first seen during this window will not alert later.`,
        diagnostics: {
          rule_ids: overdue.map(({ ruleId }) => ruleId).join(","),
          oldest_since_ts: new Date(Math.min(...overdue.map(({ sinceMs }) => sinceMs))).toISOString(),
          threshold_ms: horizonThresholdMs,
        },
      });
    }
  }

  // Fact-store capacity plan §4.3 / G2 HIGH-2: retention failures are durable family state, not a
  // one-tick structural-only condition. The daemon carries each family's retention_error or
  // retention_failing block through fast ticks, so evaluate this fixed rule from the persisted
  // status on every tick. One alert identity per family prevents a service failure from hiding or
  // recovering a peer/network failure, and a clean structural pass removes the family's candidate.
  const retentionFamilies = daemonStatus?.fact_store_budgets?.families;
  if (retentionFamilies && typeof retentionFamilies === "object" && !Array.isArray(retentionFamilies)) {
    for (const family of Object.keys(retentionFamilies).sort()) {
      const entry = retentionFamilies[family];
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      if (!(typeof entry.retention_error === "string" && entry.retention_error) && entry.retention_failing !== true) continue;
      pushCandidate(candidates, {
        rule_id: "daemon.fact_store.retention_failing",
        fingerprint: family,
        severity: "warning",
        title: "Fact-store retention is failing",
        summary: `Fact retention for the ${family} family is failing; the store may grow beyond its bounded history.`,
        diagnostics: {
          family,
          ...(typeof entry.retention_error === "string" ? { retention_error: entry.retention_error } : {}),
          ...(typeof entry.retention_error_since_ts === "string" ? { retention_error_since_ts: entry.retention_error_since_ts } : {}),
          ...(entry.retention_failing === true ? { retention_failing: true } : {}),
        },
      });
    }
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
    // Tolerate a single malformed persisted record (bad rule_id, unparseable first_seen/
    // last_seen/last_notified/cooldown_until/acknowledged_at date) instead of letting
    // Array.prototype.map's implicit re-throw abort the entire read: one bad record must not
    // blind the whole alert pipeline for this tick. Quarantine per-record and surface a count
    // via console.warn; every OTHER field in normalizeAlertRecord already degrades to a safe
    // default rather than throwing. Whole-file corruption (unparseable JSON, non-ENOENT fs
    // errors) is a distinct, more severe case and must keep propagating unchanged — see the
    // catch block below, which this loop does not touch.
    const normalized = [];
    let quarantinedCount = 0;
    for (const rawAlert of rawAlerts ?? []) {
      try {
        normalized.push(normalizeAlertRecord(rawAlert));
      } catch (recordError) {
        quarantinedCount += 1;
        const identifier = rawAlert?.id ?? rawAlert?.rule_id ?? "<unknown>";
        console.warn(`descartes: quarantined malformed alert record (id/rule_id=${identifier}): ${recordError?.message ?? recordError}`);
      }
    }
    if (quarantinedCount > 0) {
      console.warn(`descartes: readAlertRecords quarantined ${quarantinedCount} malformed record(s) out of ${(rawAlerts ?? []).length}`);
    }
    return normalized;
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
  // Detector-reported recovery coverage (§8.A): the covered set is keyed on alert IDENTITY
  // (alert.id = alertId(rule_id, fingerprint)), not rule_id, so recovery is authorized per persisted
  // alert rather than per family. undefined means "unrestricted", i.e. today's exact behavior: any
  // persisted id absent from `candidates` this call is eligible for recovery — kept for callers that
  // evaluate the full candidate universe and pass nothing. A caller that only evaluates a PARTIAL
  // universe (the CLI's read-only view, restricted to the fixed rules) or that enforces
  // detector-reported coverage (the daemon) passes an explicit Set of alert IDs so it can only
  // recover the specific alert identities it actually has full visibility into this call.
  const coveredAlertIds = options.coveredAlertIds;

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
    const isCovered = !coveredAlertIds || coveredAlertIds.has(alert.id);
    if (isCovered && !activeCandidateIds.has(id) && ["active", "acknowledged"].includes(alert.status)) {
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

// Non-persisting evaluation: computes candidates and merges them against the existing persisted
// alerts in memory, but never writes to disk. Used by evaluateAndPersistAlerts below (the daemon's
// authoritative write path) and directly by read-only callers (the CLI's alerts list/watch view)
// that must never mutate persisted state — see options.coveredAlertIds, threaded through to
// applyAlertCandidates to scope recovery eligibility (by alert identity) for a caller that only
// evaluates a partial candidate universe (e.g. fixedAlertIds()).
export async function evaluateAlerts(descartesPaths, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const [historySummary, daemonStatus, existing] = await Promise.all([
    options.historySummary ? Promise.resolve(options.historySummary) : buildHistorySummary(descartesPaths, { now, windowMs: options.windowMs ?? DEFAULT_ALERT_WINDOW_MS, limit: options.limit }),
    options.daemonStatus ? Promise.resolve(options.daemonStatus) : readDaemonStatus(descartesPaths),
    readAlertRecords(descartesPaths),
  ]);
  const candidates = evaluateAlertRules(historySummary, daemonStatus, { now, thresholds: options.thresholds });
  const extraCandidates = Array.isArray(options.extraCandidates) ? options.extraCandidates : [];
  // Both sources MUST be merged into one array before the single applyAlertCandidates call below:
  // applyAlertCandidates' recovery logic marks any active alert id absent from the current candidate
  // array as "recovered", so evaluating fixed rules and extra (e.g. constraint) candidates separately
  // would cause each source to spuriously recover the other's alerts every iteration. Every fixed-rule
  // candidate already carries an `id` (set by pushCandidate); defensively assign the same alertId()
  // to any extraCandidates entry missing one, so a source that forgets to set `id` cannot desync
  // applyAlertCandidates' recovery-detection set from the ids it actually persists under.
  const mergedCandidates = [...candidates, ...extraCandidates].map((candidate) =>
    candidate?.id ? candidate : { ...candidate, id: alertId(candidate.rule_id, candidate.fingerprint ?? "global") }
  );
  const applied = applyAlertCandidates(existing, mergedCandidates, { now, cooldownMs: options.cooldownMs, coveredAlertIds: options.coveredAlertIds });
  return { alerts: applied.alerts, candidates, history_summary: historySummary, daemon_status: daemonStatus ?? null, notification_due_ids: applied.notification_due_ids };
}

export async function evaluateAndPersistAlerts(descartesPaths, options = {}) {
  const evaluated = await evaluateAlerts(descartesPaths, options);
  const alerts = await writeAlertRecords(descartesPaths, evaluated.alerts);
  return { ...evaluated, alerts };
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
