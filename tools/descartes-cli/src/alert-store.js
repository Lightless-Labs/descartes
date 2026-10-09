import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { buildHistorySummary, readDaemonStatus } from "./history-store.js";

export const DEFAULT_ALERT_COOLDOWN_MS = 15 * 60 * 1000;
export const DEFAULT_ALERT_WINDOW_MS = 15 * 60 * 1000;
export const DELIVERY_BACKOFF_BASE_MS = 60_000;
export const DELIVERY_BACKOFF_CAP_MS = 60 * 60 * 1000;
export const MAX_LIVE_INCIDENTS = 256;
export const INCIDENT_STORM_KEY = "__incident_storm__";
export const RETENTION_FAILURE_RULE_ID = "daemon.fact_store.retention_failing";

// Retained as a compatibility export for the historical alert-config constraint and callers that
// import the old symbol. Alert delivery no longer uses this value: episode state below is the only
// notification policy for ordinary alerts. The budget_exhausted meta-signal keeps its own one-hour
// delivery window in alert-intelligence.js.

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

function normalizeIncidentKey(value) {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!text) return null;
  if (/^[A-Za-z0-9._:-]{1,128}$/.test(text)) return text;
  return `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;
}

function normalizeIncidentKeyList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeIncidentKey).filter(Boolean))];
}

export function alertEpisodeKey(alertOrCandidate = {}) {
  return normalizeIncidentKey(alertOrCandidate.current_incident_key ?? alertOrCandidate.incident_key) ?? "default";
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
        rule_id: RETENTION_FAILURE_RULE_ID,
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
  const status = ["active", "recovered", "acknowledged", "suppressed"].includes(record.status) ? record.status : "active";
  const lastNotified = record.last_notified ? normalizeIso(record.last_notified, "last_notified") : null;
  const episodeNotifiedAt = record.episode_notified_at ? normalizeIso(record.episode_notified_at, "episode_notified_at") : null;
  const normalizedCurrentIncidentKey = normalizeIncidentKey(record.current_incident_key ?? record.incident_key) ?? "default";
  const legacyWithoutEpisode = record.legacy_without_episode === true
    || (!record.episode_started_at && !record.episode_notified_at && !record.current_incident_key && !record.incident_key && !record.incidents);
  const legacyPayload = {
    severity: record.severity,
    title: record.title,
    summary: record.summary,
    evidence_refs: record.evidence_refs,
    diagnostics: record.diagnostics,
  };
  const rawIncidents = record.incidents && typeof record.incidents === "object" && !Array.isArray(record.incidents)
    ? record.incidents
    : {};
  const incidents = {};
  const singleLegacyProjection = Object.keys(rawIncidents).length === 1;
  for (const [rawKey, rawIncident] of Object.entries(rawIncidents)) {
    const key = normalizeIncidentKey(rawKey);
    if (!key || !rawIncident || typeof rawIncident !== "object") continue;
    const fallback = rawKey === normalizedCurrentIncidentKey ? legacyPayload : {};
    const compatibilityCurrent = singleLegacyProjection && rawKey === normalizedCurrentIncidentKey;
    const compatibilityLastAttempt = compatibilityCurrent && record.last_attempt_at && record.last_attempt_at !== rawIncident.last_attempt_at ? record.last_attempt_at : rawIncident.last_attempt_at;
    const compatibilityBackoff = compatibilityCurrent && Number.isFinite(record.backoff_delay_ms) && record.backoff_delay_ms !== rawIncident.backoff_delay_ms ? record.backoff_delay_ms : rawIncident.backoff_delay_ms;
    const compatibilityNextAttempt = compatibilityCurrent && record.next_attempt_at && record.next_attempt_at !== rawIncident.next_attempt_at ? record.next_attempt_at : rawIncident.next_attempt_at;
    const compatibilityNotifiedSeverity = compatibilityCurrent && record.notified_severity_max && record.notified_severity_max !== rawIncident.notified_severity ? record.notified_severity_max : undefined;
    const compatibilityConfirmedAt = compatibilityCurrent && episodeNotifiedAt && episodeNotifiedAt !== rawIncident.confirmed_at ? episodeNotifiedAt : undefined;
    const incidentFirstSeen = normalizeIso(rawIncident.first_seen ?? record.episode_started_at ?? firstSeen, "incident.first_seen");
    const incidentLastSeen = normalizeIso(rawIncident.last_seen ?? record.last_seen ?? incidentFirstSeen, "incident.last_seen");
    const severityMax = rawIncident.severity_max ?? rawIncident.severity ?? fallback.severity ?? record.severity ?? "warning";
    const topConfirmsCurrent = rawKey === normalizedCurrentIncidentKey && episodeNotifiedAt
      && (normalizeIncidentKeyList(record.notified_incident_keys).length === 0 || normalizeIncidentKeyList(record.notified_incident_keys).includes(rawKey));
    const notifiedSeverity = compatibilityNotifiedSeverity ?? rawIncident.notified_severity ?? rawIncident.notified_severity_max ?? (topConfirmsCurrent ? record.notified_severity_max : null);
    incidents[key] = {
      first_seen: incidentFirstSeen,
      last_seen: incidentLastSeen,
      severity_max: String(severityMax),
      notified_severity: notifiedSeverity === null || notifiedSeverity === undefined ? null : String(notifiedSeverity),
      confirmed_at: compatibilityConfirmedAt ? normalizeIso(compatibilityConfirmedAt, "incident.confirmed_at") : (rawIncident.confirmed_at ? normalizeIso(rawIncident.confirmed_at, "incident.confirmed_at") : (rawIncident.episode_notified_at ? normalizeIso(rawIncident.episode_notified_at, "incident.episode_notified_at") : (topConfirmsCurrent ? episodeNotifiedAt : null))),
      delivery_failure_count: Number.isInteger(rawIncident.delivery_failure_count) && rawIncident.delivery_failure_count > 0 ? rawIncident.delivery_failure_count : 0,
      next_attempt_at: compatibilityNextAttempt ? normalizeIso(compatibilityNextAttempt, "incident.next_attempt_at") : null,
      backoff_delay_ms: Number.isFinite(compatibilityBackoff) && compatibilityBackoff > 0 ? Math.min(compatibilityBackoff, DELIVERY_BACKOFF_CAP_MS) : null,
      status: ["active", "recovered", "acknowledged", "suppressed"].includes(rawIncident.status) ? rawIncident.status : "active",
      last_attempt_at: compatibilityLastAttempt ? normalizeIso(compatibilityLastAttempt, "incident.last_attempt_at") : null,
      last_delivery_failure_at: rawIncident.last_delivery_failure_at ? normalizeIso(rawIncident.last_delivery_failure_at, "incident.last_delivery_failure_at") : null,
      delivery_failure_reason: rawIncident.delivery_failure_reason ? String(rawIncident.delivery_failure_reason) : null,
      delivery_failing_since: rawIncident.delivery_failing_since ? normalizeIso(rawIncident.delivery_failing_since, "incident.delivery_failing_since") : null,
      adjudicated_at: rawIncident.adjudicated_at ? normalizeIso(rawIncident.adjudicated_at, "incident.adjudicated_at") : null,
      adjudication: rawIncident.adjudication && typeof rawIncident.adjudication === "object" && !Array.isArray(rawIncident.adjudication)
        ? { notify: rawIncident.adjudication.notify === true, severity: rawIncident.adjudication.severity === undefined ? undefined : String(rawIncident.adjudication.severity) }
        : null,
      payload: {
        severity: String(rawIncident.payload?.severity ?? rawIncident.severity ?? fallback.severity ?? record.severity ?? "warning"),
        title: String(rawIncident.payload?.title ?? rawIncident.title ?? fallback.title ?? record.title ?? ruleId),
        summary: String(rawIncident.payload?.summary ?? rawIncident.summary ?? fallback.summary ?? record.summary ?? ""),
        evidence_refs: Array.isArray(rawIncident.payload?.evidence_refs ?? rawIncident.evidence_refs ?? fallback.evidence_refs) ? (rawIncident.payload?.evidence_refs ?? rawIncident.evidence_refs ?? fallback.evidence_refs).map(String).slice(0, 16) : [],
        diagnostics: rawIncident.payload?.diagnostics ?? rawIncident.diagnostics ?? fallback.diagnostics ?? {},
      },
    };
  }
  // Migrate the prior single-episode representation to one incident without treating an old
  // record as proof that the current activation was delivered. A record with no episode marker is
  // deliberately tagged legacy_without_episode and remains silent until the alert recovers.
  if (Object.keys(incidents).length === 0 && (record.episode_started_at || record.current_incident_key || record.incident_key || record.episode_notified_at)) {
    const key = normalizedCurrentIncidentKey;
    const notifiedKeys = normalizeIncidentKeyList(record.notified_incident_keys);
    if (notifiedKeys.length === 0 && episodeNotifiedAt) notifiedKeys.push(key);
    incidents[key] = {
      first_seen: record.episode_started_at ?? firstSeen,
      last_seen: lastSeen,
      severity_max: String(record.severity ?? "warning"),
      notified_severity: notifiedKeys.includes(key) ? (record.notified_severity_max ?? record.severity ?? null) : null,
      confirmed_at: notifiedKeys.includes(key) ? episodeNotifiedAt : null,
      delivery_failure_count: Number.isInteger(record.delivery_failure_count) && record.delivery_failure_count > 0 ? record.delivery_failure_count : 0,
      next_attempt_at: record.next_attempt_at ? normalizeIso(record.next_attempt_at, "next_attempt_at") : null,
      backoff_delay_ms: Number.isFinite(record.backoff_delay_ms) && record.backoff_delay_ms > 0 ? Math.min(record.backoff_delay_ms, DELIVERY_BACKOFF_CAP_MS) : null,
      status: status === "recovered" ? "recovered" : "active",
      last_attempt_at: record.last_attempt_at ? normalizeIso(record.last_attempt_at, "last_attempt_at") : null,
      last_delivery_failure_at: record.last_delivery_failure_at ? normalizeIso(record.last_delivery_failure_at, "last_delivery_failure_at") : null,
      delivery_failure_reason: record.delivery_failure_reason ? String(record.delivery_failure_reason) : null,
      delivery_failing_since: record.delivery_failing_since ? normalizeIso(record.delivery_failing_since, "delivery_failing_since") : null,
      adjudicated_at: record.adjudicated_at ? normalizeIso(record.adjudicated_at, "adjudicated_at") : null,
      adjudication: record.adjudication,
      payload: legacyPayload,
    };
  }
  const notifiedIncidentKeys = [...new Set([
    ...normalizeIncidentKeyList(record.notified_incident_keys),
    ...Object.entries(incidents).filter(([, incident]) => incident.confirmed_at).map(([key]) => key),
  ])];
  const notifiedSeverityMax = record.notified_severity_max === undefined || record.notified_severity_max === null
    ? null
    : String(record.notified_severity_max);
  const incidentState = record.incident_state === "incident_storm" ? "incident_storm" : "normal";
  return {
    id: String(record.id ?? alertId(ruleId, fingerprint)),
    rule_id: ruleId,
    fingerprint,
    incident_key: normalizeIncidentKey(record.incident_key),
    current_incident_key: Object.hasOwn(incidents, normalizedCurrentIncidentKey) ? normalizedCurrentIncidentKey : (Object.keys(incidents).sort()[0] ?? normalizeIncidentKey(record.current_incident_key ?? record.incident_key)),
    episode_incident_keys: Object.keys(incidents).sort(),
    notified_incident_keys: notifiedIncidentKeys,
    incident_key_overflow: record.incident_key_overflow === true || incidentState === "incident_storm",
    incidents,
    incident_state: incidentState,
    incident_storm_count: Number.isInteger(record.incident_storm_count) && record.incident_storm_count > 0 ? record.incident_storm_count : 0,
    incident_storm_notified_at: record.incident_storm_notified_at ? normalizeIso(record.incident_storm_notified_at, "incident_storm_notified_at") : null,
    incident_storm_failure_count: Number.isInteger(record.incident_storm_failure_count) && record.incident_storm_failure_count > 0 ? record.incident_storm_failure_count : 0,
    legacy_without_episode: legacyWithoutEpisode,
    status,
    severity: record.severity === undefined || record.severity === null ? "warning" : String(record.severity),
    title: String(record.title ?? ruleId),
    summary: String(record.summary ?? ""),
    evidence_refs: Array.isArray(record.evidence_refs) ? record.evidence_refs.map(String).slice(0, 16) : [],
    first_seen: firstSeen,
    last_seen: lastSeen,
    last_notified: lastNotified,
    cooldown_until: record.cooldown_until ? normalizeIso(record.cooldown_until, "cooldown_until") : null,
    acknowledged_at: record.acknowledged_at ? normalizeIso(record.acknowledged_at, "acknowledged_at") : null,
    // A missing episode_started_at is meaningful legacy state: it cannot prove delivery after
    // the current activation and must remain missing until applyAlertCandidates starts the upgrade
    // episode. Never synthesize first_seen here.
    episode_started_at: record.episode_started_at ? normalizeIso(record.episode_started_at, "episode_started_at") : null,
    notified_severity_max: notifiedSeverityMax,
    episode_notified_at: episodeNotifiedAt,
    adjudicated_at: record.adjudicated_at ? normalizeIso(record.adjudicated_at, "adjudicated_at") : null,
    adjudicated_episode_key: normalizeIncidentKey(record.adjudicated_episode_key),
    adjudication: record.adjudication && typeof record.adjudication === "object" && !Array.isArray(record.adjudication)
      ? { notify: record.adjudication.notify === true, severity: record.adjudication.severity === undefined ? undefined : String(record.adjudication.severity) }
      : null,
    delivery_failure_count: Number.isInteger(record.delivery_failure_count) && record.delivery_failure_count > 0 ? record.delivery_failure_count : 0,
    last_delivery_failure_at: record.last_delivery_failure_at ? normalizeIso(record.last_delivery_failure_at, "last_delivery_failure_at") : null,
    delivery_failure_reason: record.delivery_failure_reason ? String(record.delivery_failure_reason) : null,
    delivery_failing_since: record.delivery_failing_since ? normalizeIso(record.delivery_failing_since, "delivery_failing_since") : null,
    next_attempt_at: record.next_attempt_at ? normalizeIso(record.next_attempt_at, "next_attempt_at") : null,
    last_attempt_at: record.last_attempt_at ? normalizeIso(record.last_attempt_at, "last_attempt_at") : null,
    backoff_delay_ms: Number.isFinite(record.backoff_delay_ms) && record.backoff_delay_ms > 0 ? Math.min(record.backoff_delay_ms, DELIVERY_BACKOFF_CAP_MS) : null,
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

async function writeAlertRecordsUnlocked(descartesPaths, alerts) {
  await ensureAlertDir(descartesPaths);
  const { alertsFile } = resolveAlertStorePaths(descartesPaths);
  const normalized = alerts.map(normalizeAlertRecord).sort((left, right) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    if ((severityOrder[left.severity] ?? 9) !== (severityOrder[right.severity] ?? 9)) return (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
    return right.last_seen.localeCompare(left.last_seen);
  });
  const payload = JSON.stringify({ version: 1, alerts: normalized }, null, 2);
  const tmpFile = `${alertsFile}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, alertsFile);
  return normalized;
}

export async function writeAlertRecords(descartesPaths, alerts) {
  return writeAlertRecordsUnlocked(descartesPaths, alerts);
}

const ALERT_SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
export function alertSeverityRank(severity) {
  return Object.hasOwn(ALERT_SEVERITY_RANK, severity) ? ALERT_SEVERITY_RANK[severity] : 3;
}

function deliveryBackoffEligible(alert, nowMs) {
  if (!Number.isFinite(nowMs)) return true;
  const lastAttemptMs = alert.last_attempt_at ? new Date(alert.last_attempt_at).getTime() : NaN;
  const delayMs = Number.isFinite(alert.backoff_delay_ms) ? alert.backoff_delay_ms : undefined;
  if (!Number.isFinite(lastAttemptMs) || !Number.isFinite(delayMs)) {
    if (!alert.next_attempt_at) return true;
    const nextAttemptMs = new Date(alert.next_attempt_at).getTime();
    return !Number.isFinite(nextAttemptMs) || nextAttemptMs <= nowMs;
  }
  // A future last-attempt timestamp is a clock rollback artifact. It must never suppress a retry.
  if (lastAttemptMs > nowMs) return true;
  return nowMs >= lastAttemptMs + delayMs;
}

function incidentSeverityRank(incident) {
  return alertSeverityRank(incident?.severity_max ?? incident?.payload?.severity);
}

function candidatePayload(candidate) {
  return {
    severity: String(candidate.severity ?? "warning"),
    title: String(candidate.title ?? candidate.rule_id ?? "Alert"),
    summary: String(candidate.summary ?? ""),
    evidence_refs: Array.isArray(candidate.evidence_refs) ? candidate.evidence_refs.map(String).slice(0, 16) : [],
    diagnostics: candidate.diagnostics && typeof candidate.diagnostics === "object" && !Array.isArray(candidate.diagnostics) ? candidate.diagnostics : {},
  };
}

function stableCandidate(left, right) {
  const leftRank = alertSeverityRank(left.severity);
  const rightRank = alertSeverityRank(right.severity);
  if (leftRank !== rightRank) return leftRank > rightRank ? left : right;
  const leftText = JSON.stringify({ title: left.title ?? "", summary: left.summary ?? "", diagnostics: left.diagnostics ?? {}, evidence_refs: left.evidence_refs ?? [] });
  const rightText = JSON.stringify({ title: right.title ?? "", summary: right.summary ?? "", diagnostics: right.diagnostics ?? {}, evidence_refs: right.evidence_refs ?? [] });
  return leftText.localeCompare(rightText) <= 0 ? left : right;
}

function syncAlertProjection(alert) {
  const keys = Object.keys(alert.incidents ?? {}).sort();
  const preferredKey = keys.reduce((selected, key) => {
    if (!selected) return key;
    const selectedIncident = alert.incidents[selected];
    const incident = alert.incidents[key];
    if (incidentSeverityRank(incident) !== incidentSeverityRank(selectedIncident)) {
      return incidentSeverityRank(incident) > incidentSeverityRank(selectedIncident) ? key : selected;
    }
    return key.localeCompare(selected) < 0 ? key : selected;
  }, undefined) ?? "default";
  const current = alert.incidents?.[preferredKey];
  const allIncidents = Object.values(alert.incidents ?? {});
  const confirmed = allIncidents.filter((incident) => incident.confirmed_at);
  const notified = [...new Set(confirmed.map((incident) => incident.notified_severity).filter(Boolean))]
    .sort((left, right) => alertSeverityRank(right) - alertSeverityRank(left));
  const payload = current?.payload ?? {};
  const stormRetry = alert.incident_state === "incident_storm";
  return normalizeAlertRecord({
    ...alert,
    incident_key: preferredKey === "default" ? null : preferredKey,
    current_incident_key: preferredKey,
    episode_incident_keys: keys,
    notified_incident_keys: confirmed.map((incident) => keys.find((key) => alert.incidents[key] === incident)).filter(Boolean),
    severity: allIncidents.reduce((max, incident) => incidentSeverityRank(incident) > alertSeverityRank(max) ? incident.severity_max : max, "info"),
    title: payload.title ?? alert.title,
    summary: payload.summary ?? alert.summary,
    evidence_refs: payload.evidence_refs ?? alert.evidence_refs,
    diagnostics: payload.diagnostics ?? alert.diagnostics,
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    last_notified: confirmed.map((incident) => incident.confirmed_at).sort().at(-1) ?? null,
    notified_severity_max: notified[0] ?? null,
    episode_notified_at: confirmed.map((incident) => incident.confirmed_at).sort().at(-1) ?? null,
    delivery_failure_count: stormRetry ? alert.delivery_failure_count ?? 0 : current?.delivery_failure_count ?? 0,
    last_delivery_failure_at: stormRetry ? alert.last_delivery_failure_at ?? null : current?.last_delivery_failure_at ?? null,
    delivery_failure_reason: stormRetry ? alert.delivery_failure_reason ?? null : current?.delivery_failure_reason ?? null,
    delivery_failing_since: stormRetry ? alert.delivery_failing_since ?? null : current?.delivery_failing_since ?? null,
    next_attempt_at: stormRetry ? alert.next_attempt_at ?? null : current?.next_attempt_at ?? null,
    last_attempt_at: stormRetry ? alert.last_attempt_at ?? null : current?.last_attempt_at ?? null,
    backoff_delay_ms: stormRetry ? alert.backoff_delay_ms ?? null : current?.backoff_delay_ms ?? null,
    incident_storm_failure_count: alert.incident_storm_failure_count ?? 0,
    adjudicated_at: current?.adjudicated_at ?? null,
    adjudicated_episode_key: current?.adjudicated_at ? preferredKey : null,
    adjudication: current?.adjudication ?? null,
  });
}

function notificationDueForIncident(alert, incident, { newIncident = false, severityEscalated = false, nowMs } = {}) {
  if (!incident || ["suppressed", "recovered"].includes(alert.status) || ["suppressed", "recovered"].includes(incident.status)) return false;
  if (newIncident || severityEscalated) return true;
  if (alert.status === "acknowledged") return false;
  if (incident.confirmed_at && incidentSeverityRank(incident) <= alertSeverityRank(incident.notified_severity)) return false;
  return deliveryBackoffEligible({ last_attempt_at: incident.last_attempt_at, backoff_delay_ms: incident.backoff_delay_ms }, nowMs);
}

export function applyAlertCandidates(existingAlerts, candidates, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const byId = new Map(existingAlerts.map((alert) => [alert.id, normalizeAlertRecord(alert)]));
  const activeCandidateIds = new Set(candidates.map((candidate) => candidate.id));
  const notificationDueIncidents = [];
  const adjudicationDueIncidents = [];
  // Detector-reported recovery coverage (§8.A): the covered set is keyed on alert IDENTITY
  // (alert.id = alertId(rule_id, fingerprint)), not rule_id, so recovery is authorized per persisted
  // alert rather than per family. undefined means "unrestricted", i.e. today's exact behavior: any
  // persisted id absent from `candidates` this call is eligible for recovery — kept for callers that
  // evaluate the full candidate universe and pass nothing. A caller that only evaluates a PARTIAL
  // universe (the CLI's read-only view, restricted to the fixed rules) or that enforces
  // detector-reported coverage (the daemon) passes an explicit Set of alert IDs so it can only
  // recover the specific alert identities it actually has full visibility into this call.
  const coveredAlertIds = options.coveredAlertIds;

  const grouped = new Map();
  for (const candidate of candidates) {
    if (!candidate?.id) continue;
    const key = alertEpisodeKey(candidate);
    const byIncident = grouped.get(candidate.id) ?? new Map();
    const prior = byIncident.get(key);
    byIncident.set(key, prior ? stableCandidate(prior, candidate) : candidate);
    grouped.set(candidate.id, byIncident);
  }

  for (const id of [...grouped.keys()].sort()) {
    const incidentCandidates = grouped.get(id);
    const current = byId.get(id);
    const firstCandidate = [...incidentCandidates.values()].sort((left, right) => alertEpisodeKey(left).localeCompare(alertEpisodeKey(right)))[0];
    const newEpisode = !current || current.status === "recovered"
      || (!current.episode_started_at && !["acknowledged", "suppressed"].includes(current.status));
    const base = newEpisode
      ? normalizeAlertRecord({ ...firstCandidate, status: "active", first_seen: now, last_seen: now, episode_started_at: now, incidents: {}, legacy_without_episode: current?.legacy_without_episode === true })
      : normalizeAlertRecord(current);
    const next = {
      ...base,
      status: base.status === "acknowledged" || base.status === "suppressed" ? base.status : "active",
      first_seen: base.first_seen,
      last_seen: now,
      episode_started_at: newEpisode ? now : base.episode_started_at,
      acknowledged_at: base.status === "acknowledged" ? base.acknowledged_at : null,
      incidents: newEpisode ? {} : { ...base.incidents },
      incident_state: newEpisode ? "normal" : base.incident_state,
      incident_storm_count: newEpisode ? 0 : base.incident_storm_count,
      incident_storm_notified_at: newEpisode ? null : base.incident_storm_notified_at,
      legacy_without_episode: newEpisode ? base.legacy_without_episode : base.legacy_without_episode,
    };
    let overflowCount = 0;
    const dueForAlert = [];
    const adjudicationForAlert = [];
    for (const key of [...incidentCandidates.keys()].sort()) {
      const candidate = incidentCandidates.get(key);
      const previousIncident = next.incidents[key];
      if (!previousIncident && Object.keys(next.incidents).length >= MAX_LIVE_INCIDENTS) {
        overflowCount += 1;
        continue;
      }
      const payload = candidatePayload(candidate);
      const incident = previousIncident ?? {
        first_seen: now,
        last_seen: now,
        severity_max: payload.severity,
        notified_severity: null,
        confirmed_at: null,
        delivery_failure_count: 0,
        next_attempt_at: null,
        backoff_delay_ms: null,
        status: "active",
        last_attempt_at: null,
        last_delivery_failure_at: null,
        delivery_failure_reason: null,
        delivery_failing_since: null,
        adjudicated_at: null,
        adjudication: null,
        payload,
      };
      const severityEscalated = incidentSeverityRank({ severity_max: payload.severity }) > incidentSeverityRank(previousIncident);
      const selectedCandidate = candidate;
      next.incidents[key] = {
        ...incident,
        last_seen: now,
        severity_max: alertSeverityRank(payload.severity) > incidentSeverityRank(incident) ? payload.severity : incident.severity_max,
        status: "active",
        payload: candidatePayload(selectedCandidate),
      };
      const newIncident = !previousIncident;
      const legacySuppressed = next.legacy_without_episode;
      if (next.incident_state !== "incident_storm" && !legacySuppressed && notificationDueForIncident(next, next.incidents[key], { newIncident, severityEscalated, nowMs: new Date(now).getTime() })) {
        dueForAlert.push({ alert_id: id, incident_key: key });
      }
      const sameNegativeAdjudication = next.incidents[key].adjudication?.notify === false
        && next.incidents[key].adjudication?.severity === next.incidents[key].severity_max;
      if (next.incident_state !== "incident_storm" && !legacySuppressed && !sameNegativeAdjudication && (newIncident || severityEscalated || dueForAlert.some((entry) => entry.incident_key === key))) {
        adjudicationForAlert.push({ alert_id: id, incident_key: key });
      }
    }

    // Due-ness belongs to every persisted active incident, not only to identities observed in this
    // tick. A failed incident may be absent from the current candidate set while its sibling keeps
    // the alert active; once its backoff expires it still needs another delivery attempt.
    if (next.incident_state !== "incident_storm" && !next.legacy_without_episode) {
      for (const [key, incident] of Object.entries(next.incidents).sort(([left], [right]) => left.localeCompare(right))) {
        if (!notificationDueForIncident(next, incident, { nowMs: new Date(now).getTime() })) continue;
        if (!dueForAlert.some((entry) => entry.incident_key === key)) dueForAlert.push({ alert_id: id, incident_key: key });
        const sameNegativeAdjudication = incident.adjudication?.notify === false
          && incident.adjudication?.severity === incident.severity_max;
        if (!sameNegativeAdjudication && !adjudicationForAlert.some((entry) => entry.incident_key === key)) {
          adjudicationForAlert.push({ alert_id: id, incident_key: key });
        }
      }
    }
    if (overflowCount > 0) {
      next.incident_state = "incident_storm";
      next.incident_key_overflow = true;
      next.incident_storm_count = Math.max(next.incident_storm_count ?? 0, Object.keys(next.incidents).length + overflowCount);
      dueForAlert.length = 0;
      adjudicationForAlert.length = 0;
      if (!next.incident_storm_notified_at && !["acknowledged", "suppressed"].includes(next.status) && !next.legacy_without_episode
        && deliveryBackoffEligible(next, new Date(now).getTime())) {
        dueForAlert.push({ alert_id: id, incident_key: INCIDENT_STORM_KEY, storm: true, incident_count: next.incident_storm_count });
      }
    } else if (next.incident_state === "incident_storm" && !next.incident_storm_notified_at
      && !["acknowledged", "suppressed"].includes(next.status) && !next.legacy_without_episode
      && deliveryBackoffEligible(next, new Date(now).getTime())) {
      // The storm is itself a persisted notification target. Retry a failed storm even when this
      // tick contains no new overflow identity.
      dueForAlert.push({ alert_id: id, incident_key: INCIDENT_STORM_KEY, storm: true, incident_count: next.incident_storm_count });
    }
    notificationDueIncidents.push(...dueForAlert);
    adjudicationDueIncidents.push(...adjudicationForAlert);
    byId.set(id, syncAlertProjection(next));
  }

  for (const [id, alert] of byId) {
    const isCovered = !coveredAlertIds || coveredAlertIds.has(alert.id);
    if (isCovered && !activeCandidateIds.has(id) && ["active", "acknowledged"].includes(alert.status)) {
      byId.set(id, normalizeAlertRecord({
        ...alert,
        status: "recovered",
        last_seen: now,
        legacy_without_episode: false,
        incidents: Object.fromEntries(Object.entries(alert.incidents ?? {}).map(([key, incident]) => [key, { ...incident, status: "recovered" }])),
      }));
    }
  }

  return {
    alerts: [...byId.values()],
    notification_due_incidents: notificationDueIncidents.sort((left, right) => `${left.alert_id}\0${left.incident_key}`.localeCompare(`${right.alert_id}\0${right.incident_key}`)),
    notification_due_ids: [...new Set(notificationDueIncidents.map((entry) => entry.alert_id))],
    adjudication_due_incidents: adjudicationDueIncidents.sort((left, right) => `${left.alert_id}\0${left.incident_key}`.localeCompare(`${right.alert_id}\0${right.incident_key}`)),
    adjudication_due_ids: [...new Set(adjudicationDueIncidents.map((entry) => entry.alert_id))],
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
    options.existingAlerts ? Promise.resolve(options.existingAlerts) : readAlertRecords(descartesPaths),
  ]);
  const candidates = evaluateAlertRules(historySummary, daemonStatus, { now, thresholds: options.thresholds });
  const extraCandidates = Array.isArray(options.extraCandidates) ? options.extraCandidates : [];
  const successfulRetentionFamilies = options.successfulRetentionFamilies instanceof Set
    ? options.successfulRetentionFamilies
    : new Set();
  const existingById = new Map(existing.map((alert) => [alert.id, alert]));
  // An unresolved retention alert without successful-pass evidence is frozen in place. Re-emitting
  // it as a synthetic candidate would turn stale status into fresh observation, advancing last_seen
  // and notification eligibility on every fast tick (especially while both tiers are disabled).
  // computeCoveredAlerts separately excludes the identity from recovery until its family reports a
  // genuinely successful structural retention pass, so removing the candidate preserves HIGH-2.
  const currentCandidates = candidates.filter((candidate) => {
    if (candidate.rule_id !== RETENTION_FAILURE_RULE_ID || successfulRetentionFamilies.has(candidate.fingerprint)) return true;
    const existingAlert = existingById.get(candidate.id);
    return !existingAlert || !["active", "acknowledged"].includes(existingAlert.status);
  });
  // Both sources MUST be merged into one array before the single applyAlertCandidates call below:
  // applyAlertCandidates' recovery logic marks any active alert id absent from the current candidate
  // array as "recovered", so evaluating fixed rules and extra (e.g. constraint) candidates separately
  // would cause each source to spuriously recover the other's alerts every iteration. Every fixed-rule
  // candidate already carries an `id` (set by pushCandidate); defensively assign the same alertId()
  // to any extraCandidates entry missing one, so a source that forgets to set `id` cannot desync
  // applyAlertCandidates' recovery-detection set from the ids it actually persists under.
  const mergedCandidates = [...currentCandidates, ...extraCandidates].map((candidate) =>
    candidate?.id ? candidate : { ...candidate, id: alertId(candidate.rule_id, candidate.fingerprint ?? "global") }
  );
  const applied = applyAlertCandidates(existing, mergedCandidates, { now, cooldownMs: options.cooldownMs, coveredAlertIds: options.coveredAlertIds });
  return { alerts: applied.alerts, candidates: currentCandidates, history_summary: historySummary, daemon_status: daemonStatus ?? null, notification_due_ids: applied.notification_due_ids, notification_due_incidents: applied.notification_due_incidents, adjudication_due_ids: applied.adjudication_due_ids, adjudication_due_incidents: applied.adjudication_due_incidents };
}

export async function evaluateAndPersistAlerts(descartesPaths, options = {}) {
  // Candidate computation and history reads happen before this read-modify-write. The latest
  // snapshot is re-read before writing, but this path remains intentionally unlocked: concurrent
  // alert-store writers are an existing unsupported boundary documented in todos/.
  const evaluated = await evaluateAlerts(descartesPaths, options);
    const candidates = [...(evaluated.candidates ?? []), ...(Array.isArray(options.extraCandidates) ? options.extraCandidates : [])]
    .map((candidate) => candidate?.id ? candidate : { ...candidate, id: alertId(candidate.rule_id, candidate.fingerprint ?? "global") });
  const latest = await readAlertRecords(descartesPaths);
  const applied = applyAlertCandidates(latest, candidates, { now: options.now ?? new Date().toISOString(), cooldownMs: options.cooldownMs, coveredAlertIds: options.coveredAlertIds });
  const alerts = await writeAlertRecordsUnlocked(descartesPaths, applied.alerts);
  return { ...evaluated, alerts, notification_due_ids: applied.notification_due_ids, notification_due_incidents: applied.notification_due_incidents, adjudication_due_ids: applied.adjudication_due_ids, adjudication_due_incidents: applied.adjudication_due_incidents };
}

export async function confirmAlertDelivery(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let confirmed = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    const incidentKey = options.incidentKey ?? options.episodeKey ?? alertEpisodeKey(alert);
    if (incidentKey === INCIDENT_STORM_KEY) {
      confirmed = true;
      return syncAlertProjection({
        ...alert,
        incident_storm_notified_at: now,
        last_notified: now,
        last_attempt_at: now,
        delivery_failure_count: 0,
        last_delivery_failure_at: null,
        delivery_failure_reason: null,
        delivery_failing_since: null,
        next_attempt_at: null,
        backoff_delay_ms: null,
      });
    }
    const incident = alert.incidents?.[incidentKey];
    if (!incident) return alert;
    confirmed = true;
    const currentRank = incident.notified_severity === null || incident.notified_severity === undefined ? -1 : alertSeverityRank(incident.notified_severity);
    const nextSeverity = options.severity ?? incident.severity_max ?? alert.severity;
    const nextRank = alertSeverityRank(nextSeverity);
    const updatedIncident = {
      ...incident,
      confirmed_at: now,
      notified_severity: nextRank >= currentRank ? nextSeverity : incident.notified_severity,
      delivery_failure_count: 0,
      last_delivery_failure_at: null,
      delivery_failure_reason: null,
      delivery_failing_since: null,
      next_attempt_at: null,
      last_attempt_at: now,
      backoff_delay_ms: null,
    };
    return syncAlertProjection({
      ...alert,
      incidents: { ...alert.incidents, [incidentKey]: updatedIncident },
    });
  });
  if (!confirmed) return { confirmed: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { confirmed: true, alert: written.find((alert) => alert.id === alertIdValue) };
}

export async function recordAlertDeliveryFailure(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let recorded = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    const incidentKey = options.incidentKey ?? options.episodeKey ?? alertEpisodeKey(alert);
    if (incidentKey === INCIDENT_STORM_KEY) {
      recorded = true;
      const count = (alert.incident_storm_failure_count ?? 0) + 1;
      const delay = Math.min(DELIVERY_BACKOFF_CAP_MS, DELIVERY_BACKOFF_BASE_MS * (2 ** Math.min(count - 1, 16)));
      return normalizeAlertRecord({ ...alert, incident_storm_failure_count: count, next_attempt_at: new Date(new Date(now).getTime() + delay).toISOString(), last_attempt_at: now, backoff_delay_ms: delay });
    }
    const incident = alert.incidents?.[incidentKey];
    if (!incident) return alert;
    recorded = true;
    const count = incident.delivery_failure_count + 1;
    const delay = Math.min(DELIVERY_BACKOFF_CAP_MS, DELIVERY_BACKOFF_BASE_MS * (2 ** Math.min(count - 1, 16)));
    const nextAttemptMs = new Date(now).getTime() + delay;
    return syncAlertProjection({
      ...alert,
      incidents: {
        ...alert.incidents,
        [incidentKey]: {
          ...incident,
          delivery_failure_count: count,
          last_delivery_failure_at: now,
          last_attempt_at: now,
          backoff_delay_ms: delay,
          delivery_failure_reason: String(options.reason ?? "delivery_failed").slice(0, 240),
          delivery_failing_since: incident.delivery_failing_since ?? now,
          next_attempt_at: new Date(nextAttemptMs).toISOString(),
        },
      },
    });
  });
  if (!recorded) return { recorded: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
}

export async function recordAlertAdjudication(descartesPaths, alertIdValue, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const alerts = await readAlertRecords(descartesPaths);
  let recorded = false;
  const updated = alerts.map((alert) => {
    if (alert.id !== alertIdValue || ["recovered", "suppressed"].includes(alert.status)) return alert;
    const incidentKey = options.incidentKey ?? options.episodeKey ?? alertEpisodeKey(alert);
    const incident = alert.incidents?.[incidentKey];
    if (!incident) return alert;
    recorded = true;
    return syncAlertProjection({
      ...alert,
      incidents: {
        ...alert.incidents,
        [incidentKey]: {
          ...incident,
          adjudicated_at: now,
          adjudication: { notify: options.notify === true, severity: options.severity ?? incident.severity_max },
        },
      },
    });
  });
  if (!recorded) return { recorded: false };
  const written = await writeAlertRecordsUnlocked(descartesPaths, updated);
  return { recorded: true, alert: written.find((alert) => alert.id === alertIdValue) };
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
  return (await writeAlertRecordsUnlocked(descartesPaths, updated)).find((alert) => alert.id === alertId);
}
