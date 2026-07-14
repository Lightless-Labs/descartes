import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
} from "./session-baseline.js";

export const DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR = 3;

// S13 must-fix 2: a critical-severity call is guaranteed a slot out of max_calls_per_hour so a
// burst of non-critical (e.g. learned-artifact) findings cannot starve a real emergency
// adjudication. Default reserves exactly one call/hour for critical alerts.
export const DEFAULT_ALERT_INTELLIGENCE_CRITICAL_RESERVATION = 1;

// S13 must-fix 1: the CLOSED set of namespaces that MAY ever be opted into LLM adjudication.
// "learned" is deliberately never a member of this list -- it is hard-excluded below, not merely
// defaulted off, and `normalizeEnabledNamespaces`/the alerts.js CLI reject it explicitly.
export const KNOWN_ALERT_NAMESPACES = ["metric", "constraint", "provenance", "baseline", "identity"];

// S13 must-fix 1: metric-only users (the entire installed base pre-S13) see ZERO behavior change --
// every fixed/legacy alert (daemon./system./disk.) classifies as "metric" and stays enabled by
// default; every learned namespace (constraint/provenance/baseline/identity) defaults OFF even
// when alert-intelligence.json has enabled:true.
export const DEFAULT_ENABLED_NAMESPACES = ["metric"];

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

function normalizeEnabledNamespaces(value) {
  // Missing (undefined/null) or wrong-typed ("garbage") -> the fail-open-safe default. A present
  // but explicitly EMPTY array is distinct from "missing/garbage": it's a well-typed, deliberate
  // "no namespace enabled" state (e.g. produced by `alerts intelligence disable-namespace metric`
  // when metric was the only one enabled) and must be respected as-is, not bounced back to the
  // default -- otherwise the CLI could never fully disable namespace-gated LLM adjudication short
  // of disabling alert intelligence entirely.
  if (!Array.isArray(value)) return [...DEFAULT_ENABLED_NAMESPACES];
  if (value.length === 0) return [];
  const known = new Set(KNOWN_ALERT_NAMESPACES);
  const filtered = [...new Set(value.map((entry) => String(entry)))].filter((namespace) => known.has(namespace));
  // Every entry was unknown/hard-excluded garbage (e.g. ["learned"], ["bogus"]) -> fail closed to
  // the default rather than silently enabling nothing while looking like a deliberate choice.
  return filtered.length > 0 ? filtered : [...DEFAULT_ENABLED_NAMESPACES];
}

function normalizeCriticalReservation(value, maxCallsPerHour) {
  const raw = Number(value ?? DEFAULT_ALERT_INTELLIGENCE_CRITICAL_RESERVATION);
  const base = Number.isFinite(raw) ? Math.floor(raw) : DEFAULT_ALERT_INTELLIGENCE_CRITICAL_RESERVATION;
  // S13 must-fix 2: clamp to [0, max_calls_per_hour] -- the reservation must never exceed the
  // user's hard cap. reservation==max is coherent (non-critical starved, critical still works);
  // max_calls_per_hour==0 stays "no LLM at all incl critical" since 0 <= 0 admits nothing.
  return Math.min(Math.max(base, 0), maxCallsPerHour);
}

export function normalizeAlertIntelligenceConfig(config = {}) {
  const maxCallsPerHour = Number(config.max_calls_per_hour ?? DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR);
  const normalizedMax = Number.isFinite(maxCallsPerHour) && maxCallsPerHour >= 0 ? Math.floor(maxCallsPerHour) : DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR;
  return {
    enabled: config.enabled === true,
    model_pattern: config.model_pattern ? String(config.model_pattern) : undefined,
    thinking_level: config.thinking_level ? String(config.thinking_level) : undefined,
    max_calls_per_hour: normalizedMax,
    critical_reservation: normalizeCriticalReservation(config.critical_reservation, normalizedMax),
    enabled_namespaces: normalizeEnabledNamespaces(config.enabled_namespaces),
    // S13 must-fix 5: these flags were already normalized pre-S13 but never actually wired into
    // the prompt -- see adjudicateAlertNotifications, which now gates historySummary/daemonStatus
    // inclusion on them.
    include_history_summary: config.include_history_summary !== false,
    include_daemon_status: config.include_daemon_status !== false,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

export async function readAlertIntelligenceConfig(descartesPaths) {
  const { configFile } = resolveAlertIntelligencePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeAlertIntelligenceConfig();
    throw error;
  }
  try {
    return normalizeAlertIntelligenceConfig(JSON.parse(contents));
  } catch {
    // S13 nice-to-have: fail CLOSED on a corrupt config file rather than throwing out of a daemon
    // tick -- mirrors constraint-store.js's loadLearnedConfig (~L196-204). `corrupt: true` is an
    // additive marker only; callers that only read `.enabled` are unaffected (it's still false).
    return { ...normalizeAlertIntelligenceConfig(), corrupt: true };
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

// S13 must-fix 2: budget consumption is classified by the ALERT's severity (a fact that exists
// before the LLM call), never by the model's decision severity (which doesn't exist pre-call and
// would let the model manipulate its own future budget by always claiming "critical"). Historical
// (pre-S13) llm-decisions.jsonl records carry no alert_severity field and are conservatively
// counted as non-critical -- this preserves the critical reservation rather than assuming past
// calls were critical and inflating the critical count.
function auditRecordIsCritical(record) {
  return record?.alert_severity === "critical";
}

function isWithinTrailingHour(recordTs, now, windowMs) {
  const nowMs = new Date(now).getTime();
  const tsMs = new Date(recordTs).getTime();
  return Number.isFinite(tsMs) && nowMs - tsMs >= 0 && nowMs - tsMs < windowMs;
}

// S13 must-fix 2: partitions the trailing-hour audit history into per-class counts. These seed
// the RUNNING per-class counters used by the admission loop below -- replacing the pre-S13
// one-shot `remaining`/`slice(0, remaining)` computation, which could not express "total calls
// already made earlier in this same invocation" once critical/non-critical accounting diverged.
function partitionRecentAuditCounts(records, now, windowMs = 60 * 60 * 1000) {
  let critical = 0;
  let nonCritical = 0;
  for (const record of records) {
    if (!isWithinTrailingHour(record.ts, now, windowMs)) continue;
    if (auditRecordIsCritical(record)) critical += 1;
    else nonCritical += 1;
  }
  return { critical, nonCritical };
}

const BUDGET_EXHAUSTED_RULE_ID = "adjudication.budget_exhausted";

async function hasRecentBudgetExhaustedNotification(descartesPaths, now, windowMs = 60 * 60 * 1000) {
  const { readNotificationDeliveryAudit } = await import("./notification-delivery.js");
  const records = await readNotificationDeliveryAudit(descartesPaths);
  return records.some((record) => record?.payload?.rule_id === BUDGET_EXHAUSTED_RULE_ID && isWithinTrailingHour(record.ts, now, windowMs));
}

// S13 must-fix 3: single emission point for the deterministic budget_exhausted signal. Called at
// most once per adjudicateAlertNotifications invocation, only when at least one eligible alert was
// actually dropped for budget reasons (never for namespace/consent exclusions, which are not a
// budget drop). Delivers straight through deliverNotificationDecision -- NEVER through the LLM
// loop, a session, or the alert-intelligence rate limiter above -- and carries counts only, never
// a dropped alert's title/diagnostics, so no un-consented data rides the notification channel this
// very gate protects.
async function emitBudgetExhaustedSignal(descartesPaths, { now, droppedTotal, droppedCritical, deliverNotification }) {
  if (await hasRecentBudgetExhaustedNotification(descartesPaths, now)) {
    return { fired: false, reason: "cooldown" };
  }
  const severity = droppedCritical > 0 ? "critical" : "warning";
  const decision = {
    notify: true,
    severity,
    title: "Descartes alert intelligence budget exhausted",
    body: `${droppedTotal} alert${droppedTotal === 1 ? "" : "s"} (${droppedCritical} critical) not adjudicated this hour.`,
  };
  await deliverNotification(descartesPaths, decision, { now, ruleId: BUDGET_EXHAUSTED_RULE_ID });
  return { fired: true };
}

// Slice 4 (observed-incident collectors plan), Decision 2b / must-fix 3: a deterministic,
// non-LLM local delivery branch for the fail-closed session.* rule_ids (session.count_drop,
// session.churn — see classifyAlertNamespace below: both are unknown_namespace and therefore
// structurally can NEVER reach LLM adjudication, regardless of enabled_namespaces). Left
// unmitigated, this milestone's first alerting slice — including a CRITICAL mass-drop, the exact
// motivating incident — would never actively notify the operator; it would only be visible to an
// operator who proactively ran `descartes alerts`.
//
// Mirrors emitBudgetExhaustedSignal's own "straight through deliverNotificationDecision, NEVER
// through the LLM, a session, or enableTools" precedent:
//   - scoped by an explicit rule_id ALLOWLIST (DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, imported
//     from session-baseline.js rather than restated here) — never a general unknown-namespace
//     bypass, so this cannot silently swallow some future, unrelated fail-closed namespace;
//   - the decision handed to deliverNotificationDecision is hand-built and deterministic — never
//     a session, never an LLM call;
//   - reuses the notification_due_ids/cooldown state applyAlertCandidates already computed for
//     every candidate (including these two rule_ids) inside evaluateAndPersistAlerts — no new
//     cooldown machinery. Correction, load-bearing (must-fix 3): applyAlertCandidates stamps
//     last_notified/cooldown_until on a candidate even when nothing is actually delivered
//     downstream — that stamp reflects only that the candidate was processed, not that any
//     human-visible delivery happened. This function's own tests assert on an actual call into
//     (or mock of) deliverNotificationDecision, never merely on the cooldown/last_notified fields;
//   - the delivered body is counts/hash-only — never a raw session name, matching the sanitized
//     diagnostics shape session-baseline.js's candidate builders already produce.
export async function emitSessionAlertSignals(descartesPaths, evaluation, options = {}) {
  const dueIds = new Set(evaluation?.notification_due_ids ?? []);
  if (dueIds.size === 0) return { fired: [] };

  const dueSessionAlerts = (evaluation.alerts ?? []).filter(
    (alert) => dueIds.has(alert.id) && DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS.includes(alert.rule_id),
  );
  if (dueSessionAlerts.length === 0) return { fired: [] };

  const deliverNotification = options.deliverNotification ?? (await import("./notification-delivery.js")).deliverNotificationDecision;
  const now = options.now ?? new Date().toISOString();

  const fired = [];
  for (const alert of dueSessionAlerts) {
    const decision = buildSessionAlertNotificationDecision(alert);
    await deliverNotification(descartesPaths, decision, { now, alertId: alert.id, ruleId: alert.rule_id });
    fired.push(alert.id);
  }
  return { fired };
}

// Counts/hash-only body (must-fix 3): every field interpolated below is a finite number or a
// short closed-enum/hash string already produced by session-baseline.js's sanitizeDiagnostics-gated
// candidate builders — never a raw session name, which never reaches this layer's inputs at all
// (session-baseline.js's diagnostics only ever carry counts/z-scores/confidence_state or hashed
// entity_key/fingerprints).
function buildSessionAlertNotificationDecision(alert) {
  const diagnostics = alert?.diagnostics ?? {};
  if (alert?.rule_id === SESSION_COUNT_DROP_RULE_ID) {
    return {
      notify: true,
      severity: alert.severity === "critical" ? "critical" : "warning",
      title: "Descartes: session count deviation",
      body: `Session count ${diagnostics.observed_count} vs baseline mean ${diagnostics.mean_before} (z=${diagnostics.z_score}, ${diagnostics.confidence_state}).`,
    };
  }
  if (alert?.rule_id === SESSION_CHURN_RULE_ID) {
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: session churn detected",
      body: `Session ${diagnostics.entity_key} fingerprint changed (${diagnostics.prior_fingerprint} -> ${diagnostics.current_fingerprint}).`,
    };
  }
  // Unreachable in normal operation (the caller already filters to DETERMINISTIC_LOCAL_DELIVERY_
  // RULE_IDS) — fails closed to a generic, still counts/enum-only body rather than throwing.
  return { notify: true, severity: "warning", title: "Descartes: session alert", body: `rule_id=${alert?.rule_id}` };
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

function daemonStatusContext(daemonStatus) {
  return daemonStatus ? {
    ts: daemonStatus.ts,
    state: daemonStatus.state,
    mode: daemonStatus.mode,
    interval_ms: daemonStatus.profile?.interval_ms,
    points_written: daemonStatus.points_written,
  } : null;
}

// S13 must-fix 6: the pre-S13 prompt builder, kept VERBATIM (byte-for-byte, including the exact
// context key order) so its output is byte-identical for a fixed input -- pinned by a test that
// compares against a frozen copy of the pre-S13 implementation. Do not reformat this function.
function buildMetricAlertPrompt({ alerts, historySummary, daemonStatus }) {
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
  daemon_status: daemonStatusContext(daemonStatus),
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

// S13 must-fix 6: learned-namespace (constraint/provenance/baseline/identity) prompt template.
// Adds namespace context and one extra caution rule (mined findings are treated more
// conservatively than hand-authored fixed rules); it grants NO new capability -- same bounded JSON
// contract, same hard rules, same enableTools:false session (enforced in pi-harness.js, unrelated
// to prompt content).
function buildLearnedNamespaceAlertPrompt(namespace) {
  return function namespacedAlertPrompt({ alerts, historySummary, daemonStatus }) {
    return `You are Descartes alert intelligence. A deterministic local monitoring rule from the "${namespace}" learned-artifact family woke you up.

Decide whether the user should receive a notification now and write the exact bounded notification content.

Hard rules:
- Use only the alert records and summaries in this prompt.
- Do not claim facts not present here.
- Do not recommend or imply that any remediation action was taken.
- Prefer not notifying for stale/low-confidence/noisy alerts unless the user likely needs attention.
- This finding comes from a mined/learned artifact, not a hand-authored fixed rule; prefer a
  conservative severity and prefer not notifying when uncertain.
- Keep notification title <= 80 chars and body <= 240 chars.

Context:
${JSON.stringify({
  namespace,
  alerts: alerts.map(compactAlert),
  history_summary: compactHistory(historySummary),
  daemon_status: daemonStatusContext(daemonStatus),
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
  };
}

// S13 must-fix 6: template dispatch REGISTRY, keyed by namespace. Registry membership doubles as
// the reviewed-namespace allowlist for must-fix 1's eligibility rule -- a namespace with no entry
// here is excluded from LLM adjudication even if a future classification map or enabled_namespaces
// entry names it, so an un-reviewed namespace's data can never ship under another namespace's
// framing.
const PROMPT_TEMPLATES = {
  metric: buildMetricAlertPrompt,
  constraint: buildLearnedNamespaceAlertPrompt("constraint"),
  provenance: buildLearnedNamespaceAlertPrompt("provenance"),
  baseline: buildLearnedNamespaceAlertPrompt("baseline"),
  identity: buildLearnedNamespaceAlertPrompt("identity"),
};

export const ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION = "s13.namespace-dispatch.v1";

// S13 must-fix 1: CLOSED-MAP namespace classification, fail-closed for unknowns. A naive
// prefix-before-first-dot or "non-learned => metric" umbrella is FAIL-OPEN and would send Slice-8
// learned.* self-audit findings to the LLM by default -- this is a fixed, exhaustive map instead.
export function classifyAlertNamespace(ruleId) {
  const id = String(ruleId ?? "");
  // A self-audit finding must never reach L2 (plan section 110): hard-excluded, never opt-in-able,
  // checked before anything else so no enabled_namespaces misconfiguration can override it.
  if (id.startsWith("learned.")) return { namespace: "learned", hardExcluded: true };
  if (id.startsWith("daemon.") || id.startsWith("system.") || id.startsWith("disk.")) return { namespace: "metric", hardExcluded: false };
  if (id.startsWith("constraint.")) return { namespace: "constraint", hardExcluded: false };
  if (id.startsWith("provenance.")) return { namespace: "provenance", hardExcluded: false };
  if (id.startsWith("baseline.")) return { namespace: "baseline", hardExcluded: false };
  if (id.startsWith("identity.")) return { namespace: "identity", hardExcluded: false };
  // Anything else (unrecognized prefix): fail closed, not a generic "metric" fallback.
  return { namespace: undefined, hardExcluded: false };
}

// S13 must-fix 1: LLM eligibility = (namespace NOT hard-excluded) AND (namespace in
// enabled_namespaces) AND (a prompt template is REGISTERED for that namespace). An
// unrecognized/un-templated namespace is EXCLUDED, not a generic fallback.
function classifyAlertEligibility(alert, config) {
  const { namespace, hardExcluded } = classifyAlertNamespace(alert?.rule_id);
  if (hardExcluded) return { eligible: false, namespace, reason: "hard_excluded_learned" };
  if (!namespace) return { eligible: false, namespace, reason: "unknown_namespace" };
  if (!PROMPT_TEMPLATES[namespace]) return { eligible: false, namespace, reason: "unregistered_template" };
  const enabledNamespaces = Array.isArray(config?.enabled_namespaces) ? config.enabled_namespaces : [];
  if (!enabledNamespaces.includes(namespace)) return { eligible: false, namespace, reason: "not_consented" };
  return { eligible: true, namespace, reason: undefined };
}

function summarizeExclusions(classified) {
  const counts = { hard_excluded_learned: 0, unknown_namespace: 0, unregistered_template: 0, not_consented: 0 };
  for (const entry of classified) {
    if (entry.eligible) continue;
    counts[entry.reason] = (counts[entry.reason] ?? 0) + 1;
  }
  return counts;
}

export function alertIntelligencePrompt({ alerts, historySummary, daemonStatus }) {
  // S13 remediation (defense-in-depth): the namespace/template dispatch just below is chosen from
  // alerts[0].rule_id alone. A future refactor that batched multiple alerts into one call would
  // silently ship alerts[1..n]'s data under alerts[0]'s namespace framing -- the exact
  // un-consented-data leak this whole gate exists to prevent. Enforcing the single-alert invariant
  // HERE (not only at the sole call site below) fails CLOSED: no prompt gets built, so nothing
  // ships, and the mis-refactor is loud instead of silently wrong. The sole production caller
  // always passes `alerts: [alert]`, so this never triggers in normal operation.
  if (!Array.isArray(alerts) || alerts.length !== 1) {
    throw new Error(`alertIntelligencePrompt requires exactly one alert, got ${Array.isArray(alerts) ? alerts.length : typeof alerts}`);
  }
  const ruleId = alerts?.[0]?.rule_id;
  const { namespace } = classifyAlertNamespace(ruleId);
  const template = namespace ? PROMPT_TEMPLATES[namespace] : undefined;
  if (!template) {
    // Defensive: adjudicateAlertNotifications already filters to eligible (registered-template)
    // alerts before ever calling this, so this should be unreachable in normal operation. Throwing
    // rather than silently falling back to the metric template keeps an un-reviewed namespace's
    // data from ever shipping under metric framing.
    throw new Error(`No registered alert intelligence prompt template for rule_id: ${ruleId}`);
  }
  return template({ alerts, historySummary, daemonStatus });
}

function hashPromptText(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// S13 remediation -- DEFERRED residual I/O-crash points (recorded, not fixed, in this pass):
// `readAlertIntelligenceConfig` (called a few lines below) and `readAuditRecords` (called further
// below, seeding the budget counters) only guard ENOENT; a non-ENOENT read failure (EACCES/EIO)
// still throws out of a daemon tick. They must NOT be naively wrapped with an empty/default
// fallback: the audit read seeds the budget counters, so defaulting to "no history" would
// UNDER-count prior calls and let this tick OVER-call, breaking the total <= max_calls_per_hour
// invariant. The correct fix (a separate follow-up slice) is FAIL-CLOSED -- on audit/config read
// failure, skip adjudication entirely for that tick (zero calls) -- or a write-ahead/transactional
// audit. Likewise, `appendAuditRecord` failures (the ok-path append inside the per-alert try block
// below funnels into its own catch; the error-path append inside that catch rethrows out of the
// per-alert loop) are the same bucket: swallowing them would leave a call that WAS made unrecorded,
// so the next tick under-counts and over-calls. Crash-looping is not "conservative" either
// (auto-restart can still over-call once per restart) -- the deferral here is a matter of SCOPE,
// not a claim that the current unguarded behavior is safe; the fix is the same fail-closed /
// write-ahead design as above.
export async function adjudicateAlertNotifications(descartesPaths, evaluation, options = {}) {
  const now = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const config = options.config ?? await readAlertIntelligenceConfig(descartesPaths);
  const dueIds = evaluation?.notification_due_ids ?? [];
  if (!config.enabled) return { status: "disabled", decisions: [] };
  if (dueIds.length === 0) return { status: "no_due_alerts", decisions: [] };

  const dueAlerts = (evaluation.alerts ?? []).filter((alert) => dueIds.includes(alert.id));

  // S13 must-fix 4: namespace/eligibility filter applied BEFORE any rate-limit accounting. When
  // alerts are due but none are LLM-eligible (all un-consented / hard-excluded / un-templated),
  // this returns a DISTINCT status -- never "rate_limited", since nothing was actually rate-limited.
  const classified = dueAlerts.map((alert) => ({ alert, ...classifyAlertEligibility(alert, config) }));
  const eligibleAlerts = classified.filter((entry) => entry.eligible).map((entry) => entry.alert);
  const excluded = summarizeExclusions(classified);
  if (eligibleAlerts.length === 0) {
    return { status: "no_eligible_alerts", decisions: [], excluded };
  }

  // S13 must-fix 2: process CRITICAL due alerts before non-critical ones within a tick (partition
  // before any truncation/dropping).
  const orderedAlerts = [
    ...eligibleAlerts.filter((alert) => alert.severity === "critical"),
    ...eligibleAlerts.filter((alert) => alert.severity !== "critical"),
  ];

  const audit = await readAuditRecords(descartesPaths);
  const historical = partitionRecentAuditCounts(audit, now);
  // RUNNING per-class counters, seeded from trailing-hour audit history and incremented as calls
  // are admitted within this loop -- this is what lets "so_far" include calls already made earlier
  // in THIS invocation, which a one-shot remaining/slice computation could not express.
  let runningCritical = historical.critical;
  let runningNonCritical = historical.nonCritical;

  const maxCallsPerHour = config.max_calls_per_hour;
  const criticalReservation = config.critical_reservation;
  const nonCriticalBudget = Math.max(0, maxCallsPerHour - criticalReservation);

  const createSession = options.createSession ?? (await import("./pi-harness.js")).createPrivateAlertSession;
  const deliverNotification = options.deliverNotification ?? (await import("./notification-delivery.js")).deliverNotificationDecision;

  const records = [];
  let droppedTotal = 0;
  let droppedCritical = 0;

  // S13 must-fix 3, drop site 1 ("fully-exhausted early path"): if the trailing hour (plus nothing
  // yet made this invocation) already meets/exceeds the hard cap, every eligible alert -- critical
  // included, since critical admission also requires total_so_far < max -- is dropped without
  // attempting a call. This is the same arithmetic the per-alert loop below would reach on its
  // first iteration; naming it separately keeps the "nothing new was admitted this tick" case cheap
  // and legible.
  if (runningCritical + runningNonCritical >= maxCallsPerHour) {
    droppedTotal = orderedAlerts.length;
    droppedCritical = orderedAlerts.filter((alert) => alert.severity === "critical").length;
  } else {
    for (const alert of orderedAlerts) {
      const isCritical = alert.severity === "critical";
      const totalSoFar = runningCritical + runningNonCritical;
      // S13 must-fix 2 INVARIANT: total LLM calls in the trailing hour (+ this invocation) must
      // never exceed max_calls_per_hour. A critical alert is admitted iff total_so_far < max
      // (drop site 3, "total-cap drop"); a non-critical alert additionally requires
      // non_critical_so_far < max - critical_reservation (drop site 2, "non-critical-cap drop").
      // Because admission always requires total_so_far < max, admitting always leaves
      // total_so_far + 1 <= max -- the invariant holds by construction on every admission.
      const admitted = isCritical
        ? totalSoFar < maxCallsPerHour
        : totalSoFar < maxCallsPerHour && runningNonCritical < nonCriticalBudget;

      if (!admitted) {
        droppedTotal += 1;
        if (isCritical) droppedCritical += 1;
        continue;
      }
      if (isCritical) runningCritical += 1;
      else runningNonCritical += 1;

      let session;
      const startedAt = new Date().toISOString();
      const { namespace } = classifyAlertNamespace(alert.rule_id);
      let promptText;
      try {
        // S13 must-fix 5: include_history_summary/include_daemon_status are wired here -- omitted
        // entirely (undefined, not just falsy) rather than unconditionally included as pre-S13.
        promptText = alertIntelligencePrompt({
          alerts: [alert],
          historySummary: config.include_history_summary ? evaluation.history_summary : undefined,
          daemonStatus: config.include_daemon_status ? evaluation.daemon_status : undefined,
        });
        const result = await createSession(descartesPaths, {
          modelPattern: config.model_pattern,
          thinkingLevel: config.thinking_level,
        });
        session = result.session;
        await session.prompt(promptText);
        const rawText = lastAssistantText(session.messages);
        const decision = normalizeAlertNotificationDecision(parseDecisionJson(rawText));
        const delivery = decision.notify
          ? await deliverNotification(descartesPaths, decision, { now, alertId: alert.id, ruleId: alert.rule_id })
          : undefined;
        records.push(await appendAuditRecord(descartesPaths, {
          ts: now,
          alert_id: alert.id,
          rule_id: alert.rule_id,
          namespace,
          // Distinct from decision.severity: the ALERT's severity, used for budget classification,
          // recorded so the trailing-hour partition above can reconstruct it without re-deriving
          // from rule_id-only history.
          alert_severity: alert.severity,
          status: "ok",
          selected_model: result.selectedModel ? { provider: result.selectedModel.provider, id: result.selectedModel.id ?? result.selectedModel.name } : undefined,
          thinking_level: result.selectedThinkingLevel,
          prompt_started_at: startedAt,
          // S13 nice-to-have: a stable hash of the exact prompt string + template version, not a
          // full payload copy -- verifies "what left the machine" without duplicating sensitive
          // compacted diagnostics at rest / bloating the never-rotated audit file.
          prompt_hash: hashPromptText(promptText),
          prompt_template_version: ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION,
          decision,
          delivery,
        }));
      } catch (error) {
        records.push(await appendAuditRecord(descartesPaths, {
          ts: now,
          alert_id: alert.id,
          rule_id: alert.rule_id,
          namespace,
          alert_severity: alert.severity,
          status: "error",
          prompt_hash: promptText ? hashPromptText(promptText) : undefined,
          prompt_template_version: promptText ? ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION : undefined,
          error: error instanceof Error ? error.message : String(error),
        }));
      } finally {
        try {
          session?.dispose?.();
        } catch {
          // A throwing dispose() must not crash the tick -- the session is already finished with
          // either way, so there's nothing left to do with the error but drop it.
        }
      }
    }
  }

  let budgetExhausted;
  if (droppedTotal > 0) {
    try {
      budgetExhausted = await emitBudgetExhaustedSignal(descartesPaths, { now, droppedTotal, droppedCritical, deliverNotification });
    } catch (error) {
      // Reliability remediation: emitBudgetExhaustedSignal is a PURE NOTIFICATION -- it only
      // touches notification-delivery.jsonl (the cooldown read in hasRecentBudgetExhaustedNotification
      // and the appendDeliveryAudit write inside deliverNotification), and has ZERO effect on budget
      // accounting, which is seeded exclusively from llm-decisions.jsonl. A filesystem error here
      // (realistically ENOSPC: the cooldown read succeeds but the append write fails) must not
      // propagate out of a daemon tick and crash-loop the process -- the per-alert LLM loop above
      // already catches-and-continues through the identical deliverNotification for the same reason.
      // Swallow and record the degradation in the tick's return value (not just a log line) so
      // callers/tests can observe it. Worst case of swallowing: a skipped, or (once the FS heals)
      // duplicated, budget_exhausted notification -- strictly better than a crashed daemon.
      budgetExhausted = { fired: false, reason: "error", error: error instanceof Error ? error.message : String(error) };
      console.warn(`descartes: alert intelligence budget_exhausted signal failed: ${budgetExhausted.error}`);
    }
  }

  const status = records.length === 0 && droppedTotal > 0 ? "rate_limited" : "ok";
  return { status, decisions: records, excluded, dropped_total: droppedTotal, dropped_critical: droppedCritical, budget_exhausted: budgetExhausted };
}
