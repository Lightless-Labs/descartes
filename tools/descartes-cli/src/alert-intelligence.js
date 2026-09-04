import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
import { SERVICE_APPEARED_RULE_ID, SERVICE_DISAPPEARED_RULE_ID } from "./service-baseline.js";
import { CANARY_TAMPERED_RULE_ID, CANARY_TRIPPED_RULE_ID } from "./canary-baseline.js";
import { PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "./process-lineage-baseline.js";
import { SCHEDULED_JOB_APPEARED_RULE_ID } from "./persistence-baseline.js";
import { CREDENTIAL_ACCESS_RULE_ID } from "./credential-access-baseline.js";
import {
  DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
  SESSION_CHURN_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
} from "./session-baseline.js";
// Slice 7.2 (recommend-only containment surface plan, 2026-08-21): a new, explicit
// alert-intelligence.js -> containment-recommend.js dependency edge (plan §6 File Map note on
// this exact choice), used only to (a) widen the deterministic local-delivery allowlist below and
// (b) render a containment.recommend.* record's notification body from its own stored,
// already-sanitized diagnostics -- Slice 7.2.c's must-fix option (a). containment-recommend.js
// itself imports nothing from this file, so this is a one-directional edge, not a cycle.
import { CONTAINMENT_RECOMMEND_LABEL, containmentRecommendationRuleIds, renderStoredRecommendationText } from "./containment-recommend.js";

// Slice 4b (observed-incident collectors plan), Decision 3b / Fable review MUST-FIX 4: the
// widened deterministic-delivery allowlist is composed HERE, not in session-baseline.js.
// Widening session-baseline.js's own exported DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS in place
// would force a forbidden session-baseline.js -> peer-baseline.js dependency (peer-baseline.js
// already depends on the shared welford-stats.js; session-baseline.js stays peer-agnostic, full
// stop). session-baseline.js's own DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS export stays EXACTLY
// [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID], unchanged, for every other consumer (see
// the two shipped tests this surface touches: test/session-baseline.test.js:677-678 and
// test/alert-intelligence.test.js:965-967, both of which remain green as-is). This module-private
// constant is what the delivery function's allowlist check actually uses. Widened again
// (service-disappearance-alert plan, 2026-07-23) to add SERVICE_DISAPPEARED_RULE_ID, composed here
// for the same reason -- avoids a forbidden service-baseline.js -> session-baseline.js coupling.
// Widened again (Slice 4c, observed-incident collectors plan, 2026-07-23) to add
// PEER_COUNT_DROP_RULE_ID alongside its sibling PEER_COUNT_SPIKE_RULE_ID -- same rationale,
// same module (peer-baseline.js already imported above).
const ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS = [
  ...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS,
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID,
  SERVICE_DISAPPEARED_RULE_ID,
  CANARY_TRIPPED_RULE_ID,
  // Tamper fix (canary v0 finalization): canary.tampered is the SAME fail-closed
  // canary.*-namespace posture as its sibling CANARY_TRIPPED_RULE_ID above (classifyAlertNamespace
  // is UNTOUCHED by this fix -- "canary.tampered" fails the identical unknown_namespace path
  // "canary.tripped" always has, so it can never reach LLM adjudication either) and needs the
  // identical deterministic local-delivery treatment or "tampering is suspicious in itself" would
  // silently never notify the operator, defeating the entire point of the fix.
  CANARY_TAMPERED_RULE_ID,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
  // Persistence baseline (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md, Slices B/C):
  // scheduled_job.appeared/service.appeared are the SAME fail-closed unknown_namespace posture as
  // their sibling *.disappeared/novel_edge rule_ids above — no classifyAlertNamespace branch
  // recognizes "scheduled_job."/"service." as a prefix, so both are structurally LLM-ineligible
  // regardless of enabled_namespaces and need the identical deterministic local-delivery
  // treatment or a new scheduled job/service would silently never notify the operator.
  SCHEDULED_JOB_APPEARED_RULE_ID,
  SERVICE_APPEARED_RULE_ID,
  // Credential-file-access signal (Slice D): credential.access is likewise unknown_namespace
  // ("credential." has no reserved prefix) — same deterministic local-delivery treatment.
  CREDENTIAL_ACCESS_RULE_ID,
  // Slice 7.2.a (recommend-only containment surface plan): containment.recommend.* is
  // ADDITIONALLY hard-excluded from LLM adjudication below (classifyAlertNamespace) -- this
  // allowlist entry only routes it to the SAME straight-to-notification branch every other
  // unknown_namespace/hard-excluded rule_id family above already uses, never the LLM. Derived
  // from containmentRecommendationRuleIds() (containment-recommend.js), never hand-duplicated,
  // so this can never register a rule_id the recommendation map doesn't actually emit.
  ...containmentRecommendationRuleIds(),
];

export const DEFAULT_ALERT_INTELLIGENCE_MAX_CALLS_PER_HOUR = 3;

// S13 must-fix 2: a critical-severity call is guaranteed a slot out of max_calls_per_hour so a
// burst of non-critical (e.g. learned-artifact) findings cannot starve a real emergency
// adjudication. Default reserves exactly one call/hour for critical alerts.
export const DEFAULT_ALERT_INTELLIGENCE_CRITICAL_RESERVATION = 1;

// F5 fix: bounds the per-alert LLM call (createSession + session.prompt()) so a hung/slow model
// request cannot freeze a daemon tick indefinitely. Kept meaningfully UNDER the daemon's fast-tick
// interval, mirroring this codebase's own existing precedent (daemon.js's structural-collector
// deadline is 45_000ms against a 60_000ms DEFAULT_DAEMON_INTERVAL_MS) -- do not raise this to
// 60_000+ms, which would let one adjudication push a tick past its own interval by design. Raising
// config.thinking_level trades adjudication quality against this same budget; that tension is an
// operator decision, not something a longer default should paper over.
export const DEFAULT_ALERT_INTELLIGENCE_MODEL_DEADLINE_MS = 30_000;

// S13 must-fix 1: the CLOSED set of namespaces that MAY ever be opted into LLM adjudication.
// "learned" is deliberately never a member of this list -- it is hard-excluded below, not merely
// defaulted off, and `normalizeEnabledNamespaces`/the alerts.js CLI reject it explicitly.
//
// "correlation" (Slice 6, observed-incident collectors plan): a new, real, consentable namespace
// for the cross-stream login/kill-proximity join (incident-correlation.js). Unlike Slice 4's
// session.*/unknown_namespace rule_ids (permanently un-consentable), this IS a genuine opt-in
// surface -- see the DEFAULT_ENABLED_NAMESPACES comment directly below for why it stays off by
// default regardless of this registration.
export const KNOWN_ALERT_NAMESPACES = ["metric", "constraint", "provenance", "baseline", "identity", "correlation"];

// S13 must-fix 1: metric-only users (the entire installed base pre-S13) see ZERO behavior change --
// every fixed/legacy alert (daemon./system./disk.) classifies as "metric" and stays enabled by
// default; every learned namespace (constraint/provenance/baseline/identity/correlation) defaults
// OFF even when alert-intelligence.json has enabled:true. Slice 6 (observed-incident collectors
// plan), hard requirement: "correlation" joining KNOWN_ALERT_NAMESPACES above must NOT change this
// list -- a metric-only/default user's enabled_namespaces never contains "correlation" unless they
// explicitly run `descartes alerts intelligence enable-namespace correlation`.
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

// F5 fix: shared by normalizeAlertIntelligenceConfig (for config persisted/read through the normal
// path) AND read directly at the adjudication call site (see adjudicateAlertNotifications below) --
// the call site cannot assume normalization already ran, since options.config may be supplied as a
// raw, un-normalized literal.
function resolveModelDeadlineMs(value) {
  const raw = Number(value);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_ALERT_INTELLIGENCE_MODEL_DEADLINE_MS;
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
    // F5 fix: see resolveModelDeadlineMs's own doc comment for why this is also read raw, directly
    // off config, at the adjudication call site below -- not only here.
    model_deadline_ms: resolveModelDeadlineMs(config.model_deadline_ms),
    enabled_namespaces: normalizeEnabledNamespaces(config.enabled_namespaces),
    // S13 must-fix 5: these flags were already normalized pre-S13 but never actually wired into
    // the prompt -- see adjudicateAlertNotifications, which now gates historySummary/daemonStatus
    // inclusion on them.
    include_history_summary: config.include_history_summary !== false,
    include_daemon_status: config.include_daemon_status !== false,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

function errorLabel(error) {
  return error?.code ?? (error instanceof Error ? error.message : String(error));
}

export async function readAlertIntelligenceConfig(descartesPaths) {
  const { configFile } = resolveAlertIntelligencePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeAlertIntelligenceConfig();
    // S13 I/O hardening: a non-ENOENT read failure (EACCES/EIO/ENOSPC/EROFS/EISDIR) fails CLOSED
    // rather than throwing out of a daemon tick -- mirrors the corrupt-JSON handling just below.
    // `unavailable: true` is an additive marker (enabled stays false, so adjudicate short-circuits
    // to "disabled" -- zero LLM calls); the alerts.js CLI mutation guard also checks it to refuse
    // clobbering a potentially-intact-but-unreadable config with defaults.
    console.warn(`descartes: alert-intelligence.json read failed (${errorLabel(error)}); treating alert intelligence as disabled this tick`);
    return { ...normalizeAlertIntelligenceConfig(), unavailable: true };
  }
  try {
    return normalizeAlertIntelligenceConfig(JSON.parse(contents));
  } catch (error) {
    // S13 nice-to-have: fail CLOSED on a corrupt config file rather than throwing out of a daemon
    // tick -- mirrors constraint-store.js's loadLearnedConfig (~L196-204). `corrupt: true` is an
    // additive marker only; callers that only read `.enabled` are unaffected (it's still false).
    // Warn for parity with the unavailable path above: the daemon ignores the returned status, so
    // without this a corrupt config would silently disable alert intelligence on every tick with no
    // operator signal (only surfaced via `descartes alerts intelligence status`).
    console.warn(`descartes: alert-intelligence.json is corrupt (${errorLabel(error)}); treating alert intelligence as disabled`);
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

// S13 I/O hardening -- IN-PROCESS (never persisted) latch, keyed by the RESOLVED audit-file path.
// Persisting this to disk would require the very writes that are failing, so it lives only in
// process memory; it is keyed by path (not global) so two Descartes installs / two unique-temp-dir
// tests never cross-pollute each other's degraded state. See adjudicateAlertNotifications' probe
// -heal logic and the documentation comment above it for the full rationale.
const auditWriteDegradedPaths = new Set();

// Never throws: swallows any appendFn failure, console.warns, and returns null so a caller can
// distinguish "recorded" (truthy) from "not recorded" (null) without a second try/catch. Accepts
// the append function as a parameter (rather than closing over the module-private default) so the
// DI seam (options.appendAuditRecord) and the real default share this exact same safety wrapper.
async function safeAppendAuditRecord(appendFn, descartesPaths, record) {
  try {
    return await appendFn(descartesPaths, record);
  } catch (error) {
    console.warn(`descartes: alert intelligence audit append failed (${errorLabel(error)}); this call will not be recorded in llm-decisions.jsonl`);
    return null;
  }
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
  if (!Number.isFinite(tsMs)) return false;
  // daybreak-blue #3 (HIGH) point 4: a future-dated record (the local clock stepped back, or a
  // stray future ts) is CLAMPED into the trailing-hour window rather than excluded -- excluding it
  // would under-count the budget (fail-open: admits an extra call). Only records genuinely older
  // than windowMs are excluded.
  return nowMs - tsMs < windowMs;
}

// S13 must-fix 2: partitions the trailing-hour audit history into per-class counts. These seed
// the RUNNING per-class counters used by the admission loop below -- replacing the pre-S13
// one-shot `remaining`/`slice(0, remaining)` computation, which could not express "total calls
// already made earlier in this same invocation" once critical/non-critical accounting diverged.
function partitionRecentAuditCounts(records, now, windowMs = 60 * 60 * 1000) {
  let critical = 0;
  let nonCritical = 0;
  for (const record of records) {
    // daybreak-blue #3 (HIGH) point 3: a successfully-PARSED record with a non-finite ts (e.g.
    // `{"ts":"invalid",...}`) cannot be dated, so it cannot be aged out either -- count it as ONE
    // in-window non-critical call rather than silently dropping it. Dropping it under-counts the
    // trailing-hour budget (fail-open: admits an extra call), same failure mode as an unparseable
    // line would cause if ignored outright. "non-critical" matches this file's existing conservative
    // default for calls whose real class cannot be determined (see auditRecordIsCritical's own doc
    // comment, just above).
    if (!Number.isFinite(new Date(record?.ts).getTime())) {
      nonCritical += 1;
      continue;
    }
    if (!isWithinTrailingHour(record.ts, now, windowMs)) continue;
    if (auditRecordIsCritical(record)) critical += 1;
    else nonCritical += 1;
  }
  return { critical, nonCritical };
}

// daybreak-blue #3 (HIGH) points 1-2: a STRICT, budget-local variant of readAuditRecords, used ONLY
// to seed the trailing-hour budget counters in adjudicateAlertNotifications below. readAuditRecords
// itself (and its export readAlertIntelligenceAudit) stay UNCHANGED -- calibration.js/tuning-store.js
// rely on their tolerant "silently ignore corrupt lines" behavior for reporting, and this file's own
// tests pin that tolerance.
//
// For the BUDGET seed, silently ignoring an unparseable line is a fail-open bug: the invariant this
// gate exists to protect is "total LLM calls (trailing hour + this invocation) <= max_calls_per_hour"
// -- an unparseable line that is quietly dropped is an unaccounted-for historical call, which can let
// this tick over-admit.
//
// Policy: an unparseable line counts toward the budget IFF the nearest parseable record AFTER it (or
// EOF, if none exists) is within the trailing-hour window. appendAuditRecord below always writes
// `ts: now` and the file is append-ordered (monotonic ts) and never rotated/truncated by this
// process, so a corrupt line is bounded by its neighbours:
//   - a corrupt line followed by an OLD, out-of-window parseable record ages out (the corruption
//     itself is old) -- this must NEVER count every corrupt line forever, since the file is never
//     rotated and that would permanently wedge adjudication;
//   - a corrupt line with NO following record (the last line in the file -- exactly what a write
//     interrupted mid-append, e.g. by a crash, produces) fails closed and always counts, since a
//     fresh truncation is exactly the case this policy must not silently ignore.
// This must also NEVER "skip the tick outright on any corrupt line" -- that permanently wedges
// adjudication into audit_unavailable just as badly as under-counting wedges it open.
async function readBudgetAuditRecordsStrict(descartesPaths, now) {
  const { auditFile } = resolveAlertIntelligencePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(auditFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const lines = contents.split("\n").filter((line) => line.trim());
  const parsedByIndex = lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return undefined; // unparseable -- position preserved, bounded below
    }
  });
  const records = [];
  for (let index = 0; index < parsedByIndex.length; index += 1) {
    const parsed = parsedByIndex[index];
    if (parsed !== undefined) {
      records.push(parsed);
      continue;
    }
    let boundTs = now; // EOF (no following parseable record) -- fails closed, always counts.
    for (let lookahead = index + 1; lookahead < parsedByIndex.length; lookahead += 1) {
      if (parsedByIndex[lookahead] !== undefined) {
        boundTs = parsedByIndex[lookahead].ts;
        break;
      }
    }
    records.push({ ts: boundTs, corrupt_line: true });
  }
  return records;
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
// Slice 4b (observed-incident collectors plan), Decision 3b / Fable review MUST-FIX 4: this same
// branch now also delivers a due peer.count_spike (also unknown_namespace — Decision 3) — see
// ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS above, composed in THIS file (not session-baseline.js).
//
// Mirrors emitBudgetExhaustedSignal's own "straight through deliverNotificationDecision, NEVER
// through the LLM, a session, or enableTools" precedent:
//   - scoped by an explicit rule_id ALLOWLIST (ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, composed
//     locally above from session-baseline.js's own two-id export plus PEER_COUNT_SPIKE_RULE_ID) —
//     never a general unknown-namespace bypass, so this cannot silently swallow some future,
//     unrelated fail-closed namespace;
//   - the decision handed to deliverNotificationDecision is hand-built and deterministic — never
//     a session, never an LLM call;
//   - reuses the notification_due_ids/cooldown state applyAlertCandidates already computed for
//     every candidate (including these two rule_ids) inside evaluateAndPersistAlerts — no new
//     cooldown machinery. Correction, load-bearing (must-fix 3): applyAlertCandidates stamps
//     last_notified/cooldown_until on a candidate even when nothing is actually delivered
//     downstream — that stamp reflects only that the candidate was processed, not that any
//     human-visible delivery happened. This function's own tests assert on an actual call into
//     (or mock of) deliverNotificationDecision, never merely on the cooldown/last_notified fields;
//   - the delivered body is counts/hash-only for session.*/peer.* — never a raw session/peer
//     identity, matching the sanitized diagnostics shape those candidate builders already produce.
//     EXCEPTION (operator decision, 2026-07-24, scoped to service.disappeared ONLY): the delivered
//     body for service.disappeared names the disappeared service in cleartext (sanitized, never
//     raw/unsanitized) — see buildSessionAlertNotificationDecision's service.disappeared branch
//     below for the full rationale. session.*/peer.* bodies are unaffected by this exception.
export async function emitSessionAlertSignals(descartesPaths, evaluation, options = {}) {
  // daybreak-blue #7 (MEDIUM) point 2, defense-in-depth: a non-array `notification_due_ids` (a
  // corrupt/foreign evaluation shape) must degrade to "nothing due", not throw ("is not iterable")
  // out of `new Set(...)` and abort the caller's tick.
  const dueIds = new Set(Array.isArray(evaluation?.notification_due_ids) ? evaluation.notification_due_ids : []);
  if (dueIds.size === 0) return { fired: [] };

  // Slice 4b Decision 3b (Fable review MUST-FIX 4): scoped to the LOCALLY-composed allowlist
  // (session-baseline.js's own two ids, plus PEER_COUNT_SPIKE_RULE_ID/PEER_COUNT_DROP_RULE_ID/
  // SERVICE_DISAPPEARED_RULE_ID -- see ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS above), never the
  // general unknown-namespace bypass — a due metric/other alert never reaches this branch just
  // because it also happens to classify as unknown_namespace.
  //
  // daybreak-blue #7 (MEDIUM) point 2, defense-in-depth: a non-array `evaluation.alerts` likewise
  // degrades to `[]` rather than throwing ("...filter is not a function") on a corrupt/foreign shape.
  const dueSessionAlerts = (Array.isArray(evaluation?.alerts) ? evaluation.alerts : []).filter(
    (alert) => dueIds.has(alert.id) && ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS.includes(alert.rule_id),
  );
  if (dueSessionAlerts.length === 0) return { fired: [] };

  let deliverNotification;
  try {
    // daybreak-blue #7 (MEDIUM) point 1: this dynamic import is an unguarded await on the
    // production path (it only runs when the DI seam, options.deliverNotification, is absent). A
    // module-load failure (e.g. EIO/EACCES reading an uncached module file) must DEGRADE this one
    // alert family (log + report every due alert as failed), never abort the whole daemon tick --
    // mirrors the `dependencies_unavailable` pattern in adjudicateAlertNotifications below.
    deliverNotification = options.deliverNotification ?? (await import("./notification-delivery.js")).deliverNotificationDecision;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`descartes: emitSessionAlertSignals notification-delivery module load failed (${message}); degrading this tick (zero deliveries), all due session-family alerts reported failed`);
    return { fired: [], failed: dueSessionAlerts.map((dueAlert) => dueAlert.id) };
  }
  const now = options.now ?? new Date().toISOString();

  // Reliability fix (canary v0 finalization, FIX-B): this loop was previously a bare, unguarded
  // `await deliverNotification(...)` -- a PRE-EXISTING general pattern shared by every rule_id in
  // ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS (session.*/peer.*/service.disappeared), not something
  // canary-specific. deliverNotificationDecision (notification-delivery.js) CAN throw on a genuine
  // I/O failure (a non-ENOENT readNotificationDeliveryConfig failure, or an appendDeliveryAudit
  // write failure -- ENOSPC/EACCES/EROFS/etc, itself uncaught inside that function). Left unguarded,
  // a single alert's delivery failure propagated straight out of this function and, at daemon.js's
  // call site (unlike its sibling safeAdjudicateAlertNotifications wrapper), all the way out of
  // runDaemonIteration -- ABORTING THE ENTIRE TICK (every alert family, not just this one, plus the
  // structural-checkpoint/status-write work already completed this tick going unreported). A single
  // alert-family delivery I/O failure must DEGRADE (log + skip that one delivery), never abort the
  // tick: catch here, per-alert, and continue to the next due alert. `canary.tampered` inherits this
  // fix by virtue of sharing this exact loop (ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS), not via a
  // canary-scoped special case -- a real daemon-robustness win for the whole family, not just canary.
  const fired = [];
  const failed = [];
  for (const alert of dueSessionAlerts) {
    const decision = buildSessionAlertNotificationDecision(alert);
    try {
      const delivery = await deliverNotification(descartesPaths, decision, { now, alertId: alert.id, ruleId: alert.rule_id });
      // daybreak-blue #6 (MEDIUM): deliverNotificationDecision RESOLVES (it never throws) with a
      // status enum -- "error"/"unavailable" mean the notification did NOT reach the operator, and
      // must not be reported as fired. Every other resolved status ("recorded"/"delivered"/
      // "skipped"/"disabled"/"cli_only", or a bare `undefined` from an older/simpler fake) is an
      // intentional non-failure outcome -- "disabled"/"cli_only" are config states, not failures --
      // and stays `fired`, matching this function's pre-existing "only a throw means failed"
      // contract for those.
      if (delivery?.status === "error" || delivery?.status === "unavailable") {
        failed.push(alert.id);
      } else {
        fired.push(alert.id);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`descartes: deterministic alert notification delivery failed for alert ${alert.id} (rule_id=${alert.rule_id}): ${message}; skipping this delivery, continuing the tick`);
      failed.push(alert.id);
    }
  }
  return { fired, failed };
}

// Counts/hash-only body (must-fix 3) for every branch EXCEPT service.disappeared: every field
// interpolated below is a finite number or a short closed-enum/hash string already produced by
// session-baseline.js's/peer-baseline.js's sanitizeDiagnostics-gated candidate builders — never a
// raw session/peer identity, which never reaches this layer's inputs at all for those rule_ids
// (their diagnostics only ever carry counts/z-scores/confidence_state or hashed entity_key/
// fingerprints). service.disappeared is a SCOPED, INTENTIONAL exception (operator decision,
// 2026-07-24): its body interpolates `diagnostics.service_name`, a sanitized (charset-bounded, NOT
// hashed) cleartext service name — see that branch below for the full rationale. This exception
// does not widen to any other rule_id; session/peer identity stays hashed/counts-only.
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
  // Slice 4b Decision 3b: the third deterministic-delivery branch. Body shape is identical to
  // session.count_drop's own — counts/z-score/confidence_state only, peer-flavored wording — never
  // a raw peer host/IP/pubkey, which never reaches this layer's inputs at all (peer-baseline.js's
  // diagnostics only ever carry counts/z-scores/confidence_state, no per-peer identity). Stored
  // severity is always "warning" here (peer-baseline.js's own MUST-FIX 1 cap), but this branch
  // reads `alert.severity` rather than hardcoding "warning" so a future cap-lift doesn't need a
  // second edit here.
  if (alert?.rule_id === PEER_COUNT_SPIKE_RULE_ID) {
    return {
      notify: true,
      severity: alert.severity === "critical" ? "critical" : "warning",
      title: "Descartes: peer count deviation",
      body: `Peer count ${diagnostics.observed_count} vs baseline mean ${diagnostics.mean_before} (z=${diagnostics.z_score}, ${diagnostics.confidence_state}).`,
    };
  }
  // Slice 4c (observed-incident collectors plan), additive fourth deterministic-delivery branch:
  // the sign-flipped mirror of peer.count_spike's own branch immediately above. Body shape is
  // identical -- counts/z-score/confidence_state only, peer-flavored wording -- never a raw peer
  // host/IP/pubkey, which never reaches this layer's inputs at all (peer-baseline.js's
  // diagnostics only ever carry counts/z-scores/confidence_state, no per-peer identity). Stored
  // severity is always "warning" here (peer-baseline.js's own Decision 0 cap), but this branch
  // reads `alert.severity` rather than hardcoding "warning" for the same "future cap-lift doesn't
  // need a second edit here" reason as the spike branch above.
  if (alert?.rule_id === PEER_COUNT_DROP_RULE_ID) {
    return {
      notify: true,
      severity: alert.severity === "critical" ? "critical" : "warning",
      title: "Descartes: peer count drop",
      body: `Peer count ${diagnostics.observed_count} vs baseline mean ${diagnostics.mean_before} (z=${diagnostics.z_score}, ${diagnostics.confidence_state}).`,
    };
  }
  // Service-disappearance ALERT (docs/plans/2026-07-23-service-disappearance-alert.md).
  // INTENTIONAL, SCOPED EXCEPTION to this file's general hash-only body discipline (operator
  // decision, 2026-07-24, recorded in the plan's "Operator decisions required before
  // implementation" section): the body names the disappeared service in cleartext, using the
  // SANITIZED (charset-bounded, `[A-Za-z0-9._:-]`-only, never raw/unsanitized) `diagnostics.
  // service_name` that service-baseline.js's buildDisappearedCandidates now produces --
  // superseding this branch's original hash-only body. Rationale: this is a LOCAL notification to
  // the machine's own operator, and knowing WHICH service vanished is the entire operational point
  // of the alert -- unlike session/peer identity below, where the specific session/peer is
  // irrelevant and hashing loses no signal. This exception is SCOPED to service.disappeared ONLY --
  // session.churn/session.count_drop/peer.count_spike/peer.count_drop above and below are
  // UNCHANGED and remain hash-only/counts-only; do not read this as a blanket relaxation of the
  // module-level invariants (see emitSessionAlertSignals'/this function's own header comments,
  // updated to describe this exception explicitly).
  if (alert?.rule_id === SERVICE_DISAPPEARED_RULE_ID) {
    // Defensive fallback: `diagnostics.service_name` is normally the sanitized cleartext name
    // (see the exception rationale above), but sanitizeIdentityString/sanitizeDiagnostics degrade
    // it to a redaction-marker object (never a string) when the source entity_key sanitizes to
    // nothing safe (empty, whitespace-only, or all-punctuation). Interpolating that marker object
    // directly into the body would stringify to the literal, unhelpful "[object Object]" — so fall
    // back to the always-present hash identifier instead, matching this module's degrade-not-
    // fabricate convention rather than surfacing an internal object shape to the operator.
    const displayServiceName = typeof diagnostics.service_name === "string" ? diagnostics.service_name : `unknown (${diagnostics.entity_key_hash})`;
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: service disappeared",
      body: `Service "${displayServiceName}" stopped appearing in the latest complete census (last seen ${diagnostics.last_seen_ts}).`,
    };
  }
  if (alert?.rule_id === CANARY_TRIPPED_RULE_ID) {
    const displayCanaryId = typeof diagnostics.canary_id === "string" ? diagnostics.canary_id : `unknown (${diagnostics.canary_id_hash})`;
    return {
      notify: true,
      severity: "critical",
      title: "Descartes: canary tripped",
      body: `Canary "${displayCanaryId}" (${diagnostics.canary_kind}) tripped: ${diagnostics.trip_reason}.`,
    };
  }
  if (alert?.rule_id === PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID) {
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: unexpected process lineage",
      body: `Novel process spawn edge ${diagnostics.entity_key_hash} appeared.`,
    };
  }
  // Persistence baseline, Slice B (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md):
  // scheduled_job.appeared. Hash-only body (O1 unsigned default) — mirrors
  // process-lineage's own hash-only branch immediately above, not service.disappeared's scoped
  // cleartext-name exception.
  if (alert?.rule_id === SCHEDULED_JOB_APPEARED_RULE_ID) {
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: new scheduled job",
      body: `A scheduled job not seen in this host's recent history just appeared (${diagnostics.entity_key_hash}).`,
    };
  }
  // Persistence baseline, Slice C: service.appeared, the appearance-direction twin of
  // service.disappeared above. Hash-only body (O1 unsigned default) — deliberately does NOT
  // extend service.disappeared's scoped 2026-07-24 cleartext-name exception to this new rule_id.
  if (alert?.rule_id === SERVICE_APPEARED_RULE_ID) {
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: new service",
      body: `A service unit not seen in this host's recent history just appeared (${diagnostics.entity_key_hash}).`,
    };
  }
  // Credential-file-access signal, Slice D: credential.access. Honest-claim wording (see
  // credential-access-baseline.js's own header) — `trip_reason` names "rewritten"/"replaced", NOT
  // "accessed": mtime/ino evidence proves a change, not a read.
  if (alert?.rule_id === CREDENTIAL_ACCESS_RULE_ID) {
    const tripWord = diagnostics.trip_reason === "ino_changed" ? "replaced" : diagnostics.trip_reason === "mtime_changed" ? "rewritten" : String(diagnostics.trip_reason ?? "changed");
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: credential file changed",
      body: `A tracked credential file (${diagnostics.category}) was ${tripWord} (path_hash=${diagnostics.path_hash}).`,
    };
  }
  // Tamper fix (canary v0 finalization): "tampering is suspicious in itself" -- a manifest that
  // could not be read, a canary that vanished while still listed in the manifest, or a broken
  // baseline store are each, on their own, evidence worth surfacing even though none of them is a
  // real atime/mtime/executed OBSERVATION the way canary.tripped's body above is. The per-reason
  // wording below intentionally names WHICH integrity check failed (matches this module's
  // service.disappeared precedent of naming the concrete failure, not a generic "something's
  // wrong") -- canary_vanished's `displayCanaryId` fallback mirrors canary.tripped's own
  // degrade-not-fabricate object-fallback above for the identical reason (sanitizeIdentityString
  // can degrade to a redaction-marker object, never a string).
  if (alert?.rule_id === CANARY_TAMPERED_RULE_ID) {
    const reason = diagnostics.tamper_reason;
    if (reason === "canary_vanished") {
      const displayCanaryId = typeof diagnostics.canary_id === "string" ? diagnostics.canary_id : `unknown (${diagnostics.canary_id_hash})`;
      return {
        notify: true,
        severity: "critical",
        title: "Descartes: canary tampering suspected",
        body: `Canary "${displayCanaryId}" (${diagnostics.canary_kind}) vanished while still listed in the manifest (last seen ${diagnostics.last_seen_ts}) — possible tampering.`,
      };
    }
    if (reason === "manifest_unreadable") {
      return {
        notify: true,
        severity: "critical",
        title: "Descartes: canary tampering suspected",
        body: "The canary manifest (canaries.json) could not be read or parsed — possible tampering. Established canaries keep alerting off fact history in the meantime.",
      };
    }
    if (reason === "baseline_store_error") {
      return {
        notify: true,
        severity: "critical",
        title: "Descartes: canary tampering suspected",
        body: "The canary baseline store could not be read or written — possible tampering. Canary trip detection is unaffected; only bookkeeping counters are degraded.",
      };
    }
    return {
      notify: true,
      severity: "critical",
      title: "Descartes: canary tampering suspected",
      body: `Canary integrity check failed: ${reason ?? "unknown"}.`,
    };
  }
  // Slice 7.2.c (recommend-only containment surface plan), must-fix branch: without this, adding
  // containment.recommend.* to ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS alone would route every
  // recommendation into the generic fall-through below, dropping the recommended verb, the
  // target, the rationale, and — critically — the RECOMMEND-ONLY label the whole surface's
  // honesty depends on. `diagnostics` here is the RECOMMENDATION candidate's own stored
  // diagnostics (verb/trigger_rule_id/trigger_alert_ref/target_repr — computeContainmentRecommend
  // ationCandidates in containment-recommend.js), not the triggering alert's diagnostics.
  // renderStoredRecommendationText re-derives the full rationale from the closed RECOMMEND_MAP
  // keyed on trigger_rule_id; a corrupt/foreign diagnostics shape degrades to a constant label-only
  // fallback rather than interpolating any diagnostic value into a notification.
  if (containmentRecommendationRuleIds().includes(alert?.rule_id)) {
    const body = renderStoredRecommendationText(diagnostics)
      ?? CONTAINMENT_RECOMMEND_LABEL;
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: containment recommendation",
      body,
    };
  }
  // Unreachable in normal operation (the caller already filters to
  // ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS) — fails closed to a generic, still counts/enum-only
  // body rather than throwing.
  return { notify: true, severity: "warning", title: "Descartes: session alert", body: `rule_id=${alert?.rule_id}` };
}

// Slice 6 (observed-incident collectors plan) Decision 3, must-fix 3/1, defense-in-depth: re-runs
// sanitizeDiagnostics() on stored diagnostics immediately before they reach the prompt, rather
// than trusting the candidate builder's own write-time sanitization alone. Module-wide (every
// namespace's compactAlert output is re-sanitized, not just "correlation"'s), since Slice 6 is the
// first slice whose candidate diagnostics are assembled from two independently-hashed upstream
// streams (Slice 3's peer facts, Slice 4's session-baseline alert).
//
// SCOPE (honest, per adversarial review): sanitizeDiagnostics is a CHARSET/shape/type gate -- it
// redacts unsafe-charset or over-length strings, non-finite numbers, and unsupported types, and
// restores idempotency for already-redacted markers. It is NOT a semantic hash/enum check: a
// charset-safe raw identifier (a dotted hostname like "host.example.com" or an IP "10.0.0.1")
// would PASS it. So this re-run is a shape backstop, NOT a hash-at-source enforcer -- the real
// confidentiality control is upstream, where the translators hash every entity_key/fingerprint at
// source. Every field a correlation candidate emits is a hash / number / closed-enum by
// construction (pinned by the schema-level negative test in test/incident-correlation.test.js).
//
// NOT a no-op for every existing namespace (corrected during Fable review, must-fix 1): the
// `metric` family's evaluateAlertRules (alert-store.js) never calls sanitizeDiagnostics at write
// time, so an `undefined`-valued diagnostics key (e.g. daemon.samples.missing's window_ms when
// historySummary is absent) now surfaces as a real redaction-marker key where JSON.stringify used
// to silently drop it. diagnostics-sanitizer.js's isWellFormedRedactionMarker passthrough (added
// in the same change) keeps this re-run a true fixed point for already-redacted values, and
// already-safe diagnostics (numbers, closed-enum strings, hex hashes, ISO timestamps) round-trip
// byte-identical -- see test/alert-intelligence.test.js's compactAlert idempotency fixtures.
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
    diagnostics: sanitizeDiagnostics(alert.diagnostics),
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

// Slice 6 (observed-incident collectors plan) Decision 2: a BESPOKE prompt template, not the
// generic buildLearnedNamespaceAlertPrompt factory. A correlation finding carries a different
// epistemic status than every other learned namespace's "this one signal looks anomalous" framing
// -- it is TWO independently-true facts placed near each other in time, not a single confirmed
// anomaly -- so the prompt must say so explicitly, or the model's freeform body/reason text could
// overclaim causation from what is actually only a timing coincidence with a bounded pool size.
// Same contract/shape as buildLearnedNamespaceAlertPrompt's output (same context keys, same
// bounded JSON response schema, same hard-rules block) plus three additional hard rules:
// causation, the novelty-count's real meaning, and the observed-hour-bucket-is-not-a-login-
// instant distinction (must-fix 6).
function buildCorrelationAlertPrompt({ alerts, historySummary, daemonStatus }) {
  return `You are Descartes alert intelligence. A deterministic local monitoring rule from the "correlation" learned-artifact family woke you up.

Decide whether the user should receive a notification now and write the exact bounded notification content.

Hard rules:
- Use only the alert records and summaries in this prompt.
- Do not claim facts not present here.
- Do not recommend or imply that any remediation action was taken.
- Prefer not notifying for stale/low-confidence/noisy alerts unless the user likely needs attention.
- This finding comes from a mined/learned artifact, not a hand-authored fixed rule; prefer a
  conservative severity and prefer not notifying when uncertain.
- This finding is a DETERMINISTIC TEMPORAL CORRELATION between two independently-observed
  signals (a session-count/churn deviation and a peer login), not proof of a causal
  relationship or a confirmed security incident. Do not state or imply the two events are
  causally connected. Describe them as temporally correlated and let the operator judge
  causation. candidate_pool_size in the context indicates how many peer logins matched
  this same window -- a larger pool means a weaker, more ambiguous hypothesis.
- peer_novelty_prior_tick_count means this peer was RARELY OBSERVED RECENTLY in the read
  window, NOT that any login attempt was investigated and failed to attribute to a known
  identity. Do not describe this peer as "unauthenticated," "unauthorized," or "failed
  attribution" -- describe it only as infrequently observed.
- peer_observed_hour_bucket is the hour of the OBSERVATION TICK that recorded this peer's
  presence, not necessarily the peer's actual login instant. Describe it as "observed at
  hour X", NEVER as "logged in at hour X." Treat the value "unknown" as no signal at all.
- Keep notification title <= 80 chars and body <= 240 chars.

Context:
${JSON.stringify({
  namespace: "correlation",
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

// S13 must-fix 6: template dispatch REGISTRY, keyed by namespace. Registry membership doubles as
// the reviewed-namespace allowlist for must-fix 1's eligibility rule -- a namespace with no entry
// here is excluded from LLM adjudication even if a future classification map or enabled_namespaces
// entry names it, so an un-reviewed namespace's data can never ship under another namespace's
// framing. "correlation" is added in the SAME commit as its classifyAlertNamespace branch and
// KNOWN_ALERT_NAMESPACES entry (Slice 6, per this same discipline).
const PROMPT_TEMPLATES = {
  metric: buildMetricAlertPrompt,
  constraint: buildLearnedNamespaceAlertPrompt("constraint"),
  provenance: buildLearnedNamespaceAlertPrompt("provenance"),
  baseline: buildLearnedNamespaceAlertPrompt("baseline"),
  identity: buildLearnedNamespaceAlertPrompt("identity"),
  correlation: buildCorrelationAlertPrompt,
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
  // Slice 7.2.a (recommend-only containment surface plan, must-fix): containment.* is hard-
  // excluded, checked SECOND (immediately after learned.), before every other branch -- the
  // recommended verb is chosen by deterministic code (containment-recommend.js's RECOMMEND_MAP),
  // never a model prompt. This is the stronger of the two available fencing mechanisms (vs. the
  // weaker unknown_namespace fallback session.*/peer.*/canary.* rely on): being checked first and
  // un-overridable by enabled_namespaces/PROMPT_TEMPLATES registration means a future edit that
  // adds a real containment. branch further down this chain cannot silently reopen the LLM path
  // to this surface. "containment" is deliberately NOT added to KNOWN_ALERT_NAMESPACES below
  // (belt-and-suspenders: even a mis-edited hard-exclude branch would still be blocked from
  // resolving "not_consented" -> eligible).
  if (id.startsWith("containment.")) return { namespace: "containment", hardExcluded: true };
  if (id.startsWith("daemon.") || id.startsWith("system.") || id.startsWith("disk.")) return { namespace: "metric", hardExcluded: false };
  if (id.startsWith("constraint.")) return { namespace: "constraint", hardExcluded: false };
  if (id.startsWith("provenance.")) return { namespace: "provenance", hardExcluded: false };
  if (id.startsWith("baseline.")) return { namespace: "baseline", hardExcluded: false };
  if (id.startsWith("identity.")) return { namespace: "identity", hardExcluded: false };
  // Slice 6 (observed-incident collectors plan) Decision 2: every existing branch's prefix is a
  // disjoint single token, so this cannot collide with or shadow any of them -- order within the
  // chain is a style choice here (placed after identity., before the fallback), not a correctness
  // requirement.
  if (id.startsWith("correlation.")) return { namespace: "correlation", hardExcluded: false };
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

// S13 I/O hardening -- IMPLEMENTED state (replaces the prior DEFERRED-follow-up comment that used
// to live here; see the tracking todo / plan addendum for the dated record of this pass).
//
// - readAlertIntelligenceConfig (above): a non-ENOENT read failure now fails CLOSED
//   (`unavailable: true`, enabled:false) instead of rethrowing -> `!config.enabled` below returns
//   "disabled", zero LLM calls.
// - The budget-seed audit read just below (readAuditRecords, seeding the trailing-hour counters)
//   is wrapped in its own try/catch: on ANY failure it returns a DISTINCT
//   `{ status: "audit_unavailable", decisions: [] }`, zero calls. It must NOT fall back to an
//   empty history -- an empty seed under-counts prior calls and would let THIS tick over-call,
//   breaking the total <= max_calls_per_hour invariant. readAuditRecords itself still rethrows
//   non-ENOENT (only this budget-critical call site swallows).
// - Per-alert appendAuditRecord failures (both the ok-path and error-path append, inside the loop
//   below) go through safeAppendAuditRecord (defined above appendAuditRecord), which never throws
//   -- it returns null on failure and console.warns. A null result is never pushed into `records`
//   (so it can't poison the "ok" vs "rate_limited"/"audit_write_degraded" status calculation at the
//   bottom). On a null result the loop BREAKS (no further LLM calls this tick) and sets the
//   in-process, audit-path-keyed `auditWriteDegradedPaths` latch (defined above appendAuditRecord).
//
//   THE LATCH IS THE LOAD-BEARING PIECE (Fable review correction of a naive break-only design): a
//   break alone still lets ~1 unrecorded LLM call happen on EVERY subsequent tick under a sustained
//   write fault where reads keep succeeding (the canonical case is ENOSPC, also EROFS) -- at a 60s
//   daemon cadence that is up to 60 over-budget calls per hour, the exact invariant this whole gate
//   exists to protect. The latch is checked at the TOP of the next invocation (after the
//   eligibility filter, before any budget-seed audit read or LLM call): if set, it attempts exactly
//   ONE probe append (`status: "audit_probe"`, deliberately no `alert_severity` so
//   partitionRecentAuditCounts -- which counts every in-window record regardless of status --
//   conservatively counts a successful probe as one non-critical call against the trailing-hour
//   budget, the same "unknown -> non-critical" conservatism historical pre-S13 records already
//   get). Probe success clears the latch and resumes normal adjudication THIS tick; probe failure
//   keeps this tick at zero calls. This bounds the residual leak to <=1 call per fail->heal cycle,
//   plus the pre-existing <=1-per-process-restart residual (a freshly-started process has no
//   in-memory latch state) -- NOT ~1-per-tick.
//
//   The latch is deliberately IN-PROCESS (a module-level Set), never persisted to disk: persisting
//   it would itself need the very writes that are failing.
//
// - The dynamic imports of pi-harness.js/notification-delivery.js (below the budget-seed read) are
//   also wrapped: a module-load failure (e.g. EIO on an uncached read) fails this tick closed
//   (`{ status: "dependencies_unavailable" }`, zero calls) instead of escaping adjudicate.
// - Defense-in-depth: the daemon.js call site additionally wraps the whole
//   adjudicateAlertNotifications call in try/catch (a call-site catch cannot itself break the
//   budget invariant -- by the time anything could reach that catch, any admitted call's audit
//   write has already succeeded or already been handled by the mechanisms above).
//
// NAMED FOLLOW-UP (still open, intentionally out of scope here): the zero-leak fix is a
// write-ahead/transactional audit (record "about to call" before calling, reconcile "outcome"
// after) so even the FIRST failed write after a fault is never unrecorded. The above bounds the
// residual to <=1 per heal-cycle/restart -- documented, not silently accepted.
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

  const { auditFile } = resolveAlertIntelligencePaths(descartesPaths);
  const doAppendAuditRecord = options.appendAuditRecord ?? appendAuditRecord;

  // S13 I/O hardening -- probe-heal: see the module comment above this function for the full
  // ENOSPC-leak rationale. If a PRIOR invocation's append failed for this exact audit path, do not
  // blindly resume calling the LLM -- writes may still be failing. Spend exactly one cheap probe
  // append to find out, before anything else.
  if (auditWriteDegradedPaths.has(auditFile)) {
    const probe = await safeAppendAuditRecord(doAppendAuditRecord, descartesPaths, { ts: now, status: "audit_probe" });
    if (probe) {
      auditWriteDegradedPaths.delete(auditFile);
    } else {
      console.warn(`descartes: alert intelligence audit writes are still failing at ${auditFile}; skipping adjudication this tick (zero LLM calls) until a write succeeds again`);
      return { status: "audit_write_degraded", decisions: [], excluded };
    }
  }

  // S13 must-fix 2: process CRITICAL due alerts before non-critical ones within a tick (partition
  // before any truncation/dropping).
  const orderedAlerts = [
    ...eligibleAlerts.filter((alert) => alert.severity === "critical"),
    ...eligibleAlerts.filter((alert) => alert.severity !== "critical"),
  ];

  let audit;
  try {
    // daybreak-blue #3 (HIGH): the budget seed uses the STRICT, budget-local read
    // (readBudgetAuditRecordsStrict, defined above) -- never the tolerant readAuditRecords used
    // elsewhere in this file. See that function's own doc comment for the full corrupt-line policy.
    audit = await readBudgetAuditRecordsStrict(descartesPaths, now);
  } catch (error) {
    console.warn(`descartes: alert intelligence audit read failed (${errorLabel(error)}); skipping adjudication this tick (budget cannot be computed)`);
    return { status: "audit_unavailable", decisions: [], excluded };
  }
  const historical = partitionRecentAuditCounts(audit, now);
  // RUNNING per-class counters, seeded from trailing-hour audit history and incremented as calls
  // are admitted within this loop -- this is what lets "so_far" include calls already made earlier
  // in THIS invocation, which a one-shot remaining/slice computation could not express.
  let runningCritical = historical.critical;
  let runningNonCritical = historical.nonCritical;

  const maxCallsPerHour = config.max_calls_per_hour;
  const criticalReservation = config.critical_reservation;
  const nonCriticalBudget = Math.max(0, maxCallsPerHour - criticalReservation);

  let createSession;
  let deliverNotification;
  try {
    // S13 I/O hardening (residual crash path 5a): these dynamic imports are unguarded awaits on
    // the production path (they only run when the DI fakes -- tests -- are absent). An EIO/EACCES
    // reading an uncached module file must fail this tick closed (zero calls), not escape
    // adjudicateAlertNotifications and crash the daemon tick.
    createSession = options.createSession ?? (await import("./pi-harness.js")).createPrivateAlertSession;
    deliverNotification = options.deliverNotification ?? (await import("./notification-delivery.js")).deliverNotificationDecision;
  } catch (error) {
    console.warn(`descartes: alert intelligence session/delivery module load failed (${errorLabel(error)}); skipping adjudication this tick (zero LLM calls)`);
    return { status: "dependencies_unavailable", decisions: [], excluded };
  }

  const records = [];
  let droppedTotal = 0;
  let droppedCritical = 0;
  let auditWriteFailed = false;

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
      let appended;
      // F5 fix: read directly off the (possibly un-normalized) config, not a normalized variable --
      // see resolveModelDeadlineMs's doc comment.
      const deadlineMs = resolveModelDeadlineMs(config.model_deadline_ms);
      try {
        // S13 must-fix 5: include_history_summary/include_daemon_status are wired here -- omitted
        // entirely (undefined, not just falsy) rather than unconditionally included as pre-S13.
        promptText = alertIntelligencePrompt({
          alerts: [alert],
          historySummary: config.include_history_summary ? evaluation.history_summary : undefined,
          daemonStatus: config.include_daemon_status ? evaluation.daemon_status : undefined,
        });

        // F5 fix, step 2 (lower risk than the prompt() bound below -- createPrivateSession does
        // local fs/registry work with no side effects on audit/notification state, so a
        // race-and-abandon is acceptable here, unlike session.prompt() below). Bound it so a hung
        // session-creation call cannot itself freeze the tick; attach cleanup so an eventually-
        // resolving abandoned session doesn't leak.
        const createSessionPromise = createSession(descartesPaths, {
          modelPattern: config.model_pattern,
          thinkingLevel: config.thinking_level,
        });
        let sessionCreateTimedOut = false;
        let sessionCreateTimer;
        const sessionCreateDeadline = new Promise((resolve) => {
          sessionCreateTimer = setTimeout(() => {
            sessionCreateTimedOut = true;
            resolve(undefined);
          }, deadlineMs);
        });
        let result;
        try {
          result = await Promise.race([createSessionPromise, sessionCreateDeadline]);
        } finally {
          clearTimeout(sessionCreateTimer);
        }
        if (sessionCreateTimedOut) {
          // Never await the abandoned promise here -- that would reintroduce the exact hang this
          // guards against. If/when it eventually settles on its own, dispose the session it
          // produced so a late-arriving session doesn't leak a live process/connection.
          createSessionPromise.then((raced) => {
            try {
              raced?.session?.dispose?.();
            } catch {
              // A throwing dispose() on an already-abandoned session has nothing left to do with
              // the error but drop it.
            }
          }).catch(() => {});
          throw new Error("model_session_deadline_exceeded");
        }
        session = result.session;

        // F5 fix, step 1 (THE critical fix): bound session.prompt() with a deadline AND real
        // cancellation on the SAME awaited promise -- deliberately NOT a race-and-abandon like
        // step 2 above. deliverNotification and safeAppendAuditRecord below have real side effects
        // (an OS notification; an append to the budget-critical llm-decisions.jsonl audit trail);
        // an abandoned continuation racing a LATER tick's own calls would risk duplicate/
        // out-of-order operator notifications and a genuine race on the append-only audit trail
        // S13 must-fix 2's budget accounting depends on being accurate and serial.
        //
        // F5-B re-gate (daybreak-blue CONFIRMED BLOCKER): the original fix bounded the AWAIT with
        // only a side timer flipping `timedOut` -- but `await session.prompt(promptText)` still
        // awaits prompt()'s OWN eventual settlement. If the event loop is starved (by prompt()
        // itself, e.g. a long synchronous stretch inside the provider client) past deadlineMs and
        // THEN resolves, the deadline timer's callback may not have run yet -- so the continuation
        // right after this await can observe `timedOut` still false and fall through to a
        // fabricated status:"ok" delivery (daybreak-blue repro: deadlineMs=5, elapsed~66ms ->
        // delivered). It also meant an abort() that is a no-op for the underlying request (fixspec
        // item 7) left this await never settling at all -- HIGH residual, an indefinite hang.
        // Fixed by racing prompt() against a deadline PROMISE (so the awaited expression itself
        // settles at the deadline even if prompt() never does) AND adding a wall-clock elapsed
        // check as a belt-and-braces close for the starved-then-resolves race (catches it even if
        // the timer callback hasn't run the instant this line executes).
        let timedOut = false;
        // MONOTONIC clock for the deadline belt (daybreak-blue F5 re-gate 2, BLOCKER 3): Date.now()
        // is wall-clock and can be frozen or stepped BACK (NTP, a VM pause, or the very clock-rollback
        // scenario Descartes' own fact-store guards against), which would let a starve-then-resolve
        // prompt() win the microtask race with elapsed reading <= deadline. performance.now() is
        // monotonic and immune to wall-clock manipulation.
        const promptStartedMs = performance.now();
        let deadlineTimer;
        const deadlinePromise = new Promise((resolve) => {
          deadlineTimer = setTimeout(() => {
            timedOut = true;
            // Must never throw synchronously or leave a rejected promise unhandled -- a
            // timer-callback exception is an uncaught exception that kills the daemon process,
            // exactly the class of crash S13 5b / 4d350f7 exist to prevent. Mirrors the
            // session?.dispose?.() guard idiom in the outer finally below.
            try {
              session?.abort?.()?.catch?.(() => {});
            } catch {
              // Swallow -- see comment above.
            }
            resolve();
          }, deadlineMs);
        });
        try {
          const promptPromise = session.prompt(promptText);
          // If the deadline wins the race below, `promptPromise` is left to settle on its own
          // (mirrors the createSessionPromise race-and-abandon above) -- attach a no-op catch so
          // an eventual real rejection from the LOSING side never becomes an unhandled promise
          // rejection later.
          promptPromise.catch(() => {});
          await Promise.race([promptPromise, deadlinePromise]);
        } finally {
          clearTimeout(deadlineTimer);
        }
        // MUST run before touching session.messages: abort() may make prompt() RESOLVE with
        // partial/streamed content rather than reject (fixspec item 7's no-op-abort case). Falling
        // through to lastAssistantText/parseDecisionJson on a timed-out call risks
        // normalizeAlertNotificationDecision's lenient defaults turning a truncated/partial
        // response into a spuriously "ok" audit record carrying a decision the model never
        // actually finished rendering -- a fabricated adjudication outcome (NEVER-FABRICATE).
        // Treat ANY timeout identically, regardless of how prompt() settled. The wall-clock check
        // (elapsed >= deadlineMs) closes the F5-B race even when `timedOut` itself hasn't been set
        // yet -- a starved-then-resolved prompt() can win Promise.race before the timer callback
        // runs, but real elapsed time already tells the truth.
        if (timedOut || performance.now() - promptStartedMs >= deadlineMs) throw new Error("model_deadline_exceeded");

        const rawText = lastAssistantText(session.messages);
        const decision = normalizeAlertNotificationDecision(parseDecisionJson(rawText));
        const delivery = decision.notify
          ? await deliverNotification(descartesPaths, decision, { now, alertId: alert.id, ruleId: alert.rule_id })
          : undefined;
        appended = await safeAppendAuditRecord(doAppendAuditRecord, descartesPaths, {
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
        });
      } catch (error) {
        appended = await safeAppendAuditRecord(doAppendAuditRecord, descartesPaths, {
          ts: now,
          alert_id: alert.id,
          rule_id: alert.rule_id,
          namespace,
          alert_severity: alert.severity,
          status: "error",
          prompt_hash: promptText ? hashPromptText(promptText) : undefined,
          prompt_template_version: promptText ? ALERT_INTELLIGENCE_PROMPT_TEMPLATE_VERSION : undefined,
          error: error instanceof Error ? error.message : String(error),
        });
      } finally {
        try {
          session?.dispose?.();
        } catch {
          // A throwing dispose() must not crash the tick -- the session is already finished with
          // either way, so there's nothing left to do with the error but drop it.
        }
      }

      if (appended) {
        records.push(appended);
        continue;
      }

      // S13 I/O hardening -- THE critical piece: the append for the call just made (whose LLM call
      // ALREADY happened) failed. Set the in-process latch (keyed by this audit file) and BREAK
      // rather than continue: a persistent-bound-of-<=1 or break-only design (without the latch)
      // would let ~1 unrecorded call happen on EVERY subsequent tick under a sustained fault --
      // breaking bounds THIS tick's leak to the single call already made; the latch (checked at the
      // top of the NEXT invocation, above) bounds every subsequent tick to zero calls until a probe
      // append proves writes have healed.
      auditWriteDegradedPaths.add(auditFile);
      auditWriteFailed = true;
      console.warn(`descartes: alert intelligence audit append failed for alert ${alert.id}; halting further LLM calls this tick and latching audit writes as degraded at ${auditFile}`);
      break;
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

  // A tick where an append failed must NOT report "ok" (S13 I/O hardening) -- it takes priority
  // over the pre-existing "rate_limited" classification (records.length===0 can be true either
  // because everything was dropped for budget reasons, or because the one admitted call's append
  // failed; those are distinct, actionable states).
  const status = auditWriteFailed
    ? "audit_write_degraded"
    : records.length === 0 && droppedTotal > 0 ? "rate_limited" : "ok";
  return { status, decisions: records, excluded, dropped_total: droppedTotal, dropped_critical: droppedCritical, budget_exhausted: budgetExhausted };
}
