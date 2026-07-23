// S15 (calibration report) — docs/plans/2026-07-14-compile-down-calibration.md §3/§4.
//
// A deterministic, read-only, NO-LLM per-artifact precision/recall PROXY over existing outcome
// signals (alerts.json, llm-decisions.jsonl, notification-delivery.jsonl,
// shadow-violations.jsonl). Read-only foundation for S14 (compile-down): this file never mutates
// constraints.json, signatures.json, authority/promotions.json, alert-intelligence.json, or any
// other live-evaluated state -- it only reads already-shipped reader functions and appends one
// counts-only summary record to artifact-audit.jsonl (never an active artifact).
//
// `computeCalibrationReport` itself is PURE (no I/O): callers pass already-loaded arrays. This is
// load-bearing for S14 (plan §8): the miner calls this function as a library, never a store.
//
// No LLM anywhere: this file never imports pi-harness.js, never calls createSession, and never
// imports alert-intelligence.js's adjudication path (adjudicateAlertNotifications /
// alertIntelligencePrompt / the PROMPT_TEMPLATES registry / any buildXAlertPrompt builder) --
// only its pure, zero-LLM `classifyAlertNamespace` classifier and its config reader
// (`readAlertIntelligenceConfig`, `DEFAULT_ENABLED_NAMESPACES`), both of which do nothing but
// classify a rule_id string / read a JSON config file. See the no-LLM source-regex test in
// test/calibration.test.js, mirroring promotion-store.js's own no-LLM-import test.
//
// Honesty requirements this file exists to enforce (see the plan's §0/§3 for the full rationale):
//   - recall_proxy is ALWAYS the literal `null`, with an attached reason string -- never a
//     fabricated number. There is no ground-truth incident signal anywhere in this codebase.
//   - never_escalated_count / llm_suppressed_rate are explicit JSON `null` (never 0/a number)
//     whenever llm_namespace_enabled !== true -- otherwise a --json consumer could misread
//     "namespace can't/doesn't reach the LLM" as "this artifact is never caught."
//   - precision_proxy is deduplicated (an alert can be BOTH fast-recovered AND llm-suppressed --
//     summing double-counts it) and clamped to [0,1].
//   - fired_count is honestly a LOWER BOUND: alerts.json is a live-status snapshot, not an
//     append-only event log (see the module comment on `computeCalibrationReport` below).

import { readAlertRecords } from "./alert-store.js";
import {
  DEFAULT_ENABLED_NAMESPACES,
  classifyAlertNamespace,
  readAlertIntelligenceAudit,
  readAlertIntelligenceConfig,
} from "./alert-intelligence.js";
import { appendArtifactAuditRecord } from "./artifact-audit-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { parseDurationMs } from "./history-store.js";
import { CORRELATION_RULE_ID } from "./incident-correlation.js";
import { readNotificationDeliveryAudit } from "./notification-delivery.js";
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
import { IDENTITY_DRIFT_RULE_ID, NEW_PUBLIC_BIND_RULE_ID, UNKNOWN_IDENTITY_RULE_ID } from "./provenance-store.js";
import { SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "./session-baseline.js";
import { readShadowRecords } from "./shadow-store.js";

export const SCHEMA_VERSION = 1;

// 2x alert-store.js's own DEFAULT_ALERT_COOLDOWN_MS (15min) -- plan §3.2.
export const DEFAULT_FAST_RECOVERY_THRESHOLD_MS = 30 * 60 * 1000;
export const DEFAULT_MIN_CHRONIC_FIRES = 5;
export const DEFAULT_CHRONIC_NOISE_THRESHOLD = 0.3;

// Plan §3.4: the one-line reason recall_proxy is always null, attached rather than a bare
// omission -- an explicit null+reason is unambiguous where a bare `undefined`/omitted field is
// not (a caller could assume undefined -> 0, or undefined -> not applicable).
export const RECALL_PROXY_REASON = "no ground-truth incident signal available";

const CONSTRAINT_VIOLATION_PREFIX = "constraint.violation.";

// Plan §2.2: the CLOSED set of rule_id families this plan calibrates/compiles down. Never the
// fixed, hand-authored zero-learning reflexes (daemon.*/system.*/disk.*) or the fixed
// provenance-warnings.js rules (provenance.process.deleted_exe_running /
// provenance.socket.public_bind_no_supervisor) -- those are excluded by construction below.
const CLOSED_RULE_IDS = new Set([
  UNKNOWN_IDENTITY_RULE_ID,
  IDENTITY_DRIFT_RULE_ID,
  NEW_PUBLIC_BIND_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  SESSION_CHURN_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID, // Slice 4c (observed-incident collectors plan)
  CORRELATION_RULE_ID,
]);

function isCalibratedRuleId(ruleId) {
  const id = String(ruleId ?? "");
  if (id.startsWith(CONSTRAINT_VIOLATION_PREFIX)) return true;
  return CLOSED_RULE_IDS.has(id);
}

// Degrade-not-fabricate: returns undefined (never a raw/partial value) for anything that isn't
// already a safe-charset string -- mirrors sanitizeIdentityString's own documented contract.
// Applied to every value this module ever turns into an `artifact_ref`/`rule_id_family`, as
// defense-in-depth on top of "these are already-hashed/bounded values by construction upstream"
// (plan §1 point 6) -- a row whose ref cannot be made safe is dropped, never reported unsafely.
function safeRefString(value) {
  if (typeof value !== "string" || value.length === 0) return undefined;
  return sanitizeIdentityString(value);
}

/**
 * Plan §2.1 attribution chain, WITH the 2026-07-14 review's identity_drift fix: identity_drift
 * diagnostics carry `old_identity_hash`/`new_identity_hash`, never a bare `identity_hash` -- so
 * this checks `new_identity_hash` as an explicit third branch (not merely falling through to
 * rule_id) and attributes identity_drift at granularity:"artifact", the live signatures.json key
 * going forward for that identity.
 *
 *   artifact_ref(alert) =
 *       diagnostics.constraint_id       -- constraint.violation.<family>
 *    ?? diagnostics.identity_hash       -- unknown_identity / new_public_bind
 *    ?? diagnostics.new_identity_hash   -- identity_drift
 *    ?? rule_id                         -- session/peer/correlation rule_ids (no persisted artifact)
 */
function attributeAlert(alert) {
  const diagnostics = alert?.diagnostics && typeof alert.diagnostics === "object" && !Array.isArray(alert.diagnostics) ? alert.diagnostics : {};
  const constraintId = safeRefString(diagnostics.constraint_id);
  if (constraintId !== undefined) return { rawRef: constraintId, granularity: "artifact" };
  const identityHash = safeRefString(diagnostics.identity_hash);
  if (identityHash !== undefined) return { rawRef: identityHash, granularity: "artifact" };
  const newIdentityHash = safeRefString(diagnostics.new_identity_hash);
  if (newIdentityHash !== undefined) return { rawRef: newIdentityHash, granularity: "artifact" };
  return { rawRef: undefined, granularity: "family" };
}

/**
 * Pure precision-proxy computation (plan §3.2, fixed 2026-07-14 review): the numerator is the
 * DEDUPLICATED count of alerts that are fast-recovered OR llm-suppressed (an alert can be both --
 * summing the two counts can double-count and drive the proxy negative). Exported standalone so
 * the fired_count===0 div-by-zero guard and the dedupe fixture are each directly unit-testable
 * without constructing a full alerts.json fixture.
 */
export function computePrecisionProxy(dedupedFastOrSuppressedCount, firedCount) {
  if (!Number.isFinite(firedCount) || firedCount <= 0) return null;
  const raw = 1 - dedupedFastOrSuppressedCount / firedCount;
  // Clamp is redundant given a proper subset-sized numerator, but proven-not-assumed (plan §3.2
  // must-fix 2): a future change to how the numerator is computed must not be able to silently
  // reopen the negative-proxy bug.
  return Math.min(1, Math.max(0, raw));
}

function isFastRecovered(alert, fastRecoveryThresholdMs) {
  if (alert.status !== "recovered") return false;
  const firstSeenMs = new Date(alert.first_seen).getTime();
  const lastSeenMs = new Date(alert.last_seen).getTime();
  if (!Number.isFinite(firstSeenMs) || !Number.isFinite(lastSeenMs)) return false;
  return lastSeenMs - firstSeenMs <= fastRecoveryThresholdMs;
}

function computeLlmNamespaceEnabled(ruleId, enabledNamespaces) {
  const { namespace, hardExcluded } = classifyAlertNamespace(ruleId);
  // Structurally un-consentable (session.*/peer.* -> namespace undefined) or hard-excluded
  // (learned.* self-audit findings, not reachable from the closed set above but checked for
  // defense-in-depth): null, never true/false -- no `enable-namespace` switch can ever change this.
  if (!namespace || hardExcluded) return null;
  return enabledNamespaces.includes(namespace);
}

/**
 * Pure, deterministic, no I/O. Callers pass already-loaded arrays (readAlertRecords,
 * readAlertIntelligenceAudit, readNotificationDeliveryAudit, readShadowRecords's `.records`).
 * Every array argument is defensively coerced to `[]` when missing/non-array, so a caller that
 * degrades a corrupt/missing signal file to an empty array (rather than throwing) composes
 * cleanly -- day-1 (all four empty) returns `{ artifacts: [] }`.
 *
 * `deliveryRecords` is accepted for signature parity with the plan's documented signature and as
 * a future cross-check seam (plan §2: "Supplementary... not a primary proxy") -- no
 * CalibrationRow field in this slice derives from it; every formula below is fully specified by
 * `alerts` + `auditRecords` + `shadowRecords` alone (plan §3.2).
 *
 * fired_count is honestly a LOWER BOUND, not an exact re-fire count: alerts.json
 * (alert-store.js's normalizeAlertRecord) is a live-status SNAPSHOT, not an append-only event
 * log -- a candidate that stays "active" across many daemon ticks without recovering is one
 * incident record, and a flap that recovers then re-fires with the SAME fingerprint reuses the
 * same record (applyAlertCandidates) rather than creating a new one. See the plan §3.2 for the
 * full bias-direction discussion (undercounting biases chronically_firing/retire toward
 * non-action, the fail-safe direction, but can misroute a flapping artifact into a "retune" band
 * instead of "retire" -- named there, not silently absorbed here).
 */
export function computeCalibrationReport(alerts, auditRecords, deliveryRecords, shadowRecords, options = {}) {
  const fastRecoveryThresholdMs = options.fastRecoveryThresholdMs ?? DEFAULT_FAST_RECOVERY_THRESHOLD_MS;
  const minChronicFires = options.minChronicFires ?? DEFAULT_MIN_CHRONIC_FIRES;
  const chronicNoiseThreshold = options.chronicNoiseThreshold ?? DEFAULT_CHRONIC_NOISE_THRESHOLD;
  const enabledNamespaces = Array.isArray(options.enabledNamespaces) ? options.enabledNamespaces : [...DEFAULT_ENABLED_NAMESPACES];
  const generatedAt = options.now ?? new Date().toISOString();
  const sinceMs = options.since !== undefined && options.since !== null ? new Date(options.since).getTime() : undefined;
  const untilMs = options.until !== undefined && options.until !== null ? new Date(options.until).getTime() : undefined;
  const familyPrefix = options.family ? String(options.family) : undefined;

  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const safeAudit = Array.isArray(auditRecords) ? auditRecords : [];
  const safeShadow = Array.isArray(shadowRecords) ? shadowRecords : [];
  // Accepted, deliberately unused in v1's row formulas -- see the doc comment above.
  void (Array.isArray(deliveryRecords) ? deliveryRecords : []);

  // --- Window + closed-set filter, then group by artifact_ref (plan §2.1/§2.2) ---
  const rowsByRef = new Map();
  for (const alert of safeAlerts) {
    if (!alert || typeof alert !== "object") continue;
    const ruleId = String(alert.rule_id ?? "");
    if (!isCalibratedRuleId(ruleId)) continue;
    const safeRuleId = safeRefString(ruleId);
    if (safeRuleId === undefined) continue; // degrade: unresolvable ref, never fabricate one

    const firstSeenMs = new Date(alert.first_seen).getTime();
    if (Number.isFinite(firstSeenMs)) {
      if (sinceMs !== undefined && firstSeenMs < sinceMs) continue;
      if (untilMs !== undefined && firstSeenMs > untilMs) continue;
    }
    if (familyPrefix && !ruleId.startsWith(familyPrefix)) continue;

    const { rawRef, granularity } = attributeAlert(alert);
    const artifactRef = granularity === "artifact" ? rawRef : safeRuleId;
    if (artifactRef === undefined) continue; // degrade: unresolvable ref, never fabricate one

    if (!rowsByRef.has(artifactRef)) {
      rowsByRef.set(artifactRef, { artifact_ref: artifactRef, granularity, rule_id_family: safeRuleId, alerts: [] });
    }
    rowsByRef.get(artifactRef).alerts.push(alert);
  }

  // --- Index audit/shadow records once, reused per row ---
  const auditByAlertId = new Map();
  for (const record of safeAudit) {
    if (!record || typeof record !== "object" || !record.alert_id) continue;
    const list = auditByAlertId.get(record.alert_id) ?? [];
    list.push(record);
    auditByAlertId.set(record.alert_id, list);
  }
  const shadowByConstraintId = new Map();
  for (const record of safeShadow) {
    if (!record || typeof record !== "object" || !record.constraint_id) continue;
    const list = shadowByConstraintId.get(record.constraint_id) ?? [];
    list.push(record);
    shadowByConstraintId.set(record.constraint_id, list);
  }

  const artifacts = [];
  for (const row of rowsByRef.values()) {
    const firedCount = row.alerts.length;
    const llmNamespaceEnabled = computeLlmNamespaceEnabled(row.rule_id_family, enabledNamespaces);

    let autoRecoveredFastCount = 0;
    let llmAdjudicatedCount = 0;
    let llmSuppressedCount = 0;
    let neverEscalatedCountRaw = 0;
    const fastOrSuppressedIds = new Set();

    for (const alert of row.alerts) {
      if (isFastRecovered(alert, fastRecoveryThresholdMs)) {
        autoRecoveredFastCount += 1;
        fastOrSuppressedIds.add(alert.id);
      }

      const recordsForAlert = auditByAlertId.get(alert.id) ?? [];
      // llm_adjudicated_count/llm_suppressed_count (plan §3.2): only status:"ok" records with a
      // decision object count as "adjudicated" -- an "error"/"audit_probe"/etc. record never had
      // a real decision.
      const okRecords = recordsForAlert.filter((r) => r && typeof r === "object" && r.status === "ok" && r.decision && typeof r.decision === "object");
      if (okRecords.length > 0) {
        llmAdjudicatedCount += 1;
        const latestOk = okRecords.reduce((latest, r) => (!latest || new Date(r.ts).getTime() >= new Date(latest.ts).getTime() ? r : latest), undefined);
        if (latestOk?.decision?.notify === false) {
          llmSuppressedCount += 1;
          fastOrSuppressedIds.add(alert.id);
        }
      }

      // never_escalated_count (plan §3.2): "no llm-decisions.jsonl record for a.id has
      // decision.notify === true" -- checked across ALL records for this alert id (not only
      // status:"ok" ones, though only "ok" records ever carry a decision at all in practice).
      const everNotified = recordsForAlert.some((r) => r?.decision?.notify === true);
      if (alert.status !== "recovered" && !everNotified) neverEscalatedCountRaw += 1;
    }

    const precisionProxy = computePrecisionProxy(fastOrSuppressedIds.size, firedCount);

    // Must-fix 9 (plan §3.2/§4.4): explicit JSON null -- never a computed number, never 0 --
    // whenever llm_namespace_enabled !== true. A downstream --json consumer must never be able to
    // read "100% never-escalated"/"0% suppressed" as a quality signal for a namespace that
    // cannot, or currently does not, reach the LLM at all.
    const neverEscalatedCount = llmNamespaceEnabled === true ? neverEscalatedCountRaw : null;
    const llmSuppressedRate = llmNamespaceEnabled === true && llmAdjudicatedCount > 0 ? llmSuppressedCount / llmAdjudicatedCount : null;

    const shadowRecordsForRef = shadowByConstraintId.get(row.artifact_ref) ?? [];
    const shadowFireRate = shadowRecordsForRef.length > 0 ? shadowRecordsForRef.filter((r) => r.fired === true).length / shadowRecordsForRef.length : null;

    const chronicallyFiring = firedCount >= minChronicFires && precisionProxy !== null && precisionProxy < chronicNoiseThreshold;

    artifacts.push({
      artifact_ref: row.artifact_ref,
      granularity: row.granularity,
      rule_id_family: row.rule_id_family,
      fired_count: firedCount,
      // Honesty sibling, mirroring recall_proxy_reason (adversarial-review finding): fired_count is
      // a LOWER BOUND -- alerts.json is a snapshot, not an event log, so a chronically-flapping
      // same-fingerprint artifact is undercounted. This flag travels into --json so an unsupervised
      // consumer (notably S14's chronically_firing -> retire decision) can't read the bare integer
      // as exact. The undercount is fail-safe (biases toward non-action), but the caveat must be
      // machine-visible on the report surface, not source-comment-only.
      fired_count_is_lower_bound: true,
      auto_recovered_fast_count: autoRecoveredFastCount,
      never_escalated_count: neverEscalatedCount,
      llm_adjudicated_count: llmAdjudicatedCount,
      llm_suppressed_count: llmSuppressedCount,
      llm_namespace_enabled: llmNamespaceEnabled,
      llm_suppressed_rate: llmSuppressedRate,
      precision_proxy: precisionProxy,
      // Plan §3.4: ALWAYS null. No ground-truth incident signal exists anywhere in this
      // codebase -- fabricating one from the precision-side proxies above would silently
      // launder a precision-shaped number into a recall-shaped claim.
      recall_proxy: null,
      recall_proxy_reason: RECALL_PROXY_REASON,
      shadow_fire_rate: shadowFireRate,
      chronically_firing: chronicallyFiring,
      schema_version: SCHEMA_VERSION,
    });
  }

  artifacts.sort((left, right) => left.rule_id_family.localeCompare(right.rule_id_family) || left.artifact_ref.localeCompare(right.artifact_ref));

  return {
    generated_at: generatedAt,
    window: { since: options.since ?? null, until: options.until ?? null },
    artifacts,
  };
}

// --- CLI: descartes learned calibration [--json] [--since <duration>] [--family <prefix>] ---

function calibrationUsage() {
  return `Usage:
  descartes learned calibration [--json] [--since <duration>] [--family <rule_id-prefix>]

Deterministic, read-only, NO-LLM per-artifact precision proxy over existing outcome signals
(alerts.json, llm-decisions.jsonl, notification-delivery.jsonl, shadow-violations.jsonl).
Recall is always reported as null -- no ground-truth incident signal exists to compute it from.
Gated behind configDir/learned.json's enable switch, same as every other automatic/background
learned-artifact command; disabled prints { status: "disabled" } and reads none of the signal
files.`;
}

function parseCalibrationArgs(args) {
  const options = { json: false, sinceDuration: undefined, family: undefined };
  const rest = args ?? [];
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--since") {
      const value = rest[index + 1];
      if (!value) throw new Error(`--since requires a value\n\n${calibrationUsage()}`);
      options.sinceDuration = value;
      index += 1;
    } else if (arg === "--family") {
      const value = rest[index + 1];
      if (!value) throw new Error(`--family requires a value\n\n${calibrationUsage()}`);
      options.family = value;
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`Unexpected learned calibration argument: ${arg}\n\n${calibrationUsage()}`);
    }
  }
  return options;
}

function formatRatioOrNull(value) {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(0)}%`;
}

function namespaceAnnotation(row) {
  if (row.llm_namespace_enabled === true) return undefined;
  if (row.llm_namespace_enabled === null) {
    return `never_escalated: n/a -- ${row.rule_id_family} is structurally un-consentable (no enable-namespace switch can ever reach the LLM for it)`;
  }
  return `never_escalated: n/a -- ${row.rule_id_family}'s namespace is not LLM-enabled (run 'descartes alerts intelligence enable-namespace <namespace>' to opt in)`;
}

function renderRow(row) {
  const lines = [`  ${row.artifact_ref}  [${row.rule_id_family}]`];
  lines.push(
    `    fired: ${row.fired_count} (lower bound)  auto_recovered_fast: ${row.auto_recovered_fast_count}  precision_proxy: ${row.precision_proxy === null ? "n/a" : row.precision_proxy.toFixed(2)}${row.chronically_firing ? "  ** chronically firing **" : ""}`,
  );
  lines.push(`    recall_proxy: n/a (${row.recall_proxy_reason})`);
  const annotation = namespaceAnnotation(row);
  if (annotation) {
    lines.push(`    ${annotation}`);
  } else {
    lines.push(`    never_escalated: ${row.never_escalated_count}  llm_suppressed_rate: ${formatRatioOrNull(row.llm_suppressed_rate)}`);
  }
  if (row.shadow_fire_rate !== null) lines.push(`    shadow_fire_rate: ${formatRatioOrNull(row.shadow_fire_rate)}`);
  return lines.join("\n");
}

function renderCalibrationReport(report) {
  if (!report.artifacts || report.artifacts.length === 0) {
    return "No calibrated learned-derived artifacts fired in the current window.";
  }
  // Plan §4.2: rows grouped by granularity so family-level rows (no discrete artifact) are never
  // visually conflated with per-instance artifact rows.
  const artifactRows = report.artifacts.filter((row) => row.granularity === "artifact");
  const familyRows = report.artifacts.filter((row) => row.granularity === "family");
  const lines = [`Calibration report -- generated ${report.generated_at}`, ""];
  if (artifactRows.length > 0) {
    lines.push("Per-artifact:");
    for (const row of artifactRows) lines.push(renderRow(row));
    lines.push("");
  }
  if (familyRows.length > 0) {
    lines.push("Per-family (no discrete stored artifact -- session.*/peer.*/correlation.*):");
    for (const row of familyRows) lines.push(renderRow(row));
  }
  return lines.join("\n");
}

async function safeReadSignal(readFn, label) {
  try {
    return await readFn();
  } catch (error) {
    // Tolerant of missing/corrupt signal files (plan/task requirement): a non-ENOENT failure
    // (corrupt JSON, EACCES, ...) degrades this ONE signal to empty rather than crashing the
    // whole report. The underlying reader functions already tolerate ENOENT/per-line corruption
    // themselves; this is the outer safety net for whatever they don't (e.g. a malformed
    // top-level alerts.json, which alert-store.js's readAlertRecords does not itself tolerate).
    console.warn(`descartes: calibration report could not read ${label} (${error?.code ?? (error instanceof Error ? error.message : String(error))}); treating it as empty for this report`);
    return undefined;
  }
}

/**
 * CLI handler: loads configDir/learned.json, short-circuits to { status: "disabled" } (no reads
 * of any signal file) when off, otherwise reads the four signal files + the current
 * alert-intelligence.json namespace consent state, computes the report, renders it, and appends
 * exactly one counts-only summary record to artifact-audit.jsonl.
 */
export async function runLearnedCalibration(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const options = parseCalibrationArgs(args);
  if (options.help) {
    output(calibrationUsage());
    return undefined;
  }

  const loadLearned = runtime.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadLearned(descartesPaths);
  if (!learnedConfig.enabled) {
    const disabled = { status: "disabled" };
    if (options.json) output(JSON.stringify(disabled, null, 2));
    else output("Learned emission is disabled (configDir/learned.json). Run `descartes learned enable` first.");
    return disabled;
  }

  const now = runtime.now ?? new Date().toISOString();
  const nowMs = new Date(now).getTime();
  const since = options.sinceDuration ? new Date(nowMs - parseDurationMs(options.sinceDuration)).toISOString() : undefined;

  const readAlerts = runtime.readAlertRecords ?? readAlertRecords;
  const readAudit = runtime.readAlertIntelligenceAudit ?? readAlertIntelligenceAudit;
  const readDelivery = runtime.readNotificationDeliveryAudit ?? readNotificationDeliveryAudit;
  const readShadow = runtime.readShadowRecords ?? readShadowRecords;
  const readIntelligenceConfig = runtime.readAlertIntelligenceConfig ?? readAlertIntelligenceConfig;

  const [alerts, auditRecords, deliveryRecords, shadowResult, intelligenceConfig] = await Promise.all([
    safeReadSignal(() => readAlerts(descartesPaths), "alerts.json"),
    safeReadSignal(() => readAudit(descartesPaths), "llm-decisions.jsonl"),
    safeReadSignal(() => readDelivery(descartesPaths), "notification-delivery.jsonl"),
    safeReadSignal(() => readShadow(descartesPaths), "shadow-violations.jsonl"),
    safeReadSignal(() => readIntelligenceConfig(descartesPaths), "alert-intelligence.json"),
  ]);

  const report = computeCalibrationReport(alerts, auditRecords, deliveryRecords, shadowResult?.records, {
    now,
    since,
    family: options.family,
    enabledNamespaces: intelligenceConfig?.enabled_namespaces,
  });

  const familyCounts = {};
  for (const row of report.artifacts) {
    familyCounts[row.rule_id_family] = (familyCounts[row.rule_id_family] ?? 0) + 1;
  }
  const appendAudit = runtime.appendArtifactAuditRecord ?? appendArtifactAuditRecord;
  await appendAudit(descartesPaths, {
    ts: now,
    kind: "calibration_report",
    window: report.window,
    artifact_count: report.artifacts.length,
    family_counts: familyCounts,
  });

  if (options.json) output(JSON.stringify(report, null, 2));
  else output(renderCalibrationReport(report));
  return report;
}
