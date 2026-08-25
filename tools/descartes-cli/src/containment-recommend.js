// Slice 7.2 (recommend-only containment surface plan, docs/plans/
// 2026-08-21-slice-7.2-recommend-only-containment-surface.md) -- §0's "structurally incapable of
// acting" guarantee lives HERE, in this module's total absence of an execution primitive: no
// child_process/execFile import, no capability token, no authority store
// (authority/containment.json is §(e) Slice 7.3, not built here), no mutating syscall. This file
// only:
//   (a) maps an already-persisted, already-classified deterministic anomaly alert record to a
//       fixed, closed-enum recommendation (verb + rationale + hash-only target) -- Slice 7.2.a;
//   (b) owns a dedicated, default-OFF opt-in config, independent of both learned.json
//       (monitoring) and the future containment authority kill-switch (§(e) Slice 7.3+) -- Slice
//       7.2.b;
//   (c) computes recommendation CANDIDATE alert records for the daemon's extraCandidates array,
//       exactly the same shape/gating discipline every sibling detector in this codebase
//       (session-baseline.js/peer-baseline.js/canary-baseline.js/process-lineage-baseline.js)
//       already uses -- Slice 7.2.c.
// Delivery itself reuses the pre-existing local-notification sink
// (notification-delivery.js, invoked via alert-intelligence.js's emitSessionAlertSignals) --
// this module never calls deliverNotificationDecision or any execFile-family function itself,
// and never will: see the boundary tests in
// test/containment-recommend.boundary.test.js.
//
// Every recommendation is drawn from an OPERATOR-REVIEWABLE, hand-authored, fixed
// rule_id -> verb map (RECOMMEND_MAP below) -- never a model prompt, never free text (§(c) of the
// parent design: "the recommended verb is chosen by deterministic code, never a model prompt").
import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics } from "./diagnostics-sanitizer.js";
import { CANARY_TAMPERED_RULE_ID, CANARY_TRIPPED_RULE_ID } from "./canary-baseline.js";
import { PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
import { PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "./process-lineage-baseline.js";

// ---------------------------------------------------------------------------------------------
// Slice 7.2.a -- pure recommendation mapping. No I/O.
// ---------------------------------------------------------------------------------------------

// Plan §Slice 7.2.a: the unmissable, permanent label every rendered recommendation carries.
// Placed FIRST by renderRecommendationText below (not appended) so a long rationale being
// clamped to a notification payload's 240-char body limit downstream
// (notification-delivery.js's normalizeNotificationPayload) can never truncate the label away --
// only the rationale tail is ever at risk of truncation.
export const CONTAINMENT_RECOMMEND_LABEL = "RECOMMEND-ONLY — Descartes will NOT act on this; act manually if you choose.";

// Closed enum (plan §Slice 7.2.a): the full five-verb set from the parent design's containment
// vocabulary (docs/plans/2026-07-23-slice-7-authority-containment-plane.md). Recommend-only, so
// all five are safe to NAME here -- nothing in this module (or reachable from it) can ever
// execute one. Frozen so no runtime mutation can widen it.
//
// Open Decision 2 (operator review pending, plan §7): v0's RECOMMEND_MAP below deliberately
// emits only the reversible/observational subset ("default the map to reversible/observational
// verbs; include kill only on operator confirmation"). kill/revoke are members of this enum (the
// boundary tests in 7.2.d and the namespace hard-exclude fence every POSSIBLE
// containment.recommend.<verb> rule_id, including ones v0 never emits) but neither is ever
// produced by mapAlertToRecommendation below -- containmentRecommendationRuleIds() only
// registers the verbs RECOMMEND_MAP actually emits, never a dead/unreachable allowlist entry
// (plan §7 Open Decision 2's reconciliation note).
export const KNOWN_CONTAINMENT_VERBS = Object.freeze(["throttle", "block", "revoke", "quarantine", "kill"]);

// The intrusion detectors emit 16-character, lowercase SHA-256 prefixes. Keep this validator
// exact: a broad identifier regex would accept hostnames, IPs, usernames, and paths as if they
// were hashes.
const TARGET_HASH_PATTERN = /^[0-9a-f]{16}$/;

function isTargetHash(value) {
  return typeof value === "string" && TARGET_HASH_PATTERN.test(value);
}

function hashReference(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

// No entity-level identity exists for a peer-count spike (peer-baseline.js's
// buildCountSpikeCandidate always stores fingerprint:"global"; its diagnostics carry only
// counts/z-scores, never a per-peer key) -- the recommendation's target is the whole
// currently-observed peer population, not one peer. A fixed, non-hashed, closed-enum literal
// (mirrors PEER_CENSUS_MARKER_ENTITY_KEY/SESSION_OVERFLOW_ENTITY_KEY's own "no identity to hash"
// convention elsewhere in this codebase).
const GLOBAL_TARGET_REPR = "global";

// Slice 7.2.a, P3/P6: extracts the target this recommendation names, reusing ONLY the
// already-hash-at-source representation the triggering alert's OWN diagnostics already carry --
// never re-deriving or re-resolving a raw identifier (§(a)'s hash-vs-raw tension, Open Decision 1
// v0 default: "no new re-resolution at all"). Returns undefined when nothing safe is available
// for a rule_id that WOULD otherwise need a specific target -- degrade, never fabricate.
function extractTargetRepr(alert) {
  const ruleId = alert?.rule_id;
  const diagnostics = alert?.diagnostics && typeof alert.diagnostics === "object" && !Array.isArray(alert.diagnostics) ? alert.diagnostics : {};
  if (ruleId === PEER_COUNT_SPIKE_RULE_ID) return GLOBAL_TARGET_REPR;
  if (ruleId === CANARY_TRIPPED_RULE_ID) {
    return isTargetHash(diagnostics.canary_id_hash) ? diagnostics.canary_id_hash : undefined;
  }
  if (ruleId === CANARY_TAMPERED_RULE_ID) {
    if (diagnostics.tamper_reason === "canary_vanished") {
      return isTargetHash(diagnostics.canary_id_hash) ? diagnostics.canary_id_hash : undefined;
    }
    if (diagnostics.tamper_reason === "manifest_unreadable" || diagnostics.tamper_reason === "baseline_store_error") {
      return GLOBAL_TARGET_REPR;
    }
    return undefined;
  }
  if (ruleId === PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID) {
    return isTargetHash(diagnostics.entity_key_hash) ? diagnostics.entity_key_hash : undefined;
  }
  return undefined;
}

// Signal -> verb map (plan §Slice 7.2.a, Open Decision 3), keyed on the EXACT imported rule_id
// constants from the plan's P3 -- never a glob/prefix, matching how
// ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS is composed in alert-intelligence.js.
//
// GATE/NO-GATE DECISION (workflow implementation note, since this is Open Decision 3 -- "the
// operator should review the proposed default map" -- and no live operator sign-off was
// available while implementing this slice): SESSION_COUNT_DROP_RULE_ID and
// SESSION_CHURN_RULE_ID are DELIBERATELY ABSENT from this map (no-gate), even though the plan's
// own Open Decision 3 text names them ("SESSION_COUNT_DROP_RULE_ID/SESSION_CHURN_RULE_ID ->
// investigate"). "investigate" is not a member of KNOWN_CONTAINMENT_VERBS above, and both
// triggers are "global"-fingerprint, no-single-entity anomalies (a mass session drop or a
// creation-fingerprint churn names no process/peer/canary a throttle/block/quarantine/kill verb
// could sensibly attach to) -- forcing one of the five containment verbs onto them would
// fabricate a specific action the trigger's own diagnostics do not support, which is exactly the
// "misdirected operator trust" harm vector plan §1 identifies as this surface's central risk.
// Both triggers already get their own real, deterministic local notification today (the SHIPPED
// session.* branch in alert-intelligence.js's buildSessionAlertNotificationDecision) -- this
// no-gate decision only withholds a containment VERB recommendation on top of that, it does not
// silence the underlying anomaly. This is a conservative default the operator should ratify or
// override, not a claim these two triggers are unimportant. See the workflow report for the full
// per-signal rationale.
const RECOMMEND_MAP = new Map([
  [CANARY_TRIPPED_RULE_ID, {
    verb: "quarantine",
    rationale: "A decoy credential/persistence artifact was accessed or modified. Investigate first; consider quarantining the responsible process or session if confirmed malicious.",
  }],
  [CANARY_TAMPERED_RULE_ID, {
    verb: "quarantine",
    rationale: "Canary integrity could not be verified (possible tampering). Investigate first; consider quarantining the responsible actor if confirmed.",
  }],
  [PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, {
    verb: "throttle",
    rationale: "A process spawn relationship not seen in this host's recent history just appeared. Investigate first; consider throttling the newly spawned process if it looks unexpected.",
  }],
  [PEER_COUNT_SPIKE_RULE_ID, {
    verb: "block",
    rationale: "Peer count deviated significantly above its established baseline. Investigate first; consider blocking new peer connections if this looks unauthorized.",
  }],
]);

/**
 * Maps a triggering deterministic anomaly alert record to at most one recommendation object
 * `{ verb, rule_id, trigger_rule_id, rationale, target_repr, label }`, or `undefined`.
 *
 * Degrades to `undefined` -- never a fabricated recommendation -- for: an unrecognized rule_id
 * (not a member of RECOMMEND_MAP); a garbled/non-object alert record; a verb that (defensively)
 * fails the closed-enum check; or diagnostics from which no safe target_repr can be extracted.
 */
export function mapAlertToRecommendation(alertRecord) {
  if (!alertRecord || typeof alertRecord !== "object") return undefined;
  const ruleId = alertRecord.rule_id;
  const entry = typeof ruleId === "string" ? RECOMMEND_MAP.get(ruleId) : undefined;
  if (!entry) return undefined; // unrecognized/garbled trigger -- degrade, never fabricate
  if (!KNOWN_CONTAINMENT_VERBS.includes(entry.verb)) return undefined; // defensive; unreachable given RECOMMEND_MAP is hand-authored against the closed enum above
  const targetRepr = extractTargetRepr(alertRecord);
  if (targetRepr === undefined) return undefined; // garbled/unsafe diagnostics -- degrade, never fabricate a target
  const tamperReason = ruleId === CANARY_TAMPERED_RULE_ID ? alertRecord.diagnostics?.tamper_reason : undefined;
  return {
    verb: entry.verb,
    rule_id: `containment.recommend.${entry.verb}`,
    trigger_rule_id: ruleId,
    rationale: entry.rationale,
    target_repr: targetRepr,
    label: CONTAINMENT_RECOMMEND_LABEL,
    ...(tamperReason ? { tamper_reason: tamperReason } : {}),
  };
}

/**
 * Bounded, sanitized display text for a recommendation object: the RECOMMEND-ONLY label FIRST
 * (see the label's own doc comment above for why label-first matters under downstream 240-char
 * truncation), then the closed-enum verb + hash/bucket target, then the rationale template.
 */
export function renderRecommendationText(rec) {
  if (!rec || typeof rec !== "object") return undefined;
  if (!KNOWN_CONTAINMENT_VERBS.includes(rec.verb)) return undefined;
  if (!isTargetHash(rec.target_repr) && rec.target_repr !== GLOBAL_TARGET_REPR) return undefined;
  const target = rec.target_repr;
  const rationale = typeof rec.rationale === "string" && rec.rationale ? rec.rationale : "No further detail available.";
  return `${CONTAINMENT_RECOMMEND_LABEL} Consider: ${rec.verb} ${target}. ${rationale}`;
}

/**
 * Re-derives and renders a recommendation's display text from a STORED candidate's own
 * (already-sanitized) diagnostics fields (`verb`, `trigger_rule_id`, `target_repr`) rather than
 * from a live alert record. This is what alert-intelligence.js's
 * buildSessionAlertNotificationDecision containment branch calls at delivery time (plan §Slice
 * 7.2.c, must-fix option (a): "have this branch import and call renderRecommendationText
 * directly" -- generalized here to work from the diagnostics shape actually persisted, since
 * sanitizeDiagnostics would redact a full free-text sentence stored directly). Keyed by
 * `trigger_rule_id` (not `verb` alone) so two triggers that happen to share a verb (canary.tripped
 * and canary.tampered both -> quarantine) never cross-contaminate each other's rationale text.
 * Degrades to `undefined` -- never fabricated text -- when the stored fields don't match a known
 * mapping entry (corrupt/foreign diagnostics).
 */
export function renderStoredRecommendationText(diagnostics) {
  const triggerRuleId = diagnostics?.trigger_rule_id;
  const entry = typeof triggerRuleId === "string" ? RECOMMEND_MAP.get(triggerRuleId) : undefined;
  if (!entry || entry.verb !== diagnostics?.verb) return undefined;
  const target = diagnostics?.target_repr;
  const targetValid = triggerRuleId === PEER_COUNT_SPIKE_RULE_ID
    ? target === GLOBAL_TARGET_REPR
    : triggerRuleId === CANARY_TAMPERED_RULE_ID
      ? (diagnostics?.tamper_reason === "manifest_unreadable" || diagnostics?.tamper_reason === "baseline_store_error"
        ? target === GLOBAL_TARGET_REPR
        : diagnostics?.tamper_reason === "canary_vanished" && isTargetHash(target))
      : isTargetHash(target);
  if (!targetValid) return undefined;
  return renderRecommendationText({ verb: entry.verb, rationale: entry.rationale, target_repr: target });
}

/**
 * The closed set of `containment.recommend.<verb>` rule_ids this module can ever emit --
 * derived from RECOMMEND_MAP's actual entries (never hand-duplicated), so it can never drift
 * into registering a dead/unreachable allowlist entry for a verb the map does not produce (plan
 * §7 Open Decision 2's reconciliation note). Consumed by alert-intelligence.js to widen the
 * deterministic non-LLM local-delivery allowlist and by the namespace-hard-exclude boundary
 * tests.
 */
export function containmentRecommendationRuleIds() {
  return [...new Set([...RECOMMEND_MAP.values()].map((entry) => `containment.recommend.${entry.verb}`))];
}

// ---------------------------------------------------------------------------------------------
// Slice 7.2.b -- dedicated, default-OFF opt-in config. Independent of learned.json (monitoring)
// and of the future containment authority kill-switch (§(e) Slice 7.3+).
// ---------------------------------------------------------------------------------------------

export function resolveContainmentRecommendPaths(descartesPaths) {
  return { configFile: path.join(descartesPaths.configDir, "containment-recommend.json") };
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid containment-recommend config ${field}: ${ts}`);
  return date.toISOString();
}

export function normalizeContainmentRecommendConfig(config = {}) {
  return {
    enabled: config.enabled === true,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

/**
 * Fail-closed: ENOENT (never configured), a non-ENOENT read failure (EACCES/EIO/ENOSPC/EROFS),
 * and corrupt JSON all resolve to `{ enabled: false, ... }` -- this surface's opt-in is OFF by
 * default and stays OFF on any read anomaly (P5: "a missing or corrupt opt-in config reads as
 * OFF"). `unavailable`/`corrupt` are additive markers only; callers that read only `.enabled`
 * (the daemon's own gate) are unaffected.
 */
export async function readContainmentRecommendConfig(descartesPaths) {
  const { configFile } = resolveContainmentRecommendPaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeContainmentRecommendConfig();
    console.warn(`descartes: containment-recommend.json read failed (${error?.code ?? error}); treating the recommend-only surface as disabled this tick`);
    return { ...normalizeContainmentRecommendConfig(), unavailable: true };
  }
  try {
    return normalizeContainmentRecommendConfig(JSON.parse(contents));
  } catch {
    console.warn("descartes: containment-recommend.json is corrupt; treating the recommend-only surface as disabled");
    return { ...normalizeContainmentRecommendConfig(), corrupt: true };
  }
}

/**
 * Guarded write: refuses to write (throws, config on disk untouched) when the existing config
 * could not be safely read (`corrupt` or `unavailable`) -- stricter than
 * alert-intelligence.json's own guard (which only refuses on `unavailable`, treating `corrupt` as
 * safe-to-overwrite "recovery, not data loss"). This surface is deliberately more conservative
 * (P5: "materially louder, scarier emission... a wrong one is a harm vector") -- an operator
 * finding containment-recommend.json corrupt should have to look at it before anything
 * overwrites it, even though the opt-in already reads as OFF in the meantime.
 */
export async function writeContainmentRecommendConfig(descartesPaths, config, options = {}) {
  const existing = await readContainmentRecommendConfig(descartesPaths);
  if (existing.corrupt || existing.unavailable) {
    throw new Error(
      "containment-recommend.json could not be safely read (corrupt or unreadable) -- refusing to write and risk clobbering existing state. Inspect/repair the file (or resolve the underlying read error) and retry.",
    );
  }
  const { configFile } = resolveContainmentRecommendPaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeContainmentRecommendConfig({ ...config, updated_at: options.now ?? new Date().toISOString() });
  const tmp = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmp, configFile);
  return normalized;
}

// ---------------------------------------------------------------------------------------------
// Slice 7.2.c -- daemon-tick candidate compute. The daemon supplies the result of the main alert
// evaluation, so this phase never reads stale alert history and never acts on a previous-tick
// record. Only alerts that are active AND notification-due in that current evaluation qualify.
// ---------------------------------------------------------------------------------------------

const RECOMMENDATION_TRIGGER_STATUS = "active";

/**
 * Computes containment recommendation candidates for the current daemon tick, matching every
 * sibling extraCandidates source's exact short-circuit shape: gated by BOTH learned.json
 * (monitoring, P4) AND this module's own containment-recommend.json opt-in (P5) BEFORE any I/O
 * beyond the two config reads -- either OFF short-circuits to `[]`, a structural absence from the
 * merged candidate array (not a post-hoc filter), so applyAlertCandidates' existing recovery loop
 * naturally marks any previously-active containment.recommend.* record `recovered` the very next
 * tick (the load-bearing fail-closed transition; see the plan's Slice 7.2.c "Deterministic
 * behavior" note).
 *
 * `options.evaluation` is the current result from evaluateAndPersistAlerts. The `alerts` and
 * `notification_due_ids` options remain a small pure DI seam for unit tests; neither path reads
 * persisted alert history here.
 */
export async function computeContainmentRecommendationCandidates(descartesPaths, options = {}) {
  const loadLearned = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadLearned(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const readContainmentConfig = options.readContainmentRecommendConfig ?? readContainmentRecommendConfig;
  const containmentConfig = await readContainmentConfig(descartesPaths);
  if (!containmentConfig.enabled) return [];

  const evaluation = options.evaluation ?? {
    alerts: options.alerts,
    notification_due_ids: options.notification_due_ids,
  };
  const dueIds = new Set(evaluation?.notification_due_ids ?? []);
  const alerts = evaluation?.alerts ?? [];

  const candidates = [];
  for (const alert of alerts ?? []) {
    if (alert?.status !== RECOMMENDATION_TRIGGER_STATUS || !dueIds.has(alert?.id)) continue;
    const recommendation = mapAlertToRecommendation(alert);
    if (!recommendation) continue;

    // All persisted identity-bearing fields are derived from fixed rule IDs and validated hashes;
    // the triggering alert's arbitrary id/fingerprint never crosses this boundary verbatim.
    const triggerRef = hashReference(alert.id ?? `${recommendation.trigger_rule_id}:${recommendation.target_repr}`);
    const fingerprint = hashReference(`${recommendation.trigger_rule_id}:${recommendation.target_repr}`);
    const diagnostics = sanitizeDiagnostics({
      trigger_rule_id: recommendation.trigger_rule_id,
      trigger_alert_ref: triggerRef,
      verb: recommendation.verb,
      target_repr: recommendation.target_repr,
      ...(recommendation.tamper_reason ? { tamper_reason: recommendation.tamper_reason } : {}),
    });

    candidates.push({
      id: alertId(recommendation.rule_id, fingerprint),
      rule_id: recommendation.rule_id,
      fingerprint,
      severity: "warning",
      title: `Descartes containment recommendation: ${recommendation.verb}`,
      summary: `RECOMMEND-ONLY: consider ${recommendation.verb}. Descartes will not act on this.`,
      diagnostics,
      evidence_refs: ["containment-recommend", `trigger-ref:${triggerRef}`],
    });
  }
  return candidates;
}
