// S14 human authority gate (plan §5.7/§5.8/§6) — the review-ready -> approved|rejected boundary
// for TUNING CANDIDATES. This is a near-structural clone of promotion-store.js's
// decideConstraintPromotion (itself the safety-critical review-ready -> active gate for
// constraints), pointed at a SEPARATE store (stateDir/authority/tuning-decisions.json, never
// promotions.json — plan §6.1: different risk domain, different foreign-key shape, and reusing
// decideConstraintPromotion would mean growing an already safety-reviewed function's control
// flow). Despite being structurally similar, this file is independently, adversarially verified
// (plan §6.3 point (c)) — copy-paste safety-critical code can silently reintroduce a bug even
// when the source was safe.
//
// Deny-by-default, same as promotion-store.js: a missing, expired, wrong-nonce, already-decided,
// or non-review-ready case never results in a candidate's approval advancing — every one of those
// cases fails closed and is surfaced as a thrown Error, after logging the denial into the matching
// tuning-decisions.json record's audit_transitions wherever one exists to attach it to (never
// fabricating an attempt against the wrong record — the spot-B audit-misattribution fix,
// mirrored here from promotion-store.js's logDenial).
//
// THE RETUNE REPLAY GUARD (plan §5.7/§5.8/§6.2 layer 4, must-fix): applyApprovedRetune is a
// SELF-LOOP (active -> active) on the target constraint, unlike promoteReviewReadyToActive's
// review-ready -> active transition. That means the target artifact's OWN status can never double
// as a replay guard for `retune` the way it does for constraint promotion. This file closes that
// gap by gating on the CANDIDATE's own status instead: decideTuningApproval denies unless the
// candidate itself is currently status:"review-ready", and a decision (approve or reject) flips
// the candidate to approved/rejected — so a replayed (tuningCandidateId, nonce) pair always fails
// the review-ready check on any subsequent attempt, regardless of whether the underlying artifact
// moved. mintPendingTuningApproval additionally refuses to mint a fresh pending record for a
// candidate that is not currently review-ready, closing the residual "fresh nonce against an
// already-decided candidate" gap.
//
// This file never itself writes constraints.json directly — it only ever calls
// constraint-store.js's retireActiveConstraint/applyApprovedRetune (the two functions in the
// entire codebase that can change a live constraint's status-to-retired or expected value), and
// only from the "approved" branch, gated on the candidate's own family/kind matching a known
// constraint-family case. Anything else (a malformed candidate, a future dispatch-table
// regression, or — in principle — a non-constraint-family candidate, even though the v1 miner
// never emits one) falls into a FAIL-CLOSED default: applied:false with an explicit apply_note,
// never a crash, never a silent no-op reporting applied:true (plan §5.6).
//
// No LLM anywhere: this module never imports pi-harness.js or alert-intelligence.js.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { applyApprovedRetune, loadConstraints, retireActiveConstraint, writeConstraints } from "./constraint-store.js";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { loadTuningCandidates, writeTuningCandidates } from "./tuning-store.js";

export const SCHEMA_VERSION = 1;

// Single-user local CLI, same posture as promotion-store.js's own default (24h).
export const DEFAULT_TUNING_APPROVAL_EXPIRY_MS = 24 * 60 * 60 * 1000;

export const TUNING_APPROVAL_STATUSES = ["pending", "approved", "rejected"];

const CONSTRAINT_VIOLATION_PREFIX = "constraint.violation.";

export function resolveTuningAuthorityPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "authority");
  return { dir, tuningDecisionsFile: path.join(dir, "tuning-decisions.json") };
}

async function ensureTuningAuthorityDir(descartesPaths) {
  await fs.mkdir(resolveTuningAuthorityPaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid tuning decision ${field}: ${ts}`);
  return date.toISOString();
}

/**
 * Validates a tuning-approval decision record: {id, nonce, tuning_candidate_ref, bounded_summary,
 * evidence_refs, expiry, status, audit_transitions}. Mirrors promotion-store.js's
 * validatePromotionRecord exactly, with `tuning_candidate_ref` in place of `promotion_ref` (a
 * distinct field name, not just a distinct file, so the two record shapes can never be confused
 * even if a record were accidentally read from the wrong store).
 */
export function validateTuningDecisionRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Tuning decision record must be an object");
  }

  const id = String(record.id ?? "").trim();
  if (!id) throw new Error("Tuning decision record requires a non-empty id");

  const nonce = String(record.nonce ?? "").trim();
  if (!nonce) throw new Error("Tuning decision record requires a non-empty nonce");

  const tuningCandidateRef = String(record.tuning_candidate_ref ?? "").trim();
  if (!tuningCandidateRef) throw new Error("Tuning decision record requires a non-empty tuning_candidate_ref");

  if (!TUNING_APPROVAL_STATUSES.includes(record.status)) {
    throw new Error(`Tuning decision record status must be one of ${TUNING_APPROVAL_STATUSES.join(", ")}, got: ${JSON.stringify(record.status)}`);
  }

  normalizeIso(record.expiry, "expiry");

  if (!Array.isArray(record.evidence_refs)) {
    throw new Error("Tuning decision record requires evidence_refs to be an array");
  }
  if (!Array.isArray(record.audit_transitions)) {
    throw new Error("Tuning decision record requires audit_transitions to be an array");
  }

  return true;
}

async function readJsonFile(file) {
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { parsed: undefined, missing: true };
    throw error;
  }
  try {
    return { parsed: JSON.parse(contents), missing: false };
  } catch {
    return { parsed: undefined, missing: false, corrupt: true };
  }
}

/**
 * Loads the tuning-authority store, tolerating a corrupt/malformed file (mirrors
 * promotion-store.js's loadPromotions exactly) rather than throwing. Deny-by-default holds even
 * in the degenerate case: an empty/corrupt tuning-decisions.json means nothing can ever match, so
 * every approve/reject call denies closed.
 */
export async function loadTuningDecisions(descartesPaths) {
  const { tuningDecisionsFile } = resolveTuningAuthorityPaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(tuningDecisionsFile);
  if (missing) return { decisions: [], corrupt_count: 0 };
  if (corrupt) return { decisions: [], corrupt_count: 1 };

  const rawDecisions = Array.isArray(parsed) ? parsed : parsed?.decisions;
  if (!Array.isArray(rawDecisions)) return { decisions: [], corrupt_count: 1 };

  const decisions = [];
  for (const record of rawDecisions) {
    try {
      validateTuningDecisionRecord(record);
      decisions.push(record);
    } catch {
      // Silently drop invalid individual records, mirroring loadPromotions.
    }
  }
  return { decisions, corrupt_count: 0 };
}

/**
 * Atomically writes the tuning-authority store (tmp+rename, 0o600 file / 0o700 dir), mirroring
 * promotion-store.js's writePromotions exactly. Every record is validated before persisting.
 */
export async function writeTuningDecisions(descartesPaths, decisions) {
  await ensureTuningAuthorityDir(descartesPaths);
  const { tuningDecisionsFile } = resolveTuningAuthorityPaths(descartesPaths);
  const normalized = (decisions ?? []).map((record) => {
    validateTuningDecisionRecord(record);
    return record;
  });
  const payload = JSON.stringify({ schema_version: SCHEMA_VERSION, decisions: normalized }, null, 2);
  const tmpFile = `${tuningDecisionsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, tuningDecisionsFile);
  return normalized;
}

function randomNonce() {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * Distinct id prefix from promotion-store.js's `promotion.<16-hex>` (defense-in-depth against
 * ever conflating the two stores even if accidentally read from the wrong file).
 */
function tuningApprovalRecordId(tuningCandidateId, nonce) {
  const digest = crypto.createHash("sha256").update(`${tuningCandidateId}\0${nonce}`).digest("hex").slice(0, 16);
  return `tuning-approval.${digest}`;
}

function buildBoundedSummary(candidate) {
  const kind = sanitizeIdentityString(candidate?.kind) ?? "unknown";
  const family = sanitizeIdentityString(candidate?.rule_id_family) ?? "unknown";
  const ref = sanitizeIdentityString(candidate?.artifact_ref) ?? "unknown";
  return sanitizeIdentityString([kind, family, ref].filter(Boolean).join(":")) ?? "unknown";
}

function buildEvidenceRefs() {
  return ["tuning-store", "calibration"];
}

function findValidPendingTuningApproval(decisions, tuningCandidateId, nowMs) {
  return (decisions ?? [])
    .filter((record) => record?.tuning_candidate_ref === tuningCandidateId && record?.status === "pending")
    .find((record) => {
      const expiryMs = new Date(record.expiry).getTime();
      return Number.isFinite(expiryMs) && expiryMs > nowMs;
    });
}

/**
 * Mints a fresh pending tuning-approval record for a review-ready candidate. MUST-FIX (plan
 * §5.8 rule 3): refuses to mint a pending record for a candidate that is not currently
 * status:"review-ready" -- closing the gap where a fresh nonce could otherwise be minted against
 * an already-decided candidate and used to re-trigger decideTuningApproval. Reuses an existing
 * currently-valid (pending, unexpired) record rather than minting a duplicate, mirroring
 * promotion-store.js's mintPendingPromotion.
 */
export async function mintPendingTuningApproval(descartesPaths, candidate, options = {}) {
  if (!candidate || candidate.status !== "review-ready") {
    throw new Error(`Cannot mint a pending tuning approval for ${JSON.stringify(candidate?.id)}: status is ${JSON.stringify(candidate?.status)}, not "review-ready".`);
  }

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const { decisions } = await loadTuningDecisions(descartesPaths);

  const existing = findValidPendingTuningApproval(decisions, candidate.id, nowMs);
  if (existing) return { approval: existing, minted: false };

  const nonce = options.nonce ?? randomNonce();
  const expiryMs = nowMs + (Number.isFinite(options.expiryMs) ? options.expiryMs : DEFAULT_TUNING_APPROVAL_EXPIRY_MS);
  const record = {
    id: tuningApprovalRecordId(candidate.id, nonce),
    nonce,
    tuning_candidate_ref: candidate.id,
    bounded_summary: buildBoundedSummary(candidate),
    evidence_refs: buildEvidenceRefs(),
    requested_at: nowIso,
    expiry: new Date(expiryMs).toISOString(),
    status: "pending",
    decided_at: undefined,
    audit_transitions: [{ ts: nowIso, action: "requested", actor: "human-cli", note: "minted via descartes learned tuning review" }],
  };
  await writeTuningDecisions(descartesPaths, [...decisions, record]);
  return { approval: record, minted: true };
}

/**
 * Deny-by-default matcher: returns the single pending, nonce-matched, unexpired tuning-approval
 * record for tuningCandidateId, or undefined. Every other case (no record at all, wrong nonce,
 * expired, already decided) returns undefined -- callers MUST treat "no match" as a hard deny,
 * never a fallback grant. Mirrors promotion-store.js's matchPendingPromotion.
 */
function matchPendingTuningApproval(decisions, tuningCandidateId, nonce, nowMs) {
  return (decisions ?? []).find((record) =>
    record?.tuning_candidate_ref === tuningCandidateId
    && record?.status === "pending"
    && record?.nonce === nonce
    && Number.isFinite(new Date(record?.expiry).getTime())
    && new Date(record.expiry).getTime() > nowMs);
}

function tuningDenialReason(decisions, tuningCandidateId, nonce, nowMs) {
  const forCandidate = (decisions ?? []).filter((record) => record?.tuning_candidate_ref === tuningCandidateId);
  if (forCandidate.length === 0) return "no_pending_tuning_approval";
  const pending = forCandidate.filter((record) => record.status === "pending");
  if (pending.length === 0) return "already_decided";
  const nonceMatches = pending.filter((record) => record.nonce === nonce);
  if (nonceMatches.length === 0) return "nonce_mismatch";
  const unexpired = nonceMatches.filter((record) => new Date(record.expiry).getTime() > nowMs);
  if (unexpired.length === 0) return "expired";
  return "denied";
}

/**
 * Appends a denial entry to the tuning-decision record the attempt actually targeted: the
 * nonce-matching record (attributing a replay of a consumed nonce to the record it belongs to),
 * else the live `pending` record being attacked. Never falls back to an arbitrary already-decided
 * record (the spot-B audit-misattribution fix, mirrored from promotion-store.js's logDenial). A
 * no-op (nothing written) when neither exists. Never changes a record's status/decided_at; only
 * appends to audit_transitions.
 */
async function logTuningDenial(descartesPaths, decisions, tuningCandidateId, nonce, reason, options = {}) {
  const candidates = (decisions ?? []).filter((record) => record?.tuning_candidate_ref === tuningCandidateId);
  if (candidates.length === 0) return decisions;

  const nowIso = normalizeIso(options.now ?? new Date().toISOString());
  const nowMs = new Date(nowIso).getTime();
  // Attribute the denial to the record whose nonce was actually supplied; else to the currently-
  // VALID (unexpired) pending record being attacked -- NOT merely the first pending one in array
  // order (adversarial-review finding): expired decision records keep status:"pending" (only their
  // `expiry` ages out), so a stale-expired and a freshly-re-minted valid record can coexist as
  // pending, and picking the first would misattribute the denial to the stale record's audit trail.
  // Falls back to any pending record only if none are still valid.
  const isUnexpiredPending = (record) => {
    if (record.status !== "pending") return false;
    const expiryMs = new Date(record.expiry).getTime();
    return Number.isFinite(expiryMs) && expiryMs > nowMs;
  };
  const target =
    candidates.find((record) => record.nonce === nonce)
    ?? candidates.find(isUnexpiredPending)
    ?? candidates.find((record) => record.status === "pending");
  if (!target) return decisions;
  const updated = decisions.map((record) => {
    if (record !== target) return record;
    return {
      ...record,
      audit_transitions: [
        ...(record.audit_transitions ?? []),
        { ts: nowIso, action: "denied", actor: "human-cli", reason, note: options.note },
      ],
    };
  });
  await writeTuningDecisions(descartesPaths, updated);
  return updated;
}

/**
 * The fail-closed dispatch table for an APPROVED tuning candidate (plan §5.6). Only the two real
 * constraint-family cases ever mutate constraints.json; anything else -- a malformed candidate, a
 * future dispatch-table regression, or (in principle) a non-constraint-family candidate, even
 * though the v1 miner never emits one -- falls into the explicit default: applied:false with a
 * specific apply_note, never a crash, never a silent applied:true. Returns
 * { constraints, applied, applyNote, error } -- `error` is set (and `constraints` is the
 * UNCHANGED input array) when a real constraint-family dispatch's own mutator rejected the
 * candidate (e.g. a malformed proposedExpected, or the target constraint is no longer active);
 * the caller (decideTuningApproval) treats a non-undefined `error` as a hard failure of the whole
 * approval attempt -- no partial write, ever.
 */
function dispatchApprovedTuning(constraints, candidate, options) {
  const isConstraintFamily = String(candidate?.rule_id_family ?? "").startsWith(CONSTRAINT_VIOLATION_PREFIX);

  if (candidate.kind === "retire" && isConstraintFamily) {
    try {
      const result = retireActiveConstraint(constraints, candidate.artifact_ref, options);
      return { constraints: result.constraints, applied: true, applyNote: null };
    } catch (error) {
      return { constraints, applied: false, applyNote: null, error: error instanceof Error ? error.message : String(error) };
    }
  }

  if (candidate.kind === "retune" && isConstraintFamily) {
    try {
      const result = applyApprovedRetune(constraints, candidate.artifact_ref, candidate.proposed?.expected, options);
      return { constraints: result.constraints, applied: true, applyNote: null };
    } catch (error) {
      return { constraints, applied: false, applyNote: null, error: error instanceof Error ? error.message : String(error) };
    }
  }

  if (candidate.kind === "promote_shadow_hint") {
    return {
      constraints,
      applied: false,
      applyNote: "run 'descartes learned soak' / 'descartes learned review' / 'descartes learned approve' -- this hint carries no mutation of its own",
    };
  }

  // Fail-closed dispatch default (plan §5.6/§6.3 point 3): never reachable from the v1 miner
  // (which emits only constraint.* candidates), exercised only by a hand-constructed synthetic
  // candidate in tests -- defense-in-depth against a future dispatch-table edit gone wrong.
  return {
    constraints,
    applied: false,
    applyNote: "no live-mutation path for this candidate in v1 -- see docs/plans/2026-07-14-compile-down-calibration.md §5.1/§9 (Slice 14b)",
  };
}

/**
 * The single entry point for the review-ready -> approved|rejected decision (plan §5.8).
 * `decision` is "approved" or "rejected". Deny-by-default at every step:
 *   1. Unknown tuning candidate id -> deny.
 *   2. Candidate not currently status:"review-ready" -> deny. THIS is the retune replay guard
 *      (plan §5.7/§5.8 rule 1): unlike a constraint's own status (which changes forward on
 *      promotion), applyApprovedRetune is a self-loop on the target constraint, so the
 *      CANDIDATE's own status is what prevents a replayed nonce from re-applying a decided
 *      retune -- a successful decision always flips the candidate away from review-ready first.
 *   3. No pending, nonce-matched, unexpired tuning-approval record -> deny.
 * Every denial is logged into the matching tuning-decision record's audit_transitions before the
 * Error is thrown. On "approved": dispatchApprovedTuning resolves the live-mutation path (or the
 * fail-closed default); if the mutator itself rejects (malformed retune, constraint no longer
 * active), the WHOLE approval attempt fails -- no candidate flip, no decision flip, no
 * constraints.json write. On success, both the candidate and the decision record are persisted
 * together with the (possibly failed-closed) applied/apply_note outcome.
 */
export async function decideTuningApproval(descartesPaths, tuningCandidateId, nonce, decision, options = {}) {
  if (decision !== "approved" && decision !== "rejected") {
    throw new Error(`decideTuningApproval: decision must be "approved" or "rejected", got: ${JSON.stringify(decision)}`);
  }

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const verb = decision === "approved" ? "approve" : "reject";

  const { candidates } = await loadTuningCandidates(descartesPaths);
  const candidate = candidates.find((entry) => entry?.id === tuningCandidateId);
  const { decisions } = await loadTuningDecisions(descartesPaths);

  if (!candidate) {
    await logTuningDenial(descartesPaths, decisions, tuningCandidateId, nonce, "candidate_not_found", { now: nowIso, note: options.note });
    throw new Error(`Cannot ${verb} ${tuningCandidateId}: no such tuning candidate.`);
  }
  if (candidate.status !== "review-ready") {
    await logTuningDenial(descartesPaths, decisions, tuningCandidateId, nonce, "candidate_not_review_ready", { now: nowIso, note: options.note });
    throw new Error(`Cannot ${verb} ${tuningCandidateId}: status is "${candidate.status}", not "review-ready".`);
  }

  const match = matchPendingTuningApproval(decisions, tuningCandidateId, nonce, nowMs);
  if (!match) {
    const reason = tuningDenialReason(decisions, tuningCandidateId, nonce, nowMs);
    await logTuningDenial(descartesPaths, decisions, tuningCandidateId, nonce, reason, { now: nowIso, note: options.note });
    throw new Error(
      `Cannot ${verb} ${tuningCandidateId}: tuning approval denied (${reason}). Run 'descartes learned tuning review' to (re)issue a pending approval.`,
    );
  }

  let updatedConstraints;
  let applied = false;
  let applyNote = null;

  if (decision === "approved") {
    const { constraints } = await loadConstraints(descartesPaths);
    const dispatch = dispatchApprovedTuning(constraints, candidate, {
      now: nowIso,
      note: options.note ?? `tuning-approved via descartes learned tuning approve (${tuningCandidateId})`,
    });
    if (dispatch.error) {
      // Fail closed: the mutator itself rejected the candidate (malformed retune shape, target
      // constraint no longer active, ...). No partial write of any kind -- the candidate stays
      // review-ready and can be corrected/retried, the decision stays pending.
      await logTuningDenial(descartesPaths, decisions, tuningCandidateId, nonce, `apply_failed:${dispatch.error}`, { now: nowIso, note: options.note });
      throw new Error(`Cannot approve ${tuningCandidateId}: ${dispatch.error}`);
    }
    updatedConstraints = dispatch.constraints;
    applied = dispatch.applied;
    applyNote = dispatch.applyNote;
  }

  const updatedCandidates = candidates.map((entry) => {
    if (entry.id !== tuningCandidateId) return entry;
    return {
      ...entry,
      status: decision,
      applied: decision === "approved" ? applied : entry.applied,
      apply_note: decision === "approved" ? applyNote : entry.apply_note,
      promotion_history: [
        ...(entry.promotion_history ?? []),
        { ts: nowIso, from: "review-ready", to: decision, actor: "human-cli", note: options.note },
      ],
    };
  });

  const updatedDecisions = decisions.map((record) => {
    if (record !== match) return record;
    return {
      ...record,
      status: decision,
      decided_at: nowIso,
      audit_transitions: [
        ...(record.audit_transitions ?? []),
        { ts: nowIso, action: decision, actor: "human-cli", note: options.note },
      ],
    };
  });

  // Only write constraints.json when a REAL mutation happened (applied === true) -- the
  // fail-closed dispatch default and promote_shadow_hint both return the ORIGINAL, unchanged
  // constraints array, and writing that back would needlessly create/touch constraints.json
  // even when nothing was ever meant to change.
  if (decision === "approved" && applied && updatedConstraints) {
    await writeConstraints(descartesPaths, updatedConstraints);
  }
  await writeTuningCandidates(descartesPaths, updatedCandidates);
  await writeTuningDecisions(descartesPaths, updatedDecisions);

  return {
    candidate: updatedCandidates.find((entry) => entry.id === tuningCandidateId),
    decision: updatedDecisions.find((record) => record.id === match.id),
  };
}

// --- CLI: descartes learned tuning review | approve | reject ---

function tuningReviewUsage() {
  return `Usage:
  descartes learned tuning review [--json]

Lists status:"review-ready" tuning candidates for human inspection (justification, backtest,
proposed value) and mints a fresh pending tuning-approval record (nonce + expiry) in
stateDir/authority/tuning-decisions.json for any review-ready candidate that doesn't already have
a valid one. The nonce shown here is required by 'descartes learned tuning approve'/'reject'.
Read-only of candidate status -- review never itself decides a candidate. Never gated behind
configDir/learned.json.`;
}

function renderTuningReviewEntry(entry) {
  return [
    `${entry.id} [${entry.kind}] ${entry.artifact_ref} justification=${JSON.stringify(entry.justification)}`,
    `  nonce=${entry.approval.nonce} expires=${entry.approval.expiry}`,
    `  approve: descartes learned tuning approve ${entry.id} --nonce ${entry.approval.nonce}`,
    `  reject:  descartes learned tuning reject ${entry.id} --nonce ${entry.approval.nonce}`,
  ].join("\n");
}

export async function runLearnedTuningReview(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(tuningReviewUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned tuning review argument: ${arg}\n\n${tuningReviewUsage()}`);
    }
  }

  const now = runtime.now ?? Date.now();
  const { candidates } = await loadTuningCandidates(descartesPaths);
  const reviewReady = candidates.filter((candidate) => candidate?.status === "review-ready");

  const entries = [];
  for (const candidate of reviewReady) {
    const { approval } = await mintPendingTuningApproval(descartesPaths, candidate, { now, expiryMs: runtime.expiryMs });
    entries.push({
      id: candidate.id,
      kind: candidate.kind,
      artifact_ref: candidate.artifact_ref,
      rule_id_family: candidate.rule_id_family,
      current: candidate.current,
      proposed: candidate.proposed,
      justification: candidate.justification,
      approval: { id: approval.id, nonce: approval.nonce, expiry: approval.expiry, status: approval.status },
    });
  }

  if (json) {
    output(JSON.stringify({ learned_tuning_review: { review_ready: entries } }, null, 2));
  } else if (entries.length === 0) {
    output("No review-ready tuning candidates.");
  } else {
    output(entries.map(renderTuningReviewEntry).join("\n"));
  }
  return { review_ready: entries };
}

function tuningDecisionUsage(name) {
  return `Usage:
  descartes learned tuning ${name} <tuning-candidate-id> --nonce <nonce> [--note <text>] [--json]

Requires the exact nonce shown by 'descartes learned tuning review' for that candidate.
Deny-by-default: fails closed (no candidate/constraint state change) if no pending tuning
approval exists, the nonce doesn't match, the approval has expired, or the candidate is not
status:"review-ready". No LLM anywhere.`;
}

function parseTuningDecisionArgs(args, name) {
  const [tuningCandidateId, ...rest] = args ?? [];
  if (!tuningCandidateId || tuningCandidateId === "--help" || tuningCandidateId === "-h") {
    return { help: true };
  }
  const options = { tuningCandidateId, nonce: undefined, note: undefined, json: false };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--nonce") {
      const value = rest[index + 1];
      if (!value) throw new Error(`--nonce requires a value\n\n${tuningDecisionUsage(name)}`);
      options.nonce = value;
      index += 1;
    } else if (arg === "--note") {
      const value = rest[index + 1];
      if (value === undefined) throw new Error(`--note requires a value\n\n${tuningDecisionUsage(name)}`);
      options.note = value;
      index += 1;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { help: true };
    } else {
      throw new Error(`Unexpected ${name} argument: ${arg}\n\n${tuningDecisionUsage(name)}`);
    }
  }
  return options;
}

export async function runLearnedTuningApprove(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const parsed = parseTuningDecisionArgs(args, "approve");
  if (parsed.help) {
    output(tuningDecisionUsage("approve"));
    return undefined;
  }
  if (!parsed.nonce) throw new Error(`approve requires --nonce <nonce> (shown by 'descartes learned tuning review')\n\n${tuningDecisionUsage("approve")}`);

  const now = runtime.now ?? Date.now();
  const result = await decideTuningApproval(descartesPaths, parsed.tuningCandidateId, parsed.nonce, "approved", { now, note: parsed.note });

  if (parsed.json) output(JSON.stringify({ learned_tuning_approve: result }, null, 2));
  else output(`Approved ${result.candidate.id}: status is now "${result.candidate.status}" (applied: ${result.candidate.applied}).`);
  return result;
}

export async function runLearnedTuningReject(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const parsed = parseTuningDecisionArgs(args, "reject");
  if (parsed.help) {
    output(tuningDecisionUsage("reject"));
    return undefined;
  }
  if (!parsed.nonce) throw new Error(`reject requires --nonce <nonce> (shown by 'descartes learned tuning review')\n\n${tuningDecisionUsage("reject")}`);

  const now = runtime.now ?? Date.now();
  const result = await decideTuningApproval(descartesPaths, parsed.tuningCandidateId, parsed.nonce, "rejected", { now, note: parsed.note });

  if (parsed.json) output(JSON.stringify({ learned_tuning_reject: result }, null, 2));
  else output(`Rejected ${result.candidate.id}: status is now "${result.candidate.status}".`);
  return result;
}
