// Human authority gate (Slice S7b, plan §5): the review-ready -> active promotion boundary.
// This is the single most safety-critical module in the whole pipeline — the ONLY way a
// constraint's status ever advances past review-ready is through `descartes learned approve`,
// which requires an explicit, nonce-matched, unexpired human decision recorded here.
// Deny-by-default: a missing, expired, wrong-nonce, already-decided, or non-review-ready case
// never results in the constraint advancing — every one of those cases fails closed and is
// surfaced as a thrown Error (mirrors alert-store.js's acknowledgeAlert "Alert not found"
// convention), after logging the denial into the matching promotions.json record's
// audit_transitions wherever one exists to attach it to (plan §5 acceptance: "denied attempts
// do not silently disappear").
//
// This file never itself flips a constraint's status forward — it always calls
// constraint-store.js's promoteReviewReadyToActive (the one function in the whole codebase
// that performs that specific write) for the approved path, and builds a plain status:"retired"
// record itself for the rejected path (never active, never back to draft). See
// promotion-store.test.js's "only one activation path" regression test for the source-level
// proof that this module never writes the target status literal directly.
//
// No LLM anywhere: this module never imports the coding-agent harness or the LLM-backed alert
// adjudication module used elsewhere in this codebase.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { loadConstraints, promoteReviewReadyToActive, writeConstraints } from "./constraint-store.js";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";

export const SCHEMA_VERSION = 1;

// Single-user local CLI (plan §8 open question #6) — friction against mistakes/stale reviews,
// not an attacker model. 24h recommended window.
export const DEFAULT_PROMOTION_EXPIRY_MS = 24 * 60 * 60 * 1000;

export const PROMOTION_STATUSES = ["pending", "approved", "rejected"];

export function resolvePromotionStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "authority");
  return { dir, promotionsFile: path.join(dir, "promotions.json") };
}

async function ensurePromotionDir(descartesPaths) {
  await fs.mkdir(resolvePromotionStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid promotion ${field}: ${ts}`);
  return date.toISOString();
}

/**
 * Validates a promotion-approval record against the roadmap §7 canonical shape:
 * {id, nonce, promotion_ref, bounded_summary, evidence_refs, expiry, status, audit_transitions}.
 * Throws a descriptive Error on the first invalid/missing required field; returns true
 * otherwise. Mirrors constraint-store.js's validateConstraint exactly.
 */
export function validatePromotionRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Promotion record must be an object");
  }

  const id = String(record.id ?? "").trim();
  if (!id) throw new Error("Promotion record requires a non-empty id");

  const nonce = String(record.nonce ?? "").trim();
  if (!nonce) throw new Error("Promotion record requires a non-empty nonce");

  const promotionRef = String(record.promotion_ref ?? "").trim();
  if (!promotionRef) throw new Error("Promotion record requires a non-empty promotion_ref");

  if (!PROMOTION_STATUSES.includes(record.status)) {
    throw new Error(`Promotion record status must be one of ${PROMOTION_STATUSES.join(", ")}, got: ${JSON.stringify(record.status)}`);
  }

  normalizeIso(record.expiry, "expiry");

  if (!Array.isArray(record.evidence_refs)) {
    throw new Error("Promotion record requires evidence_refs to be an array");
  }
  if (!Array.isArray(record.audit_transitions)) {
    throw new Error("Promotion record requires audit_transitions to be an array");
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
 * Loads the promotion store, tolerating a corrupt/malformed file (mirrors
 * constraint-store.js's loadConstraints exactly) rather than throwing. Individual invalid
 * records are dropped; a corrupt/unparseable file increments corrupt_count and yields an empty
 * set. Deny-by-default holds even in the degenerate case: an empty/corrupt promotions.json
 * means nothing can ever match, so every approve/reject call denies closed.
 */
export async function loadPromotions(descartesPaths) {
  const { promotionsFile } = resolvePromotionStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(promotionsFile);
  if (missing) return { promotions: [], corrupt_count: 0 };
  if (corrupt) return { promotions: [], corrupt_count: 1 };

  const rawPromotions = Array.isArray(parsed) ? parsed : parsed?.promotions;
  if (!Array.isArray(rawPromotions)) return { promotions: [], corrupt_count: 1 };

  const promotions = [];
  for (const record of rawPromotions) {
    try {
      validatePromotionRecord(record);
      promotions.push(record);
    } catch {
      // Silently drop invalid individual records, mirroring loadConstraints — a record that
      // never validated in the first place is not counted as file-level corruption.
    }
  }
  return { promotions, corrupt_count: 0 };
}

/**
 * Atomically writes the promotion store (tmp+rename, 0o600 file / 0o700 dir), mirroring
 * constraint-store.js's writeConstraints exactly. Every record is validated before persisting.
 */
export async function writePromotions(descartesPaths, promotions) {
  await ensurePromotionDir(descartesPaths);
  const { promotionsFile } = resolvePromotionStorePaths(descartesPaths);
  const normalized = (promotions ?? []).map((record) => {
    validatePromotionRecord(record);
    return record;
  });
  const payload = JSON.stringify({ schema_version: SCHEMA_VERSION, promotions: normalized }, null, 2);
  const tmpFile = `${promotionsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, promotionsFile);
  return normalized;
}

function randomNonce() {
  // 32 hex chars — deliberately one of diagnostics-sanitizer.js's HEX_HASH_LENGTHS, so a nonce
  // is safe-by-construction even if it were ever surfaced through the sanitized diagnostics
  // path (defense-in-depth; not currently required, since promotions.json is never routed
  // through sanitizeDiagnostics).
  return crypto.randomBytes(16).toString("hex");
}

function promotionRecordId(constraintId, nonce) {
  // Same truncated-sha256-hex pattern as alert-store.js's alertId()/constraint-miner.js's
  // minedId() — a hash-derived id is safe-by-construction regardless of constraintId's shape.
  const digest = crypto.createHash("sha256").update(`${constraintId}\0${nonce}`).digest("hex").slice(0, 16);
  return `promotion.${digest}`;
}

/**
 * Builds a bounded, sanitized one-line summary shown by `descartes learned review` — reuses
 * diagnostics-sanitizer.js's sanitizeIdentityString (never a raw/unbounded string), mirroring
 * constraint-miner.js's "re-apply the sanitizer, never trust upstream data stayed clean"
 * defense-in-depth convention.
 */
function buildBoundedSummary(constraint) {
  const family = sanitizeIdentityString(constraint?.family) ?? "unknown";
  const target = sanitizeIdentityString(constraint?.target) ?? "unknown";
  const comparator = typeof constraint?.expected?.comparator === "string"
    ? sanitizeIdentityString(constraint.expected.comparator)
    : undefined;
  const parts = [family, target, comparator].filter(Boolean);
  return sanitizeIdentityString(parts.join(":")) ?? "unknown";
}

function buildEvidenceRefs(constraint) {
  const refs = ["constraint-store", "shadow-store"];
  const sourceCollectors = Array.isArray(constraint?.provenance?.source_collectors) ? constraint.provenance.source_collectors : [];
  for (const collector of sourceCollectors) {
    const safe = sanitizeIdentityString(collector);
    if (safe) refs.push(safe);
  }
  return [...new Set(refs)];
}

function findValidPendingPromotion(promotions, constraintId, nowMs) {
  return (promotions ?? [])
    .filter((record) => record?.promotion_ref === constraintId && record?.status === "pending")
    .find((record) => {
      const expiryMs = new Date(record.expiry).getTime();
      return Number.isFinite(expiryMs) && expiryMs > nowMs;
    });
}

/**
 * Mints a fresh pending promotion record for a review-ready constraint if (and only if) no
 * currently-valid (pending, unexpired) record already exists for it — reuses the existing one
 * otherwise, so repeated `descartes learned review` calls keep showing the same nonce until it
 * either expires or is decided (plan §5: "expired reviews must be re-issued via review").
 */
export async function mintPendingPromotion(descartesPaths, constraint, options = {}) {
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const { promotions } = await loadPromotions(descartesPaths);

  const existing = findValidPendingPromotion(promotions, constraint.id, nowMs);
  if (existing) return { promotion: existing, minted: false };

  const nonce = options.nonce ?? randomNonce();
  const expiryMs = nowMs + (Number.isFinite(options.expiryMs) ? options.expiryMs : DEFAULT_PROMOTION_EXPIRY_MS);
  const record = {
    id: promotionRecordId(constraint.id, nonce),
    nonce,
    promotion_ref: constraint.id,
    bounded_summary: buildBoundedSummary(constraint),
    evidence_refs: buildEvidenceRefs(constraint),
    requested_at: nowIso,
    expiry: new Date(expiryMs).toISOString(),
    status: "pending",
    decided_at: undefined,
    audit_transitions: [{ ts: nowIso, action: "requested", actor: "human-cli", note: "minted via descartes learned review" }],
  };
  await writePromotions(descartesPaths, [...promotions, record]);
  return { promotion: record, minted: true };
}

/**
 * Deny-by-default matcher: returns the single pending, nonce-matched, unexpired promotion
 * record for constraintId, or undefined. Every other case (no record at all, wrong nonce,
 * expired, already decided) returns undefined — callers MUST treat "no match" as a hard deny,
 * never a fallback grant.
 */
function matchPendingPromotion(promotions, constraintId, nonce, nowMs) {
  return (promotions ?? []).find((record) =>
    record?.promotion_ref === constraintId
    && record?.status === "pending"
    && record?.nonce === nonce
    && Number.isFinite(new Date(record?.expiry).getTime())
    && new Date(record.expiry).getTime() > nowMs);
}

/**
 * Diagnoses WHY no promotion matched, for a precise (but still uniformly deny-closed) error
 * message — this is diagnostic output only, never used to grant access.
 */
function denialReason(promotions, constraintId, nonce, nowMs) {
  const forConstraint = (promotions ?? []).filter((record) => record?.promotion_ref === constraintId);
  if (forConstraint.length === 0) return "no_pending_promotion";
  const pending = forConstraint.filter((record) => record.status === "pending");
  if (pending.length === 0) return "already_decided";
  const nonceMatches = pending.filter((record) => record.nonce === nonce);
  if (nonceMatches.length === 0) return "nonce_mismatch";
  const unexpired = nonceMatches.filter((record) => new Date(record.expiry).getTime() > nowMs);
  if (unexpired.length === 0) return "expired";
  return "denied";
}

/**
 * Appends a denial entry to the promotion record the attempt actually targeted: the
 * nonce-matching record (attributing a replay of a consumed nonce to the record it belongs to),
 * else the live `pending` record being attacked. It is a no-op (nothing written) when neither
 * exists — including the "cannot skip review" case (no record at all). It NEVER falls back to an
 * arbitrary already-decided record, which would fabricate a wrong-nonce attempt in the audit
 * trail of a promotion that was never the target. Never changes a record's `status`/`decided_at`;
 * only appends to audit_transitions, so an already-decided record's decision is never overwritten.
 */
async function logDenial(descartesPaths, promotions, constraintId, nonce, reason, options = {}) {
  const candidates = (promotions ?? []).filter((record) => record?.promotion_ref === constraintId);
  if (candidates.length === 0) return promotions;

  const target =
    candidates.find((record) => record.nonce === nonce)
    ?? candidates.find((record) => record.status === "pending");
  if (!target) return promotions;
  const nowIso = normalizeIso(options.now ?? new Date().toISOString());
  const updated = promotions.map((record) => {
    if (record !== target) return record;
    return {
      ...record,
      audit_transitions: [
        ...(record.audit_transitions ?? []),
        { ts: nowIso, action: "denied", actor: "human-cli", reason, note: options.note },
      ],
    };
  });
  await writePromotions(descartesPaths, updated);
  return updated;
}

/**
 * The single entry point for the review-ready -> active decision (plan §5's human-gated
 * approve/reject). `decision` is "approved" or "rejected". Deny-by-default at every step:
 *   1. Unknown constraint id -> deny.
 *   2. Constraint not currently status:"review-ready" -> deny (covers "already decided" and
 *      "never was review-ready" alike, since a prior successful approve already moved the
 *      constraint's status away from review-ready — a replayed approve therefore denies here
 *      before even reaching the nonce check).
 *   3. No pending, nonce-matched, unexpired promotion record -> deny (covers missing record,
 *      wrong nonce, expired record, and an already-decided record).
 * Every denial is logged into the matching promotion record's audit_transitions (see
 * logDenial) before the Error is thrown, so a denied attempt is never silently invisible.
 * On success: "approved" calls constraint-store.js's promoteReviewReadyToActive (the one
 * function that performs that specific status write) and writes the result; "rejected" moves
 * the constraint straight to status:"retired" (never back to draft, never forward) — both
 * paths update the matched promotion record's status/decided_at/audit_transitions and persist
 * both stores.
 */
export async function decideConstraintPromotion(descartesPaths, constraintId, nonce, decision, options = {}) {
  if (decision !== "approved" && decision !== "rejected") {
    throw new Error(`decideConstraintPromotion: decision must be "approved" or "rejected", got: ${JSON.stringify(decision)}`);
  }

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const verb = decision === "approved" ? "approve" : "reject";

  const { constraints } = await loadConstraints(descartesPaths);
  const constraint = constraints.find((candidate) => candidate?.id === constraintId);
  const { promotions } = await loadPromotions(descartesPaths);

  if (!constraint) {
    await logDenial(descartesPaths, promotions, constraintId, nonce, "constraint_not_found", { now: nowIso, note: options.note });
    throw new Error(`Cannot ${verb} ${constraintId}: no such constraint.`);
  }
  if (constraint.status !== "review-ready") {
    await logDenial(descartesPaths, promotions, constraintId, nonce, "constraint_not_review_ready", { now: nowIso, note: options.note });
    throw new Error(`Cannot ${verb} ${constraintId}: status is "${constraint.status}", not "review-ready".`);
  }

  const match = matchPendingPromotion(promotions, constraintId, nonce, nowMs);
  if (!match) {
    const reason = denialReason(promotions, constraintId, nonce, nowMs);
    await logDenial(descartesPaths, promotions, constraintId, nonce, reason, { now: nowIso, note: options.note });
    throw new Error(
      `Cannot ${verb} ${constraintId}: promotion denied (${reason}). Run 'descartes learned review' to (re)issue a pending promotion.`,
    );
  }

  let updatedConstraints;
  if (decision === "approved") {
    const result = promoteReviewReadyToActive(constraints, constraintId, {
      now: nowIso,
      note: options.note ?? "approved via descartes learned approve",
    });
    if (!result.activated) {
      // Unreachable given the review-ready check above; fail closed rather than silently
      // marking the promotion decided if this constraint somehow could not be transitioned.
      await logDenial(descartesPaths, promotions, constraintId, nonce, "transition_failed", { now: nowIso, note: options.note });
      throw new Error(`Cannot approve ${constraintId}: transition failed.`);
    }
    updatedConstraints = result.constraints;
  } else {
    updatedConstraints = constraints.map((candidate) => {
      if (candidate.id !== constraintId) return candidate;
      return {
        ...candidate,
        status: "retired",
        promotion_history: [
          ...(candidate.promotion_history ?? []),
          {
            ts: nowIso,
            from: "review-ready",
            to: "retired",
            actor: "human-cli",
            note: options.note ?? "rejected via descartes learned reject",
          },
        ],
      };
    });
  }

  const updatedPromotions = promotions.map((record) => {
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

  await writeConstraints(descartesPaths, updatedConstraints);
  await writePromotions(descartesPaths, updatedPromotions);

  return {
    constraint: updatedConstraints.find((candidate) => candidate.id === constraintId),
    promotion: updatedPromotions.find((record) => record.id === match.id),
  };
}

// --- CLI: descartes learned review | approve | reject ---

function reviewUsage() {
  return `Usage:
  descartes learned review [--json]

Lists status:"review-ready" constraints for human inspection (fixtures, provenance, promotion
history) and mints a fresh pending promotion record (nonce + expiry) in
stateDir/authority/promotions.json for any review-ready constraint that doesn't already have a
valid one. The nonce shown here is required by 'descartes learned approve'/'reject'. Read-only
of constraint status — review never itself transitions a constraint.`;
}

function renderReviewEntry(entry) {
  return [
    `${entry.id} [${entry.family}] target=${entry.target} expected=${JSON.stringify(entry.expected)} confidence=${entry.confidence}`,
    `  nonce=${entry.promotion.nonce} expires=${entry.promotion.expiry}`,
    `  approve: descartes learned approve ${entry.id} --nonce ${entry.promotion.nonce}`,
    `  reject:  descartes learned reject ${entry.id} --nonce ${entry.promotion.nonce}`,
  ].join("\n");
}

export async function runLearnedReview(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(reviewUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned review argument: ${arg}\n\n${reviewUsage()}`);
    }
  }

  const now = runtime.now ?? Date.now();
  const { constraints } = await loadConstraints(descartesPaths);
  const reviewReady = constraints.filter((constraint) => constraint?.status === "review-ready");

  const entries = [];
  for (const constraint of reviewReady) {
    const { promotion } = await mintPendingPromotion(descartesPaths, constraint, { now, expiryMs: runtime.expiryMs });
    entries.push({
      id: constraint.id,
      family: constraint.family,
      target: constraint.target,
      expected: constraint.expected,
      confidence: constraint.confidence,
      provenance: constraint.provenance,
      fixtures: constraint.fixtures,
      promotion_history: constraint.promotion_history,
      promotion: { id: promotion.id, nonce: promotion.nonce, expiry: promotion.expiry, status: promotion.status },
    });
  }

  if (json) {
    output(JSON.stringify({ learned_review: { review_ready: entries } }, null, 2));
  } else if (entries.length === 0) {
    output("No review-ready constraints.");
  } else {
    output(entries.map(renderReviewEntry).join("\n"));
  }
  return { review_ready: entries };
}

function decisionUsage(name) {
  return `Usage:
  descartes learned ${name} <constraint-id> --nonce <nonce> [--note <text>] [--json]

Requires the exact nonce shown by 'descartes learned review' for that constraint. Deny-by-
default: fails closed (no constraint state change) if no pending promotion exists, the nonce
doesn't match, the promotion has expired, or the constraint is not status:"review-ready". No
LLM anywhere.`;
}

function parseDecisionArgs(args, name) {
  const [constraintId, ...rest] = args ?? [];
  if (!constraintId || constraintId === "--help" || constraintId === "-h") {
    return { help: true };
  }
  const options = { constraintId, nonce: undefined, note: undefined, json: false };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--nonce") {
      const value = rest[index + 1];
      if (!value) throw new Error(`--nonce requires a value\n\n${decisionUsage(name)}`);
      options.nonce = value;
      index += 1;
    } else if (arg === "--note") {
      const value = rest[index + 1];
      if (value === undefined) throw new Error(`--note requires a value\n\n${decisionUsage(name)}`);
      options.note = value;
      index += 1;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { help: true };
    } else {
      throw new Error(`Unexpected ${name} argument: ${arg}\n\n${decisionUsage(name)}`);
    }
  }
  return options;
}

export async function runLearnedApprove(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const parsed = parseDecisionArgs(args, "approve");
  if (parsed.help) {
    output(decisionUsage("approve"));
    return undefined;
  }
  if (!parsed.nonce) throw new Error(`approve requires --nonce <nonce> (shown by 'descartes learned review')\n\n${decisionUsage("approve")}`);

  const now = runtime.now ?? Date.now();
  const result = await decideConstraintPromotion(descartesPaths, parsed.constraintId, parsed.nonce, "approved", { now, note: parsed.note });

  if (parsed.json) output(JSON.stringify({ learned_approve: result }, null, 2));
  else output(`Approved ${result.constraint.id}: status is now "${result.constraint.status}".`);
  return result;
}

export async function runLearnedReject(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const parsed = parseDecisionArgs(args, "reject");
  if (parsed.help) {
    output(decisionUsage("reject"));
    return undefined;
  }
  if (!parsed.nonce) throw new Error(`reject requires --nonce <nonce> (shown by 'descartes learned review')\n\n${decisionUsage("reject")}`);

  const now = runtime.now ?? Date.now();
  const result = await decideConstraintPromotion(descartesPaths, parsed.constraintId, parsed.nonce, "rejected", { now, note: parsed.note });

  if (parsed.json) output(JSON.stringify({ learned_reject: result }, null, 2));
  else output(`Rejected ${result.constraint.id}: status is now "${result.constraint.status}".`);
  return result;
}
