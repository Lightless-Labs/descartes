// Shared, append-only, counts-only audit trail for the learned-artifact subsystem's self-audit
// records (S15 calibration report; S14 tuning-proposal mining/decisions, when built on top of
// this). See docs/plans/2026-07-14-compile-down-calibration.md §4.3.
//
// NEVER an active artifact: nothing in the daemon/alert pipeline reads this file to decide
// monitoring/alerting behavior — it exists purely as an append-only observability trail a human
// or agent can inspect later, mirroring shadow-violations.jsonl's/llm-decisions.jsonl's own
// "audit, not control" posture. `kind`-tagged so multiple slices can share one file without
// collision.
//
// Counts/enums/hashes ONLY (plan §1 point 6, "field-selection discipline at construction time"):
// this module never accepts or persists a raw diagnostics payload. `family_counts` keys are
// additionally routed through sanitizeIdentityString as defense-in-depth (the real control is
// that callers only ever construct family_counts from the closed rule_id-family set, plan §2.2).
//
// No LLM anywhere: this module never imports pi-harness.js or alert-intelligence.js.

import fs from "node:fs/promises";
import path from "node:path";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";

export const SCHEMA_VERSION = 1;

// Closed set: "calibration_report" is emitted by this slice (S15); "tuning_proposal_mined" /
// "tuning_decision" are reserved for S14 (compile-down) to share this same file/module without
// needing a second store. Emitting an unrecognized kind is a programmer error and throws (fail
// loud), not a corrupt-input case -- this is a write path, not a tolerant reader.
export const ARTIFACT_AUDIT_RECORD_KINDS = ["calibration_report", "tuning_proposal_mined", "tuning_decision"];

export function resolveArtifactAuditPaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, auditFile: path.join(dir, "artifact-audit.jsonl") };
}

async function ensureArtifactAuditDir(descartesPaths) {
  await fs.mkdir(resolveArtifactAuditPaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "ts") {
  const date = new Date(ts ?? new Date().toISOString());
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid artifact-audit record ${field}: ${ts}`);
  return date.toISOString();
}

// Defense-in-depth (plan §4.4 "Sanitized diagnostics" test): every family_counts KEY is routed
// through sanitizeIdentityString before it is ever written to disk. Legitimate rule_id-family
// strings (the closed set, plan §2.2) already satisfy sanitizeIdentityString's safe charset, so
// this is a no-op for real data; a raw-path/host-shaped key (which cannot arise from the real
// closed set, but could reach here via a malformed/hand-constructed record) is collapsed into a
// safe, mangled key rather than ever appearing verbatim.
function sanitizeFamilyCounts(familyCounts) {
  const safe = {};
  for (const [key, rawCount] of Object.entries(familyCounts ?? {})) {
    const count = Number.isFinite(rawCount) ? rawCount : 0;
    const safeKey = sanitizeIdentityString(key) ?? "redacted";
    safe[safeKey] = (safe[safeKey] ?? 0) + count;
  }
  return safe;
}

/**
 * Validates/normalizes a record before it is appended. Throws on an unrecognized `kind` (a
 * programmer error at a call site, not tolerated corrupt input -- this is the write path).
 */
export function normalizeArtifactAuditRecord(record) {
  if (!record || typeof record !== "object") throw new Error("Artifact-audit record must be an object");
  const kind = String(record.kind ?? "");
  if (!ARTIFACT_AUDIT_RECORD_KINDS.includes(kind)) {
    throw new Error(`Unsupported artifact-audit record kind: ${kind || "(missing)"}`);
  }
  const normalized = {
    ts: normalizeIso(record.ts),
    kind,
  };
  if (record.window && typeof record.window === "object" && !Array.isArray(record.window)) {
    normalized.window = {
      since: record.window.since ? normalizeIso(record.window.since, "window.since") : null,
      until: record.window.until ? normalizeIso(record.window.until, "window.until") : null,
    };
  }
  if (record.artifact_count !== undefined) {
    normalized.artifact_count = Number.isFinite(record.artifact_count) ? record.artifact_count : 0;
  }
  if (record.family_counts !== undefined) {
    normalized.family_counts = sanitizeFamilyCounts(record.family_counts);
  }
  normalized.schema_version = SCHEMA_VERSION;
  return normalized;
}

/**
 * Append-only write: ensure dir -> normalize (throw propagates -- a malformed record must never
 * silently vanish) -> single fs.appendFile. Mirrors shadow-store.js's/notification-delivery.js's
 * own JSONL append discipline (0o700 dir / 0o600 file).
 */
export async function appendArtifactAuditRecord(descartesPaths, record) {
  await ensureArtifactAuditDir(descartesPaths);
  const { auditFile } = resolveArtifactAuditPaths(descartesPaths);
  const normalized = normalizeArtifactAuditRecord(record);
  await fs.appendFile(auditFile, `${JSON.stringify(normalized)}\n`, { mode: 0o600 });
  return normalized;
}

/**
 * Tolerant read: missing file -> []; corrupt/unparseable lines are skipped, never thrown -- this
 * is an observability trail, never load-bearing for any live decision.
 */
export async function readArtifactAuditRecords(descartesPaths) {
  const { auditFile } = resolveArtifactAuditPaths(descartesPaths);
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
      // Ignore corrupt lines -- append-only observability trail, never load-bearing.
    }
  }
  return records;
}
