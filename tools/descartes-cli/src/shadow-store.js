import fs from "node:fs/promises";
import path from "node:path";
import {
  buildConstraintTarget,
  loadConstraints,
  promoteDraftsToShadow,
  promoteShadowToReviewReady,
  writeConstraints,
  DEFAULT_SOAK_DAYS,
} from "./constraint-store.js";
import { evaluateShadowConstraints } from "./constraint-eval.js";
import { readFactPoints } from "./fact-store.js";

// Shadow evaluation is structurally separate from real alerting — not a flag, a different
// code path (plan §5). Nothing in this module ever imports alert-store.js, never calls
// alertId()/buildViolationCandidate/applyAlertCandidates, and never writes to alerts.json.
// A shadow-fired constraint is observable only via shadow-violations.jsonl.

export const DEFAULT_SHADOW_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — spans several soak windows
export const DEFAULT_SHADOW_MAX_BYTES = 5 * 1024 * 1024; // 5MB, matches fact-store.js's default

export function resolveShadowStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, shadowViolationsFile: path.join(dir, "shadow-violations.jsonl") };
}

async function ensureShadowDir(descartesPaths) {
  await fs.mkdir(resolveShadowStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function normalizeTimestamp(ts = new Date().toISOString()) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid shadow record timestamp: ${ts}`);
  return date.toISOString();
}

/**
 * Shadow-violation record schema (plan §5, matches evaluateShadowConstraints' output shape
 * exactly): { ts, constraint_id, family, target, expected, actual, fired }. Required:
 * constraint_id (non-empty string) and fired (boolean) — everything else is defensively
 * coerced/passed through, mirroring fact-store.js's normalizeFactPoint conventions.
 */
export function normalizeShadowRecord(record) {
  if (!record || typeof record !== "object") throw new Error("Shadow record must be an object");
  const constraintId = String(record.constraint_id ?? "").trim();
  if (!constraintId) throw new Error("Shadow record requires a non-empty constraint_id");
  if (typeof record.fired !== "boolean") throw new Error("Shadow record requires a boolean fired");

  return {
    ts: normalizeTimestamp(record.ts),
    constraint_id: constraintId,
    family: record.family !== undefined ? String(record.family) : undefined,
    target: record.target !== undefined ? String(record.target) : undefined,
    expected: record.expected,
    actual: record.actual,
    fired: record.fired,
  };
}

// Mirrors fact-store.js's/history-store.js's readJsonLines exactly (duplicated rather than
// imported — each store module here is deliberately self-contained, matching fact-store.js's
// own precedent of not importing history-store.js's internals).
async function readJsonLines(file) {
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { records: [], corrupt_count: 0 };
    throw error;
  }

  const records = [];
  let corruptCount = 0;
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      corruptCount += 1;
    }
  }
  return { records, corrupt_count: corruptCount };
}

function encodeJsonLine(record) {
  return `${JSON.stringify(record)}\n`;
}

/**
 * Retention rewrite uses tmp+rename (atomic), mirroring fact-store.js's deliberate deviation
 * from history-store.js's direct fs.writeFile — shadow-violations.jsonl feeds promotion
 * decisions (checkShadowSoak), where partial-write corruption is more consequential than a
 * dropped record.
 */
export async function enforceShadowRetention(descartesPaths, options = {}) {
  const storePaths = resolveShadowStorePaths(descartesPaths);
  const retentionMs = options.retentionMs ?? DEFAULT_SHADOW_RETENTION_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_SHADOW_MAX_BYTES;
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const cutoffMs = nowMs - retentionMs;
  const { records, corrupt_count: corruptBefore } = await readJsonLines(storePaths.shadowViolationsFile);

  const candidates = records
    .map((record) => ({ record, tsMs: new Date(record.ts).getTime() }))
    .filter(({ tsMs }) => Number.isFinite(tsMs) && tsMs >= cutoffMs)
    .sort((left, right) => left.tsMs - right.tsMs);

  const keptReversed = [];
  let usedBytes = 0;
  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const line = encodeJsonLine(candidates[index].record);
    const size = Buffer.byteLength(line);
    if (keptReversed.length > 0 && usedBytes + size > maxBytes) break;
    if (size > maxBytes && keptReversed.length === 0) break;
    keptReversed.push(line);
    usedBytes += size;
  }

  const keptLines = keptReversed.reverse();
  await ensureShadowDir(descartesPaths);
  const tmpFile = `${storePaths.shadowViolationsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, keptLines.join(""), { mode: 0o600 });
  await fs.rename(tmpFile, storePaths.shadowViolationsFile);
  return {
    kept_count: keptLines.length,
    dropped_count: records.length - keptLines.length,
    corrupt_dropped_count: corruptBefore,
    bytes: usedBytes,
  };
}

/**
 * Append-only JSONL write (mirrors fact-store.js's appendFactPoints): ensure dir -> normalize
 * every record (throw propagates, no per-record catch) -> single fs.appendFile -> enforce
 * retention. Appends every result the caller passes (fired and non-fired) — see
 * evaluateAndLogShadowConstraints below for why both are logged.
 */
export async function appendShadowRecords(descartesPaths, records, options = {}) {
  await ensureShadowDir(descartesPaths);
  const storePaths = resolveShadowStorePaths(descartesPaths);
  const normalized = (records ?? []).map((record) => normalizeShadowRecord(record));
  if (normalized.length > 0) {
    await fs.appendFile(storePaths.shadowViolationsFile, normalized.map(encodeJsonLine).join(""), { mode: 0o600 });
  }
  const retention = await enforceShadowRetention(descartesPaths, options);
  return { written_count: normalized.length, retention };
}

/**
 * Mirrors fact-store.js's readFactPoints: re-validates each record through
 * normalizeShadowRecord and drops (doesn't throw) any that fail — corrupt lines are counted
 * separately from dropped-invalid-schema records.
 */
export async function readShadowRecords(descartesPaths, options = {}) {
  const storePaths = resolveShadowStorePaths(descartesPaths);
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const sinceMs = options.windowMs !== undefined ? nowMs - options.windowMs : undefined;
  const { records, corrupt_count } = await readJsonLines(storePaths.shadowViolationsFile);
  const normalized = records
    .map((record) => {
      try {
        return normalizeShadowRecord(record);
      } catch {
        return undefined;
      }
    })
    .filter(Boolean)
    .filter((record) => sinceMs === undefined || new Date(record.ts).getTime() >= sinceMs)
    .sort((left, right) => new Date(left.ts).getTime() - new Date(right.ts).getTime());
  return { records: normalized, corrupt_count };
}

// Closed, minimal map from fact_name -> the attribute that constitutes the mined/shadow-
// evaluated "value" for that family. Intentionally duplicated rather than imported from
// constraint-miner.js (out of this slice's blast radius) — mirrors fact-store.js's existing
// precedent of duplicating a small piece of another store's logic rather than reaching into
// it. Limited to the two fact_names S6c's miner currently produces drafts for.
const SHADOW_KEY_ATTRIBUTE_BY_FACT_NAME = {
  "service.presence": "running",
  "network.listening_port.owner": "owner",
};

function isDegradedFactPoint(point) {
  return point?.attributes?.owner_known === "false" || point?.confidence === 0;
}

/**
 * Builds a `target -> current value` lookup from a fact-history window, reconstructing each
 * fact point's target via constraint-store.js's shared buildConstraintTarget — the same
 * function constraint-miner.js's buildMinedConstraint uses — so a shadow/active constraint's
 * `target` field always matches (Codex review finding #8: the two must never diverge or two
 * distinct long entity_keys can collide onto the same target). Degraded observations
 * (owner_known:"false"/confidence:0) are excluded entirely — never used as evidence, mirroring
 * the miner's own degrade-don't-fabricate exclusion. When multiple fact points map to the same
 * target, the most recent (by ts) wins.
 *
 * Exported additively (Slice S-live-1): daemon.js's active-constraint evaluation reuses this
 * exact function so ACTIVE and SHADOW evaluation reconstruct constraint targets identically
 * (same degraded-observation exclusion, same latest-wins tie-break) — never duplicated.
 */
export function buildShadowFactLookup(factPoints) {
  const latestByTarget = new Map();
  for (const point of factPoints ?? []) {
    if (!point || isDegradedFactPoint(point)) continue;
    const keyAttribute = SHADOW_KEY_ATTRIBUTE_BY_FACT_NAME[point.fact_name];
    if (!keyAttribute) continue;
    const target = buildConstraintTarget(point.fact_name, point.entity_key);
    if (!target) continue;
    const value = point.attributes?.[keyAttribute];
    if (value === undefined) continue;
    const tsMs = new Date(point.ts).getTime();
    if (!Number.isFinite(tsMs)) continue;
    const existing = latestByTarget.get(target);
    if (!existing || tsMs >= existing.tsMs) latestByTarget.set(target, { tsMs, value });
  }
  return (target) => latestByTarget.get(target)?.value;
}

/**
 * Daemon-wired evaluation + logging step (plan §5, must-fix §0.1): reads constraints.json,
 * filters status:"shadow", evaluates against the accumulated fact-history, and appends every
 * result (fired and non-fired) to shadow-violations.jsonl via appendShadowRecords. This is the
 * ONLY thing this function does — it never writes constraints.json, never touches
 * alerts.json/notifications, and never makes a promotion decision (that's `runLearnedSoak`
 * below, CLI-only). A cheap no-op whenever no constraint is status:"shadow" (true for the
 * entire lifetime of this plan until a draft first gets promoted). Called from
 * runDaemonIteration's existing S6a structural-tick block: same structuralDue gate, same
 * loadLearnedConfig(...).enabled kill switch, same wall-clock cadence — no new timer, no new
 * checkpoint.
 */
export async function evaluateAndLogShadowConstraints(descartesPaths, options = {}) {
  const loadConstraintsFn = options.loadConstraints ?? loadConstraints;
  const readFacts = options.readFactPoints ?? readFactPoints;

  const { constraints } = await loadConstraintsFn(descartesPaths);
  const shadowConstraints = constraints.filter((constraint) => constraint?.status === "shadow");
  if (shadowConstraints.length === 0) {
    return { evaluated_count: 0, fired_count: 0, appended_count: 0 };
  }

  const { points } = await readFacts(descartesPaths, { windowMs: options.factWindowMs, now: options.now });
  const factLookup = buildShadowFactLookup(points);
  const ts = options.ts ?? (options.now !== undefined ? new Date(options.now).toISOString() : new Date().toISOString());
  const records = evaluateShadowConstraints(shadowConstraints, factLookup, { ts });

  if (records.length === 0) {
    return { evaluated_count: shadowConstraints.length, fired_count: 0, appended_count: 0 };
  }

  const appendRecords = options.appendShadowRecords ?? appendShadowRecords;
  const append = await appendRecords(descartesPaths, records, {
    now: options.now,
    retentionMs: options.retentionMs,
    maxBytes: options.maxBytes,
  });

  return {
    evaluated_count: shadowConstraints.length,
    fired_count: records.filter((record) => record.fired).length,
    appended_count: records.length,
    retention: append.retention,
  };
}

function soakUsage() {
  return `Usage:
  descartes learned soak [--json]

Makes deterministic promotion DECISIONS only, off of data already logged by the daemon-wired
evaluateAndLogShadowConstraints step — this command never evaluates constraints itself:
  1. Enrolls eligible status:"draft" constraints into status:"shadow" (minimum-fixture bar).
  2. Promotes status:"shadow" constraints into status:"review-ready" once they've completed a
     clean soak window (zero fired shadow-violations.jsonl records, full daily observation
     coverage, >= soakDays elapsed).
review-ready is the terminal state this command ever produces — review-ready->active is a
separate, strictly human-gated command. No LLM anywhere.`;
}

function renderSoakSummary(summary) {
  return `Soak: ${summary.enrolled_to_shadow} draft(s) enrolled into shadow, ` +
    `${summary.promoted_to_review_ready} shadow constraint(s) promoted to review-ready ` +
    `(${summary.total_constraints} constraint(s) total).`;
}

/**
 * `descartes learned soak` — deterministic, CLI-only (plan §5/§8.3): draft->shadow enrollment
 * and shadow->review-ready promotion. Reads constraints.json and shadow-violations.jsonl
 * (populated by the daemon-wired evaluateAndLogShadowConstraints step, or empty if
 * learned.enabled is off / no structural tick has run yet — soak degrades to "nothing
 * eligible" in that case). Never evaluates constraints itself, never promotes past
 * review-ready (that terminal-status invariant is the whole point of this slice).
 */
export async function runLearnedSoak(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(soakUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned soak argument: ${arg}\n\n${soakUsage()}`);
    }
  }

  const now = runtime.now ?? Date.now();
  const soakDays = Number.isFinite(runtime.soakDays) ? runtime.soakDays : DEFAULT_SOAK_DAYS;

  const { constraints: existing } = await loadConstraints(descartesPaths);
  const afterShadowEnrollment = promoteDraftsToShadow(existing, { now });
  const enrolledToShadow = afterShadowEnrollment.filter(
    (constraint, index) => constraint.status === "shadow" && existing[index]?.status === "draft",
  ).length;

  const { records: shadowRecords } = await readShadowRecords(descartesPaths, { now: runtime.now });
  const afterReviewReady = promoteShadowToReviewReady(afterShadowEnrollment, shadowRecords, { soakDays, now });
  const promotedToReviewReady = afterReviewReady.filter(
    (constraint, index) => constraint.status === "review-ready" && afterShadowEnrollment[index]?.status === "shadow",
  ).length;

  await writeConstraints(descartesPaths, afterReviewReady);

  const summary = {
    enrolled_to_shadow: enrolledToShadow,
    promoted_to_review_ready: promotedToReviewReady,
    total_constraints: afterReviewReady.length,
  };
  if (json) output(JSON.stringify({ learned_soak: summary }, null, 2));
  else output(renderSoakSummary(summary));
  return summary;
}
