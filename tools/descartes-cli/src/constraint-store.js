import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { MAX_STRING_LENGTH, sanitizeIdentityString } from "./diagnostics-sanitizer.js";

export const SCHEMA_VERSION = 1;
export const CONSTRAINT_STATUSES = ["draft", "shadow", "review-ready", "active", "retired"];

// Fixed-length hex digest suffix length for buildConstraintTarget (below) — matches
// constraint-miner.js's own minedId()/alert-store.js's alertId() truncated-sha256-hex
// convention, so the suffix always satisfies diagnostics-sanitizer.js's isFixedLengthHexHash.
const TARGET_HASH_LENGTH = 16;

/**
 * Builds the single canonical `target` string for a (fact_name, entity_key) pair. This is the
 * ONLY place that construction happens — constraint-miner.js's buildMinedConstraint and
 * shadow-store.js's buildShadowFactLookup both call this so the two can never diverge (Codex
 * review finding #8, target-truncation collision).
 *
 * The old approach sanitized+truncated entity_key to 64 chars, then sanitized+truncated
 * `${fact_name}.${sanitizedEntityKey}` to 64 chars AGAIN: two distinct entity_keys sharing an
 * identical 64-char sanitized prefix (long systemd unit paths, IPv6 socket keys) collided onto
 * the exact same target, so "latest wins" evaluation silently mixed up two constraints. Here,
 * a fixed-length hex digest of the FULL, UNTRUNCATED `fact_name\0entity_key` pair is always
 * appended as a suffix — regardless of how much of the human-readable prefix truncation ends up
 * discarding, two distinct entities always hash to two distinct suffixes, so they can never
 * collide onto the same target.
 *
 * Returns `undefined` (never a raw/partial value) when nothing safe survives sanitization,
 * mirroring sanitizeIdentityString's own "degrade, never fabricate" contract.
 */
export function buildConstraintTarget(factName, entityKey) {
  const rawFactName = String(factName ?? "");
  const rawEntityKey = String(entityKey ?? "");

  const sanitizedEntityKey = sanitizeIdentityString(rawEntityKey);
  if (!sanitizedEntityKey) return undefined; // entirely-unsafe identity — drop, never fabricate

  const digest = crypto.createHash("sha256").update(`${rawFactName}\0${rawEntityKey}`).digest("hex").slice(0, TARGET_HASH_LENGTH);
  // Reserve room for ".{digest}" so the digest suffix itself is never truncated away — all
  // truncation lands on the human-readable prefix instead, exactly as before, but two distinct
  // entities can no longer collide even when that prefix collides.
  const prefixMaxLength = Math.max(1, MAX_STRING_LENGTH - digest.length - 1);
  const humanReadable = sanitizeIdentityString(`${rawFactName}.${sanitizedEntityKey}`, { maxLength: prefixMaxLength });
  if (!humanReadable) return undefined; // defensive; should not happen given the pieces above are already safe

  return `${humanReadable}.${digest}`;
}

export function resolveConstraintStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return {
    dir,
    constraintsFile: path.join(dir, "constraints.json"),
    configFile: path.join(descartesPaths.configDir, "learned.json"),
  };
}

async function ensureConstraintDir(descartesPaths) {
  await fs.mkdir(resolveConstraintStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid constraint ${field}: ${ts}`);
  return date.toISOString();
}

/**
 * Validates a constraint-shaped LearnedArtifact record (plan §3.3, constraint-only for Slice 1).
 * Throws a descriptive Error on the first invalid/missing required field; returns true otherwise.
 */
export function validateConstraint(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("Constraint record must be an object");
  }

  const id = String(record.id ?? "").trim();
  if (!id) throw new Error("Constraint record requires a non-empty id");

  if (record.kind !== "constraint") {
    throw new Error(`Constraint record kind must be "constraint", got: ${JSON.stringify(record.kind)}`);
  }

  const family = String(record.family ?? "").trim();
  if (!family) throw new Error("Constraint record requires a non-empty family");

  const target = String(record.target ?? "").trim();
  if (!target) throw new Error("Constraint record requires a non-empty target");

  if (record.expected === undefined || record.expected === null) {
    throw new Error("Constraint record requires expected");
  }

  if (!CONSTRAINT_STATUSES.includes(record.status)) {
    throw new Error(`Constraint record status must be one of ${CONSTRAINT_STATUSES.join(", ")}, got: ${JSON.stringify(record.status)}`);
  }

  const confidence = Number(record.confidence);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error(`Constraint record confidence must be a number in [0, 1], got: ${JSON.stringify(record.confidence)}`);
  }

  if (!Number.isFinite(Number(record.schema_version))) {
    throw new Error("Constraint record requires a numeric schema_version");
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
 * Loads the constraint store, tolerating a corrupt or malformed file (mirroring history-store.js)
 * rather than throwing. Individual invalid records are dropped silently (they never validated in
 * the first place); a corrupt or unparseable file increments corrupt_count and yields an empty set.
 */
export async function loadConstraints(descartesPaths) {
  const { constraintsFile } = resolveConstraintStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(constraintsFile);
  if (missing) return { constraints: [], corrupt_count: 0 };
  if (corrupt) return { constraints: [], corrupt_count: 1 };

  const rawConstraints = Array.isArray(parsed) ? parsed : parsed?.constraints;
  if (!Array.isArray(rawConstraints)) return { constraints: [], corrupt_count: 1 };

  const constraints = [];
  for (const record of rawConstraints) {
    try {
      validateConstraint(record);
      constraints.push(record);
    } catch {
      // Silently drop invalid individual records, mirroring history-store.js's
      // per-point tolerance; corrupt_count tracks whole-file parse failures only.
    }
  }
  return { constraints, corrupt_count: 0 };
}

/**
 * Atomically writes the constraint store (tmp+rename, 0o600 file / 0o700 dir), mirroring
 * writeAlertRecords. Every record is validated before being persisted.
 */
export async function writeConstraints(descartesPaths, constraints) {
  await ensureConstraintDir(descartesPaths);
  const { constraintsFile } = resolveConstraintStorePaths(descartesPaths);
  const normalized = constraints.map((record) => {
    validateConstraint(record);
    return record;
  });
  const payload = JSON.stringify({ schema_version: SCHEMA_VERSION, constraints: normalized }, null, 2);
  const tmpFile = `${constraintsFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, payload, { mode: 0o600 });
  await fs.rename(tmpFile, constraintsFile);
  return normalized;
}

export function normalizeLearnedConfig(config = {}) {
  return {
    enabled: config.enabled === true,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
  };
}

/**
 * Reads the deterministic-emission enablement switch from configDir/learned.json.
 * Defaults to { enabled: false } when the file is absent, mirroring
 * readAlertIntelligenceConfig's ENOENT-defaults-to-disabled behavior.
 */
export async function loadLearnedConfig(descartesPaths) {
  const { configFile } = resolveConstraintStorePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeLearnedConfig();
    throw error;
  }
  try {
    return normalizeLearnedConfig(JSON.parse(contents));
  } catch {
    // Malformed JSON: fail CLOSED to the disabled default rather than throwing out of a daemon
    // iteration (Codex review minor finding) — mirrors loadConstraints()'s own corrupt-file
    // tolerance above. `corrupt: true` is an additive marker only; callers that only read
    // `.enabled` (daemon.js) are unaffected.
    return { ...normalizeLearnedConfig(), corrupt: true };
  }
}

export async function writeLearnedConfig(descartesPaths, config, options = {}) {
  const { configFile } = resolveConstraintStorePaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeLearnedConfig({ ...config, updated_at: options.now ?? new Date().toISOString() });
  const tmpFile = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, configFile);
  return normalized;
}

// --- CLI: descartes learned enable | disable | status ---
//
// The configDir/learned.json { enabled } kill switch is operationally load-bearing (it gates
// ALL automatic/background learned-constraint work: shadow evaluation logging, active-constraint
// alerting) but previously had no dedicated command — users had to hand-edit the JSON file
// directly (Codex review minor finding). Additive only: loadLearnedConfig/writeLearnedConfig
// above are unchanged; this just gives them a CLI face, mirroring alerts.js's
// `alerts intelligence status|enable|disable` shape.

function learnedConfigUsage() {
  return `Usage:
  descartes learned enable [--json]
  descartes learned disable [--json]
  descartes learned status [--json]

Flips or reports configDir/learned.json's { enabled } kill switch, which gates ALL automatic/
background learned-constraint work (shadow evaluation logging, active-constraint real alerting).
'enable'/'disable' are idempotent — flipping to the state it's already in is a no-op status-wise
(still refreshes updated_at) and always prints a confirmation.`;
}

function renderLearnedConfigStatus(config, configFile) {
  const lines = [`Learned emission: ${config.enabled ? "enabled" : "disabled"}`];
  lines.push(`Config path: ${configFile}`);
  if (config.updated_at) lines.push(`Last updated: ${config.updated_at}`);
  return lines.join("\n");
}

/**
 * Shared implementation for the `descartes learned enable|disable|status` subcommands
 * (dispatched from index.js). `enable`/`disable` write configDir/learned.json's `enabled` field
 * idempotently via writeLearnedConfig; `status` is read-only via loadLearnedConfig. Always
 * prints a confirmation/summary and returns `{ ...config, config_path }` for JSON/programmatic
 * callers.
 */
export async function runLearnedConfigCommand(descartesPaths, subcommand, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args ?? []) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      output(learnedConfigUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected learned ${subcommand} argument: ${arg}\n\n${learnedConfigUsage()}`);
    }
  }

  const { configFile } = resolveConstraintStorePaths(descartesPaths);
  let config;
  if (subcommand === "enable") {
    config = await writeLearnedConfig(descartesPaths, { enabled: true }, { now: runtime.now });
  } else if (subcommand === "disable") {
    config = await writeLearnedConfig(descartesPaths, { enabled: false }, { now: runtime.now });
  } else if (subcommand === "status") {
    config = await loadLearnedConfig(descartesPaths);
  } else {
    throw new Error(`Unsupported learned command: ${subcommand}\n\n${learnedConfigUsage()}`);
  }

  const result = { ...config, config_path: configFile };
  if (json) output(JSON.stringify({ learned_config: result }, null, 2));
  else output(renderLearnedConfigStatus(config, configFile));
  return result;
}

// --- Slice S7a, additive: draft->shadow / shadow->review-ready status-transition helpers ---
// Pure, no I/O — deterministic promotion decisions only. "review-ready" is the terminal
// status these functions ever produce; review-ready->active is a strictly human-gated later
// slice and is out of scope here (neither function below ever writes status:"active").

const DAY_MS = 24 * 60 * 60 * 1000;

// "Minimum-fixture bar enforced at promotion" (roadmap wording, plan §5): a schema-level gate
// any constraint source (hand-authored or mined) must clear before it's shadow-eligible. S6c's
// miner already emits exactly 2 fixtures per draft by construction, so in practice every mined
// draft is immediately eligible.
export const MIN_FIXTURE_COUNT = 2;

// Soak-window length (days) a shadow constraint must accrue zero-fire, full-daily-coverage
// observations over before it becomes shadow->review-ready eligible.
export const DEFAULT_SOAK_DAYS = 7;

/**
 * Deterministic draft -> shadow gate. A draft becomes shadow-eligible once it carries at
 * least MIN_FIXTURE_COUNT fixtures; below-threshold drafts and every non-draft status pass
 * through completely unchanged (idempotent no-op on an already-shadow/review-ready/active/
 * retired constraint).
 */
export function promoteDraftsToShadow(constraints, options = {}) {
  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return (constraints ?? []).map((constraint) => {
    if (!constraint || constraint.status !== "draft") return constraint;
    const fixtureCount = Array.isArray(constraint.fixtures) ? constraint.fixtures.length : 0;
    if (fixtureCount < MIN_FIXTURE_COUNT) return constraint;
    return {
      ...constraint,
      status: "shadow",
      promotion_history: [
        ...(constraint.promotion_history ?? []),
        { ts, from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" },
      ],
    };
  });
}

/**
 * True iff `constraint` (status:"shadow") has completed a clean soak window: it has been in
 * status:"shadow" for >= soakDays (per its own promotion_history "shadow" entry timestamp),
 * zero `shadowRecords` with `fired:true` exist for it within that window, AND at least one
 * (non-fired) observation exists per day of the window — proving the constraint was actually
 * being checked daily, not silently idle ("nobody looked" must not count as "nothing
 * happened", plan §0.1/§5 must-fix). Pure: `shadowRecords` is caller-supplied data (typically
 * shadow-store.js's readShadowRecords output) — this function performs no I/O itself.
 */
export function checkShadowSoak(constraint, shadowRecords, options = {}) {
  if (!constraint || constraint.status !== "shadow") return false;
  // Soak windows are whole days (daily coverage buckets), so normalize to a positive integer
  // up front — otherwise a fractional soakDays would size the window/buckets off the raw value
  // while requiredDays floored it, an off-by-one in the promotion gate.
  const soakDays = Math.max(1, Math.floor(Number.isFinite(options.soakDays) ? options.soakDays : DEFAULT_SOAK_DAYS));
  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();

  const shadowEntry = [...(constraint.promotion_history ?? [])].reverse().find((entry) => entry?.to === "shadow");
  if (!shadowEntry) return false;
  const shadowSinceMs = new Date(shadowEntry.ts).getTime();
  if (!Number.isFinite(shadowSinceMs)) return false;

  const soakWindowMs = soakDays * DAY_MS;
  if (nowMs - shadowSinceMs < soakWindowMs) return false;

  // Fired-record check spans the ENTIRE lifetime since shadow enrollment (shadowSince -> now),
  // not just the first fixed soak window (Codex review finding #4): a constraint that stays
  // clean for the first soakDays but then fires on, say, day 8 must still be blocked from
  // promotion when `learned soak` finally runs on day 10 — one fire leaves it shadow
  // indefinitely, regardless of when it happened relative to the fixed window.
  const sinceEnrollment = (shadowRecords ?? [])
    .filter((record) => record?.constraint_id === constraint.id)
    .filter((record) => {
      const tsMs = new Date(record.ts).getTime();
      return Number.isFinite(tsMs) && tsMs >= shadowSinceMs && tsMs <= nowMs;
    });

  if (sinceEnrollment.some((record) => record.fired === true)) return false;

  // Daily-coverage ("was it actually checked every day") is still evaluated only over the
  // fixed first soak window — that's the qualifying window a constraint must prove it was
  // observed daily within, not its entire (potentially much longer) shadow lifetime.
  const inWindow = sinceEnrollment.filter((record) => {
    const tsMs = new Date(record.ts).getTime();
    return tsMs < shadowSinceMs + soakWindowMs;
  });

  const coveredDays = new Set();
  for (const record of inWindow) {
    const tsMs = new Date(record.ts).getTime();
    const dayIndex = Math.floor((tsMs - shadowSinceMs) / DAY_MS);
    if (dayIndex >= 0 && dayIndex < soakDays) coveredDays.add(dayIndex);
  }
  const requiredDays = Math.floor(soakDays);
  for (let day = 0; day < requiredDays; day += 1) {
    if (!coveredDays.has(day)) return false;
  }

  return true;
}

/**
 * Deterministic shadow -> review-ready gate. Flips every status:"shadow" constraint that
 * passes checkShadowSoak to "review-ready"; a constraint that has fired even once (or lacks
 * full daily coverage, or hasn't soaked long enough) stays "shadow" indefinitely — inspectable
 * and unchanged, never silently reset/retried and never skipped straight to review-ready or
 * active. Pure, no I/O.
 */
export function promoteShadowToReviewReady(constraints, shadowRecords, options = {}) {
  // Soak windows are whole days (daily coverage buckets), so normalize to a positive integer
  // up front — otherwise a fractional soakDays would size the window/buckets off the raw value
  // while requiredDays floored it, an off-by-one in the promotion gate.
  const soakDays = Math.max(1, Math.floor(Number.isFinite(options.soakDays) ? options.soakDays : DEFAULT_SOAK_DAYS));
  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  return (constraints ?? []).map((constraint) => {
    if (!constraint || constraint.status !== "shadow") return constraint;
    if (!checkShadowSoak(constraint, shadowRecords, { soakDays, now: options.now })) return constraint;
    return {
      ...constraint,
      status: "review-ready",
      promotion_history: [
        ...(constraint.promotion_history ?? []),
        { ts, from: "shadow", to: "review-ready", actor: "deterministic-gate", note: `clean soak window (${soakDays}d, zero fires, full daily coverage)` },
      ],
    };
  });
}

const SEED_TS = "2026-07-09T00:00:00.000Z";

/**
 * Hand-authored, status:"active" seed constraints (plan §8 Slice 1). No mining — these
 * encode invariants already true of the shipped substrate, as fixtures/documentation of the
 * schema shape future miners will produce.
 */
export const SEED_CONSTRAINTS = [
  {
    id: "constraint.daemon.interval_ms.min",
    kind: "constraint",
    family: "daemon-config",
    target: "daemon.profile.interval_ms",
    expected: { comparator: "gte", value: 1000 },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: SEED_TS },
    fixtures: [
      { input: { interval_ms: 1000 }, expect_match: true },
      { input: { interval_ms: 60_000 }, expect_match: true },
      { input: { interval_ms: 500 }, expect_match: false },
    ],
    promotion_history: [{ ts: SEED_TS, from: "draft", to: "active", actor: "human-cli", note: "hand-authored Slice 1 seed" }],
    first_observed: SEED_TS,
    last_verified: SEED_TS,
    sensitivity: "operational",
    schema_version: SCHEMA_VERSION,
  },
  {
    id: "constraint.paths.state_dir.xdg_root",
    kind: "constraint",
    family: "path-invariant",
    target: "paths.stateDir",
    expected: { pattern: "ends_with:/descartes" },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: SEED_TS },
    fixtures: [
      { input: { stateDir: "/home/alice/.local/state/descartes" }, expect_match: true },
      { input: { stateDir: "/home/alice/.local/state" }, expect_match: false },
    ],
    promotion_history: [{ ts: SEED_TS, from: "draft", to: "active", actor: "human-cli", note: "hand-authored Slice 1 seed" }],
    first_observed: SEED_TS,
    last_verified: SEED_TS,
    sensitivity: "operational",
    schema_version: SCHEMA_VERSION,
  },
  {
    id: "constraint.paths.config_dir.xdg_root",
    kind: "constraint",
    family: "path-invariant",
    target: "paths.configDir",
    expected: { pattern: "ends_with:/descartes" },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: SEED_TS },
    fixtures: [
      { input: { configDir: "/home/alice/.config/descartes" }, expect_match: true },
      { input: { configDir: "/home/alice/.config" }, expect_match: false },
    ],
    promotion_history: [{ ts: SEED_TS, from: "draft", to: "active", actor: "human-cli", note: "hand-authored Slice 1 seed" }],
    first_observed: SEED_TS,
    last_verified: SEED_TS,
    sensitivity: "operational",
    schema_version: SCHEMA_VERSION,
  },
  {
    id: "constraint.alert.cooldown_ms.min",
    kind: "constraint",
    family: "alert-config",
    target: "alert-store.DEFAULT_ALERT_COOLDOWN_MS",
    expected: { comparator: "gte", value: 60_000 },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: SEED_TS },
    fixtures: [
      { input: { cooldown_ms: 15 * 60 * 1000 }, expect_match: true },
      { input: { cooldown_ms: 1000 }, expect_match: false },
    ],
    promotion_history: [{ ts: SEED_TS, from: "draft", to: "active", actor: "human-cli", note: "hand-authored Slice 1 seed" }],
    first_observed: SEED_TS,
    last_verified: SEED_TS,
    sensitivity: "operational",
    schema_version: SCHEMA_VERSION,
  },
];

// --- Slice S7b, additive: the ONLY code path that ever sets a mined/reviewed constraint to
// status:"active" (SEED_CONSTRAINTS above are hand-authored static data, not a code path). Pure,
// no I/O. This function is reachable ONLY through promotion-store.js's decideConstraintPromotion,
// itself only invoked by the human-gated `descartes learned approve` CLI command — never by
// soak/mine/daemon/shadow (see the S7a doc comments above: promoteDraftsToShadow and
// promoteShadowToReviewReady both stop at "review-ready" by design). Fail-closed by
// construction: a constraint is left completely untouched unless it matches the given id AND is
// currently status:"review-ready" — never activates a draft/shadow/already-active/retired
// constraint, and never activates any constraint other than the one named by id.

/**
 * Flips exactly one review-ready constraint (matched by id) to status:"active", appending a
 * promotion_history entry. Every other constraint in the array (including one with a matching
 * id but a different status) passes through unchanged. Returns { constraints, activated } so
 * the caller (promotion-store.js) can distinguish "transitioned" from "fail-closed no-op"
 * without re-scanning the result.
 */
export function promoteReviewReadyToActive(constraints, constraintId, options = {}) {
  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const note = options.note ?? "human-approved via descartes learned approve";
  let activated = false;
  const updated = (constraints ?? []).map((constraint) => {
    if (!constraint || constraint.id !== constraintId || constraint.status !== "review-ready") return constraint;
    activated = true;
    return {
      ...constraint,
      status: "active",
      promotion_history: [
        ...(constraint.promotion_history ?? []),
        { ts, from: "review-ready", to: "active", actor: "human-cli", note },
      ],
    };
  });
  return { constraints: updated, activated };
}

// --- S14 (outcome-informed compile-down), additive: the ONLY two functions in the entire
// codebase that can ever change an already-ACTIVE constraint's status-to-retired or `expected`
// value. Both are reachable ONLY through tuning-authority.js's decideTuningApproval "approved"
// branch, itself only invoked by the human-gated `descartes learned tuning approve` CLI command
// -- never by the miner, never by promoteTuningDraftsToReviewReady, never by any CLI `list`/
// `review` command (see docs/plans/2026-07-14-compile-down-calibration.md §5.7/§6.2). Both throw
// (rather than returning an { activated: false } sentinel like promoteReviewReadyToActive above)
// on a precondition failure -- the caller (tuning-authority.js) treats a thrown error as "the
// whole approval attempt fails closed, no partial write of any kind", which is the correct
// posture here since there is no "unreachable given an upstream check" analogue: the target
// constraint's OWN status can independently have changed since the candidate was mined (e.g. a
// concurrent manual retire), so both functions defend their own precondition at write time.

/**
 * active -> retired. Disjoint precondition from promotion-store.js's existing reject path
 * (review-ready -> retired, for a constraint never promoted) -- these are two independent
 * retirement paths for two disjoint lifecycle stages, not duplicate logic. Throws unless the
 * matched record has status === "active"; every other constraint in the array (including one
 * with a matching id but a different status) passes through unchanged.
 */
export function retireActiveConstraint(constraints, constraintId, options = {}) {
  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const note = options.note ?? "tuning-approved retirement (chronically noisy)";
  let retired = false;
  const updated = (constraints ?? []).map((constraint) => {
    if (!constraint || constraint.id !== constraintId || constraint.status !== "active") return constraint;
    retired = true;
    return {
      ...constraint,
      status: "retired",
      promotion_history: [
        ...(constraint.promotion_history ?? []),
        { ts, from: "active", to: "retired", actor: "human-cli", note },
      ],
    };
  });
  if (!retired) {
    throw new Error(`retireActiveConstraint: no status:"active" constraint found with id ${JSON.stringify(constraintId)}`);
  }
  return { constraints: updated, retired };
}

// Shape-validation citation, CORRECTED per the plan's 2026-07-14 review must-fix: this is NOT a
// reuse of validateConstraint's expected check (validateConstraint, above, only asserts
// `expected` is PRESENT -- it has no numeric-shape check at all). Left unvalidated, a malformed
// proposedExpected (a stray "eq" comparator, a non-finite value, a missing `value` field) would
// persist into constraints.json fine, then evaluateExpected (constraint-eval.js) would return
// { supported: false } on every subsequent live tick -- silently DISABLING a live,
// already-promoted monitor via what looks like a routine tuning approval. This is therefore a
// NEW, dedicated check, matching exactly the numeric shape evaluateExpected supports: comparator
// === "gte" or "lte" (never "eq"/pattern -- categorical targets have no retune path), and a
// finite numeric `value` (Number.isFinite, which -- unlike coercing Number(value) first --
// rejects a string/NaN/Infinity/undefined outright rather than silently coercing a string).
function isValidNumericExpected(expected) {
  return !!expected
    && typeof expected === "object"
    && !Array.isArray(expected)
    && (expected.comparator === "gte" || expected.comparator === "lte")
    && Number.isFinite(expected.value);
}

/**
 * The ONLY code path in the entire codebase that mutates `expected` on an already-active
 * constraint record without a status transition (a logged self-loop, from "active" to "active" --
 * see the promotion_history entry below -- not a silent, untracked write). Throws / REJECTS (no
 * write, no promotion_history entry appended) unless:
 *   (a) the matched record has status === "active", and
 *   (b) proposedExpected is exactly the numeric shape evaluateExpected supports (see
 *       isValidNumericExpected above).
 * A malformed shape is rejected outright rather than persisted, so a bad retune approval can
 * never silently stop the constraint from firing.
 */
export function applyApprovedRetune(constraints, constraintId, proposedExpected, options = {}) {
  if (!isValidNumericExpected(proposedExpected)) {
    throw new Error(
      `applyApprovedRetune: proposedExpected must be { comparator: "gte"|"lte", value: <finite number> }, got: ${JSON.stringify(proposedExpected)}`,
    );
  }

  const ts = normalizeIso(options.now ?? new Date().toISOString(), "now");
  const note = options.note ?? "tuning-approved retune";
  let updatedAny = false;
  const updated = (constraints ?? []).map((constraint) => {
    if (!constraint || constraint.id !== constraintId || constraint.status !== "active") return constraint;
    updatedAny = true;
    return {
      ...constraint,
      expected: { comparator: proposedExpected.comparator, value: Number(proposedExpected.value) },
      promotion_history: [
        ...(constraint.promotion_history ?? []),
        { ts, from: "active", to: "active", actor: "human-cli", note },
      ],
    };
  });
  if (!updatedAny) {
    throw new Error(`applyApprovedRetune: no status:"active" constraint found with id ${JSON.stringify(constraintId)}`);
  }
  return { constraints: updated, updated: updatedAny };
}
