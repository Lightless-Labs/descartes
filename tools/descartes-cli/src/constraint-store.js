import fs from "node:fs/promises";
import path from "node:path";

export const SCHEMA_VERSION = 1;
export const CONSTRAINT_STATUSES = ["draft", "shadow", "review-ready", "active", "retired"];

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
  try {
    return normalizeLearnedConfig(JSON.parse(await fs.readFile(configFile, "utf8")));
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeLearnedConfig();
    throw error;
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

  const inWindow = (shadowRecords ?? [])
    .filter((record) => record?.constraint_id === constraint.id)
    .filter((record) => {
      const tsMs = new Date(record.ts).getTime();
      return Number.isFinite(tsMs) && tsMs >= shadowSinceMs && tsMs < shadowSinceMs + soakWindowMs;
    });

  if (inWindow.some((record) => record.fired === true)) return false;

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
