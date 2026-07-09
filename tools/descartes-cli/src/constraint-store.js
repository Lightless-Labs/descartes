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
