import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_FACT_MAX_BYTES } from "./fact-store.js";

// configDir/watch.json — the WATCH-layer kill switch (plan docs/plans/2026-09-10-watch-by-
// default-slice-1.md §3.1). Mirrors constraint-store.js's learned.json machinery
// (normalizeLearnedConfig/loadLearnedConfig/writeLearnedConfig) EXACTLY, with ONE deliberate
// inversion: ENOENT (and any value other than the literal `false`) normalizes to
// `{ enabled: true }`, not `{ enabled: false }` -- this is the layer that turns Descartes into a
// default, no-config, discover-and-flag monitor. configDir/learned.json (constraint-store.js)
// is untouched and keeps its own default-OFF semantics: it continues to gate exactly the AUTHOR
// layer (constraint mining/promotion/tuning, active/shadow-constraint evaluation).
//
// Deliberately a SEPARATE file/module from constraint-store.js, not a shared {watch, learned}
// object or shared normalizer -- see plan §3.1's own rejection of that shape: a single file would
// make writeLearnedConfig responsible for a field it doesn't own, and would break `learned
// enable/disable`'s existing byte-identity guarantee for operators who only ever touch the AUTHOR
// flag. The two files' normalizers are independent copies of the same small validation logic on
// purpose, not an accidental duplication to be refactored away.

export function resolveWatchStorePaths(descartesPaths) {
  return {
    configFile: path.join(descartesPaths.configDir, "watch.json"),
  };
}

async function ensureParent(file) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid watch config ${field}: ${ts}`);
  return date.toISOString();
}

// Mirrors constraint-store.js's own normalizeFactStoreMaxBytes exactly (fail closed to
// DEFAULT_FACT_MAX_BYTES on anything that is not a finite, positive number) -- kept as an
// independent copy rather than a shared import so watch.json and learned.json stay two fully
// independent files, per this module's own header note above.
function normalizeFactStoreMaxBytes(value) {
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? num : DEFAULT_FACT_MAX_BYTES;
}

// S4 (fact-store capacity plan §4.5 Config): the per-family budget map. Only its SHAPE is normalized
// here (a plain object of at most 32 short keys with primitive values); each value is validated
// against its family's T8 horizon floor by fact-families.js resolveFactStoreBudgets at use, so a
// rejected value stays visible to the status surfaces (`budget_below_horizon_floor`) instead of
// being silently rewritten away. Absent (or not a plain object) -> absent: every family default.
const MAX_FACT_STORE_BUDGET_KEYS = 32;
function normalizeFactStoreBudgetsConfig(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entries = Object.entries(value)
    .filter(([key, entry]) => key.length > 0 && key.length <= 64 && (entry === null || ["number", "string", "boolean"].includes(typeof entry)))
    .slice(0, MAX_FACT_STORE_BUDGET_KEYS);
  return Object.fromEntries(entries);
}

export function normalizeWatchConfig(config = {}) {
  return {
    // The one deliberate inversion vs. normalizeLearnedConfig's `config.enabled === true`
    // (fail-closed-to-disabled): here we fail closed to ENABLED, this store's safe default --
    // only the literal `false` turns watch off. An absent field (ENOENT's `{}`), `undefined`, or
    // any other junk value all normalize to `true`.
    enabled: config.enabled !== false,
    updated_at: config.updated_at ? normalizeIso(config.updated_at, "updated_at") : undefined,
    fact_store_max_bytes: normalizeFactStoreMaxBytes(config.fact_store_max_bytes),
    ...(normalizeFactStoreBudgetsConfig(config.fact_store_budgets) ? { fact_store_budgets: normalizeFactStoreBudgetsConfig(config.fact_store_budgets) } : {}),
  };
}

// Schema-malformed-but-syntactically-valid-JSON detection (LOW, daybreak-blue re-gate): `[]` (a
// root that parses fine but isn't a plain object) or an `enabled` field present but not a boolean
// (e.g. the string "false") would otherwise silently normalize through normalizeWatchConfig's
// fail-safe-on defaults with NO corrupt marker at all -- hiding a real operator typo/config bug
// from diagnostics, even though the resulting `.enabled` value happens to still land on this
// store's safe default. Checked against the PARSED root, before normalization, so a schema
// violation here is never confused with normalizeWatchConfig's own deliberately-lenient
// value-range tolerance (e.g. an out-of-range fact_store_max_bytes is a valid number failing a
// range check, not a schema violation, and correctly stays uncorrupted per that field's own
// existing fail-closed-to-default contract).
function isSchemaValidWatchConfig(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  if ("enabled" in parsed && typeof parsed.enabled !== "boolean") return false;
  return true;
}

/**
 * Reads the WATCH-layer (structural inventory + deterministic novelty-detector) enablement switch
 * from configDir/watch.json. Defaults to { enabled: true } when the file is absent -- the one
 * deliberate inversion of loadLearnedConfig's ENOENT-defaults-to-disabled behavior.
 */
export async function loadWatchConfig(descartesPaths) {
  const { configFile } = resolveWatchStorePaths(descartesPaths);
  let contents;
  try {
    contents = await fs.readFile(configFile, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return normalizeWatchConfig();
    throw error;
  }
  try {
    const parsed = JSON.parse(contents);
    const normalized = normalizeWatchConfig(parsed);
    // Retains the enabled-by-default (fail-safe-on) behavior: normalizeWatchConfig already
    // normalizes every schema-invalid shape below to `enabled: true` on its own (its `!== false`
    // inversion treats a non-boolean/absent `enabled` as "not the literal false"), so this only
    // ADDS the diagnostic marker -- it never changes what `.enabled` resolves to.
    return isSchemaValidWatchConfig(parsed) ? normalized : { ...normalized, corrupt: true };
  } catch {
    // Malformed JSON: fail CLOSED to this store's ENABLED default rather than throwing out of a
    // daemon iteration -- mirrors loadLearnedConfig's own corrupt-file tolerance. `corrupt: true`
    // is an additive marker only; callers that only read `.enabled` are unaffected.
    return { ...normalizeWatchConfig(), corrupt: true };
  }
}

export async function writeWatchConfig(descartesPaths, config, options = {}) {
  const { configFile } = resolveWatchStorePaths(descartesPaths);
  await ensureParent(configFile);
  const normalized = normalizeWatchConfig({ ...config, updated_at: options.now ?? new Date().toISOString() });
  const tmpFile = `${configFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, configFile);
  return normalized;
}
