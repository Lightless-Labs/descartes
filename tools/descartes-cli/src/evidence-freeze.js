// Slice 2 (observed-incident collectors plan, docs/plans/2026-07-13-observed-incident-
// collectors.md) — Evidence-freeze / forensic-snapshot action.
//
// THE LOAD-BEARING DISTINCTION OF THIS SLICE (read this before touching this file): this module
// PERSISTS a timestamped, integrity-checksummed evidence bundle to Descartes-owned state, but
// MUTATES NOTHING on the monitored host. It does this by invoking ONLY the already-registered,
// already-reviewed read-only evidence-tool set from pi-harness.js's createEvidenceTools() — the
// exact same tools `descartes triage` already calls — and introduces ZERO new execFile/spawn
// surface of its own. This file must never import "node:child_process" or call anything whose
// name matches exec/spawn directly; see evidence-freeze.test.js's static source-scan regression
// test for the enforced proof (mirrors escalation-lint.test.js's own scanning discipline, but
// flags ANY exec/spawn-shaped call, not only escalation-binary ones — a plain new execFile call
// to a non-escalation binary would NOT trip escalation-lint, so that lint alone is insufficient
// to guarantee this slice's "zero new execution surface" invariant; this file's own dedicated
// test is what actually checks it).
//
// HARD EXEMPTIONS / NON-GOALS — stated explicitly so they are never mistaken for oversights
// (plan Slice 2 "Safety checks"):
//   - NOT gated by configDir/learned.json. This is an on-demand action like `descartes triage`,
//     not an inference artifact — it has no draft/shadow/review-ready lifecycle because it
//     captures facts, it never asserts a conclusion. (This file never reads/imports
//     constraint-store.js's learned.json config for this reason — see the static "no
//     learned.json gate" regression test.)
//   - NOT wired to any automatic trigger in v0. Operator-invoked only (`descartes incident
//     freeze`) — no daemon-initiated auto-freeze on alert. Coupling this to an automatic trigger
//     starts to brush the authority/containment plane and is explicitly deferred (Slice 7,
//     design-only, not implemented anywhere in this repo).
//   - The bundle NEVER enters any LLM prompt. It is a pure operator-facing forensic artifact —
//     unlike alert `diagnostics`/`compactAlert` (the only thing ever handed to the S13 LLM
//     path), nothing in this file calls createSession/session.prompt/compactAlert/
//     createPrivateAlertSession/createPrivateTriageSession, and it never will (see the static
//     "never reaches an LLM session" regression test).
//   - The bundle is NOT subject to fact-store.js's 30-day/5MB retention cap — evidence is
//     potentially legal-hold material and must never be auto-deleted by an existing retention
//     mechanism. It lives under its own `stateDir/evidence/` directory, entirely disjoint from
//     fact-store.js's `stateDir/learned/facts/` path, so no existing retention sweep can reach
//     it structurally. Retention policy for evidence bundles itself is an explicit open question
//     (plan §7, open question 8) — this file implements no auto-deletion of any kind.
//   - No privilege escalation: same-UID as whatever its constituent collectors already are.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { createEvidenceTools } from "./pi-harness.js";
import { TRIAGE_TOOL_NAMES } from "./tool-policy.js";

export const SCHEMA_VERSION = 1;
export const DEFAULT_REASON = "operator-requested evidence freeze";
export const MAX_REASON_LENGTH = 200;
export const MAX_TRIGGERED_BY_LENGTH = 80;

export function resolveEvidenceFreezePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "evidence");
  return { dir, auditFile: path.join(dir, "freeze-audit.jsonl") };
}

async function ensureEvidenceDir(descartesPaths) {
  const { dir } = resolveEvidenceFreezePaths(descartesPaths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function normalizeIso(ts, field = "timestamp") {
  const date = new Date(ts ?? new Date().toISOString());
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid evidence-freeze ${field}: ${ts}`);
  return date.toISOString();
}

// Filesystem-safe timestamp component: ISO-8601 with ":"/"." replaced by "-". This is a
// portability nicety (colons are invalid in Windows path segments) — it is NOT what prevents
// filename collisions; the random nonce (below) is the actual collision-safety mechanism.
function filenameTimestamp(iso) {
  return iso.replace(/[:.]/g, "-");
}

/**
 * Bounds+sanitizes the operator-supplied freeze reason via sanitizeIdentityString BEFORE it
 * reaches a manifest field, and separately derives a fixed-length sha256 hash of the sanitized
 * value for use in the filename. Hash-at-source (plan §1 hard requirement): the reason NEVER
 * reaches a filename in any raw or lightly-sanitized form, only as a hash — so a
 * path-traversal-shaped ("../../etc/passwd") or shell-injection-shaped reason cannot affect the
 * filename at all, and an over-long (e.g. 500-char) reason cannot make the manifest field
 * unbounded either.
 */
export function sanitizeFreezeReason(reason) {
  const raw = typeof reason === "string" && reason.trim() ? reason : DEFAULT_REASON;
  const sanitized = sanitizeIdentityString(raw, { maxLength: MAX_REASON_LENGTH })
    ?? sanitizeIdentityString(DEFAULT_REASON, { maxLength: MAX_REASON_LENGTH });
  const reasonHash = crypto.createHash("sha256").update(sanitized ?? DEFAULT_REASON).digest("hex").slice(0, 16);
  return { reason: sanitized ?? DEFAULT_REASON, reasonHash };
}

function sanitizeTriggeredBy(triggeredBy) {
  if (!triggeredBy) return "operator";
  return sanitizeIdentityString(String(triggeredBy), { maxLength: MAX_TRIGGERED_BY_LENGTH }) ?? "operator";
}

/**
 * Builds the bundle filename: <timestamp>-<nonce>-<reasonHash>.json (plan Slice 2). The random
 * nonce is what actually keeps two freezes issued within the same timestamp-resolution window
 * from colliding on a filename — see the collision-safety tests.
 */
export function buildEvidenceBundleFilename({ nowIso, nonceHex, reasonHash }) {
  return `${filenameTimestamp(nowIso)}-${nonceHex}-${reasonHash}.json`;
}

// Freeze snapshot sources: every already-registered `collect_*` tool EXCEPT
// `collect_triage_evidence`, filtered mechanically off TRIAGE_TOOL_NAMES (not a hand-duplicated
// array, so this can never silently drift from the real registered tool-name set — see
// evidence-freeze.test.js's parity assertion).
//
// Deliberately excluded, and why:
//   - `collect_triage_evidence` re-collects collect_system/collect_processes/collect_disks as an
//     aggregate — including it would re-execute the same underlying commands a second time for
//     no additional forensic value (still zero new execFile SURFACE, just redundant work).
//   - `inspect_process`/`inspect_parent_tree`/`inspect_runtime_provenance` require a specific
//     pid/port/container target; `sample_dimension` requires a specific `dimension`;
//     `read_sampling_artifact` requires a specific `artifact_id` from a prior sample_dimension
//     call. None of these have a meaningful "snapshot everything right now" value with no
//     target — a freeze does not invent one.
//   - `derive_findings` operates over previously-collected evidence envelopes; it is not itself
//     a host-state collector.
export function isFreezeSnapshotToolName(name) {
  return typeof name === "string" && name.startsWith("collect_") && name !== "collect_triage_evidence";
}

export const FREEZE_SNAPSHOT_TOOL_NAMES = Object.freeze(TRIAGE_TOOL_NAMES.filter(isFreezeSnapshotToolName));

function resolveFreezeSources(tools) {
  return (tools ?? []).filter((tool) => isFreezeSnapshotToolName(tool?.name));
}

/**
 * Invokes one already-registered evidence tool and normalizes its outcome. This is the ONLY
 * function in this module that reaches into the tool registry, and it only ever calls
 * `tool.execute(...)` — no execFile/spawn of its own. A tool that throws, times out, or returns a
 * non-"ok" envelope status degrades that ONE source to "degraded" — it never fails the whole
 * freeze (graceful partial-degrade, plan Slice 2 hard requirement: "a snapshot with 9/10 sources
 * beats no snapshot").
 */
async function collectFromTool(tool) {
  try {
    const toolResult = await tool.execute("evidence-freeze", {});
    const envelope = toolResult?.details ?? toolResult;
    const status = envelope?.status === "ok" ? "ok" : "degraded";
    return { name: tool.name, status, envelope };
  } catch (error) {
    return {
      name: tool.name,
      status: "degraded",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Computes the sha256 integrity digest over the bundle's own contents (every field except
 * `integrity` itself, which cannot include its own value). Recomputing this over a read-back
 * bundle and comparing against the stored `integrity.sha256` is how tamper-evidence is verified
 * (see verifyEvidenceBundleIntegrity) — a single flipped byte anywhere in the persisted contents
 * changes the recomputed digest.
 */
export function computeBundleDigest(bundleWithoutIntegrity) {
  return crypto.createHash("sha256").update(JSON.stringify(bundleWithoutIntegrity)).digest("hex");
}

export function verifyEvidenceBundleIntegrity(bundle) {
  if (!bundle || typeof bundle !== "object" || !bundle.integrity?.sha256) return false;
  const { integrity, ...rest } = bundle;
  return computeBundleDigest(rest) === integrity.sha256;
}

async function appendFreezeAudit(descartesPaths, record) {
  await ensureEvidenceDir(descartesPaths);
  const { auditFile } = resolveEvidenceFreezePaths(descartesPaths);
  await fs.appendFile(auditFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  return auditFile;
}

/**
 * Corrupt-tolerant audit reader, mirroring notification-delivery.js's readNotificationDeliveryAudit
 * exactly: a missing file returns [], an unparseable line is skipped rather than throwing.
 */
export async function readEvidenceFreezeAudit(descartesPaths) {
  const { auditFile } = resolveEvidenceFreezePaths(descartesPaths);
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
      // Ignore a corrupt local audit line rather than breaking freeze/read behavior.
    }
  }
  return records;
}

/**
 * Corrupt-tolerant bundle reader (mirrors constraint-store.js's readJsonFile convention): a
 * missing file is distinguished from an unparseable one, and neither throws.
 */
export async function readEvidenceBundle(descartesPaths, filename) {
  const { dir } = resolveEvidenceFreezePaths(descartesPaths);
  const bundlePath = path.join(dir, filename);
  let contents;
  try {
    contents = await fs.readFile(bundlePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { bundle: undefined, missing: true, corrupt: false, bundlePath };
    throw error;
  }
  try {
    return { bundle: JSON.parse(contents), missing: false, corrupt: false, bundlePath };
  } catch {
    return { bundle: undefined, missing: false, corrupt: true, bundlePath };
  }
}

export async function listEvidenceBundleFilenames(descartesPaths) {
  const { dir } = resolveEvidenceFreezePaths(descartesPaths);
  try {
    const entries = await fs.readdir(dir);
    return entries.filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

/**
 * Core action (plan Slice 2). Persists a timestamped, integrity-checksummed forensic evidence
 * bundle by calling ONLY the already-registered read-only evidence-tool set — zero new
 * execFile/spawn surface (see module header). Never gated by learned.json (on-demand action, not
 * an inference artifact). Never wired to an automatic trigger (operator-invoked only). Never fed
 * into an LLM prompt.
 *
 * @param {object} paths - resolveDescartesPaths() result.
 * @param {object} [options]
 * @param {string} [options.reason] - free-text operator reason; sanitized+bounded, hashed before
 *   it ever reaches a filename (see sanitizeFreezeReason).
 * @param {string} [options.triggeredBy] - who/what invoked the freeze (e.g. "operator-cli"); for
 *   the audit trail and manifest only, sanitized+bounded.
 * @param {string|number|Date} [options.now] - injectable clock (tests only — production code
 *   uses the real clock via the default `new Date().toISOString()`, exactly like every other
 *   store in this codebase; only the *workflow harness's own script* is barred from
 *   Date.now()/Math.random(), not this production module).
 * @param {Array} [options.tools] - injectable full evidence-tool registry; defaults to the real,
 *   already-registered createEvidenceTools(paths). Whichever registry is supplied (injected or
 *   default), only entries matching isFreezeSnapshotToolName are ever invoked — see
 *   resolveFreezeSources. Tests inject a fake/wrapped registry to assert orchestration behavior
 *   (partial-degrade, source accounting, collision handling) deterministically and to prove no
 *   tool outside the registered collect_* set is ever called.
 * @param {string} [options.nonce] - injectable filename nonce (tests only, to force a
 *   deterministic collision); production always uses a fresh crypto.randomBytes(8) value.
 */
export async function runEvidenceFreeze(paths, options = {}) {
  const nowIso = normalizeIso(options.now);
  const registry = options.tools ?? createEvidenceTools(paths);
  const sources = await Promise.all(resolveFreezeSources(registry).map((tool) => collectFromTool(tool)));
  const succeeded = sources.filter((source) => source.status === "ok").length;

  const { reason, reasonHash } = sanitizeFreezeReason(options.reason);
  const triggeredBy = sanitizeTriggeredBy(options.triggeredBy);

  const bundleWithoutIntegrity = {
    schema_version: SCHEMA_VERSION,
    kind: "evidence_freeze",
    created_at: nowIso,
    reason,
    triggered_by: triggeredBy,
    source_count: sources.length,
    succeeded_count: succeeded,
    degraded_count: sources.length - succeeded,
    sources,
  };
  const digest = computeBundleDigest(bundleWithoutIntegrity);
  const bundle = { ...bundleWithoutIntegrity, integrity: { algorithm: "sha256", sha256: digest } };
  const payload = JSON.stringify(bundle, null, 2);

  const dir = await ensureEvidenceDir(paths);
  const nonceHex = options.nonce ?? crypto.randomBytes(8).toString("hex");
  const filename = buildEvidenceBundleFilename({ nowIso, nonceHex, reasonHash });
  const bundlePath = path.join(dir, filename);

  // Atomic-publish discipline mirroring alert-store.js/constraint-store.js's tmp+rename
  // convention, with one deliberate addition: plain `fs.rename` always silently overwrites an
  // existing destination on POSIX, which is exactly what plan Slice 2 forbids for a forensic
  // bundle ("an actual same-path collision fails LOUDLY... never silently overwrites"). So the
  // publish step here uses `fs.link` (hard link) instead of `fs.rename`: the tmp file is written
  // first (unique per-invocation via pid+nonce, so a tmp-name collision across concurrent
  // invocations is not a real concern), then atomically published under the final name via
  // `fs.link`, which — unlike rename — refuses to clobber an existing path (EEXIST) and leaves
  // the prior bundle byte-for-byte untouched. The tmp file is then unlinked, leaving only the
  // published bundle behind.
  const tmpPath = `${bundlePath}.${process.pid}.tmp`;
  await fs.writeFile(tmpPath, payload, { mode: 0o600 });
  try {
    await fs.link(tmpPath, bundlePath);
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error(`Evidence bundle collision at ${bundlePath} (nonce collision) — refusing to overwrite an existing forensic bundle.`);
    }
    throw error;
  } finally {
    await fs.unlink(tmpPath).catch(() => {});
  }

  const auditRecord = {
    ts: nowIso,
    triggered_by: triggeredBy,
    reason,
    bundle_filename: filename,
    source_count: sources.length,
    succeeded_count: succeeded,
    degraded_count: sources.length - succeeded,
    sources: sources.map((source) => ({ name: source.name, status: source.status })),
    integrity_sha256: digest,
  };
  const auditFile = await appendFreezeAudit(paths, auditRecord);

  return { bundlePath, filename, bundle, auditFile, auditRecord };
}

function incidentUsage() {
  return `Descartes incident

Usage:
  descartes incident freeze [--reason <text>] [--json]

Safety: incident freeze is READ-ONLY against the monitored host — it persists a Descartes-owned
forensic evidence bundle (stateDir/evidence/) by calling only the already-registered read-only
evidence tools. It mutates nothing on the monitored host, is not gated by learned.json, has no
automatic trigger, and the bundle is never fed into an LLM prompt.`;
}

function renderFreezeResult(result) {
  const { bundle } = result;
  return [
    `Descartes evidence freeze: wrote ${result.bundlePath}`,
    `Reason: ${bundle.reason}`,
    `Sources: ${bundle.succeeded_count} ok, ${bundle.degraded_count} degraded (of ${bundle.source_count}).`,
    `Integrity: sha256:${bundle.integrity.sha256}`,
  ].join("\n");
}

function parseFreezeArgs(args) {
  let reason;
  let json = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--reason") {
      reason = args[i + 1];
      i += 1;
    } else if (arg === "--json") {
      json = true;
    }
  }
  return { reason, json };
}

/**
 * `descartes incident` dispatch, mirroring index.js's own top-level command dispatch pattern
 * (dedicated module, `run<Thing>(paths, args)` export — see index.js:162-168's `provenance`
 * dispatch, which this mirrors).
 */
export async function runIncident(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const [sub, ...rest] = args ?? [];

  if (!sub || sub === "--help" || sub === "-h") {
    output(incidentUsage());
    return undefined;
  }
  if (sub === "freeze") {
    const { reason, json } = parseFreezeArgs(rest);
    const result = await runEvidenceFreeze(descartesPaths, { reason, triggeredBy: "operator-cli" });
    output(json ? JSON.stringify(result, null, 2) : renderFreezeResult(result));
    return result;
  }

  throw new Error(`Unknown incident subcommand: ${sub}\n\n${incidentUsage()}`);
}
