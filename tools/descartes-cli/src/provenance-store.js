// Layer B / Slice S5 -- identity baseline store, deterministic promotion state machine, and the
// `descartes provenance` CLI. See docs/plans/2026-07-10-layer-b-provenance.md section 5 for the
// authoritative spec.
//
// This module owns three responsibilities, deliberately kept together (mirrors
// shadow-store.js/promotion-store.js's own store+CLI combination, per the plan's explicit
// naming: "New CLI tools/descartes-cli/src/provenance-store.js"):
//   - The identity_signature hash (fixture-pinned FIRST, see test/provenance-store.test.js's
//     golden fixture -- written and locked before this function existed).
//   - The provisional -> known_good -> retired promotion state machine + the atomic,
//     corrupt-tolerant signatures.json store (mirrors constraint-store.js's/history-store.js's
//     tmp+rename 0o600 convention).
//   - The `descartes provenance snapshot` / `descartes provenance baseline show` CLI.
//
// Deliberately does NOT perform any host I/O (no execFile/readdir/lsof/ps) -- that lives in
// tools/provenance-identity.js's observation-gatherer, imported here only via a dynamic import
// inside the `snapshot` CLI handler (avoids a static import cycle: provenance-identity.js
// imports this module's store/state-machine primitives).
//
// identity_signature DEVIATION (documented, not silent): the plan's data shape names
// `identity_hash` as "codesign identity or exe content hash". S5 (which added this hash's INPUT
// POSITION to computeIdentitySignature below) always passed that component as absent/undefined --
// computing a true content hash or codesign identity would mean either hashing a binary's full
// content (no such mechanism exists anywhere in this codebase) or invoking `codesign -dv` per
// observed process every reconciliation, which is unbounded per-process I/O of exactly the kind
// S4's own shipped addendum explicitly excluded from any fixed-rule path ("S4 as implemented
// needs neither codesign nor spctl for its two rule_ids... codesign remains available in S3 for
// on-demand triage but is not on any S4 fixed-rule path").
//
// S5-follow-1 (tools/provenance-identity.js's gatherIdentityObservations) closes the resulting
// identity_drift blind spot -- an in-place binary swap at the same path/launcher/owner previously
// left identity_signature unchanged, since identity_hash was always undefined -- by populating
// identity_hash with computeExecutableStatFingerprint below: a bounded, single-fs.stat
// CONTENT-CHANGE proxy (`sha256(dev:ino:size:mtimeMs).slice(0,16)`), NOT a true content hash or
// codesign identity. Still no unbounded per-process I/O (one fs.stat, reusing the already-resolved
// executable path, only on the already-rate-limited reconcile path); still degrades to undefined
// (never a fabricated value) whenever the executable path is unresolved or the stat itself fails.
// A same-inode overwrite that preserves size AND resets mtime via `touch -r` can still evade this
// pure-stat proxy -- a codesign CDHash / full content hash remains a future hardening for signed
// binaries, exactly as the plan's own open item #7 treats spctl.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { sanitizeDiagnostics, sanitizeIdentityString } from "./diagnostics-sanitizer.js";

export const SCHEMA_VERSION = 1;

// Grace window (plan section 5): provisional -> known_good requires at least this many samples
// AND at least this many DISTINCT structural-tick iterations -- mirrors the constraint layer's
// own multi-sample-across-iterations promotion discipline, at reflex-layer (hours, not days)
// scale rather than the constraint layer's multi-day soak.
export const DEFAULT_STABLE_SAMPLE_THRESHOLD = 3;
export const DEFAULT_STABLE_ITERATION_THRESHOLD = 2;

// S5-follow-2 (Codex review finding #5, Part A -- "identity alerts never age out"): bounds how
// long a known_good/grace_window identity (or a known_good entry inside an identity_drift
// target-key group) keeps producing a candidate after its last successfully-reconciled
// observation. Must comfortably exceed tools/provenance-identity.js's own
// DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS (1h, the daemon-wired reconcile cadence) so a genuinely
// still-present identity is never dropped merely because it happens to land between two reconcile
// ticks. 3x that cadence (3h) gives headroom for at least two consecutive missed/delayed ticks
// (daemon downtime, a slow/loaded host, a skipped tick) before an identity is ever treated as
// gone. Once a process exits or a socket closes, its record's last_seen stops advancing (see
// applyIdentityObservation below, which always sets last_seen := the current reconcile's own ts
// on every fold) -- once this window elapses without a fresh observation,
// deriveIdentityCandidates stops emitting a candidate for it, and applyAlertCandidates recovers
// the alert on the following tick (see deriveIdentityCandidates below).
export const DEFAULT_IDENTITY_PRESENCE_WINDOW_MS = 3 * 60 * 60 * 1000;

// Bounded, operator-introspection-only lists on each signature record -- never authoritative,
// never unbounded (plan's own "bounded list" wording for target_examples).
export const MAX_TARGET_EXAMPLES = 5;
export const MAX_PORT_TARGET_KEYS = 5;
export const MAX_BASELINE_SHOW_ENTRIES = 50;

// Fixed-length hash output, consistent with sanitizeDiagnostics' fixed-length-hash allowlist
// (diagnostics-sanitizer.js's HEX_HASH_LENGTHS includes 16 -- the same length alertId() and
// provenance-warnings.js's hashExecutablePath() already truncate to).
export const SIGNATURE_HASH_LENGTH = 16;

// NUL-byte delimiter, mirroring alert-store.js's alertId() `${ruleId}\0${fingerprint}`
// convention -- chosen (over e.g. a printable separator) specifically because it can never
// appear inside any of the four joined fields, so no field-boundary ambiguity is possible.
const IDENTITY_SIGNATURE_DELIMITER = "\u0000";

export const UNKNOWN_IDENTITY_RULE_ID = "provenance.process.unknown_identity";
export const IDENTITY_DRIFT_RULE_ID = "provenance.process.identity_drift";
export const NEW_PUBLIC_BIND_RULE_ID = "provenance.port.new_public_bind";

export function resolveSignatureStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, signaturesFile: path.join(dir, "signatures.json") };
}

async function ensureSignatureDir(descartesPaths) {
  await fs.mkdir(resolveSignatureStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function sha256Hex(value, length = SIGNATURE_HASH_LENGTH) {
  return crypto.createHash("sha256").update(String(value ?? ""), "utf8").digest("hex").slice(0, length);
}

// Hashes a raw identity field (executable_path / owning_user) down to a fixed-length hex digest
// before it is ever persisted to signatures.json (plan section 5: "Raw fields... are stored
// HASHED in signatures.json too, not just at emission"). Deliberately a small local helper
// rather than importing provenance-warnings.js's hashExecutablePath -- that would create the
// wrong dependency direction (tools/provenance-identity.js already depends on THIS module for
// identity primitives; this module must not depend back on a tools/ collector). Mirrors
// fact-store.js's own precedent of duplicating a small helper rather than reaching across a
// module boundary that would invert the intended dependency direction.
function hashIdentityField(value) {
  if (value === undefined || value === null || value === "") return undefined;
  return sha256Hex(value, 16);
}

function normalizeIdentityInput(value) {
  return value === undefined || value === null ? "" : String(value);
}

/**
 * THE GOLDEN-FIXTURE-PINNED HASH (Slice S5, plan section 5, TDD item 1 -- test written/locked
 * BEFORE this function existed; see test/provenance-store.test.js). Inputs, in this exact
 * order, NUL-joined and truncated to SIGNATURE_HASH_LENGTH (16) hex characters of the sha256
 * digest: executable_path, identity_hash (see module header re: always-absent in this build),
 * source_classification, owning_user. A missing/undefined/null field normalizes to an empty
 * string component -- NEVER omitted from the join, so the field count (and therefore the
 * serialized byte layout) never varies by which fields happen to be present. Same inputs always
 * produce the same hash (pure, deterministic); any single differing input produces a different
 * hash (verified directly by test/provenance-store.test.js).
 */
export function computeIdentitySignature({ executablePath, identityHash, sourceClassification, owningUser } = {}) {
  const serialized = [
    normalizeIdentityInput(executablePath),
    normalizeIdentityInput(identityHash),
    normalizeIdentityInput(sourceClassification),
    normalizeIdentityInput(owningUser),
  ].join(IDENTITY_SIGNATURE_DELIMITER);
  return sha256Hex(serialized, SIGNATURE_HASH_LENGTH);
}

/**
 * S5-follow-1: bounded content-CHANGE fingerprint for identity_hash (see the module header
 * above). Computed from a single fs.stat's `{ dev, ino, size, mtimeMs }` of the resolved
 * executable path -- deliberately NOT a content hash or codesign identity:
 * `sha256("${dev}:${ino}:${size}:${mtimeMs}")`, truncated to SIGNATURE_HASH_LENGTH (16) hex
 * chars, exactly like computeIdentitySignature's own truncation and sanitizeDiagnostics' own
 * fixed-length-hash allowlist. An in-place binary swap changes at least size/mtimeMs (usually
 * dev/ino too), so this fingerprint changes -- which changes identity_signature -- which lets
 * identity_drift fire for a same-path/launcher/owner swap (see deriveIdentityCandidates below).
 * Pure and deterministic (same stat inputs -> same hash, always). The caller
 * (tools/provenance-identity.js) is responsible for the DEGRADE-NOT-FABRICATE contract -- this
 * function is only ever invoked with a real, successful stat result; a failed/unavailable stat
 * must short-circuit to `identityHash: undefined` before reaching here, never a fabricated or
 * zero-valued stat object.
 */
export function computeExecutableStatFingerprint({ dev, ino, size, mtimeMs } = {}) {
  return sha256Hex(`${dev}:${ino}:${size}:${mtimeMs}`, SIGNATURE_HASH_LENGTH);
}

// ---------------------------------------------------------------------------------------------
// Promotion state machine (pure, no I/O).
// ---------------------------------------------------------------------------------------------

function boundedPushUnique(list, item, max, isEqual) {
  const existing = Array.isArray(list) ? list : [];
  if (existing.some((entry) => isEqual(entry, item))) return existing;
  const next = [...existing, item];
  return next.length > max ? next.slice(next.length - max) : next;
}

const targetExampleEqual = (a, b) => a?.kind === b?.kind && a?.value === b?.value;
const stringEqual = (a, b) => a === b;

/**
 * Folds one observation into an existing (possibly undefined -- first sighting) signature
 * record. `iterationKey` identifies the current structural-tick/iteration (e.g. the tick's own
 * ts) -- stable_iteration_count only advances when this call's iterationKey differs from the
 * record's own last-counted iteration, so multiple observations within the SAME tick bump
 * stable_sample_count but never stable_iteration_count (plan section 5: "observations spanning
 * ... DISTINCT structural ticks, not just repeated observations within one tick"). Once a
 * record reaches "known_good" it never reverts to "provisional" here -- only an explicit
 * `descartes provenance snapshot` re-baseline (via reconcileSignatures' retirement pass below)
 * or a hand-authored state change can move a record out of known_good.
 */
export function applyIdentityObservation(existingRecord, observation = {}, options = {}) {
  const sampleThreshold = options.sampleThreshold ?? DEFAULT_STABLE_SAMPLE_THRESHOLD;
  const iterationThreshold = options.iterationThreshold ?? DEFAULT_STABLE_ITERATION_THRESHOLD;
  const ts = options.ts ?? new Date().toISOString();
  const iterationKey = String(options.iterationKey ?? ts);

  const isNewIteration = !existingRecord || existingRecord.last_iteration_key !== iterationKey;
  const sampleCount = (existingRecord?.stable_sample_count ?? 0) + 1;
  const iterationCount = (existingRecord?.stable_iteration_count ?? 0) + (isNewIteration ? 1 : 0);
  const alreadyKnownGood = existingRecord?.state === "known_good";
  const crossesThreshold = sampleCount >= sampleThreshold && iterationCount >= iterationThreshold;
  const state = alreadyKnownGood ? "known_good" : crossesThreshold ? "known_good" : "provisional";

  let targetExamples = existingRecord?.target_examples ?? [];
  if (observation.target && typeof observation.target === "object") {
    targetExamples = boundedPushUnique(targetExamples, observation.target, MAX_TARGET_EXAMPLES, targetExampleEqual);
  }

  let portTargetKeys = existingRecord?.port_target_keys ?? [];
  for (const key of Array.isArray(observation.portTargetKeys) ? observation.portTargetKeys : []) {
    if (!key) continue;
    portTargetKeys = boundedPushUnique(portTargetKeys, key, MAX_PORT_TARGET_KEYS, stringEqual);
  }

  return {
    kind: "signature",
    family: "identity",
    state,
    // Additive beyond the plan's literal per-record shape (documented here, not silent): tracks
    // whether this identity's known_good status came from an explicit operator baseline
    // ("snapshot") or from crossing the grace window on its own ("grace_window"). Needed to
    // implement "unknown_identity fires only for identities NOT part of the accepted baseline"
    // without a second parallel store.
    origin: existingRecord?.origin ?? "grace_window",
    first_seen: existingRecord?.first_seen ?? ts,
    last_seen: ts,
    stable_sample_count: sampleCount,
    stable_iteration_count: iterationCount,
    // Additive (S5 implementation detail, internal bookkeeping only -- not part of the plan's
    // illustrative shape): the last iterationKey counted, so repeated same-tick observations
    // never double-count an iteration.
    last_iteration_key: iterationKey,
    inputs_hash: {
      executable_path_hash: hashIdentityField(observation.executablePath) ?? existingRecord?.inputs_hash?.executable_path_hash,
      identity_hash: hashIdentityField(observation.identityHash) ?? existingRecord?.inputs_hash?.identity_hash,
      source_classification: observation.sourceClassification ?? existingRecord?.inputs_hash?.source_classification,
      owning_user_hash: hashIdentityField(observation.owningUser) ?? existingRecord?.inputs_hash?.owning_user_hash,
    },
    target_examples: targetExamples,
    // Additive (S5 implementation detail): bounded list of "protocol.port" strings this identity
    // has been observed publicly serving -- drives new_public_bind's reverse-index lookup below.
    port_target_keys: portTargetKeys,
  };
}

/**
 * Operator-invoked bootstrap step (never automatic, per plan section 5): seeds/reaffirms an
 * identity directly as known_good/origin:"snapshot", bypassing the grace window entirely.
 * Reuses applyIdentityObservation for its sample/iteration bookkeeping (so a record's history
 * stays meaningful even once baselined) and then unconditionally overrides state/origin.
 */
export function seedKnownGoodIdentity(existingRecord, observation = {}, options = {}) {
  const updated = applyIdentityObservation(existingRecord, observation, options);
  return { ...updated, state: "known_good", origin: "snapshot" };
}

// ---------------------------------------------------------------------------------------------
// Store I/O (atomic tmp+rename 0o600, corrupt-tolerant -- mirrors constraint-store.js).
// ---------------------------------------------------------------------------------------------

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

export function normalizeSignatureStore(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const signatures = base.signatures && typeof base.signatures === "object" && !Array.isArray(base.signatures) ? base.signatures : {};
  return {
    version: SCHEMA_VERSION,
    bootstrapped_at: typeof base.bootstrapped_at === "string" ? base.bootstrapped_at : undefined,
    last_reconciled_at: typeof base.last_reconciled_at === "string" ? base.last_reconciled_at : undefined,
    signatures,
  };
}

/**
 * ENOENT-tolerant (fresh state -> empty store) and corrupt-tolerant (mirrors
 * constraint-store.js's loadConstraints: a corrupt/malformed file yields an empty store rather
 * than throwing, with `corrupt:true` surfaced to the caller).
 */
export async function loadSignatureStore(descartesPaths) {
  const { signaturesFile } = resolveSignatureStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(signaturesFile);
  if (missing) return { store: normalizeSignatureStore(undefined), corrupt: false };
  if (corrupt) return { store: normalizeSignatureStore(undefined), corrupt: true };
  return { store: normalizeSignatureStore(parsed), corrupt: false };
}

export async function writeSignatureStore(descartesPaths, store) {
  await ensureSignatureDir(descartesPaths);
  const { signaturesFile } = resolveSignatureStorePaths(descartesPaths);
  const normalized = normalizeSignatureStore(store);
  const tmpFile = `${signaturesFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, signaturesFile);
  return normalized;
}

// ---------------------------------------------------------------------------------------------
// Reconciliation (pure: folds a batch of observations into a store snapshot; I/O -- reading the
// existing store and persisting the result -- is the caller's responsibility, mirroring
// writeConstraints/loadConstraints being separate from the pure promotion helpers in
// constraint-store.js).
// ---------------------------------------------------------------------------------------------

// S5-follow-2 (Codex review finding #5, Part B -- "transient stat failure flips the signature"):
// a transient fs.stat failure (EPERM/ENOENT/a TOCTOU race -- see
// tools/provenance-identity.js's computeIdentityHash and its own DEGRADE-NOT-FABRICATE contract)
// makes the gatherer emit identityHash:undefined for a pid that normally DOES carry a
// fingerprint. Since identity_hash is one of computeIdentitySignature's four joined inputs,
// folding that observation as-is would compute a DIFFERENT identity_signature than the identity's
// own already-tracked record -- i.e. a stable identity's signature would flip
// (fingerprint-present -> "") purely because of one bad stat, which looks exactly like a brand
// new identity appearing (spurious unknown_identity) or the existing one drifting away (spurious
// identity_drift).
//
// Detected here, at the FOLD boundary (reconcileSignatures), not in the gatherer: if an
// identityHash:undefined observation's other three raw inputs (path/source/owner -- compared via
// the SAME hashed fields already persisted in inputs_hash, since raw fields are never kept
// un-hashed in the store) match an EXISTING record that already carries a real (defined)
// identity_hash, this observation is treated as "can't currently verify this identity, not a
// different one" and is skipped entirely for this reconcile -- the existing record (and its
// last_seen) is left exactly as it was. This degrades to NOT-OBSERVING this tick, never to
// observing-as-different (the two options the fix note called out; skip-at-the-fold is chosen
// over "carry forward the last-known identityHash" because the store only ever persists identity
// hashes in already-HASHED form -- there is no raw value left anywhere to carry forward without
// re-exposing it, which the sanitization invariant forbids).
//
// A genuinely first-ever sighting with no fingerprint capability (no matching fingerprinted
// record exists yet -- e.g. a stat that has ever only failed) is NOT skipped: it folds in with
// identityHash:undefined exactly as before S5-follow-2, preserving S5-follow-1's own
// DEGRADE-NOT-FABRICATE contract (still tracked, still eligible to promote/fire like any other
// identity -- degrade-to-unfingerprinted, never degrade-to-invisible).
function isTransientStatFailureOfKnownIdentity(signatures, observation) {
  if (observation?.identityHash !== undefined) return false;
  const executablePathHash = hashIdentityField(observation?.executablePath);
  if (!executablePathHash) return false;
  const owningUserHash = hashIdentityField(observation?.owningUser);
  const sourceClassification = observation?.sourceClassification;
  return Object.values(signatures ?? {}).some((record) => {
    const inputs = record?.inputs_hash ?? {};
    return (
      inputs.identity_hash !== undefined
      && inputs.executable_path_hash === executablePathHash
      && inputs.owning_user_hash === owningUserHash
      && inputs.source_classification === sourceClassification
    );
  });
}

/**
 * Folds this-tick's observations into `store`. `options.seedKnownGood: true` is set ONLY by the
 * operator-invoked `descartes provenance snapshot` CLI (never automatically, never by the daemon
 * fast-tick path) -- it seeds every currently-observed identity directly as known_good and, as a
 * re-baselining side effect, retires any OTHER known_good record that shares a target (same
 * executable_path_hash, or same public port) with a now-seeded identity but carries a different
 * identity_hash. This is what makes "operator can `descartes provenance snapshot` again to
 * re-baseline" (plan section 5 safety note) actually clear a previously-firing identity_drift.
 */
export function reconcileSignatures(store, observations = [], options = {}) {
  const ts = options.ts ?? new Date().toISOString();
  const iterationKey = String(options.iterationKey ?? ts);
  const signatures = { ...(store?.signatures ?? {}) };
  const seededHashes = new Set();

  for (const observation of observations ?? []) {
    // S5-follow-2, Part B (see isTransientStatFailureOfKnownIdentity above): a transient stat
    // failure on an already-fingerprinted identity is skipped entirely for this reconcile, rather
    // than folded in as a differently-signatured (and therefore spuriously new/drifted) identity.
    if (isTransientStatFailureOfKnownIdentity(signatures, observation)) continue;
    const identityHash = computeIdentitySignature(observation);
    seededHashes.add(identityHash);
    const existing = signatures[identityHash];
    signatures[identityHash] = options.seedKnownGood
      ? seedKnownGoodIdentity(existing, observation, { ...options, ts, iterationKey })
      : applyIdentityObservation(existing, observation, { ...options, ts, iterationKey });
  }

  if (options.seedKnownGood && seededHashes.size > 0) {
    const seededTargetKeys = new Set();
    for (const identityHash of seededHashes) {
      const record = signatures[identityHash];
      const processKey = record?.inputs_hash?.executable_path_hash;
      if (processKey) seededTargetKeys.add(`process.${processKey}`);
      for (const portKey of record?.port_target_keys ?? []) seededTargetKeys.add(`port.${portKey}`);
    }
    for (const [identityHash, record] of Object.entries(signatures)) {
      if (seededHashes.has(identityHash) || record.state !== "known_good") continue;
      const processKey = record.inputs_hash?.executable_path_hash;
      const recordKeys = [
        processKey ? `process.${processKey}` : undefined,
        ...(record.port_target_keys ?? []).map((key) => `port.${key}`),
      ].filter(Boolean);
      if (recordKeys.some((key) => seededTargetKeys.has(key))) {
        signatures[identityHash] = { ...record, state: "retired" };
      }
    }
  }

  return {
    version: SCHEMA_VERSION,
    bootstrapped_at: options.seedKnownGood ? ts : store?.bootstrapped_at,
    last_reconciled_at: store?.last_reconciled_at,
    signatures,
  };
}

// ---------------------------------------------------------------------------------------------
// Candidate derivation (pure -- operates only on an already-loaded store snapshot).
// ---------------------------------------------------------------------------------------------

function groupKnownGoodByTargetKey(signatures) {
  const groups = new Map();
  const pushEntry = (targetKey, entry) => {
    if (!groups.has(targetKey)) groups.set(targetKey, []);
    groups.get(targetKey).push(entry);
  };
  for (const [identityHash, record] of Object.entries(signatures ?? {})) {
    if (record.state !== "known_good") continue;
    const processKey = record.inputs_hash?.executable_path_hash;
    if (processKey) pushEntry(`process.${processKey}`, { identityHash, record });
    for (const portKey of record.port_target_keys ?? []) pushEntry(`port.${portKey}`, { identityHash, record });
  }
  return groups;
}

function buildUnknownIdentityCandidate(identityHash, record) {
  const fingerprint = identityHash;
  const diagnostics = sanitizeDiagnostics({
    identity_hash: identityHash,
    source_type: record.inputs_hash?.source_classification,
    stable_sample_count: record.stable_sample_count,
    stable_iteration_count: record.stable_iteration_count,
  });
  return {
    id: alertId(UNKNOWN_IDENTITY_RULE_ID, fingerprint),
    rule_id: UNKNOWN_IDENTITY_RULE_ID,
    fingerprint,
    severity: "warning",
    title: "Unrecognized process identity confirmed stable",
    summary: "A process identity outside the accepted provenance baseline has been observed consistently and is no longer provisional.",
    diagnostics,
    evidence_refs: ["provenance-identity"],
  };
}

function buildNewPublicBindCandidate(identityHash, record, portKey) {
  const [protocol, portStr] = String(portKey).split(".");
  const localPort = Number(portStr);
  const fingerprint = sanitizeIdentityString(`port.${portKey}`) ?? "unknown";
  const diagnostics = sanitizeDiagnostics({
    identity_hash: identityHash,
    protocol,
    local_port: Number.isFinite(localPort) ? localPort : undefined,
    source_type: record.inputs_hash?.source_classification,
  });
  return {
    id: alertId(NEW_PUBLIC_BIND_RULE_ID, fingerprint),
    rule_id: NEW_PUBLIC_BIND_RULE_ID,
    fingerprint,
    severity: "warning",
    title: "New public bind from an unbaselined identity",
    summary: "A listening socket bound to a public address is served by a process identity outside the accepted provenance baseline.",
    diagnostics,
    evidence_refs: ["provenance-identity"],
  };
}

function buildIdentityDriftCandidate(targetKey, staleEntry, currentEntry) {
  const targetKind = targetKey.startsWith("port.") ? "port" : "process";
  const fingerprint = sanitizeIdentityString(targetKey) ?? "unknown";
  const diagnostics = sanitizeDiagnostics({
    old_identity_hash: staleEntry.identityHash,
    new_identity_hash: currentEntry.identityHash,
    target_kind: targetKind,
    source_type: currentEntry.record.inputs_hash?.source_classification,
  });
  return {
    id: alertId(IDENTITY_DRIFT_RULE_ID, fingerprint),
    rule_id: IDENTITY_DRIFT_RULE_ID,
    fingerprint,
    severity: "warning",
    title: "Process identity changed for a previously known target",
    summary: "A target previously matching a known-good identity now resolves to a different identity (e.g. executable replaced).",
    diagnostics,
    evidence_refs: ["provenance-identity"],
  };
}

/**
 * Pure candidate derivation from an already-loaded/reconciled store snapshot -- no I/O. Day-1
 * no-storm (plan section 5, load-bearing + explicitly testable): `store.bootstrapped_at` unset
 * (no `descartes provenance snapshot` has EVER run) short-circuits to `[]` immediately,
 * regardless of how many signatures exist or what state they are in.
 *
 * unknown_identity / new_public_bind fire only for `state:"known_good" && origin:"grace_window"`
 * records -- i.e. an identity that stabilized on its own (crossed the grace window) but was
 * never part of an operator-accepted baseline. A still-`"provisional"` identity NEVER fires any
 * of the three candidates here (plan section 5: "No ... candidate fires for any identity still
 * provisional").
 *
 * identity_drift fires when a target_key (a process's executable_path_hash, or a
 * "protocol.port" public-bind key) has 2+ DISTINCT known_good identity_signatures recorded
 * against it: the most-recently-seen one is "current"; any older, differing one indicates the
 * identity behind that target changed. Both records must be state:"known_good" (reached via
 * grace-window promotion OR an operator `provenance snapshot`) -- a still-"provisional"
 * replacement does not itself drift yet (it may first surface as unknown_identity). So drift is
 * not instantaneous: for the natural (non-snapshot) case the replacement must cross the grace
 * window before drift fires.
 *
 * FIDELITY GAP CLOSED (S5-follow-1, see the module header above): identity_hash is now populated
 * by the gatherer (tools/provenance-identity.js's gatherIdentityObservations, via
 * computeExecutableStatFingerprint above) with a bounded fs.stat CONTENT-CHANGE fingerprint, so
 * an in-place binary SWAP at the same path/launcher/owner now changes identity_signature and
 * drift fires for it too -- previously, with identity_hash always undefined, the signature was
 * derived from executable_path + source_classification + owning_user only and such a swap went
 * undetected. REMAINING GAP (documented, fail-safe -- false negative only): a same-inode
 * overwrite that preserves size AND resets mtime via `touch -r` can still evade this pure-stat
 * proxy; a codesign CDHash / full content hash remains a future hardening for signed binaries.
 * In the interim S4's deleted_exe_running rule already catches the common "FD still open to a
 * deleted inode" swap.
 *
 * RECOVERY (S5-follow-2, Codex review finding #5, Part A): a candidate is only ever emitted for a
 * record (or, for identity_drift, for EACH SIDE of the comparison) whose `last_seen` is recent --
 * within `options.presenceWindowMs` (default DEFAULT_IDENTITY_PRESENCE_WINDOW_MS, see its own doc
 * comment) of `options.now` (default Date.now()). applyIdentityObservation always refreshes
 * last_seen on every successful fold, so a still-running process/still-open socket keeps its
 * record's last_seen current every reconcile; once a process exits or a socket closes, that
 * record simply stops being observed, last_seen stops advancing, and once it falls outside the
 * presence window this function stops emitting a candidate for it -- which is what lets
 * applyAlertCandidates recover the corresponding alert on the next tick. For identity_drift
 * specifically, BOTH sides of a target-key group must be currently present for drift to fire --
 * once the stale (superseded) identity ages out of the window, drift resolves even if the current
 * identity is still very much present.
 */
export function deriveIdentityCandidates(store, options = {}) {
  const signatures = store?.signatures ?? {};
  if (!store?.bootstrapped_at) return [];

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const presenceWindowMs = options.presenceWindowMs ?? DEFAULT_IDENTITY_PRESENCE_WINDOW_MS;
  const isPresent = (record) => {
    const lastSeenMs = new Date(record?.last_seen ?? Number.NaN).getTime();
    return Number.isFinite(lastSeenMs) && nowMs - lastSeenMs <= presenceWindowMs;
  };

  const candidates = [];
  for (const [identityHash, record] of Object.entries(signatures)) {
    if (record.state !== "known_good" || record.origin !== "grace_window") continue;
    if (!isPresent(record)) continue; // Recovered: unseen for longer than the presence window.
    candidates.push(buildUnknownIdentityCandidate(identityHash, record));
    for (const portKey of record.port_target_keys ?? []) {
      candidates.push(buildNewPublicBindCandidate(identityHash, record, portKey));
    }
  }

  const groups = groupKnownGoodByTargetKey(signatures);
  for (const [targetKey, entries] of groups) {
    const presentEntries = entries.filter((entry) => isPresent(entry.record));
    if (presentEntries.length < 2) continue;
    const sorted = [...presentEntries].sort((a, b) => new Date(b.record.last_seen).getTime() - new Date(a.record.last_seen).getTime());
    const current = sorted[0];
    const stale = sorted.find((entry) => entry.identityHash !== current.identityHash);
    if (stale) candidates.push(buildIdentityDriftCandidate(targetKey, stale, current));
  }

  return candidates;
}

// ---------------------------------------------------------------------------------------------
// CLI: `descartes provenance snapshot` / `descartes provenance baseline show`.
// ---------------------------------------------------------------------------------------------

function usage() {
  return `Descartes provenance

Usage:
  descartes provenance snapshot [--json]
  descartes provenance baseline show [--identity <hash>] [--json]

Safety: snapshot is an explicit, operator-invoked bootstrap -- it is never run automatically.`;
}

function snapshotUsage() {
  return "Usage: descartes provenance snapshot [--json]";
}

function baselineShowUsage() {
  return "Usage: descartes provenance baseline show [--identity <hash>] [--json]";
}

function redactedSignatureSummary(identityHash, record) {
  return {
    identity_hash: identityHash,
    state: record.state,
    origin: record.origin,
    first_seen: record.first_seen,
    last_seen: record.last_seen,
    stable_sample_count: record.stable_sample_count,
    stable_iteration_count: record.stable_iteration_count,
    source_classification: record.inputs_hash?.source_classification,
    executable_path_hash: record.inputs_hash?.executable_path_hash,
    owning_user_hash: record.inputs_hash?.owning_user_hash,
    target_example_count: (record.target_examples ?? []).length,
    port_target_key_count: (record.port_target_keys ?? []).length,
  };
}

function renderBaselineShowLine(entry) {
  return `${entry.identity_hash}  ${String(entry.state).padEnd(11)}  samples=${entry.stable_sample_count} iterations=${entry.stable_iteration_count}  source=${entry.source_classification ?? "unknown"}  origin=${entry.origin ?? "unknown"}`;
}

async function runSnapshot(descartesPaths, args, runtime) {
  const output = runtime.output ?? console.log;
  let json = false;
  for (const arg of args) {
    if (arg === "--json") json = true;
    else if (arg === "--help" || arg === "-h") {
      output(snapshotUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected provenance snapshot argument: ${arg}\n\n${snapshotUsage()}`);
    }
  }

  const gather = runtime.gatherIdentityObservations
    ?? (await import("./tools/provenance-identity.js")).gatherIdentityObservations;
  const observations = await gather(runtime);

  const loadStore = runtime.loadSignatureStore ?? loadSignatureStore;
  const { store } = await loadStore(descartesPaths);
  const ts = runtime.now ? new Date(runtime.now).toISOString() : new Date().toISOString();
  const reconciled = reconcileSignatures(store, observations, { ts, iterationKey: ts, seedKnownGood: true });
  const nextStore = { ...reconciled, bootstrapped_at: ts, last_reconciled_at: ts };

  const writeStore = runtime.writeSignatureStore ?? writeSignatureStore;
  await writeStore(descartesPaths, nextStore);

  const summary = {
    seeded_identity_count: observations.length,
    total_identity_count: Object.keys(nextStore.signatures).length,
    bootstrapped_at: nextStore.bootstrapped_at,
  };
  if (json) output(JSON.stringify({ provenance_snapshot: summary }, null, 2));
  else output(`Provenance snapshot: ${summary.seeded_identity_count} identity(ies) observed and baselined as known_good (${summary.total_identity_count} total tracked).`);
  return summary;
}

async function runBaselineShow(descartesPaths, args, runtime) {
  const output = runtime.output ?? console.log;
  let json = false;
  let identityFilter;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--json") json = true;
    else if (arg === "--identity") {
      identityFilter = args[i + 1];
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      output(baselineShowUsage());
      return undefined;
    } else {
      throw new Error(`Unexpected provenance baseline show argument: ${arg}\n\n${baselineShowUsage()}`);
    }
  }

  const loadStore = runtime.loadSignatureStore ?? loadSignatureStore;
  const { store } = await loadStore(descartesPaths);
  const entries = Object.entries(store.signatures ?? {})
    .filter(([hash]) => !identityFilter || hash === identityFilter)
    .slice(0, MAX_BASELINE_SHOW_ENTRIES)
    .map(([hash, record]) => redactedSignatureSummary(hash, record));

  if (json) output(JSON.stringify({ provenance_baseline: entries }, null, 2));
  else if (entries.length === 0) output("No tracked provenance identities.");
  else output(entries.map(renderBaselineShowLine).join("\n"));
  return entries;
}

/**
 * `descartes provenance` dispatch, mirroring index.js's own top-level command dispatch pattern
 * (dedicated module, `run<Thing>(paths, args)` export).
 */
export async function runProvenanceStore(descartesPaths, args, runtime = {}) {
  const output = runtime.output ?? console.log;
  const [sub, ...rest] = args ?? [];

  if (!sub || sub === "--help" || sub === "-h") {
    output(usage());
    return undefined;
  }
  if (sub === "snapshot") return runSnapshot(descartesPaths, rest, runtime);
  if (sub === "baseline" && rest[0] === "show") return runBaselineShow(descartesPaths, rest.slice(1), runtime);

  throw new Error(`Unknown provenance subcommand: ${sub}\n\n${usage()}`);
}
