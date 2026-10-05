// Layer B / Slice S5 -- own-UID identity observation gatherer + the daemon-wired fast-tick
// candidate function for the three new deterministic rule_ids (unknown_identity, identity_drift,
// new_public_bind). See docs/plans/2026-07-10-layer-b-provenance.md section 5.
//
// Deliberately does NOT touch collectStructuralEvidence/defaultDaemonProfile's structural-tick
// machinery (daemon.js's own test suite deep-equals the exact structural.collectors key set --
// adding a new key there would be a real regression, not just an additive change). Instead this
// module's own computeProvenanceIdentityCandidates is fully self-contained: it is the ONLY
// daemon.js edit this slice needs (added to the existing extraCandidates concatenation,
// mirroring computeActiveConstraintCandidates/computeProvenanceWarningCandidates exactly), and
// it internally rate-limits its own (bounded, own-UID-only) host I/O via a persisted
// `last_reconciled_at` timestamp on signatures.json itself -- functionally equivalent to the
// structural cadence, without needing a new collectStructuralEvidence entry.
//
// Reuses S3/S4's already-exported building blocks rather than re-deriving them:
// listListeningSocketsWithPid/snapshotProvenanceProcesses (provenance-warnings.js),
// classifySourceFromAncestry/isPublicBindAddress/resolveExecutableInfo (provenance.js),
// buildParentTreeResult (processes.js).

import fs from "node:fs/promises";
import { loadLearnedConfig } from "../constraint-store.js";
import {
  computeExecutableStatFingerprint,
  computeIdentitySignature,
  deriveIdentityCandidates,
  deriveIdentityCoverage,
  loadSignatureStore,
  reconcileSignaturesDetailed,
  writeSignatureStore,
} from "../provenance-store.js";
import { buildParentTreeResult } from "./processes.js";
import { classifySourceFromAncestry, isPublicBindAddress, resolveExecutableInfo } from "./provenance.js";
import { listListeningSocketsWithPidStatus, snapshotProvenanceProcessesStatus } from "./provenance-warnings.js";

const MAX_ANCESTRY_DEPTH = 16;

// Internal rate-limit for computeProvenanceIdentityCandidates' own host I/O -- functionally
// equivalent to the structural-tick cadence (daemon.js's structural.interval_ms default is also
// 1h) without registering a new structural sub-collector.
export const DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS = 60 * 60 * 1000;

function buildAncestryChain(processes, pid, maxDepth) {
  // Mirrors provenance-warnings.js's own (non-exported) buildAncestryChain exactly -- duplicated
  // rather than imported, since importing a private helper across the module boundary would be
  // reaching into provenance-warnings.js's internals rather than its declared export surface
  // (mirrors fact-store.js's own precedent of duplicating small helpers across store modules).
  const treeResult = buildParentTreeResult(processes, pid, maxDepth);
  const chain = treeResult.result?.chain ?? [];
  return chain.map((item) => ({ pid: item.pid, ppid: item.ppid, comm: item.command }));
}

async function defaultStatExecutablePath(executablePath) {
  return fs.stat(executablePath);
}

/**
 * S5-follow-1: populates the identityHash input position (see provenance-store.js's module
 * header) with a bounded, single-fs.stat CONTENT-CHANGE fingerprint of the already-resolved
 * executable path of an already-own-UID-scoped, already-gathered identity -- no re-resolution of
 * the path itself (resolveExecutableInfo has already run), no new per-fast-tick I/O (this only
 * runs on gatherIdentityObservations' own rate-limited reconcile / explicit-snapshot path), and
 * exactly one stat per gathered identity. DEGRADE-NOT-FABRICATE: any stat failure (ENOENT,
 * EPERM, a TOCTOU race where the executable vanished between resolveExecutableInfo and here,
 * etc.) yields `undefined` -- identical to today's always-absent behavior for that identity --
 * never a fabricated/zero value, and never throws out of this function.
 *
 * S5-follow-2 (Codex review finding #5, Part B): this function still intentionally returns
 * `undefined` on a stat failure -- DEGRADE-NOT-FABRICATE is preserved here unchanged. The
 * follow-up problem ("a TRANSIENT failure flips an already-stable identity's signature") is fixed
 * one layer up, at the fold boundary: provenance-store.js's reconcileSignatures (via its
 * isTransientStatFailureOfKnownIdentity helper) is what decides whether an
 * identityHash:undefined observation should be skipped for this reconcile (already-fingerprinted
 * identity, matching path/source/owner) or folded in as usual (first-ever sighting, no
 * fingerprint history to protect).
 */
async function computeIdentityHash(executablePath, options) {
  const statExecutablePath = options.statExecutablePath ?? defaultStatExecutablePath;
  try {
    const statResult = await statExecutablePath(executablePath);
    return computeExecutableStatFingerprint(statResult);
  } catch {
    return undefined;
  }
}

/**
 * Own-UID-only observation gatherer (Slice S5). Lists currently-listening sockets (reusing S4's
 * own platform-dispatch), resolves each DISTINCT own-uid pid's executable path + ancestry-based
 * source classification exactly once, and returns one observation per own-uid pid, carrying the
 * bounded list of "protocol.port" keys for every PUBLIC-bind socket that pid currently holds.
 *
 * UID-SCOPING (plan section 5, hard invariant): a socket/pid pair is included ONLY when the
 * ps-reported owning uid of that pid equals the caller's own uid. This is a positive
 * confirmation, not merely "pid happens to be defined" -- macOS's unprivileged `lsof` already
 * resolves pid/command for OTHER-uid listeners too (see plan section 1's own grounding note), so
 * relying on "pid is defined" alone would silently include cross-uid processes on macOS. An
 * other-uid or unresolvable-uid pid is silently excluded here -- it never becomes an
 * observation, and therefore never surfaces as a degraded-confidence anything downstream
 * (asserts silence, not a degraded-confidence candidate, per the plan's explicit requirement).
 */
export async function gatherIdentityObservations(options = {}) {
  // Legacy array contract (used by the operator-invoked `descartes provenance snapshot` CLI): the
  // observations only, WITHOUT the collection status. It must never be used as a recovery-coverage
  // authority -- computeProvenanceIdentityCandidates uses collectIdentityObservations below.
  return (await collectIdentityObservations(options)).observations;
}

// Degradation reasons added by the identity gatherer itself (on top of the socket/ps census
// reasons from provenance-warnings.js's *Status collectors). Fixed enum strings.
export const IDENTITY_COLLECTION_DEGRADED_REASONS = Object.freeze({
  OWN_UID_UNKNOWN: "own_uid_unknown",
  PID_UNRESOLVED: "pid_unresolved",
  EXECUTABLE_UNRESOLVED: "executable_unresolved",
});

// Resolves a census collector through the DI seams. The status-returning seam
// (`options.<name>Status`) wins; otherwise a legacy array-returning injection
// (`options.<name>`, test fakes that REPLACE the raw collector and therefore assert what it saw) is
// treated as a successful census; otherwise the real status-returning collector runs.
async function runCensus(statusFn, legacyFn, defaultStatusFn, field, platform, options) {
  if (statusFn) return statusFn(platform, options);
  if (legacyFn) return { status: "ok", [field]: await legacyFn(platform, options), reasons: [] };
  return defaultStatusFn(platform, options);
}

function censusIsOk(census, field) {
  return census?.status === "ok" && Array.isArray(census[field]);
}

/**
 * Status-reporting own-UID identity gatherer (2026-10, provenance-identity recovery coverage):
 * `{ status: "ok" | "degraded", observations, reasons }`. Same observations as the pre-2026-10
 * gatherer, but every way the census could MISS an own-UID identity is surfaced instead of being
 * swallowed into a silent `[]`:
 *   - the socket census or ps snapshot itself degraded (lsof/ps/proc failure, truncation, ...);
 *   - the caller's own uid is undeterminable while listeners exist (every pid would be skipped);
 *   - a listener pid is missing from the ps snapshot (cannot tell whether it is own-UID);
 *   - an own-UID pid's executable path cannot be resolved (it could be a tracked identity).
 * `status:"ok"` therefore means "genuinely and completely observed (possibly nothing)", and ONLY
 * then may absence be treated as evidence. An OTHER-UID pid is an in-scope exclusion (the UID-scoping
 * invariant), not a degradation. A degraded result still carries the observations that WERE
 * genuinely resolved (real presence, safe to fold), never fabricated ones. Residual (documented, not
 * closable here): on Linux an own-UID socket whose fd-scan races its process exit is
 * indistinguishable from a cross-UID socket (both come back pid:undefined).
 */
export async function collectIdentityObservations(options = {}) {
  const platform = options.platform ?? process.platform;
  const reasons = [];
  const addReason = (reason) => { if (!reasons.includes(reason)) reasons.push(reason); };

  const socketCensus = await runCensus(
    options.listListeningSocketsWithPidStatus,
    options.listListeningSocketsWithPid,
    listListeningSocketsWithPidStatus,
    "sockets",
    platform,
    options,
  );
  if (!censusIsOk(socketCensus, "sockets")) {
    for (const reason of Array.isArray(socketCensus?.reasons) && socketCensus.reasons.length > 0 ? socketCensus.reasons : ["socket_census_degraded"]) addReason(reason);
  }
  const sockets = Array.isArray(socketCensus?.sockets) ? socketCensus.sockets : [];

  const pids = [...new Set(sockets.map((socket) => socket.pid).filter((pid) => Number.isInteger(pid)))];
  if (pids.length === 0) return { status: reasons.length === 0 ? "ok" : "degraded", observations: [], reasons };

  const processCensus = await runCensus(
    options.snapshotProvenanceProcessesStatus,
    options.snapshotProvenanceProcesses,
    snapshotProvenanceProcessesStatus,
    "processes",
    platform,
    options,
  );
  if (!censusIsOk(processCensus, "processes")) {
    for (const reason of Array.isArray(processCensus?.reasons) && processCensus.reasons.length > 0 ? processCensus.reasons : ["process_census_degraded"]) addReason(reason);
  }
  const processes = Array.isArray(processCensus?.processes) ? processCensus.processes : [];
  const processByPid = new Map(processes.map((item) => [item.pid, item]));

  // Object.hasOwn, not a `!== undefined` check: an EXPLICIT `ownUid: undefined` means "the uid
  // could not be determined" and must be honored (downstream skips every pid), never silently
  // replaced by the real process.getuid(). A `!== undefined` check made that injection
  // impossible and left the test environment-dependent (passed on uid!=fixture hosts, failed on
  // the uid-501 CI macOS guest).
  const ownUid = Object.hasOwn(options, "ownUid")
    ? options.ownUid
    : (typeof process.getuid === "function" ? process.getuid() : undefined);

  const socketsByPid = new Map();
  for (const socket of sockets) {
    if (!Number.isInteger(socket.pid)) continue;
    if (!socketsByPid.has(socket.pid)) socketsByPid.set(socket.pid, []);
    socketsByPid.get(socket.pid).push(socket);
  }

  const resolveExeInfo = options.resolveExecutableInfo ?? resolveExecutableInfo;
  const maxAncestryDepth = options.maxAncestryDepth ?? MAX_ANCESTRY_DEPTH;
  const observations = [];

  // Listeners exist but whose they are cannot be decided: no pid can be confirmed own-UID, so the
  // census cannot claim any tracked identity is absent.
  if (ownUid === undefined) addReason(IDENTITY_COLLECTION_DEGRADED_REASONS.OWN_UID_UNKNOWN);
  const processCensusOk = censusIsOk(processCensus, "processes");

  for (const pid of pids) {
    const processRecord = processByPid.get(pid);
    if (!processRecord) {
      // Not in the ps snapshot (exited between lsof and ps, or a partial snapshot): ownership
      // unknown. Still never fabricated into an observation -- but it IS a census gap. (When the ps
      // census itself already degraded, that reason already covers every pid.)
      if (processCensusOk) addReason(IDENTITY_COLLECTION_DEGRADED_REASONS.PID_UNRESOLVED);
      continue;
    }
    if (ownUid === undefined || processRecord.uid !== ownUid) continue; // UID-scoped: other-UID is out of scope (silent, never an observation).

    const ancestryChain = buildAncestryChain(processes, pid, maxAncestryDepth);
    const source = classifySourceFromAncestry(ancestryChain);
    const executableInfo = await resolveExeInfo(pid);
    const executablePath = executableInfo?.executable_path;
    if (!executablePath) {
      // Never fabricate an identity around an unresolved path -- but an own-UID listener we could
      // not identify might be a tracked identity, so the census is incomplete.
      addReason(IDENTITY_COLLECTION_DEGRADED_REASONS.EXECUTABLE_UNRESOLVED);
      continue;
    }

    const pidSockets = socketsByPid.get(pid) ?? [];
    const publicPortKeys = [
      ...new Set(
        pidSockets
          .filter((socket) => isPublicBindAddress(socket.local_address))
          .map((socket) => `${socket.protocol}.${socket.local_port}`),
      ),
    ];

    const identityHash = await computeIdentityHash(executablePath, options);

    observations.push({
      executablePath,
      // S5-follow-1: bounded fs.stat CONTENT-CHANGE fingerprint (see computeIdentityHash above +
      // provenance-store.js's computeExecutableStatFingerprint). undefined only when the stat
      // itself failed (degrade-not-fabricate) -- never a fabricated value.
      identityHash,
      sourceClassification: source.type,
      owningUser: String(processRecord.uid),
      target: { kind: "pid", value: pid },
      portTargetKeys: publicPortKeys,
    });
  }

  return { status: reasons.length === 0 ? "ok" : "degraded", observations, reasons };
}

/**
 * Daemon-wired fast-tick candidate function (Slice S5) -- the ONLY daemon.js edit this slice
 * needs, added to the same extraCandidates concatenation as computeActiveConstraintCandidates/
 * computeProvenanceWarningCandidates. Mirrors both of those functions' short-circuit shape:
 *
 *   - learned.json {enabled:false} (the shipped default) -> `[]` immediately, no I/O at all
 *     (BYTE-IDENTICAL-WHEN-DISABLED).
 *   - signatures.json has never been bootstrapped (`descartes provenance snapshot` has never
 *     run) -> `[]` immediately, no fresh host I/O either (DAY-1 NO-STORM, explicit and
 *     testable independent of anything a structural collector might otherwise have produced).
 *
 * Only once both gates pass does this function perform its own (rate-limited, own-UID-only,
 * bounded) host I/O to reconcile signatures.json, then derives candidates purely from the
 * resulting store state.
 *
 * S5-follow-2 (Codex review finding #5, Part A): the same `now` this function already computes
 * for its own rate-limit due-check is also threaded into deriveIdentityCandidates as its presence
 * reference point, so a candidate stops being emitted once its record's last_seen falls outside
 * provenance-store.js's DEFAULT_IDENTITY_PRESENCE_WINDOW_MS -- see that function's own doc
 * comment.
 *
 * DETECTOR-REPORTED RECOVERY COVERAGE (plan 2026-09-20 §8.B; 2026-10 conversion of this DEFERRED
 * producer). Returns `{ candidates, evaluatedAlertKeys }` on EVERY path. A candidate no longer being
 * emitted is NOT, by itself, a recovery: the daemon recovers a persisted identity alert only when
 * its alertId is in `evaluatedAlertKeys`, and this function reports an identity there ONLY when
 * THIS tick's collection genuinely and successfully re-observed the host:
 *   - gate off / never bootstrapped / store unreadable-as-empty -> no keys (freeze);
 *   - not due (inside the reconcile interval; no fresh host I/O this tick) -> no keys (freeze; a
 *     present candidate is still emitted from the store, so active alerts stay active);
 *   - due + collection DEGRADED (any census gap -- see collectIdentityObservations) or malformed ->
 *     no keys, `last_reconciled_at` NOT advanced, no record treated as departed; only the
 *     genuinely-resolved observations (real presence) are folded;
 *   - due + collection OK -> every identity/port/target the freshly re-observed store tracks
 *     (provenance-store.js's deriveIdentityCoverage): present -> evaluated (still fires); genuinely
 *     absent -> evaluated-clear (recovers once outside the presence window); except anything a
 *     transient-stat-skipped observation could be (running but unverified -> never clear).
 *
 * RECONCILE BOOKKEEPING: `last_reconciled_at` = last SUCCESSFUL complete reconcile only;
 * `last_reconcile_attempt_at` = the rate-limit clock, advanced on every attempt (so a persistently
 * degraded host is re-probed hourly, not every fast tick). A legacy store without the attempt field
 * falls back to `last_reconciled_at` for the due-check.
 */
export async function computeProvenanceIdentityCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return { candidates: [], evaluatedAlertKeys: [] };

  const loadStore = options.loadSignatureStore ?? loadSignatureStore;
  const { store } = await loadStore(descartesPaths);
  if (!store.bootstrapped_at) return { candidates: [], evaluatedAlertKeys: [] };

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const lastAttemptMs = new Date(store.last_reconcile_attempt_at ?? store.last_reconciled_at ?? 0).getTime();
  const reconcileIntervalMs = options.identityReconcileIntervalMs ?? DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS;
  const due = !Number.isFinite(lastAttemptMs) || nowMs - lastAttemptMs >= reconcileIntervalMs;

  let currentStore = store;
  let evaluatedAlertKeys = [];
  if (due) {
    const collect = options.collectIdentityObservations ?? collectIdentityObservations;
    const collection = await collect(options);
    // Fail-safe: only an explicit, well-formed "ok" is a successful observation. A bare array, a
    // missing/unknown status, or a non-array observations field is DEGRADED.
    const observations = Array.isArray(collection?.observations) ? collection.observations : [];
    const collectionOk = collection?.status === "ok" && Array.isArray(collection?.observations);
    const ts = options.ts ?? new Date(nowMs).toISOString();
    const { store: reconciled, skippedObservations } = reconcileSignaturesDetailed(
      store,
      observations,
      { ts, iterationKey: ts, ...options, seedKnownGood: false },
    );
    if (collectionOk) {
      currentStore = {
        ...reconciled,
        last_reconciled_at: ts,
        last_reconcile_attempt_at: ts,
        last_reconcile_status: "ok",
        last_reconcile_degraded_reasons: [],
      };
    } else {
      const reasons = Array.isArray(collection?.reasons) && collection.reasons.length > 0
        ? collection.reasons
        : ["malformed_collection"];
      currentStore = {
        ...reconciled, // carries the store's previous last_reconciled_at through UNCHANGED
        last_reconcile_attempt_at: ts,
        last_reconcile_status: "degraded",
        last_reconcile_degraded_reasons: reasons,
      };
    }
    const writeStore = options.writeSignatureStore ?? writeSignatureStore;
    await writeStore(descartesPaths, currentStore);
    if (collectionOk) evaluatedAlertKeys = deriveIdentityCoverage(currentStore, { skippedObservations });
  }

  const candidates = deriveIdentityCandidates(currentStore, { now: nowMs, presenceWindowMs: options.identityPresenceWindowMs });
  return { candidates, evaluatedAlertKeys };
}

// Additive, exported for test-fixture reuse/clarity (mirrors provenance-store.js's own export of
// computeIdentitySignature) -- not otherwise used within this module.
export { computeIdentitySignature };
