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

import { loadLearnedConfig } from "../constraint-store.js";
import {
  computeIdentitySignature,
  deriveIdentityCandidates,
  loadSignatureStore,
  reconcileSignatures,
  writeSignatureStore,
} from "../provenance-store.js";
import { buildParentTreeResult } from "./processes.js";
import { classifySourceFromAncestry, isPublicBindAddress, resolveExecutableInfo } from "./provenance.js";
import { listListeningSocketsWithPid, snapshotProvenanceProcesses } from "./provenance-warnings.js";

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
  const platform = options.platform ?? process.platform;
  const listSockets = options.listListeningSocketsWithPid ?? listListeningSocketsWithPid;
  const sockets = await listSockets(platform, options);

  const pids = [...new Set(sockets.map((socket) => socket.pid).filter((pid) => Number.isInteger(pid)))];
  if (pids.length === 0) return [];

  const snapshotProcesses = options.snapshotProvenanceProcesses ?? snapshotProvenanceProcesses;
  const processes = await snapshotProcesses(platform, options);
  const processByPid = new Map(processes.map((item) => [item.pid, item]));

  const ownUid = options.ownUid !== undefined
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

  for (const pid of pids) {
    const processRecord = processByPid.get(pid);
    if (!processRecord || ownUid === undefined || processRecord.uid !== ownUid) continue; // UID-scoped: silent skip, never degraded.

    const ancestryChain = buildAncestryChain(processes, pid, maxAncestryDepth);
    const source = classifySourceFromAncestry(ancestryChain);
    const executableInfo = await resolveExeInfo(pid);
    const executablePath = executableInfo?.executable_path;
    if (!executablePath) continue; // Never fabricate an identity around an unresolved path.

    const pidSockets = socketsByPid.get(pid) ?? [];
    const publicPortKeys = [
      ...new Set(
        pidSockets
          .filter((socket) => isPublicBindAddress(socket.local_address))
          .map((socket) => `${socket.protocol}.${socket.local_port}`),
      ),
    ];

    observations.push({
      executablePath,
      // See provenance-store.js's module header: always absent in this build (documented,
      // bounded-I/O deviation), never fabricated.
      identityHash: undefined,
      sourceClassification: source.type,
      owningUser: String(processRecord.uid),
      target: { kind: "pid", value: pid },
      portTargetKeys: publicPortKeys,
    });
  }

  return observations;
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
 */
export async function computeProvenanceIdentityCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const loadStore = options.loadSignatureStore ?? loadSignatureStore;
  const { store } = await loadStore(descartesPaths);
  if (!store.bootstrapped_at) return [];

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const lastReconciledMs = new Date(store.last_reconciled_at ?? 0).getTime();
  const reconcileIntervalMs = options.identityReconcileIntervalMs ?? DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS;
  const due = !Number.isFinite(lastReconciledMs) || nowMs - lastReconciledMs >= reconcileIntervalMs;

  let currentStore = store;
  if (due) {
    const gather = options.gatherIdentityObservations ?? gatherIdentityObservations;
    const observations = await gather(options);
    const ts = options.ts ?? new Date(nowMs).toISOString();
    const reconciled = reconcileSignatures(store, observations, { ts, iterationKey: ts, ...options, seedKnownGood: false });
    currentStore = { ...reconciled, last_reconciled_at: ts };
    const writeStore = options.writeSignatureStore ?? writeSignatureStore;
    await writeStore(descartesPaths, currentStore);
  }

  return deriveIdentityCandidates(currentStore);
}

// Additive, exported for test-fixture reuse/clarity (mirrors provenance-store.js's own export of
// computeIdentitySignature) -- not otherwise used within this module.
export { computeIdentitySignature };
