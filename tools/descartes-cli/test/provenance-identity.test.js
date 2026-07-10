import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { loadSignatureStore, reconcileSignatures, writeSignatureStore } from "../src/provenance-store.js";
import {
  DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS,
  computeProvenanceIdentityCandidates,
  gatherIdentityObservations,
} from "../src/tools/provenance-identity.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-identity-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const OWN_UID = 501;
const OTHER_UID = 99;

const MIXED_PROCESSES = [
  { pid: 1, ppid: 0, uid: 0, command: "launchd" },
  { pid: 100, ppid: 1, uid: OWN_UID, command: "own-svc" },
  { pid: 200, ppid: 1, uid: OTHER_UID, command: "other-svc" },
];
const MIXED_SOCKETS = [
  { protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, pid: 100 },
  { protocol: "tcp", local_address: "0.0.0.0", local_port: 9090, pid: 200 },
];

function fakeCollectorOptions(overrides = {}) {
  return {
    ownUid: OWN_UID,
    listListeningSocketsWithPid: async () => MIXED_SOCKETS,
    snapshotProvenanceProcesses: async () => MIXED_PROCESSES,
    resolveExecutableInfo: async (pid) => ({ executable_path: `/opt/svc/${pid}/bin`, executable_path_unavailable: false }),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------------------------
// UID-scoping (plan section 5, hard invariant): an other-UID socket/pid is silently excluded --
// never a degraded-confidence observation.
// ---------------------------------------------------------------------------------------------

test("gatherIdentityObservations includes only own-UID pids, silently excluding an other-UID pid even though it has a resolvable pid (macOS-shaped lsof visibility)", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions());
  assert.equal(observations.length, 1);
  assert.equal(observations[0].target.value, 100);
  assert.equal(observations[0].owningUser, String(OWN_UID));
  assert.deepEqual(observations[0].portTargetKeys, ["tcp.8080"]);
});

test("gatherIdentityObservations returns [] when ownUid cannot be determined, never guessing", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions({ ownUid: undefined }));
  assert.deepEqual(observations, []);
});

test("gatherIdentityObservations never fabricates an identity around an unresolved executable path", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: undefined, executable_path_unavailable: true }),
  }));
  assert.deepEqual(observations, []);
});

// ---------------------------------------------------------------------------------------------
// BYTE-IDENTICAL-WHEN-DISABLED + DAY-1 NO-STORM.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceIdentityCandidates short-circuits to [] before any I/O when learned.json is disabled", async () => {
  const paths = await tempPaths();
  const result = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    loadSignatureStore: async () => {
      throw new Error("loadSignatureStore must not be called while the learned.json kill switch is off");
    },
  });
  assert.deepEqual(result, []);
});

test("computeProvenanceIdentityCandidates returns [] on a fresh (never-bootstrapped) signatures.json, without attempting any fresh host I/O -- day-1 no-storm", async () => {
  const paths = await tempPaths();
  let gathered = false;
  const result = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    gatherIdentityObservations: async () => {
      gathered = true;
      throw new Error("must not gather fresh observations before a snapshot baseline exists");
    },
  });
  assert.deepEqual(result, []);
  assert.equal(gathered, false);
});

test("day-1 no-storm holds regardless of how many distinct identities are currently running", async () => {
  const paths = await tempPaths();
  const manyProcesses = Array.from({ length: 20 }, (_, i) => ({ pid: 100 + i, ppid: 1, uid: OWN_UID, command: `svc${i}` }));
  const manySockets = manyProcesses.map((p, i) => ({ protocol: "tcp", local_address: "0.0.0.0", local_port: 9000 + i, pid: p.pid }));
  const result = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    // Even if fresh gathering WERE attempted (it must not be, per the gate above), returning a
    // large distinct-identity batch here must still never produce a candidate before bootstrap.
    listListeningSocketsWithPid: async () => manySockets,
    snapshotProvenanceProcesses: async () => manyProcesses,
    resolveExecutableInfo: async (pid) => ({ executable_path: `/opt/svc/${pid}/bin`, executable_path_unavailable: false }),
    ownUid: OWN_UID,
  });
  assert.deepEqual(result, []);
});

// ---------------------------------------------------------------------------------------------
// unknown_identity fires only after a snapshot baseline exists, and only once the new identity
// crosses the grace window (3 samples across 2 distinct iterations).
// ---------------------------------------------------------------------------------------------

test("unknown_identity does not fire for a brand-new identity on its first sighting after bootstrap (still provisional), but fires once it crosses the grace window", async () => {
  const paths = await tempPaths();

  // Bootstrap with an EMPTY baseline (operator ran `snapshot` with nothing else running yet).
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  const baseOptions = fakeCollectorOptions({
    identityReconcileIntervalMs: 0, // always due, for a deterministic test without racing DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS
    loadLearnedConfig: async () => ({ enabled: true }),
  });

  // Tick 1: first sighting of the new identity -- must not fire yet (still provisional).
  const tick1 = await computeProvenanceIdentityCandidates(paths, { ...baseOptions, now: "2026-07-10T01:00:00.000Z" });
  assert.deepEqual(tick1.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);

  // Tick 2: second distinct iteration -- 2 samples/2 iterations, still below the 3-sample bar.
  const tick2 = await computeProvenanceIdentityCandidates(paths, { ...baseOptions, now: "2026-07-10T02:00:00.000Z" });
  assert.deepEqual(tick2.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);

  // Tick 3: third distinct iteration -- 3 samples/3 iterations, crosses the grace window.
  const tick3 = await computeProvenanceIdentityCandidates(paths, { ...baseOptions, now: "2026-07-10T03:00:00.000Z" });
  const unknownIdentity = tick3.filter((c) => c.rule_id === "provenance.process.unknown_identity");
  assert.equal(unknownIdentity.length, 1);
  assert.match(unknownIdentity[0].diagnostics.identity_hash, /^[0-9a-f]{16}$/);

  // Also fires new_public_bind for the same (now-confirmed) identity's public port.
  const newPublicBind = tick3.filter((c) => c.rule_id === "provenance.port.new_public_bind");
  assert.equal(newPublicBind.length, 1);
  assert.equal(newPublicBind[0].diagnostics.local_port, 8080);
});

test("computeProvenanceIdentityCandidates rate-limits its own fresh host I/O: a second call within the reconcile interval reuses the persisted store instead of gathering again", async () => {
  const paths = await tempPaths();
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  let gatherCallCount = 0;
  const options = fakeCollectorOptions({
    loadLearnedConfig: async () => ({ enabled: true }),
    gatherIdentityObservations: async (opts) => {
      gatherCallCount += 1;
      return gatherIdentityObservations(opts);
    },
  });

  await computeProvenanceIdentityCandidates(paths, { ...options, now: "2026-07-10T01:00:00.000Z" });
  assert.equal(gatherCallCount, 1);

  // A second call moments later (well within DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS) must not
  // re-gather.
  await computeProvenanceIdentityCandidates(paths, { ...options, now: "2026-07-10T01:00:05.000Z" });
  assert.equal(gatherCallCount, 1, "must not perform fresh host I/O again inside the reconcile interval");

  // A call after the interval elapses gathers again.
  const laterNow = new Date(new Date("2026-07-10T01:00:00.000Z").getTime() + DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS + 1000).toISOString();
  await computeProvenanceIdentityCandidates(paths, { ...options, now: laterNow });
  assert.equal(gatherCallCount, 2);
});

// ---------------------------------------------------------------------------------------------
// identity_drift: a previously known_good identity's hash changes for the same target (e.g.
// executable replaced).
// ---------------------------------------------------------------------------------------------

test("identity_drift fires when a target's known_good identity_hash changes (executable replaced at the same path)", async () => {
  const paths = await tempPaths();
  const originalObservation = { executablePath: "/opt/svc/bin", sourceClassification: "launchd", owningUser: "0" };
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [originalObservation], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  // Simulate the executable being replaced: the path stays the same but the process is now
  // classified differently (a real content-hash/codesign change would also alter identity_hash,
  // but the store's executable_path_hash-keyed target index alone is enough to catch this since
  // computeIdentitySignature's inputs differ here via source_classification).
  const replaced = { ...originalObservation, sourceClassification: "shell" };
  const afterReplace = reconcileSignatures(bootstrapped, [replaced], { ts: "2026-07-10T01:00:00.000Z", iterationKey: "t2" });
  // Promote the replacement identity to known_good directly for this unit test's purposes
  // (identity_drift's own grace-window timing is exercised by the promotion boundary tests in
  // provenance-store.test.js; this test isolates the target-index/drift-detection logic).
  const [replacedHash] = Object.keys(afterReplace.signatures).filter((hash) => hash !== Object.keys(bootstrapped.signatures)[0]);
  afterReplace.signatures[replacedHash] = { ...afterReplace.signatures[replacedHash], state: "known_good", stable_sample_count: 3, stable_iteration_count: 2 };

  await writeSignatureStore(paths, { ...afterReplace, bootstrapped_at: "2026-07-10T00:00:00.000Z", last_reconciled_at: "2026-07-10T01:00:00.000Z" });

  const candidates = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    now: "2026-07-10T01:00:05.000Z", // within the reconcile interval -> no fresh gather, pure re-derive
  });
  const drift = candidates.filter((c) => c.rule_id === "provenance.process.identity_drift");
  assert.equal(drift.length, 1);
  assert.equal(drift[0].diagnostics.target_kind, "process");
  assert.notEqual(drift[0].diagnostics.old_identity_hash, drift[0].diagnostics.new_identity_hash);
});

// ---------------------------------------------------------------------------------------------
// Re-snapshotting clears a previously-firing deviation (drift/unknown/new_public_bind) --
// documented remediation path.
// ---------------------------------------------------------------------------------------------

test("re-running snapshot on the currently-observed identity clears a previously-firing unknown_identity", async () => {
  const paths = await tempPaths();
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  const options = fakeCollectorOptions({ loadLearnedConfig: async () => ({ enabled: true }), identityReconcileIntervalMs: 0 });
  for (const now of ["2026-07-10T01:00:00.000Z", "2026-07-10T02:00:00.000Z", "2026-07-10T03:00:00.000Z"]) {
    await computeProvenanceIdentityCandidates(paths, { ...options, now });
  }
  const beforeResnapshot = await computeProvenanceIdentityCandidates(paths, { ...options, now: "2026-07-10T04:00:00.000Z" });
  assert.ok(beforeResnapshot.some((c) => c.rule_id === "provenance.process.unknown_identity"));

  const observations = await gatherIdentityObservations(options);
  const { store } = await loadSignatureStore(paths);
  const reconciled = reconcileSignatures(store, observations, { ts: "2026-07-10T05:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...reconciled, bootstrapped_at: "2026-07-10T05:00:00.000Z", last_reconciled_at: "2026-07-10T05:00:00.000Z" });

  const afterResnapshot = await computeProvenanceIdentityCandidates(paths, { ...options, now: "2026-07-10T05:00:05.000Z" });
  assert.deepEqual(afterResnapshot.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);
});
