import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { alertId } from "../src/alert-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  NEW_PUBLIC_BIND_RULE_ID,
  UNKNOWN_IDENTITY_RULE_ID,
  computeExecutableStatFingerprint,
  computeIdentitySignature,
  loadSignatureStore,
  newPublicBindFingerprint,
  reconcileSignatures,
  unknownIdentityFingerprint,
  writeSignatureStore,
} from "../src/provenance-store.js";
import {
  DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS,
  collectIdentityObservations,
  computeProvenanceIdentityCandidates,
  gatherIdentityObservations,
} from "../src/tools/provenance-identity.js";

// computeProvenanceIdentityCandidates returns `{ candidates, evaluatedAlertKeys }` (plan 2026-09-20
// §8.B); the pre-coverage tests below only care about the candidates.
async function identityCandidates(descartesPaths, options) {
  return (await computeProvenanceIdentityCandidates(descartesPaths, options)).candidates;
}

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

// S5-follow-1 fixtures: two fs.stat-shaped fixtures for the identity_hash CONTENT-CHANGE
// fingerprint -- STAT_B simulates an in-place binary swap at the same dev/inode (later mtime).
const STAT_A = { dev: 1, ino: 111, size: 4096, mtimeMs: 1000 };
const STAT_B = { dev: 1, ino: 111, size: 4096, mtimeMs: 2000 };

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
  let statCalled = false;
  const observations = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: undefined, executable_path_unavailable: true }),
    statExecutablePath: async () => {
      statCalled = true;
      return STAT_A;
    },
  }));
  assert.deepEqual(observations, []);
  assert.equal(statCalled, false, "must never stat when the executable path itself is unresolved");
});

// ---------------------------------------------------------------------------------------------
// S5-follow-1: identity_hash populated from a bounded, single-fs.stat CONTENT-CHANGE fingerprint
// of the already-resolved executable path -- closes the identity_drift blind spot documented on
// deriveIdentityCandidates (an in-place binary swap at the same path/launcher/owner previously
// left identity_signature unchanged because identity_hash was always undefined).
// ---------------------------------------------------------------------------------------------

test("gatherIdentityObservations populates identityHash from a bounded fs.stat CONTENT-CHANGE fingerprint of the resolved executable path", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions({
    statExecutablePath: async () => STAT_A,
  }));
  assert.equal(observations.length, 1);
  assert.equal(observations[0].identityHash, computeExecutableStatFingerprint(STAT_A));
  assert.match(observations[0].identityHash, /^[0-9a-f]{16}$/);
});

test("gatherIdentityObservations: DEGRADE-NOT-FABRICATE -- a stat failure (ENOENT/permission/race) leaves identityHash undefined, never a fabricated value, and never throws", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions({
    statExecutablePath: async () => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
  }));
  assert.equal(observations.length, 1);
  assert.equal(observations[0].identityHash, undefined);
});

test("gatherIdentityObservations: BOUNDED I/O -- statExecutablePath is called exactly once per already-gathered own-UID identity, and never for an other-UID pid", async () => {
  const statedPaths = [];
  const observations = await gatherIdentityObservations(fakeCollectorOptions({
    statExecutablePath: async (execPath) => {
      statedPaths.push(execPath);
      return STAT_A;
    },
  }));
  assert.equal(observations.length, 1);
  // Only the own-UID pid (100) is ever stat'd; pid 200 (other-UID) is excluded before any
  // executable resolution or stat call happens for it at all.
  assert.deepEqual(statedPaths, ["/opt/svc/100/bin"]);
});

test("GAP CLOSED: a same-path/launcher/owner observation with a CHANGED executable stat-fingerprint yields a DIFFERENT identity_signature (so identity_drift can fire on an in-place swap)", async () => {
  const before = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: "/opt/svc/bin", executable_path_unavailable: false }),
    statExecutablePath: async () => STAT_A,
  }));
  const after = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: "/opt/svc/bin", executable_path_unavailable: false }),
    statExecutablePath: async () => STAT_B, // in-place swap: same dev/inode, later mtime
  }));

  assert.notEqual(before[0].identityHash, after[0].identityHash);
  const signatureBefore = computeIdentitySignature(before[0]);
  const signatureAfter = computeIdentitySignature(after[0]);
  assert.notEqual(
    signatureBefore,
    signatureAfter,
    "an in-place binary swap at the same path/launcher/owner must change identity_signature so identity_drift can fire",
  );
});

test("no spurious drift: an IDENTICAL executable stat across two observations of the same path/launcher/owner yields an IDENTICAL identity_signature", async () => {
  const first = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: "/opt/svc/bin", executable_path_unavailable: false }),
    statExecutablePath: async () => STAT_A,
  }));
  const second = await gatherIdentityObservations(fakeCollectorOptions({
    resolveExecutableInfo: async () => ({ executable_path: "/opt/svc/bin", executable_path_unavailable: false }),
    statExecutablePath: async () => ({ ...STAT_A }), // stable binary, unchanged stat
  }));
  assert.equal(computeIdentitySignature(first[0]), computeIdentitySignature(second[0]));
});

// ---------------------------------------------------------------------------------------------
// BYTE-IDENTICAL-WHEN-DISABLED + DAY-1 NO-STORM.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceIdentityCandidates short-circuits (no candidates, NO coverage) before any I/O when learned.json is disabled", async () => {
  const paths = await tempPaths();
  const result = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    loadSignatureStore: async () => {
      throw new Error("loadSignatureStore must not be called while the learned.json kill switch is off");
    },
  });
  assert.deepEqual(result, { candidates: [], evaluatedAlertKeys: [] });
});

test("computeProvenanceIdentityCandidates returns no candidates and NO coverage on a fresh (never-bootstrapped) signatures.json, without attempting any fresh host I/O -- day-1 no-storm", async () => {
  const paths = await tempPaths();
  let gathered = false;
  const result = await computeProvenanceIdentityCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    collectIdentityObservations: async () => {
      gathered = true;
      throw new Error("must not gather fresh observations before a snapshot baseline exists");
    },
  });
  assert.deepEqual(result, { candidates: [], evaluatedAlertKeys: [] });
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
  assert.deepEqual(result, { candidates: [], evaluatedAlertKeys: [] });
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
  const tick1 = await identityCandidates(paths, { ...baseOptions, now: "2026-07-10T01:00:00.000Z" });
  assert.deepEqual(tick1.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);

  // Tick 2: second distinct iteration -- 2 samples/2 iterations, still below the 3-sample bar.
  const tick2 = await identityCandidates(paths, { ...baseOptions, now: "2026-07-10T02:00:00.000Z" });
  assert.deepEqual(tick2.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);

  // Tick 3: third distinct iteration -- 3 samples/3 iterations, crosses the grace window.
  const tick3 = await identityCandidates(paths, { ...baseOptions, now: "2026-07-10T03:00:00.000Z" });
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
    collectIdentityObservations: async (opts) => {
      gatherCallCount += 1;
      return collectIdentityObservations(opts);
    },
  });

  await identityCandidates(paths, { ...options, now: "2026-07-10T01:00:00.000Z" });
  assert.equal(gatherCallCount, 1);

  // A second call moments later (well within DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS) must not
  // re-gather.
  await identityCandidates(paths, { ...options, now: "2026-07-10T01:00:05.000Z" });
  assert.equal(gatherCallCount, 1, "must not perform fresh host I/O again inside the reconcile interval");

  // A call after the interval elapses gathers again.
  const laterNow = new Date(new Date("2026-07-10T01:00:00.000Z").getTime() + DEFAULT_IDENTITY_RECONCILE_INTERVAL_MS + 1000).toISOString();
  await identityCandidates(paths, { ...options, now: laterNow });
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

  const candidates = await identityCandidates(paths, {
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
    await identityCandidates(paths, { ...options, now });
  }
  const beforeResnapshot = await identityCandidates(paths, { ...options, now: "2026-07-10T04:00:00.000Z" });
  assert.ok(beforeResnapshot.some((c) => c.rule_id === "provenance.process.unknown_identity"));

  const observations = await gatherIdentityObservations(options);
  const { store } = await loadSignatureStore(paths);
  const reconciled = reconcileSignatures(store, observations, { ts: "2026-07-10T05:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...reconciled, bootstrapped_at: "2026-07-10T05:00:00.000Z", last_reconciled_at: "2026-07-10T05:00:00.000Z" });

  const afterResnapshot = await identityCandidates(paths, { ...options, now: "2026-07-10T05:00:05.000Z" });
  assert.deepEqual(afterResnapshot.filter((c) => c.rule_id === "provenance.process.unknown_identity"), []);
});

// ---------------------------------------------------------------------------------------------
// Codex review finding #5, Part A -- end-to-end recovery: once the gatherer stops observing an
// identity (the process exits / the socket closes, so it no longer appears in
// listListeningSocketsWithPid's output), its last_seen stops advancing and, once the presence
// window elapses, computeProvenanceIdentityCandidates stops emitting a candidate for it.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceIdentityCandidates: recovery end-to-end -- once a confirmed-unknown identity's process disappears (gatherer stops observing it), the candidate stops firing after the presence window elapses", async () => {
  const paths = await tempPaths();
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  let sockets = MIXED_SOCKETS;
  const options = fakeCollectorOptions({
    identityReconcileIntervalMs: 0, // always due, for a deterministic test
    loadLearnedConfig: async () => ({ enabled: true }),
    listListeningSocketsWithPid: async () => sockets,
  });

  // 3 ticks to cross the grace window -> confirmed unknown_identity.
  await identityCandidates(paths, { ...options, now: "2026-07-10T01:00:00.000Z" });
  await identityCandidates(paths, { ...options, now: "2026-07-10T02:00:00.000Z" });
  const tick3 = await identityCandidates(paths, { ...options, now: "2026-07-10T03:00:00.000Z" });
  assert.ok(tick3.some((c) => c.rule_id === "provenance.process.unknown_identity"), "expected the identity to be confirmed unknown after crossing the grace window");

  // The process exits: no more sockets/pids observed from here on.
  sockets = [];

  const stillWithinWindow = await identityCandidates(paths, { ...options, now: "2026-07-10T04:00:00.000Z" });
  assert.ok(
    stillWithinWindow.some((c) => c.rule_id === "provenance.process.unknown_identity"),
    "must still fire while within the presence window even though the process just disappeared this tick",
  );

  // last_seen is frozen at tick3's ts (03:00) since no observation was folded for it after that;
  // 4h later is past the default 3h presence window.
  const afterWindow = await identityCandidates(paths, { ...options, now: "2026-07-10T07:00:00.000Z" });
  assert.deepEqual(afterWindow.filter((c) => c.rule_id === "provenance.process.unknown_identity"), [], "the candidate must recover once the process has been gone for longer than the presence window");
});

// ---------------------------------------------------------------------------------------------
// Codex review finding #5, Part B -- end-to-end: a single transient stat failure on an
// already-confirmed identity must not flip its stored signature or spuriously fire drift/unknown.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceIdentityCandidates: a single transient stat failure on an already-confirmed identity does not flip its signature or spuriously fire drift/unknown", async () => {
  const paths = await tempPaths();
  const bootstrapped = reconcileSignatures({ version: 1, signatures: {} }, [], { ts: "2026-07-10T00:00:00.000Z", seedKnownGood: true });
  await writeSignatureStore(paths, { ...bootstrapped, bootstrapped_at: "2026-07-10T00:00:00.000Z" });

  let statShouldFail = false;
  const options = fakeCollectorOptions({
    identityReconcileIntervalMs: 0,
    loadLearnedConfig: async () => ({ enabled: true }),
    statExecutablePath: async () => {
      if (statShouldFail) throw Object.assign(new Error("EPERM"), { code: "EPERM" });
      return STAT_A;
    },
  });

  await identityCandidates(paths, { ...options, now: "2026-07-10T01:00:00.000Z" });
  await identityCandidates(paths, { ...options, now: "2026-07-10T02:00:00.000Z" });
  const tick3 = await identityCandidates(paths, { ...options, now: "2026-07-10T03:00:00.000Z" });
  assert.ok(tick3.some((c) => c.rule_id === "provenance.process.unknown_identity"), "expected the identity to be confirmed unknown after crossing the grace window");

  const { store: beforeFailure } = await loadSignatureStore(paths);
  const hashesBefore = Object.keys(beforeFailure.signatures).sort();

  statShouldFail = true; // a single transient stat failure begins this tick
  const tick4 = await identityCandidates(paths, { ...options, now: "2026-07-10T04:00:00.000Z" });

  const { store: afterFailure } = await loadSignatureStore(paths);
  const hashesAfter = Object.keys(afterFailure.signatures).sort();
  assert.deepEqual(hashesAfter, hashesBefore, "a transient stat failure must not create a new signature bucket for an already-fingerprinted identity");
  assert.deepEqual(tick4.filter((c) => c.rule_id === "provenance.process.identity_drift"), [], "a transient stat failure must never itself be reported as identity_drift");
  // The original identity's own unknown_identity candidate must still be present too (last_seen
  // frozen at tick3's ts, well within the presence window) -- proves the observation was skipped
  // for this reconcile, not treated as "a different identity appeared".
  assert.ok(tick4.some((c) => c.rule_id === "provenance.process.unknown_identity"));
});

// ---------------------------------------------------------------------------------------------
// 2026-10 recovery coverage (plan 2026-09-20 §8, DEFERRED provenance-identity item): the gatherer
// surfaces collection success/failure honestly, and the reconcile only reports an identity as
// evaluated when THIS tick's collection genuinely and successfully re-observed the host.
// ---------------------------------------------------------------------------------------------

test("collectIdentityObservations: a complete census is status ok (other-UID pids are an in-scope exclusion, not a degradation)", async () => {
  const result = await collectIdentityObservations(fakeCollectorOptions());
  assert.equal(result.status, "ok");
  assert.deepEqual(result.reasons, []);
  assert.equal(result.observations.length, 1);
  assert.equal(result.observations[0].target.value, 100);
});

test("collectIdentityObservations: zero listeners from a successful census is a genuine ok-empty observation", async () => {
  let psCalled = false;
  const result = await collectIdentityObservations(fakeCollectorOptions({
    listListeningSocketsWithPidStatus: async () => ({ status: "ok", sockets: [], reasons: [] }),
    snapshotProvenanceProcessesStatus: async () => {
      psCalled = true;
      return { status: "ok", processes: MIXED_PROCESSES, reasons: [] };
    },
  }));
  assert.deepEqual(result, { status: "ok", observations: [], reasons: [] });
  assert.equal(psCalled, false);
});

test("collectIdentityObservations: a degraded socket census is DEGRADED (never a silent empty observation)", async () => {
  const result = await collectIdentityObservations(fakeCollectorOptions({
    listListeningSocketsWithPidStatus: async () => ({ status: "degraded", sockets: [], reasons: ["lsof_unavailable"] }),
  }));
  assert.equal(result.status, "degraded");
  assert.deepEqual(result.reasons, ["lsof_unavailable"]);
  assert.deepEqual(result.observations, []);
});

test("collectIdentityObservations: a degraded ps snapshot is DEGRADED", async () => {
  const result = await collectIdentityObservations(fakeCollectorOptions({
    snapshotProvenanceProcessesStatus: async () => ({ status: "degraded", processes: [], reasons: ["ps_unavailable"] }),
  }));
  assert.equal(result.status, "degraded");
  assert.ok(result.reasons.includes("ps_unavailable"));
  assert.deepEqual(result.observations, []);
});

test("collectIdentityObservations: an own-UID socket with an unattributed pid is DEGRADED even when the socket census says ok", async () => {
  const result = await collectIdentityObservations({
    ownUid: OWN_UID,
    listListeningSocketsWithPidStatus: async () => ({
      status: "ok",
      sockets: [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 9443, pid: undefined, uid: OWN_UID }],
      reasons: [],
    }),
    snapshotProvenanceProcessesStatus: async () => {
      throw new Error("must not need a process census when every pid is unattributed");
    },
  });
  assert.equal(result.status, "degraded");
  assert.deepEqual(result.reasons, ["own_uid_socket_unattributed"]);
  assert.deepEqual(result.observations, []);
});

test("collectIdentityObservations: status ok with a null sockets field is DEGRADED", async () => {
  const result = await collectIdentityObservations({
    ownUid: OWN_UID,
    listListeningSocketsWithPidStatus: async () => ({ status: "ok", sockets: null, reasons: [] }),
  });
  assert.equal(result.status, "degraded");
  assert.deepEqual(result.observations, []);
  assert.deepEqual(result.reasons, ["socket_census_degraded"]);
});

test("collectIdentityObservations: legacy array census seams are degraded without an explicit compatibility opt-in", async () => {
  const result = await collectIdentityObservations({
    ownUid: OWN_UID,
    listListeningSocketsWithPid: async () => [],
  });
  assert.equal(result.status, "degraded");
  assert.deepEqual(result.reasons, ["legacy_array_census"]);
});

test("collectIdentityObservations: an undeterminable own uid (with listeners present) is DEGRADED", async () => {
  const result = await collectIdentityObservations(fakeCollectorOptions({ ownUid: undefined }));
  assert.equal(result.status, "degraded");
  assert.deepEqual(result.reasons, ["own_uid_unknown"]);
  assert.deepEqual(result.observations, []);
});

test("collectIdentityObservations: a listener pid missing from the ps snapshot, or an own-UID pid whose executable cannot be resolved, is DEGRADED -- while the genuinely-resolved observations are still returned", async () => {
  const sockets = [...MIXED_SOCKETS, { protocol: "tcp", local_address: "0.0.0.0", local_port: 7000, pid: 300 }];
  const missingPid = await collectIdentityObservations(fakeCollectorOptions({ listListeningSocketsWithPid: async () => sockets }));
  assert.equal(missingPid.status, "degraded");
  assert.deepEqual(missingPid.reasons, ["pid_unresolved"]);
  assert.equal(missingPid.observations.length, 1, "pid 100 was genuinely observed and is still reported");

  const processes = [...MIXED_PROCESSES, { pid: 300, ppid: 1, uid: OWN_UID, command: "ghost" }];
  const unresolvedExe = await collectIdentityObservations(fakeCollectorOptions({
    listListeningSocketsWithPid: async () => sockets,
    snapshotProvenanceProcesses: async () => processes,
    resolveExecutableInfo: async (pid) => (pid === 300
      ? { executable_path: undefined, executable_path_unavailable: true }
      : { executable_path: `/opt/svc/${pid}/bin`, executable_path_unavailable: false }),
  }));
  assert.equal(unresolvedExe.status, "degraded");
  assert.deepEqual(unresolvedExe.reasons, ["executable_unresolved"]);
  assert.equal(unresolvedExe.observations.length, 1);
});

test("gatherIdentityObservations (legacy, snapshot CLI) still returns the bare observation array", async () => {
  const observations = await gatherIdentityObservations(fakeCollectorOptions());
  assert.ok(Array.isArray(observations));
  assert.equal(observations.length, 1);
});

const T0 = "2026-07-10T00:00:00.000Z";
const CONFIRMED_OBSERVATION = {
  executablePath: "/opt/acme/bin/worker",
  identityHash: "abcdabcdabcdabcd",
  sourceClassification: "shell",
  owningUser: String(OWN_UID),
  target: { kind: "pid", value: 100 },
  portTargetKeys: ["tcp.9500"],
};

// Seeds a bootstrapped store holding one confirmed-unknown identity (grace window crossed, never
// operator-baselined), last observed + last successfully reconciled at T0.
async function seedConfirmedIdentity(paths) {
  let store = { version: 1, signatures: {} };
  store = reconcileSignatures(store, [CONFIRMED_OBSERVATION], { ts: T0, iterationKey: "seed-1" });
  store = reconcileSignatures(store, [CONFIRMED_OBSERVATION], { ts: T0, iterationKey: "seed-2" });
  store = reconcileSignatures(store, [CONFIRMED_OBSERVATION], { ts: T0, iterationKey: "seed-2" });
  await writeSignatureStore(paths, { ...store, bootstrapped_at: T0, last_reconciled_at: T0 });
  const identityHash = computeIdentitySignature(CONFIRMED_OBSERVATION);
  return {
    identityHash,
    unknownKey: alertId(UNKNOWN_IDENTITY_RULE_ID, unknownIdentityFingerprint(identityHash)),
    bindKey: alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.9500")),
  };
}

function coverageOptions(collect) {
  return { loadLearnedConfig: async () => ({ enabled: true }), collectIdentityObservations: collect };
}
const okCollection = (observations) => async () => ({ status: "ok", observations, reasons: [] });
const hoursAfterT0 = (hours) => new Date(Date.parse(T0) + hours * 60 * 60 * 1000).toISOString();

test("coverage: a PRESENT identity re-observed by a successful collection is reported evaluated (and still fires)", async () => {
  const paths = await tempPaths();
  const { unknownKey, bindKey } = await seedConfirmedIdentity(paths);
  const now = hoursAfterT0(1);
  const result = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(okCollection([CONFIRMED_OBSERVATION])), now });
  assert.ok(result.candidates.some((c) => c.id === unknownKey), "present identity still fires");
  assert.ok(result.candidates.some((c) => c.id === bindKey));
  assert.ok(result.evaluatedAlertKeys.includes(unknownKey), "present identity is evaluated");
  assert.ok(result.evaluatedAlertKeys.includes(bindKey));
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, now);
  assert.equal(store.last_reconcile_attempt_at, now);
  assert.equal(store.last_reconcile_status, "ok");
});

test("coverage: GENUINE ABSENCE after a successful observation (gone past the presence window) is evaluated-clear -- no candidate, key reported", async () => {
  const paths = await tempPaths();
  const { unknownKey, bindKey } = await seedConfirmedIdentity(paths);
  const now = hoursAfterT0(4); // past the 3h presence window
  const result = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(okCollection([])), now });
  assert.equal(result.candidates.some((c) => c.id === unknownKey), false);
  assert.ok(result.evaluatedAlertKeys.includes(unknownKey), "successfully looked for and not found -> evaluated-clear");
  assert.ok(result.evaluatedAlertKeys.includes(bindKey));
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, now);
});

test("coverage: a DEGRADED collection does NOT advance last_reconciled_at or last_seen, reports NO coverage (no departure inferred), and still rate-limits host I/O via the attempt clock", async () => {
  const paths = await tempPaths();
  const { identityHash, unknownKey } = await seedConfirmedIdentity(paths);
  let collectCalls = 0;
  const degraded = async () => {
    collectCalls += 1;
    return { status: "degraded", observations: [], reasons: ["lsof_unavailable"] };
  };

  const degradedTick = hoursAfterT0(4); // the identity has aged past the presence window
  const result = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(degraded), now: degradedTick });
  assert.deepEqual(result.evaluatedAlertKeys, [], "a degraded collection must never report an identity evaluated");
  assert.equal(result.evaluatedAlertKeys.includes(unknownKey), false);

  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, T0, "last_reconciled_at must not advance on a degraded collection");
  assert.equal(store.last_reconcile_attempt_at, degradedTick, "the attempt clock advances so host I/O stays rate-limited");
  assert.equal(store.last_reconcile_status, "degraded");
  assert.deepEqual(store.last_reconcile_degraded_reasons, ["lsof_unavailable"]);
  assert.equal(store.signatures[identityHash].last_seen, T0, "last_seen must not advance on a degraded collection");

  // Within the reconcile interval of the degraded ATTEMPT: no fresh host I/O, still no coverage.
  const retry = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(degraded), now: hoursAfterT0(4.1) });
  assert.equal(collectCalls, 1, "a degraded host must not be re-probed every fast tick");
  assert.deepEqual(retry.evaluatedAlertKeys, []);

  // Once a later collection genuinely succeeds, coverage is restored.
  const recovered = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(okCollection([])), now: hoursAfterT0(5.1) });
  assert.ok(recovered.evaluatedAlertKeys.includes(unknownKey));
});

test("coverage: a PARTIALLY degraded collection folds only its genuinely-resolved observations, but still reports NO coverage and does not advance last_reconciled_at", async () => {
  const paths = await tempPaths();
  const { identityHash } = await seedConfirmedIdentity(paths);
  const now = hoursAfterT0(1);
  const result = await computeProvenanceIdentityCandidates(paths, {
    ...coverageOptions(async () => ({ status: "degraded", observations: [CONFIRMED_OBSERVATION], reasons: ["pid_unresolved"] })),
    now,
  });
  assert.deepEqual(result.evaluatedAlertKeys, []);
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, T0);
  assert.equal(store.signatures[identityHash].last_seen, now, "a genuinely-resolved observation is real presence and is folded");
});

test("coverage: a malformed collector result (bare array / missing status) is treated as DEGRADED, never as a successful observation", async () => {
  const paths = await tempPaths();
  const { unknownKey } = await seedConfirmedIdentity(paths);
  const result = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(async () => []), now: hoursAfterT0(4) });
  assert.equal(result.evaluatedAlertKeys.includes(unknownKey), false);
  assert.deepEqual(result.evaluatedAlertKeys, []);
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, T0);
  assert.equal(store.last_reconcile_status, "degraded");
});

test("coverage: a NON-DUE tick (no fresh host I/O) reports no coverage but keeps emitting present candidates", async () => {
  const paths = await tempPaths();
  const { unknownKey } = await seedConfirmedIdentity(paths);
  let collected = false;
  const result = await computeProvenanceIdentityCandidates(paths, {
    ...coverageOptions(async () => {
      collected = true;
      return { status: "ok", observations: [], reasons: [] };
    }),
    now: hoursAfterT0(0.1),
  });
  assert.equal(collected, false);
  assert.ok(result.candidates.some((c) => c.id === unknownKey));
  assert.deepEqual(result.evaluatedAlertKeys, []);
});

test("coverage: an identity whose observation was skipped as a transient stat failure (running but unverified) is NOT reported evaluated, even on an otherwise successful collection", async () => {
  const paths = await tempPaths();
  const { identityHash, unknownKey, bindKey } = await seedConfirmedIdentity(paths);
  const unverified = { ...CONFIRMED_OBSERVATION, identityHash: undefined };
  const result = await computeProvenanceIdentityCandidates(paths, { ...coverageOptions(okCollection([unverified])), now: hoursAfterT0(4) });
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.signatures[identityHash].last_seen, T0, "the unverified identity was not re-observed");
  assert.equal(result.candidates.some((c) => c.id === unknownKey), false, "aged past the presence window");
  assert.equal(result.evaluatedAlertKeys.includes(unknownKey), false, "running-but-unverified must never be evaluated-clear");
  assert.equal(result.evaluatedAlertKeys.includes(bindKey), false);
});

test("coverage: a malformed ok collection is degraded, reports no coverage, and preserves last_reconciled_at", async () => {
  const paths = await tempPaths();
  const { unknownKey } = await seedConfirmedIdentity(paths);
  const now = hoursAfterT0(4);
  const result = await computeProvenanceIdentityCandidates(paths, {
    ...coverageOptions(async () => ({ status: "ok", observations: "x" })),
    now,
  });
  assert.deepEqual(result.evaluatedAlertKeys, []);
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, T0);
  assert.equal(store.last_reconcile_status, "degraded");
  assert.ok(result.candidates.some((candidate) => candidate.id === unknownKey) === false);
});
