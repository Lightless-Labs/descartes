import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { alertId } from "../src/alert-store.js";
import {
  DEFAULT_STABLE_ITERATION_THRESHOLD,
  DEFAULT_STABLE_SAMPLE_THRESHOLD,
  IDENTITY_DRIFT_RULE_ID,
  NEW_PUBLIC_BIND_RULE_ID,
  UNKNOWN_IDENTITY_RULE_ID,
  applyIdentityObservation,
  computeIdentitySignature,
  deriveIdentityCandidates,
  deriveIdentityCoverage,
  identityDriftFingerprint,
  loadSignatureStore,
  newPublicBindFingerprint,
  normalizeSignatureStore,
  reconcileSignatures,
  reconcileSignaturesDetailed,
  unknownIdentityFingerprint,
  resolveSignatureStorePaths,
  runProvenanceStore,
  seedKnownGoodIdentity,
  writeSignatureStore,
} from "../src/provenance-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// ---------------------------------------------------------------------------------------------
// TDD item 1 (S5, plan section 5): THE GOLDEN FIXTURE, written/locked BEFORE any
// promotion-state-machine or candidate code exists. Pins the exact hashing inputs and their
// exact serialization so identity_signature can never silently drift:
//
//   identity_signature = sha256hex(
//     [executable_path, identity_hash, source_classification, owning_user]
//       .map(v => (v === undefined || v === null) ? "" : String(v))
//       .join("\u0000")          // NUL-byte delimiter, mirroring alert-store.js's alertId()
//   ).slice(0, 16)                // 16 hex chars -- a fixed length isFixedLengthHexHash allows
//
// Field order is fixed: executable_path, identity_hash (exe content hash OR codesign identity --
// may be absent, see provenance-store.js module header for why this build always passes it as
// undefined), source_classification, owning_user. A missing field normalizes to an empty-string
// component -- it is NEVER omitted from the join, so the delimiter count (and therefore the
// hashed byte layout) never varies by which fields happen to be present.
//
// These expected hash strings were computed independently via the LOCKED algorithm above (see
// scratchpad compute-fixture2.mjs), not by running this module's own (not-yet-written, at the
// time this test was authored) implementation -- this is what "pinned before behavior is
// written" means in practice.
// ---------------------------------------------------------------------------------------------

const GOLDEN_FIXTURE_INPUTS = {
  executablePath: "/usr/local/bin/nginx",
  identityHash: "sha256:abc123deadbeef",
  sourceClassification: "launchd",
  owningUser: "0",
};
const GOLDEN_FIXTURE_HASH = "0789cc3849eda84d";

test("computeIdentitySignature reproduces the golden fixture hash exactly", () => {
  assert.equal(computeIdentitySignature(GOLDEN_FIXTURE_INPUTS), GOLDEN_FIXTURE_HASH);
  assert.match(GOLDEN_FIXTURE_HASH, /^[0-9a-f]{16}$/);
});

test("computeIdentitySignature: additional pinned fixtures (no identity_hash component, an unrelated tuple, and the all-absent tuple)", () => {
  assert.equal(
    computeIdentitySignature({
      executablePath: "/usr/local/bin/nginx",
      identityHash: undefined,
      sourceClassification: "launchd",
      owningUser: "0",
    }),
    "45cda60d87f16e07",
  );
  assert.equal(
    computeIdentitySignature({
      executablePath: "/opt/acme/bin/worker",
      identityHash: undefined,
      sourceClassification: "systemd",
      owningUser: "1000",
    }),
    "75aa2dd648bcc30b",
  );
  assert.equal(computeIdentitySignature({}), "709e80c88487a241");
});

// ---------------------------------------------------------------------------------------------
// TDD item 2: hash stability -- same inputs across two calls -> identical hash; one differing
// input (owning_user) -> a different hash.
// ---------------------------------------------------------------------------------------------

test("computeIdentitySignature is stable across repeated calls with identical inputs", () => {
  const first = computeIdentitySignature(GOLDEN_FIXTURE_INPUTS);
  const second = computeIdentitySignature({ ...GOLDEN_FIXTURE_INPUTS });
  assert.equal(first, second);
});

test("computeIdentitySignature changes when exactly one input (owning_user) differs", () => {
  const base = computeIdentitySignature(GOLDEN_FIXTURE_INPUTS);
  const differentOwner = computeIdentitySignature({ ...GOLDEN_FIXTURE_INPUTS, owningUser: "1000" });
  assert.notEqual(base, differentOwner);
  assert.equal(differentOwner, "8172784e92d78c0d");
});

test("computeIdentitySignature changes when exactly one input (executable_path) differs, all else equal", () => {
  const base = computeIdentitySignature(GOLDEN_FIXTURE_INPUTS);
  const differentPath = computeIdentitySignature({ ...GOLDEN_FIXTURE_INPUTS, executablePath: "/usr/local/bin/nginx-evil" });
  assert.notEqual(base, differentPath);
});

test("computeIdentitySignature changes when exactly one input (source_classification) differs, all else equal", () => {
  const base = computeIdentitySignature(GOLDEN_FIXTURE_INPUTS);
  const differentSource = computeIdentitySignature({ ...GOLDEN_FIXTURE_INPUTS, sourceClassification: "shell" });
  assert.notEqual(base, differentSource);
});

// ---------------------------------------------------------------------------------------------
// TDD item 3: provisional -> known_good promotion boundary, table-driven. Grace window:
// stable_sample_count >= 3 AND stable_iteration_count >= 2 DISTINCT structural ticks.
// ---------------------------------------------------------------------------------------------

test("applyIdentityObservation: exactly threshold-1 samples across the required distinct iterations stays provisional; one more sample crosses into known_good", () => {
  let record;
  // Tick 1 (iterationKey "t1"): first sample, first iteration.
  record = applyIdentityObservation(record, { executablePath: "/bin/x" }, { ts: "2026-07-10T00:00:00.000Z", iterationKey: "t1" });
  assert.equal(record.state, "provisional");
  assert.equal(record.stable_sample_count, 1);
  assert.equal(record.stable_iteration_count, 1);

  // Tick 2 (iterationKey "t2"): second sample, second (distinct) iteration -- still below the
  // sample threshold (2 < 3), so still provisional despite already meeting the iteration bar.
  record = applyIdentityObservation(record, { executablePath: "/bin/x" }, { ts: "2026-07-10T01:00:00.000Z", iterationKey: "t2" });
  assert.equal(record.state, "provisional");
  assert.equal(record.stable_sample_count, 2);
  assert.equal(record.stable_iteration_count, 2);

  // One more sample WITHIN the same tick "t2" (not a new distinct iteration) crosses the sample
  // threshold (3) while iteration_count stays at 2 (already >= the iteration threshold) ->
  // known_good. Proves samples and iterations are independently gated, and a second sample
  // within one tick does NOT bump iteration_count.
  record = applyIdentityObservation(record, { executablePath: "/bin/x" }, { ts: "2026-07-10T01:05:00.000Z", iterationKey: "t2" });
  assert.equal(record.stable_sample_count, 3);
  assert.equal(record.stable_iteration_count, 2);
  assert.equal(record.state, "known_good");
});

test("applyIdentityObservation: sample threshold met within a single tick, but iteration threshold not met, stays provisional", () => {
  let record;
  for (let i = 0; i < DEFAULT_STABLE_SAMPLE_THRESHOLD; i += 1) {
    record = applyIdentityObservation(record, { executablePath: "/bin/y" }, { ts: "2026-07-10T00:00:00.000Z", iterationKey: "only-one-tick" });
  }
  assert.equal(record.stable_sample_count, DEFAULT_STABLE_SAMPLE_THRESHOLD);
  assert.equal(record.stable_iteration_count, 1);
  assert.ok(1 < DEFAULT_STABLE_ITERATION_THRESHOLD);
  assert.equal(record.state, "provisional");
});

test("applyIdentityObservation: once known_good, a record never reverts to provisional on subsequent observations", () => {
  let record;
  record = applyIdentityObservation(record, { executablePath: "/bin/z" }, { ts: "t0", iterationKey: "i1" });
  record = applyIdentityObservation(record, { executablePath: "/bin/z" }, { ts: "t1", iterationKey: "i2" });
  record = applyIdentityObservation(record, { executablePath: "/bin/z" }, { ts: "t2", iterationKey: "i2" });
  assert.equal(record.state, "known_good");
  // A later observation in a brand-new iteration must not undo the known_good state.
  record = applyIdentityObservation(record, { executablePath: "/bin/z" }, { ts: "t3", iterationKey: "i3" });
  assert.equal(record.state, "known_good");
});

test("seedKnownGoodIdentity forces known_good/origin:snapshot regardless of sample/iteration counts", () => {
  const record = seedKnownGoodIdentity(undefined, { executablePath: "/bin/w" }, { ts: "2026-07-10T00:00:00.000Z", iterationKey: "snap-1" });
  assert.equal(record.state, "known_good");
  assert.equal(record.origin, "snapshot");
  assert.equal(record.stable_sample_count, 1);
});

// ---------------------------------------------------------------------------------------------
// TDD item 9: atomic write + corrupt-file tolerance for signatures.json, mirroring
// history-store.js's/constraint-store.js's own pattern (tmp+rename, 0o600).
// ---------------------------------------------------------------------------------------------

test("writeSignatureStore/loadSignatureStore round-trips atomically (tmp+rename, 0o600)", async () => {
  const paths = await tempPaths();
  const store = reconcileSignatures(
    { version: 1, signatures: {} },
    [{ executablePath: "/bin/a", sourceClassification: "launchd", owningUser: "0" }],
    { ts: "2026-07-10T00:00:00.000Z", iterationKey: "t1" },
  );
  await writeSignatureStore(paths, store);

  const { signaturesFile } = resolveSignatureStorePaths(paths);
  const stat = await fs.stat(signaturesFile);
  assert.equal(stat.mode & 0o777, 0o600);

  const { store: reloaded, corrupt } = await loadSignatureStore(paths);
  assert.equal(corrupt, false);
  assert.equal(Object.keys(reloaded.signatures).length, 1);
});

test("loadSignatureStore tolerates a missing file (fresh state) by returning an empty store, not throwing", async () => {
  const paths = await tempPaths();
  const { store, corrupt } = await loadSignatureStore(paths);
  assert.deepEqual(store.signatures, {});
  assert.equal(store.bootstrapped_at, undefined);
  assert.equal(corrupt, false);
});

test("loadSignatureStore tolerates a corrupt signatures.json by returning an empty store and flagging corrupt", async () => {
  const paths = await tempPaths();
  const { signaturesFile, dir } = resolveSignatureStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(signaturesFile, "{ not valid json", { mode: 0o600 });

  const { store, corrupt } = await loadSignatureStore(paths);
  assert.equal(corrupt, true);
  assert.deepEqual(store.signatures, {});
});

// ---------------------------------------------------------------------------------------------
// Day-1 no-storm + snapshot-gated firing, unknown_identity / identity_drift / new_public_bind --
// exercised more thoroughly end-to-end in test/provenance-identity.test.js; these are the pure
// deriveIdentityCandidates()-level unit tests.
// ---------------------------------------------------------------------------------------------

test("deriveIdentityCandidates returns [] for a store that has never been bootstrapped (snapshot never run), regardless of signature contents", () => {
  const store = reconcileSignatures(
    { version: 1, signatures: {} },
    [
      { executablePath: "/bin/a", sourceClassification: "launchd", owningUser: "0" },
      { executablePath: "/bin/b", sourceClassification: "systemd", owningUser: "0" },
      { executablePath: "/bin/c", sourceClassification: "shell", owningUser: "0" },
    ],
    { ts: "2026-07-10T00:00:00.000Z", iterationKey: "t1" },
  );
  assert.equal(store.bootstrapped_at, undefined);
  assert.deepEqual(deriveIdentityCandidates(store), []);
});

test("deriveIdentityCandidates fires unknown_identity only for a known_good/grace_window identity, never for snapshot-origin or still-provisional identities", () => {
  const bootstrappedNoDeviation = {
    version: 1,
    bootstrapped_at: "2026-07-10T00:00:00.000Z",
    signatures: {
      snapshot_origin: {
        state: "known_good",
        origin: "snapshot",
        last_seen: "2026-07-10T00:00:00.000Z",
        stable_sample_count: 1,
        stable_iteration_count: 1,
        inputs_hash: { executable_path_hash: "aaaa000000000000", source_classification: "launchd" },
        port_target_keys: [],
      },
      still_provisional: {
        state: "provisional",
        origin: "grace_window",
        last_seen: "2026-07-10T00:00:00.000Z",
        stable_sample_count: 1,
        stable_iteration_count: 1,
        inputs_hash: { executable_path_hash: "bbbb000000000000", source_classification: "shell" },
        port_target_keys: [],
      },
    },
  };
  // "now" pinned close to the fixtures' own last_seen timestamps -- deriveIdentityCandidates'
  // presence-window recovery gate (S5-follow-2) filters by (now - last_seen), so an explicit,
  // nearby "now" is required for these fixed-date fixtures regardless of wall-clock time.
  assert.deepEqual(deriveIdentityCandidates(bootstrappedNoDeviation, { now: "2026-07-10T00:30:00.000Z" }), []);

  const withConfirmedUnknown = {
    ...bootstrappedNoDeviation,
    signatures: {
      ...bootstrappedNoDeviation.signatures,
      confirmed_unknown: {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T02:00:00.000Z",
        stable_sample_count: 3,
        stable_iteration_count: 2,
        inputs_hash: { executable_path_hash: "cccc000000000000", source_classification: "shell" },
        port_target_keys: [],
      },
    },
  };
  const candidates = deriveIdentityCandidates(withConfirmedUnknown, { now: "2026-07-10T02:15:00.000Z" });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, "provenance.process.unknown_identity");
  assert.equal(candidates[0].diagnostics.identity_hash, "confirmed_unknown");
});

// ---------------------------------------------------------------------------------------------
// TDD item 10: sanitizeDiagnostics() rejection extended to the three new rule_ids -- a malformed
// (raw-shaped) field smuggled into a store record must never pass through verbatim.
// ---------------------------------------------------------------------------------------------

test("deriveIdentityCandidates: a raw path smuggled into source_classification is redacted, never passed through verbatim", () => {
  const store = {
    version: 1,
    bootstrapped_at: "2026-07-10T00:00:00.000Z",
    signatures: {
      confirmed_unknown: {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T02:00:00.000Z",
        stable_sample_count: 3,
        stable_iteration_count: 2,
        inputs_hash: { executable_path_hash: "cccc000000000000", source_classification: "/usr/local/bin/suspicious" },
        port_target_keys: [],
      },
    },
  };
  const [candidate] = deriveIdentityCandidates(store, { now: "2026-07-10T02:10:00.000Z" });
  assert.ok(candidate);
  assert.equal(candidate.diagnostics.source_type.redacted, true);
  assert.equal(JSON.stringify(candidate.diagnostics).includes("/usr/local/bin"), false);
});

// ---------------------------------------------------------------------------------------------
// Codex review finding #5, Part A -- recovery via presence/last_seen gating. A candidate must
// only fire while its record is currently present (recent last_seen); once unseen for longer than
// DEFAULT_IDENTITY_PRESENCE_WINDOW_MS, it must stop firing (the process exited / the socket
// closed), and a still-present identity must never falsely recover between reconciles.
// ---------------------------------------------------------------------------------------------

test("deriveIdentityCandidates: recovery -- unknown_identity/new_public_bind stop firing once the record's last_seen ages past the presence window (process exited / socket closed)", () => {
  const record = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T00:00:00.000Z",
    stable_sample_count: 3,
    stable_iteration_count: 2,
    inputs_hash: { executable_path_hash: "cccc000000000000", source_classification: "shell" },
    port_target_keys: ["tcp.8080"],
  };
  const store = { version: 1, bootstrapped_at: "2026-07-09T00:00:00.000Z", signatures: { confirmed_unknown: record } };

  const present = deriveIdentityCandidates(store, { now: "2026-07-10T00:30:00.000Z" });
  assert.equal(present.filter((c) => c.rule_id === "provenance.process.unknown_identity").length, 1);
  assert.equal(present.filter((c) => c.rule_id === "provenance.port.new_public_bind").length, 1);

  // 10h later: well past the (default 3h) presence window -- the process/socket has presumably
  // disappeared, so both candidates must recover to nothing.
  const gone = deriveIdentityCandidates(store, { now: "2026-07-10T10:00:00.000Z" });
  assert.deepEqual(gone, [], "once unseen for longer than the presence window, both candidates must recover to nothing");
});

test("deriveIdentityCandidates: identity_drift recovers once the stale (superseded) identity ages out of the presence window", () => {
  const stale = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T00:00:00.000Z",
    stable_sample_count: 3,
    stable_iteration_count: 2,
    inputs_hash: { executable_path_hash: "shared0000000000", source_classification: "launchd" },
    port_target_keys: [],
  };
  const currentEarly = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T01:00:00.000Z",
    stable_sample_count: 3,
    stable_iteration_count: 2,
    inputs_hash: { executable_path_hash: "shared0000000000", source_classification: "shell" },
    port_target_keys: [],
  };
  const storeAfterSwap = {
    version: 1,
    bootstrapped_at: "2026-07-09T00:00:00.000Z",
    signatures: { stale_identity: stale, current_identity: currentEarly },
  };

  // Shortly after the swap: both the stale and the current identity are still within the
  // presence window -> drift fires.
  const driftPresent = deriveIdentityCandidates(storeAfterSwap, { now: "2026-07-10T01:15:00.000Z" });
  assert.equal(driftPresent.filter((c) => c.rule_id === "provenance.process.identity_drift").length, 1);

  // Later: several more reconciles have kept refreshing current_identity's last_seen, but
  // stale_identity was never observed again -- once its last_seen ages past the window, drift
  // must resolve (only one present identity remains in the target-key group).
  const storeLater = {
    ...storeAfterSwap,
    signatures: {
      stale_identity: stale, // unchanged -- last_seen frozen at 00:00:00, never re-observed.
      current_identity: { ...currentEarly, last_seen: "2026-07-10T05:00:00.000Z" },
    },
  };
  const driftRecovered = deriveIdentityCandidates(storeLater, { now: "2026-07-10T05:05:00.000Z" });
  assert.deepEqual(driftRecovered.filter((c) => c.rule_id === "provenance.process.identity_drift"), []);
});

test("deriveIdentityCandidates: a still-present identity (last reconciled just under one reconcile cadence ago) keeps firing -- no false recovery between reconciles", () => {
  const record = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T00:00:00.000Z",
    stable_sample_count: 3,
    stable_iteration_count: 2,
    inputs_hash: { executable_path_hash: "dddd000000000000", source_classification: "shell" },
    port_target_keys: [],
  };
  const store = { version: 1, bootstrapped_at: "2026-07-09T00:00:00.000Z", signatures: { still_here: record } };
  // 55 minutes later -- just under the ~1h daemon-wired reconcile cadence, comfortably inside the
  // (default 3h) presence window.
  const candidates = deriveIdentityCandidates(store, { now: "2026-07-10T00:55:00.000Z" });
  assert.equal(candidates.filter((c) => c.rule_id === "provenance.process.unknown_identity").length, 1);
});

// ---------------------------------------------------------------------------------------------
// Codex review finding #5, Part B -- a transient stat failure (identityHash undefined) must not
// flip an already-fingerprinted identity's signature into a different store bucket. Detected at
// the reconcileSignatures fold boundary (isTransientStatFailureOfKnownIdentity).
// ---------------------------------------------------------------------------------------------

test("reconcileSignatures: a transient stat failure (identityHash undefined) for an already-fingerprinted identity is skipped, not folded as a new/updated signature", () => {
  const withFingerprint = reconcileSignatures(
    { version: 1, signatures: {} },
    [{ executablePath: "/opt/svc/bin", identityHash: "aaaa1111bbbb2222", sourceClassification: "launchd", owningUser: "0" }],
    { ts: "2026-07-10T00:00:00.000Z", iterationKey: "i1" },
  );
  const [originalHash] = Object.keys(withFingerprint.signatures);
  const before = withFingerprint.signatures[originalHash];

  const afterTransientFailure = reconcileSignatures(
    withFingerprint,
    [{ executablePath: "/opt/svc/bin", identityHash: undefined, sourceClassification: "launchd", owningUser: "0" }],
    { ts: "2026-07-10T01:00:00.000Z", iterationKey: "i2" },
  );
  assert.deepEqual(Object.keys(afterTransientFailure.signatures), [originalHash], "no new signature bucket must be created for the transient-failure observation");
  assert.deepEqual(afterTransientFailure.signatures[originalHash], before, "the transient-failure observation must be skipped entirely, leaving the existing record (including last_seen) untouched");
});

test("reconcileSignatures: a first-ever sighting with identityHash undefined still folds in normally (no matching fingerprinted record exists yet) -- degrade-not-invisible", () => {
  const store = reconcileSignatures(
    { version: 1, signatures: {} },
    [{ executablePath: "/opt/svc/never-fingerprinted", identityHash: undefined, sourceClassification: "launchd", owningUser: "0" }],
    { ts: "2026-07-10T00:00:00.000Z", iterationKey: "i1" },
  );
  assert.equal(Object.keys(store.signatures).length, 1, "an identity with no fingerprint history must still be tracked (DEGRADE-NOT-FABRICATE must not become DEGRADE-TO-INVISIBLE)");
});

// ---------------------------------------------------------------------------------------------
// TDD item 8: provenance-store.js CLI -- snapshot idempotency, bounded/redacted baseline show.
// ---------------------------------------------------------------------------------------------

test("runProvenanceStore snapshot seeds known_good entries and is idempotent (running twice does not duplicate or reset state)", async () => {
  const paths = await tempPaths();
  const observations = [{ executablePath: "/bin/svc", sourceClassification: "launchd", owningUser: "0" }];
  const outputs = [];
  const runtime = { output: (line) => outputs.push(line), collectIdentityObservations: async () => ({ status: "ok", observations, reasons: [] }), now: "2026-07-10T00:00:00.000Z" };

  const first = await runProvenanceStore(paths, ["snapshot"], runtime);
  assert.equal(first.seeded_identity_count, 1);
  assert.equal(first.total_identity_count, 1);

  const second = await runProvenanceStore(paths, ["snapshot"], { ...runtime, now: "2026-07-10T01:00:00.000Z" });
  assert.equal(second.seeded_identity_count, 1);
  assert.equal(second.total_identity_count, 1, "running snapshot twice must not duplicate entries");

  const { store } = await loadSignatureStore(paths);
  assert.equal(Object.keys(store.signatures).length, 1);
  const [record] = Object.values(store.signatures);
  assert.equal(record.state, "known_good");
  assert.equal(record.origin, "snapshot");
});

test("runProvenanceStore snapshot uses the status collector, refuses degraded collection, and preserves reconcile bookkeeping", async () => {
  const paths = await tempPaths();
  const before = {
    version: 1,
    bootstrapped_at: "2026-07-09T00:00:00.000Z",
    last_reconciled_at: "2026-07-10T00:00:00.000Z",
    last_reconcile_attempt_at: "2026-07-10T01:00:00.000Z",
    last_reconcile_status: "degraded",
    last_reconcile_degraded_reasons: ["proc_net_unreadable"],
    signatures: {},
  };
  await writeSignatureStore(paths, before);
  await assert.rejects(
    () => runProvenanceStore(paths, ["snapshot"], {
      collectIdentityObservations: async () => ({ status: "degraded", observations: [], reasons: ["proc_net_unreadable"] }),
      now: "2026-07-10T02:00:00.000Z",
    }),
    /degraded/i,
  );
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, before.last_reconciled_at);
  assert.equal(store.last_reconcile_attempt_at, before.last_reconcile_attempt_at);
  assert.equal(store.last_reconcile_status, before.last_reconcile_status);
  assert.deepEqual(store.last_reconcile_degraded_reasons, before.last_reconcile_degraded_reasons);

  await runProvenanceStore(paths, ["snapshot"], {
    collectIdentityObservations: async () => ({ status: "ok", observations: [], reasons: [] }),
    now: "2026-07-10T03:00:00.000Z",
  });
  const afterSuccessfulSnapshot = await loadSignatureStore(paths);
  assert.equal(afterSuccessfulSnapshot.store.last_reconcile_attempt_at, before.last_reconcile_attempt_at);
  assert.equal(afterSuccessfulSnapshot.store.last_reconcile_status, before.last_reconcile_status);
  assert.deepEqual(afterSuccessfulSnapshot.store.last_reconcile_degraded_reasons, before.last_reconcile_degraded_reasons);
});

test("runProvenanceStore snapshot treats legacy array census injections as degraded unless explicitly opted in", async () => {
  const paths = await tempPaths();
  await assert.rejects(
    () => runProvenanceStore(paths, ["snapshot"], {
      ownUid: 501,
      listListeningSocketsWithPid: async () => [],
      snapshotProvenanceProcesses: async () => [],
      now: "2026-07-10T00:00:00.000Z",
    }),
    /degraded/i,
  );
});

test("runProvenanceStore baseline show is bounded and redacted -- never a raw executable path in its output", async () => {
  const paths = await tempPaths();
  const observations = [{ executablePath: "/usr/local/bin/very-secret-tool", sourceClassification: "launchd", owningUser: "0" }];
  await runProvenanceStore(paths, ["snapshot"], { output: () => {}, collectIdentityObservations: async () => ({ status: "ok", observations, reasons: [] }), now: "2026-07-10T00:00:00.000Z" });

  const outputs = [];
  const entries = await runProvenanceStore(paths, ["baseline", "show", "--json"], { output: (line) => outputs.push(line) });
  assert.equal(entries.length, 1);
  assert.equal(JSON.stringify(entries).includes("very-secret-tool"), false);
  assert.match(entries[0].executable_path_hash, /^[0-9a-f]{16}$/);
  assert.equal(outputs.length, 1);
});

test("runProvenanceStore baseline show supports --identity filtering", async () => {
  const paths = await tempPaths();
  const observations = [
    { executablePath: "/bin/one", sourceClassification: "launchd", owningUser: "0" },
    { executablePath: "/bin/two", sourceClassification: "systemd", owningUser: "0" },
  ];
  await runProvenanceStore(paths, ["snapshot"], { output: () => {}, collectIdentityObservations: async () => ({ status: "ok", observations, reasons: [] }), now: "2026-07-10T00:00:00.000Z" });
  const { store } = await loadSignatureStore(paths);
  const [targetHash] = Object.keys(store.signatures);

  const filtered = await runProvenanceStore(paths, ["baseline", "show", "--identity", targetHash, "--json"], { output: () => {} });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].identity_hash, targetHash);
});

// ---------------------------------------------------------------------------------------------
// 2026-10 provenance-identity recovery coverage (plan 2026-09-20 §8.B): reconcile bookkeeping that
// separates "attempted" from "successfully reconciled", surfacing of transient-stat skips, and the
// pure coverage derivation whose alert keys must match the candidate builders exactly.
// ---------------------------------------------------------------------------------------------

test("normalizeSignatureStore round-trips the reconcile-attempt bookkeeping (attempt ts, status, bounded reason codes) and drops malformed values", async () => {
  const paths = await tempPaths();
  await writeSignatureStore(paths, {
    version: 1,
    bootstrapped_at: "2026-07-10T00:00:00.000Z",
    last_reconciled_at: "2026-07-10T00:00:00.000Z",
    last_reconcile_attempt_at: "2026-07-10T01:00:00.000Z",
    last_reconcile_status: "degraded",
    last_reconcile_degraded_reasons: ["lsof_unavailable", "ps_empty"],
    signatures: {},
  });
  const { store } = await loadSignatureStore(paths);
  assert.equal(store.last_reconciled_at, "2026-07-10T00:00:00.000Z");
  assert.equal(store.last_reconcile_attempt_at, "2026-07-10T01:00:00.000Z");
  assert.equal(store.last_reconcile_status, "degraded");
  assert.deepEqual(store.last_reconcile_degraded_reasons, ["lsof_unavailable", "ps_empty"]);

  const malformed = normalizeSignatureStore({
    last_reconcile_attempt_at: 42,
    last_reconcile_status: "maybe",
    last_reconcile_degraded_reasons: ["ok_code", "/raw/path leak", 7],
  });
  assert.equal(malformed.last_reconcile_attempt_at, undefined);
  assert.equal(malformed.last_reconcile_status, undefined);
  assert.deepEqual(malformed.last_reconcile_degraded_reasons, ["ok_code"]);
});

test("normalizeSignatureStore omits the new bookkeeping keys entirely when absent (legacy stores normalize unchanged)", () => {
  const normalized = normalizeSignatureStore({ bootstrapped_at: "2026-07-10T00:00:00.000Z", signatures: {} });
  assert.equal(Object.hasOwn(normalized, "last_reconcile_attempt_at"), false);
  assert.equal(Object.hasOwn(normalized, "last_reconcile_status"), false);
  assert.equal(Object.hasOwn(normalized, "last_reconcile_degraded_reasons"), false);
});

test("reconcileSignaturesDetailed surfaces a transient-stat skip of an already-fingerprinted identity (NOT re-observed), and reconcileSignatures stays its .store", () => {
  const fingerprinted = { executablePath: "/opt/svc/bin", identityHash: "aaaaaaaaaaaaaaaa", sourceClassification: "launchd", owningUser: "501", portTargetKeys: ["tcp.8080"] };
  const base = reconcileSignatures({ version: 1, signatures: {} }, [fingerprinted], { ts: "2026-07-10T00:00:00.000Z", iterationKey: "t0" });
  const statFailed = { ...fingerprinted, identityHash: undefined };
  const fresh = { executablePath: "/opt/other/bin", identityHash: "bbbbbbbbbbbbbbbb", sourceClassification: "launchd", owningUser: "501" };

  const detailed = reconcileSignaturesDetailed(base, [statFailed, fresh], { ts: "2026-07-10T01:00:00.000Z", iterationKey: "t1" });
  assert.deepEqual(detailed.skippedObservations, [statFailed]);
  assert.deepEqual(detailed.store, reconcileSignatures(base, [statFailed, fresh], { ts: "2026-07-10T01:00:00.000Z", iterationKey: "t1" }));
  const originalHash = computeIdentitySignature(fingerprinted);
  assert.equal(detailed.store.signatures[originalHash].last_seen, "2026-07-10T00:00:00.000Z", "the skipped identity's last_seen must not advance");
});

function coverageStore() {
  return {
    version: 1,
    bootstrapped_at: "2026-07-10T00:00:00.000Z",
    signatures: {
      aaaa000000000001: {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T00:00:00.000Z", // long gone
        inputs_hash: { executable_path_hash: "e000000000000001", identity_hash: "f000000000000001", source_classification: "shell", owning_user_hash: "u000000000000001" },
        port_target_keys: ["tcp.8080"],
      },
      aaaa000000000002: {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T10:00:00.000Z", // present
        inputs_hash: { executable_path_hash: "e000000000000002", identity_hash: "f000000000000002", source_classification: "shell", owning_user_hash: "u000000000000001" },
        port_target_keys: ["tcp.9090"],
      },
      aaaa000000000003: {
        state: "known_good",
        origin: "snapshot",
        last_seen: "2026-07-10T10:00:00.000Z",
        inputs_hash: { executable_path_hash: "e000000000000002", identity_hash: "f000000000000003", source_classification: "shell", owning_user_hash: "u000000000000001" },
        port_target_keys: [],
      },
    },
  };
}

test("deriveIdentityCoverage reports no keys without a positive same-record observation", () => {
  const store = coverageStore();
  const keys = new Set(deriveIdentityCoverage(store));
  assert.deepEqual([...keys], []);

  // Parity: every candidate the builders emit for this store has its id inside the coverage set.
  const candidates = deriveIdentityCandidates(store, { now: "2026-07-10T10:30:00.000Z" });
  assert.deepEqual(
    candidates.map((c) => c.rule_id).sort(),
    [IDENTITY_DRIFT_RULE_ID, NEW_PUBLIC_BIND_RULE_ID, UNKNOWN_IDENTITY_RULE_ID].sort(),
    "fixture should emit one unknown + one new_public_bind + one drift candidate",
  );
});

test("deriveIdentityCoverage EXCLUDES every identity/target a transient-stat-skipped observation could be (not re-observed -> never evaluated-clear)", () => {
  const store = coverageStore();
  // The fold layer matches a skipped observation by its HASHED path/owner + source against a
  // fingerprinted record; build that record through the real fold so the hashes line up.
  const observation = { executablePath: "/opt/gone/bin", identityHash: undefined, sourceClassification: "shell", owningUser: "501", portTargetKeys: ["tcp.7070"] };
  const seeded = reconcileSignatures({ version: 1, signatures: {} }, [{ ...observation, identityHash: "1111111111111111" }], { ts: "2026-07-10T00:00:00.000Z" });
  const [seededHash] = Object.keys(seeded.signatures);
  const seededRecord = seeded.signatures[seededHash];
  store.signatures[seededHash] = { ...seededRecord, state: "known_good", origin: "grace_window", port_target_keys: ["tcp.8080"] };
  // Another tracked record really does hold the skipped observation's current port. The absence
  // of this fixture made the old assertion about tcp.7070 vacuous: nothing could have covered it.
  store.signatures.aaaa000000000001.port_target_keys = ["tcp.8080", "tcp.7070"];

  const keys = new Set(deriveIdentityCoverage(store, { skippedObservations: [observation] }));
  assert.equal(keys.has(alertId(UNKNOWN_IDENTITY_RULE_ID, unknownIdentityFingerprint(seededHash))), false, "the unverified identity itself");
  assert.equal(keys.has(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.8080"))), false, "a port the unverified identity's record holds (shared with record 1)");
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("port.tcp.8080"))), false);
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint(`process.${seededRecord.inputs_hash.executable_path_hash}`))), false, "the unverified identity's process target");
  assert.equal(keys.has(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.7070"))), false, "a port the skipped observation currently binds");
  // Unrelated identities are also frozen until they are positively re-observed.
  assert.equal(keys.has(alertId(UNKNOWN_IDENTITY_RULE_ID, unknownIdentityFingerprint("aaaa000000000001"))), false);
  assert.equal(keys.has(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.9090"))), false);
});

test("deriveIdentityCoverage excludes a currently-bound port when a bounded record evicted that port from its introspection list", () => {
  const observation = {
    executablePath: "/opt/current/bin",
    identityHash: "cccccccccccccccc",
    sourceClassification: "shell",
    owningUser: "501",
    portTargetKeys: ["tcp.7070"],
  };
  const identityHash = computeIdentitySignature(observation);
  const store = reconcileSignatures({ version: 1, signatures: {} }, [observation], { ts: "2026-07-10T10:00:00.000Z" });
  store.bootstrapped_at = "2026-07-10T00:00:00.000Z";
  // Model the bounded record after a later observation evicted the old port. The raw current
  // observation still proves tcp.7070 is bound, but the persisted list cannot authorize coverage.
  store.signatures[identityHash].port_target_keys = ["tcp.1", "tcp.2", "tcp.3", "tcp.4", "tcp.5"];
  const keys = new Set(deriveIdentityCoverage(store, {
    observations: [observation],
    ts: "2026-07-10T10:00:00.000Z",
  }));
  assert.equal(keys.has(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.7070"))), false);
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("port.tcp.7070"))), false);
});

test("deriveIdentityCoverage keeps a re-keyed record frozen when a different record observed this tick shares its process target", () => {
  const oldRecord = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T00:00:00.000Z",
    inputs_hash: { executable_path_hash: "shared-process", identity_hash: "old", source_classification: "shell", owning_user_hash: "u" },
    port_target_keys: ["tcp.7070"],
  };
  const currentRecord = {
    state: "known_good",
    origin: "grace_window",
    last_seen: "2026-07-10T04:00:00.000Z",
    inputs_hash: { executable_path_hash: "shared-process", identity_hash: "new", source_classification: "shell", owning_user_hash: "u" },
    port_target_keys: ["tcp.7070"],
  };
  const store = { ...coverageStore(), signatures: { old: oldRecord, current: currentRecord } };
  const keys = new Set(deriveIdentityCoverage(store, { ts: "2026-07-10T04:00:00.000Z" }));
  assert.equal(keys.has(alertId(UNKNOWN_IDENTITY_RULE_ID, unknownIdentityFingerprint("old"))), false);
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("process.shared-process"))), false);
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("port.tcp.7070"))), false);
});

test("deriveIdentityCoverage never reports the builders' shared unknown fallback fingerprint", () => {
  const store = {
    version: 1,
    bootstrapped_at: "2026-07-10T00:00:00.000Z",
    signatures: {
      "": {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T00:00:00.000Z",
        inputs_hash: {},
        port_target_keys: [],
      },
    },
  };
  assert.equal(deriveIdentityCoverage(store).some((key) => key.endsWith("\u0000unknown")), false);
});

test("deriveIdentityCoverage applies exclusions in FINGERPRINT space: a covered target whose sanitized fingerprint collides with an excluded one is not reported", () => {
  const store = coverageStore();
  const observation = { executablePath: "/opt/gone/bin", identityHash: undefined, sourceClassification: "shell", owningUser: "501", portTargetKeys: [] };
  const seeded = reconcileSignatures({ version: 1, signatures: {} }, [{ ...observation, identityHash: "1111111111111111" }], { ts: "2026-07-10T00:00:00.000Z" });
  const [seededHash] = Object.keys(seeded.signatures);
  // "tcp/8080" and "tcp_8080" sanitize to the SAME fingerprint (port.tcp_8080).
  store.signatures[seededHash] = { ...seeded.signatures[seededHash], state: "known_good", origin: "grace_window", port_target_keys: ["tcp/8080"] };
  store.signatures.aaaa000000000002.port_target_keys = ["tcp_8080"];
  assert.equal(newPublicBindFingerprint("tcp/8080"), newPublicBindFingerprint("tcp_8080"));

  const keys = deriveIdentityCoverage(store, { skippedObservations: [observation] });
  assert.equal(keys.includes(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp_8080"))), false);
  assert.equal(keys.includes(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("port.tcp_8080"))), false);
});

test("deriveIdentityCoverage excludes a skipped observation's own signature even when no fingerprinted sibling matches it", () => {
  const observation = {
    executablePath: "/opt/unfingerprinted/bin",
    identityHash: undefined,
    sourceClassification: "shell",
    owningUser: "501",
    portTargetKeys: ["tcp.7777"],
  };
  const ownSignature = computeIdentitySignature(observation);
  const store = {
    ...coverageStore(),
    signatures: {
      [ownSignature]: {
        state: "known_good",
        origin: "grace_window",
        last_seen: "2026-07-10T00:00:00.000Z",
        inputs_hash: { executable_path_hash: "own-path", source_classification: "shell", owning_user_hash: "own-user" },
        port_target_keys: ["tcp.7777"],
      },
    },
  };
  const keys = new Set(deriveIdentityCoverage(store, { skippedObservations: [observation] }));
  assert.equal(keys.has(alertId(UNKNOWN_IDENTITY_RULE_ID, unknownIdentityFingerprint(ownSignature))), false);
  assert.equal(keys.has(alertId(NEW_PUBLIC_BIND_RULE_ID, newPublicBindFingerprint("tcp.7777"))), false);
  assert.equal(keys.has(alertId(IDENTITY_DRIFT_RULE_ID, identityDriftFingerprint("port.tcp.7777"))), false);
});

test("deriveIdentityCoverage reports nothing for a never-bootstrapped store", () => {
  const store = { ...coverageStore(), bootstrapped_at: undefined };
  assert.deepEqual(deriveIdentityCoverage(store), []);
});
