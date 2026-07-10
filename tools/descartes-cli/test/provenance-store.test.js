import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DEFAULT_STABLE_ITERATION_THRESHOLD,
  DEFAULT_STABLE_SAMPLE_THRESHOLD,
  applyIdentityObservation,
  computeIdentitySignature,
  deriveIdentityCandidates,
  loadSignatureStore,
  reconcileSignatures,
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
  assert.deepEqual(deriveIdentityCandidates(bootstrappedNoDeviation), []);

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
  const candidates = deriveIdentityCandidates(withConfirmedUnknown);
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
  const [candidate] = deriveIdentityCandidates(store);
  assert.ok(candidate);
  assert.equal(candidate.diagnostics.source_type.redacted, true);
  assert.equal(JSON.stringify(candidate.diagnostics).includes("/usr/local/bin"), false);
});

// ---------------------------------------------------------------------------------------------
// TDD item 8: provenance-store.js CLI -- snapshot idempotency, bounded/redacted baseline show.
// ---------------------------------------------------------------------------------------------

test("runProvenanceStore snapshot seeds known_good entries and is idempotent (running twice does not duplicate or reset state)", async () => {
  const paths = await tempPaths();
  const observations = [{ executablePath: "/bin/svc", sourceClassification: "launchd", owningUser: "0" }];
  const outputs = [];
  const runtime = { output: (line) => outputs.push(line), gatherIdentityObservations: async () => observations, now: "2026-07-10T00:00:00.000Z" };

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

test("runProvenanceStore baseline show is bounded and redacted -- never a raw executable path in its output", async () => {
  const paths = await tempPaths();
  const observations = [{ executablePath: "/usr/local/bin/very-secret-tool", sourceClassification: "launchd", owningUser: "0" }];
  await runProvenanceStore(paths, ["snapshot"], { output: () => {}, gatherIdentityObservations: async () => observations, now: "2026-07-10T00:00:00.000Z" });

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
  await runProvenanceStore(paths, ["snapshot"], { output: () => {}, gatherIdentityObservations: async () => observations, now: "2026-07-10T00:00:00.000Z" });
  const { store } = await loadSignatureStore(paths);
  const [targetHash] = Object.keys(store.signatures);

  const filtered = await runProvenanceStore(paths, ["baseline", "show", "--identity", targetHash, "--json"], { output: () => {} });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].identity_hash, targetHash);
});
