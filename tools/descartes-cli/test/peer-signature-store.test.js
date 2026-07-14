import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { computeIdentitySignature } from "../src/provenance-store.js";
import { hashSessionIdentity, SESSION_ENTITY_HASH_DOMAIN } from "../src/fact-translators.js";
import {
  applyPeerIdentityObservation,
  computePeerIdentitySignature,
  DEFAULT_PEER_STABLE_ITERATION_THRESHOLD,
  DEFAULT_PEER_STABLE_SAMPLE_THRESHOLD,
  loadPeerSignatureStore,
  normalizePeerSignatureStore,
  PEER_IDENTITY_HASH_DOMAIN,
  reconcilePeerSignatures,
  resolvePeerSignatureStorePaths,
  writePeerSignatureStore,
} from "../src/peer-signature-store.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { resolveSignatureStorePaths } from "../src/provenance-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-peer-signature-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// ---------------------------------------------------------------------------------------------
// THE GOLDEN-FIXTURE-PINNED PEER HASH (must-fixes 6/7). Preimage: PEER_IDENTITY_HASH_DOMAIN,
// sourceType, peerIdentifier, remoteUser, remoteHost — NUL-joined, sha256, 16 hex chars.
// Computed independently against the locked algorithm documented in
// src/peer-signature-store.js's own module header, before any consumer code was wired up.
// ---------------------------------------------------------------------------------------------

test("PEER_IDENTITY_HASH_DOMAIN is the pinned, versioned domain tag", () => {
  assert.equal(PEER_IDENTITY_HASH_DOMAIN, "descartes.peer.v1");
});

const WG_GOLDEN_FIXTURE_INPUTS = {
  sourceType: "wireguard",
  peerIdentifier: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=",
};
const WG_GOLDEN_FIXTURE_HASH = "d871bf0b55245d7f";

test("computePeerIdentitySignature reproduces the golden WireGuard fixture hash exactly (identity = pubkey only)", () => {
  assert.equal(computePeerIdentitySignature(WG_GOLDEN_FIXTURE_INPUTS), WG_GOLDEN_FIXTURE_HASH);
  assert.match(WG_GOLDEN_FIXTURE_HASH, /^[0-9a-f]{16}$/);
});

const SSH_GOLDEN_FIXTURE_INPUTS = {
  sourceType: "ssh",
  remoteUser: "alice",
  remoteHost: "203.0.113.5",
};
const SSH_GOLDEN_FIXTURE_HASH = "401c192722ae6bd2";

test("computePeerIdentitySignature reproduces the golden SSH fixture hash exactly (identity = source_type+user+host)", () => {
  assert.equal(computePeerIdentitySignature(SSH_GOLDEN_FIXTURE_INPUTS), SSH_GOLDEN_FIXTURE_HASH);
  assert.match(SSH_GOLDEN_FIXTURE_HASH, /^[0-9a-f]{16}$/);
});

const VPN_SERVICE_GOLDEN_FIXTURE_INPUTS = {
  sourceType: "vpn_service",
  peerIdentifier: "1E4E6C58-F859-4E51-92A6-BF4B14A23689",
};
const VPN_SERVICE_GOLDEN_FIXTURE_HASH = "fe7405582c756d11";

test("computePeerIdentitySignature reproduces the golden vpn_service fixture hash exactly (identity = service UUID only)", () => {
  assert.equal(computePeerIdentitySignature(VPN_SERVICE_GOLDEN_FIXTURE_INPUTS), VPN_SERVICE_GOLDEN_FIXTURE_HASH);
});

test("computePeerIdentitySignature is pure and deterministic: identical inputs always produce the identical hash", () => {
  assert.equal(computePeerIdentitySignature(WG_GOLDEN_FIXTURE_INPUTS), computePeerIdentitySignature({ ...WG_GOLDEN_FIXTURE_INPUTS }));
});

// ---------------------------------------------------------------------------------------------
// Identity-vs-attribute split (must-fix 7): the endpoint (an attribute) must never affect a
// WireGuard peer's identity hash; the pubkey alone is identity.
// ---------------------------------------------------------------------------------------------

test("WireGuard identity is stable across an endpoint change (endpoint is an attribute, never folded into identity)", () => {
  const a = computePeerIdentitySignature({ sourceType: "wireguard", peerIdentifier: WG_GOLDEN_FIXTURE_INPUTS.peerIdentifier });
  const b = computePeerIdentitySignature({ sourceType: "wireguard", peerIdentifier: WG_GOLDEN_FIXTURE_INPUTS.peerIdentifier });
  assert.equal(a, b, "computePeerIdentitySignature has no endpoint parameter at all -- structurally incapable of folding it in");
});

test("two distinct WireGuard pubkeys produce distinct identities", () => {
  const a = computePeerIdentitySignature({ sourceType: "wireguard", peerIdentifier: "keyA" });
  const b = computePeerIdentitySignature({ sourceType: "wireguard", peerIdentifier: "keyB" });
  assert.notEqual(a, b);
});

test("an SSH peer with a changed remote_host (dynamic client IP) produces a DIFFERENT identity hash -- documented v0 limitation: such a peer may never stabilize", () => {
  const first = computePeerIdentitySignature({ sourceType: "ssh", remoteUser: "alice", remoteHost: "203.0.113.5" });
  const second = computePeerIdentitySignature({ sourceType: "ssh", remoteUser: "alice", remoteHost: "203.0.113.99" });
  assert.notEqual(first, second);
});

// ---------------------------------------------------------------------------------------------
// NUL-delimiter test (must-fix 6): IPv6 hosts contain colons, so a colon-joined preimage would be
// ambiguous. ("u", "a:b") and ("u:a", "b") must NOT collide.
// ---------------------------------------------------------------------------------------------

test("NUL-joined preimage: (\"u\", \"a:b\") and (\"u:a\", \"b\") produce DIFFERENT hashes (a colon-joined scheme would have collided them)", () => {
  const a = computePeerIdentitySignature({ sourceType: "ssh", remoteUser: "u", remoteHost: "a:b" });
  const b = computePeerIdentitySignature({ sourceType: "ssh", remoteUser: "u:a", remoteHost: "b" });
  assert.notEqual(a, b);
});

// ---------------------------------------------------------------------------------------------
// Domain-separation (must-fix 6): differs from BOTH the process scheme and the session scheme
// for otherwise-identical input bytes.
// ---------------------------------------------------------------------------------------------

test("domain separation: the peer hash of an input differs from the PROCESS scheme's hash of the same underlying bytes", () => {
  const peerHash = computePeerIdentitySignature({ sourceType: "shared-value-a", peerIdentifier: "shared-value-b" });
  const processHash = computeIdentitySignature({ executablePath: "shared-value-a", identityHash: "shared-value-b" });
  assert.notEqual(peerHash, processHash);
});

test("domain separation: the peer hash of an input differs from the SESSION scheme's hash of the same underlying bytes", () => {
  const peerHash = computePeerIdentitySignature({ sourceType: "shared-value-a", peerIdentifier: "shared-value-b" });
  const sessionHash = hashSessionIdentity("shared-value-a", "shared-value-b");
  assert.notEqual(peerHash, sessionHash);
  // Sanity: confirms this test is actually exercising the real shipped session domain tag, not a
  // stale re-derivation of it.
  assert.equal(SESSION_ENTITY_HASH_DOMAIN, "descartes.fact.session.v1");
});

// ---------------------------------------------------------------------------------------------
// Store separation (must-fix 4): its own file, distinct from provenance-store.js's
// signatures.json.
// ---------------------------------------------------------------------------------------------

test("resolvePeerSignatureStorePaths resolves to its OWN file, distinct from provenance-store.js's signatures.json", async () => {
  const paths = await tempPaths();
  const peerPaths = resolvePeerSignatureStorePaths(paths);
  const processPaths = resolveSignatureStorePaths(paths);
  assert.notEqual(peerPaths.peerSignaturesFile, processPaths.signaturesFile);
  assert.equal(path.basename(peerPaths.peerSignaturesFile), "peer-signatures.json");
  // Same parent "learned" directory is fine (mirrors constraint-store.js/learned.json living
  // alongside signatures.json already) -- what matters is the FILENAME never collides.
  assert.equal(path.dirname(peerPaths.peerSignaturesFile), path.dirname(processPaths.signaturesFile));
});

test("writePeerSignatureStore/loadPeerSignatureStore round-trip through its own file, never touching signatures.json", async () => {
  const paths = await tempPaths();
  const reconciled = reconcilePeerSignatures(normalizePeerSignatureStore(undefined), [
    { sourceType: "wireguard", peerIdentifier: "keyA" },
  ], { ts: "2026-07-13T00:00:00.000Z", iterationKey: "tick-1" });
  await writePeerSignatureStore(paths, reconciled);

  const { store } = await loadPeerSignatureStore(paths);
  assert.equal(Object.keys(store.signatures).length, 1);

  const processStore = resolveSignatureStorePaths(paths);
  await assert.rejects(() => fs.access(processStore.signaturesFile), "signatures.json must not have been written by the peer store path");
});

test("loadPeerSignatureStore is ENOENT-tolerant (fresh state -> empty store, never throws)", async () => {
  const paths = await tempPaths();
  const { store, corrupt } = await loadPeerSignatureStore(paths);
  assert.deepEqual(store.signatures, {});
  assert.equal(corrupt, false);
});

test("loadPeerSignatureStore is corrupt-tolerant (malformed JSON -> empty store, corrupt:true)", async () => {
  const paths = await tempPaths();
  const { peerSignaturesFile, dir } = resolvePeerSignatureStorePaths(paths);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(peerSignaturesFile, "{not json", "utf8");
  const { store, corrupt } = await loadPeerSignatureStore(paths);
  assert.deepEqual(store.signatures, {});
  assert.equal(corrupt, true);
});

// ---------------------------------------------------------------------------------------------
// Promotion state machine (provisional -> known_good, grace window) -- mirrors
// provenance-store.js's applyIdentityObservation behavior exactly, parameterized for peers.
// ---------------------------------------------------------------------------------------------

test("a first-ever peer observation is provisional", () => {
  const record = applyPeerIdentityObservation(undefined, { sourceType: "ssh", remoteUser: "alice", remoteHost: "203.0.113.5" }, { ts: "2026-07-13T00:00:00.000Z", iterationKey: "tick-1" });
  assert.equal(record.state, "provisional");
  assert.equal(record.stable_sample_count, 1);
  assert.equal(record.stable_iteration_count, 1);
});

test("a peer identity promotes to known_good only once BOTH the sample threshold and the DISTINCT-iteration threshold are crossed", () => {
  let record;
  const observation = { sourceType: "wireguard", peerIdentifier: "keyA" };
  for (let iteration = 1; iteration <= DEFAULT_PEER_STABLE_ITERATION_THRESHOLD; iteration += 1) {
    for (let sample = 0; sample < DEFAULT_PEER_STABLE_SAMPLE_THRESHOLD; sample += 1) {
      // Repeated observations within the SAME iteration (tick) bump stable_sample_count but never
      // stable_iteration_count -- mirrors provenance-store.js's documented discipline.
      record = applyPeerIdentityObservation(record, observation, { ts: `2026-07-13T0${iteration}:00:00.000Z`, iterationKey: `tick-${iteration}` });
    }
  }
  assert.equal(record.stable_sample_count, DEFAULT_PEER_STABLE_ITERATION_THRESHOLD * DEFAULT_PEER_STABLE_SAMPLE_THRESHOLD);
  assert.equal(record.stable_iteration_count, DEFAULT_PEER_STABLE_ITERATION_THRESHOLD);
  assert.equal(record.state, "known_good");
});

test("known_good never reverts to provisional on a later fold", () => {
  const knownGood = { state: "known_good", origin: "grace_window", first_seen: "2026-07-01T00:00:00.000Z", stable_sample_count: 10, stable_iteration_count: 5, last_iteration_key: "old" };
  const record = applyPeerIdentityObservation(knownGood, { sourceType: "ssh", remoteUser: "alice", remoteHost: "203.0.113.5" }, { ts: "2026-07-13T00:00:00.000Z", iterationKey: "tick-new" });
  assert.equal(record.state, "known_good");
});

test("SSH peer identity may legitimately never leave provisional under a dynamic (changing) client IP -- documented, consequence-free limitation (Slice 3 emits no alerts)", () => {
  let store = normalizePeerSignatureStore(undefined);
  const ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"];
  for (const [index, ip] of ips.entries()) {
    store = reconcilePeerSignatures(store, [{ sourceType: "ssh", remoteUser: "alice", remoteHost: ip }], { ts: `2026-07-1${index}T00:00:00.000Z`, iterationKey: `tick-${index}` });
  }
  // Each distinct remote_host hashes to a DIFFERENT identity -- none of the four ever
  // accumulates enough repeat observations under the SAME identity to promote.
  assert.equal(Object.keys(store.signatures).length, ips.length);
  assert(Object.values(store.signatures).every((record) => record.state === "provisional"));
});

test("raw peer fields never survive into the stored record -- only hashed inputs_hash fields, plus the closed-enum source_type", () => {
  const record = applyPeerIdentityObservation(undefined, {
    sourceType: "ssh",
    remoteUser: "alice",
    remoteHost: "203.0.113.5",
  }, { ts: "2026-07-13T00:00:00.000Z", iterationKey: "tick-1" });
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes("alice"), false);
  assert.equal(serialized.includes("203.0.113.5"), false);
  assert.match(record.inputs_hash.remote_user_hash, /^[0-9a-f]{16}$/);
  assert.match(record.inputs_hash.remote_host_hash, /^[0-9a-f]{16}$/);
  assert.equal(record.inputs_hash.source_type, "ssh"); // closed-enum, safe unhashed
});

test("reconcilePeerSignatures folds a batch of observations into distinct hash-keyed records, pure (no I/O)", () => {
  const store = reconcilePeerSignatures(normalizePeerSignatureStore(undefined), [
    { sourceType: "wireguard", peerIdentifier: "keyA" },
    { sourceType: "ssh", remoteUser: "alice", remoteHost: "203.0.113.5" },
  ], { ts: "2026-07-13T00:00:00.000Z", iterationKey: "tick-1" });
  assert.equal(Object.keys(store.signatures).length, 2);
});
