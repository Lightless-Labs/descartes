import assert from "node:assert/strict";
import test from "node:test";
import {
  factPointsFromNetworkEvidence,
  factPointsFromServiceEvidence,
  factPointsFromSessionEvidence,
  factPointsFromVpnPeerEvidence,
  sanitizeEntityKey,
} from "../src/fact-translators.js";

function envelope(id, tool, result, status = "ok") {
  return {
    id,
    status,
    layer: "L0",
    source: "test",
    result,
    confidence: 1,
    review_hint: "none",
    trace: { tool, target: null, latency_ms: 0, ts: "2026-07-10T00:00:00.000Z" },
  };
}

const TS = "2026-07-10T00:00:00.000Z";

// --- factPointsFromServiceEvidence ---

test("factPointsFromServiceEvidence maps systemd's {name, running:boolean} shape correctly", () => {
  const evidence = [envelope("services", "collect_services", {
    manager: "systemd",
    services: [
      { name: "nginx.service", running: true },
      { name: "postgres.service", running: true },
      { name: "cron.service", running: false },
    ],
  })];

  const points = factPointsFromServiceEvidence(evidence, { ts: TS });
  assert.equal(points.length, 3);
  assert.deepEqual(points.map((p) => p.entity_key).sort(), ["cron.service", "nginx.service", "postgres.service"]);
  const nginx = points.find((p) => p.entity_key === "nginx.service");
  assert.equal(nginx.fact_name, "service.presence");
  assert.equal(nginx.attributes.running, "true");
  assert.equal(nginx.attributes.manager, "systemd");
  assert.equal(nginx.source_envelope_id, "services");
  assert.equal(nginx.source_tool, "collect_services");
  const cron = points.find((p) => p.entity_key === "cron.service");
  assert.equal(cron.attributes.running, "false");
});

test("factPointsFromServiceEvidence branches on launchd's {label, pid, state} shape — no name/running keys at all", () => {
  const evidence = [envelope("services", "collect_services", {
    manager: "launchd",
    services: [
      { label: "com.example.running", pid: 123, last_exit_status: 0, state: "running", nonzero_exit: false },
      { label: "com.example.stopped", pid: null, last_exit_status: 0, state: "not_running", nonzero_exit: false },
    ],
  })];

  const points = factPointsFromServiceEvidence(evidence, { ts: TS });
  assert.equal(points.length, 2);
  const running = points.find((p) => p.entity_key === "com.example.running");
  assert.equal(running.attributes.running, "true");
  assert.equal(running.attributes.manager, "launchd");
  const stopped = points.find((p) => p.entity_key === "com.example.stopped");
  assert.equal(stopped.attributes.running, "false");
});

test("factPointsFromServiceEvidence returns [] for a status:unable envelope (no fabrication) and for missing envelope", () => {
  const unable = [envelope("services", "collect_services", { manager: "systemd", services: [] }, "unable")];
  assert.deepEqual(factPointsFromServiceEvidence(unable, { ts: TS }), []);
  assert.deepEqual(factPointsFromServiceEvidence([], { ts: TS }), []);
});

test("factPointsFromServiceEvidence drops a service entry with unresolvable identity rather than emitting an empty entity_key", () => {
  const evidence = [envelope("services", "collect_services", {
    manager: "systemd",
    services: [
      { name: "", running: true },
      { name: "real.service", running: true },
    ],
  })];
  const points = factPointsFromServiceEvidence(evidence, { ts: TS });
  assert.deepEqual(points.map((p) => p.entity_key), ["real.service"]);
});

// --- factPointsFromNetworkEvidence ---

test("factPointsFromNetworkEvidence: macOS-style resolvable owner produces owner/owner_known:true", () => {
  const evidence = [envelope("network-basics", "collect_network", {
    listening_sockets: [
      { protocol: "tcp", state: "LISTEN", command: "postgres", pid: 456, local_address: "127.0.0.1", local_port: 5432 },
    ],
  })];
  const points = factPointsFromNetworkEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert.equal(points[0].fact_name, "network.listening_port.owner");
  assert.equal(points[0].entity_key, "tcp:127.0.0.1:5432");
  assert.equal(points[0].attributes.owner, "postgres");
  assert.equal(points[0].attributes.owner_known, "true");
  assert.equal("confidence" in points[0], false);
});

test("factPointsFromNetworkEvidence: Linux-style unresolvable owner degrades to owner_known:false/confidence:0, never fabricates an owner", () => {
  const evidence = [envelope("network-basics", "collect_network", {
    listening_sockets: [
      { protocol: "tcp", state: "LISTEN", local_address: "0.0.0.0", local_port: 22, raw: "tcp LISTEN 0 0.0.0.0:22" },
    ],
  })];
  const points = factPointsFromNetworkEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert.equal(points[0].attributes.owner_known, "false");
  assert.equal("owner" in points[0].attributes, false);
  assert.equal(points[0].confidence, 0);
});

test("factPointsFromNetworkEvidence returns [] for a status:unable envelope", () => {
  const unable = [envelope("network-basics", "collect_network", { listening_sockets: [] }, "unable")];
  assert.deepEqual(factPointsFromNetworkEvidence(unable, { ts: TS }), []);
});

test("factPointsFromNetworkEvidence: two sockets sharing protocol:port but differing local_address produce distinct entity_keys", () => {
  const evidence = [envelope("network-basics", "collect_network", {
    listening_sockets: [
      { protocol: "tcp", state: "LISTEN", local_address: "0.0.0.0", local_port: 8080 },
      { protocol: "tcp", state: "LISTEN", local_address: "::", local_port: 8080 },
    ],
  })];
  const points = factPointsFromNetworkEvidence(evidence, { ts: TS });
  const keys = points.map((p) => p.entity_key);
  assert.equal(new Set(keys).size, 2, `expected distinct entity_keys, got ${JSON.stringify(keys)}`);
});

// --- Sanitization at emission (§6 gate) ---

test("sanitizeEntityKey is exported and delegates to the shared diagnostics-sanitizer allowlist", () => {
  assert.equal(sanitizeEntityKey("nginx.service"), "nginx.service");
  assert.equal(sanitizeEntityKey(""), undefined);
});

test("a hostile path-shaped service name is truncated/redacted before it ever reaches entity_key, end-to-end from raw collector shape to stored fact point", () => {
  const evidence = [envelope("services", "collect_services", {
    manager: "systemd",
    services: [
      { name: "/usr/local/bin/../../etc/passwd", running: true },
    ],
  })];
  const points = factPointsFromServiceEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert.equal(points[0].entity_key.includes("/"), false);
  assert.match(points[0].entity_key, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
});

test("an over-length process command is bounded before reaching attributes.owner", () => {
  const evidence = [envelope("network-basics", "collect_network", {
    listening_sockets: [
      { protocol: "tcp", state: "LISTEN", command: "x".repeat(200), pid: 1, local_address: "127.0.0.1", local_port: 9999 },
    ],
  })];
  const points = factPointsFromNetworkEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert(points[0].attributes.owner.length <= 64);
});

// --- factPointsFromSessionEvidence (Slice 1, observed-incident collectors plan) ---

function sessionEnvelope(result, status = "ok") {
  return envelope("sessions", "collect_sessions", result, status);
}

test("factPointsFromSessionEvidence maps a tmux session into a bucketed, hashed fact point", () => {
  const evidence = [sessionEnvelope({
    sessions: [
      { multiplexer: "tmux", session_name: "deploy-worker-3", attached: true, window_count: 3, created_at_epoch_seconds: 1720000000 },
    ],
    truncated: false,
  })];

  const points = factPointsFromSessionEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  const point = points[0];
  assert.equal(point.fact_name, "session.presence");
  assert.match(point.entity_key, /^session\.tmux\.[0-9a-f]{16}$/);
  assert.equal(point.attributes.multiplexer, "tmux");
  assert.equal(point.attributes.attached, "true");
  assert.equal(point.attributes.window_count_bucket, "2-4");
  assert.match(point.attributes.created_at_fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(point.source_envelope_id, "sessions");
  assert.equal(point.source_tool, "collect_sessions");
});

test("factPointsFromSessionEvidence: entity_key is stable across repeated ticks for the same session identity", () => {
  const buildEvidence = (attached) => [sessionEnvelope({
    sessions: [{ multiplexer: "tmux", session_name: "main", attached, window_count: 1, created_at_epoch_seconds: 1720000000 }],
  })];

  const first = factPointsFromSessionEvidence(buildEvidence(true), { ts: TS });
  const second = factPointsFromSessionEvidence(buildEvidence(false), { ts: TS });
  assert.equal(first[0].entity_key, second[0].entity_key);
});

test("factPointsFromSessionEvidence: entity_key differs across distinct multiplexers sharing the same session name — no cross-multiplexer collision", () => {
  const evidence = [sessionEnvelope({
    sessions: [
      { multiplexer: "tmux", session_name: "main", attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 },
      { multiplexer: "screen", session_name: "main", attached: true, window_count: undefined, created_at_epoch_seconds: undefined },
    ],
  })];
  const points = factPointsFromSessionEvidence(evidence, { ts: TS });
  assert.equal(new Set(points.map((p) => p.entity_key)).size, 2);
});

test("factPointsFromSessionEvidence returns [] for a status:unable envelope and for a missing envelope (no fabrication)", () => {
  const unable = [sessionEnvelope({ sessions: [] }, "unable")];
  assert.deepEqual(factPointsFromSessionEvidence(unable, { ts: TS }), []);
  assert.deepEqual(factPointsFromSessionEvidence([], { ts: TS }), []);
});

// --- Hash-at-source negative tests (must-fix 3) ---

test("factPointsFromSessionEvidence: no raw session name survives verbatim into entity_key or attributes, across adversarial name shapes", () => {
  const adversarialNames = [
    "$(rm -rf ~)-session; DROP TABLE users;--",
    "x".repeat(500),
    "10.0.0.5",
    "host-01.internal",
    "2026-07-13T14:32:00.000Z",
  ];

  for (const rawName of adversarialNames) {
    const evidence = [sessionEnvelope({
      sessions: [{ multiplexer: "tmux", session_name: rawName, attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 }],
    })];
    const points = factPointsFromSessionEvidence(evidence, { ts: TS });
    const serialized = JSON.stringify(points);
    assert.equal(serialized.includes(rawName), false, `raw name leaked verbatim for input: ${rawName}`);
    assert.match(points[0].entity_key, /^session\.tmux\.[0-9a-f]{16}$/);
  }
});

// --- Attribute bucketing (closed-enum only) ---

test("factPointsFromSessionEvidence: window_count_bucket is always one of a closed set of buckets, never the raw integer", () => {
  const CLOSED_BUCKETS = new Set(["0", "1", "2-4", "5-9", "10+", "unknown"]);
  const counts = [0, 1, 2, 4, 5, 9, 10, 500, undefined];
  for (const windowCount of counts) {
    const evidence = [sessionEnvelope({
      sessions: [{ multiplexer: "tmux", session_name: "s", attached: true, window_count: windowCount, created_at_epoch_seconds: 1720000000 }],
    })];
    const points = factPointsFromSessionEvidence(evidence, { ts: TS });
    assert(CLOSED_BUCKETS.has(points[0].attributes.window_count_bucket), `unexpected bucket for count=${windowCount}: ${points[0].attributes.window_count_bucket}`);
  }
});

test("factPointsFromSessionEvidence: a screen session with no resolvable window_count/created_at degrades to 'unknown' buckets, never fabricated", () => {
  const evidence = [sessionEnvelope({
    sessions: [{ multiplexer: "screen", session_name: "1234.foo", attached: false, window_count: undefined, created_at_epoch_seconds: undefined }],
  })];
  const points = factPointsFromSessionEvidence(evidence, { ts: TS });
  assert.equal(points[0].attributes.window_count_bucket, "unknown");
  assert.equal(points[0].attributes.created_at_fingerprint, "unknown");
});

// --- Kill-then-resurrect churn (must-fix 6) ---

test("factPointsFromSessionEvidence: a same-keyed session resurrected with a new created_at yields a DIFFERENT created_at_fingerprint, same entity_key — even for a fast, same-window resurrect", () => {
  const tick1 = [sessionEnvelope({
    sessions: [{ multiplexer: "tmux", session_name: "worker", attached: true, window_count: 2, created_at_epoch_seconds: 1720000000 }],
  })];
  // Resurrected under the same name only ONE SECOND later — the fast-resurrect case an adversary
  // would use to stay under the radar. A coarse (e.g. 10-minute) created_at bucket would have
  // collided here (both timestamps floor to the same bucket) and hidden the churn; the fingerprint
  // changes on any creation-second change, so the recreation is still visible as attribute churn.
  const tick2 = [sessionEnvelope({
    sessions: [{ multiplexer: "tmux", session_name: "worker", attached: true, window_count: 2, created_at_epoch_seconds: 1720000000 + 1 }],
  })];

  const pointsTick1 = factPointsFromSessionEvidence(tick1, { ts: TS });
  const pointsTick2 = factPointsFromSessionEvidence(tick2, { ts: TS });

  assert.equal(pointsTick1[0].entity_key, pointsTick2[0].entity_key, "same session name/multiplexer must hash to the same entity_key");
  assert.notEqual(pointsTick1[0].attributes.created_at_fingerprint, pointsTick2[0].attributes.created_at_fingerprint, "a resurrected session's created_at_fingerprint must differ from the killed session's, even one second apart");
});

// --- Flood cap + overflow marker (must-fix 5) ---

test("factPointsFromSessionEvidence: a truncated collector result emits an overflow marker fact alongside the bounded session facts", () => {
  const boundedSessions = Array.from({ length: 5 }, (_, i) => ({
    multiplexer: "tmux",
    session_name: `flood-${i}`,
    attached: false,
    window_count: 1,
    created_at_epoch_seconds: 1720000000,
  }));
  const evidence = [sessionEnvelope({ sessions: boundedSessions, truncated: true, total_count: 5000 })];

  const points = factPointsFromSessionEvidence(evidence, { ts: TS });
  assert.equal(points.length, 6, "expected 5 bounded session facts + 1 overflow marker fact");

  const marker = points.find((p) => p.attributes.overflow === "true");
  assert.ok(marker, "expected an overflow marker fact point");
  assert.equal(marker.confidence, 0);
  assert.equal(marker.attributes.total_count_bucket, "1000+");
  assert.equal(JSON.stringify(marker).includes("5000"), false, "the raw total_count must not appear verbatim, only its bucket");
});

test("factPointsFromSessionEvidence: a non-truncated collector result never emits an overflow marker", () => {
  const evidence = [sessionEnvelope({
    sessions: [{ multiplexer: "tmux", session_name: "solo", attached: true, window_count: 1, created_at_epoch_seconds: 1720000000 }],
    truncated: false,
  })];
  const points = factPointsFromSessionEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert.equal(points.some((p) => p.attributes.overflow === "true"), false);
});

// --- factPointsFromVpnPeerEvidence (Slice 3, observed-incident collectors plan) ---

function peerEnvelope(result, status = "ok") {
  return envelope("vpn-peer-status", "collect_vpn_peer_status", result, status);
}

function wgPeer(overrides = {}) {
  return {
    source_type: "wireguard",
    presence_state: "observed_active",
    interface: "wg0",
    public_key: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=",
    endpoint: "203.0.113.10:51820",
    latest_handshake_epoch_seconds: 1720000000,
    ...overrides,
  };
}

function sshPeer(overrides = {}) {
  return {
    source_type: "ssh",
    presence_state: "observed_active",
    remote_user: "alice",
    remote_host: "203.0.113.5",
    origin: "who",
    ...overrides,
  };
}

function vpnServicePeer(overrides = {}) {
  return {
    source_type: "vpn_service",
    presence_state: "observed_active",
    service_name: "Corp VPN",
    service_uuid: "1E4E6C58-F859-4E51-92A6-BF4B14A23689",
    ...overrides,
  };
}

test("factPointsFromVpnPeerEvidence maps a WireGuard peer into a hashed entity_key with closed-enum attributes", () => {
  const evidence = [peerEnvelope({ peers: [wgPeer()], truncated: false })];
  const points = factPointsFromVpnPeerEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  const point = points[0];
  assert.equal(point.fact_name, "peer.presence");
  assert.match(point.entity_key, /^peer\.wireguard\.[0-9a-f]{16}$/);
  assert.equal(point.attributes.source_type, "wireguard");
  assert.equal(point.attributes.presence_state, "observed_active");
  assert.match(point.attributes.login_hour_bucket, /^([01][0-9]|2[0-3])$/);
  assert.equal(point.attributes.handshake_age_bucket, "gte_7d"); // 1720000000 is far in the past relative to TS
  assert.equal(point.source_envelope_id, "vpn-peer-status");
  assert.equal(point.source_tool, "collect_vpn_peer_status");
});

test("factPointsFromVpnPeerEvidence: entity_key is stable across repeated ticks for the same WireGuard pubkey, regardless of a changed endpoint (endpoint is an attribute, not identity)", () => {
  const first = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer({ endpoint: "203.0.113.10:51820" })] })], { ts: TS });
  const second = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer({ endpoint: "198.51.100.7:44444" })] })], { ts: TS });
  assert.equal(first[0].entity_key, second[0].entity_key);
});

test("factPointsFromVpnPeerEvidence: an SSH peer and a vpn_service peer sharing similar-looking identifiers never collide (source_type domain-separates entity_key)", () => {
  const evidence = [peerEnvelope({ peers: [sshPeer(), vpnServicePeer(), wgPeer()] })];
  const points = factPointsFromVpnPeerEvidence(evidence, { ts: TS });
  assert.equal(new Set(points.map((p) => p.entity_key)).size, 3);
  assert.deepEqual(points.map((p) => p.attributes.source_type).sort(), ["ssh", "vpn_service", "wireguard"]);
});

test("factPointsFromVpnPeerEvidence returns [] for a status:unable envelope and for a missing envelope (no fabrication)", () => {
  const unable = [peerEnvelope({ peers: [] }, "unable")];
  assert.deepEqual(factPointsFromVpnPeerEvidence(unable, { ts: TS }), []);
  assert.deepEqual(factPointsFromVpnPeerEvidence([], { ts: TS }), []);
});

// --- Hash-at-source negative tests (must-fix 3/5) ---

test("factPointsFromVpnPeerEvidence: no raw WG public key survives verbatim into entity_key or attributes", () => {
  const rawPubkey = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=";
  const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer({ public_key: rawPubkey })] })], { ts: TS });
  assert.equal(JSON.stringify(points).includes(rawPubkey), false);
  assert.match(points[0].entity_key, /^peer\.wireguard\.[0-9a-f]{16}$/);
});

test("factPointsFromVpnPeerEvidence: no raw IP or hostname survives verbatim (SSH remote_host)", () => {
  for (const rawHost of ["10.0.0.5", "host-01.internal"]) {
    const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [sshPeer({ remote_host: rawHost })] })], { ts: TS });
    assert.equal(JSON.stringify(points).includes(rawHost), false, `raw host leaked for input: ${rawHost}`);
  }
});

test("factPointsFromVpnPeerEvidence: no raw username survives verbatim (SSH remote_user)", () => {
  const rawUser = "thomas";
  const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [sshPeer({ remote_user: rawUser })] })], { ts: TS });
  assert.equal(JSON.stringify(points).includes(rawUser), false);
});

test("factPointsFromVpnPeerEvidence: no raw handshake epoch survives verbatim — only a closed-enum bucket", () => {
  const rawEpoch = 1720000000;
  const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer({ latest_handshake_epoch_seconds: rawEpoch })] })], { ts: TS });
  assert.equal(JSON.stringify(points).includes(String(rawEpoch)), false);
  assert.match(points[0].attributes.handshake_age_bucket, /^(never|lt_5m|lt_1h|lt_1d|lt_7d|gte_7d|unknown|n\/a)$/);
});

test("factPointsFromVpnPeerEvidence: no raw scutil VPN service name or UUID survives verbatim", () => {
  const rawName = "Corp VPN — do not disclose";
  const rawUuid = "1E4E6C58-F859-4E51-92A6-BF4B14A23689";
  const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [vpnServicePeer({ service_name: rawName, service_uuid: rawUuid })] })], { ts: TS });
  const serialized = JSON.stringify(points);
  assert.equal(serialized.includes(rawName), false);
  assert.equal(serialized.includes(rawUuid), false);
});

test("factPointsFromVpnPeerEvidence: no raw ISO timestamp survives verbatim in any ATTRIBUTE (the fact point's own top-level `ts` field is expected and out of scope here, matching every other translator) — only the closed-enum login_hour_bucket", () => {
  const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer()] })], { ts: TS });
  assert.equal(JSON.stringify(points[0].attributes).includes(TS), false);
  assert.match(points[0].attributes.login_hour_bucket, /^([01][0-9]|2[0-3])$/);
});

// --- Closed-enum handshake-age bucket coverage ---

test("factPointsFromVpnPeerEvidence: handshake_age_bucket covers never/recent/stale, and is 'n/a' for non-WireGuard peers", () => {
  const nowSeconds = Math.floor(new Date(TS).getTime() / 1000);
  const cases = [
    { epoch: 0, expected: "never" },
    { epoch: nowSeconds - 60, expected: "lt_5m" },
    { epoch: nowSeconds - 1800, expected: "lt_1h" },
    { epoch: nowSeconds - 7200, expected: "lt_1d" },
    { epoch: nowSeconds - 3 * 86400, expected: "lt_7d" },
    { epoch: nowSeconds - 30 * 86400, expected: "gte_7d" },
    { epoch: undefined, expected: "unknown" },
  ];
  for (const { epoch, expected } of cases) {
    const points = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [wgPeer({ latest_handshake_epoch_seconds: epoch })] })], { ts: TS });
    assert.equal(points[0].attributes.handshake_age_bucket, expected, `epoch=${epoch}`);
  }

  const sshPoints = factPointsFromVpnPeerEvidence([peerEnvelope({ peers: [sshPeer()] })], { ts: TS });
  assert.equal(sshPoints[0].attributes.handshake_age_bucket, "n/a");
});

// --- Flood cap + overflow marker (must-fix 3) ---

test("factPointsFromVpnPeerEvidence: a truncated collector result emits an overflow marker fact alongside the bounded peer facts", () => {
  const boundedPeers = Array.from({ length: 5 }, (_, i) => sshPeer({ remote_user: `user-${i}`, remote_host: `10.0.0.${i}` }));
  const evidence = [peerEnvelope({ peers: boundedPeers, truncated: true, total_count: 5000 })];

  const points = factPointsFromVpnPeerEvidence(evidence, { ts: TS });
  assert.equal(points.length, 6, "expected 5 bounded peer facts + 1 overflow marker fact");

  const marker = points.find((p) => p.attributes.overflow === "true");
  assert.ok(marker, "expected an overflow marker fact point");
  assert.equal(marker.confidence, 0);
  assert.equal(marker.attributes.total_count_bucket, "1000+");
  assert.equal(JSON.stringify(marker).includes("5000"), false);
});

test("factPointsFromVpnPeerEvidence: a non-truncated collector result never emits an overflow marker", () => {
  const evidence = [peerEnvelope({ peers: [wgPeer()], truncated: false })];
  const points = factPointsFromVpnPeerEvidence(evidence, { ts: TS });
  assert.equal(points.length, 1);
  assert.equal(points.some((p) => p.attributes.overflow === "true"), false);
});

// --- Schema-level closed-enum/hash test (nice-to-have) ---

test("factPointsFromVpnPeerEvidence: every persisted attribute is either a closed-enum literal or a 16-hex hash — no free-form string reaches a persisted attribute", () => {
  const CLOSED_ENUM_VALUES = new Set([
    "wireguard", "ssh", "vpn_service", "unknown",
    "observed_active", "observed_historical",
    "never", "lt_5m", "lt_1h", "lt_1d", "lt_7d", "gte_7d", "n/a",
    "true", "false",
    "<=200", "201-500", "501-1000", "1000+",
  ]);
  const HOUR_BUCKET_RE = /^([01][0-9]|2[0-3])$/;
  const HEX16_RE = /^[0-9a-f]{16}$/;

  const evidence = [peerEnvelope({
    peers: [wgPeer(), sshPeer(), vpnServicePeer()],
    truncated: true,
    total_count: 999,
  })];
  const points = factPointsFromVpnPeerEvidence(evidence, { ts: TS });
  assert(points.length > 0);

  for (const point of points) {
    for (const [key, value] of Object.entries(point.attributes)) {
      const isClosedEnum = CLOSED_ENUM_VALUES.has(value) || HOUR_BUCKET_RE.test(value) || HEX16_RE.test(value);
      assert(isClosedEnum, `attribute ${key}="${value}" is neither a closed-enum literal nor a 16-hex hash`);
    }
  }
});
