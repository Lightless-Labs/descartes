import assert from "node:assert/strict";
import test from "node:test";
import {
  factPointsFromNetworkEvidence,
  factPointsFromServiceEvidence,
  factPointsFromSessionEvidence,
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
