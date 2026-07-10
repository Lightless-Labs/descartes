import assert from "node:assert/strict";
import test from "node:test";
import {
  factPointsFromNetworkEvidence,
  factPointsFromServiceEvidence,
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
