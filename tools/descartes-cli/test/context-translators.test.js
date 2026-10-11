import assert from "node:assert/strict";
import test from "node:test";
import { CONTEXT_KEY_BYTES, contextHmac } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { factPointsFromTailnetStateEvidence, observationInterval } from "../src/context-translators.js";

const TS = "2026-10-11T10:00:00.000Z";
const KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 7);

function tailscaleEnvelope(result, status = "ok") {
  return { id: "tailscale-status", status, result, trace: { tool: "collect_tailscale_status", ts: "2026-10-11T10:00:00.500Z", latency_ms: 40 } };
}

function only(points) {
  assert.equal(points.length, 1);
  assert.deepEqual(validateContextFact(points[0].fact_name, points[0].attributes), { ok: true });
  return points[0];
}

test("observationInterval prefers the daemon's own stamp, falls back to the envelope trace, and is unknown otherwise", () => {
  assert.deepEqual(observationInterval({ observation: { start_ms: 5, end_ms: 9 }, trace: { ts: TS, latency_ms: 1 } }), { obsStartMs: 5, obsEndMs: 9 });
  assert.deepEqual(observationInterval(tailscaleEnvelope({})), { obsStartMs: Date.parse("2026-10-11T10:00:00.460Z"), obsEndMs: Date.parse("2026-10-11T10:00:00.500Z") });
  assert.deepEqual(observationInterval({}), { obsStartMs: undefined, obsEndMs: undefined });
  assert.deepEqual(observationInterval({ observation: { start_ms: 9, end_ms: 5 } }), { obsStartMs: undefined, obsEndMs: undefined });
});

test("C0.3: a Running tailnet is a net.tailnet_state with the tailnet name HMAC'd at source", () => {
  const point = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope({
    status: "ok",
    tailnet: { backend_state: "Running", self_online: true, exit_node_in_use: false, health_issue_count: 3, current_tailnet_name: "corp.example" },
  })], { ts: TS, hmacKey: KEY }));
  assert.equal(point.fact_name, "net.tailnet_state");
  assert.equal(point.entity_key, "net.tailnet_state");
  assert.deepEqual(point.attributes, {
    collector_state: "ok",
    obs_start_ms: String(Date.parse("2026-10-11T10:00:00.460Z")),
    obs_end_ms: String(Date.parse("2026-10-11T10:00:00.500Z")),
    state: "running",
    self_online: "true",
    exit_node_in_use: "false",
    health_issue_bucket: "2-4",
    current_tailnet_hmac: contextHmac(KEY, "tailnet_name", "corp.example"),
    rejected_field: "none",
  });
  assert.ok(!JSON.stringify(point).includes("corp.example"), "the tailnet name never reaches the fact point");
});

test("C0.3: every probe outcome is a value of net.tailnet_state, never a dropped tick and never a fabricated zero", () => {
  const cases = [
    [{ status: "not_found_on_known_paths" }, "unable", "not_found_on_known_paths", "not_found_on_known_paths"],
    [{ status: "untrusted_binary" }, "warning", "untrusted_binary", "untrusted_binary"],
    [{ status: "missing_permission" }, "unable", "missing_permission", "missing_permission"],
    [{ status: "unable", error: "bad json" }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "NeedsLogin" } }, "unable", "ok", "needs_login"],
    [{ status: "logged_out", tailnet: { backend_state: "Stopped" } }, "unable", "ok", "stopped"],
    [{ status: "logged_out", tailnet: { backend_state: "NoState" } }, "unable", "ok", "no_state"],
    [{ status: "logged_out", tailnet: { backend_state: "NeedsMachineAuth" } }, "unable", "ok", "needs_machine_auth"],
    [{ status: "logged_out", tailnet: { backend_state: "Starting" } }, "unable", "ok", "starting"],
    [{ status: "unable", tailnet: { backend_state: "SomethingNew" } }, "unable", "ok", "unrecognized_backend_state"],
    [{ status: "unable", tailnet: { backend_state: "Running" }, error: "no valid Peer map" }, "unable", "ok", "running"],
    [{ error: "exec crashed" }, "unable", "unable", "unable"],
  ];
  for (const [result, envelopeStatus, collectorState, state] of cases) {
    const point = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope(result, envelopeStatus)], { ts: TS, hmacKey: KEY }));
    assert.equal(point.attributes.collector_state, collectorState, JSON.stringify(result));
    assert.equal(point.attributes.state, state, JSON.stringify(result));
    if (collectorState !== "ok") {
      for (const field of ["self_online", "exit_node_in_use", "health_issue_bucket", "current_tailnet_hmac"]) assert.equal(point.attributes[field], "unknown", `${state}: ${field}`);
    }
  }
  const loggedOut = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope({ status: "logged_out", tailnet: { backend_state: "NeedsLogin" } }, "unable")], { ts: TS, hmacKey: KEY }));
  assert.equal(loggedOut.attributes.health_issue_bucket, "unknown", "an absent Health list is unknown, never 0");
  assert.equal(loggedOut.attributes.current_tailnet_hmac, "unknown");
  assert.deepEqual(factPointsFromTailnetStateEvidence([], { ts: TS, hmacKey: KEY }), [], "no probe ran, no fact");
});

test("C0.3: without a usable HMAC key the tailnet name is unknown, never an unkeyed hash", () => {
  const point = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope({ status: "ok", tailnet: { backend_state: "Running", current_tailnet_name: "corp.example" } })], { ts: TS }));
  assert.equal(point.attributes.current_tailnet_hmac, "unknown");
  assert.equal(point.attributes.self_online, "unknown");
  assert.equal(point.attributes.exit_node_in_use, "unknown");
});
