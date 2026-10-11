import assert from "node:assert/strict";
import test from "node:test";
import { CONTEXT_KEY_BYTES, contextHmac } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { factPointsFromHostLifecycleEvidence, factPointsFromTailnetStateEvidence, hostBootIdHmac, observationInterval } from "../src/context-translators.js";

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
    hmac_key_id: contextHmac(KEY, "key_id", "descartes.context.key_id.v1"),
  });
  assert.ok(!JSON.stringify(point).includes("corp.example"), "the tailnet name never reaches the fact point");
});

test("C0.3: every probe outcome is a value of net.tailnet_state, never a dropped tick and never a fabricated zero", () => {
  const cases = [
    [{ status: "not_found_on_known_paths" }, "unable", "unable", "unable"],
    [{ status: "untrusted_binary" }, "warning", "untrusted_binary", "untrusted_binary"],
    [{ status: "missing_permission" }, "unable", "unable", "unable"],
    [{ status: "unable", error: "bad json" }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "NeedsLogin" } }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "Stopped" } }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "NoState" } }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "NeedsMachineAuth" } }, "unable", "unable", "unable"],
    [{ status: "logged_out", tailnet: { backend_state: "Starting" } }, "unable", "unable", "unable"],
    [{ status: "unable", tailnet: { backend_state: "SomethingNew" } }, "unable", "unable", "unable"],
    [{ status: "unable", tailnet: { backend_state: "Running" }, error: "no valid Peer map" }, "unable", "unable", "unable"],
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

test("HIGH 2: an unable tailscale envelope stays unable even when backend_state parsed", () => {
  const point = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope({
    status: "unable",
    tailnet: { backend_state: "Running", self_online: true },
  }, "unable")], { ts: TS, hmacKey: KEY }));
  assert.equal(point.attributes.collector_state, "unable");
  assert.equal(point.attributes.state, "unable");
  assert.equal(point.attributes.self_online, "unknown");
});

test("C0.3: without a usable HMAC key the tailnet name is unknown, never an unkeyed hash", () => {
  const point = only(factPointsFromTailnetStateEvidence([tailscaleEnvelope({ status: "ok", tailnet: { backend_state: "Running", current_tailnet_name: "corp.example" } })], { ts: TS }));
  assert.equal(point.attributes.current_tailnet_hmac, "unknown");
  assert.equal(point.attributes.self_online, "unknown");
  assert.equal(point.attributes.exit_node_in_use, "unknown");
});

// --- C0.8 / C0.9 / C0.12: host_lifecycle facts ---


function hostEnvelope(result) {
  return { id: "host-lifecycle", status: "ok", result, observation: { start_ms: 100, end_ms: 120 }, trace: { tool: "collect_host_lifecycle", ts: TS, latency_ms: 20 } };
}

const DARWIN_RESULT = {
  platform: "darwin",
  status: "ok",
  boot: { boot_id: "EFD29ED2-27A4-488A-96ED-7DB3B021B706", boot_id_source: "kern.bootsessionuuid", boot_time_s: 1788538230, os_build: "25C56", os_release: "25.2.0" },
  clocks: {
    wall_ms: 1791724875400, uv_hrtime_ns: "76479557408294", uv_version: "1.52.1", os_uptime_ms: 3186645200,
    kern_monotonicclock_usecs: "1791724875400525 76479557408294", kern_sleeptime_s: 0, kern_waketime_s: 0,
    kern_sleep_abs_time: "0", kern_wake_abs_time: "0", machdep_wake_abstime: "0", machdep_wake_conttime: "0",
  },
};

test("C0.8/C0.9: host.boot, host.clock_reading and host.suspend from one host-lifecycle envelope; boot id HMAC'd; named clocks never substituted", () => {
  const points = factPointsFromHostLifecycleEvidence([hostEnvelope(DARWIN_RESULT)], { ts: TS, hmacKey: KEY, bracket: "stable", suspend: { interval_basis: "same_boot_uptime_delta", exposure_upper_s: 3600 } });
  assert.deepEqual(points.map((p) => p.fact_name), ["host.boot", "host.clock_reading", "host.suspend"]);
  for (const point of points) assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true }, point.fact_name);
  const [boot, clock, suspend] = points;
  assert.equal(boot.attributes.boot_id_hmac, hostBootIdHmac(KEY, "EFD29ED2-27A4-488A-96ED-7DB3B021B706"));
  assert.ok(!JSON.stringify(points).includes("EFD29ED2"), "the raw boot id never reaches a fact");
  assert.equal(boot.attributes.boot_time_s, "1788538230");
  assert.equal(boot.attributes.os_build, "25C56");
  assert.equal(boot.attributes.bracket, "stable");
  assert.equal(boot.attributes.obs_start_ms, "100");
  assert.equal(clock.attributes.uv_hrtime_clock_id, "unverified");
  assert.equal(clock.attributes.named_clocks, "unavailable_without_native");
  assert.equal(clock.attributes.kern_monotonicclock_usecs, "1791724875400525 76479557408294");
  assert.equal(clock.attributes.proc_uptime_s, "not_applicable");
  assert.equal(clock.attributes.suspend_stats_success, "not_applicable");
  assert.deepEqual(
    { state: suspend.attributes.state, reason: suspend.attributes.reason, lower: suspend.attributes.exposure_lower_s, upper: suspend.attributes.exposure_upper_s, basis: suspend.attributes.interval_basis },
    { state: "unknown", reason: "f3_inactive_c09_pending", lower: "0", upper: "3600", basis: "same_boot_uptime_delta" },
  );
});

test("C0.8: an unreadable boot read degrades every value to unknown, never a fabricated boot", () => {
  const points = factPointsFromHostLifecycleEvidence([hostEnvelope({ platform: "linux", status: "unable", boot: {}, clocks: { wall_ms: 5 } })], { ts: TS, hmacKey: KEY });
  const boot = points[0];
  assert.equal(boot.attributes.collector_state, "unable");
  assert.equal(boot.attributes.boot_id_hmac, "unknown");
  assert.equal(boot.attributes.boot_id_source, "unknown");
  assert.equal(boot.attributes.bracket, "unknown");
  assert.equal(points[1].attributes.proc_uptime_s, "unknown");
  assert.equal(points[1].attributes.kern_sleeptime_s, "not_applicable");
  assert.equal(points[2].attributes.interval_basis, "unknown");
  assert.equal(points[2].attributes.exposure_upper_s, "unknown");
  assert.deepEqual(factPointsFromHostLifecycleEvidence([], { ts: TS }), []);
});

test("C0.8/C0.12: boundary verdict and boundary census become host.boot_boundary and host.boundary_census; a rejected value is unable, never written", () => {
  const boundary = {
    verdict: "verified", failing_conjunct: "none", tripwire: "none",
    c_never_seen: "pass", c_daemon_restart: "pass", c_boot_time_in_gap: "pass", c_uptime_consistent: "pass", c_no_preboot_instance: "pass",
    prev_boot_id_hmac: "0123456789abcdef", os_build_changed: "false", gap_s: 2400, resolution_s: 2,
  };
  const census = { trigger: "boot", status: "ran", pre_gap_s: 600, post_gap_s: 90 };
  const points = factPointsFromHostLifecycleEvidence([hostEnvelope(DARWIN_RESULT)], { ts: TS, hmacKey: KEY, boundary, boundaryCensus: census });
  const byName = Object.fromEntries(points.map((p) => [p.fact_name, p]));
  assert.equal(byName["host.boot_boundary"].attributes.verdict, "verified");
  assert.equal(byName["host.boot_boundary"].attributes.prev_boot_id_hmac, "0123456789abcdef");
  assert.equal(byName["host.boot_boundary"].attributes.gap_s, "2400");
  assert.equal(byName["host.boundary_census"].attributes.pre_gap_s, "600");
  assert.equal(byName["host.boundary_census"].attributes.boot_id_hmac, byName["host.boot"].attributes.boot_id_hmac);
  const bad = factPointsFromHostLifecycleEvidence([hostEnvelope(DARWIN_RESULT)], { ts: TS, hmacKey: KEY, boundary: { ...boundary, verdict: "probably_fine" } });
  const rejected = bad.find((p) => p.fact_name === "host.boot_boundary");
  assert.equal(rejected.attributes.collector_state, "unable");
  assert.equal(rejected.attributes.rejected_field, "verdict");
  assert.equal(rejected.attributes.verdict, "unknown");
});

test("C0 review M7: every context point carries the id of the key its HMACs were made with, so a re-keyed install is visible as a key change, not as every value changing", async () => {
  const { contextKeyId } = await import("../src/context-key.js");
  const { factPointsFromNetConfigEvidence, factPointsFromLoginSessionsEvidence } = await import("../src/context-translators.js");
  const keyId = contextKeyId(KEY);
  assert.match(keyId, /^[0-9a-f]{16}$/);
  assert.equal(contextKeyId(KEY), keyId, "deterministic per key");
  assert.notEqual(contextKeyId(Buffer.alloc(CONTEXT_KEY_BYTES, 8)), keyId);
  assert.notEqual(keyId, contextHmac(KEY, "tailnet_name", "corp.example"), "domain-separated from every value HMAC");
  assert.equal(contextKeyId(undefined), "unknown");
  const evidence = [
    tailscaleEnvelope({ status: "ok", tailnet: { backend_state: "Running" } }),
    { id: "host-lifecycle", status: "ok", result: { platform: "darwin", status: "ok", boot: { boot_id: "B" }, clocks: {} } },
    { id: "net-config", status: "ok", result: { platform: "darwin", status: "ok", route: { state: "absent", kind: "none" }, components: {} } },
    { id: "login-sessions", status: "ok", result: { platform: "darwin", status: "ok", sources: {}, records: [], history: [], presence: {} } },
  ];
  for (const hmacKey of [KEY, undefined]) {
    const points = [
      ...factPointsFromTailnetStateEvidence(evidence, { ts: TS, hmacKey }),
      ...factPointsFromHostLifecycleEvidence(evidence, { ts: TS, hmacKey, boundary: { verdict: "unverified", failing_conjunct: "uptime_consistent", tripwire: "none", c_never_seen: "pass", c_daemon_restart: "pass", c_boot_time_in_gap: "pass", c_uptime_consistent: "not_independent", c_no_preboot_instance: "pass", os_build_changed: "unknown" }, boundaryCensus: { trigger: "boot", status: "not_enabled" } }),
      ...factPointsFromNetConfigEvidence(evidence, { ts: TS, hmacKey }),
      ...factPointsFromLoginSessionsEvidence(evidence, { ts: TS, hmacKey }),
    ];
    assert.equal(points.length, 9, "tailnet 1 + host 5 + net 1 + login census and presence 2");
    for (const point of points) {
      assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true }, point.fact_name);
      assert.equal(point.attributes.hmac_key_id, hmacKey ? keyId : "unknown", point.fact_name);
    }
  }
});
