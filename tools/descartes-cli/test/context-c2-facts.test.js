// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4): the C2 context facts.
// DATA ONLY: every fact validates against its closed schema, degrades to unknown/unable, and never
// fabricates a value.
import assert from "node:assert/strict";
import test from "node:test";
import { CONTEXT_KEY_BYTES, contextHmac } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { FACT_FAMILY_BY_NAME, FAMILY_DEFAULT_BUDGET_BYTES, FAMILY_TICK_SHAPES, familyBudgetFloorBytes } from "../src/fact-families.js";
import { parseLastLifecycleRows, parseLastRows } from "../src/tools/last-history.js";
import { readLoginSessions } from "../src/tools/login-sessions.js";
import { selectNewLoginRows } from "../src/login-seen.js";
import {
  factPointsFromBinaryStateEvidence,
  factPointsFromLifecycleRecordEvidence,
  MAX_LIFECYCLE_RECORDS_PER_TICK,
  factPointsFromVpnServiceEvidence,
  MAX_BINARY_STATES_PER_TICK,
  MAX_VPN_SERVICE_STATES_PER_TICK,
} from "../src/context-translators.js";

const TS = "2026-10-11T10:00:00.000Z";
const KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 7);

function valid(points) {
  for (const point of points) assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true }, point.fact_name);
  return points;
}

function prov(binary, verdict, extra = {}) {
  return { requested_binary: binary, trust_verdict: verdict, same_uid_writable_components: [], ...extra };
}

test("C2 collector.binary_state: one fact per observed binary from the resolver verdicts already in the evidence; paths and content HMAC'd", () => {
  const evidence = [
    { id: "sessions", status: "ok", observation: { start_ms: 100, end_ms: 200 }, result: { multiplexers: [
      { multiplexer: "tmux", status: "ok", binary_provenance: prov("tmux", "trusted", { resolved_path: "/opt/homebrew/bin/tmux", content_hash: "abc" }) },
      { multiplexer: "screen", status: "not_found_on_known_paths", binary_provenance: prov("screen", "not_found_on_known_paths") },
    ] } },
    { id: "vpn-peer-status", status: "ok", observation: { start_ms: 300, end_ms: 400 }, result: { sources: {
      ssh_who: { status: "ok", binary_provenance: prov("who", "untrusted_binary", { resolved_path: "/tmp/who", trust_reason: "group_writable", offending_component: "/tmp" }) },
      ssh_last: { status: "ok", binary_provenance: prov("last", "weird_verdict") },
    } } },
  ];
  const points = valid(factPointsFromBinaryStateEvidence(evidence, { ts: TS, hmacKey: KEY }));
  const byBinary = Object.fromEntries(points.map((p) => [p.attributes.binary, p]));
  assert.deepEqual(Object.keys(byBinary).sort(), ["last", "screen", "tmux", "who"]);
  assert.equal(FACT_FAMILY_BY_NAME.get("collector.binary_state"), "collector_state");
  const tmux = byBinary.tmux.attributes;
  assert.equal(byBinary.tmux.entity_key, "collector.binary_state.tmux");
  assert.equal(tmux.state, "resolved");
  assert.equal(tmux.path_hmac, contextHmac(KEY, "collector_binary_path", "/opt/homebrew/bin/tmux"));
  assert.equal(tmux.content_hmac, contextHmac(KEY, "collector_binary_content", "abc"));
  assert.equal(tmux.same_uid_writable, "false");
  assert.equal(tmux.obs_start_ms, "100");
  assert.equal(byBinary.screen.attributes.state, "not_found_on_known_paths");
  assert.equal(byBinary.screen.attributes.path_hmac, "none");
  assert.equal(byBinary.who.attributes.state, "untrusted_binary");
  assert.equal(byBinary.who.attributes.trust_reason, "group_writable");
  assert.equal(byBinary.who.attributes.content_hmac, "unknown");
  assert.ok(!JSON.stringify(points).includes("/tmp"), "no raw path or offending component is written");
  assert.equal(byBinary.last.attributes.state, "unable", "an unrecognised verdict is unable, never resolved");
});

test("C2 collector.binary_state: disagreeing reads in one tick are inconsistent; daemon-synthesized and unlisted envelopes are ignored; no key means unknown HMACs", () => {
  const evidence = [
    { id: "vpn-peer-status", result: { sources: { a: { binary_provenance: prov("lsof", "trusted", { resolved_path: "/usr/sbin/lsof" }) }, b: { binary_provenance: prov("lsof", "untrusted_binary", { resolved_path: "/usr/sbin/lsof", trust_reason: "acl_present" }) } } } },
    { id: "tailscale-status", source: "daemon", result: { binary_provenance: prov("tailscale", "trusted") } },
    { id: "services", result: { binary_provenance: prov("launchctl", "trusted") } },
    { id: "host-lifecycle", result: { binary_provenance: prov("not-a-collector-binary", "trusted") } },
    { id: "host-lifecycle", result: { binary_provenance: prov("sysctl", "trusted", { resolved_path: "/usr/sbin/sysctl", content_hash: "h" }) } },
  ];
  const points = valid(factPointsFromBinaryStateEvidence(evidence, { ts: TS }));
  assert.deepEqual(points.map((p) => p.attributes.binary), ["lsof", "sysctl"]);
  assert.equal(points[0].attributes.state, "inconsistent");
  assert.equal(points[0].attributes.collector_state, "partial");
  assert.equal(points[0].attributes.observations, "2");
  assert.equal(points[1].attributes.path_hmac, "unknown", "no usable key: unknown, never an unkeyed hash");
  assert.deepEqual(factPointsFromBinaryStateEvidence([], { ts: TS }), []);
});

test("C2 collector_state T8: the budget holds the 30-day horizon at the per-tick cap of the schema-derived worst-case record", () => {
  const shape = FAMILY_TICK_SHAPES.get("collector_state");
  assert.equal(shape.entityCap, MAX_BINARY_STATES_PER_TICK);
  assert.ok(FAMILY_DEFAULT_BUDGET_BYTES.get("collector_state") >= familyBudgetFloorBytes("collector_state"));
  const many = Array.from({ length: 20 }, (_, i) => ["arp", "codesign", "crontab", "df", "id", "ifconfig", "ioreg", "ip", "ipconfig", "last", "launchctl", "loginctl", "lsof", "ndp", "netstat", "nmcli", "ps", "resolvectl", "screen", "scutil"][i]);
  const evidence = [{ id: "vpn-peer-status", result: { sources: Object.fromEntries(many.map((b) => [b, { binary_provenance: prov(b, "trusted") }])) } }];
  assert.equal(factPointsFromBinaryStateEvidence(evidence, { ts: TS, hmacKey: KEY }).length, MAX_BINARY_STATES_PER_TICK);
});

function vpnEnvelope({ status = "ok", peers = [], truncated = false, source } = {}) {
  return { id: "vpn-peer-status", status: "ok", ...(source ? { source } : {}), observation: { start_ms: 10, end_ms: 20 }, result: { sources: { vpn_services: { status } }, peers, truncated } };
}
const UUID_A = "11111111-2222-3333-4444-555555555555";
const UUID_B = "66666666-2222-3333-4444-555555555555";

test("C2 net.vpn_service_state: per-service connected/not_connected from the incumbent census, uuid HMAC'd, plus a census marker; the incumbent peers are untouched", () => {
  const peers = [
    { source_type: "ssh", presence_state: "observed_active", remote_user: "a", remote_host: "h" },
    { source_type: "vpn_service", presence_state: "observed_active", service_name: "Work", service_uuid: UUID_A },
    { source_type: "vpn_service", presence_state: "observed_historical", service_name: "Home", service_uuid: UUID_B },
  ];
  const envelope = vpnEnvelope({ peers });
  const before = JSON.stringify(envelope);
  const points = valid(factPointsFromVpnServiceEvidence([envelope], { ts: TS, hmacKey: KEY }));
  assert.equal(JSON.stringify(envelope), before, "the incumbent envelope is read, never changed");
  const [census, ...services] = points;
  assert.equal(census.fact_name, "net.vpn_service_census");
  assert.equal(census.attributes.services_total, "2");
  assert.equal(census.attributes.connected_total, "1");
  assert.equal(census.attributes.overflow, "0");
  assert.match(census.attributes.state_digest, /^[0-9a-f]{16}$/);
  assert.equal(services.length, 2);
  const byHmac = Object.fromEntries(services.map((p) => [p.attributes.service_hmac, p.attributes.state]));
  assert.equal(byHmac[contextHmac(KEY, "vpn_service_uuid", UUID_A)], "connected");
  assert.equal(byHmac[contextHmac(KEY, "vpn_service_uuid", UUID_B)], "not_connected");
  assert.ok(!JSON.stringify(points).includes(UUID_A) && !JSON.stringify(points).includes("Work"));
  for (const p of points) assert.equal(FACT_FAMILY_BY_NAME.get(p.fact_name), "network_context");
});

test("C2 net.vpn_service_state: an unusable source, a truncated census, a daemon-synthesized envelope or no key gives unknown totals and no per-service fact", () => {
  const peers = [{ source_type: "vpn_service", presence_state: "observed_active", service_uuid: UUID_A }];
  for (const [envelope, hmacKey, expectedState] of [
    [vpnEnvelope({ status: "unable", peers }), KEY, "unable"],
    [vpnEnvelope({ status: "not_applicable" }), KEY, "not_applicable"],
    [vpnEnvelope({ peers, truncated: true }), KEY, "partial"],
    [vpnEnvelope({ peers, source: "daemon" }), KEY, "unable"],
    [vpnEnvelope({ peers: [{ source_type: "vpn_service", presence_state: "observed_active" }] }), KEY, "partial"],
  ]) {
    const points = valid(factPointsFromVpnServiceEvidence([envelope], { ts: TS, hmacKey }));
    assert.equal(points.length, 1, JSON.stringify(envelope.result));
    assert.equal(points[0].attributes.services_total, "unknown");
    assert.equal(points[0].attributes.state_digest, "unknown");
    assert.equal(points[0].attributes.collector_state, expectedState);
  }
  const noKey = valid(factPointsFromVpnServiceEvidence([vpnEnvelope({ peers })], { ts: TS }));
  assert.equal(noKey.length, 1, "no usable key: no per-service fact, never an unkeyed id");
  assert.equal(noKey[0].attributes.state_digest, "unknown");
  assert.equal(noKey[0].attributes.overflow, "unknown");
  assert.deepEqual(factPointsFromVpnServiceEvidence([], { ts: TS }), []);
});

test("C2 net.vpn_service_state: at most 8 per tick, the rest counted as overflow", () => {
  const peers = Array.from({ length: 11 }, (_, i) => ({ source_type: "vpn_service", presence_state: "observed_active", service_uuid: `${String(i).padStart(8, "0")}-2222-3333-4444-555555555555` }));
  const points = valid(factPointsFromVpnServiceEvidence([vpnEnvelope({ peers })], { ts: TS, hmacKey: KEY }));
  assert.equal(points.length, 1 + MAX_VPN_SERVICE_STATES_PER_TICK);
  assert.equal(points[0].attributes.services_total, "11");
  assert.equal(points[0].attributes.overflow, "3");
  assert.equal(points[0].attributes.emitted, "8");
});

const LAST_DARWIN = [
  "thomas     ttys037  100.64.118.39          Sun Oct 11 12:53   still logged in",
  "reboot time                                Fri Sep  4 16:10",
  "shutdown time                              Fri Sep  4 16:08",
  "",
  "wtmp begins Fri Sep  4 16:10:30 2026",
].join("\n");
const LAST_LINUX = [
  "alice    pts/0        203.0.113.9      Mon Oct  6 08:05   still logged in",
  "reboot   system boot  6.8.0-45-generic Mon Oct  6 08:01   still running",
  "reboot   system boot  6.8.0-45-generic Sun Oct  5 22:10 - 08:00  (09:49)",
  "reboot   system boot  6.8.0-44-generic Sat Oct  4 20:10 - crash (1+00:49)",
  "",
  "wtmp begins Sat Oct  4 20:10:01 2026",
].join("\n");

test("C2 host.lifecycle_record parser: macOS and Linux reboot/shutdown rows by anchored grammar; the login rows are unchanged", () => {
  const darwin = parseLastLifecycleRows(LAST_DARWIN);
  assert.equal(darwin.malformed, 0);
  assert.deepEqual(darwin.rows.map((r) => [r.kind, r.start_text, r.end_state, r.os_release]), [
    ["reboot", "Fri Sep 4 16:10", "none", "none"],
    ["shutdown", "Fri Sep 4 16:08", "none", "none"],
  ]);
  const linux = parseLastLifecycleRows(LAST_LINUX);
  assert.equal(linux.malformed, 0);
  assert.deepEqual(linux.rows.map((r) => [r.start_text, r.end_state, r.duration_text, r.os_release]), [
    ["Mon Oct 6 08:01", "still_running", "none", "6.8.0-45-generic"],
    ["Sun Oct 5 22:10", "ended", "09:49", "6.8.0-45-generic"],
    ["Sat Oct 4 20:10", "crash", "1+00:49", "6.8.0-44-generic"],
  ]);
  // The login census parser still skips them exactly as before.
  assert.deepEqual(parseLastRows(LAST_LINUX).rows.map((r) => r.user), ["alice"]);
});

test("C2 host.lifecycle_record parser: a lifecycle-looking row off the grammar, suffix junk, junk output or a duplicate is partial, never a clean census", () => {
  for (const bad of [
    "reboot time Fri Sep  4 16:10 extra",
    "reboot time Fri Sep 32 16:10",
    "reboot   system boot  6.8.0 Mon Oct  6 08:01   still running junk",
    "shutdown",
    "MALFORMED",
  ]) assert.ok(parseLastLifecycleRows(bad).malformed > 0, bad);
  assert.equal(parseLastLifecycleRows("reboot time  Fri Sep  4 16:10\nreboot time  Fri Sep  4 16:10").duplicate_count, 1);
  assert.equal(parseLastLifecycleRows(undefined).malformed, 1);
});

test("C2 login collector carries the lifecycle rows of the same shared last read (no new subprocess), with their source state", async () => {
  const calls = [];
  const scripted = (map) => async (command, args = []) => {
    const key = [command, ...args].join(" ");
    calls.push(key);
    const hit = Object.entries(map).find(([prefix]) => key.startsWith(prefix));
    return hit ? hit[1] : { status: "not_found_on_known_paths", availability: "not_found_on_known_paths", stdout: "" };
  };
  const ok = (stdout) => ({ status: "ok", stdout, stderr: "" });
  const result = await readLoginSessions({ platform: "linux", runFixedExecFile: scripted({ "last -n 50": ok(LAST_LINUX), "loginctl": ok("") }) });
  assert.equal(calls.filter((c) => c.startsWith("last")).length, 1);
  assert.equal(result.lifecycle.state, "ok");
  assert.equal(result.lifecycle.rows.length, 3);
  const failed = await readLoginSessions({ platform: "linux", runFixedExecFile: scripted({ "last -n 50": { status: "error", stdout: "", stderr: "x" }, "loginctl": ok("") }) });
  assert.equal(failed.lifecycle.rows.length, 0);
  assert.notEqual(failed.lifecycle.state, "ok");
  assert.notEqual(failed.lifecycle.state, "absent");
});

test("C2 host.lifecycle_record: first-observed dedupe through the keyed login seen-state; at most 4 per tick with the total on each; no key, no record", () => {
  const rows = parseLastLifecycleRows(LAST_LINUX).rows;
  const result = { records: [], history: [], lifecycle: { state: "ok", rows } };
  const first = selectNewLoginRows(null, result, { nowMs: 1000, hmacKey: KEY });
  assert.equal(first.newLifecycle.length, 3);
  assert.equal(first.lifecycleDedupeState, "reseeded");
  const second = selectNewLoginRows(first.next, result, { nowMs: 2000, hmacKey: KEY });
  assert.equal(second.newLifecycle.length, 0, "a repeated sighting is not a new row");
  assert.equal(second.lifecycleDedupeState, "fresh");
  const c0State = { ...first.next };
  delete c0State.lifecycle;
  assert.equal(selectNewLoginRows(c0State, result, { nowMs: 3000, hmacKey: KEY }).lifecycleDedupeState, "reseeded", "a C0-era state has no lifecycle memory");
  const envelope = { id: "login-sessions", status: "ok", observation: { start_ms: 1, end_ms: 2 }, result };
  const points = valid(factPointsFromLifecycleRecordEvidence([envelope], { ts: TS, hmacKey: KEY, dedupe: first }));
  assert.equal(points.length, 3);
  assert.deepEqual(points.map((p) => p.attributes.end_state), ["still_running", "ended", "crash"]);
  for (const p of points) {
    assert.equal(FACT_FAMILY_BY_NAME.get(p.fact_name), "host_lifecycle");
    assert.equal(p.attributes.time_confidence, "local_minute_no_year");
    assert.equal(p.attributes.new_rows_total, "3");
  }
  const many = { ...first, newLifecycle: Array.from({ length: 7 }, (_, i) => ({ ...rows[0], digest: `${i}`.padStart(32, "0") })) };
  const capped = valid(factPointsFromLifecycleRecordEvidence([envelope], { ts: TS, hmacKey: KEY, dedupe: many }));
  assert.equal(capped.length, MAX_LIFECYCLE_RECORDS_PER_TICK);
  assert.equal(capped[0].attributes.new_rows_total, "7");
  assert.deepEqual(factPointsFromLifecycleRecordEvidence([envelope], { ts: TS, hmacKey: KEY }), []);
});
