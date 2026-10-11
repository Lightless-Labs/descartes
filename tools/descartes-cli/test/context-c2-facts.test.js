// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4): the C2 context facts.
// DATA ONLY: every fact validates against its closed schema, degrades to unknown/unable, and never
// fabricates a value.
import assert from "node:assert/strict";
import test from "node:test";
import { CONTEXT_KEY_BYTES, contextHmac } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { FACT_FAMILY_BY_NAME, FAMILY_DEFAULT_BUDGET_BYTES, FAMILY_TICK_SHAPES, familyBudgetFloorBytes } from "../src/fact-families.js";
import { factPointsFromBinaryStateEvidence, MAX_BINARY_STATES_PER_TICK } from "../src/context-translators.js";

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
