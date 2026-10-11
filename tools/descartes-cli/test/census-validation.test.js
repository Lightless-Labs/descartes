import assert from "node:assert/strict";
import test from "node:test";
import {
  finalizeCensus,
  isStrictRfc3339,
  validateCrossReferenceKeys,
} from "../src/tools/census-validate.js";
import {
  parseWgEndpoints,
  parseWgHandshakes,
  parseWgPeerList,
} from "../src/tools/vpn-peer-status.js";
import { parseTailscaleStatusJson } from "../src/tools/tailscale-status.js";
import {
  parseLinuxRouterAdvertisementPrefixes,
  parseNdpRouterAdvertisementPrefixes,
  parseResolvectlDns,
} from "../src/tools/net-config.js";
import { parseLoginctlSessionIds } from "../src/tools/login-sessions.js";
import { observationInterval } from "../src/context-translators.js";

const KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

test("census validation rejects duplicate identities and caps as partial", () => {
  const duplicate = finalizeCensus({
    records: [{ id: "a" }, { id: "a" }],
    identity: (record) => record.id,
    cap: 16,
  });
  assert.equal(duplicate.status, "partial");
  assert.equal(duplicate.complete, false);
  assert.equal(duplicate.duplicate_count, 1);

  const capped = finalizeCensus({
    records: Array.from({ length: 17 }, (_, id) => ({ id })),
    identity: (record) => record.id,
    cap: 16,
  });
  assert.equal(capped.status, "partial");
  assert.equal(capped.truncated, true);
  assert.equal(capped.complete, false);
});

test("cross-reference validation is one-to-one, not set-collapse", () => {
  assert.equal(validateCrossReferenceKeys(["a", "a"], ["a", "a"], ["a", "a"]).ok, false);
  assert.equal(validateCrossReferenceKeys(["a"], ["a"], ["b"]).ok, false);
  assert.equal(validateCrossReferenceKeys(["a"], ["a"], ["a"]).ok, true);
});

test("strict RFC3339 accepts only timestamp strings and handles Tailscale zero time separately", () => {
  assert.equal(isStrictRfc3339("2026-10-11T12:00:00Z"), true);
  assert.equal(isStrictRfc3339("2026-10-11T12:00:00.123Z"), true);
  for (const value of ["0", "2026-10-11", "10/11/2026", new String("2026-10-11T12:00:00Z")]) {
    assert.equal(isStrictRfc3339(value), false, String(value));
  }
});

test("WireGuard parser metadata exposes duplicate rows instead of overwriting them", () => {
  assert.equal(parseWgPeerList(`${KEY}\n${KEY}\n`).duplicate_count, 1);
  assert.equal(parseWgEndpoints(`${KEY}\t203.0.113.1:1\n${KEY}\t203.0.113.1:2\n`).duplicate_count, 1);
  assert.equal(parseWgHandshakes(`${KEY}\t1\n${KEY}\t2\n`).duplicate_count, 1);
});

test("Tailscale rejects map-key/PublicKey mismatch and duplicate inner PublicKey values", () => {
  const mismatch = parseTailscaleStatusJson(JSON.stringify({
    BackendState: "Running",
    Peer: { mapKey: { PublicKey: KEY } },
  }));
  assert.equal(mismatch.peer_map_valid, false);

  const duplicate = parseTailscaleStatusJson(JSON.stringify({
    BackendState: "Running",
    Peer: { a: { PublicKey: KEY }, b: { PublicKey: KEY } },
  }));
  assert.equal(duplicate.peer_map_valid, false);
});

test("WireGuard cap, malformed IPv6, NDP, and DNS output cannot become complete absence", async () => {
  const { collectVpnPeerStatusEvidence } = await import("../src/tools/vpn-peer-status.js");
  const ok = (stdout) => ({ status: "ok", stdout, stderr: "" });
  const script = {
    [JSON.stringify(["wg", "show", "interfaces"])]: ok(Array.from({ length: 17 }, (_, i) => `wg${i}`).join(" ")),
  };
  for (let i = 0; i < 17; i += 1) {
    script[JSON.stringify(["wg", "show", `wg${i}`, "peers"])] = ok("");
    script[JSON.stringify(["wg", "show", `wg${i}`, "endpoints"])] = ok("");
    script[JSON.stringify(["wg", "show", `wg${i}`, "latest-handshakes"])] = ok("");
  }
  script[JSON.stringify(["who"])] = { status: "not_found_on_known_paths", stdout: "" };
  script[JSON.stringify(["last", "-n", "50"])] = { status: "not_found_on_known_paths", stdout: "" };
  script[JSON.stringify(["scutil", "--nc", "list"])] = { status: "not_found_on_known_paths", stdout: "" };
  script[JSON.stringify(["netstat", "-an", "-p", "tcp"])] = { status: "not_found_on_known_paths", stdout: "" };
  const result = await collectVpnPeerStatusEvidence({
    platform: "linux",
    runFixedExecFile: async (command, args) => script[JSON.stringify([command, ...args])],
  });
  assert.equal(result.result.sources.wireguard.status, "partial");
  assert.equal(result.result.sources.wireguard.interfaces_truncated, true);
  assert.equal(parseLinuxRouterAdvertisementPrefixes("MALFORMED").state, "unable");
  assert.equal(parseNdpRouterAdvertisementPrefixes("MALFORMED", "en0"), undefined);
  assert.equal(parseResolvectlDns("MALFORMED"), undefined);
});

test("loginctl duplicate IDs are partial and observation metadata rejects object coercion", () => {
  const ids = parseLoginctlSessionIds("1 1000 alice seat0 tty1\n1 1000 alice seat0 tty1\n");
  assert.equal(ids.duplicate_count, 1);
  assert.deepEqual(observationInterval({
    trace: { ts: { toString: () => "2026-10-11T12:00:00Z" }, latency_ms: 1 },
    observation: { start_ms: { valueOf: () => 1 }, end_ms: 2 },
  }), { obsStartMs: undefined, obsEndMs: undefined });
});
