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
  parseWgInterfaceList,
  parseWgPeerList,
} from "../src/tools/vpn-peer-status.js";
import { collectTailscaleStatusEvidence, parseTailscaleStatusJson } from "../src/tools/tailscale-status.js";
import {
  parseLinuxRouterAdvertisementPrefixes,
  parseNdpRouterAdvertisementPrefixes,
  parseResolvectlDns,
} from "../src/tools/net-config.js";
import { parseLoginctlSessionIds, parseLastRows, parseWhoRows, readLoginSessions } from "../src/tools/login-sessions.js";
import { parseLastRows as parseSharedLastRows } from "../src/tools/last-history.js";
import { observationInterval } from "../src/context-translators.js";
import * as netConfigParsers from "../src/tools/net-config.js";
import * as networkParsers from "../src/tools/network.js";
import * as vpnParsers from "../src/tools/vpn-peer-status.js";
import * as loginParsers from "../src/tools/login-sessions.js";
import * as lastHistoryParsers from "../src/tools/last-history.js";
import * as hostLifecycleParsers from "../src/tools/host-lifecycle.js";
import * as tailscaleParsers from "../src/tools/tailscale-status.js";
import * as sessionAttachmentParsers from "../src/tools/session-attachment.js";

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
  for (const value of ["0", "2026-10-11", "10/11/2026", "2026-02-31T00:00:00Z", new String("2026-10-11T12:00:00Z")]) {
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

test("collector populations, not just parser metadata, reject duplicate peers and strict-handshake violations", async () => {
  const ok = (stdout) => ({ status: "ok", stdout, stderr: "" });
  const run = async (command, args) => {
    const key = JSON.stringify([command, ...args]);
    const fixtures = {
      [JSON.stringify(["wg", "show", "interfaces"])]: ok("wg0"),
      [JSON.stringify(["wg", "show", "wg0", "peers"])]: ok(`${KEY}\n${KEY}\n`),
      [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok(`${KEY}\t(none)\n${KEY}\t(none)\n`),
      [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok(`${KEY}\t0\n${KEY}\t0\n`),
      [JSON.stringify(["who"])]: { status: "not_found_on_known_paths", stdout: "" },
      [JSON.stringify(["last", "-n", "50"])]: { status: "not_found_on_known_paths", stdout: "" },
      [JSON.stringify(["scutil", "--nc", "list"])]: { status: "not_found_on_known_paths", stdout: "" },
      [JSON.stringify(["ss", "-H", "-tn", "state", "established"])]: { status: "not_found_on_known_paths", stdout: "" },
    };
    return fixtures[key];
  };
  const wg = await (await import("../src/tools/vpn-peer-status.js")).collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile: run });
  assert.equal(wg.result.sources.wireguard.status, "partial");
  assert.equal(wg.result.census_status, "partial");

  for (const value of ["0", "2026-08-11", "10/11/2026"]) {
    const result = await collectTailscaleStatusEvidence({
      runFixedExecFile: async () => ok(JSON.stringify({ BackendState: "Running", Peer: { [KEY]: { PublicKey: KEY, LastHandshake: value } } })),
    });
    assert.equal(result.result.status, "unable", value);
  }
  const zero = parseTailscaleStatusJson(JSON.stringify({ BackendState: "Running", Peer: { [KEY]: { PublicKey: KEY, LastHandshake: "0001-01-01T00:00:00Z" } } }));
  assert.equal(zero.peers[0].latest_handshake_epoch_seconds, 0);
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
  script[JSON.stringify(["ss", "-H", "-tn", "state", "established"])] = { status: "not_found_on_known_paths", stdout: "" };
  const result = await collectVpnPeerStatusEvidence({
    platform: "linux",
    runFixedExecFile: async (command, args) => script[JSON.stringify([command, ...args])],
  });
  assert.equal(result.result.sources.wireguard.status, "partial");
  assert.equal(result.result.sources.wireguard.interfaces_truncated, true);
  assert.equal(parseLinuxRouterAdvertisementPrefixes("MALFORMED").state, "partial");
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

test("loginctl duplicate IDs degrade the source, and malformed stamped metadata cannot fall back", async () => {
  const result = await readLoginSessions({
    platform: "linux",
    runFixedExecFile: async (command) => {
      if (command === "loginctl") return { status: "ok", stdout: "1 1000 alice seat0 tty1\n1 1000 alice seat0 tty1\n" };
      return { status: "ok", stdout: "" };
    },
  });
  assert.equal(result.sources.loginctl, "partial");
  assert.equal(result.truncated, false);
  assert.deepEqual(observationInterval({
    observation: { start_ms: { valueOf: () => 1 }, end_ms: 2 },
    trace: { ts: "2026-10-11T12:00:00Z", latency_ms: 1 },
  }), { obsStartMs: undefined, obsEndMs: undefined });
});

test("registered census parsers stay fail-closed across adversarial generated inputs", () => {
  const registered = [
    { name: "net-config.parseNetstatDefaultRoutes", parse: netConfigParsers.parseNetstatDefaultRoutes, trusted: (value) => value !== undefined },
    { name: "net-config.parseIpRouteDefault", parse: netConfigParsers.parseIpRouteDefault, trusted: (value) => value !== undefined },
    { name: "net-config.parseIfconfigVerbose", parse: netConfigParsers.parseIfconfigVerbose, trusted: (value) => value !== undefined && value.kind !== "unknown" },
    { name: "net-config.parseLinuxRouterAdvertisementPrefixes", parse: netConfigParsers.parseLinuxRouterAdvertisementPrefixes, trusted: (value) => !["partial", "unable"].includes(value?.state) },
    { name: "net-config.parseNdpRouterAdvertisementPrefixes", parse: (value) => netConfigParsers.parseNdpRouterAdvertisementPrefixes(value, "en0"), trusted: (value) => value !== undefined },
    { name: "net-config.parseIpAddrInet6", parse: netConfigParsers.parseIpAddrInet6, trusted: (value, input) => input === "" || value.length > 0 },
    { name: "net-config.parseNeighborMac", parse: netConfigParsers.parseNeighborMac, trusted: (value) => value !== undefined },
    { name: "net-config.parseScutilDnsForInterface", parse: (value) => netConfigParsers.parseScutilDnsForInterface(value, "en0"), trusted: (value) => value !== undefined },
    { name: "net-config.parseResolvectlDns", parse: netConfigParsers.parseResolvectlDns, trusted: (value) => value !== undefined },
    { name: "network.parseLinuxDefaultRoutes", parse: networkParsers.parseLinuxDefaultRoutes, trusted: (value) => value.malformed_count === 0 },
    { name: "network.parseMacDefaultRoute", parse: networkParsers.parseMacDefaultRoute, trusted: (value) => value.malformed_count === 0 },
    { name: "network.parseResolvConf", parse: networkParsers.parseResolvConf, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "network.parseScutilDns", parse: networkParsers.parseScutilDns, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "network.parseLinuxListeningSockets", parse: networkParsers.parseLinuxListeningSockets, trusted: (value) => value.rejected_count === 0 && value.duplicate_count === 0 },
    { name: "network.parseMacLsofListeningSocketsDetailed", parse: networkParsers.parseMacLsofListeningSocketsDetailed, trusted: (value) => value.rejected === 0 && value.duplicate_count === 0 },
    { name: "network.parseMacLsofListeningSockets", parse: networkParsers.parseMacLsofListeningSockets, trusted: (value) => value.length > 0 },
    { name: "vpn.parseWhoOutput", parse: vpnParsers.parseWhoOutput, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "vpn.parseLastOutput", parse: vpnParsers.parseLastOutput, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "vpn.parseWgInterfaceList", parse: parseWgInterfaceList, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "wireguard.peers", parse: parseWgPeerList, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "wireguard.endpoints", parse: parseWgEndpoints, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "wireguard.handshakes", parse: parseWgHandshakes, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "vpn.parseScutilNcListDetailed", parse: vpnParsers.parseScutilNcListDetailed, trusted: (value) => value.unparsed_count === 0 && value.duplicate_count === 0 },
    { name: "vpn.parseScutilNcList", parse: vpnParsers.parseScutilNcList, trusted: (value) => value.length > 0 },
    { name: "login.parseWhoRows", parse: parseWhoRows, trusted: (value) => value.malformed === 0 && value.duplicate_count === 0 },
    { name: "login.parseLastRows", parse: parseLastRows, trusted: (value) => value.malformed === 0 && value.duplicate_count === 0 },
    { name: "last-history.parseLastRows", parse: parseSharedLastRows, trusted: (value) => value.malformed === 0 && value.duplicate_count === 0 },
    { name: "session-attachment.parseTmuxClients", parse: sessionAttachmentParsers.parseTmuxClients, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "last-history.parseLastLifecycleRows", parse: lastHistoryParsers.parseLastLifecycleRows, trusted: (value) => value.malformed === 0 && value.duplicate_count === 0 },
    { name: "loginctl.ids", parse: parseLoginctlSessionIds, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "login.parsePlistXml", parse: loginParsers.parsePlistXml, trusted: () => false },
    { name: "login.parseConsoleUsers", parse: loginParsers.parseConsoleUsers, trusted: () => false },
    { name: "login.parseLoginctlShowSession", parse: loginParsers.parseLoginctlShowSession, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "host.parseSysctlKeyValues", parse: hostLifecycleParsers.parseSysctlKeyValues, trusted: (value) => value.malformed_count === 0 && value.duplicate_count === 0 },
    { name: "host.parseSysctlTimevalSeconds", parse: hostLifecycleParsers.parseSysctlTimevalSeconds, trusted: (value) => value !== undefined },
    { name: "host.parseProcStatBtime", parse: hostLifecycleParsers.parseProcStatBtime, trusted: (value) => value !== undefined },
    { name: "host.parseOsReleaseBuild", parse: hostLifecycleParsers.parseOsReleaseBuild, trusted: (value) => value !== undefined },
    { name: "host.parseProcUptime", parse: hostLifecycleParsers.parseProcUptime, trusted: (value) => value !== undefined },
    { name: "tailscale.parseTailscaleStatusJson", parse: tailscaleParsers.parseTailscaleStatusJson, trusted: () => false },
  ];
  const generated = [
    "MALFORMED",
    "MALFORMED\nMALFORMED",
    {},
    [],
    null,
    "",
    "Link 2 (en0):",
    "No advertising router",
  ];
  for (const parser of registered) {
    for (const input of generated) {
      let result;
      try {
        result = parser.parse(input);
      } catch {
        continue;
      }
      if (typeof input === "string" && (/MALFORMED/.test(input) || input === "!") && parser.name !== "vpn.parseWgInterfaceList") {
        assert.equal(parser.trusted(result, input), false, `${parser.name} trusted ${JSON.stringify(input)}`);
      }
      if (input !== "" && (typeof input !== "string" || input === null)) {
        assert.equal(parser.trusted(result, input), false, `${parser.name} trusted wrong type`);
      }
    }
  }
});

test("network parser grammar generators reject valid prefixes with suffix junk and invalid values", () => {
  const cases = [
    {
      name: "network.parseLinuxDefaultRoutes",
      parse: networkParsers.parseLinuxDefaultRoutes,
      trusted: (value) => value.malformed_count === 0,
      valid: "default via 192.168.1.1 dev eth0 metric 100",
      invalidValue: "default via NOT_AN_IP dev eth0 metric 100",
    },
    {
      name: "network.parseResolvConf",
      parse: networkParsers.parseResolvConf,
      trusted: (value) => value.malformed_count === 0,
      valid: "nameserver 1.1.1.1",
      invalidValue: "nameserver NOT_AN_IP",
    },
    {
      name: "network.parseScutilDns",
      parse: networkParsers.parseScutilDns,
      trusted: (value) => value.malformed_count === 0,
      valid: "resolver #1\nnameserver[0] : 1.1.1.1",
      invalidValue: "resolver #1\nnameserver[0] : NOT_AN_IP",
    },
    {
      name: "network.parseLinuxListeningSockets",
      parse: networkParsers.parseLinuxListeningSockets,
      trusted: (value) => value.rejected_count === 0,
      valid: "tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*",
      invalidValue: "tcp LISTEN NOT_A_QUEUE 128 127.0.0.1:22 0.0.0.0:*",
    },
  ];
  for (const grammar of cases) {
    for (const [label, input] of [
      ["suffix", `${grammar.valid} MALFORMED`],
      ["invalid value", grammar.invalidValue],
    ]) {
      const result = grammar.parse(input);
      assert.equal(grammar.trusted(result), false, `${grammar.name} trusted ${label}: ${input}`);
    }
  }
});

test("every exported parse* function in the touched parser modules is explicitly registered", () => {
  const modules = [
    ["net-config", netConfigParsers], ["network", networkParsers], ["vpn", vpnParsers],
    ["login", loginParsers], ["last-history", lastHistoryParsers], ["host", hostLifecycleParsers], ["tailscale", tailscaleParsers],
    ["session-attachment", sessionAttachmentParsers],
  ];
  const registeredNames = new Set([
    "net-config.parseNetstatDefaultRoutes", "net-config.parseIpRouteDefault", "net-config.parseIfconfigVerbose",
    "net-config.parseLinuxRouterAdvertisementPrefixes", "net-config.parseNdpRouterAdvertisementPrefixes", "net-config.parseIpAddrInet6",
    "net-config.parseNeighborMac", "net-config.parseScutilDnsForInterface", "net-config.parseResolvectlDns",
    "network.parseLinuxDefaultRoutes", "network.parseMacDefaultRoute", "network.parseResolvConf", "network.parseScutilDns",
    "network.parseLinuxListeningSockets", "network.parseMacLsofListeningSocketsDetailed", "network.parseMacLsofListeningSockets",
    "vpn.parseWhoOutput", "vpn.parseLastOutput", "vpn.parseWgInterfaceList", "vpn.parseWgPeerList", "vpn.parseWgEndpoints",
    "vpn.parseWgHandshakes", "vpn.parseScutilNcListDetailed", "vpn.parseScutilNcList", "login.parseWhoRows", "login.parseLastRows", "login.parsePlistXml",
    "login.parseConsoleUsers", "login.parseLoginctlSessionIds", "login.parseLoginctlShowSession", "last-history.parseLastRows", "last-history.parseLastLifecycleRows", "session-attachment.parseTmuxClients",
    "host.parseSysctlKeyValues", "host.parseSysctlTimevalSeconds", "host.parseProcStatBtime", "host.parseOsReleaseBuild",
    "host.parseProcUptime", "tailscale.parseTailscaleStatusJson",
  ]);
  const exportedNames = modules.flatMap(([prefix, module]) => Object.keys(module)
    .filter((name) => /^parse[A-Z]/.test(name)).map((name) => `${prefix}.${name}`));
  assert.deepEqual(exportedNames.filter((name) => !registeredNames.has(name)), []);
});
