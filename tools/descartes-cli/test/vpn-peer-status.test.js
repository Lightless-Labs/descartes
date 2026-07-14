import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectVpnPeerStatusEvidence,
  DEFAULT_LAST_HISTORY_LIMIT,
  DEFAULT_PEER_ENTITY_LIMIT,
  parseLastOutput,
  parseScutilNcList,
  parseWgEndpoints,
  parseWgHandshakes,
  parseWgInterfaceList,
  parseWgPeerList,
  parseWhoOutput,
} from "../src/tools/vpn-peer-status.js";

const SRC_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools", "vpn-peer-status.js");

function ok(stdout, stderr = "") {
  return { status: "ok", stdout, stderr, command: { argv: ["fixture"], read_only: true } };
}

function failure({ code, stdout = "", stderr = "", error = "boom" } = {}) {
  return { status: "error", code, stdout, stderr, error, command: { argv: ["fixture"], read_only: true } };
}

function enoent() {
  return failure({ code: "ENOENT", error: "spawn ENOENT" });
}

function permissionDenied(stderr = "Permission denied\n") {
  return failure({ code: 1, stderr });
}

// Records every invocation as `${command} ${args.join(" ")}` and dispatches against a scripted
// map keyed the same way — mirrors sessions.test.js's fakeExec DI convention, extended to
// support per-argv (not just per-command) scripting since this collector invokes `wg` with
// several distinct argvs.
function scriptedExec(script, calls = []) {
  return async (command, args = []) => {
    calls.push([command, ...args]);
    const key = JSON.stringify([command, ...args]);
    const handler = script[key];
    if (!handler) throw new Error(`unscripted command in test fake: ${key}`);
    return typeof handler === "function" ? handler(args) : handler;
  };
}

// ---------------------------------------------------------------------------------------------
// parseWhoOutput
// ---------------------------------------------------------------------------------------------

test("parseWhoOutput extracts the parenthetical remote host for a remote login, leaves it undefined for a local one", () => {
  const stdout = [
    "alice    pts/0        2026-07-13 08:00 (203.0.113.5)",
    "bob      tty7         2026-07-13 07:00",
  ].join("\n");
  const { entries } = parseWhoOutput(stdout);
  assert.deepEqual(entries, [
    { remote_user: "alice", remote_host: "203.0.113.5" },
    { remote_user: "bob", remote_host: undefined },
  ]);
});

test("parseWhoOutput on zero remote logins (all-local) yields entries with no remote_host — a real, distinguishable zero", () => {
  const { entries } = parseWhoOutput("bob      ttys000    Jul 13 08:00\n");
  assert.equal(entries.length, 1);
  assert.equal(entries[0].remote_host, undefined);
});

test("parseWhoOutput on empty stdout yields zero entries", () => {
  assert.deepEqual(parseWhoOutput(""), { entries: [] });
});

// ---------------------------------------------------------------------------------------------
// parseLastOutput — per-platform hostname fixtures (must-fix 7)
// ---------------------------------------------------------------------------------------------

test("parseLastOutput (macOS/BSD-shaped fixture): parses a remote entry, skips reboot pseudo-entries and local sessions", () => {
  const stdout = [
    "alice    ttys000  203.0.113.5      Mon Jun  1 09:00   still logged in",
    "reboot   ~                        Mon Jun  1 00:00",
    "bob      console  -                Mon Jun  1 08:00 - 08:30  (00:30)",
  ].join("\n");
  const { entries, malformed_count } = parseLastOutput(stdout);
  assert.equal(malformed_count, 0);
  assert.deepEqual(entries, [{ remote_user: "alice", remote_host: "203.0.113.5" }]);
});

test("parseLastOutput (Linux/GNU-shaped fixture): parses a remote hostname entry, skips the reboot pseudo-entry and the wtmp trailer", () => {
  const stdout = [
    "alice    pts/0        host-01.internal Sun Jul 13 08:00   still logged in",
    "reboot   system boot  5.15.0-generic   Sun Jul 13 06:00",
    "",
    "wtmp begins Sun Jul  6 00:00:00 2026",
  ].join("\n");
  const { entries, malformed_count } = parseLastOutput(stdout);
  assert.equal(malformed_count, 0);
  assert.deepEqual(entries, [{ remote_user: "alice", remote_host: "host-01.internal" }]);
});

test("parseLastOutput captures a long/truncated hostname token verbatim, whatever `last` already printed, without crashing", () => {
  // Real `last` implementations may truncate a long remote hostname to a fixed column width
  // (BSD/macOS `last` truncates to 16 chars historically) before this parser ever sees it — the
  // parser takes whatever token is there rather than assuming/re-deriving a column width itself.
  const truncatedHost = "extremely-long-h"; // simulates a real truncated 16-char host column
  const stdout = `alice    pts/1    ${truncatedHost}  Sun Jul 13 07:00 - 07:30  (00:30)`;
  const { entries } = parseLastOutput(stdout);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].remote_host, truncatedHost);
});

test("parseLastOutput skips a short/malformed line (fewer than 3 tokens) without fabricating a partial entry", () => {
  const { entries, malformed_count } = parseLastOutput("alice pts/0\n");
  assert.deepEqual(entries, []);
  assert.equal(malformed_count, 1);
});

test("parseLastOutput on empty stdout yields zero entries, zero malformed", () => {
  assert.deepEqual(parseLastOutput(""), { entries: [], malformed_count: 0 });
});

// ---------------------------------------------------------------------------------------------
// WireGuard parsers
// ---------------------------------------------------------------------------------------------

test("parseWgInterfaceList splits on whitespace, tolerates a single or multiple interfaces, and empty (real zero)", () => {
  assert.deepEqual(parseWgInterfaceList("wg0\n"), ["wg0"]);
  assert.deepEqual(parseWgInterfaceList("wg0 wg1\n"), ["wg0", "wg1"]);
  assert.deepEqual(parseWgInterfaceList(""), []);
});

test("parseWgPeerList returns one pubkey per line, empty for a real zero-peers interface", () => {
  const stdout = "+zx8L34dHV/wYi9YWNSKB2VBRTZ2hkQtwT8daVGVOX8=\nxTIBA5rboUvnH4htodjb6e697QjLERt1TrOxweBWSQ8=\n";
  assert.deepEqual(parseWgPeerList(stdout), [
    "+zx8L34dHV/wYi9YWNSKB2VBRTZ2hkQtwT8daVGVOX8=",
    "xTIBA5rboUvnH4htodjb6e697QjLERt1TrOxweBWSQ8=",
  ]);
  assert.deepEqual(parseWgPeerList(""), []);
});

test("parseWgEndpoints maps pubkey -> endpoint, treating '(none)' as no endpoint", () => {
  const stdout = "keyA\t203.0.113.10:51820\nkeyB\t(none)\n";
  assert.deepEqual(parseWgEndpoints(stdout), { keyA: "203.0.113.10:51820", keyB: undefined });
});

test("parseWgHandshakes maps pubkey -> epoch seconds, 0 means never handshaked", () => {
  const stdout = "keyA\t1720000000\nkeyB\t0\n";
  assert.deepEqual(parseWgHandshakes(stdout), { keyA: 1720000000, keyB: 0 });
});

// ---------------------------------------------------------------------------------------------
// scutil --nc list
// ---------------------------------------------------------------------------------------------

test("parseScutilNcList parses connected/disconnected VPN service lines", () => {
  const stdout = [
    '* (Connected)    1E4E6C58-F859-4E51-92A6-BF4B14A23689 "Corp VPN"     [PPP:L2TP]',
    '  (Disconnected) 2A7BDCE1-1234-4E51-92A6-BF4B14A23690 "Home VPN"     [IPSec]',
  ].join("\n");
  const services = parseScutilNcList(stdout);
  assert.deepEqual(services, [
    { status: "Connected", service_uuid: "1E4E6C58-F859-4E51-92A6-BF4B14A23689", service_name: "Corp VPN" },
    { status: "Disconnected", service_uuid: "2A7BDCE1-1234-4E51-92A6-BF4B14A23690", service_name: "Home VPN" },
  ]);
});

test("parseScutilNcList on empty stdout yields zero services (real zero)", () => {
  assert.deepEqual(parseScutilNcList(""), []);
});

// ---------------------------------------------------------------------------------------------
// WireGuard CLOSED ALLOWLIST — static + behavioral (must-fixes 1/2)
// ---------------------------------------------------------------------------------------------

test("STATIC: every runExec(\"wg\", [...]) call site in the source constructs only the closed allowlist argv, never a secret-dumping subcommand", () => {
  const source = readFileSync(SRC_FILE, "utf8");
  const callSiteRe = /runExec\(\s*"wg"\s*,\s*\[([^\]]*)\]/g;
  const callSites = [...source.matchAll(callSiteRe)];
  assert.equal(callSites.length, 4, `expected exactly 4 wg call sites (interfaces, peers, endpoints, latest-handshakes), found ${callSites.length}`);

  const literalTokens = new Set();
  for (const match of callSites) {
    const stringLiteralRe = /"([^"]*)"/g;
    let literalMatch;
    while ((literalMatch = stringLiteralRe.exec(match[1]))) {
      literalTokens.add(literalMatch[1]);
    }
  }

  assert.deepEqual([...literalTokens].sort(), ["endpoints", "interfaces", "latest-handshakes", "peers", "show"].sort());

  const forbidden = ["dump", "showconf", "private-key", "preshared-keys"];
  for (const token of forbidden) {
    assert.equal(literalTokens.has(token), false, `forbidden wg subcommand token "${token}" must never be constructible`);
  }
});

// Strips "//" line comments (this file uses only "//" comments, never "/* */" blocks, and none
// of its string/regex literals contain a literal "//" sequence — verified by inspection — so a
// naive per-line strip is safe here without needing full regex-literal-aware tokenizing, unlike
// the general-purpose escalation-lint.test.js scanner).
function stripLineComments(source) {
  return source.split("\n").map((line) => {
    const index = line.indexOf("//");
    return index === -1 ? line : line.slice(0, index);
  }).join("\n");
}

test("STATIC: with comments stripped, the CODE never references wg showconf, private-key, or preshared-keys as a bare identifier/string (defense in depth beyond the call-site scan; these words ARE allowed in comments, which document them as forbidden)", () => {
  const codeOnly = stripLineComments(readFileSync(SRC_FILE, "utf8"));
  assert.equal(/\bshowconf\b/.test(codeOnly), false);
  assert.equal(/\bpreshared-keys\b/.test(codeOnly), false);
  // "private-key" (singular) is checked, not "private" alone, to avoid false positives against
  // unrelated words; this file has no legitimate reason to reference it in real code at all.
  assert.equal(/\bprivate-key\b/.test(codeOnly), false);
});

test("BEHAVIORAL: across multiple interfaces (including an adversarial interface name), the ONLY wg argvs invoked are the closed allowlist set, each interface-scoped call is exactly 3 argv elements", async () => {
  const calls = [];
  const adversarialIface = "wg0; wg show wg0 dump"; // a crafted/compromised interface name
  const script = {
    [JSON.stringify(["wg", "show", "interfaces"])]: ok(["wg0", adversarialIface].join(" ")),
    [JSON.stringify(["wg", "show", "wg0", "peers"])]: ok("keyA\n"),
    [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok("keyA\t203.0.113.10:51820\n"),
    [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok("keyA\t1720000000\n"),
    [JSON.stringify(["wg", "show", adversarialIface, "peers"])]: ok(""),
    [JSON.stringify(["wg", "show", adversarialIface, "endpoints"])]: ok(""),
    [JSON.stringify(["wg", "show", adversarialIface, "latest-handshakes"])]: ok(""),
    [JSON.stringify(["who"])]: enoent(),
    [JSON.stringify(["last", "-n", String(DEFAULT_LAST_HISTORY_LIMIT)])]: enoent(),
    [JSON.stringify(["netstat", "-an", "-p", "tcp"])]: ok(""),
    [JSON.stringify(["scutil", "--nc", "list"])]: enoent(),
  };
  const runFixedExecFile = scriptedExec(script, calls);

  await collectVpnPeerStatusEvidence({ platform: "darwin", runFixedExecFile });

  const wgCalls = calls.filter(([command]) => command === "wg");
  for (const call of wgCalls) {
    const [, ...args] = call;
    assert.equal(args[0], "show");
    if (args.length > 2) {
      // Interface-scoped calls are ALWAYS exactly 3 argv elements: ["show", <iface>, <subcommand>]
      // — the adversarial interface name occupies exactly ONE array slot, proving it cannot smuggle
      // in an additional subcommand token (execFile takes an argv array, never a shell string).
      assert.equal(args.length, 3, `expected exactly 3 argv elements, got ${JSON.stringify(args)}`);
      assert.ok(["peers", "endpoints", "latest-handshakes"].includes(args[2]));
    } else {
      assert.deepEqual(args, ["show", "interfaces"]);
    }
  }
  const allTokens = wgCalls.flat();
  for (const forbidden of ["dump", "showconf", "private-key", "preshared-keys"]) {
    assert.equal(allTokens.includes(forbidden), false);
  }
});

test("MAX_WG_INTERFACES: more configured interfaces than the cap are truncated with an explicit interfaces_truncated flag + total count — never silently dropped", async () => {
  const N = 18; // > MAX_WG_INTERFACES (16)
  const ifaceNames = Array.from({ length: N }, (_, i) => `wg${i}`);
  const script = {
    [JSON.stringify(["wg", "show", "interfaces"])]: ok(ifaceNames.join(" ")),
    [JSON.stringify(["who"])]: enoent(),
    [JSON.stringify(["last", "-n", String(DEFAULT_LAST_HISTORY_LIMIT)])]: enoent(),
    [JSON.stringify(["scutil", "--nc", "list"])]: enoent(),
    [JSON.stringify(["netstat", "-an", "-p", "tcp"])]: enoent(),
    [JSON.stringify(["ss", "-H", "-tn", "state", "established"])]: enoent(),
  };
  // Only the first MAX_WG_INTERFACES interfaces are ever probed per-interface (after the cap slice).
  for (const iface of ifaceNames.slice(0, 16)) {
    script[JSON.stringify(["wg", "show", iface, "peers"])] = ok("");
    script[JSON.stringify(["wg", "show", iface, "endpoints"])] = ok("");
    script[JSON.stringify(["wg", "show", iface, "latest-handshakes"])] = ok("");
  }
  const calls = [];
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile: scriptedExec(script, calls) });

  const wg = envelope.result.sources.wireguard;
  assert.equal(wg.interfaces_truncated, true, "truncation past the interface cap must be flagged, not silent");
  assert.equal(wg.total_interface_count, N, "the real configured-interface count is preserved");
  assert.equal(wg.interfaces.length, 16, "only the capped number of interfaces are enumerated");
  const probedIfaces = new Set(calls.filter((call) => call[0] === "wg" && call.length === 4).map((call) => call[2]));
  assert.equal(probedIfaces.has("wg16"), false, "the 17th interface (index 16) must not be probed");
  assert.equal(probedIfaces.has("wg17"), false, "the 18th interface must not be probed");
});

// ---------------------------------------------------------------------------------------------
// Degrade matrix (per-source, never fabricated)
// ---------------------------------------------------------------------------------------------

function baseScript(overrides = {}) {
  return {
    [JSON.stringify(["who"])]: enoent(),
    [JSON.stringify(["last", "-n", String(DEFAULT_LAST_HISTORY_LIMIT)])]: enoent(),
    [JSON.stringify(["wg", "show", "interfaces"])]: enoent(),
    [JSON.stringify(["scutil", "--nc", "list"])]: enoent(),
    [JSON.stringify(["netstat", "-an", "-p", "tcp"])]: enoent(),
    [JSON.stringify(["ss", "-H", "-tn", "state", "established"])]: enoent(),
    ...overrides,
  };
}

test("no-VPN: every source absent/not_applicable -> envelope unable/confidence:0, NEVER fabricated as zero peers", async () => {
  const runFixedExecFile = scriptedExec(baseScript());
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  assert.equal(envelope.result.any_source_available, false);
  assert.deepEqual(envelope.result.peers, []);
});

test("who resolves with zero remote logins (ok+empty) -> envelope ok, distinguishable from the all-absent case", async () => {
  const runFixedExecFile = scriptedExec(baseScript({ [JSON.stringify(["who"])]: ok("bob   ttys000   Jul 13 08:00\n") }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.confidence, 1);
  assert.equal(envelope.result.sources.ssh_who.status, "ok");
  assert.deepEqual(envelope.result.peers, []);
  assert.equal(envelope.result.total_count, 0);
});

test("SSH-only: who reports a remote login, WG/scutil absent -> exactly one ssh peer, WG recorded absent", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["who"])]: ok("alice   pts/0   2026-07-13 08:00 (203.0.113.5)\n"),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.result.total_count, 1);
  assert.equal(envelope.result.peers[0].source_type, "ssh");
  assert.equal(envelope.result.sources.wireguard.status, "absent");
});

test("WireGuard present with peers, SSH absent -> exactly the WG peers, no fabricated SSH data", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: ok("wg0\n"),
    [JSON.stringify(["wg", "show", "wg0", "peers"])]: ok("keyA\nkeyB\n"),
    [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok("keyA\t203.0.113.10:51820\nkeyB\t(none)\n"),
    [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok("keyA\t1720000000\nkeyB\t0\n"),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.result.total_count, 2);
  assert.deepEqual(envelope.result.peers.map((peer) => peer.source_type), ["wireguard", "wireguard"]);
  assert.equal(envelope.result.sources.ssh_who.status, "absent");
});

test("WireGuard present, ZERO configured interfaces -> ok/empty, a real zero, never unable", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: ok(""),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.result.sources.wireguard.status, "ok");
  assert.deepEqual(envelope.result.sources.wireguard.interfaces, []);
});

test("permission-denied on `wg show interfaces` -> missing_permission, elevation_candidate:true, NEVER escalated", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: permissionDenied(),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.result.sources.wireguard.status, "missing_permission");
  assert.equal(envelope.result.sources.wireguard.elevation_candidate, true);
});

test("permission-denied on a per-interface wg subcommand -> that interface is 'missing_permission', overall wireguard status 'partial'", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: ok("wg0\n"),
    [JSON.stringify(["wg", "show", "wg0", "peers"])]: permissionDenied(),
    [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok(""),
    [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok(""),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.result.sources.wireguard.status, "partial");
  assert.deepEqual(envelope.result.sources.wireguard.interfaces, [{ name: "wg0", status: "missing_permission", error: "boom" }]);
});

test("permission-denied on who/last -> missing_permission, never fabricated as zero", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["who"])]: permissionDenied(),
    [JSON.stringify(["last", "-n", String(DEFAULT_LAST_HISTORY_LIMIT)])]: permissionDenied(),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.result.sources.ssh_who.status, "missing_permission");
  assert.equal(envelope.result.sources.ssh_last.status, "missing_permission");
});

test("macOS VPN service connected -> vpn_service peer with presence_state observed_active; disconnected -> observed_historical", async () => {
  const runFixedExecFile = scriptedExec(baseScript({
    [JSON.stringify(["scutil", "--nc", "list"])]: ok([
      '* (Connected)    1E4E6C58-F859-4E51-92A6-BF4B14A23689 "Corp VPN"     [PPP:L2TP]',
      '  (Disconnected) 2A7BDCE1-1234-4E51-92A6-BF4B14A23690 "Home VPN"     [IPSec]',
    ].join("\n")),
  }));
  const envelope = await collectVpnPeerStatusEvidence({ platform: "darwin", runFixedExecFile });
  const services = envelope.result.peers.filter((peer) => peer.source_type === "vpn_service");
  assert.equal(services.length, 2);
  const corp = services.find((s) => s.service_name === "Corp VPN");
  const home = services.find((s) => s.service_name === "Home VPN");
  assert.equal(corp.presence_state, "observed_active");
  assert.equal(home.presence_state, "observed_historical");
});

test("scutil is never attempted on Linux (not_applicable, no execFile call at all)", async () => {
  const calls = [];
  const runFixedExecFile = scriptedExec(baseScript(), calls);
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  assert.equal(envelope.result.sources.vpn_services.status, "not_applicable");
  assert.equal(calls.some(([command]) => command === "scutil"), false);
});

test("established-inbound uses `ss` on Linux and `netstat` on macOS, and is never translated into a peer record", async () => {
  const linuxScript = baseScript({ [JSON.stringify(["ss", "-H", "-tn", "state", "established"])]: ok("line1\nline2\n") });
  const linuxEnvelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile: scriptedExec(linuxScript) });
  assert.equal(linuxEnvelope.result.sources.established_inbound.status, "ok");
  assert.equal(linuxEnvelope.result.peers.some((peer) => peer.source_type === "established_inbound"), false);

  const macScript = baseScript({ [JSON.stringify(["netstat", "-an", "-p", "tcp"])]: ok("tcp4 0 0 *.22 *.* LISTEN\ntcp4 0 0 10.0.0.5.22 10.0.0.9.51000 ESTABLISHED\n") });
  const macEnvelope = await collectVpnPeerStatusEvidence({ platform: "darwin", runFixedExecFile: scriptedExec(macScript) });
  assert.equal(macEnvelope.result.sources.established_inbound.status, "ok");
});

// ---------------------------------------------------------------------------------------------
// Per-tick peer entity cap + overflow marker, bounded `last -n <N>` (must-fix 3)
// ---------------------------------------------------------------------------------------------

test("DEFAULT_PEER_ENTITY_LIMIT and DEFAULT_LAST_HISTORY_LIMIT are positive finite bounds", () => {
  assert(Number.isFinite(DEFAULT_PEER_ENTITY_LIMIT) && DEFAULT_PEER_ENTITY_LIMIT > 0);
  assert(Number.isFinite(DEFAULT_LAST_HISTORY_LIMIT) && DEFAULT_LAST_HISTORY_LIMIT > 0);
});

test("`last` is invoked with a BOUNDED -n <N> argument, never an unbounded read", async () => {
  const calls = [];
  const runFixedExecFile = scriptedExec(baseScript(), calls);
  await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile });
  const lastCall = calls.find(([command]) => command === "last");
  assert.deepEqual(lastCall, ["last", "-n", String(DEFAULT_LAST_HISTORY_LIMIT)]);
});

test("a custom lastHistoryLimit is honored and still bounded (fixture-pinned per-platform N)", async () => {
  const calls = [];
  const script = baseScript();
  script[JSON.stringify(["last", "-n", "5"])] = enoent();
  const runFixedExecFile = scriptedExec(script, calls);
  await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile, lastHistoryLimit: 5 });
  const lastCall = calls.find(([command]) => command === "last");
  assert.deepEqual(lastCall, ["last", "-n", "5"]);
});

test("a peer flood above the cap is bounded at the cap, with truncated:true and the real total preserved", async () => {
  const cap = 5;
  const pubkeys = Array.from({ length: cap * 4 }, (_, i) => `key-${i}`).join("\n");
  const script = baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: ok("wg0\n"),
    [JSON.stringify(["wg", "show", "wg0", "peers"])]: ok(pubkeys),
    [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok(""),
    [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok(""),
  });
  const runFixedExecFile = scriptedExec(script);
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile, peerLimit: cap });
  assert.equal(envelope.result.total_count, cap * 4);
  assert.equal(envelope.result.peers.length, cap);
  assert.equal(envelope.result.truncated, true);
  assert.equal(envelope.result.cap, cap);
});

test("a peer count at or below the cap is never marked truncated", async () => {
  const cap = 5;
  const pubkeys = Array.from({ length: cap }, (_, i) => `key-${i}`).join("\n");
  const script = baseScript({
    [JSON.stringify(["wg", "show", "interfaces"])]: ok("wg0\n"),
    [JSON.stringify(["wg", "show", "wg0", "peers"])]: ok(pubkeys),
    [JSON.stringify(["wg", "show", "wg0", "endpoints"])]: ok(""),
    [JSON.stringify(["wg", "show", "wg0", "latest-handshakes"])]: ok(""),
  });
  const envelope = await collectVpnPeerStatusEvidence({ platform: "linux", runFixedExecFile: scriptedExec(script), peerLimit: cap });
  assert.equal(envelope.result.peers.length, cap);
  assert.equal(envelope.result.truncated, false);
});
