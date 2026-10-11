import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectTailscaleStatusEvidence,
  DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT,
  parseTailscaleStatusJson,
  MAX_TAILSCALE_PEER_ENTITY_LIMIT,
} from "../src/tools/tailscale-status.js";

const SRC_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools", "tailscale-status.js");

function ok(stdout, stderr = "") {
  return { status: "ok", stdout, stderr, command: { argv: ["fixture"], read_only: true } };
}

function failure({ code, stdout = "", stderr = "", error = "boom" } = {}) {
  return { status: "error", code, stdout, stderr, error, command: { argv: ["fixture"], read_only: true } };
}

function enoent() {
  return failure({ code: "ENOENT", error: "spawn ENOENT" });
}

function untrusted() {
  return {
    status: "untrusted_binary",
    error: "untrusted",
    command: { argv: ["tailscale"], read_only: true },
    binary: {
      binary: "tailscale",
      status: "untrusted_binary",
      resolved_path: "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
      trust_verdict: "untrusted_binary",
      offending_component: "/Applications",
      trust_reason: "group_writable",
    },
  };
}

function permissionDenied(stderr = "Permission denied\n") {
  return failure({ code: 1, stderr });
}

function scriptedExec(script, calls = []) {
  return async (command, args = [], options = {}) => {
    calls.push({ command, args, options });
    const key = JSON.stringify([command, ...args]);
    const handler = script[key];
    if (!handler) throw new Error(`unscripted command in test fake: ${key}`);
    return typeof handler === "function" ? handler(args, options) : handler;
  };
}

const PUBLIC_KEY_A = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=";
const PUBLIC_KEY_B = "xTIBA5rboUvnH4htodjb6e697QjLERt1TrOxweBWSQ8=";
const PUBLIC_KEY_C = "QWERTYuiopASDFGHjklZXCVBNM1234567890abcd=";

function runningFixture(peerOverrides = {}) {
  return JSON.stringify({
    BackendState: "Running",
    Peer: {
      [PUBLIC_KEY_A]: {
        PublicKey: PUBLIC_KEY_A,
        Online: true,
        ExitNode: true,
        ExitNodeOption: true,
        LastHandshake: "2026-08-11T00:00:00Z",
        ...peerOverrides.active,
      },
      [PUBLIC_KEY_B]: {
        PublicKey: PUBLIC_KEY_B,
        Online: true,
        ExitNode: false,
        ExitNodeOption: false,
        LastHandshake: "2026-08-10T23:59:00Z",
        ...peerOverrides.plain,
      },
      [PUBLIC_KEY_C]: {
        PublicKey: PUBLIC_KEY_C,
        Online: false,
        ExitNode: false,
        ExitNodeOption: true,
        LastHandshake: "0001-01-01T00:00:00Z",
        ...peerOverrides.historical,
      },
    },
  });
}

function baseScript(result = enoent()) {
  return { [JSON.stringify(["tailscale", "status", "--json"])]: result };
}

test("parseTailscaleStatusJson maps a Running Peer map into the bounded in-memory peer shape", () => {
  const parsed = parseTailscaleStatusJson(runningFixture({ historical: { LastHandshake: "0001-01-01T00:00:00Z" } }));
  assert.equal(parsed.backend_state, "Running");
  assert.deepEqual(parsed.peers, [
    {
      source_type: "tailscale",
      presence_state: "observed_active",
      node_public_key: PUBLIC_KEY_A,
      is_exit_node_active: true,
      is_exit_node_option: true,
      latest_handshake_epoch_seconds: 1786406400,
    },
    {
      source_type: "tailscale",
      presence_state: "observed_active",
      node_public_key: PUBLIC_KEY_B,
      is_exit_node_active: false,
      is_exit_node_option: false,
      latest_handshake_epoch_seconds: 1786406340,
    },
    {
      source_type: "tailscale",
      presence_state: "observed_historical",
      node_public_key: PUBLIC_KEY_C,
      is_exit_node_active: false,
      is_exit_node_option: true,
      latest_handshake_epoch_seconds: 0,
    },
  ]);
});

test("parseTailscaleStatusJson keeps an absent LastHandshake distinct from the Go zero-time sentinel", () => {
  const parsed = parseTailscaleStatusJson(JSON.stringify({
    BackendState: "Running",
    Peer: {
      [PUBLIC_KEY_A]: { PublicKey: PUBLIC_KEY_A, Online: false, ExitNode: false, ExitNodeOption: false },
      [PUBLIC_KEY_B]: { PublicKey: PUBLIC_KEY_B, Online: false },
    },
  }));
  assert.equal(parsed.peers[0].latest_handshake_epoch_seconds, undefined);
  assert.equal(parsed.peers[1].latest_handshake_epoch_seconds, undefined);
});

test("parseTailscaleStatusJson rejects a malformed LastHandshake instead of turning it into unknown", () => {
  const parsed = parseTailscaleStatusJson(JSON.stringify({
    BackendState: "Running",
    Peer: { [PUBLIC_KEY_A]: { PublicKey: PUBLIC_KEY_A, Online: false, LastHandshake: "not-a-timestamp" } },
  }));
  assert.equal(parsed.peer_map_valid, false);
  assert.deepEqual(parsed.peers, []);
});

test("parseTailscaleStatusJson rejects malformed JSON instead of partially trusting it", () => {
  assert.throws(() => parseTailscaleStatusJson('{"BackendState":"Running","Peer":'), SyntaxError);
  assert.throws(() => parseTailscaleStatusJson({ BackendState: "Running", Peer: {} }), /tailscale status JSON must be a string/);
});

test("STATIC: tailscale status has exactly one fixed read-only argv and no constructible mutating subcommand", () => {
  const source = readFileSync(SRC_FILE, "utf8");
  const codeOnly = source.split("\n").map((line) => line.slice(0, line.indexOf("//") === -1 ? undefined : line.indexOf("//"))).join("\n");
  const callSites = [...codeOnly.matchAll(/runExec\(\s*"tailscale"\s*,\s*\[([^\]]*)\]/g)];
  assert.equal(callSites.length, 1);
  assert.deepEqual([...callSites[0][1].matchAll(/"([^"]*)"/g)].map((match) => match[1]), ["status", "--json"]);
  for (const token of ["up", "down", "set", "logout", "login", "switch", "configure", "serve", "funnel", "lock", "ssh", "cert"]) {
    assert.equal(new RegExp(`\\b${token}\\b`).test(codeOnly), false, `forbidden tailscale subcommand ${token} must not be constructible`);
  }
});

test("BEHAVIORAL: the collector invokes only tailscale status --json", async () => {
  const calls = [];
  const envelope = await collectTailscaleStatusEvidence({
    runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Peer: {} })), calls), calls),
  });
  assert.equal(envelope.status, "ok");
  assert.deepEqual(calls.map(({ command, args }) => [command, ...args]), [["tailscale", "status", "--json"]]);
});

test("ENOENT is not-found-on-known-paths and never fabricates a zero", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript()) });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  assert.equal(envelope.result.status, "not_found_on_known_paths");
  assert.deepEqual(envelope.result.peers, []);
});

test("untrusted binary remains explicit with offending component, reason, and operator override hint", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(untrusted())) });
  assert.equal(envelope.result.status, "untrusted_binary");
  assert.equal(envelope.status, "warning");
  assert.equal(envelope.review_hint, "untrusted_binary");
  assert.equal(envelope.result.binary_provenance.offending_component, "/Applications");
  assert.equal(envelope.result.binary_provenance.trust_reason, "group_writable");
  assert.match(envelope.result.operator_override_hint, /trusted_binary_paths/);
});

for (const backendState of ["NeedsLogin", "NoState", "Stopped", "NeedsMachineAuth", "Starting"]) {
  test(`${backendState} is a truthful logged_out zero, not unable`, async () => {
    const result = JSON.stringify({ BackendState: backendState, Peer: {} });
    const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(result))) });
    assert.equal(envelope.status, "unable");
    assert.equal(envelope.confidence, 0);
    assert.equal(envelope.result.status, "logged_out");
    assert.deepEqual(envelope.result.peers, []);
  });
}

test("permission denial degrades to missing_permission with elevation_candidate documentation only", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(permissionDenied())) });
  assert.equal(envelope.result.status, "missing_permission");
  assert.equal(envelope.result.elevation_candidate, true);
  assert.equal(envelope.status, "unable");
});

test("malformed/truncated JSON degrades to unable and never emits partial peers", async () => {
  const script = baseScript(ok('{"BackendState":"Running","Peer":{'));
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(script) });
  assert.equal(envelope.result.status, "unable");
  assert.deepEqual(envelope.result.peers, []);
  assert.equal(envelope.status, "unable");
});

test("Running with zero peers is an outer ok, genuine zero", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Peer: {} })))) });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.confidence, 1);
  assert.equal(envelope.result.status, "ok");
  assert.equal(envelope.result.total_count, 0);
  assert.deepEqual(envelope.result.peers, []);
});

test("peer cap preserves truncation and total_count", async () => {
  const peers = Object.fromEntries(Array.from({ length: 7 }, (_, index) => {
    const key = `peer-${index}`;
    return [key, { PublicKey: key, Online: true }];
  }));
  const envelope = await collectTailscaleStatusEvidence({
    peerLimit: 3,
    runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Peer: peers })))),
  });
  assert.equal(envelope.result.total_count, 7);
  assert.equal(envelope.result.peers.length, 3);
  assert.equal(envelope.result.truncated, true);
  assert.equal(envelope.result.cap, 3);
});

test("timeout and maxBuffer options are passed to the fixed execFile probe", async () => {
  const calls = [];
  await collectTailscaleStatusEvidence({
    timeout: 1234,
    maxBuffer: 4567,
    runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Peer: {} }))), calls),
  });
  assert.deepEqual(calls[0], {
    command: "tailscale",
    args: ["status", "--json"],
    options: { timeout: 1234, maxBuffer: 4567 },
  });
});

test("DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT is a positive finite bound", () => {
  assert(Number.isFinite(DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT) && DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT > 0);
});

// Fact-store capacity plan §2/S4: the Tailscale peer cap is a hard UPPER clamp (T8).
test("an options.peerLimit above MAX_TAILSCALE_PEER_ENTITY_LIMIT is clamped down to it", async () => {
  const peers = Object.fromEntries(Array.from({ length: MAX_TAILSCALE_PEER_ENTITY_LIMIT + 5 }, (_, index) => {
    const key = `peer-${index}`;
    return [key, { PublicKey: key, Online: true }];
  }));
  const envelope = await collectTailscaleStatusEvidence({
    peerLimit: 100_000,
    runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Peer: peers })))),
  });
  assert.equal(envelope.result.cap, MAX_TAILSCALE_PEER_ENTITY_LIMIT);
  assert.equal(envelope.result.peers.length, MAX_TAILSCALE_PEER_ENTITY_LIMIT);
  assert.equal(envelope.result.truncated, true);
});

// --- Context plan C0.3: tailnet state for every probe outcome ---

test("C0.3: parseTailscaleStatusJson reads BackendState without requiring Peer (logged-out daemons omit it)", () => {
  const parsed = parseTailscaleStatusJson(JSON.stringify({ BackendState: "NeedsLogin", Health: ["not logged in"] }));
  assert.equal(parsed.backend_state, "NeedsLogin");
  assert.equal(parsed.peer_map_valid, false);
  assert.deepEqual(parsed.peers, []);
  assert.deepEqual(parsed.tailnet, { backend_state: "NeedsLogin", self_online: undefined, exit_node_in_use: undefined, health_issue_count: 1, current_tailnet_name: undefined });
  assert.throws(() => parseTailscaleStatusJson(JSON.stringify({ Peer: {} })), SyntaxError, "BackendState stays required");
});

test("C0.3: a Running status carries Self.Online, exit-node use, the health-issue count and the raw CurrentTailnet name in memory only", () => {
  const parsed = parseTailscaleStatusJson(JSON.stringify({
    ...JSON.parse(runningFixture()),
    Self: { Online: true },
    Health: ["a", "b"],
    ExitNodeStatus: { ID: "n1", Online: true },
    CurrentTailnet: { Name: "corp.example", MagicDNSSuffix: "corp.ts.net", MagicDNSEnabled: true },
  }));
  assert.equal(parsed.peer_map_valid, true);
  assert.deepEqual(parsed.tailnet, { backend_state: "Running", self_online: true, exit_node_in_use: true, health_issue_count: 2, current_tailnet_name: "corp.example" });
  const noExit = parseTailscaleStatusJson(JSON.stringify({ BackendState: "Running", Peer: {}, Self: { Online: false } }));
  assert.equal(noExit.tailnet.exit_node_in_use, false, "Running with a valid Peer map and no exit node status or exit-node peer");
  assert.equal(noExit.tailnet.self_online, false);
  assert.equal(noExit.tailnet.health_issue_count, undefined, "an absent Health list is unknown, never a zero");
  const peerExit = parseTailscaleStatusJson(runningFixture());
  assert.equal(peerExit.tailnet.exit_node_in_use, true, "a peer marked ExitNode is an exit node in use");
});

test("C0.3: logged-out outcomes without a Peer map stay logged_out and carry the tailnet state", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Stopped" })))) });
  assert.equal(envelope.result.status, "logged_out");
  assert.equal(envelope.status, "unable");
  assert.deepEqual(envelope.result.peers, []);
  assert.equal(envelope.result.tailnet.backend_state, "Stopped");
});

test("C0.3: Running without a Peer map is NOT an ok zero-peer tick for the peer census, but its tailnet state is kept", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Running", Self: { Online: true } })))) });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.result.status, "unable");
  assert.deepEqual(envelope.result.peers, []);
  assert.equal(envelope.result.tailnet.backend_state, "Running");
  assert.equal(envelope.result.tailnet.self_online, true);
});

test("B3 daybreak reproduction: one malformed Peer entry invalidates the whole population and makes exit-node use unknown", async () => {
  const malformed = JSON.stringify({ BackendState: "Running", Peer: { bad: { Online: true } }, Self: { Online: true } });
  const parsed = parseTailscaleStatusJson(malformed);
  assert.equal(parsed.peer_map_valid, false);
  assert.deepEqual(parsed.peers, []);
  assert.equal(parsed.tailnet.exit_node_in_use, undefined);

  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(malformed))) });
  assert.equal(envelope.result.status, "unable");
  assert.equal(envelope.result.total_count, 0);
  assert.deepEqual(envelope.result.peers, []);
  assert.equal(envelope.result.tailnet.exit_node_in_use, undefined);
});

test("B1 daybreak reproduction: string boolean peer fields invalidate the population and exit-node use", async () => {
  const malformed = JSON.stringify({
    BackendState: "Running",
    Peer: {
      [PUBLIC_KEY_A]: {
        PublicKey: PUBLIC_KEY_A,
        Online: "false",
        ExitNode: "false",
        ExitNodeOption: "false",
      },
    },
    Self: { Online: true },
  });
  const parsed = parseTailscaleStatusJson(malformed);
  assert.equal(parsed.peer_map_valid, false);
  assert.deepEqual(parsed.peers, []);
  assert.equal(parsed.tailnet.exit_node_in_use, undefined);

  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(malformed))) });
  assert.equal(envelope.result.status, "unable");
  assert.equal(envelope.result.tailnet.exit_node_in_use, undefined);
  assert.deepEqual(envelope.result.peers, []);
});

test("B1: malformed consumed tailnet fields invalidate the source instead of becoming absent or false", () => {
  for (const [field, value] of [
    ["Self", { Online: "false" }],
    ["CurrentTailnet", { Name: false }],
    ["Health", ["healthy", 7]],
  ]) {
    const parsed = parseTailscaleStatusJson(JSON.stringify({ BackendState: "Running", Peer: {}, [field]: value }));
    assert.equal(parsed.tailnet.valid, false, field);
    assert.equal(parsed.tailnet.exit_node_in_use, undefined, field);
  }
});

test("C0.3: an unrecognized BackendState keeps the peer envelope unable and records the raw state for the translator to classify", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript(ok(JSON.stringify({ BackendState: "Weird", Peer: {} })))) });
  assert.equal(envelope.result.status, "unable");
  assert.equal(envelope.result.tailnet.backend_state, "Weird");
});

test("C0 review H1: redactTailscaleEnvelopeForModel strips the raw tailnet name (presence flag only) without mutating its input", async () => {
  const { redactTailscaleEnvelopeForModel } = await import("../src/tools/tailscale-status.js");
  const envelope = { id: "tailscale-status", result: { status: "ok", tailnet: { backend_state: "Running", self_online: true, current_tailnet_name: "corp.example.ts.net" } } };
  const redacted = redactTailscaleEnvelopeForModel(envelope);
  assert.ok(!JSON.stringify(redacted).includes("corp.example"));
  assert.equal(redacted.result.tailnet.current_tailnet_name_present, true);
  assert.equal(redacted.result.tailnet.self_online, true);
  assert.equal(envelope.result.tailnet.current_tailnet_name, "corp.example.ts.net", "input not mutated");
  const absent = { id: "tailscale-status", result: { status: "unable" } };
  assert.equal(redactTailscaleEnvelopeForModel(absent), absent);
});
