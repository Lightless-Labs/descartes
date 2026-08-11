import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectTailscaleStatusEvidence,
  DEFAULT_TAILSCALE_PEER_ENTITY_LIMIT,
  parseTailscaleStatusJson,
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
      [PUBLIC_KEY_B]: { PublicKey: PUBLIC_KEY_B, Online: false, LastHandshake: "not-a-timestamp" },
    },
  }));
  assert.equal(parsed.peers[0].latest_handshake_epoch_seconds, undefined);
  assert.equal(parsed.peers[1].latest_handshake_epoch_seconds, undefined);
});

test("parseTailscaleStatusJson rejects malformed JSON instead of partially trusting it", () => {
  assert.throws(() => parseTailscaleStatusJson('{"BackendState":"Running","Peer":'), SyntaxError);
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

test("ENOENT degrades to absent and never fabricates a zero", async () => {
  const envelope = await collectTailscaleStatusEvidence({ runFixedExecFile: scriptedExec(baseScript()) });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  assert.equal(envelope.result.status, "absent");
  assert.deepEqual(envelope.result.peers, []);
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
