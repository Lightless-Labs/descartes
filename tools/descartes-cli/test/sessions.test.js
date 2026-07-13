import assert from "node:assert/strict";
import test from "node:test";
import {
  collectSessionEvidence,
  DEFAULT_SESSION_ENTITY_LIMIT,
  parseScreenLs,
  parseTmuxSessions,
} from "../src/tools/sessions.js";

function ok(stdout, stderr = "") {
  return { status: "ok", stdout, stderr, command: { argv: ["fixture"], read_only: true } };
}

function failure({ code, stdout = "", stderr = "", error = "boom" } = {}) {
  return { status: "error", code, stdout, stderr, error, command: { argv: ["fixture"], read_only: true } };
}

function enoent() {
  return failure({ code: "ENOENT", error: "spawn tmux ENOENT" });
}

// Injects distinct fakes per binary name so a single test can simulate any combination of
// tmux/screen behavior without a real tmux/screen installation (plan §2's local testability
// model — mirrors provenance-warnings.js's own options.runFixedExecFile DI convention).
function fakeExec({ tmux, screen }) {
  return async (command) => {
    if (command === "tmux") return tmux;
    if (command === "screen") return screen;
    throw new Error(`unexpected command in test fake: ${command}`);
  };
}

// --- parseTmuxSessions ---

test("parseTmuxSessions parses well-formed tab-separated rows", () => {
  const stdout = ["main\t3\t1\t1720000000", "work\t1\t0\t1720003600"].join("\n");
  const { sessions, malformed_count } = parseTmuxSessions(stdout);
  assert.equal(malformed_count, 0);
  assert.deepEqual(sessions, [
    { session_name: "main", window_count: 3, attached: true, created_at_epoch_seconds: 1720000000 },
    { session_name: "work", window_count: 1, attached: false, created_at_epoch_seconds: 1720003600 },
  ]);
});

test("parseTmuxSessions skips malformed/truncated lines without fabricating a partial session", () => {
  const stdout = [
    "main\t3\t1\t1720000000",
    "truncated-line-missing-fields\t5", // wrong field count
    "work\t1\t0\t1720003600",
    "onlyname\tnot-a-number\t1\t1720000000", // right field count, unparseable window count
  ].join("\n");
  const { sessions, malformed_count } = parseTmuxSessions(stdout);
  assert.equal(sessions.length, 2);
  assert.equal(malformed_count, 2);
  assert.deepEqual(sessions.map((s) => s.session_name), ["main", "work"]);
});

test("parseTmuxSessions treats an EMPTY numeric field as malformed, not a fabricated 0 (degrade-not-fabricate at the field level)", () => {
  // Number("") === 0 (finite), so a lenient Number.isFinite check would fabricate a concrete
  // window_count/created_at of 0 from an empty field (reachable only via a corrupted/interposed
  // tmux or truncated stdout). Both a mid-row empty window field and an empty created field must
  // drop the row as malformed rather than invent a 0.
  const stdout = [
    "main\t3\t1\t1720000000",       // well-formed
    "emptywin\t\t1\t1720000000",    // empty #{session_windows}
    "emptycreated\t2\t1\t",         // empty #{session_created} (trailing) — also field-count guarded, but assert intent
    "whitespacewin\t \t1\t1720000000", // whitespace-only window field
  ].join("\n");
  const { sessions, malformed_count } = parseTmuxSessions(stdout);
  assert.equal(sessions.length, 1);
  assert.equal(malformed_count, 3);
  assert.deepEqual(sessions.map((s) => s.session_name), ["main"]);
});

test("parseTmuxSessions on empty stdout yields zero sessions, zero malformed", () => {
  assert.deepEqual(parseTmuxSessions(""), { sessions: [], malformed_count: 0 });
});

// --- parseScreenLs ---

test("parseScreenLs recognizes the genuine-zero-sessions phrasing", () => {
  const { sessions, no_sockets } = parseScreenLs("No Sockets found in /run/screen/S-user.\n");
  assert.deepEqual(sessions, []);
  assert.equal(no_sockets, true);
});

test("parseScreenLs parses attached/detached session lines, skipping header/footer", () => {
  const stdout = [
    "There are screens on:",
    "\t23536.pts-4.host\t(Detached)",
    "\t23400.pts-3.host\t(Attached)",
    "2 Sockets in /run/screen/S-user.",
  ].join("\n");
  const { sessions, malformed_count } = parseScreenLs(stdout);
  assert.equal(malformed_count, 0);
  assert.deepEqual(sessions, [
    { session_name: "23536.pts-4.host", window_count: undefined, attached: false, created_at_epoch_seconds: undefined },
    { session_name: "23400.pts-3.host", window_count: undefined, attached: true, created_at_epoch_seconds: undefined },
  ]);
});

test("parseScreenLs tolerates a locale-formatted date column between name and attach state", () => {
  const stdout = [
    "There is a screen on:",
    "\t24328.pts-3.hostname\t(05/13/2020 09:12:34 PM)\t(Attached)",
  ].join("\n");
  const { sessions } = parseScreenLs(stdout);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].session_name, "24328.pts-3.hostname");
  assert.equal(sessions[0].attached, true);
});

test("parseScreenLs skips a malformed line but still parses a well-formed sibling", () => {
  const stdout = [
    "There are screens on:",
    "\t12345.foo\tgarbage-that-does-not-match",
    "\t23456.bar\t(Attached)",
    "2 Sockets in /run/screen/S-user.",
  ].join("\n");
  const { sessions, malformed_count } = parseScreenLs(stdout);
  assert.equal(malformed_count, 1);
  assert.deepEqual(sessions.map((s) => s.session_name), ["23456.bar"]);
});

// --- collectSessionEvidence: degrade-not-fabricate ---

test("neither tmux nor screen present -> envelope is unable/confidence:0, NEVER a fabricated zero-sessions ok", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({ tmux: enoent(), screen: enoent() }),
  });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  assert.equal(envelope.review_hint, "missing_permission");
  assert.equal(envelope.result.any_binary_available, false);
  assert.deepEqual(envelope.result.multiplexers.map((m) => m.status), ["absent", "absent"]);
});

test("tmux absent, screen present with genuinely zero sessions -> ok/empty, distinguishable from the neither-binary-present case", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({ tmux: enoent(), screen: ok("No Sockets found in /run/screen/S-user.\n") }),
  });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.confidence, 1);
  assert.deepEqual(envelope.result.sessions, []);
  assert.equal(envelope.result.total_count, 0);
});

test("tmux present with no server running (its own genuine-zero-sessions signal) -> ok/empty, not unable", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: failure({ code: 1, stderr: "no server running on /tmp/tmux-501/default\n" }),
      screen: enoent(),
    }),
  });
  assert.equal(envelope.status, "ok");
  assert.deepEqual(envelope.result.sessions, []);
});

test("both tmux and screen present with real sessions -> combined, per-multiplexer-tagged session list", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: ok("main\t3\t1\t1720000000\n"),
      screen: ok(["There are screens on:", "\t23400.pts-3.host\t(Attached)", "1 Socket in /run/screen/S-user."].join("\n")),
    }),
  });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.result.total_count, 2);
  const multiplexers = envelope.result.sessions.map((s) => s.multiplexer).sort();
  assert.deepEqual(multiplexers, ["screen", "tmux"]);
});

test("screen -ls exits non-zero even though sessions genuinely exist (pinned version quirk) -> parsed as ok, not unable", async () => {
  const screenStdout = ["There are screens on:", "\t23400.pts-3.host\t(Attached)", "1 Socket in /run/screen/S-user."].join("\n");
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: enoent(),
      screen: failure({ code: 1, stdout: screenStdout }), // non-zero exit, but real session content in stdout
    }),
  });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.result.sessions.length, 1);
  assert.equal(envelope.result.sessions[0].attached, true);
});

test("malformed/truncated tmux output degrades gracefully: well-formed lines still parsed, envelope stays ok", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: ok(["main\t3\t1\t1720000000", "###garbage###"].join("\n")),
      screen: enoent(),
    }),
  });
  assert.equal(envelope.status, "ok");
  assert.equal(envelope.result.sessions.length, 1);
});

test("permission-denied on tmux (no recognizable no-server message) + screen absent -> overall unable", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: failure({ code: "EACCES", stderr: "permission denied" }),
      screen: enoent(),
    }),
  });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  const tmuxEntry = envelope.result.multiplexers.find((m) => m.multiplexer === "tmux");
  assert.equal(tmuxEntry.status, "unable");
});

test("permission-denied on tmux only, screen ok -> overall ok (partial degrade recorded, not fabricated as failure)", async () => {
  const envelope = await collectSessionEvidence({
    runFixedExecFile: fakeExec({
      tmux: failure({ code: "EACCES", stderr: "permission denied" }),
      screen: ok(["There are screens on:", "\t1.foo\t(Attached)", "1 Socket in /x."].join("\n")),
    }),
  });
  assert.equal(envelope.status, "ok");
  const tmuxEntry = envelope.result.multiplexers.find((m) => m.multiplexer === "tmux");
  assert.equal(tmuxEntry.status, "unable");
  assert.equal(envelope.result.sessions.length, 1);
});

// --- Flood cap (must-fix 5) ---

test("DEFAULT_SESSION_ENTITY_LIMIT is a positive finite bound", () => {
  assert(Number.isFinite(DEFAULT_SESSION_ENTITY_LIMIT));
  assert(DEFAULT_SESSION_ENTITY_LIMIT > 0);
});

test("a session flood above the cap is bounded at the cap, with truncated:true and the real total preserved", async () => {
  const cap = 10;
  const floodedTmuxOutput = Array.from({ length: cap * 5 }, (_, i) => `flood-${i}\t1\t0\t1720000000`).join("\n");
  const envelope = await collectSessionEvidence({
    sessionLimit: cap,
    runFixedExecFile: fakeExec({ tmux: ok(floodedTmuxOutput), screen: enoent() }),
  });
  assert.equal(envelope.result.total_count, cap * 5);
  assert.equal(envelope.result.sessions.length, cap);
  assert.equal(envelope.result.truncated, true);
  assert.equal(envelope.result.cap, cap);
});

test("a session count at or below the cap is never marked truncated", async () => {
  const cap = 10;
  const withinCapOutput = Array.from({ length: cap }, (_, i) => `s-${i}\t1\t0\t1720000000`).join("\n");
  const envelope = await collectSessionEvidence({
    sessionLimit: cap,
    runFixedExecFile: fakeExec({ tmux: ok(withinCapOutput), screen: enoent() }),
  });
  assert.equal(envelope.result.sessions.length, cap);
  assert.equal(envelope.result.truncated, false);
});
