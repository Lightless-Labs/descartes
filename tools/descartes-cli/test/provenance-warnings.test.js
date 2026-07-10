import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import {
  DELETED_EXE_RULE_ID,
  PUBLIC_BIND_RULE_ID,
  bindAddressFamilyLabel,
  buildProvenanceWarningCandidates,
  collectProvenanceWarningsEvidence,
  computeProvenanceWarningCandidates,
  hashExecutablePath,
  listListeningSocketsWithPid,
  provenanceWarningFactPoints,
  reduceLatestProvenanceWarnings,
  snapshotProvenanceProcesses,
} from "../src/tools/provenance-warnings.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-warnings-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// A five-listener fixture used across several tests below: pid 501/504 are launchd-owned
// (recognized supervisor) even though public-bound; pid 502/503 are unknown-source but bound
// to non-public addresses; pid 505 is the ONE listener that is both public-bound and
// unknown-source — the sole narrowed candidate.
const FIVE_LISTENER_PROCESSES = [
  { pid: 1, ppid: 0, command: "launchd" },
  { pid: 501, ppid: 1, command: "svc1" },
  { pid: 502, ppid: 9999, command: "svc2" },
  { pid: 503, ppid: 9999, command: "svc3" },
  { pid: 504, ppid: 1, command: "svc4" },
  { pid: 505, ppid: 9999, command: "svc5" },
];
const FIVE_LISTENER_SOCKETS = [
  { protocol: "tcp", local_address: "0.0.0.0", local_port: 9001, pid: 501 },
  { protocol: "tcp", local_address: "127.0.0.1", local_port: 9002, pid: 502 },
  { protocol: "tcp", local_address: "10.0.0.5", local_port: 9003, pid: 503 },
  { protocol: "tcp", local_address: "[::]", local_port: 9004, pid: 504 },
  { protocol: "tcp", local_address: "0.0.0.0", local_port: 9005, pid: 505 },
];

// ---------------------------------------------------------------------------------------------
// TDD item 1: outer-disabled short-circuit, spy-verified — no I/O attempted.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceWarningCandidates short-circuits to [] before any I/O when learned.json is disabled", async () => {
  const paths = await tempPaths();
  let readFactsCalled = false;
  const result = await computeProvenanceWarningCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readFactPoints: async () => {
      readFactsCalled = true;
      throw new Error("readFactPoints must not be called while the learned.json kill switch is off");
    },
  });
  assert.deepEqual(result, []);
  assert.equal(readFactsCalled, false);
});

test("computeProvenanceWarningCandidates calls the real (default) loadLearnedConfig/readFactPoints when not injected, and returns [] on a fresh state dir", async () => {
  const paths = await tempPaths();
  // configDir/learned.json intentionally never written -> loadLearnedConfig defaults to
  // { enabled: false } (constraint-store.js's own default), matching the disabled-by-default
  // acceptance criterion end-to-end, not just via an injected fake.
  const result = await computeProvenanceWarningCandidates(paths, {});
  assert.deepEqual(result, []);
});

// ---------------------------------------------------------------------------------------------
// TDD items 2/3/8, combined: bounded-I/O narrowing + exactly-one-candidate-per-rule fixture,
// driven end-to-end through the real evidence -> fact-point -> candidate pipeline.
// ---------------------------------------------------------------------------------------------

test("collectProvenanceWarningsEvidence invokes the expensive deleted-exe check only for the one socket already narrowed to a public-bind-no-supervisor candidate, not for every listener", async () => {
  let resolveExecutableInfoCallCount = 0;
  const calledWithPids = [];
  const resolveExecutableInfoSpy = async (pid) => {
    resolveExecutableInfoCallCount += 1;
    calledWithPids.push(pid);
    return { executable_path: "/opt/svc5/bin/svc5", executable_path_unavailable: false, deleted_exe: true, deleted_exe_confidence: 1 };
  };

  const envelope = await collectProvenanceWarningsEvidence({
    listListeningSocketsWithPid: async () => FIVE_LISTENER_SOCKETS,
    snapshotProvenanceProcesses: async () => FIVE_LISTENER_PROCESSES,
    resolveExecutableInfo: resolveExecutableInfoSpy,
  });

  assert.equal(envelope.status, "ok");
  assert.equal(resolveExecutableInfoCallCount, 1, "expensive deleted-exe check must run exactly once, not once per listener (5 listeners here)");
  assert.deepEqual(calledWithPids, [505]);
  assert.equal(envelope.result.checked_socket_count, 5);
  assert.equal(envelope.result.narrowed_candidate_count, 1);

  const activePublicBind = envelope.result.warnings.filter((w) => w.rule_id === "public_bind_no_supervisor" && w.active);
  assert.equal(activePublicBind.length, 1);
  assert.equal(activePublicBind[0].local_port, 9005);

  const activeDeletedExe = envelope.result.warnings.filter((w) => w.rule_id === "deleted_exe_running" && w.active);
  assert.equal(activeDeletedExe.length, 1);
  assert.equal(activeDeletedExe[0].pid, 505);
  assert.match(activeDeletedExe[0].executable_path_hash, /^[0-9a-f]{16}$/);

  // Self-healing: every checked socket gets a public_bind_no_supervisor entry (active true or
  // false), not just the one that fired — so a socket that stops being a candidate on a later
  // tick gets an explicit active:"false" fact refresh instead of going silently stale.
  const publicBindEntries = envelope.result.warnings.filter((w) => w.rule_id === "public_bind_no_supervisor");
  assert.equal(publicBindEntries.length, 5);
  assert.equal(publicBindEntries.filter((w) => w.active).length, 1);
  assert.equal(publicBindEntries.filter((w) => !w.active).length, 4);

  // The raw executable path must never appear anywhere in the evidence result, not just in the
  // eventual candidate diagnostics — it is hashed at the point of construction.
  assert.equal(JSON.stringify(envelope.result).includes("/opt/svc5"), false);
});

test("end-to-end: the narrowed fixture above produces exactly one deleted_exe_running and one public_bind_no_supervisor candidate with sanitized, hashed diagnostics", async () => {
  const envelope = await collectProvenanceWarningsEvidence({
    listListeningSocketsWithPid: async () => FIVE_LISTENER_SOCKETS,
    snapshotProvenanceProcesses: async () => FIVE_LISTENER_PROCESSES,
    resolveExecutableInfo: async () => ({ executable_path: "/opt/svc5/bin/svc5", executable_path_unavailable: false, deleted_exe: true, deleted_exe_confidence: 1 }),
  });

  const factPoints = provenanceWarningFactPoints([envelope], { ts: "2026-07-10T00:00:00.000Z" });
  const paths = await tempPaths();
  const candidates = await computeProvenanceWarningCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => ({ points: factPoints, corrupt_count: 0 }),
  });

  assert.equal(candidates.length, 2);
  const publicBind = candidates.find((c) => c.rule_id === PUBLIC_BIND_RULE_ID);
  const deletedExe = candidates.find((c) => c.rule_id === DELETED_EXE_RULE_ID);
  assert.ok(publicBind, "expected exactly one public_bind_no_supervisor candidate");
  assert.ok(deletedExe, "expected exactly one deleted_exe_running candidate");

  assert.equal(deletedExe.diagnostics.pid, 505);
  assert.match(deletedExe.diagnostics.executable_path_hash, /^[0-9a-f]{16}$/);
  assert.equal(JSON.stringify(deletedExe).includes("/opt/svc5"), false);
  assert.equal(JSON.stringify(deletedExe).includes("svc5"), false, "raw command/path fragments must never reach the candidate");

  assert.equal(publicBind.diagnostics.local_port, 9005);
  assert.equal(publicBind.diagnostics.protocol, "tcp");
  assert.ok(["info", "warning", "critical"].includes(publicBind.severity));
  assert.ok(["info", "warning", "critical"].includes(deletedExe.severity));

  // Candidate ids are stable/deterministic for the same fingerprint (alertId is a pure hash).
  const again = await computeProvenanceWarningCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readFactPoints: async () => ({ points: factPoints, corrupt_count: 0 }),
  });
  assert.deepEqual(again.map((c) => c.id).sort(), candidates.map((c) => c.id).sort());
});

test("a recognized-supervisor public bind and a non-public unknown-source bind never produce a candidate", async () => {
  const envelope = await collectProvenanceWarningsEvidence({
    listListeningSocketsWithPid: async () => [
      { protocol: "tcp", local_address: "0.0.0.0", local_port: 9001, pid: 501 }, // launchd-owned
      { protocol: "tcp", local_address: "127.0.0.1", local_port: 9002, pid: 502 }, // not public
    ],
    snapshotProvenanceProcesses: async () => FIVE_LISTENER_PROCESSES,
    resolveExecutableInfo: async () => {
      throw new Error("must not be called: neither listener narrows to a candidate");
    },
  });

  assert.equal(envelope.result.narrowed_candidate_count, 0);
  assert.equal(envelope.result.warnings.some((w) => w.active), false);

  const factPoints = provenanceWarningFactPoints([envelope], { ts: "2026-07-10T00:00:00.000Z" });
  const candidates = buildProvenanceWarningCandidates(reduceLatestProvenanceWarnings(factPoints));
  assert.deepEqual(candidates, []);
});

test("a socket with no resolvable pid (e.g. cross-UID) is silently skipped — never a fabricated classification", async () => {
  const envelope = await collectProvenanceWarningsEvidence({
    listListeningSocketsWithPid: async () => [
      { protocol: "tcp", local_address: "0.0.0.0", local_port: 9010, pid: undefined },
    ],
    snapshotProvenanceProcesses: async () => {
      throw new Error("must not snapshot processes when there is no resolvable pid to classify");
    },
    resolveExecutableInfo: async () => {
      throw new Error("must not be called");
    },
  });

  assert.equal(envelope.result.checked_socket_count, 1);
  assert.equal(envelope.result.narrowed_candidate_count, 0);
  assert.deepEqual(envelope.result.warnings, []);
});

// ---------------------------------------------------------------------------------------------
// TDD item 4: sanitizeDiagnostics rejection — a raw path smuggled into a diagnostics-bound
// field must never pass through verbatim.
// ---------------------------------------------------------------------------------------------

test("sanitizeDiagnostics rejection: a raw path smuggled into a fact point's executable_path_hash field is redacted, never passed through verbatim", () => {
  const point = {
    entity_key: "deleted_exe_running.process.999",
    ts: "2026-07-10T00:00:00.000Z",
    attributes: {
      rule_id: "deleted_exe_running",
      active: "true",
      pid: "999",
      executable_path_hash: "/usr/local/bin/suspicious-binary", // malformed input: a raw path, not a hash
      source_type: "unknown",
      confidence: "1",
    },
  };
  const [candidate] = buildProvenanceWarningCandidates([point]);
  assert.ok(candidate);
  assert.equal(candidate.diagnostics.executable_path_hash.redacted, true);
  assert.equal(JSON.stringify(candidate.diagnostics).includes("/usr/local/bin"), false);
});

test("sanitizeDiagnostics rejection: a raw username-shaped source_type is redacted, not passed through", () => {
  const point = {
    entity_key: "public_bind_no_supervisor.socket.tcp.9000.ipv4_any",
    ts: "2026-07-10T00:00:00.000Z",
    attributes: {
      rule_id: "public_bind_no_supervisor",
      active: "true",
      protocol: "tcp",
      local_port: "9000",
      bind_address_family: "ipv4_any",
      source_type: "someone@example.com", // malformed input: never a legitimate source.type value
    },
  };
  const [candidate] = buildProvenanceWarningCandidates([point]);
  assert.ok(candidate);
  assert.equal(candidate.diagnostics.source_type.redacted, true);
});

// ---------------------------------------------------------------------------------------------
// reduceLatestProvenanceWarnings: latest-per-entity reduction, including self-healing
// recovery when a later observation reports active:"false" for the same entity.
// ---------------------------------------------------------------------------------------------

test("reduceLatestProvenanceWarnings keeps only the newest observation per entity_key, ignoring an older active point once a newer inactive one supersedes it", () => {
  const points = [
    { entity_key: "public_bind_no_supervisor.socket.tcp.9000.ipv4_any", ts: "2026-07-10T00:00:00.000Z", fact_name: "provenance.warning", attributes: { rule_id: "public_bind_no_supervisor", active: "true", protocol: "tcp", local_port: "9000", bind_address_family: "ipv4_any" } },
    { entity_key: "public_bind_no_supervisor.socket.tcp.9000.ipv4_any", ts: "2026-07-10T01:00:00.000Z", fact_name: "provenance.warning", attributes: { rule_id: "public_bind_no_supervisor", active: "false", protocol: "tcp", local_port: "9000", bind_address_family: "ipv4_any" } },
  ];
  const latest = reduceLatestProvenanceWarnings(points);
  assert.equal(latest.length, 1);
  assert.equal(latest[0].attributes.active, "false");
  assert.deepEqual(buildProvenanceWarningCandidates(latest), []);
});

test("reduceLatestProvenanceWarnings ignores fact points with a different fact_name", () => {
  const points = [
    { entity_key: "x", ts: "2026-07-10T00:00:00.000Z", fact_name: "service.presence", attributes: { running: "true" } },
  ];
  assert.deepEqual(reduceLatestProvenanceWarnings(points), []);
});

// ---------------------------------------------------------------------------------------------
// Pure helper unit tests.
// ---------------------------------------------------------------------------------------------

test("bindAddressFamilyLabel classifies the pinned public-bind literal set and falls back to other", () => {
  assert.equal(bindAddressFamilyLabel("0.0.0.0"), "ipv4_any");
  assert.equal(bindAddressFamilyLabel("[::]"), "ipv6_any");
  assert.equal(bindAddressFamilyLabel("*"), "wildcard");
  assert.equal(bindAddressFamilyLabel("127.0.0.1"), "other");
});

test("hashExecutablePath produces a fixed-length hex digest and never echoes the raw path", () => {
  const hash = hashExecutablePath("/usr/local/bin/nginx");
  assert.match(hash, /^[0-9a-f]{16}$/);
  assert.notEqual(hash, "/usr/local/bin/nginx");
  assert.equal(hashExecutablePath(undefined), undefined);
  assert.equal(hashExecutablePath(""), undefined);
});

// ---------------------------------------------------------------------------------------------
// Platform-specific socket listing, fixture-driven (Linux: no live host available; macOS: a
// fixture test plus a live smoke elsewhere covers realism).
// ---------------------------------------------------------------------------------------------

test("listListeningSocketsWithPid('darwin', ...) parses a fixed lsof fixture into pid-attributed sockets", async () => {
  const lsofFixture = "COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
    + "node     1234 me     23u  IPv4 0xabc              0t0  TCP 0.0.0.0:3000 (LISTEN)\n"
    + "launchd   431 root   10u  IPv6 0xdef              0t0  TCP 127.0.0.1:5000 (LISTEN)\n";
  const sockets = await listListeningSocketsWithPid("darwin", {
    runFixedExecFile: async (command, args) => {
      assert.equal(command, "lsof");
      assert.deepEqual(args, ["-nP", "-iTCP", "-sTCP:LISTEN"]);
      return { status: "ok", stdout: lsofFixture };
    },
  });
  assert.deepEqual(sockets, [
    { protocol: "tcp", local_address: "0.0.0.0", local_port: 3000, pid: 1234 },
    { protocol: "tcp", local_address: "127.0.0.1", local_port: 5000, pid: 431 },
  ]);
});

test("listListeningSocketsWithPid('darwin', ...) degrades to an empty list when lsof is unavailable, never throwing", async () => {
  const sockets = await listListeningSocketsWithPid("darwin", {
    runFixedExecFile: async () => ({ status: "unable", error: "ENOENT" }),
  });
  assert.deepEqual(sockets, []);
});

const PROC_NET_TCP_LISTEN_OWN_UID = [
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
  " 0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
].join("\n");

test("listListeningSocketsWithPid('linux', ...) resolves an own-UID listener's pid via the injected fd-scan, fixture-driven (no live /proc)", async () => {
  const sockets = await listListeningSocketsWithPid("linux", {
    readFile: async (file) => {
      if (file === "/proc/net/tcp") return PROC_NET_TCP_LISTEN_OWN_UID;
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
    listProcPids: async () => [777],
    scanProcFdForInode: async (pids) => pids.map((pid) => ({ pid, accessible: true, fds: [{ fd: "12", target: "socket:[12345]" }] })),
  });
  assert.deepEqual(sockets, [
    { protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, pid: 777 },
  ]);
});

test("listListeningSocketsWithPid('linux', ...) leaves pid undefined for a cross-UID socket (EACCES fd-scan), never fabricating a pid", async () => {
  const sockets = await listListeningSocketsWithPid("linux", {
    readFile: async (file) => {
      if (file === "/proc/net/tcp") return PROC_NET_TCP_LISTEN_OWN_UID;
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
    listProcPids: async () => [777],
    scanProcFdForInode: async (pids) => pids.map((pid) => ({ pid, accessible: false, error: "EACCES" })),
  });
  assert.deepEqual(sockets, [
    { protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, pid: undefined },
  ]);
});

test("listListeningSocketsWithPid returns [] for an unsupported platform, never throwing", async () => {
  assert.deepEqual(await listListeningSocketsWithPid("win32", {}), []);
});

test("snapshotProvenanceProcesses reuses the shared ps-argv/parse pair and degrades to [] when ps is unavailable", async () => {
  const processes = await snapshotProvenanceProcesses("darwin", {
    runFixedExecFile: async (command, args) => {
      assert.equal(command, "ps");
      assert.deepEqual(args, ["-axo", "pid,ppid,uid,pcpu,pmem,rss,ucomm,args"]);
      return { status: "ok", stdout: "  PID  PPID  UID  %CPU  %MEM  RSS UCOMM ARGS\n    1     0    0   0.0   0.0    0 launchd /sbin/launchd\n" };
    },
  });
  assert.equal(processes.length, 1);
  assert.equal(processes[0].pid, 1);

  const degraded = await snapshotProvenanceProcesses("darwin", { runFixedExecFile: async () => ({ status: "unable" }) });
  assert.deepEqual(degraded, []);
});

// ---------------------------------------------------------------------------------------------
// Live macOS smoke (one clean case), mirrors provenance.test.js's own live-smoke precedent.
// ---------------------------------------------------------------------------------------------

test("collectProvenanceWarningsEvidence runs end-to-end on a live macOS host without throwing", { skip: process.platform !== "darwin" }, async () => {
  const envelope = await collectProvenanceWarningsEvidence({});
  assert.equal(envelope.status, "ok");
  assert.equal(typeof envelope.result.checked_socket_count, "number");
  assert.equal(typeof envelope.result.narrowed_candidate_count, "number");
  assert.ok(Array.isArray(envelope.result.warnings));
});
