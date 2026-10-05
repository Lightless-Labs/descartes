import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { redactAndBoundProcessArgs } from "../src/tools/processes.js";
import {
  buildLinuxSocketFact,
  buildMacPortSockets,
  classifySourceFromAncestry,
  classifyOwnerAmbiguityReason,
  computeProvenanceEnvelopeFields,
  detectWarnings,
  inferMacosDeletedExe,
  isLinuxDeletedExeLink,
  isPublicBindAddress,
  normalizeProvenanceTarget,
  parseContainerInspectPid,
  parseIdUsernameOutput,
  parseMacLsofTxtExecutablePath,
  parseProcNetContents,
  parseProcNetLine,
  parseProvenancePs,
  resolvePidFromFdScanResults,
  resolveByPortLinux,
  resolveVerifiedPidFromFdScanResults,
  parseLinuxProcessIdentity,
  resolveProvenance,
  summarizeSocketAttributions,
  verifyFinalSocketResolution,
  verifyProcfsPidNamespace,
} from "../src/tools/provenance.js";

// ---------------------------------------------------------------------------------------------
// 1/2. Linux /proc/net/tcp line parsing + own-uid/cross-uid fd-inode matching (pure fixtures).
// ---------------------------------------------------------------------------------------------

test("parseProcNetLine parses a /proc/net/tcp row into local_port/uid/inode facts", () => {
  const line = " 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
  assert.deepEqual(parseProcNetLine(line, { protocol: "tcp" }), {
    protocol: "tcp",
    local_address: "127.0.0.1",
    local_port: 8080,
    state: "LISTEN",
    uid: 1000,
    inode: "12345",
  });
});

test("parseProcNetLine recognizes the all-zero IPv4 and IPv6 public-bind literals", () => {
  const v4 = " 1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0";
  assert.equal(parseProcNetLine(v4, { protocol: "tcp" }).local_address, "0.0.0.0");
  assert.equal(parseProcNetLine(v4, { protocol: "tcp" }).local_port, 80);

  const v6 = " 2: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54322 1 0000000000000000 100 0 0 10 0";
  assert.equal(parseProcNetLine(v6, { protocol: "tcp6" }).local_address, "[::]");
});

test("parseProcNetLine skips malformed rows without throwing", () => {
  assert.equal(parseProcNetLine("not a real row", { protocol: "tcp" }), undefined);
  assert.equal(parseProcNetLine("", { protocol: "tcp" }), undefined);
});

test("parseProcNetLine excludes connected UDP rows and keeps only state 07", () => {
  const connected = " 0: 0100007F:1F90 0100007F:1770 01 00000000:00000000 00:00000000 00000000     1000        0 12345 1 0000000000000000 100 0 0 10 0";
  const unconnected = " 1: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000     1000        0 12346 1 0000000000000000 100 0 0 10 0";
  assert.equal(parseProcNetLine(connected, { protocol: "udp" }), undefined);
  assert.equal(parseProcNetLine(unconnected, { protocol: "udp" }).state, "UNCONN");
});

test("parseProcNetContents parses a multi-row /proc/net/tcp fixture, skipping the header", () => {
  const contents = [
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    " 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
    " 1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0",
  ].join("\n");
  const parsed = parseProcNetContents(contents, { protocol: "tcp" });
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].local_port, 8080);
  assert.equal(parsed[1].local_address, "0.0.0.0");
});

test("Linux socket facts retain protocol, inode, and uid for every attributed row", () => {
  assert.deepEqual(buildLinuxSocketFact({
    protocol: "udp",
    local_address: "0.0.0.0",
    local_port: 5353,
    state: "UNCONN",
    inode: "777777",
    uid: 1001,
  }), {
    protocol: "udp",
    local_address: "0.0.0.0",
    local_port: 5353,
    state: "UNCONN",
    public_bind: true,
    inode: "777777",
    uid: 1001,
  });
});

test("resolvePidFromFdScanResults matches an inode to its owning pid for an accessible own-uid scan", () => {
  const fdScanResults = [
    {
      pid: 100,
      tgid: 100,
      start_time: "10",
      executable_path: "/usr/bin/app",
      executable_dev: "7",
      executable_ino: "8",
      cmdline: "app\u0000--port\u00008080\u0000",
      accessible: true,
      fds: [{ fd: "3", target: "socket:[12345]" }, { fd: "4", target: "/dev/null" }],
    },
    { pid: 200, accessible: true, fds: [{ fd: "3", target: "socket:[99999]" }] },
  ];
  assert.deepEqual(resolvePidFromFdScanResults("12345", fdScanResults), {
    status: "ok", pid: 100, confidence: 1, owners: [{
      pid: 100,
      tgid: 100,
      start_time: "10",
      executable_path: "/usr/bin/app",
      executable_dev: "7",
      executable_ino: "8",
      cmdline: "app\u0000--port\u00008080\u0000",
    }],
  });
});

test("Linux port attribution returns evidence checked by the real default final verifier", async () => {
  const uid = process.getuid?.() ?? 1000;
  const socketRow = [
    " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
    ` 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ${uid} 0 424242 1`,
  ].join("\n");
  const cmdline = "app\u0000--api-key\u0000top secret value\u0000";
  const stat = `100 (app) S ${Array.from({ length: 18 }, () => "0").join(" ")} 10`;
  const owner = {
    pid: 100,
    tgid: 100,
    start_time: "10",
    executable_path: "/verified",
    executable_dev: "7",
    executable_ino: "8",
    cmdline,
    accessible: true,
    fds: [{ fd: "3", target: "socket:[424242]" }],
  };
  let verifierStarted = false;
  let coreCalls = 0;
  const result = await resolveByPortLinux(8080, {
    readFile: async (filePath) => {
      if (filePath === "/proc/net/tcp") return socketRow;
      if (filePath === "/proc/100/stat") return stat;
      if (filePath === "/proc/100/cmdline") return cmdline;
      return "header\n";
    },
    readlink: async (filePath) => {
      if (filePath === "/proc/100/fd/3") return "socket:[424242]";
      if (filePath === "/proc/100/exe") return "/verified";
      throw new Error(`unexpected readlink: ${filePath}`);
    },
    readdir: async (filePath) => {
      if (filePath === "/proc/100/fd") {
        verifierStarted = true;
        return ["3"];
      }
      throw new Error(`unexpected readdir: ${filePath}`);
    },
    open: async () => ({ stat: async () => ({ dev: "7", ino: "8" }), close: async () => {} }),
    verifyProcfsPidNamespace: async () => true,
    listProcPids: async () => ({ pids: [100], truncated: false }),
    scanProcFdForInode: async () => ({ results: [owner], truncated: false, uncertain: false }),
    resolvePidCore: async (pid) => {
      coreCalls += 1;
      const executablePath = verifierStarted ? "/unverified-later" : "/verified";
      return {
        resolvedStatus: "ok",
        resolved: {
          status: "ok",
          pid,
          ppid: 1,
          executable_path: executablePath,
          executable_path_unavailable: false,
          command: "app --api-key [REDACTED]",
          args_redaction: { redacted: true, truncated: false, original_length: cmdline.length, max_length: 240 },
          user: { uid, username: undefined, username_unavailable: true },
          tgid: 100,
          start_time: "10",
          start_time_unavailable: false,
          process_identity: { tgid: 100, start_time: "10" },
        },
        ancestry: [],
        source: { type: "supervisor", name: "app", confidence: 1, review_hint: "none", details: {} },
      };
    },
  });
  assert.equal(result.resolvedStatus, "ok");
  assert.equal(result.result.resolved.executable_path, "/verified");
  assert.equal(result.result.resolved.executable_dev, "7");
  assert.equal(result.result.resolved.executable_ino, "8");
  assert.equal(result.result.resolved.command, "app --api-key [REDACTED]");
  assert.equal(result.result.resolved.args_redaction.redacted, true);
  assert(!result.result.resolved.command.includes("top secret value"));
  assert.deepEqual(result.result.resolved.process_identity, { tgid: 100, start_time: "10" });
  assert.equal(result.result.sockets[0].inode, "424242");
  assert.equal(coreCalls, 1);
});

test("resolvePidFromFdScanResults degrades to partial with no fabricated pid when the fd walk is EACCES", () => {
  const fdScanResults = [
    { pid: 100, accessible: false, error: "EACCES" },
    { pid: 200, accessible: false, error: "EACCES" },
  ];
  const result = resolvePidFromFdScanResults("12345", fdScanResults);
  assert.equal(result.status, "partial");
  assert.equal(result.pid, undefined);
  assert.equal(result.confidence, 0);
  assert.equal(result.review_hint, "missing_permission");
});

test("resolvePidFromFdScanResults returns unknown (not partial) when nothing was even permission-limited", () => {
  const fdScanResults = [{ pid: 100, accessible: true, fds: [{ fd: "3", target: "socket:[1]" }] }];
  const result = resolvePidFromFdScanResults("999999", fdScanResults);
  assert.equal(result.status, "unknown");
  assert.equal(result.pid, undefined);
});

test("resolvePidFromFdScanResults never reports confidence when the exhaustive PID scan hit its cap or had a read failure", () => {
  const owner = { pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] };
  const truncated = resolvePidFromFdScanResults("12345", { results: [owner], truncated: true, uncertain: false });
  assert.equal(truncated.status, "truncated");
  assert.equal(truncated.reason, "fd_scan_truncated");
  assert.equal(truncated.confidence, 0);

  const uncertain = resolvePidFromFdScanResults("12345", { results: [owner], truncated: false, uncertain: true });
  assert.equal(uncertain.status, "ambiguous");
  assert.equal(uncertain.reason, "fd_scan_uncertain");
  assert.equal(uncertain.confidence, 0);
});

test("resolveVerifiedPidFromFdScanResults refreshes once after a stale holder recheck", async () => {
  const first = [{ pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  const second = [{ pid: 200, tgid: 200, start_time: "20", accessible: true, fds: [{ fd: "4", target: "socket:[12345]" }] }];
  let refreshes = 0;
  const result = await resolveVerifiedPidFromFdScanResults("12345", first, {
    scanAgain: async () => {
      refreshes += 1;
      return second;
    },
    verifyHolder: async (_inode, owner) => owner.pid === 200 ? { status: "ok" } : { status: "ambiguous", reason: "owner_fd_recheck_failed" },
  });
  assert.equal(refreshes, 2);
  assert.equal(result.status, "ok");
  assert.equal(result.pid, 200);
});

test("resolveVerifiedPidFromFdScanResults treats a forked inherited holder as ambiguous", async () => {
  const first = [{ pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  const afterFork = [
    ...first,
    { pid: 200, tgid: 200, start_time: "20", accessible: true, fds: [{ fd: "4", target: "socket:[12345]" }] },
  ];
  const result = await resolveVerifiedPidFromFdScanResults("12345", first, {
    scanAgain: async () => afterFork,
    verifyHolder: async () => ({ status: "ok" }),
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.reason, "owner_ambiguous");
});

test("resolveVerifiedPidFromFdScanResults requires a stable PID set before returning the sole holder", async () => {
  const stable = [{ pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  let enumerations = 0;
  const result = await resolveVerifiedPidFromFdScanResults("12345", stable, {
    scanAgain: async () => {
      enumerations += 1;
      return stable;
    },
    verifyHolder: async () => ({ status: "ok" }),
  });
  assert.equal(result.status, "ok");
  assert.equal(result.pid, 100);
  assert.equal(enumerations, 1, "a stable result stops after the first confirming enumeration");
});

test("resolveVerifiedPidFromFdScanResults treats PID churn that never converges as ambiguous", async () => {
  const owner = (pid, startTime) => ({ pid, tgid: pid, start_time: String(startTime), accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] });
  const unrelated = (pid, startTime) => ({ pid, tgid: pid, start_time: String(startTime), accessible: true, fds: [{ fd: "4", target: "/dev/null" }] });
  const scans = [
    [owner(100, 10), unrelated(200, 20)],
    [owner(100, 10), unrelated(200, 20), unrelated(300, 30)],
    [owner(100, 10), unrelated(200, 20), unrelated(300, 30), unrelated(400, 40)],
  ];
  let enumerations = 0;
  const result = await resolveVerifiedPidFromFdScanResults("12345", [owner(100, 10)], {
    scanAgain: async () => scans[enumerations++],
    verifyHolder: async () => ({ status: "ok" }),
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.reason, "owner_recheck_exhausted");
  assert.equal(enumerations, 3);
});

test("resolveVerifiedPidFromFdScanResults treats a reused PID as a new process", async () => {
  const first = [{ pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  const reused = [{ pid: 100, tgid: 100, start_time: "11", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  const result = await resolveVerifiedPidFromFdScanResults("12345", first, {
    scanAgain: async () => reused,
    verifyHolder: async () => ({ status: "ok" }),
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.reason, "owner_identity_changed");
});

test("final verification runs after the stable enumeration and rejects an exec-generation change", async () => {
  const stable = [{ pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] }];
  let enumerations = 0;
  let finalChecks = 0;
  const result = await resolveVerifiedPidFromFdScanResults("12345", stable, {
    scanAgain: async () => {
      enumerations += 1;
      return stable;
    },
    verifyFinal: async () => {
      finalChecks += 1;
      return { status: "ambiguous", reason: "executable_generation_changed" };
    },
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.reason, "executable_generation_changed");
  assert.equal(enumerations, 3, "a changed final generation retries the whole proof once");
  assert.equal(finalChecks, 2, "the final phase runs only after each proof's last enumeration");
});

test("final socket verification checks UDP owner evidence after the row remains stable", async () => {
  const oldRow = { protocol: "udp", local_address: "127.0.0.1", local_port: 5353, state: "UNCONN", uid: 1000, inode: "424242" };
  const stableUdpRow = [
    " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
    " 0: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 424242 1",
  ].join("\n");
  const result = await verifyFinalSocketResolution("424242", oldRow, [{ pid: 100, tgid: 100, start_time: "10" }], {
    readFileFn: async () => stableUdpRow,
    readdirFn: async () => ["3"],
    readlinkFn: async (filePath) => filePath.endsWith("/fd/3") ? "socket:[424242]" : "/usr/bin/app",
    openFn: async () => ({ stat: async () => ({ dev: "7", ino: "8" }), close: async () => {} }),
  });
  assert.equal(result.status, "ambiguous");
  assert.equal(result.reason, "owner_evidence_unavailable");
});

test("a complete refresh that loses the owner is authoritative and never resurrects the old pid", async () => {
  const owner = { pid: 100, tgid: 100, start_time: "10", accessible: true, fds: [{ fd: "3", target: "socket:[12345]" }] };
  const result = await resolveVerifiedPidFromFdScanResults("12345", [owner], {
    scanAgain: async () => ({ results: [], truncated: false, uncertain: false }),
    verifyFinal: async () => ({ status: "ok" }),
  });
  assert.notEqual(result.status, "ok");
  assert.notEqual(result.pid, 100);
  assert.notEqual(result.confidence, 1);
});

test("same-UID Linux resolution refuses an injected procfs PID-namespace mismatch before listing PIDs", async () => {
  const uid = process.getuid?.() ?? 1000;
  const tcp = [
    " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
    ` 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ${uid} 0 424242 1`,
  ].join("\n");
  let listed = false;
  const outcome = await resolveByPortLinux(8080, {
    readFile: async (filePath) => filePath === "/proc/net/tcp" ? tcp : "header\n",
    verifyProcfsPidNamespace: async () => false,
    listProcPids: async () => {
      listed = true;
      throw new Error("must not list /proc after a namespace mismatch");
    },
  });
  assert.equal(listed, false);
  assert.equal(outcome.resolvedStatus, "ambiguous");
  assert.equal(outcome.result.resolved.reason, "procfs_pid_namespace_mismatch");
});

test("verifyProcfsPidNamespace compares injected /proc/self exactly to process.pid", async () => {
  assert.equal(await verifyProcfsPidNamespace({ readlinkFn: async () => String(process.pid) }), true);
  assert.equal(await verifyProcfsPidNamespace({ readlinkFn: async () => "999999" }), false);
});

test("same-port socket attribution is ambiguous when inodes map to different executables or any row is unresolved", () => {
  assert.deepEqual(summarizeSocketAttributions([
    { resolved: true, executablePath: "/usr/sbin/nginx", processIdentity: { tgid: 100, start_time: "10" } },
    { resolved: true, executablePath: "/usr/sbin/nginx", processIdentity: { tgid: 100, start_time: "10" } },
  ]), { status: "ok", reason: "socket_attribution_consistent" });
  assert.equal(summarizeSocketAttributions([
    { resolved: true, executablePath: "/usr/sbin/nginx", processIdentity: { tgid: 100, start_time: "10" } },
    { resolved: true, executablePath: "/usr/bin/node", processIdentity: { tgid: 101, start_time: "11" } },
  ]).status, "ambiguous");
  assert.equal(summarizeSocketAttributions([
    { resolved: true, executablePath: "/usr/sbin/nginx", processIdentity: { tgid: 100, start_time: "10" } },
    { resolved: false },
  ]).status, "partial");
  assert.deepEqual(summarizeSocketAttributions([
    { resolved: false, reason: "fd_scan_truncated" },
    { resolved: false, reason: "elevated_owner_ambiguous" },
  ]), {
    status: "ambiguous",
    executablePath: undefined,
    reason: "fd_scan_truncated",
    reasons: ["fd_scan_truncated", "elevated_owner_ambiguous"],
  });
});

test("classifyOwnerAmbiguityReason gives every owner uncertainty an explicit non-confident class", () => {
  assert.equal(classifyOwnerAmbiguityReason("owner_ambiguous").status, "ambiguous");
  assert.equal(classifyOwnerAmbiguityReason("elevated_owner_ambiguous").status, "ambiguous");
  assert.equal(classifyOwnerAmbiguityReason("owner_identity_unavailable").status, "ambiguous");
  assert.equal(classifyOwnerAmbiguityReason("owner_evidence_unavailable").status, "ambiguous");
  assert.equal(classifyOwnerAmbiguityReason("fd_scan_truncated").status, "truncated");
  assert.equal(classifyOwnerAmbiguityReason("fd_scan_uncertain").status, "ambiguous");
  assert.equal(classifyOwnerAmbiguityReason("owner_identity_unavailable").owner_dependent, true);
  assert.equal(classifyOwnerAmbiguityReason("ordinary_other_reason"), undefined);
});

test("same-executable SO_REUSEPORT holders are ambiguous, while TCP and UDP from one process agree", () => {
  assert.equal(summarizeSocketAttributions([
    { resolved: true, executablePath: "/usr/bin/node", processIdentity: { tgid: 100, start_time: "10" } },
    { resolved: true, executablePath: "/usr/bin/node", processIdentity: { tgid: 101, start_time: "11" } },
  ]).reason, "owner_ambiguous");
  assert.equal(summarizeSocketAttributions([
    { resolved: true, executablePath: "/usr/bin/node", processIdentity: { tgid: 100, start_time: "10" } },
    { resolved: true, executablePath: "/usr/bin/node", processIdentity: { tgid: 100, start_time: "10" } },
  ]).status, "ok");
});

test("parseLinuxProcessIdentity uses the stat start-time field without trusting the executable path", () => {
  const stat = "100 (node) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 21";
  assert.deepEqual(parseLinuxProcessIdentity(stat, 100), { tgid: 100, start_time: "424242" });
});

// ---------------------------------------------------------------------------------------------
// 3. macOS lsof -iTCP:<port> fixture parsing -> pid + command.
// ---------------------------------------------------------------------------------------------

test("buildMacPortSockets parses a lsof -iTCP:<port> fixture into pid, command, and public-bind facts", () => {
  const stdout = "COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
    + "postgres 4821 me     7u  IPv4 0xabc              0t0  TCP *:5432 (LISTEN)\n";
  assert.deepEqual(buildMacPortSockets(stdout, 5432), [{
    protocol: "tcp",
    local_address: "*",
    local_port: 5432,
    state: "LISTEN",
    public_bind: true,
    pid: 4821,
    command: "postgres",
  }]);
});

test("buildMacPortSockets filters to only the requested port", () => {
  const stdout = "COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
    + "node     1234 me     23u  IPv4 0xabc              0t0  TCP 127.0.0.1:3000 (LISTEN)\n";
  assert.deepEqual(buildMacPortSockets(stdout, 5432), []);
});

// ---------------------------------------------------------------------------------------------
// 4. Source classification fixtures, table-driven, one per branch.
// ---------------------------------------------------------------------------------------------

test("classifySourceFromAncestry classifies each known source type from ancestry fixtures", () => {
  const cases = [
    {
      label: "launchd",
      chain: [{ pid: 500, ppid: 1, comm: "node" }, { pid: 1, ppid: 0, comm: "launchd" }],
      type: "launchd",
    },
    {
      label: "systemd",
      chain: [{ pid: 500, ppid: 1, comm: "nginx" }, { pid: 1, ppid: 0, comm: "systemd" }],
      type: "systemd",
    },
    {
      label: "cron",
      chain: [{ pid: 600, ppid: 550, comm: "backup.sh" }, { pid: 550, ppid: 1, comm: "cron" }],
      type: "cron",
    },
    {
      label: "ssh",
      chain: [{ pid: 700, ppid: 650, comm: "bash" }, { pid: 650, ppid: 600, comm: "sshd" }, { pid: 600, ppid: 1, comm: "launchd" }],
      type: "ssh",
    },
    {
      label: "shell",
      chain: [{ pid: 800, ppid: 750, comm: "npm" }, { pid: 750, ppid: 1, comm: "bash" }],
      type: "shell",
    },
    {
      label: "supervisor",
      chain: [{ pid: 900, ppid: 850, comm: "worker.py" }, { pid: 850, ppid: 800, comm: "python3" }, { pid: 800, ppid: 1, comm: "supervisord" }],
      type: "supervisor",
    },
    {
      label: "container",
      chain: [{ pid: 1000, ppid: 950, comm: "nginx" }, { pid: 950, ppid: 1, comm: "containerd-shim" }],
      type: "container",
    },
    {
      label: "init",
      chain: [{ pid: 1, ppid: 0, comm: "launchd" }],
      type: "init",
    },
    {
      label: "unknown",
      chain: [{ pid: 1100, ppid: 1050, comm: "weird_process" }, { pid: 1050, ppid: 1, comm: "custom_launcher" }],
      type: "unknown",
    },
  ];

  for (const testCase of cases) {
    const source = classifySourceFromAncestry(testCase.chain);
    assert.equal(source.type, testCase.type, `expected ${testCase.label} to classify as ${testCase.type}, got ${source.type}`);
    if (testCase.type === "unknown") {
      assert.equal(source.confidence, 0);
      assert.equal(source.review_hint, "ambiguous");
    } else {
      assert.equal(source.confidence, 1);
      assert.equal(source.review_hint, "none");
    }
  }
});

test("classifySourceFromAncestry handles an empty ancestry chain without throwing", () => {
  assert.deepEqual(classifySourceFromAncestry([]).type, "unknown");
  assert.deepEqual(classifySourceFromAncestry(undefined).type, "unknown");
});

// ---------------------------------------------------------------------------------------------
// 5. Warning fixtures against the pure detectWarnings export.
// ---------------------------------------------------------------------------------------------

test("detectWarnings flags a kernel-asserted deleted-but-running executable at full confidence", () => {
  const record = { resolved: { deleted_exe: true, deleted_exe_confidence: 1 }, source: { type: "shell" }, ancestry: [] };
  const warning = detectWarnings(record, []).find((item) => item.rule_id === "deleted_exe_running");
  assert.deepEqual(warning, {
    rule_id: "deleted_exe_running",
    message: "Process executable path is deleted/unlinked but the process is still running.",
    severity: "high",
    confidence: 1,
  });
});

test("detectWarnings flags a macOS-inferred deleted exe at reduced (0.7) confidence", () => {
  const record = { resolved: { deleted_exe: true, deleted_exe_confidence: 0.7 }, source: { type: "shell" }, ancestry: [] };
  const warning = detectWarnings(record, []).find((item) => item.rule_id === "deleted_exe_running");
  assert.equal(warning.confidence, 0.7);
  assert.equal(warning.severity, "medium");
});

test("detectWarnings does not flag deleted_exe_running when the executable is present", () => {
  const record = { resolved: { deleted_exe: false }, source: { type: "shell" }, ancestry: [] };
  assert.equal(detectWarnings(record, []).some((item) => item.rule_id === "deleted_exe_running"), false);
});

test("detectWarnings flags a public bind with no recognized supervisor, including the bare * address form", () => {
  const record = { resolved: {}, source: { type: "shell" }, ancestry: [] };
  assert.ok(detectWarnings(record, [{ local_address: "0.0.0.0", local_port: 8080 }]).some((item) => item.rule_id === "public_bind_no_supervisor"));
  assert.ok(detectWarnings(record, [{ local_address: "[::]", local_port: 8080 }]).some((item) => item.rule_id === "public_bind_no_supervisor"));
  assert.ok(detectWarnings(record, [{ local_address: "*", local_port: 5432 }]).some((item) => item.rule_id === "public_bind_no_supervisor"));
});

test("detectWarnings does not flag public bind when a recognized supervisor is the classified source", () => {
  const record = { resolved: {}, source: { type: "launchd" }, ancestry: [] };
  assert.equal(detectWarnings(record, [{ local_address: "0.0.0.0", local_port: 80 }]).some((item) => item.rule_id === "public_bind_no_supervisor"), false);
});

test("detectWarnings does not derive an owner-dependent public-bind warning from ambiguous ownership", () => {
  const record = {
    resolved: { status: "ambiguous", reason: "owner_identity_unavailable" },
    source: { type: "unknown", details: { reason: "owner_identity_unavailable" } },
    ancestry: [],
  };
  assert.equal(detectWarnings(record, [{ local_address: "0.0.0.0", local_port: 80 }]).length, 0);
});

test("detectWarnings does not flag a non-public bind address", () => {
  const record = { resolved: {}, source: { type: "shell" }, ancestry: [] };
  assert.equal(detectWarnings(record, [{ local_address: "127.0.0.1", local_port: 5432 }]).some((item) => item.rule_id === "public_bind_no_supervisor"), false);
});

test("detectWarnings flags an unexpected parent for an unclassified source with real ancestry", () => {
  const record = { resolved: {}, source: { type: "unknown" }, ancestry: [{ pid: 1 }, { pid: 2 }] };
  assert.ok(detectWarnings(record, []).some((item) => item.rule_id === "unexpected_parent"));
});

test("detectWarnings does not flag unexpected parent for a trivial single-element ancestry", () => {
  const record = { resolved: {}, source: { type: "unknown" }, ancestry: [{ pid: 1 }] };
  assert.equal(detectWarnings(record, []).some((item) => item.rule_id === "unexpected_parent"), false);
});

test("provenance.js never imports or calls into alert-store", () => {
  const source = readFileSync(new URL("../src/tools/provenance.js", import.meta.url), "utf8");
  assert.equal(/alert-store/.test(source), false);
});

// ---------------------------------------------------------------------------------------------
// 6. deleted_exe mechanism fixtures per-platform.
// ---------------------------------------------------------------------------------------------

test("isLinuxDeletedExeLink detects the kernel (deleted) suffix", () => {
  assert.equal(isLinuxDeletedExeLink("/usr/bin/node (deleted)"), true);
  assert.equal(isLinuxDeletedExeLink("/usr/bin/node"), false);
  assert.equal(isLinuxDeletedExeLink(undefined), false);
});

test("inferMacosDeletedExe infers deletion from an ENOENT stat while lsof still shows the FD open", () => {
  assert.equal(inferMacosDeletedExe({ exePathFromLsof: "/usr/local/bin/postgres", statResult: { status: "enoent" } }), true);
  assert.equal(inferMacosDeletedExe({ exePathFromLsof: "/usr/local/bin/postgres", statResult: { status: "ok" } }), false);
  assert.equal(inferMacosDeletedExe({ exePathFromLsof: undefined, statResult: { status: "enoent" } }), "unknown");
  assert.equal(inferMacosDeletedExe({ exePathFromLsof: "/usr/local/bin/postgres", statResult: { status: "unable" } }), "unknown");
  assert.equal(inferMacosDeletedExe(), "unknown");
});

test("parseMacLsofTxtExecutablePath extracts the executable path from a lsof -d txt fixture", () => {
  const stdout = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF     NODE NAME\n"
    + "postgres 4821 me    txt    REG    1,4    123456    7890 /usr/local/bin/postgres\n";
  assert.equal(parseMacLsofTxtExecutablePath(stdout), "/usr/local/bin/postgres");
  assert.equal(parseMacLsofTxtExecutablePath("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"), undefined);
});

// ---------------------------------------------------------------------------------------------
// 7. username resolution fixtures.
// ---------------------------------------------------------------------------------------------

test("parseIdUsernameOutput accepts a single bare username token", () => {
  assert.equal(parseIdUsernameOutput("postgres\n"), "postgres");
});

test("parseIdUsernameOutput rejects malformed, multi-token, or empty stdout", () => {
  assert.equal(parseIdUsernameOutput(""), undefined);
  assert.equal(parseIdUsernameOutput("uid=1000(postgres) gid=1000\n"), undefined);
  assert.equal(parseIdUsernameOutput("postgres extra\n"), undefined);
  assert.equal(parseIdUsernameOutput(undefined), undefined);
});

// ---------------------------------------------------------------------------------------------
// 8. Redaction reuse: command/args fields match redactAndBoundProcessArgs's output exactly.
// ---------------------------------------------------------------------------------------------

test("parseProvenancePs redacts and bounds args using the shared processes.js redaction helper verbatim", () => {
  const stdout = "PID PPID UID %CPU %MEM RSS COMM ARGS\n"
    + "4821  1  501  0.5  0.2  1024 app app --api-key=hunter2\n";
  const processes = parseProvenancePs(stdout);
  assert.equal(processes.length, 1);
  const expected = redactAndBoundProcessArgs("app --api-key=hunter2");
  assert.equal(processes[0].args, expected.value);
  assert.deepEqual(processes[0].args_redaction, {
    redacted: expected.redacted,
    truncated: expected.truncated,
    original_length: expected.original_length,
    max_length: expected.max_length,
  });
  assert.equal(processes[0].pid, 4821);
  assert.equal(processes[0].ppid, 1);
  assert.equal(processes[0].uid, 501);
});

// ---------------------------------------------------------------------------------------------
// container inspect parsing.
// ---------------------------------------------------------------------------------------------

test("parseContainerInspectPid parses a plain numeric docker/podman inspect pid", () => {
  assert.equal(parseContainerInspectPid("4821\n"), 4821);
  assert.equal(parseContainerInspectPid("0\n"), undefined);
  assert.equal(parseContainerInspectPid("<no value>\n"), undefined);
  assert.equal(parseContainerInspectPid(""), undefined);
});

// ---------------------------------------------------------------------------------------------
// envelope confidence/review_hint policy.
// ---------------------------------------------------------------------------------------------

test("computeProvenanceEnvelopeFields maps resolved status/source type to confidence and review_hint", () => {
  assert.deepEqual(computeProvenanceEnvelopeFields("ok", "shell"), { status: "ok", confidence: 1, reviewHint: "none" });
  assert.deepEqual(computeProvenanceEnvelopeFields("partial", "unknown"), { status: "partial", confidence: 0.4, reviewHint: "missing_permission" });
  assert.deepEqual(computeProvenanceEnvelopeFields("ambiguous", "unknown"), { status: "ambiguous", confidence: 0, reviewHint: "ambiguous" });
  assert.deepEqual(computeProvenanceEnvelopeFields("truncated", "unknown"), { status: "truncated", confidence: 0, reviewHint: "out_of_range" });
  assert.deepEqual(computeProvenanceEnvelopeFields("unknown", "unknown"), { status: "unknown", confidence: 0, reviewHint: "ambiguous" });
});

// ---------------------------------------------------------------------------------------------
// 9. timedEnvelope fail-closed contract for provenance.js's own envelope usage.
// ---------------------------------------------------------------------------------------------

test("resolveProvenance fails closed via timedEnvelope when target normalization throws mid-collection", async () => {
  const hostilePid = { valueOf() { throw new Error("boom: malformed input"); } };
  const envelope = await resolveProvenance({ pid: hostilePid });
  assert.equal(envelope.status, "unable");
  assert.equal(envelope.confidence, 0);
  assert.equal(envelope.review_hint, "missing_permission");
  assert.equal(typeof envelope.trace.latency_ms, "number");
  assert.equal(envelope.layer, "L0");
  assert.equal(envelope.trace.tool, "inspect_runtime_provenance");
});

// ---------------------------------------------------------------------------------------------
// 10. Ambiguous-target guard: deterministic rejection, not silent pick.
// ---------------------------------------------------------------------------------------------

test("normalizeProvenanceTarget deterministically rejects zero or multiple targets", () => {
  assert.equal(normalizeProvenanceTarget({}).error, "missing_target");
  assert.equal(normalizeProvenanceTarget({ pid: 123, port: 80 }).error, "multiple_targets");
  assert.equal(normalizeProvenanceTarget({ pid: 123, container: "abc" }).error, "multiple_targets");
  assert.equal(normalizeProvenanceTarget({ pid: 0 }).error, "invalid_target_value");
  assert.equal(normalizeProvenanceTarget({ port: 70000 }).error, "invalid_target_value");
  assert.equal(normalizeProvenanceTarget({ container: "   " }).error, "invalid_target_value");
  assert.deepEqual(normalizeProvenanceTarget({ pid: 42 }), { kind: "pid", value: 42 });
  assert.deepEqual(normalizeProvenanceTarget({ port: 8080 }), { kind: "port", value: 8080 });
  assert.deepEqual(normalizeProvenanceTarget({ container: "abc123" }), { kind: "container", value: "abc123" });
  // Container refs must match Docker/Podman's own charset, so a flag-shaped value can never be
  // passed to `inspect` as an argv option (argument-injection guard).
  assert.equal(normalizeProvenanceTarget({ container: "-f=/etc/passwd" }).error, "invalid_target_value");
  assert.equal(normalizeProvenanceTarget({ container: "--format" }).error, "invalid_target_value");
  assert.equal(normalizeProvenanceTarget({ container: "a b" }).error, "invalid_target_value");
  assert.deepEqual(normalizeProvenanceTarget({ container: "my-app/web_1.2" }), { kind: "container", value: "my-app/web_1.2" });
});

test("resolveProvenance rejects ambiguous or missing targets deterministically through the real envelope", async () => {
  const both = await resolveProvenance({ pid: 123, port: 80 });
  assert.equal(both.status, "unknown");
  assert.equal(both.confidence, 0);
  assert.equal(both.review_hint, "ambiguous");
  assert.equal(both.result.resolved.status, "unknown");
  assert.equal(both.result.resolved.pid, undefined);

  const none = await resolveProvenance({});
  assert.equal(none.status, "unknown");
  assert.equal(none.review_hint, "ambiguous");
  assert.equal(none.result.resolved.pid, undefined);
});

// ---------------------------------------------------------------------------------------------
// Live macOS smoke: one clean same-UID case, as authorized for this host (macOS Apple Silicon).
// ---------------------------------------------------------------------------------------------

test("resolveProvenance resolves this test process's own pid on a live macOS host", { skip: process.platform !== "darwin" }, async () => {
  const envelope = await resolveProvenance({ pid: process.pid });
  assert.equal(envelope.id, `provenance-pid-${process.pid}`);
  assert.equal(envelope.result.resolved.status, "ok");
  assert.equal(envelope.result.resolved.pid, process.pid);
  assert.equal(envelope.result.resolved.user.uid, process.getuid());
  assert.equal(Array.isArray(envelope.result.warnings), true);
  assert.equal(envelope.result.privilege.mechanism, "unprivileged");
  assert.equal(envelope.result.privilege.elevated_used, false);
  // Never a fabricated pid: an unresolvable pid degrades to pid:undefined (not the queried
  // value echoed back), consistent with the port/container not-found paths.
  const unresolvable = await resolveProvenance({ pid: 999999 });
  assert.equal(unresolvable.result.resolved.pid, undefined);
});

test("isPublicBindAddress recognizes only the pinned literal set", () => {
  assert.equal(isPublicBindAddress("0.0.0.0"), true);
  assert.equal(isPublicBindAddress("[::]"), true);
  assert.equal(isPublicBindAddress("*"), true);
  assert.equal(isPublicBindAddress("127.0.0.1"), false);
  assert.equal(isPublicBindAddress(undefined), false);
});
