import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { collectProcessEvidence } from "../src/tools/processes.js";
import { getLinuxAclEvidenceCapability } from "../src/tools/binary-resolver.js";
import { runDaemonIteration } from "../src/daemon.js";
import { readFactPoints } from "../src/fact-store.js";
import { readDaemonStatus } from "../src/history-store.js";
import { resolveDescartesPaths } from "../src/paths.js";

const PS_OUTPUT = [
  "  PID  PPID  %CPU %MEM   RSS COMM             COMMAND",
  "    1     0   0.1  0.2 11000 init             /sbin/init",
].join("\n");

function regularExecutable() {
  return { mode: 0o100755, uid: 0, dev: 1, ino: 2, isFile: () => true };
}

function directory() {
  return { mode: 0o40755, uid: 0, dev: 1, ino: 3, isDirectory: () => true };
}

function linuxResolverDeps({ getfattr = false, gnuLs = false } = {}) {
  const files = new Set([
    "/usr/bin/ps",
    "/bin/ls",
    ...(getfattr ? ["/usr/bin/getfattr"] : []),
  ]);
  const dirs = new Set(["/usr", "/usr/bin", "/bin", "/"]);
  const realpathFn = async (candidate) => {
    if (files.has(candidate) || dirs.has(candidate)) return candidate;
    throw Object.assign(new Error(`missing ${candidate}`), { code: "ENOENT" });
  };
  const statFn = async (target) => {
    if (files.has(target)) return regularExecutable();
    if (dirs.has(target)) return directory();
    throw Object.assign(new Error(`missing ${target}`), { code: "ENOENT" });
  };
  const execFileAsync = async (command, args) => {
    if (command.endsWith("getfattr")) {
      if (!getfattr) throw Object.assign(new Error("missing getfattr"), { code: "ENOENT" });
      const error = Object.assign(new Error("No such attribute"), { code: "ENODATA", stderr: "No such attribute\n" });
      throw error;
    }
    if (command.endsWith("/ls") && args[0] === "--version") {
      return { stdout: gnuLs ? "ls (GNU coreutils) 9.5\n" : "toybox 0.8.11\n", stderr: "" };
    }
    if (command.endsWith("/ls")) return { stdout: "-rwxr-xr-x 1 root root 123 Jan 1 00:00 /usr/bin/ps\n", stderr: "" };
    if (command.endsWith("/ps")) return { stdout: PS_OUTPUT, stderr: "" };
    throw new Error(`unexpected command ${command}`);
  };
  return { platform: "linux", expectedUid: 0, realpathFn, statFn, readFileFn: async () => Buffer.from("not a script"), execFileAsync };
}

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-acl-regate-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function envelope(id, tool, result) {
  return { id, status: "ok", layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: "2026-11-03T00:00:00.000Z" } };
}

function fastCollectors(processes) {
  return {
    system: async () => envelope("system-overview", "collect_system", { load_average: [0, 0, 0], uptime_seconds: 1, memory: { used_fraction: 0.1, free_bytes: 1 }, swap: { used_bytes: 0 } }),
    processes,
    disks: async () => envelope("disk-usage", "collect_disks", { filesystems: [], inodes: [] }),
  };
}

function profile() {
  return {
    interval_ms: 60000,
    collectors: { system: { enabled: true }, processes: { enabled: true, limit: 5 }, disks: { enabled: true } },
    structural: { interval_ms: 3600000, collectors: {} },
  };
}

test("Linux without getfattr and with toybox ls reports unverified provenance from the real processes collector", async () => {
  const result = await collectProcessEvidence({ limit: 5, ...linuxResolverDeps() });
  assert.equal(result.status, "ok");
  assert.equal(result.result.binary_provenance.acl_evidence, "unverified");
});

test("host ACL capability uses the trust-checked helper chain and distinguishes fallback states", async () => {
  assert.equal(await getLinuxAclEvidenceCapability(linuxResolverDeps()), "unverified");
  assert.equal(await getLinuxAclEvidenceCapability(linuxResolverDeps({ getfattr: true })), "verified");
  assert.equal(await getLinuxAclEvidenceCapability({ ...linuxResolverDeps(), platform: "darwin" }), "not_applicable");
});

test("daemon propagates real ps ACL evidence to status, collector status, and collector.binary_state", async () => {
  const paths = await tempPaths();
  const deps = linuxResolverDeps();
  let capabilityCalls = 0;
  const processes = () => collectProcessEvidence({ limit: 5, ...deps });
  const result = await runDaemonIteration(paths, {
    profile: profile(),
    collectors: fastCollectors(processes),
    platform: "linux",
    aclEvidenceCapability: async () => {
      capabilityCalls += 1;
      return getLinuxAclEvidenceCapability(deps);
    },
    ts: "2026-11-03T00:00:00.000Z",
    now: "2026-11-03T00:00:00.000Z",
    evaluateAlerts: false,
  });

  assert.equal(capabilityCalls, 1);
  assert.equal(result.status.acl_evidence, "unverified");
  assert.equal(result.status.collector_statuses.find((entry) => entry.id === "top-processes").acl_evidence, "unverified");
  const facts = await readFactPoints(paths, { family: "collector_state", now: "2026-11-03T00:00:00.000Z" });
  const ps = facts.points.find((point) => point.entity_key === "collector.binary_state.ps");
  assert.equal(ps.attributes.acl_evidence, "unverified");
  assert.equal((await readDaemonStatus(paths)).acl_evidence, "unverified");
});

test("verified Linux host and macOS never emit unverified ACL evidence", async () => {
  const verifiedPaths = await tempPaths();
  const verifiedDeps = linuxResolverDeps({ getfattr: true });
  const verified = await runDaemonIteration(verifiedPaths, {
    profile: profile(),
    collectors: fastCollectors(() => collectProcessEvidence({ limit: 5, ...verifiedDeps })),
    platform: "linux",
    aclEvidenceCapability: () => getLinuxAclEvidenceCapability(verifiedDeps),
    ts: "2026-11-03T00:00:00.000Z",
    now: "2026-11-03T00:00:00.000Z",
    evaluateAlerts: false,
  });
  assert.equal("unverified" in verified.status, false);
  assert.equal(JSON.stringify(verified), JSON.stringify(verified).replaceAll("unverified", ""));

  const macPaths = await tempPaths();
  const mac = await runDaemonIteration(macPaths, {
    profile: profile(),
    collectors: fastCollectors(async () => envelope("top-processes", "collect_processes", { top_cpu: [], top_memory: [] })),
    platform: "darwin",
    aclEvidenceCapability: () => getLinuxAclEvidenceCapability({ platform: "darwin" }),
    ts: "2026-11-03T00:00:00.000Z",
    now: "2026-11-03T00:00:00.000Z",
    evaluateAlerts: false,
  });
  assert.equal("acl_evidence" in mac.status, false);
  assert.equal(JSON.stringify(mac).includes("unverified"), false);
});
