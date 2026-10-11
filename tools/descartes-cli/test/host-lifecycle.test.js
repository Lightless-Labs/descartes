import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  BOOT_MEASUREMENT_RESOLUTION_S,
  collectHostLifecycleEvidence,
  DARWIN_SYSCTL_KEYS,
  LINUX_PATHS,
  parseOsReleaseBuild,
  parseProcStatBtime,
  parseProcUptime,
  parseSysctlKeyValues,
  parseSysctlTimevalSeconds,
  readHostLifecycle,
} from "../src/tools/host-lifecycle.js";

const SRC_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "tools", "host-lifecycle.js");

// Real `sysctl <keys>` output captured on the Darwin 25.2 dev VM (2026-10-11). This VM has never
// slept, so the sleep/wake values are the kernel's own zeros.
const DARWIN_SYSCTL_REAL = [
  "kern.bootsessionuuid: EFD29ED2-27A4-488A-96ED-7DB3B021B706",
  "kern.boottime: { sec = 1788538230, usec = 201182 } Fri Sep  4 16:10:30 2026",
  "kern.osversion: 25C56",
  "kern.osrelease: 25.2.0",
  "kern.monotonicclock_usecs: 1791724875400525 76479557408294",
  "kern.sleeptime: { sec = 0, usec = 0 } Thu Jan  1 00:00:00 1970",
  "kern.waketime: { sec = 0, usec = 0 } Thu Jan  1 00:00:00 1970",
  "kern.sleep_abs_time: 0",
  "kern.wake_abs_time: 0",
  "machdep.wake_abstime: 0",
  "machdep.wake_conttime: 0",
  "",
].join("\n");

const FIXED_CLOCKS = { nowFn: () => 1_791_724_875_400, hrtimeFn: () => 76_479_557_408_294n, uptimeFn: () => 3_186_645.2, uvVersion: "1.52.1" };

test("parsers: sysctl key/value lines keep only the fixed key list; timeval seconds; btime; os-release; /proc/uptime", () => {
  const values = parseSysctlKeyValues(`${DARWIN_SYSCTL_REAL}evil.key: x\nkern.osversion: SECOND\n`);
  assert.equal(values["kern.osversion"], "25C56", "first occurrence wins; a duplicate never overrides");
  assert.equal(values["evil.key"], undefined);
  assert.equal(parseSysctlTimevalSeconds(values["kern.boottime"]), 1788538230);
  assert.equal(parseSysctlTimevalSeconds(values["kern.sleeptime"]), 0, "the kernel's own zero is a raw reading, kept as reported");
  assert.equal(parseSysctlTimevalSeconds("garbage"), undefined);
  assert.equal(parseProcStatBtime("cpu 1 2 3\nbtime 1788538230\nprocesses 9\n"), 1788538230);
  assert.equal(parseProcStatBtime("cpu 1 2 3\n"), undefined);
  assert.equal(parseOsReleaseBuild('NAME="Ubuntu"\nVERSION_ID="24.04"\n'), "24.04");
  assert.equal(parseOsReleaseBuild('BUILD_ID=rolling\nVERSION_ID="24.04"\n'), "rolling");
  assert.equal(parseOsReleaseBuild('VERSION_ID="$(rm -rf /)"\n'), undefined, "an out-of-shape token is unknown, never passed through");
  assert.equal(parseProcUptime("12345.67 54321.00\n"), "12345.67");
  assert.equal(parseProcUptime("nope"), undefined);
});

test("STATIC: the darwin read is ONE fixed sysctl argv (no -w, no shell, no constructed key)", () => {
  const source = readFileSync(SRC_FILE, "utf8");
  const calls = [...source.matchAll(/runExec\(\s*"([^"]+)"\s*,\s*([^,]+),/g)];
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1], "sysctl");
  assert.equal(calls[0][2].trim(), "[...DARWIN_SYSCTL_KEYS]");
  assert.ok(!/["']-w["']|=\s*1["']|shell:\s*true/.test(source));
  assert.ok(DARWIN_SYSCTL_KEYS.every((key) => /^[a-z]+\.[a-z_]+$/.test(key)));
});

test("C0.8/C0.9 darwin: boot id, boot time, OS build and raw clock readings from one sysctl call (real-output fixture)", async () => {
  const calls = [];
  const result = await readHostLifecycle({
    platform: "darwin",
    runFixedExecFile: async (command, args) => {
      calls.push([command, ...args]);
      return { status: "ok", stdout: DARWIN_SYSCTL_REAL, stderr: "", command: { argv: [command, ...args] } };
    },
    ...FIXED_CLOCKS,
  });
  assert.deepEqual(calls, [["sysctl", ...DARWIN_SYSCTL_KEYS]]);
  assert.equal(result.status, "ok");
  assert.deepEqual(result.boot, {
    boot_id: "EFD29ED2-27A4-488A-96ED-7DB3B021B706",
    boot_id_source: "kern.bootsessionuuid",
    boot_time_s: 1788538230,
    os_build: "25C56",
    os_release: "25.2.0",
  });
  assert.deepEqual(result.clocks, {
    wall_ms: 1_791_724_875_400,
    uv_hrtime_ns: "76479557408294",
    uv_version: "1.52.1",
    os_uptime_ms: 3_186_645_200,
    kern_monotonicclock_usecs: "1791724875400525 76479557408294",
    kern_sleeptime_s: 0,
    kern_waketime_s: 0,
    kern_sleep_abs_time: "0",
    kern_wake_abs_time: "0",
    machdep_wake_abstime: "0",
    machdep_wake_conttime: "0",
  });
});

test("C0.8 darwin: an older kernel missing some keys (sysctl exits non-zero) is partial with those values unknown, never zero", async () => {
  const stdout = DARWIN_SYSCTL_REAL.split("\n").filter((line) => !line.startsWith("machdep.") && !line.startsWith("kern.monotonicclock")).join("\n");
  const result = await readHostLifecycle({
    platform: "darwin",
    runFixedExecFile: async () => ({ status: "error", code: 1, stdout, stderr: "sysctl: unknown oid 'machdep.wake_abstime'", error: "exit 1" }),
    ...FIXED_CLOCKS,
  });
  assert.equal(result.status, "partial");
  assert.equal(result.boot.boot_id, "EFD29ED2-27A4-488A-96ED-7DB3B021B706");
  assert.equal(result.clocks.machdep_wake_abstime, undefined);
  assert.equal(result.clocks.kern_monotonicclock_usecs, undefined);
});

test("C0.8 darwin: a missing or untrusted sysctl degrades explicitly; no output is unable", async () => {
  const notFound = await readHostLifecycle({ platform: "darwin", runFixedExecFile: async () => ({ status: "not_found_on_known_paths", availability: "not_found_on_known_paths", stdout: "" }), ...FIXED_CLOCKS });
  assert.equal(notFound.status, "not_found_on_known_paths");
  assert.deepEqual(notFound.boot, {});
  const untrusted = await readHostLifecycle({ platform: "darwin", runFixedExecFile: async () => ({ status: "untrusted_binary", availability: "untrusted_binary", stdout: "" }), ...FIXED_CLOCKS });
  assert.equal(untrusted.status, "untrusted_binary");
  const empty = await readHostLifecycle({ platform: "darwin", runFixedExecFile: async () => ({ status: "error", code: 1, stdout: "", error: "boom" }), ...FIXED_CLOCKS });
  assert.equal(empty.status, "unable");
  assert.equal(empty.clocks.wall_ms, FIXED_CLOCKS.nowFn(), "runtime clocks are still read raw");
});

function linuxFiles(overrides = {}) {
  const files = {
    [LINUX_PATHS.boot_id]: "6f1c3a2e-7d4b-4c1a-9e8f-0123456789ab\n",
    [LINUX_PATHS.stat]: "cpu  1 2 3 4\nbtime 1788538230\nprocesses 42\n",
    [LINUX_PATHS.osrelease]: "6.8.0-45-generic\n",
    [LINUX_PATHS.os_release_file]: 'NAME="Ubuntu"\nVERSION_ID="24.04"\n',
    [LINUX_PATHS.uptime]: "3186645.20 12345.00\n",
    [LINUX_PATHS.suspend_success]: "7\n",
    ...overrides,
  };
  return async (file) => {
    if (files[file] === undefined) {
      const error = new Error("ENOENT");
      error.code = "ENOENT";
      throw error;
    }
    return files[file];
  };
}

test("C0.8/C0.9 linux (injected reads, runs on every platform): boot_id, btime, osrelease + build, /proc/uptime, suspend_stats", async () => {
  const result = await readHostLifecycle({ platform: "linux", readFile: linuxFiles(), ...FIXED_CLOCKS });
  assert.equal(result.status, "ok");
  assert.deepEqual(result.boot, {
    boot_id: "6F1C3A2E-7D4B-4C1A-9E8F-0123456789AB",
    boot_id_source: "proc_boot_id",
    boot_time_s: 1788538230,
    os_build: "24.04",
    os_release: "6.8.0-45-generic",
  });
  assert.equal(result.clocks.proc_uptime_s, "3186645.20");
  assert.equal(result.clocks.suspend_stats_success, 7);
});

test("C0.9 linux: a kernel without suspend_stats leaves the counter unknown (never zero); a missing boot_id is partial", async () => {
  const noSuspend = await readHostLifecycle({ platform: "linux", readFile: linuxFiles({ [LINUX_PATHS.suspend_success]: undefined }), ...FIXED_CLOCKS });
  assert.equal(noSuspend.status, "ok");
  assert.equal(noSuspend.clocks.suspend_stats_success, undefined);
  const noBootId = await readHostLifecycle({ platform: "linux", readFile: linuxFiles({ [LINUX_PATHS.boot_id]: "not-a-uuid\n" }), ...FIXED_CLOCKS });
  assert.equal(noBootId.status, "partial");
  assert.equal(noBootId.boot.boot_id, undefined);
  assert.equal(noBootId.boot.boot_id_source, "unknown");
});

test("HIGH 3: malformed required lifecycle fields make the whole result partial with per-field unknown state", async () => {
  const result = await readHostLifecycle({
    platform: "linux",
    readFile: linuxFiles({
      [LINUX_PATHS.stat]: "not stat\n",
      [LINUX_PATHS.osrelease]: 6.8,
      [LINUX_PATHS.uptime]: 3186645,
    }),
    ...FIXED_CLOCKS,
  });
  assert.equal(result.status, "partial");
  assert.deepEqual(result.field_states, { boot_id: "ok", boot_time_s: "unknown", kernel_release: "unknown", uptime: "unknown" });
  assert.equal(result.boot.boot_id, "6F1C3A2E-7D4B-4C1A-9E8F-0123456789AB");
  assert.equal(result.boot.boot_time_s, undefined);
  assert.equal(result.boot.os_release, undefined);
  assert.equal(result.clocks.proc_uptime_s, undefined);
});

test("MEDIUM 2 reproduction: typed runtime clocks reject coercible strings and objects", async () => {
  const result = await readHostLifecycle({
    platform: "darwin",
    runFixedExecFile: async () => ({ status: "ok", stdout: DARWIN_SYSCTL_REAL, stderr: "" }),
    nowFn: () => 1_791_724_875_400,
    uptimeFn: () => "12.5",
    hrtimeFn: () => ({ toString: () => "999" }),
    uvVersion: "1.52.1",
  });
  assert.equal(result.status, "partial");
  assert.equal(result.clocks.os_uptime_ms, undefined);
  assert.equal(result.clocks.uv_hrtime_ns, undefined);
});

test("an unsupported platform is not_applicable, with raw runtime clocks only", async () => {
  const result = await readHostLifecycle({ platform: "sunos", ...FIXED_CLOCKS });
  assert.equal(result.status, "not_applicable");
  assert.deepEqual(result.boot, {});
});

test("collectHostLifecycleEvidence wraps the read in a host-lifecycle envelope carrying the observation interval", async () => {
  const envelope = await collectHostLifecycleEvidence({ platform: "linux", readFile: linuxFiles(), ...FIXED_CLOCKS });
  assert.equal(envelope.id, "host-lifecycle");
  assert.equal(envelope.status, "ok");
  assert.deepEqual(envelope.observation, { start_ms: FIXED_CLOCKS.nowFn(), end_ms: FIXED_CLOCKS.nowFn() });
});

test("I24/I66: the boundary measurement resolution is one named constant with a stated basis", () => {
  assert.equal(BOOT_MEASUREMENT_RESOLUTION_S, 2);
});

// Real-OS reads. Each runs only on its own platform (the Linux path is CI-gated: the dev host cannot
// run VMs). They check shape, never a host-specific value.
test("real darwin host: kern.bootsessionuuid is readable unprivileged and stable across two reads", { skip: process.platform !== "darwin" }, async () => {
  const first = await readHostLifecycle({ platform: "darwin" });
  const second = await readHostLifecycle({ platform: "darwin" });
  // A CI image whose resolver distrusts sysctl degrades explicitly; only an ok read is checked further.
  if (["partial", "unable", "not_found_on_known_paths", "untrusted_binary"].includes(first.status)) return;
  assert.match(first.boot.boot_id ?? "", /^[0-9A-F-]{36}$/);
  assert.equal(first.boot.boot_id, second.boot.boot_id);
  assert.ok(Number.isSafeInteger(first.boot.boot_time_s));
  assert.ok(typeof first.boot.os_build === "string");
});

test("real linux host: /proc/sys/kernel/random/boot_id is readable and stable across two reads", { skip: process.platform !== "linux" }, async () => {
  const first = await readHostLifecycle({ platform: "linux" });
  const second = await readHostLifecycle({ platform: "linux" });
  assert.match(first.boot.boot_id ?? "", /^[0-9A-F-]{36}$/);
  assert.equal(first.boot.boot_id, second.boot.boot_id);
  assert.ok(Number.isSafeInteger(first.boot.boot_time_s));
});

// C0.8 conformance (plan §3 C0.8, §7.8.6): these need a real reboot of a VM, which neither this dev
// host nor the current CI can perform. They are named here so they stay visible; none is claimed.
for (const name of [
  "conformance: Linux CI VM reboot changes boot_id; no pre-boot pid/starttime survives",
  "conformance: Linux kexec changes boot_id",
  "conformance: Linux systemd soft-reboot leaves boot_id unchanged",
  "conformance: macOS tart VM reboot changes kern.bootsessionuuid",
  "conformance: macOS `launchctl reboot userspace` behaviour of kern.bootsessionuuid is recorded, not assumed",
  "conformance: a VM snapshot revert is detected as a boot-id regression",
]) {
  test(name, { todo: "needs a rebootable VM in CI (deferred; context plan C0 addendum)" }, () => {});
}
