// Context plan C0.8 / C0.9 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.1):
// the boot-identity primitive and the raw clock-reading capture.
//
// READ ONLY. macOS: ONE fixed-argv `sysctl` invocation through the binary resolver (no shell, no
// write flag, no `-w`). Linux: plain reads of /proc and /sys files (no exec at all). Unprivileged.
//
// What it reads (raw, never interpreted here):
//   - boot identity: macOS kern.bootsessionuuid (verified 2026-10-06 readable unprivileged on
//     Darwin 25.2); Linux /proc/sys/kernel/random/boot_id;
//   - the reported boot time (kern.boottime; /proc/stat btime), the OS build (kern.osversion;
//     /etc/os-release BUILD_ID, else VERSION_ID) and kernel release (kern.osrelease;
//     /proc/sys/kernel/osrelease);
//   - C0.9 RAW clock readings: wall clock, libuv hrtime (its kernel clock is UNVERIFIED and is
//     labelled so, never named as pausing or non-pausing), os.uptime(), and per platform: macOS
//     kern.monotonicclock_usecs, kern.sleeptime / kern.waketime, kern.sleep_abs_time /
//     kern.wake_abs_time, machdep.wake_abstime / machdep.wake_conttime; Linux /proc/uptime (its first
//     field is CLOCK_BOOTTIME-based) and /sys/power/suspend_stats/success.
//
// The clock ids the plan names (Linux CLOCK_MONOTONIC vs CLOCK_BOOTTIME; macOS CLOCK_UPTIME_RAW /
// mach_absolute_time vs CLOCK_MONOTONIC / mach_continuous_time) are NOT readable from Node without
// native code. They are recorded as `unavailable_without_native` rather than substituted. Deriving
// suspend bounds from these readings is F3, inactive until the C0.9 real-laptop measurement lands:
// host.suspend is `unknown` with exposure [0, wall delta] on every platform until then.
//
// Degrade, never fabricate: an unreadable value is undefined here and "unknown" in the fact; a
// missing sysctl key is never a zero.

import fs from "node:fs/promises";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { binaryProvenance, isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

// I24 / I66 (context plan §0.5): the measurement resolution of the boot-boundary checks, in seconds.
// Basis: the reported boot time has whole-second resolution on both platforms (kern.boottime is
// read as its `sec` field, /proc/stat btime is an integer), and the boot time, the wall clock and the
// uptime are read non-atomically, within one probe, adding at most one more second. It is a
// measurement resolution (class S), not a claim about normal behaviour, and there is no separate
// boundary tolerance constant (I66).
export const BOOT_MEASUREMENT_RESOLUTION_S = 2;

// The closed, fixed sysctl key list. Never built from input.
export const DARWIN_SYSCTL_KEYS = Object.freeze([
  "kern.bootsessionuuid",
  "kern.boottime",
  "kern.osversion",
  "kern.osrelease",
  "kern.monotonicclock_usecs",
  "kern.sleeptime",
  "kern.waketime",
  "kern.sleep_abs_time",
  "kern.wake_abs_time",
  "machdep.wake_abstime",
  "machdep.wake_conttime",
]);

export const LINUX_PATHS = Object.freeze({
  boot_id: "/proc/sys/kernel/random/boot_id",
  stat: "/proc/stat",
  osrelease: "/proc/sys/kernel/osrelease",
  os_release_file: "/etc/os-release",
  uptime: "/proc/uptime",
  suspend_success: "/sys/power/suspend_stats/success",
});

const UUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const VERSION_TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$/;
const DIGITS_RE = /^[0-9]{1,24}$/;

/** `sysctl a b c` prints "key: value" lines; unknown keys go to stderr. Only listed keys are kept. */
export function parseSysctlKeyValues(stdout, keys = DARWIN_SYSCTL_KEYS) {
  if (typeof stdout !== "string") return {};
  const allowed = new Set(keys);
  const values = {};
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const index = rawLine.indexOf(": ");
    if (index <= 0) continue;
    const key = rawLine.slice(0, index).trim();
    if (!allowed.has(key) || Object.prototype.hasOwnProperty.call(values, key)) continue;
    values[key] = rawLine.slice(index + 2).trim();
  }
  return values;
}

/** "{ sec = 1788538230, usec = 201182 } Fri Sep  4 ..." -> 1788538230 (whole seconds), else undefined. */
export function parseSysctlTimevalSeconds(value) {
  if (typeof value !== "string") return undefined;
  const match = /^\{\s*sec\s*=\s*([0-9]{1,15}),\s*usec\s*=\s*[0-9]{1,7}\s*\}/.exec(value);
  if (!match) return undefined;
  const seconds = Number(match[1]);
  return Number.isSafeInteger(seconds) ? seconds : undefined;
}

function digitsOrUndefined(value) {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  return DIGITS_RE.test(text) ? text : undefined;
}

function versionTokenOrUndefined(value) {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  return VERSION_TOKEN_RE.test(text) ? text : undefined;
}

export function parseProcStatBtime(text) {
  if (typeof text !== "string") return undefined;
  const match = /^btime\s+([0-9]{1,15})\s*$/m.exec(text);
  if (!match) return undefined;
  const seconds = Number(match[1]);
  return Number.isSafeInteger(seconds) ? seconds : undefined;
}

/** /etc/os-release: BUILD_ID if present, else VERSION_ID; quotes stripped; bounded token only. */
export function parseOsReleaseBuild(text) {
  if (typeof text !== "string") return undefined;
  const fields = {};
  for (const rawLine of String(text ?? "").split("\n")) {
    const match = /^([A-Z_]+)=(.*)$/.exec(rawLine.trim());
    if (match) fields[match[1]] = match[2].replace(/^["']|["']$/g, "");
  }
  return versionTokenOrUndefined(fields.BUILD_ID) ?? versionTokenOrUndefined(fields.VERSION_ID);
}

/** /proc/uptime: "12345.67 54321.00" -> "12345.67" (raw text of the CLOCK_BOOTTIME-based field). */
export function parseProcUptime(text) {
  if (typeof text !== "string") return undefined;
  const first = text.trim().split(/\s+/)[0];
  return /^[0-9]{1,20}(\.[0-9]{1,9})?$/.test(first ?? "") ? first : undefined;
}

function runtimeClocks(options) {
  const nowFn = options.nowFn ?? Date.now;
  const hrtimeFn = options.hrtimeFn ?? (() => process.hrtime.bigint());
  const uptimeFn = options.uptimeFn ?? os.uptime;
  let uptime;
  try {
    uptime = Number(uptimeFn());
  } catch {
    uptime = Number.NaN;
  }
  return {
    wall_ms: nowFn(),
    uv_hrtime_ns: String(hrtimeFn()),
    uv_version: versionTokenOrUndefined(options.uvVersion ?? process.versions.uv),
    os_uptime_ms: Number.isFinite(uptime) && uptime >= 0 ? Math.round(uptime * 1000) : undefined,
  };
}

async function readDarwin(options) {
  const runExec = options.runFixedExecFile ?? ((command, args, execOptions) => runResolvedExecFile(command, args, {
    ...execOptions,
    timeout: execOptions.timeout ?? 2000,
    maxBuffer: execOptions.maxBuffer ?? 64 * 1024,
    execFileAsync,
  }));
  const { runFixedExecFile: _drop, ...resolverOptions } = options;
  const probe = await runExec("sysctl", [...DARWIN_SYSCTL_KEYS], resolverOptions);
  if (isBinaryNotFound(probe)) return { status: "not_found_on_known_paths", binary: probe.binary };
  if (isBinaryUntrusted(probe)) return { status: "untrusted_binary", binary: probe.binary, error: probe.error };
  // sysctl exits non-zero when ANY listed key is unknown (e.g. a key an older kernel lacks) but still
  // prints the known ones on stdout: parse whatever printed; a missing key stays undefined.
  const values = parseSysctlKeyValues(probe.stdout);
  if (Object.keys(values).length === 0) return { status: "unable", binary: probe.binary, error: probe.error ?? "no sysctl values" };
  const bootId = UUID_RE.test(values["kern.bootsessionuuid"] ?? "") ? values["kern.bootsessionuuid"].toUpperCase() : undefined;
  const monotonic = /^[0-9]{1,24} [0-9]{1,24}$/.test(values["kern.monotonicclock_usecs"] ?? "") ? values["kern.monotonicclock_usecs"] : undefined;
  return {
    status: Object.keys(values).length === DARWIN_SYSCTL_KEYS.length && bootId ? "ok" : "partial",
    binary: probe.binary,
    boot: {
      boot_id: bootId,
      boot_id_source: bootId ? "kern.bootsessionuuid" : "unknown",
      boot_time_s: parseSysctlTimevalSeconds(values["kern.boottime"]),
      os_build: versionTokenOrUndefined(values["kern.osversion"]),
      os_release: versionTokenOrUndefined(values["kern.osrelease"]),
    },
    platform_clocks: {
      kern_monotonicclock_usecs: monotonic,
      kern_sleeptime_s: parseSysctlTimevalSeconds(values["kern.sleeptime"]),
      kern_waketime_s: parseSysctlTimevalSeconds(values["kern.waketime"]),
      kern_sleep_abs_time: digitsOrUndefined(values["kern.sleep_abs_time"]),
      kern_wake_abs_time: digitsOrUndefined(values["kern.wake_abs_time"]),
      machdep_wake_abstime: digitsOrUndefined(values["machdep.wake_abstime"]),
      machdep_wake_conttime: digitsOrUndefined(values["machdep.wake_conttime"]),
    },
  };
}

async function readTextFile(readFile, file) {
  try {
    const text = await readFile(file, "utf8");
    return typeof text === "string" ? { text } : { error: "non_string_output" };
  } catch (error) {
    return { error: error?.code ?? "read_failed" };
  }
}

async function readLinux(options) {
  const readFile = options.readFile ?? fs.readFile;
  const [bootId, stat, osrelease, osReleaseFile, uptime, suspend] = await Promise.all([
    readTextFile(readFile, LINUX_PATHS.boot_id),
    readTextFile(readFile, LINUX_PATHS.stat),
    readTextFile(readFile, LINUX_PATHS.osrelease),
    readTextFile(readFile, LINUX_PATHS.os_release_file),
    readTextFile(readFile, LINUX_PATHS.uptime),
    readTextFile(readFile, LINUX_PATHS.suspend_success),
  ]);
  const rawBootId = typeof bootId.text === "string" ? bootId.text.trim() : "";
  const bootIdValue = UUID_RE.test(rawBootId) ? rawBootId.toUpperCase() : undefined;
  const suspendCount = digitsOrUndefined(suspend.text);
  const readsOk = [bootId, stat, osrelease, uptime].every((read) => read.text !== undefined);
  const bootTime = parseProcStatBtime(stat.text);
  const kernelRelease = versionTokenOrUndefined(osrelease.text);
  const uptimeValue = parseProcUptime(uptime.text);
  return {
    status: bootIdValue && readsOk ? "ok" : bootIdValue || readsOk ? "partial" : "unable",
    boot: {
      boot_id: bootIdValue,
      boot_id_source: bootIdValue ? "proc_boot_id" : "unknown",
      boot_time_s: bootTime,
      os_build: parseOsReleaseBuild(osReleaseFile.text),
      os_release: kernelRelease,
    },
    platform_clocks: {
      proc_uptime_s: uptimeValue,
      // A kernel without CONFIG_PM_SLEEP has no suspend_stats: unknown, never zero.
      suspend_stats_success: suspendCount !== undefined ? Number(suspendCount) : undefined,
    },
  };
}

/**
 * The host-lifecycle read: boot identity, boot time, OS build and the raw clock readings, in one
 * cheap probe. Used both as the structural context collector and as the daemon's fast-tick boundary
 * probe (C0.12). Unsupported platforms are not_applicable.
 */
export async function readHostLifecycle(options = {}) {
  const platform = options.platform ?? process.platform;
  const obsStartMs = (options.nowFn ?? Date.now)();
  let platformRead;
  if (platform === "darwin") platformRead = await readDarwin(options);
  else if (platform === "linux") platformRead = await readLinux(options);
  else platformRead = { status: "not_applicable" };
  // Runtime clocks are read AFTER the kernel read, as close to it as possible; the raw pairing is
  // what C0.9 needs, not an interpretation.
  const clocks = runtimeClocks(options);
  const field_states = {
    boot_id: typeof platformRead.boot?.boot_id === "string" ? "ok" : "unknown",
    boot_time_s: Number.isSafeInteger(platformRead.boot?.boot_time_s) ? "ok" : "unknown",
    kernel_release: typeof platformRead.boot?.os_release === "string" ? "ok" : "unknown",
    uptime: platform === "linux"
      ? typeof platformRead.platform_clocks?.proc_uptime_s === "string" ? "ok" : "unknown"
      : Number.isSafeInteger(clocks.os_uptime_ms) ? "ok" : "unknown",
  };
  const requiredFieldsParsed = Object.values(field_states).every((state) => state === "ok");
  const baseStatus = platformRead.status;
  const status = baseStatus === "not_applicable" || baseStatus === "not_found_on_known_paths" || baseStatus === "untrusted_binary" || baseStatus === "missing_permission"
    ? baseStatus
    : baseStatus === "unable" && !requiredFieldsParsed
      ? "unable"
      : baseStatus === "partial" || !requiredFieldsParsed ? "partial" : "ok";
  return {
    platform,
    status,
    field_states,
    error: platformRead.error,
    boot: platformRead.boot ?? {},
    clocks: { ...clocks, ...(platformRead.platform_clocks ?? {}) },
    binary_provenance: platformRead.binary ? binaryProvenance(platformRead.binary) : undefined,
    observation: { start_ms: obsStartMs, end_ms: (options.nowFn ?? Date.now)() },
  };
}

export async function collectHostLifecycleEvidence(options = {}) {
  return timedEnvelope(async () => readHostLifecycle(options), (result) => {
    const built = evidenceEnvelope({
      id: "host-lifecycle",
      status: result.status === "ok" ? "ok" : result.status === "partial" ? "warning" : "unable",
      source: "host_lifecycle",
      result,
      confidence: result.status === "ok" ? 1 : result.status === "partial" ? 0.5 : 0,
      reviewHint: result.status === "untrusted_binary" ? "untrusted_binary" : "none",
      tool: "collect_host_lifecycle",
      target: "boot_identity",
    });
    if (result.observation) built.observation = result.observation;
    return built;
  });
}
