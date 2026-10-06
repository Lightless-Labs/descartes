import { realpath as defaultRealpath, stat as defaultStat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsyncDefault = promisify(execFile);

export const NOT_FOUND_ON_KNOWN_PATHS = "not_found_on_known_paths";
export const UNTRUSTED_BINARY = "untrusted_binary";

const COMMON_BINARY_DIRECTORIES = Object.freeze([
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  "/run/current-system/sw/bin",
  "/snap/bin",
  "/nix/var/nix/profiles/default/bin",
]);

const PLATFORM_BINARY_DIRECTORIES = Object.freeze({
  darwin: Object.freeze([...COMMON_BINARY_DIRECTORIES, "/opt/homebrew/bin", "/opt/homebrew/sbin"]),
  linux: Object.freeze(COMMON_BINARY_DIRECTORIES),
  freebsd: Object.freeze(COMMON_BINARY_DIRECTORIES),
  openbsd: Object.freeze(COMMON_BINARY_DIRECTORIES),
  netbsd: Object.freeze(COMMON_BINARY_DIRECTORIES),
});

const SPECIAL_BINARY_PATHS = Object.freeze({
  tailscale: Object.freeze([
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
  ]),
});

function nixProfileDirectories({ homeDir = os.homedir(), username = os.userInfo().username } = {}) {
  return [
    path.join(homeDir, ".nix-profile", "bin"),
    path.join("/etc/profiles/per-user", username, "bin"),
  ];
}

export function candidatePaths(binary, platform, options = {}) {
  const directories = PLATFORM_BINARY_DIRECTORIES[platform] ?? PLATFORM_BINARY_DIRECTORIES.linux;
  const special = platform === "darwin" ? (SPECIAL_BINARY_PATHS[binary] ?? []) : [];
  const configured = (options.trustedBinaryPaths ?? [])
    .filter((candidate) => typeof candidate === "string" && path.isAbsolute(candidate) && path.basename(candidate) === binary);
  const nix = nixProfileDirectories(options);
  return [...new Set([
    ...configured,
    ...special,
    ...directories.map((directory) => path.join(directory, binary)),
    ...nix.map((directory) => path.join(directory, binary)),
  ])];
}

function isRegularExecutable(statResult) {
  return Boolean(statResult?.isFile?.()) && (Number(statResult.mode) & 0o111) !== 0;
}

function isGroupOrWorldWritable(statResult) {
  return (Number(statResult?.mode) & 0o022) !== 0;
}

function ownerIsAllowed(statResult, expectedUid) {
  const uid = Number(statResult?.uid);
  return uid === 0 || (Number.isFinite(expectedUid) && uid === expectedUid);
}

function ancestorPaths(filePath) {
  const ancestors = [];
  let current = path.dirname(filePath);
  while (true) {
    ancestors.push(current);
    if (current === path.parse(current).root) return ancestors;
    current = path.dirname(current);
  }
}

async function safeStat(statFn, target) {
  try {
    return { stat: await statFn(target) };
  } catch (error) {
    return { error };
  }
}

async function safeRealpath(realpathFn, target) {
  try {
    return { path: await realpathFn(target) };
  } catch (error) {
    return { error };
  }
}

function missing(error) {
  return error?.code === "ENOENT" || error?.code === "ENOTDIR";
}

function trustFailure({ resolvedPath, component, reason, sameUidWritableComponents = [] }) {
  return {
    status: UNTRUSTED_BINARY,
    path: undefined,
    resolved_path: resolvedPath,
    trust_verdict: UNTRUSTED_BINARY,
    offending_component: component,
    trust_reason: reason,
    same_uid_writable_components: sameUidWritableComponents,
  };
}

async function inspectTrustedPath(resolvedPath, { statFn, expectedUid, operatorTrusted = false } = {}) {
  const fileResult = await safeStat(statFn, resolvedPath);
  if (!fileResult.stat) return trustFailure({ resolvedPath, component: resolvedPath, reason: "stat_failed" });
  if (!isRegularExecutable(fileResult.stat)) {
    return trustFailure({ resolvedPath, component: resolvedPath, reason: "not_regular_executable" });
  }

  // An explicit operator path is an escape hatch for ownership/mode policy only. It is still
  // realpath-resolved and must be a regular executable, and the identity is rechecked before exec.
  if (operatorTrusted) {
    return {
      status: "resolved",
      path: resolvedPath,
      resolved_path: resolvedPath,
      trust_verdict: "operator_trusted",
      same_uid_writable_components: [],
      file_stat: fileResult.stat,
    };
  }

  const components = [resolvedPath, ...ancestorPaths(resolvedPath)];
  const sameUidWritableComponents = [];
  for (const component of components) {
    const result = component === resolvedPath ? fileResult : await safeStat(statFn, component);
    if (!result.stat) return trustFailure({ resolvedPath, component, reason: "stat_failed", sameUidWritableComponents });
    if (component !== resolvedPath && !result.stat.isDirectory?.()) {
      return trustFailure({ resolvedPath, component, reason: "not_directory", sameUidWritableComponents });
    }
    if (!ownerIsAllowed(result.stat, expectedUid)) {
      return trustFailure({ resolvedPath, component, reason: "owner_not_root_or_daemon", sameUidWritableComponents });
    }
    if (isGroupOrWorldWritable(result.stat)) {
      return trustFailure({ resolvedPath, component, reason: "group_or_world_writable", sameUidWritableComponents });
    }
    if (Number(result.stat.uid) === expectedUid && (Number(result.stat.mode) & 0o200) !== 0) {
      sameUidWritableComponents.push(component);
    }
  }

  return {
    status: "resolved",
    path: resolvedPath,
    resolved_path: resolvedPath,
    trust_verdict: "trusted",
    same_uid_writable_components: sameUidWritableComponents,
    file_stat: fileResult.stat,
  };
}

/**
 * Resolve a collector command without consulting PATH. Candidates are realpath-resolved and a
 * normal candidate is accepted only when the executable and every directory up to / are owned by
 * root or the daemon UID and no component is group/world writable. Same-UID owner writability is
 * intentionally accepted and recorded in same_uid_writable_components as provenance.
 */
export async function resolveCollectorBinary(binary, {
  platform = process.platform,
  statFn = defaultStat,
  realpathFn = defaultRealpath,
  expectedUid = typeof process.getuid === "function" ? process.getuid() : undefined,
  trustedBinaryPaths = [],
  homeDir,
  username,
} = {}) {
  const name = String(binary ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) {
    throw new TypeError(`collector binary must be a bare allowlisted name: ${name}`);
  }

  const configuredPaths = new Set(trustedBinaryPaths.filter((candidate) => typeof candidate === "string" && path.isAbsolute(candidate)));
  const candidates = candidatePaths(name, platform, { trustedBinaryPaths, homeDir, username });
  let firstUntrusted;

  for (const candidate of candidates) {
    const operatorTrusted = configuredPaths.has(candidate);
    const real = await safeRealpath(realpathFn, candidate);
    if (!real.path) {
      if (operatorTrusted || !missing(real.error)) {
        firstUntrusted ??= trustFailure({ resolvedPath: undefined, component: candidate, reason: "realpath_failed" });
      }
      continue;
    }
    const inspected = await inspectTrustedPath(real.path, { statFn, expectedUid, operatorTrusted });
    if (inspected.status === "resolved") {
      return { ...inspected, binary: name, candidates };
    }
    firstUntrusted ??= { ...inspected, binary: name, candidates };
  }

  if (firstUntrusted) return { ...firstUntrusted, binary: name, candidates };
  return { status: NOT_FOUND_ON_KNOWN_PATHS, binary: name, path: undefined, resolved_path: undefined, trust_verdict: NOT_FOUND_ON_KNOWN_PATHS, candidates };
}

export function binaryAvailability(probe) {
  if (probe?.status === NOT_FOUND_ON_KNOWN_PATHS || probe?.availability === NOT_FOUND_ON_KNOWN_PATHS || probe?.code === "ENOENT" || probe?.code === "NOT_FOUND_ON_KNOWN_PATHS") {
    return NOT_FOUND_ON_KNOWN_PATHS;
  }
  if (probe?.status === UNTRUSTED_BINARY || probe?.availability === UNTRUSTED_BINARY) return UNTRUSTED_BINARY;
  if (probe?.status === "ok") return "resolved";
  return "unable";
}

export function isBinaryNotFound(probe) {
  return binaryAvailability(probe) === NOT_FOUND_ON_KNOWN_PATHS;
}

export function isBinaryUntrusted(probe) {
  return binaryAvailability(probe) === UNTRUSTED_BINARY;
}

export function binaryProvenance(probe) {
  const binary = probe?.binary && typeof probe.binary === "object" ? probe.binary : probe;
  return {
    requested_binary: binary?.binary,
    resolved_path: binary?.resolved_path ?? binary?.path,
    trust_verdict: binary?.trust_verdict,
    offending_component: binary?.offending_component,
    trust_reason: binary?.trust_reason,
    same_uid_writable_components: binary?.same_uid_writable_components ?? [],
  };
}

async function reverifyResolvedBinary(resolution, options) {
  const resolvedPath = resolution.resolved_path ?? resolution.path;
  const real = await safeRealpath(options.realpathFn ?? defaultRealpath, resolvedPath);
  if (!real.path || real.path !== resolvedPath) {
    return { ...resolution, status: UNTRUSTED_BINARY, trust_verdict: UNTRUSTED_BINARY, trust_reason: "realpath_changed", offending_component: resolvedPath, path: undefined };
  }
  const current = await safeStat(options.statFn ?? defaultStat, real.path);
  if (!current.stat || !isRegularExecutable(current.stat)) {
    return { ...resolution, status: UNTRUSTED_BINARY, trust_verdict: UNTRUSTED_BINARY, trust_reason: "file_recheck_failed", offending_component: real.path, path: undefined };
  }
  const original = resolution.file_stat;
  if (original?.dev !== undefined && original?.ino !== undefined
    && (current.stat.dev !== original.dev || current.stat.ino !== original.ino)) {
    return { ...resolution, status: UNTRUSTED_BINARY, trust_verdict: UNTRUSTED_BINARY, trust_reason: "file_identity_changed", offending_component: real.path, path: undefined };
  }
  return { ...resolution, path: real.path, resolved_path: real.path, file_stat: current.stat };
}

/**
 * Run a fixed collector command after resolution. The final stat identity check narrows (but does
 * not eliminate) the resolution/exec TOCTOU window; the residual is documented for operators.
 */
export async function runResolvedExecFile(binary, args = [], options = {}) {
  const resolution = await resolveCollectorBinary(binary, options);
  const requestedArgv = [binary, ...args];
  if (resolution.status !== "resolved") {
    const unavailable = resolution.status === UNTRUSTED_BINARY ? UNTRUSTED_BINARY : NOT_FOUND_ON_KNOWN_PATHS;
    return {
      status: unavailable,
      code: unavailable === UNTRUSTED_BINARY ? "UNTRUSTED_BINARY" : "NOT_FOUND_ON_KNOWN_PATHS",
      availability: unavailable,
      stdout: "",
      stderr: "",
      error: unavailable === UNTRUSTED_BINARY ? `${binary} resolved only to an untrusted executable` : `${binary} was not found on pinned known paths`,
      command: { argv: requestedArgv, requested_binary: binary, read_only: true },
      binary: resolution,
    };
  }

  const reverified = await reverifyResolvedBinary(resolution, options);
  if (reverified.status !== "resolved") {
    return {
      status: UNTRUSTED_BINARY,
      code: "UNTRUSTED_BINARY",
      availability: UNTRUSTED_BINARY,
      stdout: "",
      stderr: "",
      error: `${binary} changed during resolution before exec`,
      command: { argv: requestedArgv, requested_binary: binary, read_only: true },
      binary: reverified,
    };
  }

  const execFileAsync = options.execFileAsync ?? execFileAsyncDefault;
  const command = { argv: [reverified.path, ...args], requested_binary: binary, read_only: true };
  try {
    const { stdout, stderr } = await execFileAsync(reverified.path, args, {
      timeout: options.timeout,
      maxBuffer: options.maxBuffer,
    });
    return { status: "ok", stdout, stderr, command, binary: reverified };
  } catch (error) {
    const notFound = error?.code === "ENOENT";
    return {
      status: notFound ? NOT_FOUND_ON_KNOWN_PATHS : "error",
      code: error?.code,
      availability: notFound ? NOT_FOUND_ON_KNOWN_PATHS : undefined,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? "",
      error: error instanceof Error ? error.message : String(error),
      command,
      binary: reverified,
    };
  }
}
