import { readFile as defaultReadFile, realpath as defaultRealpath, stat as defaultStat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsyncDefault = promisify(execFile);
const MACOS_GROUP_LOOKUP = "/usr/bin/dscl";
const MACOS_UID_LOOKUP = "/usr/bin/id";
const LINUX_GROUP_LOOKUP = "/usr/bin/getent";

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

function trustFailure({ resolvedPath, component, reason, sameUidWritableComponents = [], writerUids = [] }) {
  return {
    status: UNTRUSTED_BINARY,
    path: undefined,
    resolved_path: resolvedPath,
    trust_verdict: UNTRUSTED_BINARY,
    offending_component: component,
    trust_reason: reason,
    same_uid_writable_components: sameUidWritableComponents,
    writer_uids: writerUids,
    operator_override_hint: "Review this absolute path and add it to trusted_binary_paths in watch.json only if the operator accepts the risk.",
  };
}

function asUid(value) {
  const uid = Number(String(value).trim());
  return Number.isInteger(uid) && uid >= 0 ? uid : undefined;
}

function parseDsclGroupMembership(stdout) {
  const line = String(stdout ?? "").split("\n").find((candidate) => /^GroupMembership:\s*/.test(candidate.trim()));
  if (!line) return undefined;
  return line.replace(/^\s*GroupMembership:\s*/, "").trim().split(/\s+/).filter(Boolean);
}

function parseDsclPrimaryGroupList(stdout, gid) {
  return String(stdout ?? "").split("\n").flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length >= 2 && fields.at(-1) === String(gid) ? [fields[0]] : [];
  });
}

function parseDsclGroupList(stdout, gid) {
  const fields = String(stdout ?? "").split("\n").map((line) => line.trim().split(/\s+/));
  return fields.find((parts) => parts.length >= 2 && parts.at(-1) === String(gid))?.[0];
}

function parseGetentGroup(stdout, gid) {
  const line = String(stdout ?? "").split("\n").map((candidate) => candidate.trim())
    .find((candidate) => candidate && candidate.split(":").length >= 4 && candidate.split(":")[2] === String(gid));
  if (!line) return undefined;
  const fields = line.split(":");
  return { name: fields[0], members: fields[3] ? fields[3].split(",").filter(Boolean) : [] };
}

function parseGetentPasswd(stdout, names, gid) {
  const wanted = new Set(names);
  const uids = new Set();
  for (const line of String(stdout ?? "").split("\n")) {
    const fields = line.trim().split(":");
    if (fields.length < 4) continue;
    const uid = asUid(fields[2]);
    const primaryGid = fields[3];
    if (uid !== undefined && (wanted.has(fields[0]) || primaryGid === String(gid))) uids.add(uid);
  }
  return uids;
}

async function execLookup(execFileAsync, command, args) {
  try {
    const result = await execFileAsync(command, args, { timeout: 2000, maxBuffer: 256 * 1024 });
    return { stdout: result.stdout ?? "" };
  } catch (error) {
    return { error };
  }
}

async function loadGroupWriterUids(gid, { platform, cache = {}, execFileAsync = execFileAsyncDefault } = {}) {
  const numericGid = asUid(gid);
  if (numericGid === undefined) return { error: "group_id_unavailable" };
  cache.groupWriterUids ??= new Map();
  if (cache.groupWriterUids.has(numericGid)) return cache.groupWriterUids.get(numericGid);

  let result;
  if (platform === "darwin") {
    const groupList = await execLookup(execFileAsync, MACOS_GROUP_LOOKUP, [".", "-list", "/Groups", "PrimaryGroupID"]);
    const groupName = groupList.error ? undefined : parseDsclGroupList(groupList.stdout, numericGid);
    if (!groupName) result = { error: "group_membership_unresolvable" };
    else {
      const [membership, primaryUsers] = await Promise.all([
        execLookup(execFileAsync, MACOS_GROUP_LOOKUP, [".", "-read", `/Groups/${groupName}`, "GroupMembership"]),
        execLookup(execFileAsync, MACOS_GROUP_LOOKUP, [".", "-list", "/Users", "PrimaryGroupID"]),
      ]);
      const supplementaryNames = membership.error ? undefined : parseDsclGroupMembership(membership.stdout);
      const primaryNames = primaryUsers.error ? undefined : parseDsclPrimaryGroupList(primaryUsers.stdout, numericGid);
      if (!supplementaryNames || !primaryNames) result = { error: "group_membership_unresolvable" };
      else {
        const names = [...new Set([...supplementaryNames, ...primaryNames])];
        const uidResults = await Promise.all(names.map((name) => execLookup(execFileAsync, MACOS_UID_LOOKUP, ["-u", name])));
        const uids = uidResults.map((entry) => entry.error ? undefined : asUid(entry.stdout)).filter((uid) => uid !== undefined);
        result = uids.length === uidResults.length ? { uids } : { error: "group_membership_unresolvable" };
      }
    }
  } else if (platform === "linux") {
    const group = await execLookup(execFileAsync, LINUX_GROUP_LOOKUP, ["group", String(numericGid)]);
    const parsedGroup = group.error ? undefined : parseGetentGroup(group.stdout, numericGid);
    const passwd = await execLookup(execFileAsync, LINUX_GROUP_LOOKUP, ["passwd"]);
    if (!parsedGroup || passwd.error) result = { error: "group_membership_unresolvable" };
    else result = { uids: [...parseGetentPasswd(passwd.stdout, parsedGroup.members, numericGid)] };
  } else {
    result = { error: "group_membership_unresolvable" };
  }

  cache.groupWriterUids.set(numericGid, result);
  return result;
}

async function inspectTrustedPath(resolvedPath, {
  statFn,
  readFileFn = defaultReadFile,
  expectedUid,
  platform = process.platform,
  operatorTrusted = false,
  groupWriterUidsFn = loadGroupWriterUids,
  groupWriterCache = {},
} = {}) {
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
    const mode = Number(result.stat.mode);
    const ownerWritable = (mode & 0o200) !== 0;
    const groupWritable = (mode & 0o020) !== 0;
    const otherWritable = (mode & 0o002) !== 0;
    const writerUids = [];
    if (ownerWritable) {
      const ownerUid = asUid(result.stat.uid);
      if (ownerUid === undefined) return trustFailure({ resolvedPath, component, reason: "owner_unresolvable", sameUidWritableComponents });
      writerUids.push(ownerUid);
    }
    if (groupWritable) {
      const groupResult = await groupWriterUidsFn(result.stat.gid, {
        platform,
        cache: groupWriterCache,
      });
      if (!groupResult || groupResult.error || !Array.isArray(groupResult.uids)) {
        return trustFailure({ resolvedPath, component, reason: groupResult?.error ?? "group_membership_unresolvable", sameUidWritableComponents, writerUids });
      }
      writerUids.push(...groupResult.uids);
    }
    const uniqueWriterUids = [...new Set(writerUids)];
    if (otherWritable || uniqueWriterUids.some((uid) => uid !== 0 && uid !== expectedUid)) {
      return trustFailure({
        resolvedPath,
        component,
        reason: otherWritable ? "everyone_writable" : "writer_set_not_subset_allowed",
        sameUidWritableComponents,
        writerUids: uniqueWriterUids,
      });
    }
    if (ownerWritable && Number(result.stat.uid) === expectedUid) {
      sameUidWritableComponents.push(component);
    }
  }

  let contents;
  try {
    contents = await readFileFn(resolvedPath, { encoding: "utf8" });
  } catch {
    return trustFailure({ resolvedPath, component: resolvedPath, reason: "script_probe_failed", sameUidWritableComponents });
  }
  if (String(contents).startsWith("#!")) {
    return trustFailure({ resolvedPath, component: resolvedPath, reason: "shell_wrapper_not_allowed", sameUidWritableComponents });
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
 * normal candidate is accepted only when the executable and every directory up to / has an
 * effective writer set contained in {root, daemon UID}. Owner/group write bits are expanded to
 * actual UIDs; world-write, unresolved membership, and shell wrappers fail closed. Same-UID owner
 * writability is intentionally accepted and recorded in same_uid_writable_components.
 */
export async function resolveCollectorBinary(binary, {
  platform = process.platform,
  statFn = defaultStat,
  realpathFn = defaultRealpath,
  expectedUid = typeof process.getuid === "function" ? process.getuid() : undefined,
  trustedBinaryPaths = [],
  homeDir,
  username,
  readFileFn = defaultReadFile,
  groupWriterUidsFn = loadGroupWriterUids,
  groupWriterCache = {},
  execFileAsync = execFileAsyncDefault,
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
    const inspected = await inspectTrustedPath(real.path, {
      statFn,
      readFileFn,
      expectedUid,
      platform,
      operatorTrusted,
      groupWriterUidsFn,
      groupWriterCache,
      execFileAsync,
    });
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
