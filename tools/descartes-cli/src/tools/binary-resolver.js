import { readFile as defaultReadFile, realpath as defaultRealpath, stat as defaultStat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsyncDefault = promisify(execFile);
const MACOS_LS = "/bin/ls";
const MACOS_DSCL = "/usr/bin/dscl";
const LINUX_XATTR_COMMANDS = ["/usr/bin/getfattr", "/bin/getfattr"];
const LINUX_NSSWITCH = "/etc/nsswitch.conf";
const LINUX_GROUP = "/etc/group";
const LINUX_PASSWD = "/etc/passwd";

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

function parseDsclAttribute(stdout, attribute) {
  const prefix = `${attribute}:`;
  const line = String(stdout ?? "").split(/\r?\n/).find((candidate) => candidate.trim().startsWith(prefix));
  if (!line) return undefined;
  return line.trim().slice(prefix.length).trim();
}

export function parseDsclGroupMembership(stdout) {
  const value = parseDsclAttribute(stdout, "GroupMembership");
  return value === undefined ? undefined : value.split(/\s+/).filter(Boolean);
}

export function parseDsclPrimaryGroupList(stdout, gid) {
  return String(stdout ?? "").split(/\r?\n/).flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length >= 2 && fields.at(-1) === String(gid) ? [fields[0]] : [];
  });
}

export function parseDsclGroupList(stdout, gid) {
  const matches = String(stdout ?? "").split(/\r?\n/).flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length >= 2 && fields.at(-1) === String(gid) ? [fields[0]] : [];
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function parseDsclUniqueId(stdout) {
  return asUid(parseDsclAttribute(stdout, "UniqueID") ?? String(stdout ?? "").trim());
}

function parseMacOsNode(stdout) {
  return parseDsclAttribute(stdout, "AppleMetaNodeLocation");
}

function parseMacOsNestedGroups(stdout) {
  const value = parseDsclAttribute(stdout, "NestedGroups");
  return value === undefined ? [] : value.split(/\s+/).filter(Boolean);
}

function isLocalMacOsNode(node) {
  return node === undefined || node === "/Local/Default" || node === "local";
}

function validLocalRecordName(name) {
  return typeof name === "string" && name.length > 0 && !/[\0/\s]/.test(name);
}

export function parseLinuxNsswitchGroupSources(stdout) {
  const line = String(stdout ?? "").split(/\r?\n/).map((candidate) => candidate.replace(/#.*/, "").trim())
    .find((candidate) => /^group\s*:/.test(candidate));
  if (!line) return undefined;
  return line.slice(line.indexOf(":") + 1).trim().split(/\s+/).filter((token) => token && !/^\[.*\]$/.test(token));
}

function parseLinuxGroupFile(stdout, gid) {
  const matches = [];
  for (const rawLine of String(stdout ?? "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(":");
    if (fields.length < 4 || !fields[0] || asUid(fields[2]) === undefined) {
      if (fields.length >= 3 && asUid(fields[2]) === gid) return undefined;
      continue;
    }
    if (asUid(fields[2]) !== gid) continue;
    const members = fields[3] ? fields[3].split(",").filter(Boolean) : [];
    if (members.some((member) => !validLocalRecordName(member))) return undefined;
    matches.push({ name: fields[0], members });
  }
  return matches.length === 1 ? matches[0] : undefined;
}

function parseLinuxPasswdFile(stdout, gid) {
  const users = new Map();
  for (const rawLine of String(stdout ?? "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(":");
    if (fields.length < 7 || !validLocalRecordName(fields[0])) return undefined;
    const uid = asUid(fields[2]);
    const primaryGid = asUid(fields[3]);
    if (uid === undefined || primaryGid === undefined || users.has(fields[0])) return undefined;
    users.set(fields[0], { uid, primary: primaryGid === gid });
  }
  return users;
}

function hasNonLocalLinuxGroupSource(sources) {
  return !Array.isArray(sources) || sources.length === 0 || sources.some((source) => source !== "files");
}

async function execLookup(execFileAsync, command, args) {
  try {
    const result = await execFileAsync(command, args, { timeout: 2000, maxBuffer: 256 * 1024 });
    return { stdout: result.stdout ?? "" };
  } catch (error) {
    return { error };
  }
}

async function readLocalText(readLocalFileFn, target) {
  try {
    const value = await readLocalFileFn(target, { encoding: "utf8" });
    return { text: String(value) };
  } catch (error) {
    return { error };
  }
}

function unresolvedGroupMembership() {
  return { error: "group_membership_unverifiable" };
}

async function loadMacOsGroupWriterUids(gid, { execFileAsync }) {
  const numericGid = asUid(gid);
  if (numericGid === undefined) return unresolvedGroupMembership();

  const groupList = await execLookup(execFileAsync, MACOS_DSCL, [".", "-list", "/Groups", "PrimaryGroupID"]);
  const groupName = groupList.error ? undefined : parseDsclGroupList(groupList.stdout, numericGid);
  if (!groupName || !validLocalRecordName(groupName)) return unresolvedGroupMembership();

  const fullRecord = await execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Groups/${groupName}`]);
  if (fullRecord.error || !isLocalMacOsNode(parseMacOsNode(fullRecord.stdout)) || parseMacOsNestedGroups(fullRecord.stdout).length > 0) {
    return unresolvedGroupMembership();
  }

  const [membership, primaryUsers] = await Promise.all([
    execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Groups/${groupName}`, "GroupMembership"]),
    execLookup(execFileAsync, MACOS_DSCL, [".", "-list", "/Users", "PrimaryGroupID"]),
  ]);
  const supplementaryNames = membership.error ? undefined : parseDsclGroupMembership(membership.stdout);
  if (!supplementaryNames || primaryUsers.error) return unresolvedGroupMembership();
  const primaryNames = parseDsclPrimaryGroupList(primaryUsers.stdout, numericGid);
  const names = [...new Set([...supplementaryNames, ...primaryNames])];
  if (names.some((name) => !validLocalRecordName(name))) return unresolvedGroupMembership();

  const uidResults = await Promise.all(names.map((name) => execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Users/${name}`, "UniqueID"])));
  const uids = uidResults.map((result) => result.error ? undefined : parseDsclUniqueId(result.stdout));
  return uids.every((uid) => uid !== undefined) ? { uids } : unresolvedGroupMembership();
}

async function loadLinuxGroupWriterUids(gid, { readLocalFileFn }) {
  const numericGid = asUid(gid);
  if (numericGid === undefined) return unresolvedGroupMembership();
  const [nsswitch, groupFile, passwdFile] = await Promise.all([
    readLocalText(readLocalFileFn, LINUX_NSSWITCH),
    readLocalText(readLocalFileFn, LINUX_GROUP),
    readLocalText(readLocalFileFn, LINUX_PASSWD),
  ]);
  if (nsswitch.error || groupFile.error || passwdFile.error) return unresolvedGroupMembership();
  const sources = parseLinuxNsswitchGroupSources(nsswitch.text);
  if (hasNonLocalLinuxGroupSource(sources)) return unresolvedGroupMembership();
  const group = parseLinuxGroupFile(groupFile.text, numericGid);
  const users = parseLinuxPasswdFile(passwdFile.text, numericGid);
  if (!group || !users) return unresolvedGroupMembership();

  const names = [...new Set([...group.members, ...[...users.entries()].filter(([, user]) => user.primary).map(([name]) => name)])];
  if (names.some((name) => !users.has(name))) return unresolvedGroupMembership();
  return { uids: names.map((name) => users.get(name).uid) };
}

async function loadGroupWriterUids(gid, {
  platform,
  cache = {},
  execFileAsync = execFileAsyncDefault,
  readLocalFileFn = defaultReadFile,
} = {}) {
  const numericGid = asUid(gid);
  if (numericGid === undefined) return unresolvedGroupMembership();
  cache.groupWriterUids ??= new Map();
  if (cache.groupWriterUids.has(numericGid)) return cache.groupWriterUids.get(numericGid);

  const result = platform === "darwin"
    ? await loadMacOsGroupWriterUids(numericGid, { execFileAsync })
    : platform === "linux"
      ? await loadLinuxGroupWriterUids(numericGid, { readLocalFileFn })
      : unresolvedGroupMembership();
  cache.groupWriterUids.set(numericGid, result);
  return result;
}

function normalizeAclStatus(result) {
  const status = typeof result === "string" ? result : result?.status;
  return status === "present" || status === "absent" ? status : "unknown";
}

export function parseMacOsAclStatus(stdout) {
  const lines = String(stdout ?? "").split(/\r?\n/);
  const firstLineIndex = lines.findIndex((candidate) => candidate.trim());
  const line = firstLineIndex === -1 ? undefined : lines[firstLineIndex];
  if (!line) return "unknown";
  const mode = line.trim().split(/\s+/)[0];
  const match = /^([bcdlps-][rwxXsStT-]{9})([+@])?$/.exec(mode);
  if (!match) return "unknown";
  if (match[2] !== "+") return "absent";

  // `ls -led` prints one numbered ACE per line after the mode line. A `+` without
  // an ACE is not a trustworthy ACL observation, so retain the fail-closed result
  // for truncated or otherwise malformed command output.
  const aceLines = lines
    .slice(firstLineIndex + 1)
    .map((candidate) => candidate.trim())
    .filter(Boolean);
  return aceLines.length > 0 && aceLines.every((candidate) => /^\d+:\s+\S+\s+(?:allow|deny)\b/.test(candidate))
    ? "present"
    : "unknown";
}

async function detectAclStatus(component, { platform, execFileAsync = execFileAsyncDefault } = {}) {
  if (platform === "darwin") {
    const result = await execLookup(execFileAsync, MACOS_LS, ["-led", component]);
    return result.error ? "unknown" : parseMacOsAclStatus(result.stdout);
  }
  if (platform === "linux") {
    for (const command of LINUX_XATTR_COMMANDS) {
      const result = await execLookup(execFileAsync, command, ["--only-values", "--name=system.posix_acl_access", "--absolute-names", component]);
      if (!result.error) return "present";
      if (result.error.code === "ENOENT") continue;
      // getfattr uses exit status 1 for a missing xattr. Other failures mean that the
      // filesystem's ACL state was not established and must not be trusted.
      if (result.error.code === 1 || /no such attribute/i.test(String(result.error.stderr ?? ""))) return "absent";
      return "unknown";
    }
  }
  return "unknown";
}

async function inspectTrustedPath(resolvedPath, {
  statFn,
  readFileFn = defaultReadFile,
  expectedUid,
  platform = process.platform,
  operatorTrusted = false,
  groupWriterUidsFn = loadGroupWriterUids,
  groupWriterCache = {},
  readLocalFileFn = defaultReadFile,
  aclCheckFn = detectAclStatus,
  execFileAsync = execFileAsyncDefault,
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
    const ownerUid = asUid(result.stat.uid);
    if (ownerUid !== 0 && ownerUid !== expectedUid) {
      return trustFailure({ resolvedPath, component, reason: "foreign_owner", sameUidWritableComponents });
    }
    const mode = Number(result.stat.mode);
    let writerUids = [];
    if ((mode & 0o020) !== 0) {
      const groupResult = await groupWriterUidsFn(result.stat.gid, {
        platform,
        cache: groupWriterCache,
        execFileAsync,
        readLocalFileFn,
      });
      if (!groupResult || groupResult.error || !Array.isArray(groupResult.uids)) {
        return trustFailure({ resolvedPath, component, reason: groupResult?.error ?? "group_membership_unverifiable", sameUidWritableComponents, writerUids });
      }
      writerUids = [...new Set(groupResult.uids)];
      const allowed = writerUids.every((uid) => uid === 0 || (expectedUid !== undefined && uid === expectedUid));
      if (!allowed) {
        return trustFailure({ resolvedPath, component, reason: "writer_set_not_subset_allowed", sameUidWritableComponents, writerUids });
      }
    }
    if ((mode & 0o002) !== 0) {
      return trustFailure({ resolvedPath, component, reason: "other_writable", sameUidWritableComponents, writerUids });
    }
    const aclStatus = normalizeAclStatus(await aclCheckFn(component, { platform, stat: result.stat, execFileAsync }));
    if (aclStatus !== "absent") {
      return trustFailure({ resolvedPath, component, reason: aclStatus === "present" ? "acl_present" : "acl_unknown", sameUidWritableComponents, writerUids });
    }
    if ((mode & 0o200) !== 0 && ownerUid === expectedUid) {
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
 * normal candidate is accepted only when the executable and every directory up to / is owned by
 * root or the daemon UID, has no other-write bit, has no extended ACL, and any group-writable
 * component's locally resolved effective member set is contained in {root, daemon UID}. Group
 * membership is read from local platform sources only and is cached for the caller's tick. ACL
 * uncertainty, foreign ownership, unresolved membership, and write bits fail closed. Same-UID
 * owner writability is intentionally accepted and recorded in same_uid_writable_components.
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
  readLocalFileFn = defaultReadFile,
  groupWriterUidsFn = loadGroupWriterUids,
  groupWriterCache = {},
  execFileAsync = execFileAsyncDefault,
  aclCheckFn = detectAclStatus,
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
      readLocalFileFn,
      execFileAsync,
      aclCheckFn,
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
    ...(binary?.operator_override_hint ? { operator_override_hint: binary.operator_override_hint } : {}),
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
