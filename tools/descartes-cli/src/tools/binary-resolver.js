import {
  mkdir as defaultMkdir,
  readFile as defaultReadFile,
  realpath as defaultRealpath,
  rename as defaultRename,
  stat as defaultStat,
  writeFile as defaultWriteFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsyncDefault = promisify(execFile);
const MACOS_LS = "/bin/ls";
const MACOS_DSCL = "/usr/bin/dscl";
const LINUX_XATTR_COMMANDS = ["/usr/bin/getfattr", "/bin/getfattr"];
const LINUX_ACL_ATTRIBUTES = ["system.posix_acl_access", "system.posix_acl_default"];

export const NOT_FOUND_ON_KNOWN_PATHS = "not_found_on_known_paths";
export const UNTRUSTED_BINARY = "untrusted_binary";

export const MAX_CONTENT_PIN_ENTRIES = 256;
export const CONTENT_PIN_SCHEMA_VERSION = 1;
export const CONTENT_PIN_STORE_NAME = "binary-content-pins.json";

export const KNOWN_COLLECTOR_BINARIES = Object.freeze([
  "VBoxManage", "codesign", "colima", "container", "crontab", "df", "docker", "id", "incus",
  "ip", "journalctl", "launchctl", "limactl", "log", "lsof", "lxc", "multipass", "netstat",
  "ntpq", "plutil", "podman", "prlctl", "ps", "qm", "route", "scutil", "screen",
  "sntp", "spctl", "ss", "sestatus", "sysctl", "systemctl", "systemsetup", "tail", "tart",
  "tailscale", "timedatectl", "tmux", "virsh", "vmrun", "wg", "who", "xl",
]);

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

function trustFailure({ resolvedPath, component, reason, sameUidWritableComponents = [], writerUids = [], acceptedSystemAccounts = [] }) {
  return {
    status: UNTRUSTED_BINARY,
    path: undefined,
    resolved_path: resolvedPath,
    trust_verdict: UNTRUSTED_BINARY,
    offending_component: component,
    trust_reason: reason,
    same_uid_writable_components: sameUidWritableComponents,
    writer_uids: writerUids,
    accepted_system_accounts: acceptedSystemAccounts,
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

function dsclAttributeEvidence(stdout, attribute) {
  const lines = String(stdout ?? "").split(/\r?\n/).map((line) => line.trim());
  const prefix = `${attribute}:`;
  const valueLine = lines.find((line) => line.startsWith(prefix));
  const explicitAbsent = lines.some((line) => line === `No such key: ${attribute}`);
  return {
    present: valueLine !== undefined,
    explicitAbsent,
    value: valueLine === undefined ? undefined : valueLine.slice(prefix.length).trim(),
  };
}

function parseDsclAttributes(stdout, attribute) {
  const prefix = `${attribute}:`;
  return String(stdout ?? "").split(/\r?\n/)
    .filter((candidate) => candidate.trim().startsWith(prefix))
    .map((candidate) => candidate.trim().slice(prefix.length).trim());
}

export function parseDsclGroupMembership(stdout) {
  const evidence = dsclAttributeEvidence(stdout, "GroupMembership");
  if (evidence.present) return evidence.value.split(/\s+/).filter(Boolean);
  return evidence.explicitAbsent ? [] : undefined;
}

export function parseDsclPrimaryGroupList(stdout, gid) {
  const lines = String(stdout ?? "").split(/\r?\n/).filter((line) => line.trim());
  if (lines.length === 0) return undefined;
  if (lines.every((line) => line.trim() === "No such key: PrimaryGroupID")) return undefined;
  if (lines.some((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length < 2 || !/^-?\d+$/.test(fields.at(-1));
  })) return undefined;
  return lines.flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length >= 2 && fields.at(-1) === String(gid) ? [fields[0]] : [];
  });
}

export function parseDsclGroupList(stdout, gid) {
  const lines = String(stdout ?? "").split(/\r?\n/).filter((line) => line.trim());
  if (lines.some((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length < 2 || !/^-?\d+$/.test(fields.at(-1));
  })) return undefined;
  const matches = lines.flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    return fields.length >= 2 && fields.at(-1) === String(gid) ? [fields[0]] : [];
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function parseDsclUniqueId(stdout) {
  return asUid(dsclAttributeEvidence(stdout, "UniqueID").value);
}

function parseMacOsNode(stdout) {
  return parseDsclAttribute(stdout, "AppleMetaNodeLocation");
}

function parseMacOsNestedGroups(stdout) {
  const value = parseDsclAttribute(stdout, "NestedGroups");
  return value === undefined ? [] : value.split(/\s+/).filter(Boolean);
}

export function parseMacOsSearchPath(stdout) {
  const lines = String(stdout ?? "").split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim().startsWith("CSPSearchPath:"));
  if (start < 0) return undefined;
  const first = lines[start].trim().slice("CSPSearchPath:".length).trim();
  const paths = first ? first.split(/\s+/) : [];
  for (const line of lines.slice(start + 1)) {
    const value = line.trim();
    if (!value) continue;
    if (!value.startsWith("/")) break;
    paths.push(value);
  }
  return paths;
}

function localAuthenticationSearchPolicy(stdout) {
  const paths = parseMacOsSearchPath(stdout);
  return Array.isArray(paths)
    && paths.length > 0
    && paths.includes("/Local/Default")
    && paths.every((value) => value === "/Local/Default" || value === "/BSD/local");
}

function isLocalMacOsNode(node) {
  return node === undefined || node === "/Local/Default" || node === "local";
}

function validLocalRecordName(name) {
  return typeof name === "string" && name.length > 0 && !/[\0/\s]/.test(name);
}

function parseDsclGroupMembers(stdout) {
  const evidence = dsclAttributeEvidence(stdout, "GroupMembers");
  if (evidence.present) return evidence.value.split(/\s+/).filter(Boolean);
  return evidence.explicitAbsent ? [] : undefined;
}

function parseDsclSearchUser(stdout, guid) {
  const lines = String(stdout ?? "").split(/\r?\n/);
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    const compact = /^(\S+)\s+GeneratedUID:\s*(\S+)\s*$/.exec(line);
    if (compact && compact[2] === guid) {
      matches.push(compact[1]);
      continue;
    }
    const multiline = /^(\S+)\s+GeneratedUID\s*=\s*\(\s*$/.exec(line);
    if (!multiline) continue;
    const quotedGuid = lines.slice(index + 1).map((candidate) => candidate.trim()).find((candidate) => /^"[^"]+"$/.test(candidate));
    if (quotedGuid === `"${guid}"`) matches.push(multiline[1]);
  }
  return matches.length === 1 && validLocalRecordName(matches[0]) ? matches[0] : undefined;
}

function onlyDisabledUserAuthorities(authorities) {
  return authorities.length === 0 || authorities.every((value) => /^(?:;DisabledUser;)(?:\s+;DisabledUser;)*$/.test(value.trim()));
}

async function execLookup(execFileAsync, command, args) {
  try {
    const result = await execFileAsync(command, args, { timeout: 5000, maxBuffer: 256 * 1024 });
    return { stdout: result.stdout ?? "" };
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

  const searchPolicy = await execLookup(execFileAsync, MACOS_DSCL, ["/Search", "-read", "/", "CSPSearchPath"]);
  if (searchPolicy.error || !localAuthenticationSearchPolicy(searchPolicy.stdout)) {
    return { error: "directory_bound" };
  }

  const groupList = await execLookup(execFileAsync, MACOS_DSCL, [".", "-list", "/Groups", "PrimaryGroupID"]);
  const groupName = groupList.error ? undefined : parseDsclGroupList(groupList.stdout, numericGid);
  if (!groupName || !validLocalRecordName(groupName)) return unresolvedGroupMembership();

  const fullRecord = await execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Groups/${groupName}`]);
  if (fullRecord.error || !isLocalMacOsNode(parseMacOsNode(fullRecord.stdout)) || parseMacOsNestedGroups(fullRecord.stdout).length > 0) {
    return unresolvedGroupMembership();
  }
  const fullMembership = parseDsclGroupMembership(fullRecord.stdout);
  if (!fullMembership) return unresolvedGroupMembership();
  // ACCEPTED RESIDUAL: a former member of any accepted component group can retain that group's GID in processes started before removal; multi-admin or directory-bound Macs fail closed.
  const groupGuids = parseDsclGroupMembers(fullRecord.stdout);
  if (!groupGuids) return unresolvedGroupMembership();
  const guidNames = await Promise.all(groupGuids.map(async (guid) => {
    const result = await execLookup(execFileAsync, MACOS_DSCL, [".", "-search", "/Users", "GeneratedUID", guid]);
    return result.error ? undefined : parseDsclSearchUser(result.stdout, guid);
  }));
  if (guidNames.some((name) => name === undefined)) return unresolvedGroupMembership();

  const [membership, primaryUsers] = await Promise.all([
    execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Groups/${groupName}`, "GroupMembership"]),
    execLookup(execFileAsync, MACOS_DSCL, [".", "-list", "/Users", "PrimaryGroupID"]),
  ]);
  if (membership.error) return unresolvedGroupMembership();
  const supplementaryNames = parseDsclGroupMembership(membership.stdout);
  if (!supplementaryNames || primaryUsers.error) return unresolvedGroupMembership();
  if (supplementaryNames.join("\u0000") !== fullMembership.join("\u0000")) return unresolvedGroupMembership();
  const primaryNames = parseDsclPrimaryGroupList(primaryUsers.stdout, numericGid);
  if (!primaryNames) return unresolvedGroupMembership();
  const names = [...new Set([...(supplementaryNames ?? []), ...guidNames, ...primaryNames])];
  if (names.some((name) => !validLocalRecordName(name))) return unresolvedGroupMembership();

  const userResults = await Promise.all(names.map((name) => execLookup(execFileAsync, MACOS_DSCL, [".", "-read", `/Users/${name}`, "AuthenticationAuthority", "UniqueID"])));
  const principals = userResults.map((result, index) => {
    if (result.error) return undefined;
    const uid = parseDsclUniqueId(result.stdout);
    if (uid === undefined) return undefined;
    const authenticationAuthority = dsclAttributeEvidence(result.stdout, "AuthenticationAuthority");
    // A missing AuthenticationAuthority line is not evidence that the account is disabled.
    // Only dscl's explicit "No such key" response proves that the attribute is absent.
    if (!authenticationAuthority.present && !authenticationAuthority.explicitAbsent) return undefined;
    const authenticationAuthorities = authenticationAuthority.present
      ? parseDsclAttributes(result.stdout, "AuthenticationAuthority")
      : [];
    return {
      name: names[index],
      uid,
      authentication_authorities: authenticationAuthorities,
      authenticating: !onlyDisabledUserAuthorities(authenticationAuthorities),
    };
  });
  if (principals.some((principal) => principal === undefined)) return unresolvedGroupMembership();

  const acceptedSystemAccounts = principals
    .filter((principal) => principal.uid > 0 && principal.uid < 501 && !principal.authenticating)
    .map(({ name, uid }) => ({ name, uid }));
  return {
    uids: principals.map((principal) => principal.uid),
    principals,
    acceptedSystemAccounts,
  };
}

async function loadGroupWriterUids(gid, {
  platform,
  cache = {},
  execFileAsync = execFileAsyncDefault,
} = {}) {
  const numericGid = asUid(gid);
  if (numericGid === undefined) return unresolvedGroupMembership();
  cache.groupWriterUids ??= new Map();
  if (cache.groupWriterUids.has(numericGid)) return cache.groupWriterUids.get(numericGid);

  const result = platform === "darwin"
    ? await loadMacOsGroupWriterUids(numericGid, { execFileAsync })
    : unresolvedGroupMembership();
  cache.groupWriterUids.set(numericGid, result);
  return result;
}

function normalizeAclStatus(result) {
  const status = typeof result === "string" ? result : result?.status;
  return status === "present" || status === "absent" ? status : "unknown";
}

function contentIdentity(stat) {
  if (stat?.dev === undefined || stat?.ino === undefined) return undefined;
  return `${String(stat.dev)}:${String(stat.ino)}`;
}

function cachedContentHash(cache, identity) {
  if (!identity) return undefined;
  return cache instanceof Map ? cache.get(identity) : cache?.[identity];
}

function saveContentHash(cache, identity, value) {
  if (!identity) return;
  if (cache instanceof Map) cache.set(identity, value);
  else if (cache && typeof cache === "object") cache[identity] = value;
}

export function resolveBinaryContentPinStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "daemon");
  return { dir, file: path.join(dir, CONTENT_PIN_STORE_NAME) };
}

function normalizeContentPin(value) {
  if (!value || typeof value !== "object" || !/^[0-9a-f]{64}$/.test(String(value.sha256 ?? value.hash ?? ""))) return undefined;
  return {
    size: value.size ?? null,
    mtime: value.mtime ?? null,
    sha256: String(value.sha256 ?? value.hash),
  };
}

function contentPinEntries(cache) {
  if (cache instanceof Map) return [...cache.entries()];
  if (!cache || typeof cache !== "object") return [];
  return Object.entries(cache);
}

async function presentContentPinIdentities({
  platform,
  trustedBinaryPaths,
  homeDir,
  username,
  binaries,
  realpathFn,
  statFn,
}) {
  const present = new Set();
  for (const binary of binaries ?? []) {
    for (const candidate of candidatePaths(binary, platform, { trustedBinaryPaths, homeDir, username })) {
      const real = await safeRealpath(realpathFn, candidate);
      if (!real.path) continue;
      const result = await safeStat(statFn, real.path);
      // Retain a pin for any inode that is still present at a known candidate, even if a
      // transient mode change makes it non-executable. Dropping it in that state would allow
      // the same inode to be re-pinned after executability is restored.
      if (result.stat) {
        const identity = contentIdentity(result.stat);
        if (identity) present.add(identity);
      }
    }
  }
  return present;
}

export async function loadContentHashCache(descartesPaths, {
  platform = process.platform,
  trustedBinaryPaths = [],
  homeDir,
  username,
  binaries = KNOWN_COLLECTOR_BINARIES,
  maxEntries = MAX_CONTENT_PIN_ENTRIES,
  realpathFn = defaultRealpath,
  statFn = defaultStat,
} = {}) {
  const cache = new Map();
  const { file } = resolveBinaryContentPinStorePaths(descartesPaths);
  try {
    const parsed = JSON.parse(await defaultReadFile(file, "utf8"));
    if (parsed?.version !== CONTENT_PIN_SCHEMA_VERSION || !parsed?.pins || typeof parsed.pins !== "object") return cache;
    for (const [identity, value] of Object.entries(parsed.pins).slice(-maxEntries)) {
      const pin = normalizeContentPin(value);
      if (pin && /^.+:.+$/.test(identity)) cache.set(identity, pin);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") return cache;
  }

  const present = await presentContentPinIdentities({
    platform,
    trustedBinaryPaths,
    homeDir,
    username,
    binaries,
    realpathFn,
    statFn,
  });
  for (const identity of cache.keys()) {
    if (!present.has(identity)) cache.delete(identity);
  }
  return cache;
}

export async function persistContentHashCache(descartesPaths, cache, { maxEntries = MAX_CONTENT_PIN_ENTRIES } = {}) {
  const { dir, file } = resolveBinaryContentPinStorePaths(descartesPaths);
  const entries = contentPinEntries(cache)
    .map(([identity, value]) => [identity, normalizeContentPin(value)])
    .filter(([, value]) => value !== undefined)
    .slice(-maxEntries);
  await defaultMkdir(dir, { recursive: true, mode: 0o700 });
  const tempFile = `${file}.${process.pid}.tmp`;
  await defaultWriteFile(tempFile, JSON.stringify({ version: CONTENT_PIN_SCHEMA_VERSION, pins: Object.fromEntries(entries) }, null, 2), { mode: 0o600 });
  await defaultRename(tempFile, file);
}

async function readAndRecordContent(readFileFn, resolvedPath, stat, contentHashCache) {
  const identity = contentIdentity(stat);
  if (!identity) return { error: "content_identity_unavailable" };
  let contents;
  try {
    contents = await readFileFn(resolvedPath);
  } catch {
    return { error: "content_read_failed" };
  }
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(String(contents));
  const hash = createHash("sha256").update(bytes).digest("hex");
  const previous = cachedContentHash(contentHashCache, identity);
  if (previous && (previous.sha256 ?? previous.hash) !== hash) return { error: "content_changed_in_place" };
  saveContentHash(contentHashCache, identity, {
    size: stat?.size,
    mtime: stat?.mtimeMs ?? stat?.mtimeNs,
    sha256: hash,
  });
  return { contents, hash };
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

export async function detectAclStatus(component, { platform, stat, execFileAsync = execFileAsyncDefault } = {}) {
  if (platform === "darwin") {
    const result = await execLookup(execFileAsync, MACOS_LS, ["-led", component]);
    return result.error ? "unknown" : parseMacOsAclStatus(result.stdout);
  }
  if (platform === "linux") {
    const attributes = stat?.isDirectory?.()
      ? LINUX_ACL_ATTRIBUTES
      : [LINUX_ACL_ATTRIBUTES[0]];
    for (const command of LINUX_XATTR_COMMANDS) {
      let commandUnavailable = true;
      for (const attribute of attributes) {
        const result = await execLookup(execFileAsync, command, ["--only-values", `--name=${attribute}`, "--absolute-names", component]);
        if (!result.error) return "present";
        if (result.error.code === "ENOENT") continue;
        commandUnavailable = false;
        // A missing attribute is the only trustworthy proof that no ACL is present. In
        // particular, getfattr's exit status 1 is ambiguous unless its stderr identifies the
        // requested attribute as absent; permission, unsupported-filesystem, and other errors
        // must remain unknown and therefore untrusted.
        if (result.error.code === "ENODATA" || /no such attribute/i.test(String(result.error.stderr ?? ""))) continue;
        return "unknown";
      }
      if (!commandUnavailable) return "absent";
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
  contentHashCache,
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
    const content = await readAndRecordContent(readFileFn, resolvedPath, fileResult.stat, contentHashCache);
    if (content.error) return trustFailure({ resolvedPath, component: resolvedPath, reason: content.error });
    return {
      status: "resolved",
      path: resolvedPath,
      resolved_path: resolvedPath,
      trust_verdict: "operator_trusted",
      same_uid_writable_components: [],
      file_stat: fileResult.stat,
      content_hash: content.hash,
    };
  }

  const components = [resolvedPath, ...ancestorPaths(resolvedPath)];
  const sameUidWritableComponents = [];
  const acceptedSystemAccounts = [];
  for (const component of components) {
    const result = component === resolvedPath ? fileResult : await safeStat(statFn, component);
    if (!result.stat) return trustFailure({ resolvedPath, component, reason: "stat_failed", sameUidWritableComponents, acceptedSystemAccounts });
    if (component !== resolvedPath && !result.stat.isDirectory?.()) {
      return trustFailure({ resolvedPath, component, reason: "not_directory", sameUidWritableComponents, acceptedSystemAccounts });
    }
    const ownerUid = asUid(result.stat.uid);
    if (ownerUid !== 0 && ownerUid !== expectedUid) {
      return trustFailure({ resolvedPath, component, reason: "foreign_owner", sameUidWritableComponents, acceptedSystemAccounts });
    }
    const mode = Number(result.stat.mode);
    let writerUids = [];
    if ((mode & 0o020) !== 0 && platform === "linux") {
      return trustFailure({ resolvedPath, component, reason: "group_writable", sameUidWritableComponents, writerUids, acceptedSystemAccounts });
    }
    if ((mode & 0o020) !== 0) {
      const groupResult = await groupWriterUidsFn(result.stat.gid, {
        platform,
        cache: groupWriterCache,
        execFileAsync,
      });
      if (!groupResult || groupResult.error || !Array.isArray(groupResult.uids)) {
        return trustFailure({ resolvedPath, component, reason: groupResult?.error ?? "group_membership_unverifiable", sameUidWritableComponents, writerUids, acceptedSystemAccounts });
      }
      writerUids = [...new Set(groupResult.uids)];
      for (const account of groupResult.acceptedSystemAccounts ?? []) {
        if (!acceptedSystemAccounts.some((existing) => existing.name === account.name && existing.uid === account.uid)) {
          acceptedSystemAccounts.push(account);
        }
      }
      const principals = groupResult.principals ?? writerUids.map((uid) => ({ uid }));
      const allowed = principals.every((principal) => principal.uid === 0
        || (expectedUid !== undefined && principal.uid === expectedUid)
        || (platform === "darwin" && principal.uid > 0 && principal.uid < 501 && !principal.authenticating));
      if (!allowed) {
        return trustFailure({ resolvedPath, component, reason: "writer_set_not_subset_allowed", sameUidWritableComponents, writerUids, acceptedSystemAccounts });
      }
    }
    if ((mode & 0o002) !== 0) {
      return trustFailure({ resolvedPath, component, reason: "group_writable", sameUidWritableComponents, writerUids, acceptedSystemAccounts });
    }
    const aclStatus = normalizeAclStatus(await aclCheckFn(component, { platform, stat: result.stat, execFileAsync }));
    if (aclStatus !== "absent") {
      return trustFailure({ resolvedPath, component, reason: aclStatus === "present" ? "acl_present" : "acl_unknown", sameUidWritableComponents, writerUids, acceptedSystemAccounts });
    }
    if ((mode & 0o200) !== 0 && ownerUid === expectedUid) {
      sameUidWritableComponents.push(component);
    }
  }

  const content = await readAndRecordContent(readFileFn, resolvedPath, fileResult.stat, contentHashCache);
  if (content.error) {
    return trustFailure({ resolvedPath, component: resolvedPath, reason: content.error === "content_read_failed" ? "script_probe_failed" : content.error, sameUidWritableComponents, acceptedSystemAccounts });
  }
  if (String(content.contents).startsWith("#!")) {
    return trustFailure({ resolvedPath, component: resolvedPath, reason: "shell_wrapper_not_allowed", sameUidWritableComponents, acceptedSystemAccounts });
  }

  return {
    status: "resolved",
    path: resolvedPath,
    resolved_path: resolvedPath,
    trust_verdict: "trusted",
    same_uid_writable_components: sameUidWritableComponents,
    accepted_system_accounts: acceptedSystemAccounts,
    file_stat: fileResult.stat,
    content_hash: content.hash,
  };
}

/**
 * Resolve a collector command without consulting PATH. Candidates are realpath-resolved and a
 * normal candidate is accepted only when the executable and every directory up to / is owned by
 * root or the daemon UID, has no group/other-write bit, and has no extended ACL. Linux rejects
 * group-writable components without consulting account databases. macOS may trust a local group
 * after complete local dscl resolution; low-UID system accounts are accepted only when
 * AuthenticationAuthority is explicitly reported absent by dscl or contains only DisabledUser,
 * and are recorded in provenance.
 * ACL uncertainty, foreign ownership, unresolved membership, and write bits fail closed.
 * Same-UID owner writability is intentionally accepted and recorded in same_uid_writable_components.
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
  contentHashCache,
  execFileAsync = execFileAsyncDefault,
  aclCheckFn = detectAclStatus,
} = {}) {
  const name = String(binary ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) {
    throw new TypeError(`collector binary must be a bare allowlisted name: ${name}`);
  }

  const configuredPaths = new Set(trustedBinaryPaths.filter((candidate) => typeof candidate === "string" && path.isAbsolute(candidate)));
  const candidates = candidatePaths(name, platform, { trustedBinaryPaths, homeDir, username });
  const effectiveContentHashCache = contentHashCache ?? new Map();
  let firstUntrusted;
  let firstResolvedUntrusted;

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
      contentHashCache: effectiveContentHashCache,
      execFileAsync,
      aclCheckFn,
    });
    if (inspected.status === "resolved") {
      return { ...inspected, binary: name, candidates };
    }
    firstResolvedUntrusted ??= { ...inspected, binary: name, candidates };
  }

  if (firstResolvedUntrusted) return firstResolvedUntrusted;
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
    ...(typeof binary?.content_hash === "string" ? { content_hash: binary.content_hash } : {}),
    same_uid_writable_components: binary?.same_uid_writable_components ?? [],
    ...((binary?.accepted_system_accounts?.length ?? 0) > 0
      ? { accepted_system_accounts: binary.accepted_system_accounts }
      : {}),
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
  const content = await readAndRecordContent(
    options.readFileFn ?? defaultReadFile,
    real.path,
    current.stat,
    options.contentHashCache ?? new Map(),
  );
  if (content.error || (resolution.content_hash && content.hash !== resolution.content_hash)) {
    return {
      ...resolution,
      status: UNTRUSTED_BINARY,
      trust_verdict: UNTRUSTED_BINARY,
      trust_reason: content.error ?? "content_changed_in_place",
      offending_component: real.path,
      path: undefined,
    };
  }
  return { ...resolution, path: real.path, resolved_path: real.path, file_stat: current.stat, content_hash: content.hash };
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
