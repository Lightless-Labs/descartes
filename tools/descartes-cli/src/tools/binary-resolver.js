import { stat as defaultStat } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsyncDefault = promisify(execFile);

export const NOT_FOUND_ON_KNOWN_PATHS = "not_found_on_known_paths";

const COMMON_BINARY_DIRECTORIES = Object.freeze([
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  "/run/current-system/sw/bin",
  "/snap/bin",
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

function candidatePaths(binary, platform) {
  const directories = PLATFORM_BINARY_DIRECTORIES[platform] ?? PLATFORM_BINARY_DIRECTORIES.linux;
  const special = platform === "darwin" ? (SPECIAL_BINARY_PATHS[binary] ?? []) : [];
  return [...special, ...directories.map((directory) => path.join(directory, binary))];
}

function isRegularExecutable(statResult) {
  return Boolean(statResult?.isFile?.()) && (Number(statResult.mode) & 0o111) !== 0;
}

function isWorldWritableDirectory(statResult) {
  return Boolean(statResult?.isDirectory?.()) && (Number(statResult.mode) & 0o002) !== 0;
}

async function safeStat(statFn, target) {
  try {
    return await statFn(target);
  } catch {
    return undefined;
  }
}

/**
 * Resolve a collector command without consulting PATH. Only the fixed, platform-specific
 * directories below are searched. A candidate must resolve to a regular executable and its
 * containing directory must not be world-writable.
 */
export async function resolveCollectorBinary(binary, { platform = process.platform, statFn = defaultStat } = {}) {
  const name = String(binary ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) {
    throw new TypeError(`collector binary must be a bare allowlisted name: ${name}`);
  }

  const candidates = candidatePaths(name, platform);
  for (const candidate of candidates) {
    const fileStat = await safeStat(statFn, candidate);
    if (!isRegularExecutable(fileStat)) continue;
    const directoryStat = await safeStat(statFn, path.dirname(candidate));
    if (isWorldWritableDirectory(directoryStat)) continue;
    return { status: "resolved", binary: name, path: candidate, candidates };
  }
  return { status: NOT_FOUND_ON_KNOWN_PATHS, binary: name, path: undefined, candidates };
}

export function binaryAvailability(probe) {
  if (probe?.status === NOT_FOUND_ON_KNOWN_PATHS || probe?.availability === NOT_FOUND_ON_KNOWN_PATHS || probe?.code === "ENOENT" || probe?.code === "NOT_FOUND_ON_KNOWN_PATHS") {
    return NOT_FOUND_ON_KNOWN_PATHS;
  }
  if (probe?.status === "ok") return "resolved";
  return "unable";
}

export function isBinaryNotFound(probe) {
  return binaryAvailability(probe) === NOT_FOUND_ON_KNOWN_PATHS;
}

/**
 * Run a fixed collector command after resolution. The returned command record contains the
 * resolved absolute path, while requested_binary preserves the stable logical command name.
 * `execFileAsync` and `statFn` are injectable for deterministic unit tests.
 */
export async function runResolvedExecFile(binary, args = [], options = {}) {
  const resolution = await resolveCollectorBinary(binary, options);
  const requestedArgv = [binary, ...args];
  if (resolution.status !== "resolved") {
    return {
      status: NOT_FOUND_ON_KNOWN_PATHS,
      code: "NOT_FOUND_ON_KNOWN_PATHS",
      availability: NOT_FOUND_ON_KNOWN_PATHS,
      stdout: "",
      stderr: "",
      error: `${binary} was not found on pinned known paths`,
      command: { argv: requestedArgv, requested_binary: binary, read_only: true },
      binary: resolution,
    };
  }

  const execFileAsync = options.execFileAsync ?? execFileAsyncDefault;
  const command = { argv: [resolution.path, ...args], requested_binary: binary, read_only: true };
  try {
    const { stdout, stderr } = await execFileAsync(resolution.path, args, {
      timeout: options.timeout,
      maxBuffer: options.maxBuffer,
    });
    return { status: "ok", stdout, stderr, command, binary: resolution };
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
      binary: resolution,
    };
  }
}
