import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
export const DEFAULT_SINGLETON_TIMEOUT_MS = 5_000;
export const DEFAULT_SINGLETON_RETRY_MS = 25;

export function daemonSingletonPath(descartesPaths) {
  const dir = descartesPaths.runtimeDir ?? path.join(descartesPaths.stateDir, "daemon");
  return path.join(dir, "daemon.singleton");
}

async function readLinuxBootIdentity() {
  try {
    return (await fs.readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim() || undefined;
  } catch {
    return undefined;
  }
}

async function readMacBootIdentity() {
  try {
    const result = await execFileAsync("sysctl", ["-n", "kern.bootsessionuuid"], { timeout: 1_000 });
    return result.stdout.trim() || undefined;
  } catch {
    return undefined;
  }
}

async function readProcessStartIdentity(pid) {
  try {
    const stat = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    const closeParen = stat.lastIndexOf(")");
    if (closeParen < 0) return undefined;
    return stat.slice(closeParen + 2).trim().split(/\s+/)[19] || undefined;
  } catch {
    return undefined;
  }
}

async function currentMetadata(options) {
  const platform = options.platform ?? process.platform;
  const bootIdentity = options.bootIdentity !== undefined
    ? options.bootIdentity
    : platform === "darwin" ? await readMacBootIdentity() : await readLinuxBootIdentity();
  const processStartIdentity = options.processStartIdentity !== undefined
    ? options.processStartIdentity
    : await readProcessStartIdentity(options.pid ?? process.pid);
  return {
    pid: options.pid ?? process.pid,
    process_start_identity: processStartIdentity ?? null,
    boot_identity: bootIdentity ?? null,
    nonce: options.nonce ?? crypto.randomUUID(),
  };
}

function parseOwner(contents) {
  try {
    const owner = JSON.parse(contents);
    if (!owner || typeof owner !== "object" || !Number.isInteger(owner.pid) || typeof owner.nonce !== "string" || !owner.nonce) return undefined;
    return owner;
  } catch {
    return undefined;
  }
}

async function processAlive(pid, options) {
  if (options.processAlive) return options.processAlive(pid);
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

export async function ownerIsProvablyGone(owner, options = {}) {
  if (!owner || !Number.isInteger(owner.pid) || !owner.nonce) return false;
  const platform = options.platform ?? process.platform;
  const currentBoot = options.bootIdentity !== undefined
    ? options.bootIdentity
    : platform === "darwin" ? await readMacBootIdentity() : await readLinuxBootIdentity();
  if (owner.boot_identity && currentBoot && owner.boot_identity !== currentBoot) return true;

  const alive = await processAlive(owner.pid, options);
  if (!alive) {
    // A PID that has disappeared is enough on platforms with a start identity only when the
    // identity was recorded. On macOS, a missing start identity is explicitly not recoverable:
    // PID reuse cannot be ruled out by a later observation.
    return Boolean(owner.process_start_identity);
  }
  if (!owner.process_start_identity) return false;
  const currentStart = options.processStartIdentityForPid
    ? await options.processStartIdentityForPid(owner.pid)
    : await readProcessStartIdentity(owner.pid);
  return Boolean(currentStart && currentStart !== owner.process_start_identity);
}

function singletonBusyError(file, owner, reason = "already owned") {
  const ownerText = owner ? ` (pid ${owner.pid}, nonce ${owner.nonce})` : " (owner metadata is unreadable)";
  const clear = `Stop the owner if it is running, then remove ${file} only after verifying that no Descartes daemon remains.`;
  const error = new Error(`Descartes daemon singleton is ${reason}${ownerText}. ${clear}`);
  error.code = "DAEMON_SINGLETON_BUSY";
  return error;
}

async function sleepMonotonic(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export async function acquireDaemonSingleton(descartesPaths, options = {}) {
  const file = daemonSingletonPath(descartesPaths);
  const owner = await currentMetadata(options);
  const timeoutMs = options.timeoutMs ?? 0;
  const retryMs = options.retryMs ?? DEFAULT_SINGLETON_RETRY_MS;
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const started = monotonicNow();

  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  for (;;) {
    try {
      await fs.writeFile(file, JSON.stringify(owner), { mode: 0o600, flag: "wx" });
      let released = false;
      return {
        ...owner,
        path: file,
        async release() {
          if (released) return;
          released = true;
          try {
            const current = parseOwner(await fs.readFile(file, "utf8"));
            if (current?.nonce === owner.nonce) await fs.unlink(file);
          } catch (error) {
            if (error?.code !== "ENOENT") throw error;
          }
        },
      };
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      let existing;
      try {
        existing = parseOwner(await fs.readFile(file, "utf8"));
      } catch (readError) {
        if (readError?.code !== "ENOENT") throw singletonBusyError(file, undefined, "cannot be inspected safely");
      }
      if (existing && await ownerIsProvablyGone(existing, {
        ...options,
        platform: options.platform ?? process.platform,
      })) {
        await fs.unlink(file).catch((unlinkError) => {
          if (unlinkError?.code !== "ENOENT") throw unlinkError;
        });
        continue;
      }
      if (timeoutMs <= 0) {
        throw singletonBusyError(file, existing, existing?.process_start_identity ? "already owned" : "cannot prove the owner is gone");
      }
      if (monotonicNow() - started >= timeoutMs) {
        const timeout = new Error(`Descartes daemon singleton acquisition timed out after ${timeoutMs}ms (monotonic deadline); ${file} remains untouched.`);
        timeout.code = "DAEMON_SINGLETON_BUSY";
        throw timeout;
      }
      await sleepMonotonic(retryMs);
    }
  }
}

export async function withDaemonSingleton(descartesPaths, operation, options = {}) {
  const owner = await acquireDaemonSingleton(descartesPaths, options);
  try {
    return await operation(owner);
  } finally {
    await owner.release();
  }
}
