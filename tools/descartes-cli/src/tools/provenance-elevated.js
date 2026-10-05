// S3-priv Slice 2 — elevated-path plumbing against an INJECTABLE MOCK HELPER. No real privilege,
// no Rust, no setcap/sudo anywhere in this file. See
// docs/plans/2026-07-11-s3-priv-elevated-read-path.md §0 (Grounding, esp. the two degrade shapes)
// and §1 Slice 2.
//
// THE LOAD-BEARING DEGRADE INVARIANT: every failure mode in resolveElevated (config disabled,
// helper absent, probe fail, invoke timeout, malformed/oversized/scope-mismatch response,
// trust-boundary reject, auto-never-root_helper) returns `undefined`. The caller
// (provenance.js's resolveCrossUidPortResult) is what turns an `undefined` back into the
// already-computed unprivileged `status:'partial'`, `confidence:0.4`,
// `review_hint:'missing_permission'` result -- this module never touches that shape directly, so
// it structurally cannot collapse it to the more-degraded `unable`/`0` surface (that shape is
// timedEnvelope's thrown-exception contract only, untouched by this module).
//
// DI precedent mirrors provenance-identity.js's shipped shape verbatim:
// `const fn = options.fn ?? defaultFn;` -- no mocking library anywhere in this repo's tests.

import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { readFile as fsReadFile, lstat, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { loadProvenanceConfig as defaultLoadProvenanceConfig, resolveProvenanceConfigPaths } from "../provenance-elevated-config.js";
import { redactAndBoundProcessArgv } from "./processes.js";

const execFileAsync = promisify(execFile);

// Explicit minimal environment for every helper child process -- defense-in-depth against
// LD_PRELOAD/LD_LIBRARY_PATH-class injection into a capability-bearing child, not relying solely
// on the kernel's AT_SECURE/secure-execution mode. Never the daemon's ambient process.env.
const MINIMAL_ENV = Object.freeze({ PATH: "/usr/bin:/bin" });

const DEFAULT_PROBE_TIMEOUT_MS = 2000;
const DEFAULT_INVOKE_TIMEOUT_MS = 3000;
const DEFAULT_MAX_BUFFER = 64 * 1024;

// descartes-root-helper's EXIT_RESOLUTION_TRUNCATED (main.rs): a `--resolve-socket` that found no
// owner AND gave up at least one candidate's /proc/<pid>/fd scan at the per-process cap (or the pid
// walk at its cap), so "no owner" is UNCERTAIN, not definitive (Codex-hardening #6). Still a nonzero
// (failure) exit — the degrade-to-unprivileged flow is unchanged — but distinguishable, so the
// truncation can be surfaced as an observable provenance signal instead of a silent negative.
const HELPER_EXIT_FD_SCAN_TRUNCATED = 3;
// descartes-root-helper's hardening::EXIT_HARDENING_FAILURE: NO_NEW_PRIVS / seccomp / capability
// drop failed to engage and the helper aborted fail-closed. Before 2026-10 this shared exit 3 with
// the truncated scan, so a confinement failure was mislabelled `fd_scan_truncated` exactly when the
// security boundary failed (research 2026-09-26, finding 8). Now distinct, and surfaced as its own
// diagnostic; still a plain failure for the degrade path.
const HELPER_EXIT_HARDENING_FAILURE = 4;
// descartes-root-helper's EXIT_OWNER_AMBIGUOUS (2026-10, research finding 2): the exact socket is
// held by processes running DIFFERENT executables (e.g. systemd socket activation), so the helper
// names no owner. Still a plain failure for the degrade path; surfaced as its own diagnostic.
const HELPER_EXIT_OWNER_AMBIGUOUS = 5;
const HELPER_EXIT_PROCFS_NAMESPACE_MISMATCH = 6;

// The four /proc/net tables resolveByPortLinux observes; passed to the helper verbatim.
const SOCKET_PROTOCOLS = new Set(["tcp", "tcp6", "udp", "udp6"]);
// A /proc/net inode column value as the kernel prints it (%lu): no sign, no leading zero, nonzero.
// The helper independently rejects anything that overflows u64.
const SOCKET_INODE_PATTERN = /^[1-9][0-9]{0,19}$/;
// Stricter than execFile's own maxBuffer -- a bounded-length check applied BEFORE JSON.parse is
// ever attempted, so a technically-below-maxBuffer-but-still-huge response can't reach the parser.
const MAX_RESPONSE_BYTES = 8 * 1024;

// Fixed, documented install location (Slice 5's operator doc target). Overridable via
// options.helperPath for tests and, eventually, config.elevated.helper_path.
export const DEFAULT_HELPER_PATH = "/usr/local/libexec/descartes/descartes-root-helper";

const UNSAFE_MODE_BITS = 0o022; // group- or world-writable
const VALID_MECHANISMS = new Set(["auto", "cap_sys_ptrace", "root_helper", "helper_xpc", "none"]);

// ---------------------------------------------------------------------------------------------
// S3-priv Slice 5 Phase 2 Part B: real (non-mock) ptrace_scope diagnostic, deferred from Slice 2.
// A pure, standalone, NEVER-THROWING surface -- deliberately NOT wired into resolveElevated's
// return value below. resolveElevated's contract is undefined-on-every-non-success-path (see its
// own doc comment further down); a diagnostic field can't be hung off "undefined" without either
// breaking that contract or requiring every caller to unpack a richer shape just to reach a field
// that's absent on the one path (success) where it isn't needed. The diagnostic is most valuable
// ON FAILURE ("elevated didn't upgrade -- is ptrace_scope=2 why?"), so the CALLER
// (provenance.js's resolveCrossUidPortResult) invokes this directly and attaches the result to
// its own privilege block on both a successful elevated upgrade and a degrade-to-unprivileged
// outcome. Closed-set validation (`^[0-3]$`) matches Yama's only four documented ptrace_scope
// values (0=classic, 1=restricted, 2=admin-only, 3=no-attach); anything else -- ENOENT
// (non-Linux, or an unusual kernel config without this sysctl), EACCES, a multi-line/garbage
// read, or any other error -- degrades identically to "unreadable": `undefined`, never a raw
// unvalidated string, never thrown.
const PTRACE_SCOPE_PATH = "/proc/sys/kernel/yama/ptrace_scope";
const PTRACE_SCOPE_PATTERN = /^[0-3]$/;

export async function readPtraceScopeDiagnostic({ readFile = fsReadFile } = {}) {
  try {
    const raw = await readFile(PTRACE_SCOPE_PATH, "utf8");
    const trimmed = String(raw).trim();
    return PTRACE_SCOPE_PATTERN.test(trimmed) ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------
// Fixed-argv probe + invoke. Mirrors provenance.js's runFixedExecFile (array-argv, bounded
// timeout/maxBuffer, no shell:true) shape, diverging only to force the MINIMAL_ENV override that
// runFixedExecFile does not need (its callers all run trusted, unprivileged host tools) -- kept as
// a small local helper here rather than importing runFixedExecFile, so this module stays
// self-contained and never needs anything from provenance.js (provenance.js imports FROM this
// module, not the other way around).
// ---------------------------------------------------------------------------------------------

async function runMinimalEnvExecFile(command, args, { timeout, maxBuffer } = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeout ?? DEFAULT_INVOKE_TIMEOUT_MS,
      maxBuffer: maxBuffer ?? DEFAULT_MAX_BUFFER,
      env: { ...MINIMAL_ENV },
    });
    return { status: "ok", stdout, stderr, command: { argv, read_only: true } };
  } catch (error) {
    const result = {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? "",
      command: { argv, read_only: true },
    };
    // Codex-hardening #6: on the helper's dedicated truncated-scan exit code, tag the (still-unable)
    // result additively so callers can surface `fd_scan_truncated` in provenance. The degrade path
    // is untouched — status stays "unable", so every consumer that keys on status?.=== "ok" still
    // degrades to the unprivileged shape exactly as before. On a real process exit the child's
    // numeric exit status arrives as error.code; a signal/ENOENT string code simply won't match.
    if (error?.code === HELPER_EXIT_FD_SCAN_TRUNCATED) result.fd_scan_truncated = true;
    if (error?.code === HELPER_EXIT_HARDENING_FAILURE) result.helper_hardening_failure = true;
    if (error?.code === HELPER_EXIT_OWNER_AMBIGUOUS) result.owner_ambiguous = true;
    if (error?.code === HELPER_EXIT_PROCFS_NAMESPACE_MISMATCH) result.procfs_namespace_mismatch = true;
    if (error?.signal === "SIGSYS") result.helper_seccomp_killed = true;
    if (error?.killed === true) result.helper_timeout_killed = true;
    return result;
  }
}

// Probe-cache note (plan §1): callers that want per-process memoization are free to wrap this --
// this module deliberately does not cache internally, since the authoritative gate is always
// invoke-time OS enforcement, never the probe result. A stale cached "available:true" can never
// fabricate success: the next real invoke still fails closed on EPERM/ENOENT.
export async function defaultProbeElevatedHelper(helperPath, options = {}) {
  const result = await runMinimalEnvExecFile(helperPath, ["--probe"], {
    timeout: options.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS,
    maxBuffer: options.maxBuffer,
  });
  return { available: result.status === "ok" };
}

// argv is always one of the two literal bounded forms built by buildHelperArgv below -- never a
// template/interpolated string.
export async function defaultInvokeElevatedHelper(helperPath, argv, options = {}) {
  return runMinimalEnvExecFile(helperPath, argv, {
    timeout: options.invokeTimeoutMs ?? DEFAULT_INVOKE_TIMEOUT_MS,
    maxBuffer: options.maxBuffer,
  });
}

// ---------------------------------------------------------------------------------------------
// Trust boundary (pure decision, DI'able stat). Rejects if the config file, its parent dir, the
// helper binary, OR ANY ANCESTOR DIRECTORY of the helper binary is group/world-writable or not
// owned by a trusted principal (root, or the running principal) -- the classic dir-hijack local
// privesc vector, worse here because a rejected check must never let the (possibly root-running)
// helper execute. Fail-closed: any stat error anywhere in the chain also rejects.
// ---------------------------------------------------------------------------------------------

function isUnsafeMode(mode) {
  return (mode & UNSAFE_MODE_BITS) !== 0;
}

function isTrustedOwner(uid, expectedUid) {
  if (uid === 0) return true; // root-owned is the expected owner of an installed helper/ancestor.
  return expectedUid !== undefined && uid === expectedUid;
}

function isSymlinkMode(mode) {
  return (mode & fsConstants.S_IFMT) === fsConstants.S_IFLNK;
}

async function statIsTrusted(targetPath, statFn, expectedUid, { rejectSymlink = false } = {}) {
  try {
    const info = await statFn(targetPath);
    if (!info) return { trusted: false, reason: `stat_failed:${targetPath}` };
    if (rejectSymlink && isSymlinkMode(info.mode)) return { trusted: false, reason: `symlink:${targetPath}` };
    if (isUnsafeMode(info.mode)) return { trusted: false, reason: `group_or_world_writable:${targetPath}` };
    if (!isTrustedOwner(info.uid, expectedUid)) return { trusted: false, reason: `untrusted_owner:${targetPath}` };
    return { trusted: true };
  } catch (error) {
    return { trusted: false, reason: `stat_error:${targetPath}:${error?.code ?? "unknown"}` };
  }
}

// Walks from the immediate parent up to the filesystem root ('/'), inclusive.
function ancestorDirs(targetPath) {
  const dirs = [];
  let current = path.dirname(targetPath);
  while (true) {
    dirs.push(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return dirs;
}

// 2026-10 (research finding 5, bounded part): the two LEAF paths -- the helper binary and the
// config file -- are checked with lstat (no final-symlink follow) and a symlink there is rejected
// outright. stat() followed a final symlink, so a root-owned, correctly-moded TARGET vouched for a
// link whose own location the check never examined. The residual check-then-exec window (execFile
// re-resolves the path after this check) is narrowed by re-running this check immediately before
// the invoke as well as before the probe (see resolveElevated); closing it fully needs
// descriptor-pinned execution or a long-lived root-owned service -- deferred, see the research doc.
export async function verifyTrustBoundary({ configPath, configDir, helperPath } = {}, options = {}) {
  const statFn = options.statFn ?? stat;
  // Tests that inject only statFn keep exercising their fixtures for the leaves too.
  const lstatFn = options.lstatFn ?? options.statFn ?? lstat;
  const expectedUid = options.expectedUid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);

  const leaves = [...(helperPath ? [helperPath] : []), ...(configPath ? [configPath] : [])];
  for (const leaf of leaves) {
    const outcome = await statIsTrusted(leaf, lstatFn, expectedUid, { rejectSymlink: true });
    if (!outcome.trusted) return outcome;
  }

  const directories = [
    ...(helperPath ? ancestorDirs(helperPath) : []),
    ...(configDir ? [configDir] : []),
  ];
  for (const candidate of [...new Set(directories)]) {
    if (leaves.includes(candidate)) continue;
    const outcome = await statIsTrusted(candidate, statFn, expectedUid);
    if (!outcome.trusted) return outcome;
  }
  return { trusted: true };
}

// ---------------------------------------------------------------------------------------------
// Echo-back scope verification of untrusted helper stdout. Bounded-length parse, closed-shape
// field pick (no pass-through of arbitrary helper-supplied keys), and the response MUST describe
// the EXACT pid/port requested before any field is merged. Any mismatch is treated identically to
// a parse failure -- never merged.
// ---------------------------------------------------------------------------------------------

// 2026-10 (research finding 2): a port-attributed request is a SOCKET request bound to the exact
// identity the unprivileged path observed -- protocol + port + inode -- never a bare port. The
// helper echoes all three back, and every one must match (strict ===, inode compared as the exact
// decimal string from /proc/net), with no extra keys in `requested`.
function requestedEchoMatches(requested, target) {
  if (target.kind === "pid") return requested.pid === target.value;
  if (target.kind === "socket") {
    const keys = Object.keys(requested);
    return (
      keys.length === 3 &&
      requested.protocol === target.protocol &&
      requested.port === target.port &&
      requested.inode === target.inode
    );
  }
  return false;
}

export function parseAndVerifyHelperResponse(rawStdout, requestedTarget) {
  if (typeof rawStdout !== "string" || rawStdout.length === 0 || Buffer.byteLength(rawStdout, "utf8") > MAX_RESPONSE_BYTES) return undefined;

  let parsed;
  try {
    parsed = JSON.parse(rawStdout);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;

  const requested = parsed.requested;
  const resolved = parsed.resolved;
  if (!requested || typeof requested !== "object" || !resolved || typeof resolved !== "object") return undefined;

  if (!requestedTarget || (requestedTarget.kind !== "pid" && requestedTarget.kind !== "socket")) return undefined;
  if (!requestedEchoMatches(requested, requestedTarget)) return undefined;

  const pid = Number.isInteger(resolved.pid) && resolved.pid > 0 ? resolved.pid : undefined;
  if (pid === undefined) return undefined; // never merge a response without a concrete resolved pid.
  // 2026-10 (research finding 6): for a PID request the answer must describe THAT pid. Echoing the
  // requested pid while resolving another (buggy or compromised helper) is a scope mismatch, not
  // an answer -- the echo alone only proved the helper read the request, not what it resolved.
  if (requestedTarget.kind === "pid" && pid !== requestedTarget.value) return undefined;

  const uid = Number.isInteger(resolved.uid) ? resolved.uid : undefined;
  const tgid = Number.isInteger(resolved.tgid) && resolved.tgid > 0 ? resolved.tgid : undefined;
  const startTime = Number.isSafeInteger(resolved.start_time) && resolved.start_time >= 0 ? String(resolved.start_time) : undefined;
  if (tgid === undefined || startTime === undefined) return undefined;
  const executablePath = typeof resolved.executable_path === "string" ? resolved.executable_path : undefined;
  if (!Array.isArray(resolved.argv) || resolved.argv.some((arg) => typeof arg !== "string")) return undefined;
  if (resolved.argv_truncated !== undefined && typeof resolved.argv_truncated !== "boolean") return undefined;
  const argvTruncated = resolved.argv_truncated === true;
  const redaction = redactAndBoundProcessArgv(resolved.argv);
  const command = redaction.value;

  const out = { pid, uid, executable_path: executablePath, command };
  Object.defineProperty(out, "argv", { value: resolved.argv, enumerable: false });
  Object.defineProperty(out, "args_redaction", {
    value: argvTruncated
      ? { ...redaction, truncated: true, reason: "cmdline_truncated" }
      : redaction,
    enumerable: false,
  });
  Object.defineProperty(out, "argv_truncated", { value: argvTruncated, enumerable: false });
  Object.defineProperties(out, {
    tgid: { value: tgid, enumerable: false },
    start_time: { value: startTime, enumerable: false },
  });
  if (requestedTarget.kind === "socket") {
    // Number of processes the helper found holding the exact socket (all one executable -- it
    // reports disagreeing holders as ambiguous instead). Must be a positive integer if present.
    if (resolved.holders !== undefined) {
      if (!Number.isInteger(resolved.holders) || resolved.holders < 1) return undefined;
      out.holders = resolved.holders;
    }
  }
  return out;
}

// Builds the helper argv for a target, or `undefined` for anything outside the two literal forms
// (fail closed: an unbuildable target never reaches the helper). Exported for tests.
export function buildHelperArgv(target) {
  if (!target || typeof target !== "object") return undefined;
  if (target.kind === "pid") {
    return Number.isInteger(target.value) && target.value > 0 ? ["--resolve-pid", String(target.value)] : undefined;
  }
  if (target.kind === "socket") {
    if (!SOCKET_PROTOCOLS.has(target.protocol)) return undefined;
    if (!Number.isInteger(target.port) || target.port < 0 || target.port > 65535) return undefined;
    if (typeof target.inode !== "string" || !SOCKET_INODE_PATTERN.test(target.inode)) return undefined;
    return ["--resolve-socket", target.protocol, String(target.port), target.inode];
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// Orchestrator. Two-condition AND gate: config.elevated.enabled===true AND probe reports
// available:true. mechanism:"auto" never targets root_helper -- only probed/attempted when
// explicitly named in config. Returns `undefined` on ANY non-success exit path (the caller is
// responsible for falling back to the already-computed unprivileged result unchanged); returns a
// plain success descriptor `{pid, uid, executablePath, command, mechanism, holders?}` on a verified
// echo-back-matching success.
// ---------------------------------------------------------------------------------------------

export async function resolveElevated({ target, paths } = {}, options = {}) {
  if (!target || !paths) return undefined;
  // Fixed-argv, always one of the two literal bounded forms -- never a template/interpolated
  // string. Built (and validated) up front: a target that cannot be expressed exactly is never
  // attempted at all.
  const argv = buildHelperArgv(target);
  if (!argv) return undefined;

  const loadConfig = options.loadProvenanceConfig ?? defaultLoadProvenanceConfig;
  let config;
  try {
    config = await loadConfig(paths);
  } catch {
    return undefined;
  }
  if (config?.elevated?.enabled !== true) return undefined; // condition 1 of the two-condition AND gate.

  const configuredMechanism = config.elevated.mechanism ?? "auto";
  // DI callers and hand-written config can bypass normalizeProvenanceConfig. Never let an
  // unknown mechanism reach probing/invocation, even if enabled was also true.
  if (!VALID_MECHANISMS.has(configuredMechanism)) return undefined;
  if (configuredMechanism === "none") return undefined;

  const helperPath = options.helperPath ?? DEFAULT_HELPER_PATH;
  const { configFile } = resolveProvenanceConfigPaths(paths);

  // Trust boundary gates ALL uses of helperPath, including the probe below -- an untrusted binary
  // is never even exec'd for a --probe call, not just skipped at invoke time.
  const trust = await verifyTrustBoundary({ configPath: configFile, configDir: paths.configDir, helperPath }, options);
  if (!trust.trusted) return undefined;

  const probe = options.probeElevatedHelper ?? defaultProbeElevatedHelper;
  let probeResult;
  try {
    probeResult = await probe(helperPath, options);
  } catch {
    return undefined;
  }
  if (!probeResult?.available) return undefined; // condition 2 of the two-condition AND gate.

  // mechanism:"auto" never targets root_helper: only comparable-blast-radius mechanisms are
  // attempted under auto. A probe may self-report which mechanism it represents; root_helper is
  // only ever attempted when named explicitly in config.
  const attemptedMechanism = configuredMechanism === "auto" ? (probeResult.mechanism ?? "auto") : configuredMechanism;
  if (attemptedMechanism === "root_helper" && configuredMechanism !== "root_helper") return undefined;

  // 2026-10 (research finding 5): re-verify immediately before the invoke rather than trusting the
  // pre-probe check across the probe's whole lifetime (up to its timeout) -- shrinks, but does not
  // close, the check-then-exec window; see verifyTrustBoundary's doc.
  const trustAtInvoke = await verifyTrustBoundary({ configPath: configFile, configDir: paths.configDir, helperPath }, options);
  if (!trustAtInvoke.trusted) return undefined;

  const invoke = options.invokeElevatedHelper ?? defaultInvokeElevatedHelper;
  let invokeResult;
  try {
    invokeResult = await invoke(helperPath, argv, options);
  } catch {
    return undefined;
  }
  if (invokeResult?.status !== "ok") return undefined;

  const parsed = parseAndVerifyHelperResponse(invokeResult.stdout, target);
  if (!parsed) return undefined;

  const success = {
    pid: parsed.pid,
    tgid: parsed.tgid,
    startTime: parsed.start_time,
    uid: parsed.uid,
    executablePath: parsed.executable_path,
    command: parsed.command,
    ...(parsed.argv_truncated === true ? { argv_truncated: true } : {}),
    mechanism: attemptedMechanism,
  };
  Object.defineProperty(success, "argv", { value: parsed.argv, enumerable: false });
  if (parsed.holders !== undefined) success.holders = parsed.holders;
  return success;
}
