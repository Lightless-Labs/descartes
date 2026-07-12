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
import { readFile as fsReadFile, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { loadProvenanceConfig as defaultLoadProvenanceConfig, resolveProvenanceConfigPaths } from "../provenance-elevated-config.js";

const execFileAsync = promisify(execFile);

// Explicit minimal environment for every helper child process -- defense-in-depth against
// LD_PRELOAD/LD_LIBRARY_PATH-class injection into a capability-bearing child, not relying solely
// on the kernel's AT_SECURE/secure-execution mode. Never the daemon's ambient process.env.
const MINIMAL_ENV = Object.freeze({ PATH: "/usr/bin:/bin" });

const DEFAULT_PROBE_TIMEOUT_MS = 2000;
const DEFAULT_INVOKE_TIMEOUT_MS = 3000;
const DEFAULT_MAX_BUFFER = 64 * 1024;
// Stricter than execFile's own maxBuffer -- a bounded-length check applied BEFORE JSON.parse is
// ever attempted, so a technically-below-maxBuffer-but-still-huge response can't reach the parser.
const MAX_RESPONSE_BYTES = 8 * 1024;

// Fixed, documented install location (Slice 5's operator doc target). Overridable via
// options.helperPath for tests and, eventually, config.elevated.helper_path.
export const DEFAULT_HELPER_PATH = "/usr/local/libexec/descartes/descartes-root-helper";

const UNSAFE_MODE_BITS = 0o022; // group- or world-writable

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
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? "",
      command: { argv, read_only: true },
    };
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

// argv is always one of the two literal bounded forms below -- never a template/interpolated
// string. Callers pass `argv` in from resolveElevated, which builds it as a literal array.
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

async function statIsTrusted(targetPath, statFn, expectedUid) {
  try {
    const info = await statFn(targetPath);
    if (!info) return { trusted: false, reason: `stat_failed:${targetPath}` };
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

export async function verifyTrustBoundary({ configPath, configDir, helperPath } = {}, options = {}) {
  const statFn = options.statFn ?? stat;
  const expectedUid = options.expectedUid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);

  const candidates = [
    ...(helperPath ? [helperPath, ...ancestorDirs(helperPath)] : []),
    ...(configPath ? [configPath] : []),
    ...(configDir ? [configDir] : []),
  ];
  const uniqueCandidates = [...new Set(candidates)];

  for (const candidate of uniqueCandidates) {
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

export function parseAndVerifyHelperResponse(rawStdout, requestedTarget) {
  if (typeof rawStdout !== "string" || rawStdout.length === 0 || rawStdout.length > MAX_RESPONSE_BYTES) return undefined;

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

  if (!requestedTarget || (requestedTarget.kind !== "pid" && requestedTarget.kind !== "port")) return undefined;
  if (requestedTarget.kind === "port" && requested.port !== requestedTarget.value) return undefined;
  if (requestedTarget.kind === "pid" && requested.pid !== requestedTarget.value) return undefined;

  const pid = Number.isInteger(resolved.pid) && resolved.pid > 0 ? resolved.pid : undefined;
  if (pid === undefined) return undefined; // never merge a response without a concrete resolved pid.

  const uid = Number.isInteger(resolved.uid) ? resolved.uid : undefined;
  const executablePath = typeof resolved.executable_path === "string" ? resolved.executable_path : undefined;
  const command = typeof resolved.command === "string" ? resolved.command : undefined;

  return { pid, uid, executable_path: executablePath, command };
}

// ---------------------------------------------------------------------------------------------
// Orchestrator. Two-condition AND gate: config.elevated.enabled===true AND probe reports
// available:true. mechanism:"auto" never targets root_helper -- only probed/attempted when
// explicitly named in config. Returns `undefined` on ANY non-success exit path (the caller is
// responsible for falling back to the already-computed unprivileged result unchanged); returns a
// plain success descriptor `{pid, uid, executablePath, command, mechanism}` on a verified
// echo-back-matching success.
// ---------------------------------------------------------------------------------------------

export async function resolveElevated({ target, paths } = {}, options = {}) {
  if (!target || !paths) return undefined;

  const loadConfig = options.loadProvenanceConfig ?? defaultLoadProvenanceConfig;
  let config;
  try {
    config = await loadConfig(paths);
  } catch {
    return undefined;
  }
  if (config?.elevated?.enabled !== true) return undefined; // condition 1 of the two-condition AND gate.

  const configuredMechanism = config.elevated.mechanism ?? "auto";
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

  // Fixed-argv, always one of the two literal bounded forms -- never a template/interpolated
  // string.
  const argv = target.kind === "pid" ? ["--resolve-pid", String(target.value)] : ["--resolve-port", String(target.value)];

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

  return { pid: parsed.pid, uid: parsed.uid, executablePath: parsed.executable_path, command: parsed.command, mechanism: attemptedMechanism };
}
