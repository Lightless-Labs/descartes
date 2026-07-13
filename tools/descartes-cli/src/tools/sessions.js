// Slice 1 (observed-incident collectors plan) — session-census L0 collector.
//
// Enumerates resident tmux/screen sessions via fixed-argv execFile, mirroring services.js's/
// system.js's timedEnvelope-wrapped shape exactly (docs/plans/2026-07-13-observed-incident-
// collectors.md, Slice 1). Read-only, same-UID only (v0 does not attempt to enumerate other
// users' sessions — tmux/screen only ever expose the invoking user's own sessions unprivileged,
// so this is a statement of scope, not a gap this collector papers over).
//
// Degrade-not-fabricate (hard requirement): neither tmux nor screen present on the host ->
// envelope status "unable"/confidence 0 — this is asserted as NEVER equivalent to "0 sessions".
// A binary that IS present but genuinely reports zero sessions (tmux with no server running,
// screen's "No Sockets found") is a real, distinguishable fact -> status "ok", sessions: [].
//
// Flood cap (must-fix 5): the combined tmux+screen session list is bounded at
// DEFAULT_SESSION_ENTITY_LIMIT entities per tick, mirroring daemon.js's DEFAULT_DAEMON_PROCESS_
// LIMIT precedent — a pathological session flood must not be allowed to blow past a fixed
// per-tick cap, because an unbounded fact-count from this one collector could evict OTHER
// collectors' fact-history out of the shared fact-store.js retention cap. When the real count
// exceeds the cap, `truncated: true` and `total_count` are carried on the result so the
// fact-translator (fact-translators.js) can emit an explicit overflow marker fact — entities are
// never silently dropped with no indication anything was truncated.
//
// Injectable execFile runner (options.runFixedExecFile), mirroring provenance-warnings.js's own
// DI convention — this is how both platform paths are exercised from a single macOS dev machine
// without a real Linux/second tmux-less host (plan §2's local testability model).

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_SESSION_ENTITY_LIMIT = 200;

// tmux's #{session_created} format variable is a Unix epoch-seconds integer — locale-independent
// and reliable, unlike screen's optional (and locale-formatted) creation-date column, which is
// deliberately NOT parsed below (see collectScreenSessions/parseScreenLs doc).
const TMUX_FORMAT = "#{session_name}\t#{session_windows}\t#{session_attached}\t#{session_created}";

async function runFixedExecFile(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 3000,
      maxBuffer: options.maxBuffer ?? 256 * 1024,
    });
    return { status: "ok", stdout, stderr, command: { argv, read_only: true } };
  } catch (error) {
    return {
      status: "error",
      code: error?.code,
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? "",
      error: error instanceof Error ? error.message : String(error),
      command: { argv, read_only: true },
    };
  }
}

/**
 * Pure parser for `tmux list-sessions -F` output in TMUX_FORMAT's tab-separated shape. Lines
 * that don't split into exactly 4 fields, or whose numeric fields don't parse, are skipped
 * (counted in malformed_count) rather than fabricating a partial session record — mirrors
 * fact-translators.js's own "drop, never invent" convention applied at parse time instead.
 */
// tmux always emits non-negative integers for #{session_windows}/#{session_created}. A strict
// match — NOT Number.isFinite(Number(x)) — is required because Number("") === 0 (finite): an EMPTY
// field would otherwise be fabricated into a concrete 0 (→ a "0" window / epoch-1970 created bucket)
// instead of being dropped as malformed. Degrade-not-fabricate at the field level; only reachable
// via a corrupted/interposed tmux, but the contract must hold there too.
const TMUX_UINT_FIELD_RE = /^\d+$/;
export function parseTmuxSessions(stdout) {
  const sessions = [];
  let malformedCount = 0;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const fields = line.split("\t");
    if (fields.length !== 4) {
      malformedCount += 1;
      continue;
    }
    const [name, windowsText, attachedText, createdText] = fields;
    if (!name || !TMUX_UINT_FIELD_RE.test(windowsText) || !TMUX_UINT_FIELD_RE.test(createdText)) {
      malformedCount += 1;
      continue;
    }
    const windowCount = Number(windowsText);
    const createdAtEpochSeconds = Number(createdText);
    sessions.push({
      session_name: name,
      window_count: windowCount,
      attached: attachedText === "1",
      created_at_epoch_seconds: createdAtEpochSeconds,
    });
  }
  return { sessions, malformed_count: malformedCount };
}

const SCREEN_NO_SOCKETS_RE = /no sockets? found/i;
const SCREEN_HEADER_RE = /^there (is|are) (a |)screens? on:?$/i;
const SCREEN_FOOTER_RE = /^\d+ sockets? in /i;
// Matches "<pid>.<name>\t...\t(Attached|Detached)" — deliberately tolerant of an optional
// locale-formatted date column in between (never parsed; see doc below), anchored on the
// trailing "(Attached)"/"(Detached)" marker which is stable across screen versions/locales.
const SCREEN_SESSION_LINE_RE = /^(\d+)\.(\S+)\s+.*\((Attached|Detached)\)\s*$/;

/**
 * Pure parser for `screen -ls` output. screen has no reliable, locale-independent way to expose
 * a window count or creation timestamp via -ls (some builds show a locale-formatted date column,
 * others don't) — window_count and created_at_epoch_seconds are therefore always undefined for
 * screen sessions (degrade-not-fabricate: the fact-translator buckets this to "unknown" rather
 * than inventing a value). The "No Sockets found" phrasing is screen's own genuine-zero-sessions
 * signal, distinguished from a malformed/unrecognized line.
 */
export function parseScreenLs(stdout) {
  const text = String(stdout ?? "");
  if (SCREEN_NO_SOCKETS_RE.test(text)) return { sessions: [], malformed_count: 0, no_sockets: true };

  const sessions = [];
  let malformedCount = 0;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (SCREEN_HEADER_RE.test(line) || SCREEN_FOOTER_RE.test(line)) continue;
    const match = line.match(SCREEN_SESSION_LINE_RE);
    if (!match) {
      malformedCount += 1;
      continue;
    }
    const [, pid, name, attachState] = match;
    sessions.push({
      session_name: `${pid}.${name}`,
      window_count: undefined,
      attached: attachState === "Attached",
      created_at_epoch_seconds: undefined,
    });
  }
  return { sessions, malformed_count: malformedCount, no_sockets: false };
}

/**
 * tmux exits non-zero both when the binary is genuinely absent (ENOENT) AND when it's present
 * but no server is running (the honest "zero tmux sessions" case) — these must not be conflated.
 * Any OTHER failure (permission denied, timeout, unexpected error) degrades this multiplexer to
 * "unable" rather than being guessed as either extreme.
 */
async function collectTmuxSessions(options = {}) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const args = ["list-sessions", "-F", TMUX_FORMAT];
  const probe = await runExec("tmux", args, { timeout: options.timeout, maxBuffer: options.maxBuffer });

  if (probe.status === "ok") {
    const parsed = parseTmuxSessions(probe.stdout);
    return { multiplexer: "tmux", status: "ok", sessions: parsed.sessions, malformed_count: parsed.malformed_count, command: probe.command };
  }
  if (probe.code === "ENOENT") {
    return { multiplexer: "tmux", status: "absent", sessions: [], command: probe.command };
  }
  const text = `${probe.stdout ?? ""}\n${probe.stderr ?? ""}`;
  if (/no server running|no such file or directory|error connecting to/i.test(text)) {
    // tmux binary present, ran, and told us (via its own no-server error) that zero sessions
    // exist — a real, distinguishable fact, not a fabricated one.
    return { multiplexer: "tmux", status: "ok", sessions: [], malformed_count: 0, command: probe.command };
  }
  return { multiplexer: "tmux", status: "unable", sessions: [], error: probe.error, command: probe.command };
}

/**
 * screen -ls is known to exit non-zero even when it succeeds and sessions exist on some
 * versions/platforms — a raw non-zero exit code must never be treated as "unable" without first
 * inspecting stdout/stderr for screen's own recognizable session-listing content (must-fix
 * "nice-to-have" pinned fixture requirement, plan Slice 1).
 */
async function collectScreenSessions(options = {}) {
  const runExec = options.runFixedExecFile ?? runFixedExecFile;
  const args = ["-ls"];
  const probe = await runExec("screen", args, { timeout: options.timeout, maxBuffer: options.maxBuffer });

  if (probe.code === "ENOENT") {
    return { multiplexer: "screen", status: "absent", sessions: [], command: probe.command };
  }

  const text = `${probe.stdout ?? ""}\n${probe.stderr ?? ""}`;
  const parsed = parseScreenLs(text);
  if (probe.status === "ok" || parsed.no_sockets || parsed.sessions.length > 0) {
    return { multiplexer: "screen", status: "ok", sessions: parsed.sessions, malformed_count: parsed.malformed_count, command: probe.command };
  }
  return { multiplexer: "screen", status: "unable", sessions: [], error: probe.error, command: probe.command };
}

/**
 * Session-census L0 collector (Slice 1). Combines tmux + screen results, bounds the combined
 * entity count at DEFAULT_SESSION_ENTITY_LIMIT (must-fix 5), and computes the overall
 * degrade-not-fabricate envelope status: "unable"/confidence 0 only when NEITHER multiplexer
 * binary is present/usable this tick — any single successful (even zero-session) read from
 * either multiplexer counts as a real "ok" observation.
 */
export async function collectSessionEvidence(options = {}) {
  const cap = Math.max(1, Number(options.sessionLimit) || DEFAULT_SESSION_ENTITY_LIMIT);

  return timedEnvelope(async () => {
    const platform = options.platform ?? process.platform;
    const tmux = await collectTmuxSessions(options);
    const screen = await collectScreenSessions(options);
    const multiplexers = [tmux, screen];

    const allSessions = [];
    for (const mux of multiplexers) {
      for (const session of mux.sessions) {
        allSessions.push({ multiplexer: mux.multiplexer, ...session });
      }
    }

    const anyBinaryAvailable = multiplexers.some((mux) => mux.status === "ok");
    const truncated = allSessions.length > cap;

    return {
      platform,
      multiplexers: multiplexers.map((mux) => ({
        multiplexer: mux.multiplexer,
        status: mux.status,
        ...(mux.error ? { error: mux.error } : {}),
      })),
      any_binary_available: anyBinaryAvailable,
      total_count: allSessions.length,
      sessions: allSessions.slice(0, cap),
      truncated,
      cap,
    };
  }, (result) => evidenceEnvelope({
    id: "sessions",
    status: result.any_binary_available ? "ok" : "unable",
    source: "session_multiplexer",
    result,
    confidence: result.any_binary_available ? 1 : 0,
    reviewHint: result.any_binary_available ? "none" : "missing_permission",
    tool: "collect_sessions",
    target: `cap=${result.cap}`,
  }));
}
