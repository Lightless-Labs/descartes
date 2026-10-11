// Context plan C0.4 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.3): the
// login-origin context collector.
//
// READ ONLY, fixed argv, no shell, every binary through the binary resolver (trust model):
//   macOS: `who` (current logins), `ioreg -r -k IOConsoleUsers -d 1 -a` (console users and the
//          screen-lock state), bounded `last -n <N>` (login history);
//   Linux: `loginctl list-sessions --no-legend --no-pager`, then ONE
//          `loginctl show-session --no-pager -p ... <ids>` for at most MAX_LOGINCTL_SESSIONS ids
//          (Remote, RemoteHost, Service, Type, Class, TTY, State, IdleHint, LockedHint), and bounded
//          `last -n <N>` for history.
//
// It returns RAW rows (user, tty, host) in memory only; context-translators.js HMACs every
// identifying value and the daemon dedupes rows by digest across ticks, so a login is recorded at
// its FIRST-OBSERVED tick, never at a parsed login time (decision kept from fact-translators.js).
// Classification uses the closed patterns of login-origin.js.
//
// Degrade, never fabricate: each source has its own state; a missing or failing source is never an
// empty login list.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { classifyLoginOrigin, isLastDateStart, ttyClassOf } from "./login-origin.js";

const execFileAsync = promisify(execFile);

export const LOGIN_HISTORY_LIMIT = 50;
export const MAX_LOGIN_RECORDS = 256;
export const MAX_LOGINCTL_SESSIONS = 64;
const LOGINCTL_PROPERTIES = ["Id", "Name", "Remote", "RemoteHost", "Service", "Type", "Class", "TTY", "State", "IdleHint", "LockedHint"];

async function defaultRunFixedExecFile(command, args, options = {}) {
  return runResolvedExecFile(command, args, {
    ...options,
    timeout: options.timeout ?? 3000,
    maxBuffer: options.maxBuffer ?? 1024 * 1024,
    execFileAsync,
  });
}

function probeOptions(options) {
  const { runFixedExecFile: _drop, ...resolverOptions } = options;
  return resolverOptions;
}

function failureState(probe) {
  if (isBinaryNotFound(probe)) return "not_found_on_known_paths";
  if (isBinaryUntrusted(probe)) return "untrusted_binary";
  const text = `${probe?.stderr ?? ""}`.toLowerCase();
  if (probe?.code === "EACCES" || probe?.code === "EPERM" || /permission denied|operation not permitted/.test(text)) return "missing_permission";
  return "unable";
}

// ---------------------------------------------------------------------------------------------- who

const WHO_ROW_RE = /^(\S+)\s+(\S+)\s+([^(]*?)\s*(?:\((.+)\))?\s*$/;

/** who rows -> { user, tty, host, login_text } (login_text is identity material only, never a time). */
export function parseWhoRows(stdout) {
  const rows = [];
  let malformed = 0;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = WHO_ROW_RE.exec(line);
    if (!match) {
      malformed += 1;
      continue;
    }
    const [, user, tty, loginText, host] = match;
    rows.push({ user, tty, host: host || undefined, login_text: loginText.trim() });
  }
  return { rows, malformed };
}

// --------------------------------------------------------------------------------------------- last

/**
 * last rows -> { user, tty, host, login_text }. A row whose third token starts the date has no host
 * column (local). reboot/shutdown pseudo-rows and the wtmp trailer are skipped here (lifecycle rows
 * are a C2 fact). login_text is the 4-token login date ("Sun Oct 11 12:53"), used only for identity:
 * the logout/duration suffix changes after logout and must not make a row look new.
 */
export function parseLastRows(stdout) {
  const rows = [];
  let malformed = 0;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line || /^wtmp(x)? begins/i.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (/^(reboot|shutdown)$/i.test(tokens[0] ?? "")) continue;
    if (tokens.length < 6) {
      malformed += 1;
      continue;
    }
    const [user, tty] = tokens;
    const hostless = isLastDateStart(tokens[2], tokens[3]);
    const host = hostless ? undefined : tokens[2];
    const dateStart = hostless ? 2 : 3;
    const loginTokens = tokens.slice(dateStart, dateStart + 4);
    if (loginTokens.length < 4 || !isLastDateStart(loginTokens[0], loginTokens[1])) {
      malformed += 1;
      continue;
    }
    rows.push({ user, tty, host, login_text: loginTokens.join(" ") });
  }
  return { rows, malformed };
}

// ----------------------------------------------------------------------------------- ioreg (plist)

function decodeXmlText(text) {
  return text.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}

/**
 * A minimal, bounded XML plist reader for `ioreg -a` (dict / array / key / string / integer / real /
 * true / false / data / date). Throws SyntaxError on anything it does not understand: the caller
 * then reports the console source `unable`, never a guessed value.
 */
export function parsePlistXml(xml) {
  const tokens = String(xml ?? "").match(/<[^>]+>|[^<]+/g) ?? [];
  let index = 0;
  const next = () => tokens[index++];
  const skipWhitespace = () => {
    while (index < tokens.length && !tokens[index].startsWith("<") && tokens[index].trim() === "") index += 1;
  };
  function readText(close) {
    let text = "";
    while (index < tokens.length && tokens[index] !== close) {
      if (tokens[index].startsWith("<")) throw new SyntaxError("unexpected tag in plist text");
      text += tokens[index];
      index += 1;
    }
    if (next() !== close) throw new SyntaxError("unterminated plist element");
    return decodeXmlText(text);
  }
  function readValue() {
    skipWhitespace();
    const tag = next();
    if (tag === undefined) throw new SyntaxError("unexpected end of plist");
    if (tag === "<dict/>") return {};
    if (tag === "<array/>") return [];
    if (tag === "<true/>") return true;
    if (tag === "<false/>") return false;
    if (tag === "<string/>") return "";
    if (tag === "<dict>") {
      const dict = {};
      for (;;) {
        skipWhitespace();
        if (tokens[index] === "</dict>") {
          index += 1;
          return dict;
        }
        if (next() !== "<key>") throw new SyntaxError("plist dict without key");
        const key = readText("</key>");
        dict[key] = readValue();
      }
    }
    if (tag === "<array>") {
      const array = [];
      for (;;) {
        skipWhitespace();
        if (tokens[index] === "</array>") {
          index += 1;
          return array;
        }
        array.push(readValue());
      }
    }
    const simple = /^<(string|integer|real|data|date)>$/.exec(tag);
    if (simple) {
      const text = readText(`</${simple[1]}>`);
      if (simple[1] === "integer" || simple[1] === "real") {
        const value = Number(text.trim());
        if (!Number.isFinite(value)) throw new SyntaxError("bad plist number");
        return value;
      }
      return text;
    }
    throw new SyntaxError("unsupported plist element");
  }
  while (index < tokens.length && (tokens[index].startsWith("<?") || tokens[index].startsWith("<!") || tokens[index].trim() === "")) index += 1;
  if (next() !== '<plist version="1.0">') throw new SyntaxError("not an XML plist");
  return readValue();
}

/** ioreg IOConsoleUsers -> { users: [{ user, on_console, screen_locked }], console_locked }. */
export function parseConsoleUsers(xml) {
  const root = parsePlistXml(xml);
  const entries = Array.isArray(root) ? root : [root];
  const holder = entries.find((entry) => entry && typeof entry === "object" && Array.isArray(entry.IOConsoleUsers));
  if (!holder) throw new SyntaxError("no IOConsoleUsers array");
  return {
    users: holder.IOConsoleUsers
      .filter((user) => user && typeof user === "object")
      .map((user) => ({
        user: typeof user.kCGSSessionUserNameKey === "string" ? user.kCGSSessionUserNameKey : undefined,
        on_console: user.kCGSSessionOnConsoleKey === true,
        screen_locked: typeof user.CGSSessionScreenIsLocked === "boolean" ? user.CGSSessionScreenIsLocked : undefined,
      })),
    console_locked: typeof holder.IOConsoleLocked === "boolean" ? holder.IOConsoleLocked : undefined,
  };
}

// ----------------------------------------------------------------------------------------- loginctl

export function parseLoginctlSessionIds(stdout) {
  const ids = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const id = rawLine.trim().split(/\s+/)[0];
    if (id && /^[A-Za-z0-9_-]{1,32}$/.test(id)) ids.push(id);
  }
  return ids;
}

/** `loginctl show-session -p ... id1 id2` prints KEY=VALUE blocks separated by blank lines. */
export function parseLoginctlShowSession(stdout) {
  const sessions = [];
  let current = {};
  const flush = () => {
    if (Object.keys(current).length > 0) sessions.push(current);
    current = {};
  };
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) {
      flush();
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq);
    if (!LOGINCTL_PROPERTIES.includes(key)) continue;
    if (key === "Id" && current.Id !== undefined) flush();
    current[key] = line.slice(eq + 1);
  }
  flush();
  return sessions;
}

export function loginctlServiceClass(service) {
  const value = typeof service === "string" ? service.trim() : "";
  if (!value) return "none";
  if (value === "sshd") return "ssh";
  if (value === "login") return "local_login";
  if (/^(gdm|lightdm|sddm|xdm|lxdm|greetd)/.test(value)) return "display_manager";
  return "other";
}

/** logind fields -> origin class (Remote=yes is remote; a graphical Type is a local display). */
export function loginctlOrigin(session) {
  if (session.Remote === "yes") {
    return session.RemoteHost ? { origin_class: "remote", remote_host: session.RemoteHost } : { origin_class: "remote", remote_host: undefined };
  }
  if (session.Remote !== "no") return { origin_class: "unknown", remote_host: undefined };
  if (["x11", "wayland", "mir"].includes(session.Type)) return { origin_class: "local_display", remote_host: undefined };
  const ttyClass = ttyClassOf(session.TTY);
  if (ttyClass === "tty" || ttyClass === "pts") return { origin_class: "local_tty", remote_host: undefined };
  return { origin_class: "unknown", remote_host: undefined };
}

// --------------------------------------------------------------------------------------- collector

async function runWho(runExec, options) {
  const probe = await runExec("who", [], probeOptions(options));
  if (probe.status !== "ok") return { state: failureState(probe), rows: [] };
  const { rows, malformed } = parseWhoRows(probe.stdout);
  return { state: malformed > 0 ? "partial" : rows.length === 0 ? "absent" : "ok", rows };
}

async function runLast(runExec, options) {
  const probe = await runExec("last", ["-n", String(LOGIN_HISTORY_LIMIT)], probeOptions(options));
  if (probe.status !== "ok") return { state: failureState(probe), rows: [] };
  const { rows, malformed } = parseLastRows(probe.stdout);
  return { state: malformed > 0 ? "partial" : rows.length === 0 ? "absent" : "ok", rows };
}

async function runConsole(runExec, options) {
  const probe = await runExec("ioreg", ["-r", "-k", "IOConsoleUsers", "-d", "1", "-a"], probeOptions(options));
  if (probe.status !== "ok") return { state: failureState(probe) };
  try {
    return { state: "ok", ...parseConsoleUsers(probe.stdout) };
  } catch {
    return { state: "unable" };
  }
}

async function runLoginctl(runExec, options) {
  const list = await runExec("loginctl", ["list-sessions", "--no-legend", "--no-pager"], probeOptions(options));
  if (list.status !== "ok") return { state: failureState(list), sessions: [] };
  const allIds = parseLoginctlSessionIds(list.stdout);
  const ids = allIds.slice(0, MAX_LOGINCTL_SESSIONS);
  if (ids.length === 0) return { state: "absent", sessions: [] };
  const args = ["show-session", "--no-pager", ...LOGINCTL_PROPERTIES.flatMap((property) => ["-p", property]), ...ids];
  const show = await runExec("loginctl", args, probeOptions(options));
  if (show.status !== "ok") return { state: failureState(show), sessions: [] };
  const sessions = parseLoginctlShowSession(show.stdout);
  return { state: allIds.length > ids.length || sessions.length !== ids.length ? "partial" : "ok", sessions };
}

function boolHint(value) {
  return value === "yes" ? true : value === "no" ? false : undefined;
}

function aggregatePresenceFlag(values) {
  if (values.length === 0 || values.some((value) => value === undefined)) return values.length === 0 ? "not_applicable" : "unknown";
  return values.some(Boolean) ? "true" : "false";
}

export async function readLoginSessions(options = {}) {
  const platform = options.platform ?? process.platform;
  const runExec = options.runFixedExecFile ?? defaultRunFixedExecFile;
  const sources = { who: "not_applicable", last: "not_applicable", console: "not_applicable", loginctl: "not_applicable" };
  const records = [];
  const history = [];
  let presence = { screen_locked: "unknown", idle_hint: "unknown", source: "none" };

  if (platform === "darwin" || platform === "linux") {
    const last = await runLast(runExec, options);
    sources.last = last.state;
    for (const row of last.rows) {
      const { origin_class: originClass, remote_host: remoteHost } = classifyLoginOrigin(row);
      history.push({ user: row.user, tty_class: ttyClassOf(row.tty), origin_class: originClass, remote_host: remoteHost, identity: ["last", row.user, row.tty, row.host ?? "", row.login_text].join("\u0000") });
    }
  }

  if (platform === "darwin") {
    const who = await runWho(runExec, options);
    // C0 review L5: rows beyond the per-read cap are not records, so the census is partial (the
    // translator then reports the current count as unknown, never the truncated number).
    sources.who = who.state === "ok" && who.rows.length > MAX_LOGIN_RECORDS ? "partial" : who.state;
    for (const row of who.rows.slice(0, MAX_LOGIN_RECORDS)) {
      const { origin_class: originClass, remote_host: remoteHost } = classifyLoginOrigin(row);
      records.push({ source: "who", user: row.user, tty_class: ttyClassOf(row.tty), origin_class: originClass, service_class: "unknown", remote_host: remoteHost, identity: ["who", row.user, row.tty, row.host ?? "", row.login_text].join("\u0000") });
    }
    const consoleRead = await runConsole(runExec, options);
    sources.console = consoleRead.state === "ok" && consoleRead.users.length === 0 ? "absent" : consoleRead.state;
    if (consoleRead.state === "ok") {
      const onConsole = consoleRead.users.filter((user) => user.on_console);
      presence = {
        // The registry root's IOConsoleLocked, else the on-console users' own lock flags.
        screen_locked: typeof consoleRead.console_locked === "boolean"
          ? String(consoleRead.console_locked)
          : aggregatePresenceFlag(onConsole.map((user) => user.screen_locked)),
        idle_hint: "not_applicable",
        source: "io_console",
      };
    }
  } else if (platform === "linux") {
    const logind = await runLoginctl(runExec, options);
    sources.loginctl = logind.state;
    for (const session of logind.sessions.slice(0, MAX_LOGIN_RECORDS)) {
      const { origin_class: originClass, remote_host: remoteHost } = loginctlOrigin(session);
      records.push({
        source: "loginctl",
        user: session.Name,
        tty_class: ["x11", "wayland", "mir"].includes(session.Type) && !session.TTY ? "display" : ttyClassOf(session.TTY),
        origin_class: originClass,
        service_class: loginctlServiceClass(session.Service),
        remote_host: remoteHost,
        // A logind session id is a per-boot counter (F1): the daemon salts this identity with the boot.
        identity: ["loginctl", session.Id ?? "", session.Name ?? "", session.TTY ?? "", session.RemoteHost ?? "", session.Service ?? ""].join("\u0000"),
      });
    }
    const local = logind.sessions.filter((session) => session.Remote === "no" && session.State === "active");
    if (logind.state === "ok" || logind.state === "partial" || logind.state === "absent") {
      presence = {
        screen_locked: aggregatePresenceFlag(local.map((session) => boolHint(session.LockedHint))),
        idle_hint: aggregatePresenceFlag(local.map((session) => boolHint(session.IdleHint))),
        source: "loginctl",
      };
    }
  }

  const states = Object.values(sources).filter((state) => state !== "not_applicable");
  const usable = states.filter((state) => state === "ok" || state === "absent" || state === "partial");
  const status = states.length === 0 ? "not_applicable" : usable.length === states.length && states.every((state) => state !== "partial") ? "ok" : usable.length > 0 ? "partial" : "unable";
  return { platform, status, sources, records, history, presence };
}

export async function collectLoginSessionsEvidence(options = {}) {
  return timedEnvelope(async () => readLoginSessions(options), (result) => evidenceEnvelope({
    id: "login-sessions",
    status: result.status === "ok" ? "ok" : result.status === "partial" ? "warning" : "unable",
    source: "login_sessions",
    result,
    confidence: result.status === "ok" ? 1 : result.status === "partial" ? 0.5 : 0,
    reviewHint: "none",
    tool: "collect_login_sessions",
    target: `history=${LOGIN_HISTORY_LIMIT}`,
  }));
}
