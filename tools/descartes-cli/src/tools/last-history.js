import { isLastDateStart } from "./login-origin.js";
import { finalizeCensus } from "./census-validate.js";
import { throwIfCollectorAborted } from "./collector-abort.js";

const LAST_PSEUDO_USER_RE = /^(reboot|shutdown)$/i;

/** Shared bounded `last` parser used by both peer and login collectors. */
export function parseLastRows(stdout) {
  if (typeof stdout !== "string") return { rows: [], malformed: 1 };
  const rows = [];
  let malformed = 0;
  let raw_count = 0;
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (!line || /^wtmp(x)? begins/i.test(line)) continue;
    raw_count += 1;
    const tokens = line.split(/\s+/);
    if (LAST_PSEUDO_USER_RE.test(tokens[0] ?? "")) continue;
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
  const census = finalizeCensus({ records: rows, identity: (row) => JSON.stringify([row.user, row.tty, row.host, row.login_text]), malformed });
  return { rows, malformed, raw_count, duplicate_count: census.duplicate_count };
}

// Context plan C2 (§4.1 host.lifecycle_record): the reboot/shutdown rows of the SAME `last` output
// (parseLastRows above skips them for the login census; this reads them, it never changes that).
// Anchored full-line grammars only; a row that starts like a lifecycle row but does not match is
// malformed, never guessed. `last` prints no year, so a row's time is a local minute without a year
// (its time confidence), never parsed into an instant.
const LAST_DOW = "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)";
const LAST_MON = "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";
const LAST_DAY = "(?:[1-9]|[12][0-9]|3[01])";
const LAST_HM = "(?:[01][0-9]|2[0-3]):[0-5][0-9]";
const LAST_START = `(${LAST_DOW}) +(${LAST_MON}) +(${LAST_DAY}) +(${LAST_HM})`;
// macOS: "reboot time                                Fri Sep  4 16:10" (older releases print "~").
const DARWIN_LIFECYCLE_RE = new RegExp(`^(reboot|shutdown) +(?:time|~) +${LAST_START}$`);
// Linux wtmp: "reboot   system boot  6.8.0-45-generic Mon Oct  6 08:01   still running" or
// "... Sun Oct  5 22:10 - 08:00  (09:49)" / "- crash" / "- down"; shutdown rows ("system down") only
// appear with `last -x`, which the shared probe does not pass (C2 deviation: Linux shutdown rows are
// not observed).
const LINUX_LIFECYCLE_RE = new RegExp(`^(reboot|shutdown) +system (?:boot|down) +([A-Za-z0-9][A-Za-z0-9._+~-]{0,63}) +${LAST_START}(?: +(?:(still running)|- +(?:(crash|down)|(${LAST_HM}))(?: +\\(((?:[0-9]{1,4}\\+)?${LAST_HM})\\))?))?$`);
const LIFECYCLE_PREFIX_RE = /^(reboot|shutdown)(\s|$)/i;

/** `last` stdout -> { rows: [{ kind, start_text, end_state, duration_text, os_release, identity }], malformed, duplicate_count, raw_count }. */
export function parseLastLifecycleRows(stdout) {
  if (typeof stdout !== "string") return { rows: [], malformed: 1, duplicate_count: 0, raw_count: 0 };
  const rows = [];
  let malformed = 0;
  let raw_count = 0;
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (!LIFECYCLE_PREFIX_RE.test(line)) continue;
    raw_count += 1;
    const darwin = DARWIN_LIFECYCLE_RE.exec(line);
    const linux = darwin ? undefined : LINUX_LIFECYCLE_RE.exec(line);
    if (!darwin && !linux) {
      malformed += 1;
      continue;
    }
    const [kind, dow, mon, day, hm] = darwin ? [darwin[1], darwin[2], darwin[3], darwin[4], darwin[5]] : [linux[1], linux[3], linux[4], linux[5], linux[6]];
    const startText = `${dow} ${mon} ${day} ${hm}`;
    let endState = "none";
    let durationText = "none";
    if (linux) {
      if (linux[7]) endState = "still_running";
      else if (linux[8]) endState = linux[8];
      else if (linux[9]) endState = "ended";
      if (linux[10]) durationText = linux[10];
    }
    const osRelease = linux ? linux[2] : "none";
    rows.push({ kind, start_text: startText, end_state: endState, duration_text: durationText, os_release: osRelease, identity: ["lifecycle", kind, startText, osRelease].join("\u0000") });
  }
  // Every other line must be a well-formed login row (or header): a lifecycle census over output the
  // login grammar cannot read is not "no reboot rows", it is partial.
  const loginMalformed = parseLastRows(stdout).malformed;
  const totalMalformed = malformed + (Number.isSafeInteger(loginMalformed) ? loginMalformed : 1);
  const census = finalizeCensus({ records: rows, identity: (row) => row.identity, malformed: totalMalformed });
  return { rows, malformed: totalMalformed, duplicate_count: census.duplicate_count, raw_count };
}

/** Run one bounded `last` probe per shared structural-tick cache and share its parsed rows. */
export async function readSharedLastHistory(options, runExec, probeOptions, limit) {
  const cache = options.lastHistoryCache;
  const run = async () => {
    throwIfCollectorAborted(options.signal);
    const probe = await runExec("last", ["-n", String(limit)], probeOptions);
    const parsed = parseLastRows(probe.stdout);
    return { probe, ...parsed, truncated: parsed.raw_count >= limit };
  };
  if (!cache) return run();
  if (cache.lastHistoryLimit !== limit || !cache.lastHistoryPromise) {
    cache.lastHistoryLimit = limit;
    cache.lastHistoryPromise = run();
  }
  return cache.lastHistoryPromise;
}
