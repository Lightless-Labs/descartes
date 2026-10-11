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
