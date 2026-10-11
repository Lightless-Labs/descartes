import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  collectLoginSessionsEvidence,
  loginctlOrigin,
  loginctlServiceClass,
  parseConsoleUsers,
  parseLastRows,
  parseLoginctlSessionIds,
  parseLoginctlShowSession,
  parsePlistXml,
  parseWhoRows,
  readLoginSessions,
} from "../src/tools/login-sessions.js";
import { LOGIN_SEEN_CAP, LOGIN_SEEN_VERSION, loginRowDigest, readLoginSeen, resolveLoginSeenPath, selectNewLoginRows, writeLoginSeen } from "../src/login-seen.js";
import { CONTEXT_KEY_BYTES, contextHmac, contextKeyId } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { factPointsFromLoginSessionsEvidence, MAX_LOGIN_ARRIVALS_PER_TICK } from "../src/context-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";

// Real outputs captured on the Darwin 25.2 dev VM (2026-10-11); remote IPs are tailnet addresses.
const WHO_REAL = [
  "thomas           console      Sep  4 16:17 ",
  "thomas           ttys000      Sep  4 16:18 ",
  "thomas           ttys001      Sep  4 16:18 ",
  "thomas           ttys037      Oct 11 12:53 (100.64.118.39)",
  "",
].join("\n");
const LAST_REAL = [
  "thomas     ttys037  100.64.118.39          Sun Oct 11 12:53   still logged in",
  "thomas     ttys037  100.113.174.105        Sat Oct 10 17:42 - 18:14  (00:31)",
  "thomas     ttys001                         Fri Sep  4 16:18   still logged in",
  "reboot time                                Fri Sep  4 16:10",
  "",
  "wtmp begins Fri Sep  4 16:10:30 2026",
].join("\n");
const IOREG_REAL = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>IOConsoleLocked</key>
		<true/>
		<key>IOConsoleUsers</key>
		<array>
			<dict>
				<key>CGSSessionScreenIsLocked</key>
				<true/>
				<key>CGSSessionScreenLockedTime</key>
				<integer>1788538677</integer>
				<key>kCGSSessionOnConsoleKey</key>
				<true/>
				<key>kCGSSessionUserNameKey</key>
				<string>thomas</string>
			</dict>
		</array>
		<key>IOKitDiagnostics</key>
		<dict>
			<key>Classes</key>
			<dict>
				<key>ACMKernelService</key>
				<integer>6</integer>
			</dict>
		</dict>
	</dict>
</array>
</plist>
`;

function scripted(map, calls = []) {
  return async (command, args = []) => {
    const key = [command, ...args].join(" ");
    calls.push(key);
    const handler = Object.entries(map).find(([prefix]) => key.startsWith(prefix));
    if (!handler) return { status: "not_found_on_known_paths", availability: "not_found_on_known_paths", stdout: "" };
    return typeof handler[1] === "function" ? handler[1](args) : handler[1];
  };
}
const ok = (stdout) => ({ status: "ok", stdout, stderr: "" });

test("parsers: who rows, last rows (login date only, hostless local rows), plist console users", () => {
  const who = parseWhoRows(WHO_REAL);
  assert.deepEqual(who.rows.map((r) => [r.user, r.tty, r.host ?? null, r.login_text]), [
    ["thomas", "console", null, "Sep  4 16:17"],
    ["thomas", "ttys000", null, "Sep  4 16:18"],
    ["thomas", "ttys001", null, "Sep  4 16:18"],
    ["thomas", "ttys037", "100.64.118.39", "Oct 11 12:53"],
  ]);
  const last = parseLastRows(LAST_REAL);
  assert.equal(last.malformed, 0);
  assert.deepEqual(last.rows.map((r) => [r.tty, r.host ?? null, r.login_text]), [
    ["ttys037", "100.64.118.39", "Sun Oct 11 12:53"],
    ["ttys037", "100.113.174.105", "Sat Oct 10 17:42"],
    ["ttys001", null, "Fri Sep 4 16:18"],
  ]);
  const consoleUsers = parseConsoleUsers(IOREG_REAL);
  assert.deepEqual(consoleUsers, { users: [{ user: "thomas", on_console: true, screen_locked: true }], console_locked: true });
  assert.throws(() => parsePlistXml("<plist version=\"1.0\"><dict><string>x</string></dict></plist>"), SyntaxError);
  assert.throws(() => parseConsoleUsers('<?xml version="1.0"?><plist version="1.0"><array><dict/></array></plist>'), SyntaxError);
});

test("C0.4 last identity ignores the logout suffix: a session that ends is not a new row", () => {
  const before = parseLastRows("alice pts/1 203.0.113.9 Sun Oct 11 12:53   still logged in\n").rows[0];
  const after = parseLastRows("alice pts/1 203.0.113.9 Sun Oct 11 12:53 - 14:00  (01:07)\n").rows[0];
  assert.equal(before.login_text, after.login_text);
});

test("C0.4 darwin collector: who + IOConsoleUsers + bounded last, each through the fixed argv; origins classified", async () => {
  const calls = [];
  const result = await readLoginSessions({
    platform: "darwin",
    runFixedExecFile: scripted({ "who": ok(WHO_REAL), "last -n 50": ok(LAST_REAL), "ioreg -r -k IOConsoleUsers -d 1 -a": ok(IOREG_REAL) }, calls),
  });
  assert.deepEqual(calls, ["last -n 50", "who", "ioreg -r -k IOConsoleUsers -d 1 -a"]);
  assert.equal(result.status, "ok");
  assert.deepEqual(result.sources, { who: "ok", last: "ok", console: "ok", loginctl: "not_applicable" });
  assert.deepEqual(result.records.map((r) => [r.origin_class, r.tty_class, r.remote_host ?? null]), [
    ["console", "console", null], ["local_tty", "ttys", null], ["local_tty", "ttys", null], ["remote", "ttys", "100.64.118.39"],
  ]);
  assert.deepEqual(result.history.map((r) => r.origin_class), ["remote", "remote", "local_tty"]);
  assert.deepEqual(result.presence, { screen_locked: "true", idle_hint: "not_applicable", source: "io_console" });
});

test("C0.4 darwin: a missing ioreg leaves presence unknown and the census partial; a failed who is never an empty login list", async () => {
  const result = await readLoginSessions({ platform: "darwin", runFixedExecFile: scripted({ "who": { status: "error", code: 1, stdout: "", stderr: "boom" }, "last -n 50": ok(LAST_REAL) }) });
  assert.equal(result.sources.who, "unable");
  assert.equal(result.sources.console, "not_found_on_known_paths");
  assert.equal(result.status, "partial");
  assert.deepEqual(result.records, []);
  assert.deepEqual(result.presence, { screen_locked: "unknown", idle_hint: "unknown", source: "none" });
});

const LOGINCTL_LIST = "     2 1000 alice seat0 tty2\n     5 1000 alice       pts/0\n     7 1001 bob         \n";
const LOGINCTL_SHOW = [
  "Id=2", "Name=alice", "Remote=no", "RemoteHost=", "Service=gdm-password", "Type=wayland", "Class=user", "TTY=tty2", "State=active", "IdleHint=no", "LockedHint=yes", "",
  "Id=5", "Name=alice", "Remote=yes", "RemoteHost=203.0.113.4", "Service=sshd", "Type=tty", "Class=user", "TTY=pts/0", "State=active", "IdleHint=no", "LockedHint=no", "",
  "Id=7", "Name=bob", "Remote=no", "RemoteHost=", "Service=login", "Type=tty", "Class=user", "TTY=tty3", "State=online", "IdleHint=yes", "LockedHint=no", "",
].join("\n");

test("C0.4 linux collector: loginctl list + ONE show-session with fixed properties; Remote/RemoteHost/Service/Type/Class/TTY/Idle/Locked", async () => {
  const calls = [];
  const result = await readLoginSessions({
    platform: "linux",
    runFixedExecFile: scripted({ "loginctl list-sessions --no-legend --no-pager": ok(LOGINCTL_LIST), "loginctl show-session": ok(LOGINCTL_SHOW), "last -n 50": ok("") }, calls),
  });
  assert.equal(calls.filter((c) => c.startsWith("loginctl show-session")).length, 1);
  assert.match(calls.find((c) => c.startsWith("loginctl show-session")), / 2 5 7$/);
  assert.deepEqual(result.sources, { who: "not_applicable", last: "absent", console: "not_applicable", loginctl: "ok" });
  assert.deepEqual(result.records.map((r) => [r.origin_class, r.tty_class, r.service_class, r.remote_host ?? null]), [
    ["local_display", "tty", "display_manager", null],
    ["remote", "pts", "ssh", "203.0.113.4"],
    ["local_tty", "tty", "local_login", null],
  ]);
  assert.deepEqual(result.presence, { screen_locked: "true", idle_hint: "false", source: "loginctl" });
});

test("C0.4 linux parsers and classes", () => {
  assert.deepEqual(parseLoginctlSessionIds(LOGINCTL_LIST), ["2", "5", "7"]);
  assert.equal(parseLoginctlShowSession(LOGINCTL_SHOW).length, 3);
  assert.deepEqual(["sshd", "login", "gdm-password", "lightdm", "", "cron"].map(loginctlServiceClass), ["ssh", "local_login", "display_manager", "display_manager", "none", "other"]);
  assert.deepEqual(loginctlOrigin({ Remote: "yes", RemoteHost: "" }), { origin_class: "remote", remote_host: undefined });
  assert.deepEqual(loginctlOrigin({}), { origin_class: "unknown", remote_host: undefined });
});

test("collectLoginSessionsEvidence wraps the read in a login-sessions envelope", async () => {
  const envelope = await collectLoginSessionsEvidence({ platform: "sunos" });
  assert.equal(envelope.id, "login-sessions");
  assert.equal(envelope.result.status, "not_applicable");
});

// --- first-observed-tick dedupe ---

const DEDUPE_KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 7);

test("C0.4 dedupe: a row is new only at its first observed tick; logind ids are scoped to the boot; loss re-emits as reseeded", () => {
  const result = { records: [{ source: "who", identity: "who\u0000a" }, { source: "loginctl", identity: "loginctl\u00005" }], history: [{ identity: "last\u0000x" }] };
  const first = selectNewLoginRows(null, result, { nowMs: 1000, bootSalt: "boot1", hmacKey: DEDUPE_KEY });
  assert.equal(first.dedupeState, "reseeded");
  assert.equal(first.newRecords.length, 2);
  assert.equal(first.newHistory.length, 1);
  const second = selectNewLoginRows(first.next, result, { nowMs: 2000, bootSalt: "boot1", hmacKey: DEDUPE_KEY });
  assert.equal(second.dedupeState, "fresh");
  assert.equal(second.newRecords.length, 0, "a repeated sighting is not a repeated login");
  assert.equal(second.newHistory.length, 0);
  const rebooted = selectNewLoginRows(second.next, result, { nowMs: 3000, bootSalt: "boot2", hmacKey: DEDUPE_KEY });
  assert.deepEqual(rebooted.newRecords.map((r) => r.source), ["loginctl"], "a logind id in a new boot is a new login (F1: per-boot counter)");
  assert.equal(rebooted.next.records[loginRowDigest(DEDUPE_KEY, "who\u0000a")], 3000);
});

test("C0 review M5: without a boot salt logind rows cannot be scoped to their boot, so there is no dedupe that tick (never a cross-boot merge); who-only rows still dedupe", () => {
  const logind = { records: [{ source: "loginctl", identity: "loginctl\u00005" }], history: [{ identity: "last\u0000x" }] };
  assert.equal(selectNewLoginRows(null, logind, { nowMs: 1, hmacKey: DEDUPE_KEY }), undefined);
  assert.equal(selectNewLoginRows(null, logind, { nowMs: 1, hmacKey: DEDUPE_KEY, bootSalt: "" }), undefined);
  const who = { records: [{ source: "who", identity: "who\u0000a" }], history: [] };
  assert.equal(selectNewLoginRows(null, who, { nowMs: 1, hmacKey: DEDUPE_KEY }).newRecords.length, 1);
});

test("C0 review L4: row digests are keyed (no dictionary reversal of user/tty/host/time); no usable key means no dedupe at all, never an unkeyed digest", () => {
  const identity = "who\u0000alice\u0000ttys003\u0000203.0.113.9\u0000Oct 11 12:00";
  const keyed = loginRowDigest(DEDUPE_KEY, identity);
  assert.match(keyed, /^[0-9a-f]{32}$/);
  assert.notEqual(keyed, loginRowDigest(Buffer.alloc(CONTEXT_KEY_BYTES, 8), identity), "a different install key gives a different digest");
  const unkeyed = crypto.createHash("sha256").update(`descartes.login_row.v1\u0000\u0000${identity}`).digest("hex").slice(0, 32);
  assert.notEqual(keyed, unkeyed);
  assert.equal(loginRowDigest(undefined, identity), undefined);
  assert.equal(selectNewLoginRows(null, { records: [{ source: "who", identity }], history: [] }, { nowMs: 1, hmacKey: undefined }), undefined);
});

test("C0 review M7: the seen-state records the key id; a re-keyed install re-emits as reseeded, never as fresh arrivals", () => {
  const result = { records: [{ source: "who", identity: "who\u0000a" }], history: [] };
  const first = selectNewLoginRows(null, result, { nowMs: 1, hmacKey: DEDUPE_KEY });
  assert.equal(first.next.key_id, contextKeyId(DEDUPE_KEY));
  const rekeyed = selectNewLoginRows(first.next, result, { nowMs: 2, hmacKey: Buffer.alloc(CONTEXT_KEY_BYTES, 8) });
  assert.equal(rekeyed.dedupeState, "reseeded");
  assert.equal(rekeyed.newRecords.length, 1);
  assert.deepEqual(Object.keys(rekeyed.next.records).length, 1, "the old key's digests are dropped, not carried");
});

test("C0.4 dedupe state is bounded and aged; the file is 0600 and a corrupt (or pre-key v1) file reads as corrupt", async () => {
  const many = { records: Array.from({ length: LOGIN_SEEN_CAP + 20 }, (_, i) => ({ source: "who", identity: `who\u0000${i}` })), history: [] };
  const { next } = selectNewLoginRows(null, many, { nowMs: 5, hmacKey: DEDUPE_KEY });
  assert.equal(Object.keys(next.records).length, LOGIN_SEEN_CAP);
  const aged = selectNewLoginRows({ version: LOGIN_SEEN_VERSION, key_id: contextKeyId(DEDUPE_KEY), records: { [loginRowDigest(DEDUPE_KEY, "old")]: 0 }, history: {} }, { records: [], history: [] }, { nowMs: 31 * 24 * 3600 * 1000, hmacKey: DEDUPE_KEY });
  assert.deepEqual(aged.next.records, {});
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-login-seen-"));
  const paths = resolveDescartesPaths({ HOME: root, XDG_STATE_HOME: path.join(root, "s"), XDG_CONFIG_HOME: path.join(root, "c"), XDG_DATA_HOME: path.join(root, "d"), XDG_CACHE_HOME: path.join(root, "x") });
  assert.equal((await readLoginSeen(paths)).status, "missing");
  await writeLoginSeen(paths, next);
  assert.equal((await fs.stat(resolveLoginSeenPath(paths))).mode & 0o777, 0o600);
  assert.equal((await readLoginSeen(paths)).status, "ok");
  await fs.writeFile(resolveLoginSeenPath(paths), JSON.stringify({ version: 1, records: {}, history: {} }));
  assert.equal((await readLoginSeen(paths)).status, "corrupt", "an unkeyed v1 state is not reused");
  await fs.writeFile(resolveLoginSeenPath(paths), "{");
  assert.equal((await readLoginSeen(paths)).status, "corrupt");
});

// --- translator ---

const KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 9);
const TS = "2026-10-11T12:00:00.000Z";

test("C0.4 translator: arrivals at their first-observed tick with every identifying value HMAC'd; census and presence each tick", async () => {
  const result = await readLoginSessions({ platform: "darwin", runFixedExecFile: scripted({ "who": ok(WHO_REAL), "last -n 50": ok(LAST_REAL), "ioreg -r -k IOConsoleUsers -d 1 -a": ok(IOREG_REAL) }) });
  const envelope = { id: "login-sessions", status: "ok", result, observation: { start_ms: 10, end_ms: 20 } };
  const dedupe = selectNewLoginRows({ version: LOGIN_SEEN_VERSION, key_id: contextKeyId(KEY), records: {}, history: {} }, result, { nowMs: 1, hmacKey: KEY });
  const points = factPointsFromLoginSessionsEvidence([envelope], { ts: TS, hmacKey: KEY, dedupe });
  for (const point of points) assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true }, `${point.fact_name} ${JSON.stringify(point.attributes)}`);
  const records = points.filter((p) => p.fact_name === "session.login_record");
  assert.equal(records.length, 4);
  const remote = records.find((p) => p.attributes.origin_class === "remote");
  assert.equal(remote.attributes.remote_host_hmac, contextHmac(KEY, "login_remote_host", "100.64.118.39"));
  assert.equal(records.find((p) => p.attributes.origin_class === "console").attributes.remote_host_hmac, "none");
  assert.ok(!JSON.stringify(points).includes("thomas") && !JSON.stringify(points).includes("100.64.118.39"), "no raw user or host reaches a fact");
  const census = points.find((p) => p.fact_name === "session.login_census");
  assert.deepEqual(
    [census.attributes.who_state, census.attributes.current_count, census.attributes.arrivals_emitted, census.attributes.history_emitted, census.attributes.dedupe_state],
    ["ok", "4", "4", "3", "fresh"],
  );
  assert.equal(points.find((p) => p.fact_name === "user.presence").attributes.screen_locked, "true");
});

test("C0.4 translator: arrivals beyond the per-tick cap are counted as overflow; no dedupe selection emits no rows and says unavailable", () => {
  const records = Array.from({ length: MAX_LOGIN_ARRIVALS_PER_TICK + 3 }, (_, i) => ({ source: "who", user: "u", origin_class: "remote", tty_class: "pts", remote_host: `h${i}`, identity: `who\u0000${i}` }));
  const result = { platform: "darwin", status: "ok", sources: { who: "ok", last: "absent", console: "ok", loginctl: "not_applicable" }, records, history: [], presence: {} };
  const envelope = { id: "login-sessions", status: "ok", result };
  const dedupe = selectNewLoginRows(null, result, { nowMs: 1, hmacKey: KEY });
  const points = factPointsFromLoginSessionsEvidence([envelope], { ts: TS, hmacKey: KEY, dedupe });
  assert.equal(points.filter((p) => p.fact_name === "session.login_record").length, MAX_LOGIN_ARRIVALS_PER_TICK);
  const census = points.find((p) => p.fact_name === "session.login_census");
  assert.equal(census.attributes.arrivals_overflow, "3");
  assert.equal(census.attributes.dedupe_state, "reseeded");
  const none = factPointsFromLoginSessionsEvidence([envelope], { ts: TS, hmacKey: KEY });
  assert.deepEqual(none.map((p) => p.fact_name), ["session.login_census", "user.presence"]);
  assert.equal(none[0].attributes.dedupe_state, "unavailable");
  assert.equal(none[0].attributes.arrivals_emitted, "0");
});
