// Context plan C0.4 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.3; Astra 12):
// first-observed-tick dedupe for login rows.
//
// `who`/`loginctl` re-list the same logins and `last` re-reads the same history rows on every tick.
// A repeated sighting is not a repeated login: a row is recorded once, at the FIRST tick it is
// observed (never at a parsed login time), keyed by a digest of its identity (row digest).
//
// The seen-state is a small bounded local file (stateDir/daemon/login-seen.json, 0600, atomic). It
// holds digests only. Losing it is never silence: the next tick re-emits the rows it sees, marked
// `dedupe_state: reseeded`, a visible burst bounded by the per-tick emission caps.
//
// C0 review L4: a row identity (user, tty, host, login time) has little entropy, so an unkeyed hash
// of it is reversible by dictionary. Row digests are HMACs under the per-install context key
// (context-key.js); the state records that key's id, and a state made under another key (or the
// unkeyed v1 format) is not reused: the rows re-emit as `reseeded`. Without a usable key there is
// no dedupe at all (the caller records `dedupe_state: unavailable` and emits no row), never an
// unkeyed digest.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { CONTEXT_KEY_BYTES, contextKeyId } from "./context-key.js";

export const LOGIN_SEEN_VERSION = 2;
export const LOGIN_SEEN_CAP = 512;
// A digest not seen for this long is dropped (a resource bound, class S; `last -n 50` and the
// current logins are re-read every tick, so a still-present row is never dropped by age).
export const LOGIN_SEEN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

const DIGEST_RE = /^[0-9a-f]{32}$/;
const KEY_ID_RE = /^[0-9a-f]{16}$/;

export function resolveLoginSeenPath(descartesPaths) {
  return path.join(descartesPaths.stateDir, "daemon", "login-seen.json");
}

/** Keyed row digest (32 hex), or undefined without a usable key or identity. */
export function loginRowDigest(hmacKey, identity, salt = "") {
  if (!Buffer.isBuffer(hmacKey) || hmacKey.length !== CONTEXT_KEY_BYTES || typeof identity !== "string") return undefined;
  return crypto.createHmac("sha256", hmacKey).update(`descartes.login_row.v2\u0000${salt}\u0000${identity}`).digest("hex").slice(0, 32);
}

function validMap(map) {
  return Boolean(map) && typeof map === "object" && !Array.isArray(map)
    && Object.keys(map).length <= LOGIN_SEEN_CAP
    && Object.entries(map).every(([digest, ms]) => DIGEST_RE.test(digest) && Number.isSafeInteger(ms));
}

/** { status: "ok" | "missing" | "corrupt", seen } (seen is null unless ok). */
export async function readLoginSeen(descartesPaths) {
  let contents;
  try {
    contents = await fs.readFile(resolveLoginSeenPath(descartesPaths), "utf8");
  } catch (error) {
    return { status: error?.code === "ENOENT" ? "missing" : "corrupt", seen: null };
  }
  try {
    const parsed = JSON.parse(contents);
    if (parsed?.version !== LOGIN_SEEN_VERSION || !KEY_ID_RE.test(parsed.key_id ?? "") || !validMap(parsed.records) || !validMap(parsed.history)) return { status: "corrupt", seen: null };
    return { status: "ok", seen: parsed };
  } catch {
    return { status: "corrupt", seen: null };
  }
}

export async function writeLoginSeen(descartesPaths, seen) {
  const file = resolveLoginSeenPath(descartesPaths);
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(seen), { mode: 0o600 });
  await fs.rename(tmp, file);
}

function prune(map, nowMs) {
  const kept = Object.entries(map).filter(([, ms]) => nowMs - ms <= LOGIN_SEEN_RETENTION_MS);
  kept.sort((a, b) => b[1] - a[1]); // newest first; the oldest are dropped at the cap
  return Object.fromEntries(kept.slice(0, LOGIN_SEEN_CAP));
}

/**
 * Pure. Given the loaded seen-state (null when missing/corrupt) and this tick's login-sessions
 * result, returns the rows observed for the first time, their digests, the next seen-state and the
 * dedupe state ("fresh" | "reseeded"), or undefined when no usable key was supplied (no dedupe is
 * possible: the caller emits no row). A seen-state made under another key id is not reused
 * ("reseeded"). `bootSalt` scopes logind session ids, which are per-boot counters (F1): the same id
 * in a new boot is a new login.
 */
export function selectNewLoginRows(seen, result, { nowMs, bootSalt = "", hmacKey } = {}) {
  const keyId = contextKeyId(hmacKey);
  if (keyId === "unknown") return undefined;
  const usable = seen && seen.key_id === keyId ? seen : null;
  const dedupeState = usable ? "fresh" : "reseeded";
  const records = { ...(usable?.records ?? {}) };
  const history = { ...(usable?.history ?? {}) };
  const newRecords = [];
  const newHistory = [];
  for (const record of result?.records ?? []) {
    const digest = loginRowDigest(hmacKey, record.identity, record.source === "loginctl" ? bootSalt : "");
    if (!digest) continue;
    if (records[digest] === undefined) newRecords.push({ ...record, digest });
    records[digest] = nowMs;
  }
  for (const row of result?.history ?? []) {
    const digest = loginRowDigest(hmacKey, row.identity);
    if (!digest) continue;
    if (history[digest] === undefined) newHistory.push({ ...row, digest });
    history[digest] = nowMs;
  }
  return {
    newRecords,
    newHistory,
    dedupeState,
    next: { version: LOGIN_SEEN_VERSION, key_id: keyId, records: prune(records, nowMs), history: prune(history, nowMs) },
  };
}
