// C0.5 / C0.6 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3): the per-install HMAC key
// for context facts.
//
// Context values that identify a place, a network, a peer host or a user (gateway MAC, DHCP domain,
// resolvers, RA prefix, the tailnet name, a login's remote host, the boot id) are HMAC'd at source,
// so fact history holds no reversible value: an unkeyed hash of a gateway MAC or a /64 prefix is
// trivially brute-forced, a keyed one is not without the key.
//
// The key:
//   - lives OUTSIDE fact history (stateDir/keys/context-hmac.key, never under learned/facts/), so a
//     copied or exported fact store does not carry it;
//   - is created once per install from crypto.randomBytes(32), in a 0700 directory, as a 0600 file,
//     by tmp-write + link (never clobbers a concurrent creator's key) ;
//   - is NEVER federated, uploaded, logged or included in any diagnostics bundle. Nothing outside this
//     module reads the file.
//
// Degrade, never fabricate: a key that is unreadable, of the wrong size, not a regular file, owned by
// another uid or readable by group/other is reported `unable` (with a closed reason). Callers then
// emit "unknown" for every keyed value. They never fall back to an unkeyed hash or a zero key.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export const CONTEXT_KEY_BYTES = 32;
export const CONTEXT_HMAC_HEX_LENGTH = 16;

export function resolveContextKeyPath(descartesPaths) {
  return path.join(descartesPaths.stateDir, "keys", "context-hmac.key");
}

async function inspectKeyFile(file, { expectedUid }) {
  let stat;
  try {
    stat = await fs.lstat(file);
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "missing" };
    return { status: "unable", reason: "stat_failed" };
  }
  if (!stat.isFile()) return { status: "unable", reason: "not_a_regular_file" };
  if ((stat.mode & 0o077) !== 0) return { status: "unable", reason: "mode_too_wide" };
  if (expectedUid !== undefined && stat.uid !== expectedUid) return { status: "unable", reason: "foreign_owner" };
  if (stat.size !== CONTEXT_KEY_BYTES) return { status: "unable", reason: "wrong_size" };
  let key;
  try {
    key = await fs.readFile(file);
  } catch {
    return { status: "unable", reason: "read_failed" };
  }
  if (key.length !== CONTEXT_KEY_BYTES) return { status: "unable", reason: "wrong_size" };
  return { status: "ok", key };
}

/**
 * Returns { status: "ok", key, created } or { status: "unable", reason }. Creates the key on first
 * use. Never throws for an I/O fault.
 */
export async function loadOrCreateContextKey(descartesPaths, options = {}) {
  const expectedUid = options.expectedUid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  const file = resolveContextKeyPath(descartesPaths);
  const existing = await inspectKeyFile(file, { expectedUid });
  if (existing.status !== "missing") return existing.status === "ok" ? { status: "ok", key: existing.key, created: false } : existing;

  const dir = path.dirname(file);
  try {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const dirStat = await fs.lstat(dir);
    if (!dirStat.isDirectory() || (dirStat.mode & 0o077) !== 0) return { status: "unable", reason: "key_dir_mode_too_wide" };
  } catch {
    return { status: "unable", reason: "key_dir_unavailable" };
  }
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    await fs.writeFile(tmp, crypto.randomBytes(CONTEXT_KEY_BYTES), { mode: 0o600, flag: "wx" });
    try {
      await fs.link(tmp, file); // fails with EEXIST if another creator won the race: keep theirs
    } catch (error) {
      if (error?.code !== "EEXIST") return { status: "unable", reason: "key_create_failed" };
    }
  } catch {
    return { status: "unable", reason: "key_create_failed" };
  } finally {
    await fs.unlink(tmp).catch(() => {});
  }
  const created = await inspectKeyFile(file, { expectedUid });
  return created.status === "ok" ? { status: "ok", key: created.key, created: true } : created.status === "missing" ? { status: "unable", reason: "key_create_failed" } : created;
}

/**
 * Domain-separated, keyed, truncated HMAC-SHA256 (16 hex chars, the width every hash-at-source
 * scheme in fact-translators.js uses). Returns "unknown" when no usable key is supplied or the value
 * is not a non-empty string: never an unkeyed hash, never a placeholder that looks like a real one.
 */
export function contextHmac(key, domain, value) {
  if (!Buffer.isBuffer(key) || key.length !== CONTEXT_KEY_BYTES) return "unknown";
  if (typeof value !== "string" || value.length === 0) return "unknown";
  return crypto.createHmac("sha256", key).update(`descartes.context.${domain}.v1\u0000${value}`).digest("hex").slice(0, CONTEXT_HMAC_HEX_LENGTH);
}
