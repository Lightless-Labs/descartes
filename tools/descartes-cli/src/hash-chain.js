// Shared append-only, hash-chained JSONL primitives (context plan C1.1/C1.4: the alert transition
// log and the pending journal). Tamper-EVIDENT at the daemon's UID, not tamper-proof: a same-UID
// writer can rewrite a whole chain, but cannot edit, drop or reorder a record without a break the
// reader detects.
//
// Record shape: { ...body, seq, prev_hash, hash }, hash = sha256(domain \0 canonicalJson(record
// without hash)). The first record of a chain cites prev_hash "genesis" or a declared cut marker.
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export const GENESIS_PREV_HASH = "genesis";

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value ?? null);
}

export function recordHash(domain, recordWithoutHash) {
  return crypto.createHash("sha256").update(`${domain}\u0000${canonicalJson(recordWithoutHash)}`).digest("hex");
}

export function sealRecord(domain, { prevHash, seq }, body) {
  const { hash: _ignored, ...rest } = body ?? {};
  const unsealed = { ...rest, seq, prev_hash: prevHash };
  return { ...unsealed, hash: recordHash(domain, unsealed) };
}

/**
 * Reads a JSONL file without tolerance: every line must parse. A final line with no trailing newline
 * that does not parse is a torn tail (a crash mid-append), reported separately so a writer can trim it
 * before appending. Returns { exists, records, torn_tail, bad_line (1-based) | null, bytes }.
 */
export async function readJsonlStrict(file) {
  let raw;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { exists: false, records: [], torn_tail: false, bad_line: null, bytes: 0 };
    throw error;
  }
  const bytes = Buffer.byteLength(raw);
  const endsWithNewline = raw.endsWith("\n");
  const lines = raw.split("\n");
  if (endsWithNewline) lines.pop();
  const records = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    try {
      const parsed = JSON.parse(line);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      records.push(parsed);
    } catch {
      const isTail = index === lines.length - 1 && !endsWithNewline;
      return { exists: true, records, torn_tail: isTail, bad_line: isTail ? null : index + 1, bytes };
    }
  }
  return { exists: true, records, torn_tail: false, bad_line: null, bytes };
}

/**
 * Verifies a chain. `records` may begin with an unchained cut header ({ kind: cutKind, through_seq,
 * through_hash }) left by compaction; the first chained record must then cite through_hash. Returns
 * { ok, verified (records up to the first break), break_at (index) | null, reason, head_seq,
 * head_hash, header }.
 */
export function verifyChain(domain, records, { cutKind = "compacted" } = {}) {
  let index = 0;
  let header = null;
  let prevHash = GENESIS_PREV_HASH;
  let prevSeq = 0;
  if (records[0]?.kind === cutKind && records[0].hash === undefined) {
    header = records[0];
    if (typeof header.through_hash !== "string" || !Number.isSafeInteger(header.through_seq)) {
      return { ok: false, verified: [], break_at: 0, reason: "bad_cut_header", head_seq: 0, head_hash: GENESIS_PREV_HASH, header: null };
    }
    prevHash = header.through_hash;
    prevSeq = header.through_seq;
    index = 1;
  }
  const verified = [];
  for (; index < records.length; index += 1) {
    const record = records[index];
    const { hash, ...rest } = record;
    const expectedSeq = prevSeq + 1;
    // A restart record legitimately cites a lost head; it must still be the next seq.
    const citesPrev = record.prev_hash === prevHash || (record.restart === true && typeof record.prev_hash === "string" && record.prev_hash.startsWith("lost:"));
    if (record.seq !== expectedSeq || !citesPrev || typeof hash !== "string" || recordHash(domain, rest) !== hash) {
      return { ok: false, verified, break_at: index, reason: record.seq !== expectedSeq ? "seq_gap" : (!citesPrev ? "prev_hash_mismatch" : "hash_mismatch"), head_seq: prevSeq, head_hash: prevHash, header };
    }
    verified.push(record);
    prevHash = hash;
    prevSeq = record.seq;
  }
  return { ok: true, verified, break_at: null, reason: null, head_seq: prevSeq, head_hash: prevHash, header };
}

export async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
}

/** Trims a torn tail (bytes after the last newline) so the next append starts on a fresh line. */
export async function trimTornTail(file) {
  const raw = await fs.readFile(file, "utf8");
  const cut = raw.lastIndexOf("\n");
  const kept = cut < 0 ? "" : raw.slice(0, cut + 1);
  await atomicWrite(file, kept);
}

export async function atomicWrite(file, content) {
  await ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(tmp, content, { mode: 0o600 });
  await fs.rename(tmp, file);
}

export async function appendLines(file, records) {
  if (records.length === 0) return;
  await ensureDir(path.dirname(file));
  await fs.appendFile(file, records.map((record) => `${JSON.stringify(record)}\n`).join(""), { mode: 0o600 });
}
