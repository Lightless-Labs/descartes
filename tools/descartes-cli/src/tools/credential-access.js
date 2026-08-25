// Credential-file-access collector, Gap 3 (docs/plans/2026-08-21-agent-intrusion-detection-
// gaps.md, Slice D). Filesystem-only, deliberately read-only and strictly smaller than
// tools/canary.js: `fs.lstat` ONLY. This collector must NEVER `readFile`/open the contents of any
// credential path (standalone safety invariant, stated explicitly — metadata only) and NEVER
// `readdir` any directory (the v1 path list is fixed LITERAL filenames, not a glob, precisely so
// no directory enumeration of `~/.ssh` — or anywhere else — is ever needed).
import { createHash } from "node:crypto";
import { lstat as fsLstat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

// [REVIEW 2026-08-21, must-fix] No glob expansion of `~/.ssh/id_*`. Fixed LITERAL filenames only
// (existence-gated per-entry below — a host without a given key file simply skips that entry,
// never a fabricated stat). Each entry carries a closed-enum `category`.
//
// [O6] Churn-control policy: v1 ships LOW-CHURN secrets only. High-churn paths
// (~/.config/gcloud/credentials.db, ~/.kube/config, ~/.docker/config.json, ~/.npmrc — each
// rewritten on routine day-to-day tool use) are EXCLUDED from v1 entirely; a future revision may
// add them only alongside a per-entry `min_refire_ms` policy the detector's own store enforces
// (not the generic alert cooldown). See credential-access-baseline.test.js's churn-rate-ceiling
// test, which pins that no v1 entry is drawn from the excluded high-churn set.
//
// [O7] atime watch eligibility: every v1 entry watches `["mtime", "ino"]` — never `"atime"`.
// There is no v1 operator manifest (O4) to mark a specific path atime-eligible, so an "atime
// opt-in per path" branch would be either untestable dead code or an unpinned silent default; v1
// states the default explicitly instead. `atime_advanced` remains implemented in the shared
// stat-diff.js helper (for a future opt-in) but is exercised only via injected test fixtures,
// never by any real v1 path list entry.
function defaultCredentialPaths(homeDir) {
  const sshDir = path.join(homeDir, ".ssh");
  return [
    { category: "ssh_private_key", path: path.join(sshDir, "id_rsa"), watch: ["mtime", "ino"] },
    { category: "ssh_private_key", path: path.join(sshDir, "id_ecdsa"), watch: ["mtime", "ino"] },
    { category: "ssh_private_key", path: path.join(sshDir, "id_ed25519"), watch: ["mtime", "ino"] },
    { category: "ssh_private_key", path: path.join(sshDir, "id_ed25519_sk"), watch: ["mtime", "ino"] },
    { category: "ssh_private_key", path: path.join(sshDir, "id_ecdsa_sk"), watch: ["mtime", "ino"] },
    { category: "ssh_config", path: path.join(sshDir, "config"), watch: ["mtime", "ino"] },
    { category: "aws_credentials", path: path.join(homeDir, ".aws", "credentials"), watch: ["mtime", "ino"] },
    { category: "netrc", path: path.join(homeDir, ".netrc"), watch: ["mtime", "ino"] },
  ];
}

// [O4] Fixed code-defined list for v1 (YAGNI — no operator manifest yet). Exported so
// credential-access-baseline.js / tests can reuse the SAME closed-enum category set and path
// count without re-deriving a parallel copy that could silently drift from this one.
export function resolveDefaultCredentialPaths(options = {}) {
  const homeDir = options.homeDir ?? os.homedir();
  return defaultCredentialPaths(homeDir);
}

export const CREDENTIAL_CATEGORY_VALUES = new Set([
  "ssh_private_key",
  "ssh_config",
  "aws_credentials",
  "netrc",
]);

/**
 * `path_hash` = sha256(literalPath).slice(0,16) — the literal path can embed a username/home
 * detail; hash it for dedup/identity, carry only the closed-enum `category` for the operator, the
 * literal path never reaches a diagnostic, notification, or persisted store field.
 */
export function credentialPathHash(literalPath) {
  return createHash("sha256").update(`descartes.credential_access.path.v1:${literalPath}`).digest("hex").slice(0, 16);
}

async function collectOneCredentialPath(entry, lstat) {
  const pathHash = credentialPathHash(entry.path);
  let stat;
  try {
    stat = await lstat(entry.path);
  } catch (error) {
    // Existence-gated (P5): a missing path is a distinguishable "not present on this host"
    // state, skipped from the baseline — NEVER a fabricated stat.
    if (error?.code === "ENOENT") return { category: entry.category, path_hash: pathHash, watch: entry.watch, status: "absent" };
    // Permission-denied (or any other non-ENOENT lstat failure) degrades to no-claim (P4) —
    // never "untouched".
    return { category: entry.category, path_hash: pathHash, watch: entry.watch, status: "unreadable" };
  }
  // Credential-access-baseline.js's dedicated per-path store schema wants finite NUMBERS (epoch
  // ms for atime/mtime, the raw inode number) — unlike canary's fact-store-backed persistence
  // (which coerces every attribute to a string regardless), this collector's own store has no
  // such constraint, so numbers are used directly. computeStatDiffTripReason (stat-diff.js) — the
  // ACTUAL shared logic this collector reuses, per the plan — composes correctly against either
  // representation: mtime/ino compare by `!==`, and atime is coerced through `Number(value)`.
  return {
    category: entry.category,
    path_hash: pathHash,
    watch: entry.watch,
    status: "ok",
    atime: stat.atime instanceof Date ? stat.atime.getTime() : Number(stat.atime),
    mtime: stat.mtime instanceof Date ? stat.mtime.getTime() : Number(stat.mtime),
    ino: Number(stat.ino),
  };
}

/**
 * `{ lstat }` ONLY — no `readdir`, no `readFile`/`open` parameter exists on this collector at
 * all, so no code path here can ever read a credential's bytes or enumerate a directory.
 */
export async function collectCredentialAccessEvidence(options = {}) {
  const lstat = options.lstat ?? fsLstat;
  const entries = options.paths ?? resolveDefaultCredentialPaths(options);

  return timedEnvelope(async () => {
    const results = [];
    for (const entry of entries) {
      results.push(await collectOneCredentialPath(entry, lstat));
    }
    const summary = {
      total_count: results.length,
      ok_count: results.filter((entry) => entry.status === "ok").length,
      absent_count: results.filter((entry) => entry.status === "absent").length,
      unreadable_count: results.filter((entry) => entry.status === "unreadable").length,
    };
    return {
      platform: options.platform ?? process.platform,
      status: summary.unreadable_count > 0 ? "warning" : "ok",
      summary,
      entries: results,
      note: "Credential-file-access evidence is read-only lstat metadata only; file contents are never read.",
    };
  }, (result) => evidenceEnvelope({
    id: "credential-access",
    status: result?.status ?? "ok",
    source: "filesystem",
    result,
    confidence: result?.status === "warning" ? 0.5 : 0.9,
    reviewHint: result?.status === "warning" ? "missing_permission" : "none",
    tool: "collect_credential_access_evidence",
  }));
}
