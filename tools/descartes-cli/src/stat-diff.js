// Shared stat-snapshot + trip-reason diff primitive, extracted from tools/canary.js /
// canary-baseline.js (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md, Slice D). Both the
// canary tripwire and the credential-file-access detector (credential-access-baseline.js) are
// POSITIVE, two-snapshot direct-evidence detectors built on the exact same fs.lstat metadata
// diff — this module is the single source of truth for that diff so canary's already-shipped
// atime_advanced/mtime_changed/executed trip reasons and credential-access's new mtime_changed/
// ino_changed reasons can never silently drift apart from one another.
//
// Pure, deterministic, no I/O. Extraction-only for the three canary reasons (behavior must stay
// byte-identical — see canary-baseline.test.js's own regression coverage); `ino_changed` is
// genuinely NEW logic added here, not a reuse of prior canary behavior (the shipped canary trip
// reasons never included `ino` — see tools/canary.js/canary-baseline.js's own module comments).

// Mirrors tools/canary.js's own statAttribute helper exactly (generic across all four fields,
// even though only atime/mtime are ever actually Date instances in practice).
function statAttribute(value) {
  return value instanceof Date ? value.toISOString() : String(value);
}

export function statSnapshotAttributes(stat) {
  return {
    atime: statAttribute(stat.atime),
    mtime: statAttribute(stat.mtime),
    ino: statAttribute(stat.ino),
    size: statAttribute(stat.size),
  };
}

function atimeValue(value) {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value !== "string" || value.length === 0) return undefined;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : undefined;
}

function isFiniteStatValue(value) {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "string" || value.length === 0) return false;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return true;
  return Number.isFinite(new Date(value).getTime());
}

/**
 * Returns the FIRST matching trip reason across `watches`, in the order given, or `undefined`
 * when nothing tripped. `previousSnapshot`/`latestSnapshot` carry `{atime, mtime, ino, executed?}`
 * — a field the caller's domain doesn't track (e.g. credential-access never sets `executed`; the
 * canary manifest never sets `watch: ["ino"]`) simply never matches that branch, degrading to "no
 * trip from that branch" rather than throwing. Fail-closed on every branch: a MISSING value on
 * either side (`undefined !== "x"` would be trivially true in JS) never trips — a hole in the
 * snapshot is not evidence of a real attribute change (mirrors canary-baseline.js's own HIGH-fix
 * discipline this extraction preserves verbatim for atime/mtime/executed).
 */
export function computeStatDiffTripReason(previousSnapshot, latestSnapshot, watches = []) {
  for (const watch of watches) {
    if (watch === "atime") {
      const latestAtime = atimeValue(latestSnapshot?.atime);
      const previousAtime = atimeValue(previousSnapshot?.atime);
      if (latestAtime !== undefined && previousAtime !== undefined && latestAtime > previousAtime) {
        return "atime_advanced";
      }
    } else if (
      watch === "mtime" &&
      isFiniteStatValue(latestSnapshot?.mtime) &&
      isFiniteStatValue(previousSnapshot?.mtime) &&
      latestSnapshot.mtime !== previousSnapshot.mtime
    ) {
      return "mtime_changed";
    } else if (watch === "executed" && latestSnapshot?.executed === "true" && previousSnapshot?.executed === "false") {
      return "executed";
    } else if (
      // NEW (Slice D, credential-access's first consumer): a changed inode means the file was
      // REPLACED (unlink+recreate — an attacker swapping in a new key, or a tool that rotates via
      // rename), distinct from mtime_changed's in-place rewrite. Same fail-closed missing-value
      // discipline as the three reasons above.
      watch === "ino" &&
      isFiniteStatValue(latestSnapshot?.ino) &&
      isFiniteStatValue(previousSnapshot?.ino) &&
      latestSnapshot.ino !== previousSnapshot.ino
    ) {
      return "ino_changed";
    }
  }
  return undefined;
}
