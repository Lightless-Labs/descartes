// Context plan C0.8 / C0.12 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.1,
// §7.8.3, I41, I66): the boot-identity ledger, the boundary-verification conjunction, and the
// boundary-census bookkeeping.
//
// This is the boot-identity primitive the trusted-state Phase 3 B-ledger (docs/plans/
// 2026-09-06-trusted-state-step-1.md §5.3) and todos/2026-09-08-clamp-boot-identity-guard.md are to
// consume: one reader (tools/host-lifecycle.js), one ledger, one digest. It is NOT a clock: ordering
// and continuity use the boot id, never a pausing clock (the A5 lesson).
//
// DATA ONLY. Nothing here raises an alert, recovers or closes anything, admits data, or defines
// normal. A verified boundary is a precondition a later F1 card may use; F1 itself is inactive.
//
// The ledger file (stateDir/daemon/boot-ledger.json, 0600, atomic tmp+rename) holds only digests of
// boot ids, never the raw id. A missing ledger is a first observation (nothing is verified); a corrupt
// one is reported and restarted as a first observation (a boundary can then not be verified, never
// fabricated as verified).

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { BOOT_MEASUREMENT_RESOLUTION_S } from "./tools/host-lifecycle.js";

export const BOOT_LEDGER_VERSION = 1;
// Bounded memory of seen boot ids, for regression/duplicate detection (I41 tripwire). A boot id older
// than the cap cannot be recognised as a regression; that limit is stated, not hidden.
export const BOOT_LEDGER_SEEN_CAP = 64;

// One nonce per daemon process: "a boot-id change under a daemon process that never restarted" is a
// tripwire (§7.8.3 item 5), detectable only if each process has its own identity.
export const DAEMON_INSTANCE_NONCE = crypto.randomBytes(8).toString("hex");

export function currentDaemonInstance({ nowMs = Date.now(), processUptimeS = process.uptime() } = {}) {
  return { nonce: DAEMON_INSTANCE_NONCE, start_ms: Math.round(nowMs - processUptimeS * 1000) };
}

const DIGEST_RE = /^[0-9a-f]{32}$/;

export function bootIdDigest(rawBootId) {
  if (typeof rawBootId !== "string" || rawBootId.length === 0) return undefined;
  return crypto.createHash("sha256").update(`descartes.boot_id.ledger.v1\u0000${rawBootId}`).digest("hex").slice(0, 32);
}

export function resolveBootLedgerPath(descartesPaths) {
  return path.join(descartesPaths.stateDir, "daemon", "boot-ledger.json");
}

function isFiniteInt(value) {
  return Number.isSafeInteger(value);
}

function validBootRecord(record) {
  return Boolean(record) && typeof record === "object" && DIGEST_RE.test(record.boot_id_digest ?? "")
    && isFiniteInt(record.last_observed_ms);
}

function emptyLedger() {
  return { version: BOOT_LEDGER_VERSION, current: null, seen: [], pending_boundary: null, pending_census: null, last_structural_clock: null };
}

function validLedger(parsed) {
  if (!parsed || typeof parsed !== "object" || parsed.version !== BOOT_LEDGER_VERSION) return false;
  if (parsed.current !== null && !validBootRecord(parsed.current)) return false;
  if (!Array.isArray(parsed.seen) || parsed.seen.length > BOOT_LEDGER_SEEN_CAP || !parsed.seen.every((d) => DIGEST_RE.test(d))) return false;
  return true;
}

/** { status: "ok" | "missing" | "corrupt", ledger } (a corrupt or missing ledger yields an empty one). */
export async function readBootLedger(descartesPaths) {
  let contents;
  try {
    contents = await fs.readFile(resolveBootLedgerPath(descartesPaths), "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "missing", ledger: emptyLedger() };
    return { status: "corrupt", ledger: emptyLedger() };
  }
  try {
    const parsed = JSON.parse(contents);
    if (!validLedger(parsed)) return { status: "corrupt", ledger: emptyLedger() };
    return { status: "ok", ledger: { ...emptyLedger(), ...parsed } };
  } catch {
    return { status: "corrupt", ledger: emptyLedger() };
  }
}

export async function writeBootLedger(descartesPaths, ledger) {
  const file = resolveBootLedgerPath(descartesPaths);
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(ledger, null, 2), { mode: 0o600 });
  await fs.rename(tmp, file);
  return ledger;
}

// The OS-reported wake marker: a value that changes when the OS records a wake. macOS kern.waketime
// (seconds) changes on each wake; Linux /sys/power/suspend_stats/success counts successful suspends.
// Undefined where neither is readable (then no wake can trigger a census).
export function wakeMarkerOf(probe) {
  const clocks = probe?.clocks ?? {};
  if (isFiniteInt(clocks.kern_waketime_s)) return `darwin:${clocks.kern_waketime_s}`;
  if (isFiniteInt(clocks.suspend_stats_success)) return `linux:${clocks.suspend_stats_success}`;
  return undefined;
}

function bootRecordFrom(probe, digest, { nowMs, daemon, bootIdHmac }) {
  return {
    boot_id_digest: digest,
    // The keyed HMAC the facts carry (context-key.js), so a later boundary fact can name the previous
    // boot without the ledger ever holding the raw id. "unknown" when no key was usable.
    boot_id_hmac: typeof bootIdHmac === "string" ? bootIdHmac : "unknown",
    boot_time_s: isFiniteInt(probe?.boot?.boot_time_s) ? probe.boot.boot_time_s : null,
    os_build: typeof probe?.boot?.os_build === "string" ? probe.boot.os_build : null,
    first_observed_ms: nowMs,
    last_observed_ms: nowMs,
    daemon_nonce: daemon.nonce,
    wake_marker: wakeMarkerOf(probe) ?? null,
  };
}

/**
 * Folds one boundary probe into the ledger. Pure: returns { ledger, trigger } where trigger is
 * "boot" (a boot id different from the ledger's current one), "wake" (the OS wake marker changed
 * within the same boot) or undefined. The first-ever observation triggers nothing (there is no
 * previous boot to compare, so no boundary can be claimed). `lastCensusMs` is the last structural
 * census before this probe (the structural checkpoint), for the pre-boundary gap.
 */
export function observeBootProbe(ledger, probe, { nowMs, daemon, lastCensusMs, bootIdHmac } = {}) {
  const next = structuredClone(ledger ?? emptyLedger());
  const digest = bootIdDigest(probe?.boot?.boot_id);
  if (!digest) return { ledger: next, trigger: undefined };
  if (!next.current) {
    next.current = bootRecordFrom(probe, digest, { nowMs, daemon, bootIdHmac });
    next.seen = [digest];
    return { ledger: next, trigger: undefined };
  }
  if (digest !== next.current.boot_id_digest) {
    const current = bootRecordFrom(probe, digest, { nowMs, daemon, bootIdHmac });
    next.pending_boundary = {
      prev: next.current,
      current,
      detected_ms: nowMs,
      seen_before: next.seen.includes(digest),
      // Daemon identity at detection: the process that observed the new boot id first.
      daemon_nonce: daemon.nonce,
      daemon_start_ms: daemon.start_ms,
      uptime_ms_at_detection: isFiniteInt(probe?.clocks?.os_uptime_ms) ? probe.clocks.os_uptime_ms : null,
    };
    next.pending_census = {
      trigger: "boot",
      detected_ms: nowMs,
      boot_id_digest: digest,
      event_s: current.boot_time_s,
      sleep_s: null,
      last_census_ms: isFiniteInt(lastCensusMs) ? lastCensusMs : null,
    };
    next.current = current;
    next.seen = [...next.seen.filter((d) => d !== digest), digest].slice(-BOOT_LEDGER_SEEN_CAP);
    return { ledger: next, trigger: "boot" };
  }
  next.current.last_observed_ms = nowMs;
  next.current.daemon_nonce = daemon.nonce;
  if (typeof bootIdHmac === "string" && bootIdHmac !== "unknown") next.current.boot_id_hmac = bootIdHmac;
  const marker = wakeMarkerOf(probe);
  let trigger;
  if (marker !== undefined) {
    if (next.current.wake_marker !== null && next.current.wake_marker !== undefined && marker !== next.current.wake_marker) {
      trigger = "wake";
      next.pending_census = {
        trigger: "wake",
        detected_ms: nowMs,
        boot_id_digest: digest,
        event_s: isFiniteInt(probe?.clocks?.kern_waketime_s) ? probe.clocks.kern_waketime_s : null,
        sleep_s: isFiniteInt(probe?.clocks?.kern_sleeptime_s) ? probe.clocks.kern_sleeptime_s : null,
        last_census_ms: isFiniteInt(lastCensusMs) ? lastCensusMs : null,
      };
    }
    next.current.wake_marker = marker;
  }
  return { ledger: next, trigger };
}

function conjunct(value) {
  return value === true ? "pass" : value === false ? "fail" : "unknown";
}

/**
 * The pre-boot-instance conjunct, from this tick's session census (tools/sessions.js evidence): a
 * tmux session created before the current boot time (beyond the resolution) is a pre-boot instance
 * after the boundary: a contradiction (tripwire). A session with no creation time (screen), or no
 * usable census, leaves the conjunct unknown, never "pass".
 */
export function preBootInstanceCheck(sessionEvidence, bootTimeS) {
  if (!isFiniteInt(bootTimeS)) return undefined;
  const envelope = (sessionEvidence ?? []).find((e) => e?.id === "sessions");
  const result = envelope?.result;
  if (!result || !Array.isArray(result.sessions) || !Array.isArray(result.multiplexers)) return undefined;
  if (!result.multiplexers.some((mux) => mux?.status === "ok") || result.truncated) return undefined;
  if (result.multiplexers.some((mux) => mux?.status !== "ok" && mux?.status !== "not_found_on_known_paths")) return undefined;
  let unknown = false;
  for (const session of result.sessions) {
    const created = session?.created_at_epoch_seconds;
    if (!Number.isFinite(created)) {
      unknown = true;
      continue;
    }
    if (created < bootTimeS - BOOT_MEASUREMENT_RESOLUTION_S) return false;
  }
  return unknown ? undefined : true;
}

/**
 * I41: a boot boundary is verified by CONJUNCTION and fails closed. Pure. Every conjunct is pass /
 * fail / unknown; a contradiction is a tripwire (forgery, snapshot restore or a collector bug, never
 * "this host is different"). Checked to within BOOT_MEASUREMENT_RESOLUTION_S (I66).
 *   c_never_seen         the new boot id is not in the bounded seen ring (else: regression/duplicate)
 *   c_daemon_restart     the daemon observing it is a different process from the one that last
 *                        observed the previous boot, and it started after the new boot time
 *   c_boot_time_in_gap   the reported boot time lies in (last observation of the previous boot, now]
 *   c_uptime_consistent  uptime at detection agrees with (detection - boot time)
 *   c_no_preboot_instance no session in the post-boot census was created before the boot time
 */
export function verifyBootBoundary(pending, { sessionEvidence } = {}) {
  const resolutionMs = BOOT_MEASUREMENT_RESOLUTION_S * 1000;
  const prev = pending?.prev;
  const current = pending?.current;
  const bootTimeMs = isFiniteInt(current?.boot_time_s) ? current.boot_time_s * 1000 : undefined;
  const tripwires = [];

  const neverSeen = pending ? !pending.seen_before : undefined;
  if (neverSeen === false) tripwires.push("boot_id_regression");

  let daemonRestart;
  if (typeof pending?.daemon_nonce === "string" && typeof prev?.daemon_nonce === "string") {
    if (pending.daemon_nonce === prev.daemon_nonce) daemonRestart = false;
    else if (bootTimeMs !== undefined && isFiniteInt(pending.daemon_start_ms)) daemonRestart = pending.daemon_start_ms >= bootTimeMs - resolutionMs;
  }
  if (daemonRestart === false) tripwires.push("boot_id_change_without_daemon_restart");

  let bootTimeInGap;
  if (bootTimeMs !== undefined && isFiniteInt(prev?.last_observed_ms) && isFiniteInt(pending?.detected_ms)) {
    bootTimeInGap = bootTimeMs > prev.last_observed_ms - resolutionMs && bootTimeMs <= pending.detected_ms + resolutionMs;
  }
  if (bootTimeInGap === false) tripwires.push("boot_time_outside_gap");

  let uptimeConsistent;
  if (bootTimeMs !== undefined && isFiniteInt(pending?.uptime_ms_at_detection) && isFiniteInt(pending?.detected_ms)) {
    uptimeConsistent = Math.abs((pending.detected_ms - bootTimeMs) - pending.uptime_ms_at_detection) <= resolutionMs;
  }
  if (uptimeConsistent === false) tripwires.push("uptime_inconsistent");

  const noPreboot = preBootInstanceCheck(sessionEvidence, current?.boot_time_s);
  if (noPreboot === false) tripwires.push("preboot_instance");

  const conjuncts = {
    c_never_seen: conjunct(neverSeen),
    c_daemon_restart: conjunct(daemonRestart),
    c_boot_time_in_gap: conjunct(bootTimeInGap),
    c_uptime_consistent: conjunct(uptimeConsistent),
    c_no_preboot_instance: conjunct(noPreboot),
  };
  const order = [
    ["c_never_seen", "never_seen_boot_id"],
    ["c_daemon_restart", "daemon_restart"],
    ["c_boot_time_in_gap", "boot_time_in_gap"],
    ["c_uptime_consistent", "uptime_consistent"],
    ["c_no_preboot_instance", "no_preboot_instance"],
  ];
  const failing = order.find(([key]) => conjuncts[key] !== "pass");
  const verdict = tripwires.length > 0 ? "tripwire" : failing ? "unverified" : "verified";
  const gapMs = isFiniteInt(prev?.last_observed_ms) && isFiniteInt(pending?.detected_ms) ? pending.detected_ms - prev.last_observed_ms : undefined;
  return {
    verdict,
    failing_conjunct: failing ? failing[1] : "none",
    tripwire: tripwires[0] ?? "none",
    ...conjuncts,
    os_build_changed: typeof prev?.os_build === "string" && typeof current?.os_build === "string"
      ? String(prev.os_build !== current.os_build)
      : "unknown",
    gap_s: gapMs !== undefined && gapMs >= 0 ? Math.floor(gapMs / 1000) : undefined,
  };
}

/**
 * C0.12 gap durations for a boundary census (§7.8.3 item 3: the straddle is reported with its
 * durations, as "unobserved", never "explained"). Pure. Pre-boundary: last census -> boot time (or
 * sleep time); post-boundary: boot time (or wake time) -> this census. A missing or inconsistent
 * (negative) input is unknown, never clamped to zero.
 */
export function boundaryCensusGaps(pendingCensus, censusMs) {
  const eventMs = isFiniteInt(pendingCensus?.event_s) ? pendingCensus.event_s * 1000 : undefined;
  const preEndMs = pendingCensus?.trigger === "wake"
    ? (isFiniteInt(pendingCensus?.sleep_s) && pendingCensus.sleep_s > 0 ? pendingCensus.sleep_s * 1000 : undefined)
    : eventMs;
  const lastCensusMs = isFiniteInt(pendingCensus?.last_census_ms) ? pendingCensus.last_census_ms : undefined;
  const pre = preEndMs !== undefined && lastCensusMs !== undefined ? preEndMs - lastCensusMs : undefined;
  const postStartMs = pendingCensus?.trigger === "wake" && !(isFiniteInt(pendingCensus?.event_s) && pendingCensus.event_s > 0) ? undefined : eventMs;
  const post = postStartMs !== undefined && isFiniteInt(censusMs) ? censusMs - postStartMs : undefined;
  return {
    pre_gap_s: pre !== undefined && pre >= 0 ? Math.floor(pre / 1000) : undefined,
    post_gap_s: post !== undefined && post >= 0 ? Math.floor(post / 1000) : undefined,
  };
}

/**
 * C0.9 no-go fallback: host.suspend is unknown, with exposure [0, wall delta] between this structural
 * reading and the previous one, ONLY within one boot (F2: boot-relative clocks share an epoch only
 * within one boot; the wall delta across a boot does not bound a suspend inside one boot either).
 */
export function suspendExposure(lastStructuralClock, { bootIdDigest: digest, wallMs }) {
  if (!lastStructuralClock || !isFiniteInt(lastStructuralClock.wall_ms)) return { interval_basis: "no_previous_reading", exposure_upper_s: undefined };
  if (!digest || lastStructuralClock.boot_id_digest !== digest) return { interval_basis: "cross_boot", exposure_upper_s: undefined };
  if (!isFiniteInt(wallMs) || wallMs < lastStructuralClock.wall_ms) return { interval_basis: "wall_regressed", exposure_upper_s: undefined };
  return { interval_basis: "same_boot_wall_delta", exposure_upper_s: Math.ceil((wallMs - lastStructuralClock.wall_ms) / 1000) };
}
