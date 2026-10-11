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
  return { version: BOOT_LEDGER_VERSION, current: null, seen: [], pending_boundary: null, pending_census: null, last_structural_clock: null, last_census_ms: null, daemon_gap: null };
}

/**
 * C2 (§4.1 host.daemon_gap): a fresh per-structural-interval accumulator of the gaps between
 * consecutive daemon observations (boundary probes). Additive to the v1 ledger (an older ledger has
 * none: its first interval's gap is then unknown).
 */
export function emptyDaemonGap(sinceMs) {
  return { since_ms: Number.isSafeInteger(sinceMs) ? sinceMs : null, max_gap_ms: 0, max_gap_uptime_ms: 0, uptime_known: true, wall_known: true, observations: 0, restarts: 0, boot_changed: false };
}

/**
 * C2 review L2: two consecutive accumulators as one (the older interval's gap fact was never written,
 * so it is carried into the next record rather than lost). Maxima and counts combine; a maximum is
 * known only when both halves knew it.
 */
export function mergeDaemonGap(older, newer) {
  const a = older && typeof older === "object" ? older : undefined;
  const b = newer && typeof newer === "object" ? newer : undefined;
  if (!a) return b;
  if (!b) return a;
  const int = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : 0);
  return {
    since_ms: Number.isSafeInteger(a.since_ms) ? a.since_ms : null,
    max_gap_ms: Math.max(int(a.max_gap_ms), int(b.max_gap_ms)),
    max_gap_uptime_ms: Math.max(int(a.max_gap_uptime_ms), int(b.max_gap_uptime_ms)),
    uptime_known: a.uptime_known === true && b.uptime_known === true,
    wall_known: a.wall_known === true && b.wall_known === true,
    observations: int(a.observations) + int(b.observations),
    restarts: int(a.restarts) + int(b.restarts),
    boot_changed: a.boot_changed === true || b.boot_changed === true,
  };
}

function foldDaemonGap(ledger, { gapMs, uptimeGapMs, restarted, bootChanged }) {
  const acc = ledger.daemon_gap && typeof ledger.daemon_gap === "object" ? ledger.daemon_gap : { ...emptyDaemonGap(null), wall_known: false, uptime_known: false };
  acc.observations = (Number.isSafeInteger(acc.observations) ? acc.observations : 0) + 1;
  if (restarted) acc.restarts = (Number.isSafeInteger(acc.restarts) ? acc.restarts : 0) + 1;
  if (bootChanged) acc.boot_changed = true;
  // Degrade, never clamp: a negative wall gap (a backward step) or a missing reading makes the
  // maximum unknown for this interval, never zero.
  if (Number.isSafeInteger(gapMs) && gapMs >= 0) acc.max_gap_ms = Math.max(Number.isSafeInteger(acc.max_gap_ms) ? acc.max_gap_ms : 0, gapMs);
  else acc.wall_known = false;
  if (Number.isSafeInteger(uptimeGapMs) && uptimeGapMs >= 0) acc.max_gap_uptime_ms = Math.max(Number.isSafeInteger(acc.max_gap_uptime_ms) ? acc.max_gap_uptime_ms : 0, uptimeGapMs);
  else acc.uptime_known = false;
  ledger.daemon_gap = acc;
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
 * census before this probe (the structural checkpoint), for the pre-boundary gap. `detectedBy`
 * ("before_probe" | "after_probe") records which half of the census bracket saw the change first.
 */
export function observeBootProbe(ledger, probe, { nowMs, daemon, lastCensusMs, bootIdHmac, detectedBy = "before_probe" } = {}) {
  const next = structuredClone(ledger ?? emptyLedger());
  const digest = bootIdDigest(probe?.boot?.boot_id);
  if (!digest) return { ledger: next, trigger: undefined };
  const uptimeMs = isFiniteInt(probe?.clocks?.os_uptime_ms) ? probe.clocks.os_uptime_ms : undefined;
  if (!next.current) {
    next.current = bootRecordFrom(probe, digest, { nowMs, daemon, bootIdHmac });
    next.current.last_uptime_ms = uptimeMs ?? null;
    next.seen = [digest];
    next.daemon_gap = { ...emptyDaemonGap(nowMs), observations: 1 };
    return { ledger: next, trigger: undefined };
  }
  if (digest !== next.current.boot_id_digest) {
    // C2: the gap since the previous boot's last observation (wall only: no uptime delta spans a boot).
    foldDaemonGap(next, {
      gapMs: isFiniteInt(next.current.last_observed_ms) ? nowMs - next.current.last_observed_ms : undefined,
      uptimeGapMs: undefined,
      restarted: next.current.daemon_nonce !== daemon.nonce,
      bootChanged: true,
    });
    const current = bootRecordFrom(probe, digest, { nowMs, daemon, bootIdHmac });
    // C0 review L2: a boundary or census still pending (never recorded: no census ran since) is
    // superseded, and counted, never silently lost.
    const supersededBoundaries = next.pending_boundary ? (next.pending_boundary.superseded_count ?? 0) + 1 : 0;
    const supersededCensuses = next.pending_census ? (next.pending_census.superseded_count ?? 0) + 1 : 0;
    next.pending_boundary = {
      prev: next.current,
      current,
      detected_ms: nowMs,
      seen_before: next.seen.includes(digest),
      // Daemon identity at detection: the process that observed the new boot id first.
      daemon_nonce: daemon.nonce,
      daemon_start_ms: daemon.start_ms,
      uptime_ms_at_detection: isFiniteInt(probe?.clocks?.os_uptime_ms) ? probe.clocks.os_uptime_ms : null,
      superseded_count: supersededBoundaries,
    };
    next.pending_census = {
      trigger: "boot",
      detected_ms: nowMs,
      detected_by: detectedBy,
      boot_id_digest: digest,
      event_s: current.boot_time_s,
      sleep_s: null,
      last_census_ms: isFiniteInt(lastCensusMs) ? lastCensusMs : null,
      superseded_count: supersededCensuses,
    };
    next.current = current;
    next.current.last_uptime_ms = uptimeMs ?? null;
    next.seen = [...next.seen.filter((d) => d !== digest), digest].slice(-BOOT_LEDGER_SEEN_CAP);
    return { ledger: next, trigger: "boot" };
  }
  foldDaemonGap(next, {
    gapMs: isFiniteInt(next.current.last_observed_ms) ? nowMs - next.current.last_observed_ms : undefined,
    uptimeGapMs: uptimeMs !== undefined && isFiniteInt(next.current.last_uptime_ms) ? uptimeMs - next.current.last_uptime_ms : undefined,
    restarted: next.current.daemon_nonce !== daemon.nonce,
    bootChanged: false,
  });
  next.current.last_uptime_ms = uptimeMs ?? null;
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
        detected_by: detectedBy,
        boot_id_digest: digest,
        event_s: isFiniteInt(probe?.clocks?.kern_waketime_s) ? probe.clocks.kern_waketime_s : null,
        sleep_s: isFiniteInt(probe?.clocks?.kern_sleeptime_s) ? probe.clocks.kern_sleeptime_s : null,
        last_census_ms: isFiniteInt(lastCensusMs) ? lastCensusMs : null,
        superseded_count: next.pending_census ? (next.pending_census.superseded_count ?? 0) + 1 : 0,
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
 * fail / unknown (or not_independent, below). Checked to within BOOT_MEASUREMENT_RESOLUTION_S (I66).
 *   c_never_seen          the new boot id is not in the bounded seen ring (else: regression/duplicate)
 *   c_daemon_restart      the daemon observing it is a different process from the one that last
 *                         observed the previous boot, and it started after the new boot time
 *   c_boot_time_in_gap    the reported boot time lies in (last observation of the previous boot, now]
 *   c_uptime_consistent   NOT INDEPENDENT (C0 review H3), see below
 *   c_no_preboot_instance no session in the post-boot census was created before the boot time
 *
 * c_uptime_consistent: both platforms derive the reported boot time from the uptime and the wall
 * clock at read time (Linux /proc/stat btime = realtime - CLOCK_BOOTTIME; macOS libuv uptime =
 * time(NULL) - kern.boottime). "(detection - boot time) agrees with uptime" is then an identity, and
 * "uptime fits the gap" is algebraically c_boot_time_in_gap. No captured clock is independent of it
 * (kern.monotonicclock_usecs is unvalidated until C0.9), so the conjunct is reported as
 * `not_independent`: never "pass" for a check that cannot fail. It is not a pass, so the verdict is
 * fail-closed `unverified` until C0.9 names an independent clock or I41 is amended (plan addendum).
 *
 * Tripwires (C0 review M3): only the clock-INDEPENDENT contradictions -- a boot id seen before
 * (regression/duplicate) and a boot-id change under the SAME daemon process (nonce) -- are tripwires.
 * A contradiction that rests on comparing wall-clock readings taken at different instants (boot time
 * outside the gap, a session apparently created before the boot, a daemon apparently started before
 * the boot) is also what a benign clock step produces (a lagging RTC, then an NTP step), and there is
 * no clock-step detection yet (host.clock, C2): it fails its conjunct and the verdict is
 * `unverified`, never `tripwire`.
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
    if (pending.daemon_nonce === prev.daemon_nonce) {
      daemonRestart = false;
      tripwires.push("boot_id_change_without_daemon_restart");
    } else if (bootTimeMs !== undefined && isFiniteInt(pending.daemon_start_ms)) {
      daemonRestart = pending.daemon_start_ms >= bootTimeMs - resolutionMs; // wall-derived: fail, never a tripwire
    }
  }

  let bootTimeInGap;
  if (bootTimeMs !== undefined && isFiniteInt(prev?.last_observed_ms) && isFiniteInt(pending?.detected_ms)) {
    bootTimeInGap = bootTimeMs > prev.last_observed_ms - resolutionMs && bootTimeMs <= pending.detected_ms + resolutionMs;
  }

  const noPreboot = preBootInstanceCheck(sessionEvidence, current?.boot_time_s);

  const conjuncts = {
    c_never_seen: conjunct(neverSeen),
    c_daemon_restart: conjunct(daemonRestart),
    c_boot_time_in_gap: conjunct(bootTimeInGap),
    c_uptime_consistent: "not_independent",
    c_no_preboot_instance: conjunct(noPreboot),
  };
  const order = [
    ["c_never_seen", "never_seen_boot_id"],
    ["c_daemon_restart", "daemon_restart"],
    ["c_boot_time_in_gap", "boot_time_in_gap"],
    ["c_uptime_consistent", "uptime_consistent"],
    ["c_no_preboot_instance", "no_preboot_instance"],
  ];
  // The most informative non-pass conjunct is named: a fail first, then an unknown, then the
  // permanently not-independent one (which would otherwise mask every later conjunct).
  const failing = order.find(([key]) => conjuncts[key] === "fail")
    ?? order.find(([key]) => conjuncts[key] === "unknown")
    ?? order.find(([key]) => conjuncts[key] !== "pass");
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
 * C0.9 no-go fallback: host.suspend is unknown, with exposure [0, upper] between this structural
 * reading and the previous one, ONLY within one boot (F2: boot-relative clocks share an epoch only
 * within one boot; no delta across a boot bounds a suspend inside one boot either).
 *
 * C0 review M2: the upper bound is the delta of the OS uptime (`os.uptime()`: on Linux CLOCK_BOOTTIME
 * via /proc/uptime; on macOS now - kern.boottime, which the kernel moves with a calendar set), NOT the
 * wall-clock delta: a backward wall step shrinks the wall delta below the real elapsed time, so it
 * would not bound a real suspend. The uptime delta includes suspended time, so it is an upper bound,
 * widened by the one measurement resolution (I66: whole-second uptime plus non-atomic reads). A
 * missing uptime on either side is unknown, never the wall delta. Pure; `wallMs` is accepted for the
 * caller's convenience and not used for the bound.
 */
export function suspendExposure(lastStructuralClock, { bootIdDigest: digest, uptimeMs } = {}) {
  // C0 review H2: a boot id that could not be read this tick (a timed-out or failed host-lifecycle
  // read) says nothing about a boot boundary: the interval is unknown, never "cross_boot".
  if (!digest) return { interval_basis: "unknown", exposure_upper_s: undefined };
  if (!lastStructuralClock || typeof lastStructuralClock.boot_id_digest !== "string") return { interval_basis: "no_previous_reading", exposure_upper_s: undefined };
  if (lastStructuralClock.boot_id_digest !== digest) return { interval_basis: "cross_boot", exposure_upper_s: undefined };
  if (!isFiniteInt(lastStructuralClock.uptime_ms) || !isFiniteInt(uptimeMs)) return { interval_basis: "unknown", exposure_upper_s: undefined };
  if (uptimeMs < lastStructuralClock.uptime_ms) return { interval_basis: "uptime_regressed", exposure_upper_s: undefined };
  return { interval_basis: "same_boot_uptime_delta", exposure_upper_s: Math.ceil((uptimeMs - lastStructuralClock.uptime_ms) / 1000) + BOOT_MEASUREMENT_RESOLUTION_S };
}
