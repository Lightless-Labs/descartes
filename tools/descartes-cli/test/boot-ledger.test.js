import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BOOT_LEDGER_SEEN_CAP,
  bootIdDigest,
  boundaryCensusGaps,
  currentDaemonInstance,
  DAEMON_INSTANCE_NONCE,
  observeBootProbe,
  preBootInstanceCheck,
  readBootLedger,
  resolveBootLedgerPath,
  suspendExposure,
  verifyBootBoundary,
  wakeMarkerOf,
  writeBootLedger,
} from "../src/boot-ledger.js";
import { resolveDescartesPaths } from "../src/paths.js";

const BOOT_A = "AAAAAAAA-0000-0000-0000-000000000001";
const BOOT_B = "BBBBBBBB-0000-0000-0000-000000000002";
const T0 = Date.parse("2026-10-11T08:00:00.000Z");
const MIN = 60_000;

function probe(bootId, { bootTimeS, waketime, uptimeMs, osBuild = "25C56" } = {}) {
  return {
    boot: { boot_id: bootId, boot_time_s: bootTimeS, os_build: osBuild },
    clocks: { kern_waketime_s: waketime, os_uptime_ms: uptimeMs },
  };
}

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-boot-ledger-test-"));
  return resolveDescartesPaths({ HOME: root, XDG_STATE_HOME: path.join(root, "state"), XDG_CONFIG_HOME: path.join(root, "config"), XDG_DATA_HOME: path.join(root, "data"), XDG_CACHE_HOME: path.join(root, "cache") });
}

const daemonOld = { nonce: "old-daemon", start_ms: T0 - 10 * 24 * 3600_000 };
const daemonNew = (bootTimeS) => ({ nonce: "new-daemon", start_ms: bootTimeS * 1000 + 30_000 });

function bootedLedger() {
  const bootA = Math.floor((T0 - 5 * 24 * 3600_000) / 1000);
  return observeBootProbe(undefined, probe(BOOT_A, { bootTimeS: bootA, waketime: 0 }), { nowMs: T0, daemon: daemonOld }).ledger;
}

test("ledger digests never hold the raw boot id; the daemon nonce is per process", () => {
  const digest = bootIdDigest(BOOT_A);
  assert.match(digest, /^[0-9a-f]{32}$/);
  assert.ok(!digest.includes("AAAAAAAA"));
  assert.equal(bootIdDigest(""), undefined);
  assert.match(DAEMON_INSTANCE_NONCE, /^[0-9a-f]{16}$/);
  assert.equal(currentDaemonInstance({ nowMs: 10_000, processUptimeS: 4 }).start_ms, 6_000);
});

test("C0.8: the first-ever observation triggers nothing and verifies nothing (no previous boot to compare)", () => {
  const { ledger, trigger } = observeBootProbe(undefined, probe(BOOT_A, { bootTimeS: 1, waketime: 0 }), { nowMs: T0, daemon: daemonOld });
  assert.equal(trigger, undefined);
  assert.equal(ledger.current.boot_id_digest, bootIdDigest(BOOT_A));
  assert.deepEqual(ledger.seen, [bootIdDigest(BOOT_A)]);
  assert.equal(ledger.pending_boundary, null);
  assert.equal(observeBootProbe(undefined, probe(undefined), { nowMs: T0, daemon: daemonOld }).ledger.current, null, "an unreadable boot id observes nothing");
});

test("C0.8: a new boot id triggers a boot boundary with the previous record kept for verification; the same id only refreshes", () => {
  let ledger = bootedLedger();
  const same = observeBootProbe(ledger, probe(BOOT_A, { bootTimeS: 1, waketime: 0 }), { nowMs: T0 + MIN, daemon: daemonOld });
  assert.equal(same.trigger, undefined);
  assert.equal(same.ledger.current.last_observed_ms, T0 + MIN);
  ledger = same.ledger;
  const bootB = Math.floor((T0 + 30 * MIN) / 1000);
  const changed = observeBootProbe(ledger, probe(BOOT_B, { bootTimeS: bootB, uptimeMs: 5 * MIN }), {
    nowMs: bootB * 1000 + 5 * MIN, daemon: daemonNew(bootB), lastCensusMs: T0, bootIdHmac: "0123456789abcdef",
  });
  assert.equal(changed.trigger, "boot");
  assert.equal(changed.ledger.pending_boundary.prev.boot_id_digest, bootIdDigest(BOOT_A));
  assert.equal(changed.ledger.pending_boundary.prev.last_observed_ms, T0 + MIN);
  assert.equal(changed.ledger.pending_boundary.seen_before, false);
  assert.equal(changed.ledger.current.boot_id_hmac, "0123456789abcdef");
  assert.deepEqual(changed.ledger.pending_census, { trigger: "boot", detected_ms: bootB * 1000 + 5 * MIN, boot_id_digest: bootIdDigest(BOOT_B), event_s: bootB, sleep_s: null, last_census_ms: T0 });
  assert.equal(ledger.pending_boundary, null, "pure: the input ledger is not mutated");
});

test("C0.12: a changed OS wake marker within one boot triggers a wake census; an unreadable marker never triggers", () => {
  const ledger = bootedLedger();
  const wake = observeBootProbe(ledger, { ...probe(BOOT_A, { waketime: 1791720000 }), clocks: { kern_waketime_s: 1791720000, kern_sleeptime_s: 1791710000 } }, { nowMs: T0 + MIN, daemon: daemonOld, lastCensusMs: T0 - 20 * MIN });
  assert.equal(wake.trigger, "wake");
  assert.deepEqual(wake.ledger.pending_census, { trigger: "wake", detected_ms: T0 + MIN, boot_id_digest: bootIdDigest(BOOT_A), event_s: 1791720000, sleep_s: 1791710000, last_census_ms: T0 - 20 * MIN });
  const unreadable = observeBootProbe(ledger, { boot: { boot_id: BOOT_A }, clocks: {} }, { nowMs: T0 + MIN, daemon: daemonOld });
  assert.equal(unreadable.trigger, undefined);
  assert.equal(wakeMarkerOf({ clocks: { suspend_stats_success: 4 } }), "linux:4");
  assert.equal(wakeMarkerOf({ clocks: {} }), undefined);
});

function sessions(list, muxStatus = "ok") {
  return [{ id: "sessions", result: { sessions: list, multiplexers: [{ multiplexer: "tmux", status: muxStatus }], truncated: false } }];
}

function freshBoundary({ bootOffsetMs = 30 * MIN, uptimeSkewMs = 0, daemon, sessionList = [], seenBefore = false } = {}) {
  let ledger = bootedLedger();
  if (seenBefore) ledger = { ...ledger, seen: [...ledger.seen, bootIdDigest(BOOT_B)] };
  const bootB = Math.floor((T0 + bootOffsetMs) / 1000);
  const detectedMs = T0 + 40 * MIN;
  const { ledger: next } = observeBootProbe(ledger, probe(BOOT_B, { bootTimeS: bootB, uptimeMs: detectedMs - bootB * 1000 + uptimeSkewMs }), { nowMs: detectedMs, daemon: daemon ?? daemonNew(bootB) });
  return verifyBootBoundary(next.pending_boundary, { sessionEvidence: sessions(sessionList) });
}

test("I41: an ordinary boot boundary with every conjunct true is verified", () => {
  const verdict = freshBoundary({ sessionList: [{ created_at_epoch_seconds: Math.floor((T0 + 35 * MIN) / 1000) }] });
  assert.equal(verdict.verdict, "verified");
  assert.equal(verdict.failing_conjunct, "none");
  assert.equal(verdict.tripwire, "none");
  assert.equal(verdict.os_build_changed, "false");
  assert.equal(verdict.gap_s, 40 * 60, "previous boot last observed at T0, new boot detected at T0 + 40 min");
});

test("I41 tripwires: boot-id regression, no daemon restart, boot time outside the gap, inconsistent uptime, a pre-boot instance", () => {
  assert.equal(freshBoundary({ seenBefore: true }).tripwire, "boot_id_regression");
  assert.equal(freshBoundary({ daemon: { nonce: "old-daemon", start_ms: daemonOld.start_ms } }).tripwire, "boot_id_change_without_daemon_restart");
  assert.equal(freshBoundary({ bootOffsetMs: -60 * MIN }).tripwire, "boot_time_outside_gap", "a boot time before the previous boot's last observation");
  assert.equal(freshBoundary({ uptimeSkewMs: 10 * MIN }).tripwire, "uptime_inconsistent");
  const preboot = freshBoundary({ sessionList: [{ created_at_epoch_seconds: Math.floor((T0 - 60 * MIN) / 1000) }] });
  assert.equal(preboot.verdict, "tripwire");
  assert.equal(preboot.tripwire, "preboot_instance");
  assert.equal(preboot.c_no_preboot_instance, "fail");
});

test("I66: the conjunction tolerates exactly the measurement resolution, no more", () => {
  assert.equal(freshBoundary({ uptimeSkewMs: 2000 }).c_uptime_consistent, "pass");
  assert.equal(freshBoundary({ uptimeSkewMs: 2001 }).c_uptime_consistent, "fail");
});

test("I41 fails closed: an unknown conjunct (screen sessions without creation time, no usable census) is unverified, never verified", () => {
  const screen = freshBoundary({ sessionList: [{ multiplexer: "screen" }] });
  assert.equal(screen.verdict, "unverified");
  assert.equal(screen.failing_conjunct, "no_preboot_instance");
  assert.equal(screen.c_no_preboot_instance, "unknown");
  assert.equal(preBootInstanceCheck([], 100), undefined, "no session census this tick");
  assert.equal(preBootInstanceCheck(sessions([], "unable"), 100), undefined, "an incomplete census");
  assert.equal(preBootInstanceCheck(sessions([]), 100), true, "a complete, empty census has no pre-boot instance");
  assert.equal(verifyBootBoundary(undefined).verdict, "unverified");
});

test("C0.12: boundary-census gaps are durations from the last census to the boot and from the boot to the census; unknown inputs stay unknown", () => {
  const boot = { trigger: "boot", event_s: 1000, sleep_s: null, last_census_ms: 400_000 };
  assert.deepEqual(boundaryCensusGaps(boot, 1_090_000), { pre_gap_s: 600, post_gap_s: 90 });
  assert.deepEqual(boundaryCensusGaps({ ...boot, last_census_ms: null }, 1_090_000), { pre_gap_s: undefined, post_gap_s: 90 });
  assert.deepEqual(boundaryCensusGaps({ ...boot, last_census_ms: 2_000_000 }, 1_090_000), { pre_gap_s: undefined, post_gap_s: 90 }, "a negative gap is inconsistent: unknown, never clamped");
  const wake = { trigger: "wake", event_s: 2000, sleep_s: 1500, last_census_ms: 1_000_000 };
  assert.deepEqual(boundaryCensusGaps(wake, 2_030_000), { pre_gap_s: 500, post_gap_s: 30 });
  assert.deepEqual(boundaryCensusGaps({ trigger: "wake", event_s: null, sleep_s: null, last_census_ms: 1 }, 5_000), { pre_gap_s: undefined, post_gap_s: undefined }, "a Linux wake has no wake instant: unknown");
});

test("C0.9 no-go fallback: suspend exposure is [0, wall delta] within one boot only", () => {
  const digest = bootIdDigest(BOOT_A);
  assert.deepEqual(suspendExposure(null, { bootIdDigest: digest, wallMs: 10 }), { interval_basis: "no_previous_reading", exposure_upper_s: undefined });
  assert.deepEqual(suspendExposure({ boot_id_digest: digest, wall_ms: 1_000 }, { bootIdDigest: digest, wallMs: 3_601_000 }), { interval_basis: "same_boot_wall_delta", exposure_upper_s: 3600 });
  assert.deepEqual(suspendExposure({ boot_id_digest: digest, wall_ms: 1_000 }, { bootIdDigest: bootIdDigest(BOOT_B), wallMs: 9_000 }), { interval_basis: "cross_boot", exposure_upper_s: undefined });
  assert.deepEqual(suspendExposure({ boot_id_digest: digest, wall_ms: 9_000 }, { bootIdDigest: digest, wallMs: 1_000 }), { interval_basis: "wall_regressed", exposure_upper_s: undefined });
});

test("ledger I/O: atomic 0600 write and round trip; a corrupt or oversized ledger is reported and restarts as a first observation", async () => {
  const paths = await tempPaths();
  assert.equal((await readBootLedger(paths)).status, "missing");
  const ledger = bootedLedger();
  await writeBootLedger(paths, ledger);
  const file = resolveBootLedgerPath(paths);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  const read = await readBootLedger(paths);
  assert.equal(read.status, "ok");
  assert.deepEqual(read.ledger.current, ledger.current);
  await fs.writeFile(file, "{not json");
  assert.deepEqual((await readBootLedger(paths)).status, "corrupt");
  assert.equal((await readBootLedger(paths)).ledger.current, null);
  await fs.writeFile(file, JSON.stringify({ ...ledger, seen: Array.from({ length: BOOT_LEDGER_SEEN_CAP + 1 }, () => "a".repeat(32)) }));
  assert.equal((await readBootLedger(paths)).status, "corrupt");
});

test("the seen ring is bounded", () => {
  let ledger = bootedLedger();
  for (let i = 0; i < BOOT_LEDGER_SEEN_CAP + 10; i += 1) {
    ledger = observeBootProbe(ledger, probe(`CCCCCCCC-0000-0000-0000-${String(i).padStart(12, "0")}`, { bootTimeS: 1 }), { nowMs: T0 + i, daemon: daemonOld }).ledger;
  }
  assert.equal(ledger.seen.length, BOOT_LEDGER_SEEN_CAP);
});
