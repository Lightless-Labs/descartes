import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeTimeSyncRequest,
  parseChronycTracking,
  parseLaunchctlPrintService,
  parseMacSystemsetup,
  parseNtpqPeers,
  parseSntpOutput,
  parseTimedatectlShow,
  parseTimedatectlStatus,
} from "../src/tools/time-sync.js";

test("normalizeTimeSyncRequest preserves bounded offset options", () => {
  assert.deepEqual(normalizeTimeSyncRequest({ checkOffset: true, server: "time.example.test" }), {
    check_offset: true,
    server: "time.example.test",
  });
  assert.deepEqual(normalizeTimeSyncRequest({}), {
    check_offset: false,
    server: undefined,
  });
});

test("parseTimedatectlShow extracts Linux time sync fields", () => {
  assert.deepEqual(parseTimedatectlShow(`Timezone=Etc/UTC
LocalRTC=no
NTP=yes
CanNTP=yes
NTPSynchronized=yes
TimeUSec=Thu 2026-05-21 08:00:00 UTC
RTCTimeUSec=Thu 2026-05-21 08:00:01 UTC
`), {
    timezone: "Etc/UTC",
    local_rtc: false,
    ntp_enabled: true,
    can_ntp: true,
    synchronized: true,
    time_usec: "Thu 2026-05-21 08:00:00 UTC",
    rtc_time_usec: "Thu 2026-05-21 08:00:01 UTC",
  });
});

test("parseTimedatectlStatus extracts human status fields", () => {
  assert.deepEqual(parseTimedatectlStatus(`               Local time: Thu 2026-05-21 08:00:00 UTC
           Universal time: Thu 2026-05-21 08:00:00 UTC
                 RTC time: Thu 2026-05-21 08:00:00
                Time zone: Etc/UTC (UTC, +0000)
System clock synchronized: no
              NTP service: inactive
          RTC in local TZ: no
`), {
    timezone: "Etc/UTC (UTC, +0000)",
    synchronized: false,
    ntp_service_active: false,
    local_rtc: false,
  });
});

test("parseChronycTracking extracts offset and leap state", () => {
  assert.deepEqual(parseChronycTracking(`Reference ID    : C0A80101 (time.local)
Stratum         : 3
Ref time (UTC)  : Thu May 21 08:00:00 2026
System time     : 0.000123456 seconds slow of NTP time
Last offset     : -0.000111111 seconds
RMS offset      : 0.000222222 seconds
Leap status     : Normal
`), {
    reference_id: "C0A80101 (time.local)",
    stratum: 3,
    reference_time_utc: "Thu May 21 08:00:00 2026",
    system_time_offset_seconds: -0.000123456,
    last_offset_seconds: -0.000111111,
    rms_offset_seconds: 0.000222222,
    leap_status: "Normal",
  });
});

test("parseNtpqPeers parses selected peer offsets", () => {
  const peers = parseNtpqPeers(`     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
*time1.example   .GPS.            1 u   12   64  377    1.234   -0.456   0.123
+time2.example   time1.example    2 u   14   64  377    2.000    0.789   0.456
`);

  assert.equal(peers.length, 2);
  assert.equal(peers[0].selected, true);
  assert.equal(peers[0].remote, "time1.example");
  assert.equal(peers[0].offset_ms, -0.456);
  assert.equal(peers[1].selected, false);
});

test("parseMacSystemsetup extracts network time settings", () => {
  assert.deepEqual(parseMacSystemsetup(`Network Time: On
Network Time Server: time.apple.com
`), {
    network_time_enabled: true,
    network_time_server: "time.apple.com",
  });
});

test("parseLaunchctlPrintService extracts macOS timed service state", () => {
  assert.deepEqual(parseLaunchctlPrintService(`system/com.apple.timed = {
    state = running
    pid = 136
    last exit code = (never exited)
}`), {
    state: "running",
    pid: 136,
    last_exit_code: "(never exited)",
    running: true,
  });
});

test("parseSntpOutput extracts read-only offset probe output", () => {
  assert.deepEqual(parseSntpOutput(`+0.001139 +/- 0.004598 time.apple.com 17.253.108.125\n`), {
    offset_seconds: 0.001139,
    uncertainty_seconds: 0.004598,
    server: "time.apple.com",
    address: "17.253.108.125",
  });
});
