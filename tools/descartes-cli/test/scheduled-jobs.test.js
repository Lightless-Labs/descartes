import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeScheduledJobsRequest,
  parseCronContent,
  parseLaunchdPlistObject,
  parseSystemctlListTimers,
} from "../src/tools/scheduled-jobs.js";

test("normalizeScheduledJobsRequest clamps limits and preserves include flags", () => {
  assert.deepEqual(normalizeScheduledJobsRequest({ jobLimit: 999, includeSystem: false, includeUser: true }), {
    job_limit: 200,
    include_system: false,
    include_user: true,
  });
  assert.deepEqual(normalizeScheduledJobsRequest({ job_limit: -5, include_system: true, include_user: false }), {
    job_limit: 1,
    include_system: true,
    include_user: false,
  });
});

test("parseCronContent parses user crontab schedules and redacts commands", () => {
  const jobs = parseCronContent(`
# comment
SHELL=/bin/sh
*/5 * * * * /usr/local/bin/backup --token abc123 # rotate backups
@daily /usr/local/bin/report password=secret
`, { source: "user_crontab", path: "crontab -l" });

  assert.deepEqual(jobs, [
    {
      kind: "cron",
      source: "user_crontab",
      path: "crontab -l",
      line_number: 4,
      schedule: "*/5 * * * *",
      user: undefined,
      command: "/usr/local/bin/backup --token [REDACTED]",
      command_redaction: { redacted: true, truncated: false, original_length: 36, max_length: 260 },
    },
    {
      kind: "cron",
      source: "user_crontab",
      path: "crontab -l",
      line_number: 5,
      schedule: "@daily",
      user: undefined,
      command: "/usr/local/bin/report password=[REDACTED]",
      command_redaction: { redacted: true, truncated: false, original_length: 37, max_length: 260 },
    },
  ]);
});

test("parseCronContent parses system crontab user fields", () => {
  const jobs = parseCronContent(`
17 * * * * root cd / && run-parts --report /etc/cron.hourly
@reboot deploy /opt/app/start.sh --api-key sk-test
`, { source: "system_crontab", path: "/etc/crontab", hasUserField: true });

  assert.equal(jobs.length, 2);
  assert.equal(jobs[0].schedule, "17 * * * *");
  assert.equal(jobs[0].user, "root");
  assert.equal(jobs[0].command, "cd / && run-parts --report /etc/cron.hourly");
  assert.equal(jobs[1].schedule, "@reboot");
  assert.equal(jobs[1].user, "deploy");
  assert.equal(jobs[1].command, "/opt/app/start.sh --api-key [REDACTED]");
});

test("parseSystemctlListTimers extracts timer units from variable-width output", () => {
  const timers = parseSystemctlListTimers(`NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES
Thu 2026-05-21 10:00:00 UTC 4h left       Wed 2026-05-20 10:00:00 UTC 20h ago      apt-daily.timer              apt-daily.service
n/a                         n/a           n/a                         n/a          fstrim.timer                 fstrim.service
2 timers listed.
`, { scope: "system" });

  assert.deepEqual(timers, [
    {
      kind: "systemd_timer",
      source: "systemd_timers",
      scope: "system",
      unit: "apt-daily.timer",
      activates: "apt-daily.service",
      timing: "Thu 2026-05-21 10:00:00 UTC 4h left Wed 2026-05-20 10:00:00 UTC 20h ago",
      raw: "Thu 2026-05-21 10:00:00 UTC 4h left       Wed 2026-05-20 10:00:00 UTC 20h ago      apt-daily.timer              apt-daily.service",
    },
    {
      kind: "systemd_timer",
      source: "systemd_timers",
      scope: "system",
      unit: "fstrim.timer",
      activates: "fstrim.service",
      timing: "n/a n/a n/a n/a",
      raw: "n/a                         n/a           n/a                         n/a          fstrim.timer                 fstrim.service",
    },
  ]);
});

test("parseLaunchdPlistObject returns only scheduled launchd jobs", () => {
  const job = parseLaunchdPlistObject({
    Label: "com.example.cleanup",
    ProgramArguments: ["/usr/local/bin/cleanup", "--password", "secret"],
    StartInterval: 3600,
    StartCalendarInterval: [{ Hour: 3, Minute: 15 }],
    RunAtLoad: true,
  }, { path: "/Library/LaunchDaemons/com.example.cleanup.plist", scope: "system" });

  assert.deepEqual(job, {
    kind: "launchd_scheduled_job",
    source: "launchd_plist",
    scope: "system",
    label: "com.example.cleanup",
    path: "/Library/LaunchDaemons/com.example.cleanup.plist",
    start_interval_seconds: 3600,
    start_calendar_interval: [{ Hour: 3, Minute: 15 }],
    run_at_load: true,
    command: "/usr/local/bin/cleanup --password [REDACTED]",
    command_redaction: { redacted: true, truncated: false, original_length: 40, max_length: 260 },
  });

  assert.equal(parseLaunchdPlistObject({ Label: "com.example.unscheduled", RunAtLoad: true }), undefined);
});
