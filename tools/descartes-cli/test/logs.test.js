import assert from "node:assert/strict";
import test from "node:test";
import {
  categorizeLogEntry,
  normalizeLogRequest,
  parseJournalctlJsonLines,
  parseMacUnifiedLogJson,
  parseSyslogLines,
  redactAndBoundLogMessage,
} from "../src/tools/logs.js";

test("normalizeLogRequest clamps time, event, and message bounds", () => {
  assert.deepEqual(normalizeLogRequest({ windowMinutes: 999, eventLimit: 999, messageChars: 9999, includeSecurity: false }), {
    window_minutes: 360,
    event_limit: 200,
    message_chars: 1200,
    include_security: false,
  });
  assert.deepEqual(normalizeLogRequest({ window_minutes: 0, event_limit: -1, message_chars: 1 }), {
    window_minutes: 1,
    event_limit: 1,
    message_chars: 80,
    include_security: true,
  });
});

test("redactAndBoundLogMessage redacts obvious secrets and bounds excerpts", () => {
  const redacted = redactAndBoundLogMessage("failed password=opensesame token=abc123 Authorization: Bearer super-secret-token", { maxChars: 200 });
  assert.equal(redacted.value, "failed password=[REDACTED] token=[REDACTED] Authorization: Bearer [REDACTED]");
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.truncated, false);

  const bounded = redactAndBoundLogMessage("x".repeat(90), { maxChars: 80 });
  assert.equal(bounded.value.length, 81);
  assert.equal(bounded.value.endsWith("…"), true);
  assert.equal(bounded.truncated, true);
});

test("categorizeLogEntry recognizes fail2ban, firewall, auth, and crash signals", () => {
  assert.equal(categorizeLogEntry({ message: "fail2ban.actions banned 203.0.113.10" }), "fail2ban");
  assert.equal(categorizeLogEntry({ message: "UFW BLOCK IN=en0 SRC=203.0.113.10" }), "firewall");
  assert.equal(categorizeLogEntry({ message: "sshd: Failed password for invalid user root" }), "auth");
  assert.equal(categorizeLogEntry({ message: "worker crashed with segfault" }), "crash");
  assert.equal(categorizeLogEntry({ message: "ordinary warning" }), "general");
});

test("parseJournalctlJsonLines parses bounded sanitized journal entries", () => {
  const stdout = [
    JSON.stringify({ __REALTIME_TIMESTAMP: "1716200000000000", PRIORITY: "3", _SYSTEMD_UNIT: "ssh.service", SYSLOG_IDENTIFIER: "sshd", _PID: "123", MESSAGE: "Failed password for invalid user admin token=abc123" }),
    "not json",
    JSON.stringify({ __REALTIME_TIMESTAMP: "1716200001000000", PRIORITY: "4", _SYSTEMD_UNIT: "ufw.service", SYSLOG_IDENTIFIER: "kernel", MESSAGE: "UFW BLOCK IN=eth0 SRC=203.0.113.10" }),
  ].join("\n");

  const entries = parseJournalctlJsonLines(stdout, { limit: 10, messageChars: 120 });
  assert.deepEqual(entries, [
    {
      ts: "2024-05-20T10:13:20.000Z",
      source: "journal",
      category: "auth",
      severity: "error",
      message: "Failed password for invalid user admin token=[REDACTED]",
      message_redaction: { redacted: true, truncated: false, original_length: 51, max_chars: 120 },
      priority: 3,
      unit: "ssh.service",
      identifier: "sshd",
      pid: 123,
    },
    {
      ts: "2024-05-20T10:13:21.000Z",
      source: "journal",
      category: "firewall",
      severity: "warning",
      message: "UFW BLOCK IN=eth0 SRC=203.0.113.10",
      message_redaction: { redacted: false, truncated: false, original_length: 34, max_chars: 120 },
      priority: 4,
      unit: "ufw.service",
      identifier: "kernel",
    },
  ]);
});

test("parseJournalctlJsonLines supports category filtering", () => {
  const stdout = [
    JSON.stringify({ PRIORITY: "4", MESSAGE: "ordinary warning" }),
    JSON.stringify({ PRIORITY: "4", MESSAGE: "nftables DROP packet" }),
  ].join("\n");

  assert.deepEqual(parseJournalctlJsonLines(stdout, { categoryFilter: (category) => category === "firewall" }).map((entry) => entry.category), ["firewall"]);
});

test("parseMacUnifiedLogJson parses line-delimited and array JSON", () => {
  const lineDelimited = [
    JSON.stringify({ timestamp: "2026-05-20 10:00:00.000000-0700", messageType: "error", process: "socketfilterfw", subsystem: "com.apple.alf", eventMessage: "Firewall blocked incoming connection" }),
    JSON.stringify({ timestamp: "2026-05-20 10:00:01.000000-0700", messageType: "fault", process: "app", composedMessage: "worker crashed" }),
  ].join("\n");

  assert.deepEqual(parseMacUnifiedLogJson(lineDelimited, { limit: 1 }).map((entry) => entry.category), ["firewall"]);

  const arrayJson = JSON.stringify([{ timestamp: "now", messageType: "error", process: "fail2ban", eventMessage: "fail2ban jail started" }]);
  assert.equal(parseMacUnifiedLogJson(arrayJson)[0].category, "fail2ban");
});

test("parseSyslogLines parses fail2ban and ufw log-file excerpts", () => {
  const entries = parseSyslogLines(`May 20 12:34:01 host fail2ban.actions[123]: NOTICE [sshd] Ban 203.0.113.10\nMay 20 12:35:01 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.11\n`, {
    source: "ufw_log",
    rawFile: "/var/log/ufw.log",
  });

  assert.equal(entries[0].category, "fail2ban");
  assert.equal(entries[0].identifier, "fail2ban.actions");
  assert.equal(entries[0].raw_file, "/var/log/ufw.log");
  assert.equal(entries[1].category, "firewall");
});
