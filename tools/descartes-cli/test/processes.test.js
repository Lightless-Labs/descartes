import assert from "node:assert/strict";
import test from "node:test";
import {
  buildInspectProcessResult,
  buildParentTreeResult,
  parsePs,
  psArgsForPlatform,
  redactAndBoundProcessArgs,
  topProcessesBy,
} from "../src/tools/processes.js";

test("psArgsForPlatform uses Linux procps-compatible syntax", () => {
  assert.deepEqual(psArgsForPlatform("linux"), ["-eo", "pid,ppid,pcpu,pmem,rss,comm,args"]);
  assert(!psArgsForPlatform("linux").includes("-axo"));
});

test("psArgsForPlatform preserves BSD-style syntax for macOS", () => {
  assert.deepEqual(psArgsForPlatform("darwin"), ["-axo", "pid,ppid,pcpu,pmem,rss,comm,args"]);
});

test("redactAndBoundProcessArgs redacts obvious secret assignments and following secret flag values", () => {
  const redacted = redactAndBoundProcessArgs("node server.js --token abc123 password=hunter2 key=value --api-key sk-test-123");

  assert.equal(redacted.value, "node server.js --token [REDACTED] password=[REDACTED] key=[REDACTED] --api-key [REDACTED]");
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.truncated, false);
  assert.equal(redacted.original_length, 78);
});

test("redactAndBoundProcessArgs redacts high-entropy long values and bounds output", () => {
  const secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z";
  const redacted = redactAndBoundProcessArgs(`python worker.py ${secret} --mode ingest ${"x".repeat(80)}`, { maxLength: 42, maxTokenLength: 30 });

  assert.match(redacted.value, /^python worker\.py \[REDACTED\]/);
  assert(redacted.value.length <= 43); // max plus ellipsis
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.truncated, true);
});

test("parsePs parses process rows, redacts args, and topProcessesBy sorts in-process", () => {
  const rows = parsePs(`  PID  PPID  %CPU %MEM   RSS COMM             COMMAND
    1     0   0.1  0.2 11000 systemd          /sbin/init
   42     1  12.5  3.0 50000 node             node server.js --token abc
   99     1   4.0  9.5 80000 postgres         postgres: writer process
`);

  assert.equal(rows.length, 3);
  assert.equal(rows[1].pid, 42);
  assert.equal(rows[1].args, "node server.js --token [REDACTED]");
  assert.deepEqual(rows[1].args_redaction, {
    redacted: true,
    truncated: false,
    original_length: 26,
    max_length: 240,
  });
  assert.deepEqual(topProcessesBy(rows, "cpu_percent", 2).map((process) => process.pid), [42, 99]);
  assert.deepEqual(topProcessesBy(rows, "memory_percent", 2).map((process) => process.pid), [99, 42]);
});

test("buildInspectProcessResult returns process identity, parent, and children", () => {
  const processes = parsePs(`  PID  PPID  %CPU %MEM   RSS COMM             COMMAND
    1     0   0.1  0.2 11000 launchd          /sbin/launchd
   10     1   0.5  1.0 20000 zsh              /bin/zsh
   42    10  12.5  3.0 50000 node             node server.js
   43    42   4.0  0.5 10000 worker           worker --password nope
`);

  const inspection = buildInspectProcessResult(processes, 42, { argv: ["ps"], read_only: true }, { executable_path: "/usr/local/bin/node", uid: 501 });

  assert.equal(inspection.status, "ok");
  assert.equal(inspection.result.found, true);
  assert.equal(inspection.result.process.pid, 42);
  assert.equal(inspection.result.parent.pid, 10);
  assert.equal(inspection.result.child_count, 1);
  assert.equal(inspection.result.top_children[0].args, "worker --password [REDACTED]");
  assert.equal(inspection.result.executable_path, "/usr/local/bin/node");
  assert.equal(inspection.result.uid, 501);
});

test("buildInspectProcessResult handles missing processes gracefully", () => {
  const inspection = buildInspectProcessResult([], 4242, { argv: ["ps"], read_only: true });

  assert.equal(inspection.status, "unknown");
  assert.equal(inspection.reviewHint, "ambiguous");
  assert.deepEqual(inspection.result, {
    pid: 4242,
    found: false,
    reason: "process_not_found_or_permission_limited",
    command: { argv: ["ps"], read_only: true },
  });
});

test("buildParentTreeResult returns bounded ancestry chain", () => {
  const processes = parsePs(`  PID  PPID  %CPU %MEM   RSS COMM             COMMAND
    1     0   0.1  0.2 11000 launchd          /sbin/launchd
   10     1   0.5  1.0 20000 zsh              /bin/zsh
   42    10  12.5  3.0 50000 node             node server.js
   43    42   4.0  0.5 10000 worker           worker --token abc
`);

  const tree = buildParentTreeResult(processes, 43, 16, { argv: ["ps"], read_only: true });

  assert.equal(tree.status, "ok");
  assert.deepEqual(tree.result.chain.map((item) => item.pid), [43, 42, 10, 1]);
  assert.equal(tree.result.chain[0].args, "worker --token [REDACTED]");
  assert.equal(tree.result.missing_parent, false);
  assert.equal(tree.result.truncated_by_depth, false);
});

test("buildParentTreeResult records depth truncation and missing targets", () => {
  const processes = parsePs(`  PID  PPID  %CPU %MEM   RSS COMM             COMMAND
    1     0   0.1  0.2 11000 init             /sbin/init
    2     1   0.1  0.2 11000 shell            shell
    3     2   0.1  0.2 11000 node             node
`);

  const truncated = buildParentTreeResult(processes, 3, 2);
  assert.equal(truncated.reviewHint, "ambiguous");
  assert.equal(truncated.result.truncated_by_depth, true);
  assert.deepEqual(truncated.result.chain.map((item) => item.pid), [3, 2]);

  const missing = buildParentTreeResult(processes, 999);
  assert.equal(missing.status, "unknown");
  assert.equal(missing.result.found, false);
});
