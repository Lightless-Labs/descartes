import assert from "node:assert/strict";
import test from "node:test";
import { parsePs, psArgsForPlatform, topProcessesBy } from "../src/tools/processes.js";

test("psArgsForPlatform uses Linux procps-compatible syntax", () => {
  assert.deepEqual(psArgsForPlatform("linux"), ["-eo", "pid,ppid,pcpu,pmem,rss,comm,args"]);
  assert(!psArgsForPlatform("linux").includes("-axo"));
});

test("psArgsForPlatform preserves BSD-style syntax for macOS", () => {
  assert.deepEqual(psArgsForPlatform("darwin"), ["-axo", "pid,ppid,pcpu,pmem,rss,comm,args"]);
});

test("parsePs parses process rows and topProcessesBy sorts in-process", () => {
  const rows = parsePs(`  PID  PPID  %CPU %MEM   RSS COMM             COMMAND
    1     0   0.1  0.2 11000 systemd          /sbin/init
   42     1  12.5  3.0 50000 node             node server.js --token abc
   99     1   4.0  9.5 80000 postgres         postgres: writer process
`);

  assert.equal(rows.length, 3);
  assert.equal(rows[1].pid, 42);
  assert.equal(rows[1].args, "node server.js --token abc");
  assert.deepEqual(topProcessesBy(rows, "cpu_percent", 2).map((process) => process.pid), [42, 99]);
  assert.deepEqual(topProcessesBy(rows, "memory_percent", 2).map((process) => process.pid), [99, 42]);
});
