import assert from "node:assert/strict";
import test from "node:test";
import {
  parseLaunchctlList,
  parseSystemctlListUnits,
  summarizeLaunchdServices,
  summarizeSystemdServices,
} from "../src/tools/services.js";

test("parseSystemctlListUnits parses service state rows and strips failure bullets", () => {
  const services = parseSystemctlListUnits(`UNIT                            LOAD   ACTIVE     SUB          DESCRIPTION
accounts-daemon.service         loaded active     running      Accounts Service
● apache2.service               loaded failed     failed       The Apache HTTP Server
postgresql.service              loaded active     exited       PostgreSQL RDBMS
restarting.service              loaded activating auto-restart Restarting Example
systemd-journald.socket         loaded active     running      Journal Socket
LOAD   = Reflects whether the unit definition was properly loaded.
4 loaded units listed.
`);

  assert.deepEqual(services, [
    {
      name: "accounts-daemon.service",
      load: "loaded",
      active: "active",
      sub: "running",
      description: "Accounts Service",
      failed: false,
      running: true,
      restarting: false,
    },
    {
      name: "apache2.service",
      load: "loaded",
      active: "failed",
      sub: "failed",
      description: "The Apache HTTP Server",
      failed: true,
      running: false,
      restarting: false,
    },
    {
      name: "postgresql.service",
      load: "loaded",
      active: "active",
      sub: "exited",
      description: "PostgreSQL RDBMS",
      failed: false,
      running: false,
      restarting: false,
    },
    {
      name: "restarting.service",
      load: "loaded",
      active: "activating",
      sub: "auto-restart",
      description: "Restarting Example",
      failed: false,
      running: false,
      restarting: true,
    },
  ]);
});

test("summarizeSystemdServices counts failed and restarting services", () => {
  const services = parseSystemctlListUnits(`accounts-daemon.service loaded active running Accounts Service
apache2.service loaded failed failed The Apache HTTP Server
postgresql.service loaded active exited PostgreSQL RDBMS
restarting.service loaded activating auto-restart Restarting Example
`);

  assert.deepEqual(summarizeSystemdServices(services, { limit: 1 }), {
    manager: "systemd",
    total_count: 4,
    running_count: 1,
    failed_count: 1,
    restarting_count: 1,
    exited_count: 1,
    inactive_count: 0,
    failed_services: [services[1]],
    restarting_services: [services[3]],
  });
});

test("parseLaunchctlList parses launchd rows", () => {
  const services = parseLaunchctlList(`PID\tStatus\tLabel
123\t0\tcom.example.running
-\t0\tcom.example.clean-exit
-\t78\tcom.example.failed
456 -9 com.example.signal-exit
`);

  assert.deepEqual(services, [
    {
      label: "com.example.running",
      pid: 123,
      last_exit_status: 0,
      state: "running",
      nonzero_exit: false,
    },
    {
      label: "com.example.clean-exit",
      pid: null,
      last_exit_status: 0,
      state: "not_running",
      nonzero_exit: false,
    },
    {
      label: "com.example.failed",
      pid: null,
      last_exit_status: 78,
      state: "not_running",
      nonzero_exit: true,
    },
    {
      label: "com.example.signal-exit",
      pid: 456,
      last_exit_status: -9,
      state: "running",
      nonzero_exit: true,
    },
  ]);
});

test("summarizeLaunchdServices counts nonzero exits and bounds examples", () => {
  const services = parseLaunchctlList(`PID Status Label
123 0 com.example.running
- 78 com.example.failed
- 1 com.example.failed-too
`);

  assert.deepEqual(summarizeLaunchdServices(services, { limit: 1 }), {
    manager: "launchd",
    total_count: 3,
    running_count: 1,
    not_running_count: 2,
    nonzero_exit_count: 2,
    nonzero_exit_services: [services[1]],
  });
});
