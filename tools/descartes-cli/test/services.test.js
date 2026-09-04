import assert from "node:assert/strict";
import test from "node:test";
import {
  collectLaunchdServices,
  collectServiceEvidence,
  collectSystemdServices,
  DEFAULT_SERVICE_CENSUS_CEILING,
  parseLaunchctlList,
  parseSystemctlListUnits,
  summarizeLaunchdServices,
  summarizeSystemdServices,
} from "../src/tools/services.js";

// --- F3 fix: presentation (<=80, human/LLM display) vs authoritative (census-sanity-ceiling,
// baseline-feeding) service inventory split. Fixture builders + a DI-injectable fake command
// runner (mirrors tools/tailscale-status.js's runFixedExecFile injection point) so these
// collectors can be exercised without a real systemctl/launchctl on the machine running the
// suite.

function systemdFixtureStdout(count) {
  const lines = ["UNIT                            LOAD   ACTIVE     SUB          DESCRIPTION"];
  for (let i = 0; i < count; i += 1) {
    lines.push(`svc${String(i).padStart(6, "0")}.service loaded active running Fixture service ${i}`);
  }
  lines.push(`${count} loaded units listed.`);
  return lines.join("\n");
}

function launchdFixtureStdout(count) {
  const lines = ["PID\tStatus\tLabel"];
  for (let i = 0; i < count; i += 1) {
    lines.push(`${1000 + i}\t0\tcom.example.job${String(i).padStart(6, "0")}`);
  }
  return lines.join("\n");
}

function fakeRunOk(stdout) {
  return async (command, args = []) => ({
    status: "ok",
    stdout,
    stderr: "",
    command: { argv: [command, ...args], read_only: true },
  });
}

function fakeRunUnable(message = "fixture-injected failure") {
  return async (command, args = []) => ({
    status: "unable",
    error: message,
    stdout: "",
    stderr: "",
    command: { argv: [command, ...args], read_only: true },
  });
}

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

// --- F3 fix: presentation/authoritative split ---

test("collectSystemdServices on a 150-unit host: presentation `services` stays <=80, authoritative `services_census` carries all 150, and truncated stays false (a normal >80-service host must never read truncated:true)", async () => {
  const result = await collectSystemdServices(80, DEFAULT_SERVICE_CENSUS_CEILING, fakeRunOk(systemdFixtureStdout(150)));

  assert.equal(result.status, "ok");
  assert.equal(result.summary.total_count, 150, "the summary's own counts are already computed against the FULL list, unaffected by this fix");
  assert.ok(result.services.length <= 80, `presentation-bounded services must stay <=80, got ${result.services.length}`);
  assert.equal(result.services_census.length, 150, "authoritative census must carry every genuinely-enumerated unit, not just the first 80");
  assert.equal(result.truncated, false, "150 > 80 (the old presentation cap) but well under the census sanity ceiling — must read truncated:false");
  // Authoritative entries carry the {name, running} identity projection fact-translators.js needs.
  assert.deepEqual(result.services_census[149], { name: "svc000149.service", running: true });
});

test("collectLaunchdServices on a 150-job host: same presentation/authoritative split, truncated:false", async () => {
  const result = await collectLaunchdServices(80, DEFAULT_SERVICE_CENSUS_CEILING, fakeRunOk(launchdFixtureStdout(150)));

  assert.equal(result.status, "ok");
  assert.equal(result.summary.total_count, 150);
  assert.ok(result.services.length <= 80, `presentation-bounded services must stay <=80, got ${result.services.length}`);
  assert.equal(result.services_census.length, 150);
  assert.equal(result.truncated, false);
  assert.deepEqual(result.services_census[149], { label: "com.example.job000149", state: "running" });
});

test("collectSystemdServices on a host exceeding the census sanity ceiling: truncated:true, services_census capped at the ceiling (not unbounded), and the truncation is logged (no silent cap)", async (t) => {
  const warnMock = t.mock.method(console, "warn", () => {});
  const overCeilingCount = DEFAULT_SERVICE_CENSUS_CEILING + 500; // pathological, well beyond any real host
  const result = await collectSystemdServices(80, DEFAULT_SERVICE_CENSUS_CEILING, fakeRunOk(systemdFixtureStdout(overCeilingCount)));

  assert.equal(result.status, "ok");
  assert.equal(result.summary.total_count, overCeilingCount, "the summary still reports the true full count");
  assert.equal(result.truncated, true, "genuinely exceeding the sanity ceiling must set truncated:true");
  assert.equal(result.services_census.length, DEFAULT_SERVICE_CENSUS_CEILING, "the authoritative array itself must still be capped — not literally unbounded");
  assert.ok(result.services.length <= 80, "the presentation array is unaffected and stays <=80");
  assert.equal(warnMock.mock.calls.length, 1, "truncation past the sanity ceiling must be logged, not a silent cap");
  assert.match(String(warnMock.mock.calls[0].arguments[0]), /truncated/i);
});

test("collectSystemdServices: a genuine enumeration failure (execFile error) still yields status:'unable' with empty presentation AND authoritative arrays and truncated:false — the fix must not touch the degrade-not-fabricate failure path", async () => {
  const result = await collectSystemdServices(80, DEFAULT_SERVICE_CENSUS_CEILING, fakeRunUnable("boom: systemctl not found"));

  assert.equal(result.status, "unable");
  assert.deepEqual(result.services, []);
  assert.deepEqual(result.services_census, []);
  assert.equal(result.truncated, false);
  assert.equal(result.error, "boom: systemctl not found");
});

test("collectServiceEvidence wires the presentation limit and the (default) census ceiling through to whichever platform collector runs, via the injected runFixedCommand test seam", async () => {
  // Platform-agnostic: exercise via collectServiceEvidence's own DI seam rather than assuming
  // process.platform, since this suite may run on either linux or darwin CI/dev hosts. A single
  // fake command handles both systemctl and launchctl argv shapes.
  const stdout = process.platform === "linux" ? systemdFixtureStdout(150) : launchdFixtureStdout(150);
  const envelope = await collectServiceEvidence({ runFixedCommand: fakeRunOk(stdout) });

  if (envelope.result.manager === "unsupported") return; // unsupported test platform — nothing to assert
  assert.equal(envelope.result.status, "ok");
  assert.ok(envelope.result.services.length <= 80);
  assert.equal(envelope.result.services_census.length, 150);
  assert.equal(envelope.result.truncated, false);
});
