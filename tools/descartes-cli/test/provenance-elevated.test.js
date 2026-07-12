// S3-priv Slice 2 — elevated-path plumbing tests, entirely against an INJECTABLE MOCK HELPER. No
// real privilege, no Rust, no setcap/sudo anywhere in this file. See
// docs/plans/2026-07-11-s3-priv-elevated-read-path.md §0/§1.
//
// THE LOAD-BEARING DEGRADE INVARIANT under test throughout: every elevated-path FAILURE mode
// returns the already-computed unprivileged `status:'partial'`, `confidence:0.4`,
// `review_hint:'missing_permission'` result WITH the owning uid preserved -- never the
// more-degraded `unable`/`confidence:0` shape (that shape is timedEnvelope's thrown-exception
// contract only -- see test/provenance.test.js:334-343 -- and is never exercised by this file).
//
// DI precedent mirrors provenance-identity.js's shipped shape verbatim (plain object literals,
// zero mocking library) -- `fakeElevatedOptions({...})` below is that same pattern.

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { writeProvenanceConfig } from "../src/provenance-elevated-config.js";
import {
  computeProvenanceEnvelopeFields,
  resolveCrossUidPortResult,
} from "../src/tools/provenance.js";
import {
  DEFAULT_HELPER_PATH,
  defaultInvokeElevatedHelper,
  defaultProbeElevatedHelper,
  parseAndVerifyHelperResponse,
  readPtraceScopeDiagnostic,
  resolveElevated,
  verifyTrustBoundary,
} from "../src/tools/provenance-elevated.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-elevated-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const FIXTURE_HELPER_PATH = "/opt/descartes-test-fixture/bin/root_helper";

function ancestorsOf(targetPath) {
  const dirs = [];
  let current = path.dirname(targetPath);
  while (true) {
    dirs.push(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return dirs;
}

// Safe/trusted fixture for FIXTURE_HELPER_PATH and its full ancestor chain: root-owned, not
// group/world-writable anywhere -- the "everything checks out" baseline every trust-boundary
// negative test starts from and overrides exactly one entry of.
function trustedHelperFixture(helperPath = FIXTURE_HELPER_PATH) {
  const entries = { [helperPath]: { mode: 0o750, uid: 0 } };
  for (const dir of ancestorsOf(helperPath)) entries[dir] = { mode: 0o755, uid: 0 };
  return entries;
}

// Plain object literal DI helper (no mocking library, per repo precedent). `statOverrides` falls
// back to the REAL fs.stat for any path not explicitly listed -- so a real tempPaths() config
// file/dir (created 0600/0700 by writeProvenanceConfig, owned by the current test principal)
// passes the trust check for free, and only the fictitious helper path needs canned fixtures.
function fakeElevatedOptions({ statOverrides = trustedHelperFixture(), helperPath = FIXTURE_HELPER_PATH, ...rest } = {}) {
  return {
    helperPath,
    statFn: async (targetPath) => {
      if (Object.prototype.hasOwnProperty.call(statOverrides, targetPath)) return statOverrides[targetPath];
      return fs.stat(targetPath);
    },
    ...rest,
  };
}

function validHelperStdout({ port, pid = 4242, uid = 1000, executablePath = "/opt/svc/bin/app", command = "app" } = {}) {
  return JSON.stringify({ requested: { port }, resolved: { pid, uid, executable_path: executablePath, command } });
}

// ---------------------------------------------------------------------------------------------
// 1/2. Two-condition AND gate: config.elevated.enabled===true AND probe available:true. Both
// legs are independently load-bearing.
// ---------------------------------------------------------------------------------------------

test("resolveElevated never attempts when config is disabled, even though the helper would probe available (config wins)", async () => {
  const paths = await tempPaths(); // no provenance.json written -> defaults to disabled.
  let probeCalls = 0;
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => { probeCalls++; return { available: true }; },
    invokeElevatedHelper: async () => { throw new Error("must not be called when config is disabled"); },
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
  assert.equal(probeCalls, 0, "the gate must short-circuit on config before ever probing the helper");
});

test("resolveElevated never attempts when the helper is absent (probe reports unavailable), even with config enabled", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  let invokeCalls = 0;
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: false }), // ENOENT-equivalent, per defaultProbeElevatedHelper's own contract.
    invokeElevatedHelper: async () => { invokeCalls++; throw new Error("must not be called when the probe is unavailable"); },
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
  assert.equal(invokeCalls, 0);
});

test("resolveCrossUidPortResult falls through to the unprivileged partial/0.4/missing_permission baseline when the gate fails (either leg)", async () => {
  const paths = await tempPaths(); // disabled default.
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  const options = fakeElevatedOptions({ paths, probeElevatedHelper: async () => ({ available: true }) });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(outcome.resolvedStatus, "partial");
  assert.equal(outcome.result.resolved.status, "partial");
  assert.equal(outcome.result.resolved.pid, undefined);
  assert.equal(outcome.result.resolved.user.uid, 1000, "the owning uid is a free confident fact and must be preserved");
  assert.deepEqual(outcome.result.privilege, { mechanism: "unprivileged", elevated_available: false, elevated_used: false });

  const fields = computeProvenanceEnvelopeFields(outcome.resolvedStatus, outcome.result.source.type);
  assert.deepEqual(fields, { status: "partial", confidence: 0.4, reviewHint: "missing_permission" });
});

// ---------------------------------------------------------------------------------------------
// 3. Successful elevated upgrade: partial/0.4 -> ok/1, elevated_used:true, privilege.mechanism set.
// ---------------------------------------------------------------------------------------------

test("resolveElevated returns a verified success descriptor when config is enabled, probe succeeds, and the echo-back matches", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080 }) }),
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.deepEqual(result, { pid: 4242, uid: 1000, executablePath: "/opt/svc/bin/app", command: "app", mechanism: "cap_sys_ptrace" });
});

test("resolveCrossUidPortResult upgrades the partial/0.4 baseline to a resolved ok/1 pid record on a verified elevated success, with the real ptrace_scope diagnostic attached", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  const options = fakeElevatedOptions({
    paths,
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080 }) }),
    // DI'd rather than left to the real host's /proc/sys/kernel/yama/ptrace_scope -- this
    // repo's tests never depend on real host state (see fakeElevatedOptions's own statFn
    // precedent), and a Linux CI host's real value (non-undefined) would otherwise silently
    // change this assertion depending on where the suite runs.
    readFile: async () => "1\n",
  });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(outcome.resolvedStatus, "ok");
  assert.equal(outcome.result.resolved.status, "ok");
  assert.equal(outcome.result.resolved.pid, 4242);
  assert.equal(outcome.result.resolved.executable_path, "/opt/svc/bin/app");
  assert.deepEqual(outcome.result.privilege, { mechanism: "cap_sys_ptrace", elevated_available: true, elevated_used: true, ptrace_scope: "1" });

  const fields = computeProvenanceEnvelopeFields(outcome.resolvedStatus, outcome.result.source.type);
  assert.deepEqual(fields, { status: "ok", confidence: 1, reviewHint: "none" }, "upgrade must reach the same ok/1/none envelope shape as an own-uid resolution");
});

test("resolveCrossUidPortResult degrades when the helper's self-reported uid disagrees with the trusted owning uid (never overwrites a free fact), with the real ptrace_scope diagnostic attached", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  const options = fakeElevatedOptions({
    paths,
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    // Helper self-reports uid 4242, contradicting the trusted primary.uid 1000.
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080, uid: 4242 }) }),
    readFile: async () => "2\n",
  });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(outcome.resolvedStatus, "partial", "a helper uid contradicting the known-good owning uid must degrade, not upgrade");
  assert.equal(outcome.result.resolved.pid, undefined, "the contradictory helper's pid is not trusted either");
  assert.equal(outcome.result.resolved.user.uid, 1000, "the trusted unprivileged-derived owning uid is preserved");
  // Most valuable ON FAILURE: an elevated attempt was genuinely configured and reached a real
  // helper response, but degraded anyway -- the ptrace_scope value is surfaced here precisely
  // because this is a case an operator would want to correlate against.
  assert.deepEqual(outcome.result.privilege, { mechanism: "unprivileged", elevated_available: false, elevated_used: false, ptrace_scope: "2" });
});

test("resolveCrossUidPortResult bounds the untrusted helper's executable_path (truncated) before it reaches the envelope/LLM", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  const longPath = "/x".repeat(1500); // 3000 chars, > the 2048 truncate bound, still < the 8KB response cap
  const options = fakeElevatedOptions({
    paths,
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080, uid: 1000, executablePath: longPath, command: "app" }) }),
  });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(outcome.resolvedStatus, "ok");
  assert(outcome.result.resolved.executable_path.length <= 2049, "executable_path bounded like the unprivileged path");
  assert(outcome.result.resolved.executable_path.endsWith("…"), "over-long path is visibly truncated, not passed verbatim");
});

// ---------------------------------------------------------------------------------------------
// 4. Fixed-argv assertion.
// ---------------------------------------------------------------------------------------------

test("resolveElevated invokes the helper with a literal, bounded argv array -- never a template/interpolated string", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  let capturedArgv;
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async (_helperPath, argv) => {
      capturedArgv = argv;
      return { status: "ok", stdout: validHelperStdout({ port: 8080 }) };
    },
  });

  await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(Array.isArray(capturedArgv), true);
  assert.deepEqual(capturedArgv, ["--resolve-port", "8080"]);
  assert.equal(typeof capturedArgv[0], "string");
  assert.equal(typeof capturedArgv[1], "string");

  const pidOptions = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async (_helperPath, argv) => {
      capturedArgv = argv;
      return { status: "unable", stdout: "" };
    },
  });
  await resolveElevated({ target: { kind: "pid", value: 9999 }, paths }, pidOptions);
  assert.deepEqual(capturedArgv, ["--resolve-pid", "9999"]);
});

// ---------------------------------------------------------------------------------------------
// 5. Probe timeout: degrades, bounded, never hangs the collector.
// ---------------------------------------------------------------------------------------------

test("resolveElevated degrades (does not hang) when the probe times out", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const options = fakeElevatedOptions({
    // Emulates a bounded execFile timeout: rejects after a short, injected delay rather than
    // hanging forever.
    probeElevatedHelper: () => new Promise((_resolve, reject) => {
      setTimeout(() => reject(Object.assign(new Error("ETIMEDOUT"), { code: "ETIMEDOUT", killed: true })), 20);
    }),
  });

  const startedAt = Date.now();
  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  const elapsedMs = Date.now() - startedAt;
  assert.equal(result, undefined);
  assert.ok(elapsedMs < 2000, `expected the bounded probe timeout to resolve quickly, took ${elapsedMs}ms`);
});

// ---------------------------------------------------------------------------------------------
// 8. Malformed / oversized helper response: degrades, never a partial-parse merge.
// ---------------------------------------------------------------------------------------------

test("resolveElevated degrades on malformed JSON stdout from the helper", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: "not-json{{{" }),
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
});

test("resolveElevated degrades on an oversized helper response, rejected before JSON.parse is even attempted", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const oversized = JSON.stringify({ requested: { port: 8080 }, resolved: { pid: 4242, uid: 1000, padding: "x".repeat(100_000) } });
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: oversized }),
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
  assert.equal(parseAndVerifyHelperResponse(oversized, { kind: "port", value: 8080 }), undefined);
});

// ---------------------------------------------------------------------------------------------
// 9. Echo-back scope mismatch: a well-formed response for a DIFFERENT pid/port never merges.
// ---------------------------------------------------------------------------------------------

test("resolveElevated degrades when the helper echoes back a different port than requested (scope mismatch)", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 9999 }) }), // requested 8080, echoes 9999.
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
});

test("parseAndVerifyHelperResponse rejects a response describing a different pid/port than requested", () => {
  const stdout = validHelperStdout({ port: 9999 });
  assert.equal(parseAndVerifyHelperResponse(stdout, { kind: "port", value: 8080 }), undefined);
  assert.deepEqual(
    parseAndVerifyHelperResponse(stdout, { kind: "port", value: 9999 }),
    { pid: 4242, uid: 1000, executable_path: "/opt/svc/bin/app", command: "app" },
  );
});

// ---------------------------------------------------------------------------------------------
// 10. Trust-boundary rejection, including the ancestor-directory dir-hijack vector.
// ---------------------------------------------------------------------------------------------

test("verifyTrustBoundary rejects a group/world-writable helper binary", async () => {
  const fixture = trustedHelperFixture();
  fixture[FIXTURE_HELPER_PATH] = { mode: 0o777, uid: 0 };
  const outcome = await verifyTrustBoundary(
    { helperPath: FIXTURE_HELPER_PATH },
    { statFn: async (p) => fixture[p] ?? fs.stat(p) },
  );
  assert.equal(outcome.trusted, false);
});

test("verifyTrustBoundary rejects a helper binary not owned by root or the running principal", async () => {
  const fixture = trustedHelperFixture();
  fixture[FIXTURE_HELPER_PATH] = { mode: 0o750, uid: 31337 };
  const outcome = await verifyTrustBoundary(
    { helperPath: FIXTURE_HELPER_PATH },
    { statFn: async (p) => fixture[p] ?? fs.stat(p), expectedUid: 1000 },
  );
  assert.equal(outcome.trusted, false);
});

test("verifyTrustBoundary rejects the dir-hijack case: leaf binary correctly 0750 root:root but its PARENT dir is 0777", async () => {
  const fixture = trustedHelperFixture();
  const parentDir = path.dirname(FIXTURE_HELPER_PATH);
  fixture[parentDir] = { mode: 0o777, uid: 0 }; // world-writable parent -- classic dir-hijack vector.
  const outcome = await verifyTrustBoundary(
    { helperPath: FIXTURE_HELPER_PATH },
    { statFn: async (p) => fixture[p] ?? fs.stat(p) },
  );
  assert.equal(outcome.trusted, false);
  assert.match(outcome.reason, new RegExp(parentDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("verifyTrustBoundary rejects a group/world-writable config directory", async () => {
  const outcome = await verifyTrustBoundary(
    { configPath: "/tmp/does-not-matter/provenance.json", configDir: "/tmp/does-not-matter" },
    { statFn: async () => ({ mode: 0o777, uid: 0 }) },
  );
  assert.equal(outcome.trusted, false);
});

test("verifyTrustBoundary fails closed on a stat error anywhere in the chain", async () => {
  const outcome = await verifyTrustBoundary(
    { helperPath: FIXTURE_HELPER_PATH },
    { statFn: async () => { throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); } },
  );
  assert.equal(outcome.trusted, false);
});

test("resolveElevated rejects on a trust-boundary failure without ever invoking the helper", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const fixture = trustedHelperFixture();
  const parentDir = path.dirname(FIXTURE_HELPER_PATH);
  fixture[parentDir] = { mode: 0o777, uid: 0 };
  let probeCalls = 0;
  let invokeCalls = 0;
  const options = fakeElevatedOptions({
    statOverrides: fixture,
    probeElevatedHelper: async () => { probeCalls++; return { available: true }; },
    invokeElevatedHelper: async () => { invokeCalls++; return { status: "ok", stdout: validHelperStdout({ port: 8080 }) }; },
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
  assert.equal(probeCalls, 0, "an untrusted helper path must never even be probed");
  assert.equal(invokeCalls, 0);
});

test("resolveElevated rejects when the config file lives in a group/world-writable directory", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  await fs.chmod(paths.configDir, 0o777);
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "cap_sys_ptrace" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080 }) }),
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
});

// ---------------------------------------------------------------------------------------------
// 11. mechanism:"auto" never targets root_helper; root_helper requires an explicit named mechanism.
// ---------------------------------------------------------------------------------------------

test('mechanism:"auto" does not auto-select root_helper even when a fake probe reports it as available', async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "auto" } });
  let invokeCalls = 0;
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "root_helper" }),
    invokeElevatedHelper: async () => { invokeCalls++; return { status: "ok", stdout: validHelperStdout({ port: 8080 }) }; },
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result, undefined);
  assert.equal(invokeCalls, 0, "root_helper must never be invoked under an auto-selected mechanism");
});

test('mechanism:"root_helper" named EXPLICITLY is allowed to proceed (the auto guard is auto-specific, not a blanket ban)', async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "root_helper" } });
  const options = fakeElevatedOptions({
    probeElevatedHelper: async () => ({ available: true, mechanism: "root_helper" }),
    invokeElevatedHelper: async () => ({ status: "ok", stdout: validHelperStdout({ port: 8080 }) }),
  });

  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 }, paths }, options);
  assert.equal(result?.mechanism, "root_helper");
});

// ---------------------------------------------------------------------------------------------
// 12. Minimal-env assertion: the REAL default probe/invoke implementations never leak ambient
// process.env into the child -- exercised against a real (unprivileged) fixture script, no
// mocking library, no real elevated file needed.
// ---------------------------------------------------------------------------------------------

test("defaultProbeElevatedHelper and defaultInvokeElevatedHelper pass an explicit minimal env, never the daemon's ambient process.env", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-provenance-elevated-env-test-"));
  const scriptPath = path.join(root, "env-dump.sh");
  const probeDumpFile = path.join(root, "probe-env.txt");
  const invokeDumpFile = path.join(root, "invoke-env.txt");
  // The script embeds its own fixed output paths (rather than reading them from env) precisely
  // because MINIMAL_ENV strips everything but PATH -- an env-based side channel would itself be
  // proof the env wasn't minimal.
  const scriptContent = [
    "#!/bin/sh",
    `if [ "$1" = "--probe" ]; then env > "${probeDumpFile}"; else env > "${invokeDumpFile}"; fi`,
    "exit 0",
    "",
  ].join("\n");
  await fs.writeFile(scriptPath, scriptContent, { mode: 0o755 });

  const marker = "descartes-ambient-leak-marker";
  process.env.DESCARTES_TEST_AMBIENT_MARKER = marker;
  try {
    const probeResult = await defaultProbeElevatedHelper(scriptPath, {});
    assert.equal(probeResult.available, true);
    const invokeResult = await defaultInvokeElevatedHelper(scriptPath, ["--resolve-port", "8080"], {});
    assert.equal(invokeResult.status, "ok");
  } finally {
    delete process.env.DESCARTES_TEST_AMBIENT_MARKER;
  }

  const probeEnv = await fs.readFile(probeDumpFile, "utf8");
  const invokeEnv = await fs.readFile(invokeDumpFile, "utf8");
  // `_`/`SHLVL`/`PWD` are injected by /bin/sh itself on every invocation, independent of the
  // parent's env (proof of nothing about leakage); excluded from the ambient-leak check below.
  // The load-bearing assertions are: PATH is exactly the minimal literal, and no OTHER ambient
  // variable (the marker, or anything else from this test process's real env) made it into the
  // child.
  const SHELL_INJECTED_KEYS = new Set(["_", "SHLVL", "PWD"]);
  const ambientKeysBesidesPath = Object.keys(process.env).filter((key) => key !== "PATH" && !SHELL_INJECTED_KEYS.has(key));
  for (const dumped of [probeEnv, invokeEnv]) {
    const lines = dumped.trim().split("\n");
    const env = Object.fromEntries(lines.map((line) => { const idx = line.indexOf("="); return [line.slice(0, idx), line.slice(idx + 1)]; }));
    assert.equal(env.PATH, "/usr/bin:/bin", "PATH must be exactly the explicit minimal literal, never the ambient PATH");
    assert.equal(dumped.includes(marker), false, "ambient process.env must never leak into the capability-bearing child");
    for (const ambientKey of ambientKeysBesidesPath) {
      assert.equal(ambientKey in env, false, `ambient env var ${ambientKey} must not leak into the capability-bearing child`);
    }
  }
});

// ---------------------------------------------------------------------------------------------
// Shared fixture contract (pre-flight checklist item): the exact bytes the Rust helper emits and
// the exact bytes parseAndVerifyHelperResponse must accept live in ONE file, read by both sides --
// see crates/descartes-root-helper/src/json.rs's `emit_response_matches_the_shared_golden_fixture_byte_for_byte`
// for the Rust-side reader of this same fixture.
// ---------------------------------------------------------------------------------------------

test("parseAndVerifyHelperResponse accepts the shared echo-back-contract.json fixture the Rust helper is pinned against", async () => {
  const fixturePath = path.join(import.meta.dirname, "../../../crates/descartes-root-helper/tests/fixtures/echo-back-contract.json");
  const rawStdout = (await fs.readFile(fixturePath, "utf8")).trim();

  const parsed = parseAndVerifyHelperResponse(rawStdout, { kind: "port", value: 8080 });
  assert.deepEqual(parsed, { pid: 4242, uid: 997, executable_path: "/opt/svc/bin/app", command: "app --serve" });
});

// ---------------------------------------------------------------------------------------------
// S3-priv Slice 5 Phase 2 Part B: real (non-mock) ptrace_scope diagnostic. Pure unit coverage of
// readPtraceScopeDiagnostic itself (DI'd readFile, no real /proc/sys read anywhere in this
// file), plus caller-level coverage (resolveCrossUidPortResult) proving the CRITICAL attachment
// point: NOT on resolveElevated's own return value (its undefined-on-failure contract is
// untouched), but layered on by the caller, on both a successful elevated upgrade (already
// covered above) and a generic degrade-to-unprivileged outcome below -- and proving the
// byte-identical guarantee that a disabled (default) config never surfaces the field, even when
// paths is present and the real ptrace_scope value would otherwise be readable.
// ---------------------------------------------------------------------------------------------

test("readPtraceScopeDiagnostic returns the trimmed raw value for each member of the closed 0-3 set", async () => {
  for (const value of ["0", "1", "2", "3"]) {
    const result = await readPtraceScopeDiagnostic({ readFile: async () => `${value}\n` });
    assert.equal(result, value);
  }
});

test("readPtraceScopeDiagnostic returns undefined on ENOENT (non-Linux, or an unusual kernel without this sysctl), never throws", async () => {
  const result = await readPtraceScopeDiagnostic({
    readFile: async () => { throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); },
  });
  assert.equal(result, undefined);
});

test("readPtraceScopeDiagnostic returns undefined on EACCES, never throws", async () => {
  const result = await readPtraceScopeDiagnostic({
    readFile: async () => { throw Object.assign(new Error("EACCES"), { code: "EACCES" }); },
  });
  assert.equal(result, undefined);
});

test("readPtraceScopeDiagnostic rejects any value outside the closed 0-3 set (garbage/negative/multi-digit/empty/multi-line), never passes a raw unvalidated string through", async () => {
  for (const garbage of ["banana", "9", "", "-1", "10", "1\n2", "  "]) {
    const result = await readPtraceScopeDiagnostic({ readFile: async () => garbage });
    assert.equal(result, undefined, `expected undefined for garbage value ${JSON.stringify(garbage)}`);
  }
});

test("readPtraceScopeDiagnostic defaults readFile to fs.promises.readFile (no DI override) and honors the closed-set contract on any host", async () => {
  // No readFile override: exercises the real default-parameter wiring end-to-end against the
  // actual /proc. The result is host-dependent -- undefined where the sysctl is absent (macOS,
  // a Linux host without Yama) OR the real "0".."3" value where it is readable (Linux CI, where
  // Yama ptrace_scope exists). Assert the diagnostic's CONTRACT (never throws; returns either
  // undefined or a validated closed-set value), not a host-specific outcome -- the earlier
  // hardcoded `undefined` failed on the Linux CI guest, which returns "1".
  const result = await readPtraceScopeDiagnostic();
  assert.ok(
    result === undefined || /^[0-3]$/.test(result),
    `expected undefined or a "0".."3" value, got ${JSON.stringify(result)}`,
  );
});

test("resolveCrossUidPortResult attaches ptrace_scope on a generic degrade-to-unprivileged outcome (config configured, probe unavailable) -- most valuable exactly on this failure path", async () => {
  const paths = await tempPaths();
  await writeProvenanceConfig(paths, { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } });
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  let probeCalls = 0;
  const options = fakeElevatedOptions({
    paths,
    probeElevatedHelper: async () => { probeCalls++; return { available: false }; }, // helper absent/unavailable.
    invokeElevatedHelper: async () => { throw new Error("must not be called when the probe is unavailable"); },
    readFile: async () => "3\n",
  });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(probeCalls, 1, "the elevated attempt was genuinely made (config enabled) -- this is the FAILURE case the diagnostic exists for");
  assert.equal(outcome.resolvedStatus, "partial");
  assert.deepEqual(outcome.result.privilege, { mechanism: "unprivileged", elevated_available: false, elevated_used: false, ptrace_scope: "3" });
});

test("resolveCrossUidPortResult never attaches ptrace_scope when config is disabled (default), even if paths is present and ptrace_scope is readable (byte-identical-by-default)", async () => {
  const paths = await tempPaths(); // no writeProvenanceConfig call -> defaults to disabled.
  const sockets = [{ protocol: "tcp", local_address: "0.0.0.0", local_port: 8080, state: "LISTEN", public_bind: true }];
  let readFileCalls = 0;
  let probeCalls = 0;
  const options = fakeElevatedOptions({
    paths,
    readFile: async () => { readFileCalls++; return "1\n"; }, // proves this is gated, not opportunistic.
    probeElevatedHelper: async () => { probeCalls++; return { available: true }; },
  });

  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, options);
  assert.equal(probeCalls, 0, "config disabled must short-circuit before ever probing (pre-existing gate, unaffected)");
  assert.equal(readFileCalls, 0, "the ptrace_scope diagnostic must never even be read when elevation was never configured");
  assert.deepEqual(outcome.result.privilege, { mechanism: "unprivileged", elevated_available: false, elevated_used: false });
});

// ---------------------------------------------------------------------------------------------
// Additional structural coverage.
// ---------------------------------------------------------------------------------------------

test("resolveElevated never even calls loadProvenanceConfig when paths is not supplied (guards the byte-identical-by-default call sites)", async () => {
  let loadCalls = 0;
  const result = await resolveElevated({ target: { kind: "port", value: 8080, uid: 1000 } }, {
    loadProvenanceConfig: async () => { loadCalls++; return { elevated: { enabled: true, mechanism: "cap_sys_ptrace" } }; },
  });
  assert.equal(result, undefined);
  assert.equal(loadCalls, 0);
});

test("resolveCrossUidPortResult never attempts elevation when options.paths is absent (matches every pre-existing single-arg resolveProvenance call site)", async () => {
  const sockets = [];
  const outcome = await resolveCrossUidPortResult({ port: 8080, primary: { uid: 1000 }, sockets }, {});
  assert.equal(outcome.resolvedStatus, "partial");
  assert.deepEqual(outcome.result.privilege, { mechanism: "unprivileged", elevated_available: false, elevated_used: false });
});

test("DEFAULT_HELPER_PATH is a fixed, non-empty absolute path", () => {
  assert.equal(typeof DEFAULT_HELPER_PATH, "string");
  assert.ok(path.isAbsolute(DEFAULT_HELPER_PATH));
});
