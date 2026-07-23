import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  resolveAlertIntelligencePaths,
  writeAlertIntelligenceConfig,
} from "../src/alert-intelligence.js";
import { normalizeAlertRecord, resolveAlertStorePaths, writeAlertRecords } from "../src/alert-store.js";
import { readArtifactAuditRecords, resolveArtifactAuditPaths } from "../src/artifact-audit-store.js";
import {
  DEFAULT_CHRONIC_NOISE_THRESHOLD,
  DEFAULT_FAST_RECOVERY_THRESHOLD_MS,
  DEFAULT_MIN_CHRONIC_FIRES,
  RECALL_PROXY_REASON,
  computeCalibrationReport,
  computePrecisionProxy,
  runLearnedCalibration,
} from "../src/calibration.js";
import { resolveConstraintStorePaths, writeConstraints, writeLearnedConfig } from "../src/constraint-store.js";
import { resolveNotificationDeliveryPaths } from "../src/notification-delivery.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { resolveSignatureStorePaths, writeSignatureStore } from "../src/provenance-store.js";
import { normalizeShadowRecord, resolveShadowStorePaths } from "../src/shadow-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-calibration-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function alert(overrides = {}) {
  return normalizeAlertRecord({
    rule_id: "constraint.violation.daemon-config",
    fingerprint: "global",
    status: "active",
    severity: "warning",
    title: "t",
    summary: "s",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-01T00:00:00.000Z",
    diagnostics: {},
    ...overrides,
  });
}

function decisionRecord(overrides = {}) {
  return {
    ts: "2026-07-01T00:05:00.000Z",
    alert_id: overrides.alert_id,
    rule_id: overrides.rule_id,
    namespace: overrides.namespace,
    alert_severity: "warning",
    status: "ok",
    decision: { notify: true, severity: "warning", title: "t", body: "b", reason: "r", evidence_refs: [] },
    ...overrides,
  };
}

function shadowRecord(overrides = {}) {
  return normalizeShadowRecord({
    ts: "2026-07-01T00:00:00.000Z",
    constraint_id: "constraint.mined.x.deadbeefdeadbeef",
    family: "x",
    target: "service.presence::x",
    expected: { comparator: "eq", value: "true" },
    actual: "true",
    fired: false,
    ...overrides,
  });
}

// ============================================================================================
// computeCalibrationReport -- pure, no I/O
// ============================================================================================

test("day-1: empty inputs -> { artifacts: [] }", () => {
  const report = computeCalibrationReport([], [], [], []);
  assert.deepEqual(report.artifacts, []);
});

test("tolerates non-array/undefined inputs (day-1 via missing files degraded upstream) -> empty report, never throws", () => {
  const report = computeCalibrationReport(undefined, undefined, undefined, undefined);
  assert.deepEqual(report.artifacts, []);
});

test("scoping: excludes fixed, hand-authored rules (daemon./system./disk.) entirely -- never fixed reflexes, never mined/promoted artifacts", () => {
  const alerts = [
    alert({ rule_id: "daemon.status.missing", fingerprint: "a" }),
    alert({ rule_id: "system.memory.sustained_high", fingerprint: "b" }),
    alert({ rule_id: "disk.space.high_used_fraction", fingerprint: "c" }),
    alert({ rule_id: "provenance.process.deleted_exe_running", fingerprint: "d" }),
    alert({ rule_id: "constraint.violation.daemon-config", diagnostics: { constraint_id: "constraint.mined.daemon-config.deadbeefdeadbeef" } }),
  ];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].rule_id_family, "constraint.violation.daemon-config");
});

// --- Attribution (plan §2.1, incl. the identity_drift must-fix 7) ---

test("attribution: constraint.violation.<family> -> diagnostics.constraint_id, granularity artifact", () => {
  const alerts = [alert({ rule_id: "constraint.violation.daemon-config", diagnostics: { constraint_id: "constraint.mined.daemon-config.deadbeefdeadbeef" } })];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts[0].artifact_ref, "constraint.mined.daemon-config.deadbeefdeadbeef");
  assert.equal(report.artifacts[0].granularity, "artifact");
  assert.equal(report.artifacts[0].rule_id_family, "constraint.violation.daemon-config");
});

test("attribution: provenance.process.unknown_identity -> diagnostics.identity_hash, granularity artifact", () => {
  const alerts = [alert({ rule_id: "provenance.process.unknown_identity", diagnostics: { identity_hash: "aaaa1111bbbb2222" } })];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts[0].artifact_ref, "aaaa1111bbbb2222");
  assert.equal(report.artifacts[0].granularity, "artifact");
});

test("attribution: provenance.port.new_public_bind -> diagnostics.identity_hash, granularity artifact", () => {
  const alerts = [alert({ rule_id: "provenance.port.new_public_bind", diagnostics: { identity_hash: "cccc3333dddd4444" } })];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts[0].artifact_ref, "cccc3333dddd4444");
  assert.equal(report.artifacts[0].granularity, "artifact");
});

test("attribution FIX (must-fix 7): provenance.process.identity_drift -> new_identity_hash, granularity artifact -- NOT identity_hash (absent), NOT family", () => {
  const alerts = [
    alert({
      rule_id: "provenance.process.identity_drift",
      diagnostics: { old_identity_hash: "1111111122222222", new_identity_hash: "3333333344444444", target_kind: "process" },
    }),
  ];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].artifact_ref, "3333333344444444");
  assert.equal(report.artifacts[0].granularity, "artifact");
});

test("attribution: session.*/peer.*/correlation.* -> rule_id, granularity family (no persisted artifact exists)", () => {
  const alerts = [
    alert({ rule_id: "session.count_drop", diagnostics: {} }),
    alert({ rule_id: "session.churn", diagnostics: {} }),
    alert({ rule_id: "peer.count_spike", diagnostics: {} }),
    // Slice 4c (observed-incident collectors plan): peer.count_drop joins CLOSED_RULE_IDS
    // alongside its sibling peer.count_spike -- this is the load-bearing regression for that
    // addition (without it, this fixture would silently produce only 4 artifacts instead of 5).
    alert({ rule_id: "peer.count_drop", diagnostics: {} }),
    alert({ rule_id: "correlation.login_kill_proximity", diagnostics: {} }),
  ];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts.length, 5);
  for (const row of report.artifacts) {
    assert.equal(row.granularity, "family");
    assert.equal(row.artifact_ref, row.rule_id_family);
  }
});

// --- Proxy honesty ---

test("recall_proxy is ALWAYS exactly null with a non-empty reason string, across every fixture shape", () => {
  const fixtures = [
    [],
    [alert({ rule_id: "session.count_drop" })],
    [alert({ rule_id: "constraint.violation.x", diagnostics: { constraint_id: "constraint.mined.x.1111111111111111" } })],
    [alert({ rule_id: "provenance.process.unknown_identity", diagnostics: { identity_hash: "2222222222222222" } })],
  ];
  for (const alerts of fixtures) {
    const report = computeCalibrationReport(alerts, [], [], []);
    for (const row of report.artifacts) {
      assert.equal(row.recall_proxy, null);
      assert.equal(typeof row.recall_proxy_reason, "string");
      assert.ok(row.recall_proxy_reason.length > 0);
      assert.equal(row.recall_proxy_reason, RECALL_PROXY_REASON);
    }
  }
});

test("fired_count honesty (adversarial-review finding): every row carries fired_count_is_lower_bound:true, and it survives JSON round-trip so an unsupervised --json consumer (S14) sees the caveat, not a bare exact-looking integer", () => {
  const alerts = [
    alert({ rule_id: "constraint.violation.x", diagnostics: { constraint_id: "constraint.mined.x.1111111111111111" } }),
    alert({ rule_id: "session.count_drop" }),
  ];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.ok(report.artifacts.length > 0);
  for (const row of report.artifacts) {
    assert.equal(row.fired_count_is_lower_bound, true);
    // The caveat must be present-with-value in serialized JSON (mirrors recall_proxy_reason), not
    // dropped like an `undefined` would be.
    const roundTripped = JSON.parse(JSON.stringify(row));
    assert.equal(roundTripped.fired_count_is_lower_bound, true);
    assert.ok(Object.prototype.hasOwnProperty.call(roundTripped, "fired_count_is_lower_bound"));
  }
});

test("must-fix 9: never_escalated_count and llm_suppressed_rate are explicit null (not 0/a number) for a structurally-unconsentable family row (session./peer.)", () => {
  const report = computeCalibrationReport([alert({ rule_id: "session.count_drop", status: "active" })], [], [], []);
  const row = report.artifacts[0];
  assert.equal(row.llm_namespace_enabled, null);
  assert.equal(row.never_escalated_count, null);
  assert.equal(row.llm_suppressed_rate, null);

  // Must survive a JSON round-trip: the KEY must be present with value null, never omitted --
  // JSON.stringify drops `undefined` values but preserves explicit `null` ones.
  const parsed = JSON.parse(JSON.stringify(row));
  assert.equal("never_escalated_count" in parsed, true);
  assert.strictEqual(parsed.never_escalated_count, null);
  assert.equal("llm_suppressed_rate" in parsed, true);
  assert.strictEqual(parsed.llm_suppressed_rate, null);
});

test("never_escalated_count and llm_suppressed_rate are explicit null when a consentable namespace is currently off (not yet enable-namespace'd)", () => {
  const alerts = [alert({ rule_id: "constraint.violation.daemon-config", diagnostics: { constraint_id: "constraint.mined.x.aaaaaaaaaaaaaaaa" } })];
  const report = computeCalibrationReport(alerts, [], [], [], { enabledNamespaces: [] });
  const row = report.artifacts[0];
  assert.equal(row.llm_namespace_enabled, false);
  assert.equal(row.never_escalated_count, null);
  assert.equal(row.llm_suppressed_rate, null);
});

test("never_escalated_count and llm_suppressed_rate are REAL numbers for a consented + enabled row (llm_namespace_enabled === true)", () => {
  const recoveredFast = alert({
    rule_id: "provenance.process.unknown_identity",
    fingerprint: "hash-a",
    status: "recovered",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-01T00:05:00.000Z",
    diagnostics: { identity_hash: "1111222233334444" },
  });
  const stillActive = alert({
    rule_id: "provenance.process.unknown_identity",
    fingerprint: "hash-b",
    status: "active",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-01T00:00:00.000Z",
    diagnostics: { identity_hash: "1111222233334444" },
  });
  const audit = [decisionRecord({ alert_id: stillActive.id, rule_id: stillActive.rule_id, namespace: "provenance" })];
  const report = computeCalibrationReport([recoveredFast, stillActive], audit, [], [], { enabledNamespaces: ["provenance"] });
  const row = report.artifacts[0];
  assert.equal(row.llm_namespace_enabled, true);
  assert.equal(row.fired_count, 2);
  assert.equal(row.auto_recovered_fast_count, 1);
  assert.equal(row.llm_adjudicated_count, 1);
  assert.equal(row.llm_suppressed_count, 0);
  assert.equal(row.never_escalated_count, 0);
  assert.equal(row.llm_suppressed_rate, 0); // a REAL zero (there WAS an adjudication), not null
});

test("llm_suppressed_rate is null (not 0) when llm_adjudicated_count === 0, even though the namespace is enabled -- a separate, already-handled gate", () => {
  const alerts = [alert({ rule_id: "provenance.process.unknown_identity", status: "active", diagnostics: { identity_hash: "5555666677778888" } })];
  const report = computeCalibrationReport(alerts, [], [], [], { enabledNamespaces: ["provenance"] });
  const row = report.artifacts[0];
  assert.equal(row.llm_adjudicated_count, 0);
  assert.equal(row.llm_suppressed_rate, null);
  assert.equal(row.never_escalated_count, 1); // still a genuine, real "never escalated" count
});

test("must-fix 2: precision_proxy dedupes an alert that is BOTH fast-recovered AND llm-suppressed -- stays in [0,1], never negative", () => {
  const fastAndSuppressed = alert({
    rule_id: "constraint.violation.x",
    status: "recovered",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-01T00:05:00.000Z", // 5min, well under the 30min fast-recovery threshold
    diagnostics: { constraint_id: "constraint.mined.x.2222222222222222" },
  });
  const audit = [
    decisionRecord({
      alert_id: fastAndSuppressed.id,
      rule_id: fastAndSuppressed.rule_id,
      decision: { notify: false, severity: "info", title: "t", body: "b", reason: "r", evidence_refs: [] },
    }),
  ];
  const report = computeCalibrationReport([fastAndSuppressed], audit, [], []);
  const row = report.artifacts[0];
  assert.equal(row.fired_count, 1);
  assert.equal(row.auto_recovered_fast_count, 1);
  assert.equal(row.llm_suppressed_count, 1);
  // Naive sum would compute 1 - (1+1)/1 = -1. Correct dedupe computes 1 - 1/1 = 0.
  assert.equal(row.precision_proxy, 0);
  assert.ok(row.precision_proxy >= 0 && row.precision_proxy <= 1);
});

test("computePrecisionProxy: fired_count === 0 -> null (no div-by-zero)", () => {
  assert.equal(computePrecisionProxy(0, 0), null);
  assert.equal(computePrecisionProxy(3, 0), null);
  assert.equal(computePrecisionProxy(3, -1), null);
});

test("computePrecisionProxy clamps to [0,1] even if fed an out-of-range numerator directly (defense-in-depth)", () => {
  assert.equal(computePrecisionProxy(5, 2), 0); // unclamped would be -1.5
  assert.equal(computePrecisionProxy(-3, 2), 1); // unclamped would be 2.5
});

test("auto_recovered_fast_count boundary: exactly FAST_RECOVERY_THRESHOLD_MS counts as fast (<=); one ms over does not", () => {
  const boundaryMs = new Date("2026-07-01T00:00:00.000Z").getTime() + DEFAULT_FAST_RECOVERY_THRESHOLD_MS;
  const atBoundary = alert({
    rule_id: "constraint.violation.boundary-a",
    status: "recovered",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: new Date(boundaryMs).toISOString(),
    diagnostics: { constraint_id: "constraint.mined.boundary-a.3333333333333333" },
  });
  const overBoundary = alert({
    rule_id: "constraint.violation.boundary-b",
    status: "recovered",
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: new Date(boundaryMs + 1).toISOString(),
    diagnostics: { constraint_id: "constraint.mined.boundary-b.4444444444444444" },
  });
  const report = computeCalibrationReport([atBoundary, overBoundary], [], [], []);
  const byRef = new Map(report.artifacts.map((row) => [row.artifact_ref, row]));
  assert.equal(byRef.get("constraint.mined.boundary-a.3333333333333333").auto_recovered_fast_count, 1);
  assert.equal(byRef.get("constraint.mined.boundary-b.4444444444444444").auto_recovered_fast_count, 0);
});

test("chronically_firing: true for a chronically-noisy constraint, false for a healthy provenance artifact (plan §4.6 Definition of Done)", () => {
  const noisyId = "constraint.mined.daemon-config.5555555555555555";
  const noisyAlerts = [];
  for (let i = 0; i < 5; i += 1) {
    noisyAlerts.push(
      alert({
        rule_id: "constraint.violation.daemon-config",
        fingerprint: `noisy-${i}`,
        status: "recovered",
        first_seen: `2026-07-01T00:0${i}:00.000Z`,
        last_seen: `2026-07-01T00:0${i}:05.000Z`,
        diagnostics: { constraint_id: noisyId },
      }),
    );
  }
  noisyAlerts.push(
    alert({
      rule_id: "constraint.violation.daemon-config",
      fingerprint: "noisy-real",
      status: "active",
      first_seen: "2026-07-01T00:10:00.000Z",
      last_seen: "2026-07-01T00:10:00.000Z",
      diagnostics: { constraint_id: noisyId },
    }),
  );

  const healthyId = "9999888877776666";
  const healthyAlerts = [
    alert({
      rule_id: "provenance.process.unknown_identity",
      fingerprint: "healthy",
      status: "active",
      diagnostics: { identity_hash: healthyId },
    }),
  ];

  const report = computeCalibrationReport([...noisyAlerts, ...healthyAlerts], [], [], []);
  const byRef = new Map(report.artifacts.map((row) => [row.artifact_ref, row]));
  const noisyRow = byRef.get(noisyId);
  const healthyRow = byRef.get(healthyId);

  assert.equal(noisyRow.fired_count, 6);
  assert.ok(noisyRow.fired_count >= DEFAULT_MIN_CHRONIC_FIRES);
  assert.ok(noisyRow.precision_proxy < DEFAULT_CHRONIC_NOISE_THRESHOLD);
  assert.equal(noisyRow.chronically_firing, true);

  assert.equal(healthyRow.fired_count, 1);
  assert.ok(healthyRow.fired_count < DEFAULT_MIN_CHRONIC_FIRES);
  assert.equal(healthyRow.chronically_firing, false);
});

test("shadow_fire_rate: computed from shadow-violations.jsonl for a constraint-family artifact ref", () => {
  const constraintId = "constraint.mined.shadow-test.7777777777777777";
  const alerts = [alert({ rule_id: "constraint.violation.shadow-test", diagnostics: { constraint_id: constraintId } })];
  const shadow = [
    shadowRecord({ constraint_id: constraintId, fired: true }),
    shadowRecord({ constraint_id: constraintId, fired: false }),
    shadowRecord({ constraint_id: constraintId, fired: false }),
    shadowRecord({ constraint_id: constraintId, fired: false }),
  ];
  const report = computeCalibrationReport(alerts, [], [], shadow);
  const row = report.artifacts.find((entry) => entry.artifact_ref === constraintId);
  assert.equal(row.shadow_fire_rate, 0.25);
});

test("shadow_fire_rate is null when no shadow records exist yet for that ref", () => {
  const alerts = [alert({ rule_id: "provenance.process.unknown_identity", diagnostics: { identity_hash: "8888777766665555" } })];
  const report = computeCalibrationReport(alerts, [], [], []);
  assert.equal(report.artifacts[0].shadow_fire_rate, null);
});

test("--since narrows the window by first_seen; --family filters by rule_id prefix", () => {
  const constraintId = "constraint.mined.x.aaaa111122223333";
  const inWindow = alert({ rule_id: "constraint.violation.x", fingerprint: "in", first_seen: "2026-07-02T00:00:00.000Z", last_seen: "2026-07-02T00:00:00.000Z", diagnostics: { constraint_id: constraintId } });
  const outOfWindow = alert({ rule_id: "constraint.violation.x", fingerprint: "out", first_seen: "2026-06-01T00:00:00.000Z", last_seen: "2026-06-01T00:00:00.000Z", diagnostics: { constraint_id: constraintId } });
  const otherFamily = alert({ rule_id: "session.count_drop", fingerprint: "global", first_seen: "2026-07-02T00:00:00.000Z", last_seen: "2026-07-02T00:00:00.000Z" });

  const sinceOnly = computeCalibrationReport([inWindow, outOfWindow, otherFamily], [], [], [], { since: "2026-07-01T00:00:00.000Z" });
  assert.equal(sinceOnly.window.since, "2026-07-01T00:00:00.000Z");
  assert.equal(sinceOnly.artifacts.find((row) => row.artifact_ref === constraintId).fired_count, 1);

  const familyOnly = computeCalibrationReport([inWindow, outOfWindow, otherFamily], [], [], [], { family: "constraint." });
  assert.equal(familyOnly.artifacts.length, 1);
  assert.equal(familyOnly.artifacts[0].rule_id_family, "constraint.violation.x");
});

test("sanitization: only hashes/counts/enums surface -- a raw diagnostics field never leaks into a row (field-selection discipline, plan §1 point 6)", () => {
  const fixture = alert({
    rule_id: "provenance.process.unknown_identity",
    diagnostics: {
      identity_hash: "abcdefabcdefabcd",
      raw_hostname: "attacker-host.example.com",
      client_ip: "203.0.113.7",
    },
  });
  const report = computeCalibrationReport([fixture], [], [], []);
  const row = report.artifacts[0];
  const allowedKeys = new Set([
    "artifact_ref",
    "granularity",
    "rule_id_family",
    "fired_count",
    "fired_count_is_lower_bound",
    "auto_recovered_fast_count",
    "never_escalated_count",
    "llm_adjudicated_count",
    "llm_suppressed_count",
    "llm_namespace_enabled",
    "llm_suppressed_rate",
    "precision_proxy",
    "recall_proxy",
    "recall_proxy_reason",
    "shadow_fire_rate",
    "chronically_firing",
    "schema_version",
  ]);
  for (const key of Object.keys(row)) assert.ok(allowedKeys.has(key), `unexpected row key leaked: ${key}`);
  const serialized = JSON.stringify(row);
  assert.equal(serialized.includes("attacker-host.example.com"), false);
  assert.equal(serialized.includes("203.0.113.7"), false);
});

test("no LLM anywhere: calibration.js never imports pi-harness.js, never calls createSession, and imports only the pure classifier/config reader from alert-intelligence.js (never its adjudication entry points)", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/calibration.js"), "utf8");
  // Real import/call syntax only (a doc comment is free to name these files/functions in prose --
  // this targets the actual import/call surface, not a comment-stripping lint).
  assert.equal(/from\s*["'`]\.\/pi-harness\.js["'`]/.test(source), false);
  assert.equal(/import\(\s*["'`][^"'`]*pi-harness\.js["'`]\s*\)/.test(source), false);
  assert.equal(/\bcreateSession\s*\(/.test(source), false);

  const importMatch = source.match(/import\s*{([^}]*)}\s*from\s*["'`]\.\/alert-intelligence\.js["'`]/);
  assert.ok(importMatch, "expected exactly one named-import statement from alert-intelligence.js");
  const importedNames = importMatch[1].split(",").map((name) => name.trim()).filter(Boolean);
  const allowedNames = new Set(["classifyAlertNamespace", "readAlertIntelligenceAudit", "readAlertIntelligenceConfig", "DEFAULT_ENABLED_NAMESPACES"]);
  for (const name of importedNames) assert.ok(allowedNames.has(name), `unexpected alert-intelligence.js import: ${name}`);
  const forbiddenNames = [
    "adjudicateAlertNotifications",
    "alertIntelligencePrompt",
    "PROMPT_TEMPLATES",
    "buildMetricAlertPrompt",
    "buildLearnedNamespaceAlertPrompt",
    "buildCorrelationAlertPrompt",
  ];
  for (const forbidden of forbiddenNames) assert.equal(importedNames.includes(forbidden), false);
});

// ============================================================================================
// runLearnedCalibration -- the CLI handler (I/O, gated behind learned.json)
// ============================================================================================

test("learned.json disabled -> { status: \"disabled\" }, and NO signal file is ever read", async () => {
  const paths = await tempPaths();
  const calls = { alerts: 0, audit: 0, delivery: 0, shadow: 0, config: 0 };
  const result = await runLearnedCalibration(paths, [], {
    output: () => {},
    loadLearnedConfig: async () => ({ enabled: false }),
    readAlertRecords: async () => {
      calls.alerts += 1;
      return [];
    },
    readAlertIntelligenceAudit: async () => {
      calls.audit += 1;
      return [];
    },
    readNotificationDeliveryAudit: async () => {
      calls.delivery += 1;
      return [];
    },
    readShadowRecords: async () => {
      calls.shadow += 1;
      return { records: [] };
    },
    readAlertIntelligenceConfig: async () => {
      calls.config += 1;
      return {};
    },
  });
  assert.deepEqual(result, { status: "disabled" });
  assert.deepEqual(calls, { alerts: 0, audit: 0, delivery: 0, shadow: 0, config: 0 });
});

test("corrupt configDir/learned.json fails closed to disabled (mirrors loadLearnedConfig's own posture)", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveConstraintStorePaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{ not valid json");
  const result = await runLearnedCalibration(paths, [], { output: () => {} });
  assert.deepEqual(result, { status: "disabled" });
});

test("day-1 (learned.json enabled, no signal files exist) -> empty report, still appends exactly one artifact_count:0 audit record", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const output = [];
  const report = await runLearnedCalibration(paths, ["--json"], { output: (line) => output.push(line), now: "2026-07-10T00:00:00.000Z" });
  const parsed = JSON.parse(output[0]);
  assert.deepEqual(parsed.artifacts, []);
  assert.deepEqual(report.artifacts, []);

  const auditRecords = await readArtifactAuditRecords(paths);
  assert.equal(auditRecords.length, 1);
  assert.equal(auditRecords[0].kind, "calibration_report");
  assert.equal(auditRecords[0].artifact_count, 0);
});

test("tolerates a corrupt (malformed top-level JSON) alerts.json without throwing -- degrades that signal to empty", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const { alertsFile } = resolveAlertStorePaths(paths);
  await fs.mkdir(path.dirname(alertsFile), { recursive: true });
  await fs.writeFile(alertsFile, "{ not valid json ][");
  const report = await runLearnedCalibration(paths, [], { output: () => {}, now: "2026-07-10T00:00:00.000Z" });
  assert.deepEqual(report.artifacts, []);
});

test("tolerates missing/corrupt llm-decisions.jsonl, notification-delivery.jsonl, shadow-violations.jsonl -- never throws", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const constraintId = "constraint.mined.tolerant.aaaa111122223333";
  await writeAlertRecords(paths, [
    { rule_id: "constraint.violation.tolerant", diagnostics: { constraint_id: constraintId }, first_seen: "2026-07-01T00:00:00.000Z", last_seen: "2026-07-01T00:00:00.000Z" },
  ]);

  const { auditFile: llmAuditFile } = resolveAlertIntelligencePaths(paths);
  await fs.mkdir(path.dirname(llmAuditFile), { recursive: true });
  await fs.writeFile(llmAuditFile, "not-json\n");

  const { auditFile: deliveryAuditFile } = resolveNotificationDeliveryPaths(paths);
  await fs.mkdir(path.dirname(deliveryAuditFile), { recursive: true });
  await fs.writeFile(deliveryAuditFile, "garbage\n");

  const { shadowViolationsFile } = resolveShadowStorePaths(paths);
  await fs.mkdir(path.dirname(shadowViolationsFile), { recursive: true });
  await fs.writeFile(shadowViolationsFile, "garbage\n");

  const report = await runLearnedCalibration(paths, [], { output: () => {}, now: "2026-07-10T00:00:00.000Z" });
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].artifact_ref, constraintId);
});

test("read-only: constraints.json, signatures.json, alert-intelligence.json, alerts.json are byte-unchanged after a run", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeConstraints(paths, []);
  await writeSignatureStore(paths, {});
  await writeAlertIntelligenceConfig(paths, { enabled: true, enabled_namespaces: ["constraint"] });
  await writeAlertRecords(paths, [
    { rule_id: "constraint.violation.x", diagnostics: { constraint_id: "constraint.mined.x.aaaa111122223333" }, first_seen: "2026-07-01T00:00:00.000Z", last_seen: "2026-07-01T00:00:00.000Z" },
  ]);

  const { constraintsFile } = resolveConstraintStorePaths(paths);
  const { signaturesFile } = resolveSignatureStorePaths(paths);
  const { configFile: intelligenceConfigFile } = resolveAlertIntelligencePaths(paths);
  const { alertsFile } = resolveAlertStorePaths(paths);
  const files = [constraintsFile, signaturesFile, intelligenceConfigFile, alertsFile];

  const before = await Promise.all(files.map((file) => fs.readFile(file, "utf8")));
  await runLearnedCalibration(paths, ["--json"], { output: () => {}, now: "2026-07-10T00:00:00.000Z" });
  const after = await Promise.all(files.map((file) => fs.readFile(file, "utf8")));

  assert.deepEqual(after, before);
});

test("human-readable render: session./peer. rows show an explicit n/a annotation, never a raw percentage", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeAlertRecords(paths, [{ rule_id: "session.count_drop", first_seen: "2026-07-01T00:00:00.000Z", last_seen: "2026-07-01T00:00:00.000Z" }]);
  const output = [];
  await runLearnedCalibration(paths, [], { output: (line) => output.push(line), now: "2026-07-10T00:00:00.000Z" });
  const rendered = output.join("\n");
  assert.ok(rendered.includes("never_escalated: n/a"));
  assert.equal(/never_escalated: \d/.test(rendered), false);
});

test("--json emits explicit null (not a number) for never_escalated_count/llm_suppressed_rate/recall_proxy on a structurally-unconsentable row", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeAlertRecords(paths, [{ rule_id: "peer.count_spike", first_seen: "2026-07-01T00:00:00.000Z", last_seen: "2026-07-01T00:00:00.000Z" }]);
  const output = [];
  await runLearnedCalibration(paths, ["--json"], { output: (line) => output.push(line), now: "2026-07-10T00:00:00.000Z" });
  const parsed = JSON.parse(output[0]);
  const row = parsed.artifacts[0];
  assert.equal(row.llm_namespace_enabled, null);
  assert.strictEqual(row.never_escalated_count, null);
  assert.strictEqual(row.llm_suppressed_rate, null);
  assert.strictEqual(row.recall_proxy, null);
});

test("CLI: --family narrows the report to a rule_id prefix", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeAlertRecords(paths, [
    { rule_id: "constraint.violation.x", diagnostics: { constraint_id: "constraint.mined.x.aaaa111122223333" }, first_seen: "2026-07-09T00:00:00.000Z", last_seen: "2026-07-09T00:00:00.000Z" },
    { rule_id: "session.count_drop", first_seen: "2026-07-09T00:00:00.000Z", last_seen: "2026-07-09T00:00:00.000Z" },
  ]);
  const output = [];
  await runLearnedCalibration(paths, ["--json", "--family", "constraint."], { output: (line) => output.push(line), now: "2026-07-10T00:00:00.000Z" });
  const parsed = JSON.parse(output[0]);
  assert.equal(parsed.artifacts.length, 1);
  assert.equal(parsed.artifacts[0].rule_id_family, "constraint.violation.x");
});

test("CLI: --since narrows the report by a relative duration", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  await writeAlertRecords(paths, [
    { rule_id: "constraint.violation.x", diagnostics: { constraint_id: "constraint.mined.x.bbbb222233334444" }, first_seen: "2026-07-09T12:00:00.000Z", last_seen: "2026-07-09T12:00:00.000Z" },
  ]);
  const output = [];
  await runLearnedCalibration(paths, ["--json", "--since", "1h"], { output: (line) => output.push(line), now: "2026-07-10T00:00:00.000Z" });
  const parsed = JSON.parse(output[0]);
  assert.deepEqual(parsed.artifacts, []); // the alert is >1h before "now" -> filtered out
});

test("CLI: unknown argument throws with usage", async () => {
  const paths = await tempPaths();
  await assert.rejects(() => runLearnedCalibration(paths, ["--nope"], { output: () => {} }), /Unexpected learned calibration argument/);
});

test("CLI: --since/--family missing a value throws", async () => {
  const paths = await tempPaths();
  await assert.rejects(() => runLearnedCalibration(paths, ["--since"], { output: () => {} }), /--since requires a value/);
  await assert.rejects(() => runLearnedCalibration(paths, ["--family"], { output: () => {} }), /--family requires a value/);
});

test("CLI: --help prints usage and performs no reads/writes", async () => {
  const paths = await tempPaths();
  const output = [];
  const result = await runLearnedCalibration(paths, ["--help"], { output: (line) => output.push(line) });
  assert.equal(result, undefined);
  assert.ok(output.join("\n").includes("descartes learned calibration"));
  assert.deepEqual(await readArtifactAuditRecords(paths), []);
});
