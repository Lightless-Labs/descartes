import assert from "node:assert/strict";
import { test } from "node:test";
import { alertId } from "../src/alert-store.js";
import { emitSessionAlertSignals, classifyAlertNamespace } from "../src/alert-intelligence.js";

function alert(diagnostics) {
  return {
    id: alertId("canary.tripped", "abcdef0123456789"),
    rule_id: "canary.tripped",
    severity: "critical",
    diagnostics,
  };
}

function tamperAlert(diagnostics, fingerprint = "abcdef0123456789") {
  return {
    id: alertId("canary.tampered", fingerprint),
    rule_id: "canary.tampered",
    severity: "critical",
    diagnostics,
  };
}

test("canary namespace remains fail-closed and deterministic delivery is available", async () => {
  assert.deepEqual(classifyAlertNamespace("canary.tripped"), { namespace: undefined, hardExcluded: false });
  const delivered = [];
  const result = await emitSessionAlertSignals({}, {
    notification_due_ids: [alert({ canary_id: "credential.bak", canary_kind: "credential-file", trip_reason: "executed" }).id],
    alerts: [alert({ canary_id: "credential.bak", canary_kind: "credential-file", trip_reason: "executed" })],
  }, { deliverNotification: async (_paths, decision) => delivered.push(decision) });
  assert.equal(result.fired.length, 1);
  assert.deepEqual(delivered[0], {
    notify: true,
    severity: "critical",
    title: "Descartes: canary tripped",
    body: 'Canary "credential.bak" (credential-file) tripped: executed.',
  });
});

test("canary deterministic delivery falls back from a redaction marker object", async () => {
  const current = alert({ canary_id: { redacted: true }, canary_id_hash: "abcdef0123456789", canary_kind: "suid-binary", trip_reason: "mtime_changed" });
  const delivered = [];
  await emitSessionAlertSignals({}, { notification_due_ids: [current.id], alerts: [current] }, {
    deliverNotification: async (_paths, decision) => delivered.push(decision),
  });
  assert.equal(delivered[0].body, 'Canary "unknown (abcdef0123456789)" (suid-binary) tripped: mtime_changed.');
});

// Tamper fix (canary v0 finalization): canary.tampered must share canary.tripped's exact
// fail-closed/deterministic-delivery posture -- classifyAlertNamespace is UNTOUCHED (still
// unknown_namespace, so it can never reach LLM adjudication) AND it must still actively notify the
// operator via the same deterministic local-delivery branch, or "tampering is suspicious in
// itself" would silently never reach anyone.
test("canary.tampered namespace remains fail-closed and deterministic delivery is available", async () => {
  assert.deepEqual(classifyAlertNamespace("canary.tampered"), { namespace: undefined, hardExcluded: false });
  const current = tamperAlert({ tamper_reason: "manifest_unreadable" });
  const delivered = [];
  const result = await emitSessionAlertSignals({}, { notification_due_ids: [current.id], alerts: [current] }, {
    deliverNotification: async (_paths, decision) => delivered.push(decision),
  });
  assert.equal(result.fired.length, 1);
  assert.equal(delivered[0].notify, true);
  assert.equal(delivered[0].severity, "critical");
  assert.match(delivered[0].body, /canaries\.json/);
});

test("canary.tampered(canary_vanished) delivery names the vanished canary", async () => {
  const current = tamperAlert({ tamper_reason: "canary_vanished", canary_id: "credential.bak", canary_kind: "credential-file", last_seen_ts: "2026-08-01T00:00:00.000Z" });
  const delivered = [];
  await emitSessionAlertSignals({}, { notification_due_ids: [current.id], alerts: [current] }, {
    deliverNotification: async (_paths, decision) => delivered.push(decision),
  });
  assert.equal(delivered[0].body, 'Canary "credential.bak" (credential-file) vanished while still listed in the manifest (last seen 2026-08-01T00:00:00.000Z) — possible tampering.');
});

test("canary.tampered(canary_vanished) delivery falls back from a redaction marker object", async () => {
  const current = tamperAlert({ tamper_reason: "canary_vanished", canary_id: { redacted: true }, canary_id_hash: "abcdef0123456789", canary_kind: "suid-binary", last_seen_ts: "2026-08-01T00:00:00.000Z" });
  const delivered = [];
  await emitSessionAlertSignals({}, { notification_due_ids: [current.id], alerts: [current] }, {
    deliverNotification: async (_paths, decision) => delivered.push(decision),
  });
  assert.match(delivered[0].body, /unknown \(abcdef0123456789\)/);
});

test("canary.tampered(baseline_store_error) delivery names the failure without naming a specific canary", async () => {
  const current = tamperAlert({ tamper_reason: "baseline_store_error" });
  const delivered = [];
  await emitSessionAlertSignals({}, { notification_due_ids: [current.id], alerts: [current] }, {
    deliverNotification: async (_paths, decision) => delivered.push(decision),
  });
  assert.match(delivered[0].body, /baseline store/);
});
