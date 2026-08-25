import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { alertId } from "../src/alert-store.js";
import { CANARY_TAMPERED_RULE_ID, CANARY_TRIPPED_RULE_ID } from "../src/canary-baseline.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import {
  CONTAINMENT_RECOMMEND_LABEL,
  KNOWN_CONTAINMENT_VERBS,
  computeContainmentRecommendationCandidates,
  containmentRecommendationRuleIds,
  mapAlertToRecommendation,
  readContainmentRecommendConfig,
  renderRecommendationText,
  renderStoredRecommendationText,
  resolveContainmentRecommendPaths,
  writeContainmentRecommendConfig,
} from "../src/containment-recommend.js";
import { PEER_COUNT_SPIKE_RULE_ID } from "../src/peer-baseline.js";
import { PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID } from "../src/process-lineage-baseline.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "../src/session-baseline.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-containment-recommend-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const ALL_TRIGGER_RULE_IDS = [
  SESSION_COUNT_DROP_RULE_ID,
  SESSION_CHURN_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  CANARY_TRIPPED_RULE_ID,
  CANARY_TAMPERED_RULE_ID,
  PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID,
];

// ---------------------------------------------------------------------------------------------
// Slice 7.2.a: mapAlertToRecommendation / renderRecommendationText — pure, no I/O.
// ---------------------------------------------------------------------------------------------

test("mapAlertToRecommendation: unrecognized rule_id degrades to undefined, never fabricates", () => {
  assert.equal(mapAlertToRecommendation({ rule_id: "weird.thing", diagnostics: {} }), undefined);
  assert.equal(mapAlertToRecommendation({ rule_id: "daemon.status.not_ok", diagnostics: {} }), undefined);
});

test("mapAlertToRecommendation: garbled/absent trigger degrades to undefined, never fabricates", () => {
  assert.equal(mapAlertToRecommendation(undefined), undefined);
  assert.equal(mapAlertToRecommendation(null), undefined);
  assert.equal(mapAlertToRecommendation("not-an-object"), undefined);
  assert.equal(mapAlertToRecommendation({}), undefined);
  // A recognized rule_id whose diagnostics don't parse as the mapper expects (no canary_id_hash
  // AND no fallback available -- process-lineage always needs entity_key_hash, has no
  // "global" fallback the way peer-count-spike does) degrades to undefined, same as an
  // unrecognized rule_id.
  assert.equal(mapAlertToRecommendation({ rule_id: PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, diagnostics: {} }), undefined);
  assert.equal(mapAlertToRecommendation({ rule_id: PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, diagnostics: { entity_key_hash: "not a safe repr!" } }), undefined);
});

// Deliberate, documented gate/no-gate decisions (see the module header in containment-recommend.js
// for the full per-signal rationale): SESSION_COUNT_DROP/SESSION_CHURN are GLOBAL/no-single-target
// anomalies with no natural containment verb, so they are NOT in the v0 map (no-gate) -- this is a
// conservative default the operator should ratify per the plan's Open Decision 3, not an oversight.
test("mapAlertToRecommendation: SESSION_COUNT_DROP_RULE_ID and SESSION_CHURN_RULE_ID are deliberately NO-GATE in v0 (no natural containment target)", () => {
  assert.equal(mapAlertToRecommendation({ rule_id: SESSION_COUNT_DROP_RULE_ID, diagnostics: { observed_count: 0, mean_before: 20 } }), undefined);
  assert.equal(mapAlertToRecommendation({ rule_id: SESSION_CHURN_RULE_ID, diagnostics: { entity_key: "session.tmux.aaaaaaaaaaaaaaaa" } }), undefined);
});

test("mapAlertToRecommendation: peer.count_spike maps to block/global (no per-peer identity exists to name)", () => {
  const rec = mapAlertToRecommendation({ rule_id: PEER_COUNT_SPIKE_RULE_ID, diagnostics: { observed_count: 8, mean_before: 2, z_score: 6, confidence_state: "established" } });
  assert.ok(rec);
  assert.equal(rec.verb, "block");
  assert.equal(rec.rule_id, "containment.recommend.block");
  assert.equal(rec.trigger_rule_id, PEER_COUNT_SPIKE_RULE_ID);
  assert.equal(rec.target_repr, "global");
  assert.equal(rec.label, CONTAINMENT_RECOMMEND_LABEL);
});

test("mapAlertToRecommendation: canary.tripped maps to quarantine/canary_id_hash (never the cleartext canary_id)", () => {
  const rec = mapAlertToRecommendation({
    rule_id: CANARY_TRIPPED_RULE_ID,
    diagnostics: { canary_id: "credential.bak", canary_id_hash: "abcdef0123456789", canary_kind: "credential-file", trip_reason: "executed" },
  });
  assert.ok(rec);
  assert.equal(rec.verb, "quarantine");
  assert.equal(rec.target_repr, "abcdef0123456789");
  assert.notEqual(rec.target_repr, "credential.bak");
});

test("mapAlertToRecommendation: canary.tampered singleton reasons (no canary_id) degrade the target to 'global', never fabricate a per-canary identity", () => {
  const rec = mapAlertToRecommendation({ rule_id: CANARY_TAMPERED_RULE_ID, diagnostics: { tamper_reason: "manifest_unreadable" } });
  assert.ok(rec);
  assert.equal(rec.verb, "quarantine");
  assert.equal(rec.target_repr, "global");
});

test("mapAlertToRecommendation: process.lineage.novel_edge maps to throttle/entity_key_hash", () => {
  const rec = mapAlertToRecommendation({ rule_id: PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID, diagnostics: { entity_key_hash: "0123456789abcdef" } });
  assert.ok(rec);
  assert.equal(rec.verb, "throttle");
  assert.equal(rec.target_repr, "0123456789abcdef");
});

test("verb is always drawn from KNOWN_CONTAINMENT_VERBS; every trigger this module can map to a recommendation produces one of those verbs", () => {
  for (const ruleId of ALL_TRIGGER_RULE_IDS) {
    const rec = mapAlertToRecommendation({ rule_id: ruleId, diagnostics: { canary_id_hash: "abcdef0123456789", entity_key_hash: "abcdef0123456789", entity_key: "session.tmux.aaaaaaaaaaaaaaaa", observed_count: 8, mean_before: 2 } });
    if (rec) assert.ok(KNOWN_CONTAINMENT_VERBS.includes(rec.verb), `${ruleId} produced an out-of-enum verb: ${rec.verb}`);
  }
  assert.deepEqual(KNOWN_CONTAINMENT_VERBS, ["throttle", "block", "revoke", "quarantine", "kill"]);
});

test("renderRecommendationText: a hand-forged recommendation with a free-text/out-of-enum verb is rejected, not passed through", () => {
  assert.equal(renderRecommendationText({ verb: "nuke", target_repr: "global", rationale: "x" }), undefined);
  assert.equal(renderRecommendationText(undefined), undefined);
  assert.equal(renderRecommendationText({}), undefined);
});

test("renderRecommendationText: always contains the RECOMMEND-ONLY label, label-first so downstream truncation can never remove it", () => {
  const text = renderRecommendationText({ verb: "quarantine", target_repr: "abcdef0123456789", rationale: "x".repeat(500) });
  assert.ok(text.includes(CONTAINMENT_RECOMMEND_LABEL));
  assert.ok(text.startsWith(CONTAINMENT_RECOMMEND_LABEL), "the label must be first so a 240-char body clamp downstream truncates the rationale tail, never the label");
});

test("renderRecommendationText: an unsafe/garbled target_repr degrades to the global marker, never passes a raw value through", () => {
  const text = renderRecommendationText({ verb: "block", target_repr: "raw peer host name with spaces", rationale: "x" });
  assert.ok(text.includes("global"));
  assert.equal(text.includes("raw peer host name with spaces"), false);
});

test("renderStoredRecommendationText: re-derives the exact rationale for the matching trigger_rule_id, and never cross-contaminates two triggers sharing a verb", () => {
  const trippedText = renderStoredRecommendationText({ verb: "quarantine", trigger_rule_id: CANARY_TRIPPED_RULE_ID, target_repr: "abcdef0123456789" });
  const tamperedText = renderStoredRecommendationText({ verb: "quarantine", trigger_rule_id: CANARY_TAMPERED_RULE_ID, target_repr: "global" });
  assert.ok(trippedText.includes(CONTAINMENT_RECOMMEND_LABEL));
  assert.ok(tamperedText.includes(CONTAINMENT_RECOMMEND_LABEL));
  assert.notEqual(trippedText, tamperedText);
});

test("renderStoredRecommendationText: mismatched/corrupt stored diagnostics degrade to undefined, never fabricated text", () => {
  assert.equal(renderStoredRecommendationText({ verb: "kill", trigger_rule_id: CANARY_TRIPPED_RULE_ID, target_repr: "global" }), undefined, "verb doesn't match this trigger's real mapped verb");
  assert.equal(renderStoredRecommendationText({ verb: "quarantine", trigger_rule_id: "some.foreign.rule_id", target_repr: "global" }), undefined);
  assert.equal(renderStoredRecommendationText({}), undefined);
  assert.equal(renderStoredRecommendationText(undefined), undefined);
});

test("containment namespace absent from the map-keys guarantee: map keys are a subset of the shipped P3 rule_id constants, never a glob/prefix", () => {
  for (const ruleId of ALL_TRIGGER_RULE_IDS) {
    // Every rule_id this module CAN produce a recommendation for (given plausible diagnostics) is
    // a member of the shipped constant set -- proven by construction, since mapAlertToRecommendation
    // never inspects anything but these exact string constants.
    const rec = mapAlertToRecommendation({ rule_id: ruleId, diagnostics: { canary_id_hash: "abcdef0123456789", entity_key_hash: "abcdef0123456789", observed_count: 8, mean_before: 2 } });
    if (rec) assert.ok(ALL_TRIGGER_RULE_IDS.includes(rec.trigger_rule_id));
  }
});

test("containmentRecommendationRuleIds(): the closed emitted set is exactly the verbs RECOMMEND_MAP actually produces — no dead/unreachable allowlist entry for kill/revoke, which v0 never emits", () => {
  const ids = containmentRecommendationRuleIds();
  assert.deepEqual([...ids].sort(), ["containment.recommend.block", "containment.recommend.quarantine", "containment.recommend.throttle"]);
  assert.equal(ids.includes("containment.recommend.kill"), false);
  assert.equal(ids.includes("containment.recommend.revoke"), false);
});

// ---------------------------------------------------------------------------------------------
// Slice 7.2.b: readContainmentRecommendConfig / writeContainmentRecommendConfig — fail-closed,
// default-OFF opt-in.
// ---------------------------------------------------------------------------------------------

test("readContainmentRecommendConfig: defaults OFF with no file", async () => {
  const paths = await tempPaths();
  const config = await readContainmentRecommendConfig(paths);
  assert.equal(config.enabled, false);
  assert.equal(config.corrupt, undefined);
  assert.equal(config.unavailable, undefined);
});

test("readContainmentRecommendConfig: corrupt JSON reads as OFF, never throws into 'enabled'", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveContainmentRecommendPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "{ not valid json", "utf8");
  const config = await readContainmentRecommendConfig(paths);
  assert.equal(config.enabled, false);
  assert.equal(config.corrupt, true);
});

test("writeContainmentRecommendConfig: round-trips enable/disable", async () => {
  const paths = await tempPaths();
  const enabled = await writeContainmentRecommendConfig(paths, { enabled: true }, { now: "2026-08-21T00:00:00.000Z" });
  assert.equal(enabled.enabled, true);
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, true);

  const disabled = await writeContainmentRecommendConfig(paths, { enabled: false }, { now: "2026-08-21T00:01:00.000Z" });
  assert.equal(disabled.enabled, false);
  assert.equal((await readContainmentRecommendConfig(paths)).enabled, false);
});

test("writeContainmentRecommendConfig: a corrupt-config marker refuses to write (stricter than alert-intelligence.json's own guard, which allows overwriting a merely-corrupt file)", async () => {
  const paths = await tempPaths();
  const { configFile } = resolveContainmentRecommendPaths(paths);
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.writeFile(configFile, "not json at all", "utf8");

  await assert.rejects(
    () => writeContainmentRecommendConfig(paths, { enabled: true }),
    /could not be safely read/,
  );
  // The file on disk is untouched by the refused write attempt.
  assert.equal(await fs.readFile(configFile, "utf8"), "not json at all");
});

test("--json-shaped config output carries no raw identifiers (the config itself only ever holds enabled/updated_at)", async () => {
  const paths = await tempPaths();
  const config = await writeContainmentRecommendConfig(paths, { enabled: true }, { now: "2026-08-21T00:00:00.000Z" });
  assert.deepEqual(Object.keys(config).sort(), ["enabled", "updated_at"]);
});

// ---------------------------------------------------------------------------------------------
// Slice 7.2.c: computeContainmentRecommendationCandidates — double-gated candidate compute over
// already-persisted alert history (never live facts, never a sibling's same-tick candidates).
// ---------------------------------------------------------------------------------------------

function activeCanaryTrippedAlert(fingerprint = "abcdef0123456789") {
  return {
    id: alertId(CANARY_TRIPPED_RULE_ID, fingerprint),
    rule_id: CANARY_TRIPPED_RULE_ID,
    fingerprint,
    status: "active",
    severity: "critical",
    title: "Canary tripped",
    summary: "x",
    first_seen: "2026-08-21T00:00:00.000Z",
    last_seen: "2026-08-21T00:00:00.000Z",
    diagnostics: { canary_id: "credential.bak", canary_id_hash: fingerprint, canary_kind: "credential-file", trip_reason: "executed" },
  };
}

test("computeContainmentRecommendationCandidates: both gates ON + an active trigger ⇒ exactly one recommendation candidate", async () => {
  const paths = await tempPaths();
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: true }),
    alerts: [activeCanaryTrippedAlert()],
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].rule_id, "containment.recommend.quarantine");
  assert.equal(candidates[0].diagnostics.trigger_rule_id, CANARY_TRIPPED_RULE_ID);
  assert.equal(candidates[0].diagnostics.target_repr, "abcdef0123456789");
  assert.equal(JSON.stringify(candidates).includes("redacted"), false);
});

test("computeContainmentRecommendationCandidates: the opt-in OFF ⇒ zero candidates, structurally, even with the trigger active and learned.json ON", async () => {
  const paths = await tempPaths();
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: false }),
    alerts: [activeCanaryTrippedAlert()],
  });
  assert.deepEqual(candidates, []);
});

test("computeContainmentRecommendationCandidates: learned.json OFF ⇒ zero candidates, and neither the opt-in nor the alert history is even read (short-circuit BEFORE I/O)", async () => {
  const paths = await tempPaths();
  let containmentConfigRead = false;
  let alertsRead = false;
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: false }),
    readContainmentRecommendConfig: async () => { containmentConfigRead = true; return { enabled: true }; },
    readAlertRecords: async () => { alertsRead = true; return [activeCanaryTrippedAlert()]; },
  });
  assert.deepEqual(candidates, []);
  assert.equal(containmentConfigRead, false);
  assert.equal(alertsRead, false);
});

test("computeContainmentRecommendationCandidates: no trigger present ⇒ zero (no storm on the first tick)", async () => {
  const paths = await tempPaths();
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: true }),
    alerts: [],
  });
  assert.deepEqual(candidates, []);
});

test("computeContainmentRecommendationCandidates: a recovered/acknowledged-away trigger produces no candidate; only an active/acknowledged trigger does", async () => {
  const paths = await tempPaths();
  const recovered = { ...activeCanaryTrippedAlert(), status: "recovered" };
  const suppressed = { ...activeCanaryTrippedAlert("1111111111111111"), status: "suppressed" };
  const acknowledged = { ...activeCanaryTrippedAlert("2222222222222222"), status: "acknowledged" };
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: true }),
    alerts: [recovered, suppressed, acknowledged],
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].fingerprint, "2222222222222222");
});

test("computeContainmentRecommendationCandidates: two distinct triggers sharing the same verb (canary.tripped + canary.tampered both -> quarantine) produce two distinct candidate records, never a collision", async () => {
  const paths = await tempPaths();
  const tripped = activeCanaryTrippedAlert("abcdef0123456789");
  const tampered = {
    id: alertId(CANARY_TAMPERED_RULE_ID, "fedcba9876543210"),
    rule_id: CANARY_TAMPERED_RULE_ID,
    fingerprint: "fedcba9876543210",
    status: "active",
    severity: "critical",
    title: "Canary tampering suspected",
    summary: "x",
    first_seen: "2026-08-21T00:00:00.000Z",
    last_seen: "2026-08-21T00:00:00.000Z",
    diagnostics: { tamper_reason: "manifest_unreadable" },
  };
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: true }),
    alerts: [tripped, tampered],
  });
  assert.equal(candidates.length, 2);
  assert.equal(candidates.every((c) => c.rule_id === "containment.recommend.quarantine"), true);
  const ids = new Set(candidates.map((c) => c.id));
  assert.equal(ids.size, 2, "two distinct triggers must never collide onto the same candidate id");
});

test("computeContainmentRecommendationCandidates: a garbled trigger (unrecognized rule_id) among otherwise-real alerts contributes no candidate, degrade not fabricate", async () => {
  const paths = await tempPaths();
  const candidates = await computeContainmentRecommendationCandidates(paths, {
    loadLearnedConfig: async () => ({ enabled: true }),
    readContainmentRecommendConfig: async () => ({ enabled: true }),
    alerts: [{ id: "alert_weird", rule_id: "weird.thing", status: "active", diagnostics: {} }],
  });
  assert.deepEqual(candidates, []);
});
