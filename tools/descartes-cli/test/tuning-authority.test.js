// S14 (outcome-informed compile-down) — docs/plans/2026-07-14-compile-down-calibration.md
// §5.7/§5.8/§6. tuning-authority.js: the deny-by-default human authority gate, independently
// (re-)verified per §6.3 point (c) -- a structural clone of promotion-store.js's proven-safe
// pattern is NOT assumed correct just because the source was safe.

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { evaluateConstraints } from "../src/constraint-eval.js";
import { loadConstraints, writeConstraints } from "../src/constraint-store.js";
import {
  DEFAULT_TUNING_APPROVAL_EXPIRY_MS,
  decideTuningApproval,
  loadTuningDecisions,
  mintPendingTuningApproval,
  resolveTuningAuthorityPaths,
  runLearnedTuningApprove,
  runLearnedTuningReject,
  runLearnedTuningReview,
  validateTuningDecisionRecord,
  writeTuningDecisions,
} from "../src/tuning-authority.js";
import { loadTuningCandidates, tuningCandidateId, writeTuningCandidates } from "../src/tuning-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-tuning-authority-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function activeConstraint(overrides = {}) {
  return {
    id: "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa",
    kind: "constraint",
    family: "daemon-config",
    target: "daemon.profile.interval_ms",
    expected: { comparator: "gte", value: 1000 },
    status: "active",
    confidence: 1,
    provenance: { window: "static", samples: 1, source_collectors: ["hand-authored"], mined_at: "2026-07-01T00:00:00.000Z" },
    fixtures: [],
    promotion_history: [],
    first_observed: "2026-07-01T00:00:00.000Z",
    last_verified: "2026-07-01T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

function reviewReadyRetireCandidate(overrides = {}) {
  const artifactRef = overrides.artifact_ref ?? "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa";
  return {
    id: tuningCandidateId("retire", artifactRef),
    kind: "retire",
    artifact_ref: artifactRef,
    rule_id_family: "constraint.violation.daemon-config",
    granularity: "artifact",
    status: "review-ready",
    current: null,
    proposed: null,
    justification: { fired_count: 6, auto_recovered_fast_count: 5, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: null },
    applied: false,
    apply_note: null,
    mined_at: "2026-07-01T00:00:00.000Z",
    backtested_at: "2026-07-01T00:00:00.000Z",
    promotion_history: [],
    schema_version: 1,
    ...overrides,
  };
}

function reviewReadyRetuneCandidate(overrides = {}) {
  const artifactRef = overrides.artifact_ref ?? "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa";
  return {
    id: tuningCandidateId("retune", artifactRef),
    kind: "retune",
    artifact_ref: artifactRef,
    rule_id_family: "constraint.violation.daemon-config",
    granularity: "artifact",
    status: "review-ready",
    current: { expected: { comparator: "gte", value: 1000 } },
    proposed: { expected: { comparator: "gte", value: 750 } },
    justification: { fired_count: 3, auto_recovered_fast_count: 0, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: { sample_ticks: 12, would_fire_count_current: 3, would_fire_count_proposed: 0 } },
    applied: false,
    apply_note: null,
    mined_at: "2026-07-01T00:00:00.000Z",
    backtested_at: "2026-07-01T00:00:00.000Z",
    promotion_history: [],
    schema_version: 1,
    ...overrides,
  };
}

// ============================================================================================
// resolveTuningAuthorityPaths / validateTuningDecisionRecord / load-write round trip
// ============================================================================================

test("resolveTuningAuthorityPaths points at stateDir/authority/tuning-decisions.json -- a SEPARATE file from promotions.json, no double-nesting", async () => {
  const paths = await tempPaths();
  const resolved = resolveTuningAuthorityPaths(paths);
  assert.equal(resolved.dir, path.join(paths.stateDir, "authority"));
  assert.equal(resolved.tuningDecisionsFile, path.join(paths.stateDir, "authority", "tuning-decisions.json"));
  assert.notEqual(resolved.tuningDecisionsFile, path.join(paths.stateDir, "authority", "promotions.json"));
  for (const value of Object.values(resolved)) {
    const occurrences = value.split(path.sep).filter((segment) => segment === "descartes").length;
    assert.equal(occurrences, 1, `expected exactly one "descartes" path segment in ${value}`);
  }
});

test("validateTuningDecisionRecord accepts a well-formed record and rejects missing/invalid fields", () => {
  const good = {
    id: "tuning-approval.deadbeefdeadbeef",
    nonce: "n",
    tuning_candidate_ref: "tuning.aaaaaaaaaaaaaaaa",
    bounded_summary: "s",
    evidence_refs: [],
    expiry: "2026-07-11T00:00:00.000Z",
    status: "pending",
    audit_transitions: [],
  };
  assert.equal(validateTuningDecisionRecord(good), true);
  assert.throws(() => validateTuningDecisionRecord({ ...good, id: "" }), /non-empty id/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, nonce: "" }), /non-empty nonce/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, tuning_candidate_ref: "" }), /non-empty tuning_candidate_ref/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, status: "bogus" }), /status must be one of/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, expiry: "not-a-date" }), /Invalid tuning decision/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, evidence_refs: "nope" }), /evidence_refs to be an array/);
  assert.throws(() => validateTuningDecisionRecord({ ...good, audit_transitions: "nope" }), /audit_transitions to be an array/);
});

test("writeTuningDecisions/loadTuningDecisions round-trip, atomic write, corrupt tolerance", async () => {
  const paths = await tempPaths();
  const record = { id: "tuning-approval.deadbeefdeadbeef", nonce: "n", tuning_candidate_ref: "tuning.aaaaaaaaaaaaaaaa", bounded_summary: "s", evidence_refs: [], expiry: "2026-07-11T00:00:00.000Z", status: "pending", audit_transitions: [] };
  await writeTuningDecisions(paths, [record]);
  const { decisions, corrupt_count } = await loadTuningDecisions(paths);
  assert.equal(corrupt_count, 0);
  assert.deepEqual(decisions, [record]);

  const { dir, tuningDecisionsFile } = resolveTuningAuthorityPaths(paths);
  const entries = await fs.readdir(dir);
  assert.equal(entries.some((entry) => entry.endsWith(".tmp")), false);

  await fs.writeFile(tuningDecisionsFile, "{ not json", "utf8");
  const corrupted = await loadTuningDecisions(paths);
  assert.deepEqual(corrupted.decisions, []);
  assert.equal(corrupted.corrupt_count, 1);
});

test("loadTuningDecisions returns an empty result on ENOENT -- deny-by-default holds even in the degenerate case", async () => {
  const paths = await tempPaths();
  const { decisions } = await loadTuningDecisions(paths);
  assert.deepEqual(decisions, []);
});

// ============================================================================================
// mintPendingTuningApproval
// ============================================================================================

test("mintPendingTuningApproval mints a nonce+expiry-bearing pending record for a review-ready candidate", async () => {
  const paths = await tempPaths();
  const candidate = reviewReadyRetireCandidate();
  const { approval, minted } = await mintPendingTuningApproval(paths, candidate, { now: "2026-07-10T00:00:00.000Z" });
  assert.equal(minted, true);
  assert.equal(approval.status, "pending");
  assert.equal(approval.tuning_candidate_ref, candidate.id);
  assert.match(approval.id, /^tuning-approval\.[0-9a-f]{16}$/);
  assert.equal(approval.expiry, new Date(Date.parse("2026-07-10T00:00:00.000Z") + DEFAULT_TUNING_APPROVAL_EXPIRY_MS).toISOString());
});

test("mintPendingTuningApproval reuses an existing valid pending record rather than minting a duplicate", async () => {
  const paths = await tempPaths();
  const candidate = reviewReadyRetireCandidate();
  const first = await mintPendingTuningApproval(paths, candidate, { now: "2026-07-10T00:00:00.000Z" });
  const second = await mintPendingTuningApproval(paths, candidate, { now: "2026-07-10T00:05:00.000Z" });
  assert.equal(second.minted, false);
  assert.equal(second.approval.id, first.approval.id);
});

test("MUST-FIX (plan §5.8 rule 3): mintPendingTuningApproval REFUSES to mint for a candidate that is not currently review-ready", async () => {
  const paths = await tempPaths();
  for (const status of ["draft", "approved", "rejected"]) {
    await assert.rejects(
      () => mintPendingTuningApproval(paths, reviewReadyRetireCandidate({ status }), { now: "2026-07-10T00:00:00.000Z" }),
      /not "review-ready"/,
    );
  }
  const { decisions } = await loadTuningDecisions(paths);
  assert.deepEqual(decisions, [], "no pending record must ever be written by a refused mint attempt");
});

// ============================================================================================
// decideTuningApproval -- deny-by-default core
// ============================================================================================

test("approve with the correct nonce transitions review-ready -> approved, flips applied:true, and writes the target constraint", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  const result = await decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now });
  assert.equal(result.candidate.status, "approved");
  assert.equal(result.candidate.applied, true);
  assert.equal(result.candidate.apply_note, null);
  assert.equal(result.decision.status, "approved");

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "retired");
});

test("approve on a NON-review-ready candidate fails closed -- no constraint/candidate/decision state change", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate({ status: "draft" });
  await writeTuningCandidates(paths, [candidate]);

  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, "any-nonce", "approved", { now: "2026-07-10T00:00:00.000Z" }),
    /not "review-ready"/,
  );
  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active");
});

test("approve with an unknown candidate id fails closed", async () => {
  const paths = await tempPaths();
  await assert.rejects(
    () => decideTuningApproval(paths, "tuning.doesnotexist", "any-nonce", "approved", { now: "2026-07-10T00:00:00.000Z" }),
    /no such tuning candidate/,
  );
});

test("approve with NO pending approval record at all denies (deny-by-default) and never mutates constraints.json", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);

  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, "never-minted-nonce", "approved", { now: "2026-07-10T00:00:00.000Z" }),
    /no_pending_tuning_approval/,
  );
  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active");
});

test("approve with the WRONG nonce denies, leaves everything untouched, and logs the denial against the live pending record", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  await assert.rejects(() => decideTuningApproval(paths, candidate.id, "wrong-nonce", "approved", { now }), /nonce_mismatch/);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active");
  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.id === approval.id);
  assert.equal(record.status, "pending");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "nonce_mismatch"));
});

test("adversarial-review fix: a denial is attributed to the currently-VALID pending record, not a stale-expired one that still carries status:pending", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [activeConstraint()]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  // D1: minted with a short expiry, then allowed to expire. Expired decision records keep
  // status:"pending" (only their `expiry` ages out), so it stays a pending record.
  const { approval: stale } = await mintPendingTuningApproval(paths, candidate, { now: "2026-07-10T00:00:00.000Z", expiryMs: 60_000 });
  // D2: re-minted after D1 expired -> a fresh, still-valid pending record coexisting with the stale one.
  const afterExpiry = "2026-07-10T00:05:00.000Z";
  const { approval: valid } = await mintPendingTuningApproval(paths, candidate, { now: afterExpiry });
  assert.notEqual(valid.id, stale.id, "expected a fresh record, not reuse of the expired one");

  // A garbage nonce denies; the denial must land on the VALID record's audit trail, not the stale one.
  await assert.rejects(() => decideTuningApproval(paths, candidate.id, "garbage-nonce", "approved", { now: afterExpiry }), /nonce_mismatch/);

  const { decisions } = await loadTuningDecisions(paths);
  const staleRecord = decisions.find((d) => d.id === stale.id);
  const validRecord = decisions.find((d) => d.id === valid.id);
  // The stale/expired record may carry its own lifecycle transition, but it must NEVER receive the
  // DENIED transition; that belongs on the live/valid record being attacked.
  assert.equal(staleRecord.audit_transitions.filter((t) => t.action === "denied").length, 0, "the stale/expired record must NOT get the denial");
  assert(validRecord.audit_transitions.some((t) => t.action === "denied" && t.reason === "nonce_mismatch"), "the live valid record must record the denial");
});

test("an EXPIRED approval is denied, and tuning review re-issues a fresh one", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const requestedAt = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, candidate, { now: requestedAt, expiryMs: 60_000 });

  const afterExpiry = "2026-07-10T00:05:00.000Z";
  await assert.rejects(() => decideTuningApproval(paths, candidate.id, minted.nonce, "approved", { now: afterExpiry }), /expired/);

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates[0].status, "review-ready");

  const reviewed = await runLearnedTuningReview(paths, [], { now: afterExpiry, output: () => {} });
  assert.notEqual(reviewed.review_ready[0].approval.nonce, minted.nonce);

  const approved = await runLearnedTuningApprove(paths, [candidate.id, "--nonce", reviewed.review_ready[0].approval.nonce], { now: afterExpiry, output: () => {} });
  assert.equal(approved.candidate.status, "approved");
});

// ============================================================================================
// MUST-FIX 1 -- THE RETUNE REPLAY GUARD (plan §5.7/§5.8/§6.2 layer 4): applyApprovedRetune is a
// self-loop (active -> active), so the CANDIDATE's own status -- not the constraint's -- is what
// prevents a replayed/re-minted nonce from re-applying a decided retune.
// ============================================================================================

test("MUST-FIX 1: a REPLAYED (already-consumed) nonce against a retune candidate is denied on the second attempt -- the candidate's own status is the replay guard", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetuneCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  const first = await decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now });
  assert.equal(first.candidate.status, "approved");
  assert.equal(first.candidate.applied, true);
  const { constraints: afterFirst } = await loadConstraints(paths);
  assert.deepEqual(afterFirst[0].expected, { comparator: "gte", value: 750 });

  // Replay: same candidate id + same nonce, again. The target constraint's OWN status never
  // changed (active -> active self-loop), so if this guard relied on the constraint's status it
  // would succeed again -- it must instead deny via the candidate's own status.
  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now: "2026-07-10T00:01:00.000Z" }),
    /not "review-ready"/,
  );

  const { constraints: afterReplay } = await loadConstraints(paths);
  assert.deepEqual(afterReplay[0].expected, { comparator: "gte", value: 750 }, "the replayed approve must not re-apply/change the value again");
  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates[0].promotion_history.filter((t) => t.to === "approved").length, 1, "exactly one review-ready -> approved transition ever recorded");
});

test("MUST-FIX 1: mintPendingTuningApproval refuses to mint a fresh nonce for an already-decided (approved) candidate -- closes the re-mint gap", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetuneCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });
  await decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now });

  const { candidates } = await loadTuningCandidates(paths);
  const decided = candidates.find((c) => c.id === candidate.id);
  assert.equal(decided.status, "approved");

  await assert.rejects(() => mintPendingTuningApproval(paths, decided, { now: "2026-07-10T00:02:00.000Z" }), /not "review-ready"/);
  const { decisions } = await loadTuningDecisions(paths);
  assert.equal(decisions.length, 1, "no new pending record must be minted for an already-decided candidate");
});

test("a REPLAYED nonce against a still-review-ready candidate (manufactured state) is independently denied via already_decided, at the authority-store layer directly", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  await decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now });

  // Manually reset the candidate back to review-ready (bypassing the guard) to prove the NONCE
  // itself is independently single-use even if some future code path ever reached this function
  // with a review-ready candidate again.
  const { candidates } = await loadTuningCandidates(paths);
  await writeTuningCandidates(paths, candidates.map((c) => (c.id === candidate.id ? { ...c, status: "review-ready" } : c)));

  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now: "2026-07-10T00:02:00.000Z" }),
    /already_decided/,
  );
});

// ============================================================================================
// Deny-by-default clone independence (plan §6.3 point (c)/§5.9): re-verified fresh, not assumed
// ============================================================================================

test("a nonce minted for candidate A cannot approve candidate B", async () => {
  const paths = await tempPaths();
  const constraintA = activeConstraint({ id: "constraint.mined.daemon-config.aaaaaaaaaaaaaaaa" });
  const constraintB = activeConstraint({ id: "constraint.mined.daemon-config.bbbbbbbbbbbbbbbb", target: "daemon.profile.other" });
  await writeConstraints(paths, [constraintA, constraintB]);
  const candidateA = reviewReadyRetireCandidate({ artifact_ref: constraintA.id });
  const candidateB = reviewReadyRetireCandidate({ artifact_ref: constraintB.id, id: tuningCandidateId("retire", constraintB.id) });
  await writeTuningCandidates(paths, [candidateA, candidateB]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: approvalForA } = await mintPendingTuningApproval(paths, candidateA, { now });

  await assert.rejects(() => decideTuningApproval(paths, candidateB.id, approvalForA.nonce, "approved", { now }), /no_pending_tuning_approval|nonce_mismatch/);
  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints.find((c) => c.id === constraintB.id).status, "active");
});

test("a denial never fabricates a wrong-nonce attempt on an already-decided record (audit-integrity, spot-B fix mirrored from promotion-store.js)", async () => {
  const paths = await tempPaths();
  const now = Date.parse("2026-07-10T00:00:00.000Z");
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);

  const expiry = new Date(now + DEFAULT_TUNING_APPROVAL_EXPIRY_MS).toISOString();
  // Manufactured multi-record state: an already-approved record AND a live pending record for the
  // same candidate, with the decided record FIRST in array order.
  const decided = { id: "tuning-approval.decided", nonce: "nonce-decided", tuning_candidate_ref: candidate.id, status: "approved", expiry, evidence_refs: [], audit_transitions: [] };
  const pending = { id: "tuning-approval.pending", nonce: "nonce-pending", tuning_candidate_ref: candidate.id, status: "pending", expiry, evidence_refs: [], audit_transitions: [] };
  await writeTuningDecisions(paths, [decided, pending]);

  await assert.rejects(() => decideTuningApproval(paths, candidate.id, "garbage-nonce", "approved", { now }));

  const { decisions } = await loadTuningDecisions(paths);
  const decidedAfter = decisions.find((d) => d.id === "tuning-approval.decided");
  const pendingAfter = decisions.find((d) => d.id === "tuning-approval.pending");
  assert.deepEqual(decidedAfter.audit_transitions, [], "the already-decided record must NEVER receive a fabricated denial entry");
  assert.equal(pendingAfter.audit_transitions.length, 1, "the denial must attribute to the live pending record instead");
  assert.equal(pendingAfter.audit_transitions[0].action, "denied");
});

// ============================================================================================
// MUST-FIX 4 -- malformed-retune rejection is fail-closed end-to-end through the authority gate
// ============================================================================================

test("MUST-FIX 4: approving a retune candidate whose proposed.expected is malformed fails the WHOLE attempt closed -- no candidate flip, no decision flip, no constraints.json write", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetuneCandidate({ proposed: { expected: { comparator: "gte", value: Number.NaN } } });
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  await assert.rejects(() => decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now }), /proposedExpected must be/);

  const { constraints } = await loadConstraints(paths);
  assert.deepEqual(constraints[0].expected, { comparator: "gte", value: 1000 }, "constraints.json must be byte-identical -- the malformed retune never wrote anything");

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates[0].status, "review-ready", "the candidate must stay review-ready (correctable/retryable), never silently flipped to approved");

  const { decisions } = await loadTuningDecisions(paths);
  assert.equal(decisions.find((d) => d.id === approval.id).status, "pending", "the pending approval record must stay pending, not silently consumed");
});

// ============================================================================================
// MUST-FIX 6 -- the applied:false FAIL-CLOSED DISPATCH DEFAULT (synthetic candidate; the real
// v1 miner never emits a non-constraint candidate, see tuning-store.test.js)
// ============================================================================================

test("MUST-FIX 6: a hand-constructed non-constraint-family candidate approved through the gate falls into the fail-closed default -- applied:false, a non-empty apply_note, zero live mutation", async () => {
  const paths = await tempPaths();
  // No constraints.json / signatures.json / session-baseline.json at all -- proving this path
  // touches none of them.
  const syntheticCandidate = {
    id: tuningCandidateId("retire", "9999888877776666"),
    kind: "retire", // a recognized KIND, but paired with a non-constraint family below
    artifact_ref: "9999888877776666",
    rule_id_family: "provenance.process.unknown_identity", // NOT constraint.violation.*
    granularity: "artifact",
    status: "review-ready",
    current: null,
    proposed: null,
    justification: { fired_count: 4, auto_recovered_fast_count: 0, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: null, backtest: null },
    applied: false,
    apply_note: null,
    mined_at: "2026-07-01T00:00:00.000Z",
    backtested_at: "2026-07-01T00:00:00.000Z",
    promotion_history: [],
    schema_version: 1,
  };
  await writeTuningCandidates(paths, [syntheticCandidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, syntheticCandidate, { now });

  const result = await decideTuningApproval(paths, syntheticCandidate.id, approval.nonce, "approved", { now });
  assert.equal(result.candidate.status, "approved");
  assert.equal(result.candidate.applied, false);
  assert.ok(result.candidate.apply_note && result.candidate.apply_note.length > 0, "expected a non-empty apply_note explaining the fail-closed default");

  // Zero live mutation: no constraints.json was ever created/written.
  await assert.rejects(() => fs.readFile(path.join(paths.stateDir, "learned", "constraints.json"), "utf8"), { code: "ENOENT" });
});

test("promote_shadow_hint approval is a pure no-op on constraints.json -- applied:false by construction, never a real mutation", async () => {
  const paths = await tempPaths();
  const shadowConstraint = activeConstraint({ id: "constraint.mined.service-presence.cccccccccccccccc", status: "shadow" });
  await writeConstraints(paths, [shadowConstraint]);
  const candidate = {
    id: tuningCandidateId("promote_shadow_hint", shadowConstraint.id),
    kind: "promote_shadow_hint",
    artifact_ref: shadowConstraint.id,
    rule_id_family: "constraint.violation.service-presence",
    granularity: "artifact",
    status: "review-ready",
    current: null,
    proposed: null,
    justification: { fired_count: 0, auto_recovered_fast_count: 0, never_escalated_count: null, llm_suppressed_count: 0, llm_adjudicated_count: 0, shadow_fire_rate: 0, backtest: null },
    applied: false,
    apply_note: null,
    mined_at: "2026-07-01T00:00:00.000Z",
    backtested_at: "2026-07-01T00:00:00.000Z",
    promotion_history: [],
    schema_version: 1,
  };
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  const before = JSON.stringify((await loadConstraints(paths)).constraints);
  const result = await decideTuningApproval(paths, candidate.id, approval.nonce, "approved", { now });
  const after = JSON.stringify((await loadConstraints(paths)).constraints);

  assert.equal(result.candidate.applied, false);
  assert.ok(result.candidate.apply_note);
  assert.equal(before, after, "constraints.json must be byte-identical before/after a promote_shadow_hint approval");
});

// ============================================================================================
// reject
// ============================================================================================

test("reject leaves the constraint untouched, flips the candidate to rejected, with an audit entry on both stores", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, candidate, { now });

  const result = await runLearnedTuningReject(paths, [candidate.id, "--nonce", approval.nonce, "--note", "false positive"], { now, output: () => {} });
  assert.equal(result.candidate.status, "rejected");
  assert.equal(result.candidate.applied, false);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active", "reject must never touch the target constraint");

  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.id === approval.id);
  assert.equal(record.status, "rejected");
  assert(record.audit_transitions.some((t) => t.action === "rejected"));
});

// ============================================================================================
// THE NEVER-AUTO-APPLY INVARIANT (plan §5.9/§6.2 -- highest priority test in this plan)
// ============================================================================================

test("THE NEVER-AUTO-APPLY INVARIANT: a draft AND a review-ready tuning candidate leave evaluateConstraints byte-identical; ONLY an approved decision changes the live threshold", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint({ expected: { comparator: "gte", value: 1000 } });
  await writeConstraints(paths, [constraint]);
  const factLookup = () => 800; // violates gte:1000, would still violate gte:750

  const baseline = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.equal(baseline.length, 1, "sanity: 800 violates the original gte:1000 floor");

  // --- Phase 1: draft ---
  const draftCandidate = reviewReadyRetuneCandidate({ status: "draft" });
  await writeTuningCandidates(paths, [draftCandidate]);
  const withDraft = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.deepEqual(withDraft, baseline, "a DRAFT tuning candidate must have ZERO effect on evaluateConstraints' output");

  // --- Phase 2: review-ready (still nothing approved) ---
  const reviewReadyCandidate = { ...draftCandidate, status: "review-ready" };
  await writeTuningCandidates(paths, [reviewReadyCandidate]);
  const withReviewReady = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.deepEqual(withReviewReady, baseline, "a REVIEW-READY tuning candidate must ALSO have ZERO effect -- proves architectural blindness, not just 'review-ready doesn't trigger a check'");

  // --- Phase 3: approved ---
  const now = "2026-07-10T00:00:00.000Z";
  const { approval } = await mintPendingTuningApproval(paths, reviewReadyCandidate, { now });
  await decideTuningApproval(paths, reviewReadyCandidate.id, approval.nonce, "approved", { now });

  const afterApprove = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.equal(afterApprove.length, 0, "ONLY after an explicit human approve does the loosened gte:750 floor take effect (800 >= 750 -> satisfied)");
});

// Real import/call syntax only (a doc comment is free to name these files in prose -- e.g.
// constraint-eval.js's own comment explaining WHY evaluateExpected is exported names
// "tuning-store.js" -- this targets the actual import surface, not a comment-stripping lint).
function hasRealImportOf(source, moduleName) {
  const fromImport = new RegExp(`from\\s*["'\`]\\.\\/${moduleName}["'\`]`);
  const dynamicImport = new RegExp(`import\\(\\s*["'\`][^"'\`]*${moduleName}["'\`]\\s*\\)`);
  return fromImport.test(source) || dynamicImport.test(source);
}

test("evaluateConstraints / constraint-eval.js has ZERO import of tuning-store.js or tuning-authority.js (architectural blindness, static assertion)", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/constraint-eval.js"), "utf8");
  assert.equal(hasRealImportOf(source, "tuning-store\\.js"), false);
  assert.equal(hasRealImportOf(source, "tuning-authority\\.js"), false);
});

test("daemon.js (the live evaluation loop) has ZERO import of tuning-store.js or tuning-authority.js", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/daemon.js"), "utf8");
  assert.equal(hasRealImportOf(source, "tuning-store\\.js"), false);
  assert.equal(hasRealImportOf(source, "tuning-authority\\.js"), false);
});

// ============================================================================================
// No LLM anywhere
// ============================================================================================

test("tuning-authority.js never imports the pi-harness/alert-intelligence LLM touchpoints", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/tuning-authority.js"), "utf8");
  assert.equal(hasRealImportOf(source, "pi-harness\\.js"), false);
  assert.equal(hasRealImportOf(source, "alert-intelligence\\.js"), false);
});

test("tuning-authority.js never itself writes the literal status:\"active\"/status:\"retired\" on a constraint -- it only ever calls constraint-store.js's retireActiveConstraint/applyApprovedRetune", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/tuning-authority.js"), "utf8");
  assert.equal(/["']active["']/.test(source), false, "tuning-authority.js source must never contain a quoted \"active\" literal");
  assert.equal(/["']retired["']/.test(source), false, "tuning-authority.js source must never contain a quoted \"retired\" literal");
  assert(/retireActiveConstraint/.test(source));
  assert(/applyApprovedRetune/.test(source));
});
