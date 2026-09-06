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
import { loadTuningCandidates, resolveTuningStorePaths, tuningCandidateId, writeTuningCandidates } from "../src/tuning-store.js";

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
// MUST-FIX 4 -- malformed-retune rejection is fail-closed at the STORE BOUNDARY (security-sweep F6)
// ============================================================================================
//
// Originally this asserted the AUTHORITY gate (decideTuningApproval) fails closed at APPLY time on a
// malformed proposed.expected. Security-sweep F6 hardened tuning-store.js so a malformed retune
// candidate is rejected EARLIER and cannot be persisted OR loaded at all -- writeTuningCandidates
// throws, loadTuningCandidates drops it -- so the apply-time path is unreachable THROUGH THE STORE
// by design (exactly F6's "never persisted / never review-ready" guarantee). The apply-time backstop
// itself still exists (constraint-store.js:688) and is covered in isolation by constraint-store.test.js
// ("REJECTS a non-finite value"). This test now pins the STRONGER, EARLIER guarantee at the same
// authority-facing boundary: a malformed retune never reaches the gate, and the live monitor is never
// touched.
test("MUST-FIX 4 (F6): a malformed retune candidate is rejected at the store boundary -- write throws, a raw round-tripped one is dropped at load -- so it can never reach the authority gate or mutate a live constraint", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const malformed = reviewReadyRetuneCandidate({ proposed: { expected: { comparator: "gte", value: Number.NaN } } });

  // (1) Write-time gate: the malformed retune candidate cannot be persisted into the store the
  // authority reads -- writeTuningCandidates validates every record and throws before any file write.
  await assert.rejects(
    () => writeTuningCandidates(paths, [malformed]),
    /requires proposed\.expected to be/,
    "a malformed retune candidate must be rejected at write, never persisted",
  );
  assert.deepEqual(
    (await loadTuningCandidates(paths)).candidates,
    [],
    "nothing was written -- the tmp+rename never completed, so no malformed candidate reached the store",
  );

  // (2) Load-time gate (defense-in-depth for a hand-edited / round-tripped store where an overflow
  // was persisted as JSON null): a malformed retune record placed RAW on disk is silently dropped by
  // loadTuningCandidates, so it never becomes a review-ready candidate the authority could approve.
  const { tuningCandidatesFile } = resolveTuningStorePaths(paths);
  await fs.mkdir(path.dirname(tuningCandidatesFile), { recursive: true });
  await fs.writeFile(
    tuningCandidatesFile,
    JSON.stringify(
      { schema_version: 1, candidates: [{ ...malformed, proposed: { expected: { comparator: "gte", value: null } } }] },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  assert.deepEqual(
    (await loadTuningCandidates(paths)).candidates,
    [],
    "a raw round-tripped malformed retune must be dropped at load, never surfaced to the authority",
  );

  // (3) The live monitor is untouched throughout: constraints.json is byte-identical.
  const { constraints } = await loadConstraints(paths);
  assert.deepEqual(
    constraints[0].expected,
    { comparator: "gte", value: 1000 },
    "no malformed retune ever mutated the live constraint",
  );
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
// L3 (daybreak sweep): extend the Astra-F2 count-and-fail-closed one-approval-one-record guard
// to decideTuningApproval, which had NO matchCount guard at all -- a duplicate-id decision would
// unconditionally stamp status:approved/rejected (and, on approve, applied:true/apply_note) onto
// EVERY review-ready candidate record sharing that id, even though the live constraint mutation
// itself only ever fires once (dispatchApprovedTuning only ever sees the single `.find`-matched
// candidate) -- corrupting the tuning audit trail for a duplicate that was never actually acted on.
// ============================================================================================

test("L3: approve with an AMBIGUOUS duplicate (two review-ready candidate records sharing the same id) fails closed via the audited denial helper before ANY dispatch/mutation", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const dup1 = reviewReadyRetireCandidate();
  const dup2 = reviewReadyRetireCandidate({ mined_at: "2026-07-02T00:00:00.000Z" }); // same id, both review-ready
  await writeTuningCandidates(paths, [dup1, dup2]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, dup1, { now });

  await assert.rejects(
    () => decideTuningApproval(paths, dup1.id, minted.nonce, "approved", { now }),
    /ambiguous duplicate review-ready/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active", "the target constraint must never be touched -- dispatch never runs when ambiguous");

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates.filter((c) => c.status === "review-ready").length, 2, "neither duplicate candidate record's status changed");

  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.id === minted.id);
  assert.equal(record.status, "pending", "the decision record itself is not consumed by an ambiguous-duplicate denial");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "ambiguous_duplicate_candidate"));
});

test("L3: reject with an AMBIGUOUS duplicate candidate id also fails closed -- neither duplicate is falsely flipped to rejected", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const dup1 = reviewReadyRetireCandidate();
  const dup2 = reviewReadyRetireCandidate({ mined_at: "2026-07-02T00:00:00.000Z" });
  await writeTuningCandidates(paths, [dup1, dup2]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, dup1, { now });

  await assert.rejects(
    () => decideTuningApproval(paths, dup1.id, minted.nonce, "rejected", { now }),
    /ambiguous duplicate review-ready/,
  );

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates.filter((c) => c.status === "review-ready").length, 2, "neither duplicate was falsely flipped to rejected");
  assert.equal(candidates.filter((c) => c.status === "rejected").length, 0);
});

// ============================================================================================
// L4 (daybreak sweep): logTuningDenial must AUDIT a denial attempt against a target with NO
// pending authority record at all (candidates.length===0), mirroring promotion-store.js's fix.
// Deny-by-default authority logic (matchPendingTuningApproval) is untouched.
// ============================================================================================

test("L4: approve with an unknown candidate id fails closed AND is audited (a phantom denied record is written, not a silent no-op)", async () => {
  const paths = await tempPaths();
  await assert.rejects(
    () => decideTuningApproval(paths, "tuning.doesnotexist", "any-nonce", "approved", { now: "2026-07-10T00:00:00.000Z" }),
    /no such tuning candidate/,
  );

  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.tuning_candidate_ref === "tuning.doesnotexist");
  assert(record, "a denial against an unknown candidate id must leave a persisted audit trace");
  assert.equal(record.status, "denied");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "candidate_not_found"));
});

test("L4: approve with NO pending approval record at all denies AND persists the audit trail (reason: no_pending_tuning_approval)", async () => {
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

  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.tuning_candidate_ref === candidate.id);
  assert(record, "a denial against a target with zero decision records must still be persisted");
  assert.equal(record.status, "denied");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "no_pending_tuning_approval"));
});

test("L4: a REPLAYED identical (candidateId, nonce) probe against a never-reviewed candidate dedups into ONE phantom record with two audit entries", async () => {
  const paths = await tempPaths();
  await assert.rejects(() => decideTuningApproval(paths, "tuning.doesnotexist", "same-nonce", "approved", { now: "2026-07-10T00:00:00.000Z" }));
  await assert.rejects(() => decideTuningApproval(paths, "tuning.doesnotexist", "same-nonce", "approved", { now: "2026-07-10T00:01:00.000Z" }));

  const { decisions } = await loadTuningDecisions(paths);
  const matching = decisions.filter((d) => d.tuning_candidate_ref === "tuning.doesnotexist");
  assert.equal(matching.length, 1, "an identical-nonce replay must dedup into the SAME record, not spam a new one each time");
  assert.equal(matching[0].audit_transitions.filter((t) => t.action === "denied").length, 2);
});

// ============================================================================================
// L3/L4 round 3 (daybreak re-gate round 2): two residuals from the round-1 L3/L4 fixes above,
// mirrored from promotion-store.js's own round-3 fix.
//
// L3 residual: decideTuningApproval's candidate lookup was `candidates.find(id-match)` --
// order-dependent. If an EARLIER same-id record sits in another status (approved/rejected) and
// the SOLE review-ready record is later in the array, `.find` picks the earlier wrong-status
// record and denies via "candidate_not_review_ready" BEFORE the matchCount>1 guard ever runs --
// over-fail-closed on a genuinely legitimate single approval/reject.
//
// L4 residual: logTuningDenial's phantom "denied" record self-suppressed every LATER attempt
// with a DIFFERENT nonce, exactly like promotion-store.js's logDenial.
// ============================================================================================

test("L3 round-3: approve SUCCEEDS when an EARLIER same-id candidate record is REJECTED and the sole review-ready record is later in the array (order-independent matcher)", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const rejectedDup = reviewReadyRetireCandidate({ status: "rejected", mined_at: "2026-07-02T00:00:00.000Z" }); // earlier, same id, WRONG status
  const reviewReady = reviewReadyRetireCandidate(); // later, same id, the one eligible record
  await writeTuningCandidates(paths, [rejectedDup, reviewReady]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, reviewReady, { now });

  const result = await decideTuningApproval(paths, reviewReady.id, minted.nonce, "approved", { now });
  assert.equal(result.candidate.status, "approved", "the legitimate single review-ready record must be approved, not wrongly denied");

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates.filter((c) => c.status === "rejected").length, 1, "the pre-existing rejected dup is untouched");
  assert.equal(candidates.filter((c) => c.status === "approved").length, 1);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "retired", "the approved retire dispatch still fires against the live constraint");
});

test("L3 round-3: reject SUCCEEDS when an EARLIER same-id candidate record is APPROVED and the sole review-ready record is later in the array (order-independent matcher)", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const approvedDup = reviewReadyRetireCandidate({ status: "approved", mined_at: "2026-07-02T00:00:00.000Z" }); // earlier, same id, WRONG status
  const reviewReady = reviewReadyRetireCandidate(); // later, same id, the one eligible record
  await writeTuningCandidates(paths, [approvedDup, reviewReady]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, reviewReady, { now });

  const result = await decideTuningApproval(paths, reviewReady.id, minted.nonce, "rejected", { now });
  assert.equal(result.candidate.status, "rejected", "the legitimate single review-ready record must be rejected, not wrongly denied");

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates.filter((c) => c.status === "approved").length, 1, "the pre-existing approved dup is untouched by the reject");
  assert.equal(candidates.filter((c) => c.status === "rejected").length, 1);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active", "a rejected candidate never dispatches any mutation");
});

test("L3 round-3: approve with TWO genuinely-duplicate review-ready same-id candidate records + one nonce still fails closed AUDITED (order-independence never weakens the duplicate guard)", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const dup1 = reviewReadyRetireCandidate();
  const dup2 = reviewReadyRetireCandidate({ mined_at: "2026-07-02T00:00:00.000Z" });
  await writeTuningCandidates(paths, [dup1, dup2]);
  const now = "2026-07-10T00:00:00.000Z";
  const { approval: minted } = await mintPendingTuningApproval(paths, dup1, { now });

  await assert.rejects(
    () => decideTuningApproval(paths, dup1.id, minted.nonce, "approved", { now }),
    /ambiguous duplicate review-ready/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active", "the target constraint must never be touched -- dispatch never runs when ambiguous");

  const { candidates } = await loadTuningCandidates(paths);
  assert.equal(candidates.filter((c) => c.status === "review-ready").length, 2, "neither duplicate candidate record's status changed");

  const { decisions } = await loadTuningDecisions(paths);
  const record = decisions.find((d) => d.id === minted.id);
  assert.equal(record.status, "pending", "the decision record itself is not consumed by the duplicate denial");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "ambiguous_duplicate_candidate"));
});

test("L4 round-3: TWO distinct no-pending attempts (different nonces) leave TWO audited denial transitions, not one -- a phantom must never self-suppress a later attempt", async () => {
  const paths = await tempPaths();
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);

  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, "nonce-A", "approved", { now: "2026-07-10T00:00:00.000Z" }),
    /no_pending_tuning_approval/,
  );
  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, "nonce-B", "approved", { now: "2026-07-10T00:01:00.000Z" }),
    /no_pending_tuning_approval/,
  );

  const { decisions } = await loadTuningDecisions(paths);
  const matching = decisions.filter((d) => d.tuning_candidate_ref === candidate.id);
  assert.equal(matching.length, 1, "still only ONE phantom RECORD per candidate id, never one per distinct nonce");
  assert.equal(matching[0].status, "denied");
  assert.equal(matching[0].audit_transitions.filter((t) => t.action === "denied").length, 2, "both distinct-nonce attempts must be audited");
});

test("L4 round-3 scope guard: a WRONG-nonce attempt against an already-decided record (no live pending, no phantom yet) stays the spot-B no-op -- it must NOT fabricate a new phantom record", async () => {
  const paths = await tempPaths();
  const now = Date.parse("2026-07-10T00:00:00.000Z");
  const constraint = activeConstraint();
  await writeConstraints(paths, [constraint]);
  const candidate = reviewReadyRetireCandidate();
  await writeTuningCandidates(paths, [candidate]);
  const expiry = new Date(now + DEFAULT_TUNING_APPROVAL_EXPIRY_MS).toISOString();
  const decided = { id: "tuning.decided", nonce: "nonce-decided", tuning_candidate_ref: candidate.id, status: "approved", expiry, evidence_refs: [], audit_transitions: [] };
  await writeTuningDecisions(paths, [decided]);

  await assert.rejects(
    () => decideTuningApproval(paths, candidate.id, "garbage-nonce", "approved", { now }),
    /already_decided/,
  );

  const { decisions } = await loadTuningDecisions(paths);
  assert.equal(decisions.length, 1, "no phantom is fabricated next to a real already-decided record");
  assert.deepEqual(decisions[0].audit_transitions, [], "the already-decided record's audit trail remains untouched");
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
