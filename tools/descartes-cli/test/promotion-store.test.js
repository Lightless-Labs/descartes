import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertNoPiOwnedPath, resolveDescartesPaths } from "../src/paths.js";
import { loadConstraints, writeConstraints } from "../src/constraint-store.js";
import {
  DEFAULT_PROMOTION_EXPIRY_MS,
  decideConstraintPromotion,
  loadPromotions,
  mintPendingPromotion,
  resolvePromotionStorePaths,
  runLearnedApprove,
  runLearnedReject,
  runLearnedReview,
  validatePromotionRecord,
  writePromotions,
} from "../src/promotion-store.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-promotion-store-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

function reviewReadyConstraint(overrides = {}) {
  return {
    id: "constraint.mined.service-presence.deadbeefdeadbeef",
    kind: "constraint",
    family: "service-presence",
    target: "service.presence.nginx",
    expected: { comparator: "eq", value: "true" },
    status: "review-ready",
    confidence: 1,
    provenance: { window: "7d", samples: 21, source_collectors: ["services"], mined_at: "2026-07-01T00:00:00.000Z" },
    fixtures: [
      { input: { "service.presence": "true" }, expect_match: true },
      { input: { "service.presence": "false" }, expect_match: false },
    ],
    promotion_history: [
      { ts: "2026-07-01T00:00:00.000Z", from: "draft", to: "shadow", actor: "deterministic-gate", note: "minimum-fixture bar met" },
      { ts: "2026-07-08T00:00:00.000Z", from: "shadow", to: "review-ready", actor: "deterministic-gate", note: "clean soak window" },
    ],
    first_observed: "2026-07-01T00:00:00.000Z",
    last_verified: "2026-07-08T00:00:00.000Z",
    sensitivity: "operational",
    schema_version: 1,
    ...overrides,
  };
}

// --- resolvePromotionStorePaths ---

test("resolvePromotionStorePaths points at stateDir/authority/promotions.json with no double-nesting, passes the Pi-owned path guard", async () => {
  const paths = await tempPaths();
  const storePaths = resolvePromotionStorePaths(paths);
  assert.equal(storePaths.dir, path.join(paths.stateDir, "authority"));
  assert.equal(storePaths.promotionsFile, path.join(paths.stateDir, "authority", "promotions.json"));
  assert.doesNotThrow(() => assertNoPiOwnedPath({ promotionsFile: storePaths.promotionsFile }));
});

test("DEFAULT_PROMOTION_EXPIRY_MS is 24h", () => {
  assert.equal(DEFAULT_PROMOTION_EXPIRY_MS, 24 * 60 * 60 * 1000);
});

// --- validatePromotionRecord ---

function wellFormedPromotion(overrides = {}) {
  return {
    id: "promotion.abc123",
    nonce: "deadbeefdeadbeefdeadbeefdeadbeef",
    promotion_ref: "constraint.mined.service-presence.deadbeefdeadbeef",
    bounded_summary: "service-presence:service.presence.nginx",
    evidence_refs: ["constraint-store", "shadow-store"],
    requested_at: "2026-07-10T00:00:00.000Z",
    expiry: "2026-07-11T00:00:00.000Z",
    status: "pending",
    decided_at: undefined,
    audit_transitions: [{ ts: "2026-07-10T00:00:00.000Z", action: "requested", actor: "human-cli" }],
    ...overrides,
  };
}

test("validatePromotionRecord accepts a well-formed record", () => {
  assert.doesNotThrow(() => validatePromotionRecord(wellFormedPromotion()));
});

test("validatePromotionRecord rejects missing id/nonce/promotion_ref", () => {
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ id: "" })), /id/);
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ nonce: "" })), /nonce/);
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ promotion_ref: "" })), /promotion_ref/);
});

test("validatePromotionRecord rejects an invalid status and a non-ISO expiry", () => {
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ status: "bogus" })), /status/);
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ expiry: "not-a-date" })), /expiry/);
});

test("validatePromotionRecord rejects non-array evidence_refs/audit_transitions", () => {
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ evidence_refs: "nope" })), /evidence_refs/);
  assert.throws(() => validatePromotionRecord(wellFormedPromotion({ audit_transitions: "nope" })), /audit_transitions/);
});

// --- loadPromotions / writePromotions: atomic + corrupt-tolerant ---

test("writePromotions/loadPromotions round-trip", async () => {
  const paths = await tempPaths();
  await writePromotions(paths, [wellFormedPromotion()]);
  const { promotions, corrupt_count } = await loadPromotions(paths);
  assert.equal(corrupt_count, 0);
  assert.equal(promotions.length, 1);
  assert.equal(promotions[0].id, "promotion.abc123");
});

test("loadPromotions returns an empty result on ENOENT (deny-by-default: nothing can match)", async () => {
  const paths = await tempPaths();
  const { promotions, corrupt_count } = await loadPromotions(paths);
  assert.deepEqual(promotions, []);
  assert.equal(corrupt_count, 0);
});

test("a corrupted promotions.json is tolerated rather than thrown", async () => {
  const paths = await tempPaths();
  const { dir, promotionsFile } = resolvePromotionStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(promotionsFile, "{ not json", { mode: 0o600 });

  const { promotions, corrupt_count } = await loadPromotions(paths);
  assert.deepEqual(promotions, []);
  assert(corrupt_count >= 1);
});

test("loadPromotions drops an individually invalid record without counting it as file-level corruption", async () => {
  const paths = await tempPaths();
  const { dir, promotionsFile } = resolvePromotionStorePaths(paths);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(promotionsFile, JSON.stringify({
    schema_version: 1,
    promotions: [wellFormedPromotion(), { id: "promotion.bad" /* missing nonce etc */ }],
  }));

  const { promotions, corrupt_count } = await loadPromotions(paths);
  assert.equal(corrupt_count, 0);
  assert.equal(promotions.length, 1);
  assert.equal(promotions[0].id, "promotion.abc123");
});

test("writePromotions is atomic (tmp+rename, no leftover tmp file)", async () => {
  const paths = await tempPaths();
  await writePromotions(paths, [wellFormedPromotion()]);
  const storePaths = resolvePromotionStorePaths(paths);
  const dirEntries = await fs.readdir(storePaths.dir);
  assert(!dirEntries.some((entry) => entry.endsWith(".tmp")), "no leftover tmp file after a successful write");
});

// --- mintPendingPromotion ---

test("mintPendingPromotion mints a nonce+expiry-bearing pending record for a review-ready constraint", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const constraint = reviewReadyConstraint();
  const { promotion, minted } = await mintPendingPromotion(paths, constraint, { now });

  assert.equal(minted, true);
  assert.equal(promotion.promotion_ref, constraint.id);
  assert.equal(promotion.status, "pending");
  assert.equal(typeof promotion.nonce, "string");
  assert(promotion.nonce.length > 0);
  assert.equal(promotion.expiry, new Date(Date.parse(now) + DEFAULT_PROMOTION_EXPIRY_MS).toISOString());
  assert.equal(promotion.audit_transitions.length, 1);
  assert.equal(promotion.audit_transitions[0].action, "requested");

  const { promotions } = await loadPromotions(paths);
  assert.equal(promotions.length, 1);
});

test("mintPendingPromotion reuses an existing valid pending record rather than minting a duplicate", async () => {
  const paths = await tempPaths();
  const now = "2026-07-10T00:00:00.000Z";
  const constraint = reviewReadyConstraint();
  const first = await mintPendingPromotion(paths, constraint, { now });
  const second = await mintPendingPromotion(paths, constraint, { now: "2026-07-10T00:05:00.000Z" });

  assert.equal(second.minted, false);
  assert.equal(second.promotion.nonce, first.promotion.nonce);
  const { promotions } = await loadPromotions(paths);
  assert.equal(promotions.length, 1);
});

test("mintPendingPromotion mints a fresh record once the prior one has expired", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  const first = await mintPendingPromotion(paths, constraint, { now: "2026-07-10T00:00:00.000Z", expiryMs: 60_000 });
  const second = await mintPendingPromotion(paths, constraint, { now: "2026-07-10T00:05:00.000Z" });

  assert.equal(second.minted, true);
  assert.notEqual(second.promotion.nonce, first.promotion.nonce);
  const { promotions } = await loadPromotions(paths);
  assert.equal(promotions.length, 2);
});

test("mintPendingPromotion's bounded_summary and evidence_refs are sanitized, bounded strings — never a raw/unbounded value", async () => {
  const paths = await tempPaths();
  const hostile = reviewReadyConstraint({
    family: "service-presence",
    target: "/usr/local/bin/../../etc/passwd".repeat(3),
    provenance: { window: "7d", samples: 21, source_collectors: ["../../etc/shadow"], mined_at: "2026-07-01T00:00:00.000Z" },
  });
  const { promotion } = await mintPendingPromotion(paths, hostile, { now: "2026-07-10T00:00:00.000Z" });

  assert.equal(typeof promotion.bounded_summary, "string");
  assert(promotion.bounded_summary.length <= 64);
  assert.doesNotMatch(promotion.bounded_summary, /\//);
  for (const ref of promotion.evidence_refs) {
    assert.equal(typeof ref, "string");
    assert(ref.length <= 64);
    assert.doesNotMatch(ref, /\//);
  }
});

// --- descartes learned review (CLI) ---

test("descartes learned review lists only review-ready constraints and mints a pending promotion for each", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [
    reviewReadyConstraint(),
    reviewReadyConstraint({ id: "constraint.mined.service-presence.other", status: "shadow" }),
    reviewReadyConstraint({ id: "constraint.mined.service-presence.retired", status: "retired" }),
  ]);

  const lines = [];
  const result = await runLearnedReview(paths, [], { now: "2026-07-10T00:00:00.000Z", output: (line) => lines.push(line) });

  assert.equal(result.review_ready.length, 1);
  assert.equal(result.review_ready[0].id, reviewReadyConstraint().id);
  assert.equal(typeof result.review_ready[0].promotion.nonce, "string");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /nonce=/);
});

test("descartes learned review is read-only of constraint status (never mutates constraints.json)", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [reviewReadyConstraint()]);
  await runLearnedReview(paths, [], { now: "2026-07-10T00:00:00.000Z", output: () => {} });

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");
  assert.deepEqual(constraints[0].promotion_history, reviewReadyConstraint().promotion_history);
});

test("descartes learned review --json prints a machine-readable listing with fixtures/provenance/promotion_history", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, [reviewReadyConstraint()]);
  const lines = [];
  await runLearnedReview(paths, ["--json"], { now: "2026-07-10T00:00:00.000Z", output: (line) => lines.push(line) });

  assert.equal(lines.length, 1);
  const payload = JSON.parse(lines[0]);
  const entry = payload.learned_review.review_ready[0];
  assert.equal(entry.id, reviewReadyConstraint().id);
  assert.deepEqual(entry.fixtures, reviewReadyConstraint().fixtures);
  assert.deepEqual(entry.provenance, reviewReadyConstraint().provenance);
  assert.deepEqual(entry.promotion_history, reviewReadyConstraint().promotion_history);
  assert.equal(typeof entry.promotion.nonce, "string");
});

test("descartes learned review with no review-ready constraints prints a clear empty message", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, []);
  const lines = [];
  await runLearnedReview(paths, [], { now: "2026-07-10T00:00:00.000Z", output: (line) => lines.push(line) });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /No review-ready/);
});

// --- descartes learned approve: the ONLY path to status:"active" ---

test("approve with the correct nonce transitions review-ready -> active and writes an approved promotions.json record with audit", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  const lines = [];
  const result = await runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce], { now, output: (line) => lines.push(line) });

  assert.equal(result.constraint.status, "active");
  assert.equal(result.constraint.promotion_history.at(-1).from, "review-ready");
  assert.equal(result.constraint.promotion_history.at(-1).to, "active");
  assert.equal(result.constraint.promotion_history.at(-1).actor, "human-cli");
  assert.match(lines[0], /Approved/);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints.find((c) => c.id === constraint.id).status, "active");

  const { promotions } = await loadPromotions(paths);
  const record = promotions.find((p) => p.id === minted.id);
  assert.equal(record.status, "approved");
  assert.equal(typeof record.decided_at, "string");
  assert(record.audit_transitions.some((t) => t.action === "approved"));
});

test("approve --json prints a machine-readable payload", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  const lines = [];
  await runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce, "--json"], { now, output: (line) => lines.push(line) });
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.learned_approve.constraint.status, "active");
  assert.equal(payload.learned_approve.promotion.status, "approved");
});

test("approve on a NON-review-ready constraint fails closed — stays non-active, no state change", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint({ status: "shadow" });
  await writeConstraints(paths, [constraint]);

  await assert.rejects(
    () => runLearnedApprove(paths, [constraint.id, "--nonce", "irrelevant"], { now: "2026-07-10T00:00:00.000Z", output: () => {} }),
    /not "review-ready"/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "shadow");
});

test("approve with an unknown constraint id fails closed", async () => {
  const paths = await tempPaths();
  await writeConstraints(paths, []);
  await assert.rejects(
    () => runLearnedApprove(paths, ["constraint.does.not.exist", "--nonce", "irrelevant"], { now: "2026-07-10T00:00:00.000Z", output: () => {} }),
    /no such constraint/,
  );
});

test("approve with NO promotion record at all denies (deny-by-default) and never activates", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  // Deliberately never called runLearnedReview/mintPendingPromotion — promotions.json is empty.

  await assert.rejects(
    () => runLearnedApprove(paths, [constraint.id, "--nonce", "anything"], { now: "2026-07-10T00:00:00.000Z", output: () => {} }),
    /no_pending_promotion/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");
});

test("approve with the WRONG nonce denies, leaves the constraint untouched, and logs the denial", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  await assert.rejects(
    () => runLearnedApprove(paths, [constraint.id, "--nonce", `${minted.nonce}-wrong`], { now, output: () => {} }),
    /nonce_mismatch/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");

  const { promotions } = await loadPromotions(paths);
  const record = promotions.find((p) => p.id === minted.id);
  assert.equal(record.status, "pending", "the legitimate pending record is not consumed by a wrong-nonce attempt");
  assert(record.audit_transitions.some((t) => t.action === "denied" && t.reason === "nonce_mismatch"));
});

test("an EXPIRED approval is denied, and review re-issues a fresh promotion", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const requestedAt = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now: requestedAt, expiryMs: 60_000 });

  const afterExpiry = "2026-07-10T00:05:00.000Z"; // 5 minutes later, past the 60s expiry
  await assert.rejects(
    () => runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce], { now: afterExpiry, output: () => {} }),
    /expired/,
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");

  // review re-issues a fresh, distinct, currently-valid promotion.
  const lines = [];
  const reviewed = await runLearnedReview(paths, [], { now: afterExpiry, output: (line) => lines.push(line) });
  assert.notEqual(reviewed.review_ready[0].promotion.nonce, minted.nonce);

  // ...and approving with the NEW nonce now succeeds.
  const approved = await runLearnedApprove(paths, [constraint.id, "--nonce", reviewed.review_ready[0].promotion.nonce], { now: afterExpiry, output: () => {} });
  assert.equal(approved.constraint.status, "active");
});

test("a REPLAYED (already-consumed) nonce is rejected on a second approve attempt", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  const first = await runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce], { now, output: () => {} });
  assert.equal(first.constraint.status, "active");

  // Replay: same constraint id + same nonce, again.
  await assert.rejects(
    () => runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce], { now: "2026-07-10T00:01:00.000Z", output: () => {} }),
    /not "review-ready"/, // the constraint is already active, so the review-ready guard denies first
  );

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "active");
  // Exactly one review-ready -> active transition was ever recorded.
  assert.equal(constraints[0].promotion_history.filter((t) => t.to === "active").length, 1);
});

test("a REPLAYED nonce against a still-review-ready constraint (two constraints sharing no state) is independently denied via already_decided", async () => {
  // Regression for the "consumed nonce" invariant at the promotions-store layer directly,
  // independent of the review-ready guard exercised by the test above.
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  await decideConstraintPromotion(paths, constraint.id, minted.nonce, "approved", { now });

  // Manually attempt the same decision again at the promotion-store layer (bypassing the
  // review-ready guard by resetting the constraint back to review-ready) to prove the nonce
  // itself is single-use even if some future code path ever reached this function with a
  // review-ready constraint again.
  const { constraints } = await loadConstraints(paths);
  await writeConstraints(paths, constraints.map((c) => (c.id === constraint.id ? { ...c, status: "review-ready" } : c)));

  await assert.rejects(
    () => decideConstraintPromotion(paths, constraint.id, minted.nonce, "approved", { now: "2026-07-10T00:02:00.000Z" }),
    /already_decided/,
  );
});

// --- descartes learned reject ---

test("reject leaves the constraint non-active (status:\"retired\") with an audit entry, on both stores", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  const lines = [];
  const result = await runLearnedReject(paths, [constraint.id, "--nonce", minted.nonce, "--note", "false positive"], { now, output: (line) => lines.push(line) });

  assert.equal(result.constraint.status, "retired");
  assert.equal(result.constraint.promotion_history.at(-1).to, "retired");
  assert.match(lines[0], /Rejected/);

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "retired");
  assert.notEqual(constraints[0].status, "active");

  const { promotions } = await loadPromotions(paths);
  const record = promotions.find((p) => p.id === minted.id);
  assert.equal(record.status, "rejected");
  assert(record.audit_transitions.some((t) => t.action === "rejected"));
});

test("reject --json prints a machine-readable payload", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });

  const lines = [];
  await runLearnedReject(paths, [constraint.id, "--nonce", minted.nonce, "--json"], { now, output: (line) => lines.push(line) });
  const payload = JSON.parse(lines[0]);
  assert.equal(payload.learned_reject.constraint.status, "retired");
});

test("reject follows the same deny-by-default nonce/expiry rules as approve", async () => {
  const paths = await tempPaths();
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);
  const now = "2026-07-10T00:00:00.000Z";
  await mintPendingPromotion(paths, constraint, { now });

  await assert.rejects(
    () => runLearnedReject(paths, [constraint.id, "--nonce", "wrong"], { now, output: () => {} }),
    /nonce_mismatch/,
  );
  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints[0].status, "review-ready");
});

// --- No LLM anywhere ---

test("promotion-store.js never imports the pi-harness/alert-intelligence LLM touchpoints", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/promotion-store.js"), "utf8");
  assert.equal(/pi-harness\.js/.test(source), false);
  assert.equal(/alert-intelligence\.js/.test(source), false);
});

// --- Load-bearing safety regression: exactly one activation path in the whole codebase ---

test("promotion-store.js never itself writes the literal status:\"active\" — it only ever calls constraint-store.js's promoteReviewReadyToActive", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../src/promotion-store.js"), "utf8");
  assert.equal(/["']active["']/.test(source), false, "promotion-store.js source must never contain a quoted \"active\" literal");
  assert(/promoteReviewReadyToActive/.test(source), "the approved path must delegate to constraint-store.js's single writer");
});

test("evaluateConstraints (already shipped) is the only consumer of status:\"active\" constraints, and mine/soak/review never produce one — end-to-end fixture", async () => {
  const paths = await tempPaths();
  // A constraint that would obviously violate itself if ever evaluated while still
  // review-ready — proves review-ready constraints are inert until approve runs.
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);

  const { evaluateConstraints } = await import("../src/constraint-eval.js");
  const factLookup = () => "false"; // contradicts expected value:"true" -> would violate if active
  const beforeApprove = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.equal(beforeApprove.length, 0, "a review-ready constraint must never be evaluated as if active");

  const now = "2026-07-10T00:00:00.000Z";
  const { promotion: minted } = await mintPendingPromotion(paths, constraint, { now });
  await runLearnedApprove(paths, [constraint.id, "--nonce", minted.nonce], { now, output: () => {} });

  const afterApprove = evaluateConstraints((await loadConstraints(paths)).constraints, factLookup);
  assert.equal(afterApprove.length, 1, "only after an explicit human approve does the constraint become evaluable/active");
});

test("a denial never fabricates a wrong-nonce attempt on an already-decided record (audit-integrity, spot B)", async () => {
  const paths = await tempPaths();
  const now = Date.parse("2026-07-10T00:00:00.000Z");
  const constraint = reviewReadyConstraint();
  await writeConstraints(paths, [constraint]);

  const expiry = new Date(now + DEFAULT_PROMOTION_EXPIRY_MS).toISOString();
  // Manufactured multi-record state: an already-approved record AND a live pending record for the
  // same constraint, with the decided record LAST in array order (what the old at(-1) fallback
  // would have wrongly targeted).
  const decided = { id: "promotion.decided", nonce: "nonce-decided", promotion_ref: constraint.id, status: "approved", expiry, evidence_refs: [], audit_transitions: [] };
  const pending = { id: "promotion.pending", nonce: "nonce-pending", promotion_ref: constraint.id, status: "pending", expiry, evidence_refs: [], audit_transitions: [] };
  await writePromotions(paths, [pending, decided]);

  // A garbage nonce matches neither record: it must deny closed AND attribute the denial to the
  // live pending record — never fabricate an attempt in the already-decided record's audit trail.
  await assert.rejects(() => decideConstraintPromotion(paths, constraint.id, "garbage-nonce", "approved", { now }));

  const { promotions } = await loadPromotions(paths);
  const decidedAfter = promotions.find((r) => r.id === "promotion.decided");
  const pendingAfter = promotions.find((r) => r.id === "promotion.pending");
  assert.deepEqual(decidedAfter.audit_transitions, [], "the already-decided record's audit trail is untouched");
  assert.equal(pendingAfter.audit_transitions.length, 1, "the denial is attributed to the live pending record");
  assert.equal(pendingAfter.audit_transitions[0].action, "denied");

  const { constraints } = await loadConstraints(paths);
  assert.equal(constraints.find((c) => c.id === constraint.id).status, "review-ready", "the constraint was not activated");
});
