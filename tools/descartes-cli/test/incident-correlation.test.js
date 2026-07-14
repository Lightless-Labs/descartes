import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { alertId, applyAlertCandidates, readAlertRecords, writeAlertRecords } from "../src/alert-store.js";
import { writeLearnedConfig } from "../src/constraint-store.js";
import { appendFactPoints } from "../src/fact-store.js";
import { PEER_OVERFLOW_ENTITY_KEY } from "../src/fact-translators.js";
import { resolveDescartesPaths } from "../src/paths.js";
import { SESSION_CHURN_RULE_ID, SESSION_COUNT_DROP_RULE_ID } from "../src/session-baseline.js";
import {
  CORRELATION_MIN_PEER_HISTORY_DAYS,
  CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS,
  CORRELATION_NOVELTY_MAX_PRIOR_TICKS,
  CORRELATION_ODD_HOURS,
  CORRELATION_RULE_ID,
  DEFAULT_CORRELATION_LOOKBACK_MS,
  DEFAULT_CORRELATION_WINDOW_MS,
  buildCorrelationCandidate,
  computeCorrelationCandidates,
  findKillSideAnchors,
  findQualifyingPeerObservations,
  rankAndSelectBestPeer,
} from "../src/incident-correlation.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-incident-correlation-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const DAY_MS = 24 * 60 * 60 * 1000;
const BASE_TS = Date.parse("2026-02-01T00:00:00.000Z");

function dayTs(offsetDays, hour = 0, minute = 0) {
  return new Date(BASE_TS + offsetDays * DAY_MS + hour * 60 * 60 * 1000 + minute * 60 * 1000).toISOString();
}

function peerPoint(ts, entityKey, { hourBucket = "02", sourceType = "wireguard" } = {}) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: entityKey,
    attributes: {
      source_type: sourceType,
      presence_state: "observed_active",
      login_hour_bucket: hourBucket,
      handshake_age_bucket: sourceType === "wireguard" ? "lt_1h" : "n/a",
    },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
  };
}

function overflowPoint(ts) {
  return {
    ts,
    fact_name: "peer.presence",
    entity_key: PEER_OVERFLOW_ENTITY_KEY,
    attributes: { overflow: "true", total_count_bucket: "1000+" },
    source_envelope_id: "vpn-peer-status",
    source_tool: "collect_vpn_peer_status",
    sensitivity: "operational",
    confidence: 0,
  };
}

// A "regular" contributor peer appearing on N consecutive days at a NON-odd hour: purely to
// establish stream-wide maturity (the must-fix 4 cold-start gate) without itself ever qualifying
// as odd-hour/novel. Returns one point per day in [startDay, endDay] inclusive.
function regularPeerPoints(entityKey, startDay, endDay) {
  const points = [];
  for (let day = startDay; day <= endDay; day += 1) points.push(peerPoint(dayTs(day, 12), entityKey, { hourBucket: "12", sourceType: "ssh" }));
  return points;
}

function killSideAlertRecord(ruleId, firstSeenTs, { severity = "critical", fingerprint = "global", status = "active" } = {}) {
  return {
    id: alertId(ruleId, fingerprint),
    rule_id: ruleId,
    fingerprint,
    status,
    severity,
    title: ruleId === SESSION_COUNT_DROP_RULE_ID ? "Session count deviation" : "Session churn detected",
    summary: "test fixture",
    evidence_refs: ["session-baseline"],
    first_seen: firstSeenTs,
    last_seen: firstSeenTs,
    diagnostics: {},
  };
}

async function seed(paths, { alerts = [], factPoints = [], now, learnedEnabled = true } = {}) {
  if (learnedEnabled) await writeLearnedConfig(paths, { enabled: true });
  if (alerts.length > 0) await writeAlertRecords(paths, alerts);
  if (factPoints.length > 0) await appendFactPoints(paths, factPoints, { now });
}

// ---------------------------------------------------------------------------------------------
// findKillSideAnchors: reads alert-HISTORY (any status), bounded lookback.
// ---------------------------------------------------------------------------------------------

test("findKillSideAnchors: session.count_drop/session.churn within lookback qualify regardless of status (active/recovered/acknowledged/suppressed)", () => {
  const now = dayTs(10);
  const records = [
    killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, dayTs(9, 12), { status: "active" }),
    killSideAlertRecord(SESSION_CHURN_RULE_ID, dayTs(9, 13), { status: "recovered", fingerprint: "session.tmux.aaaaaaaaaaaaaaaa" }),
    killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, dayTs(9, 14), { status: "acknowledged" }),
    killSideAlertRecord(SESSION_CHURN_RULE_ID, dayTs(9, 15), { status: "suppressed", fingerprint: "session.tmux.bbbbbbbbbbbbbbbb" }),
    { ...killSideAlertRecord("system.memory.sustained_high", dayTs(9, 16)), id: "alert_unrelated" }, // not a kill-side rule_id
  ];
  const anchors = findKillSideAnchors(records, { now, lookbackMs: DEFAULT_CORRELATION_LOOKBACK_MS });
  assert.equal(anchors.length, 4, "expected all four kill-side rows regardless of status, excluding the unrelated rule_id");
  assert.ok(anchors.every((a) => [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID].includes(a.rule_id)));
});

test("findKillSideAnchors: a kill-side alert older than the lookback window is excluded", () => {
  const now = dayTs(40);
  const records = [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, dayTs(0, 0))]; // 40 days old
  assert.deepEqual(findKillSideAnchors(records, { now, lookbackMs: DEFAULT_CORRELATION_LOOKBACK_MS }), []);
});

test("findKillSideAnchors: empty alert history yields zero anchors, no throw", () => {
  assert.deepEqual(findKillSideAnchors([], { now: dayTs(0) }), []);
});

// ---------------------------------------------------------------------------------------------
// computeCorrelationCandidates: full deterministic join, gated by learned.json.
// ---------------------------------------------------------------------------------------------

test("Slice 6: gated by learned.json BEFORE any I/O — disabled/default config short-circuits to [] without reading alerts/facts", async () => {
  const paths = await tempPaths();
  // learned.json intentionally never written -> loadLearnedConfig defaults to {enabled:false}.
  let readAlertsCalled = false;
  let readFactsCalled = false;
  const result = await computeCorrelationCandidates(paths, {
    now: dayTs(0),
    readAlertRecords: async (...args) => {
      readAlertsCalled = true;
      return readAlertRecords(...args);
    },
    readFactPoints: async (...args) => {
      readFactsCalled = true;
      return { points: [], corrupt_count: 0 };
    },
  });
  assert.deepEqual(result, []);
  assert.equal(readAlertsCalled, false, "readAlertRecords must never be called while learned.json is disabled");
  assert.equal(readFactsCalled, false, "readFactPoints must never be called while learned.json is disabled");
});

test("Slice 6 day-1 no-storm: empty alert-history and empty fact-history -> [], no throw", async () => {
  const paths = await tempPaths();
  await writeLearnedConfig(paths, { enabled: true });
  const result = await computeCorrelationCandidates(paths, { now: dayTs(0) });
  assert.deepEqual(result, []);
});

test("Slice 6 positive fixture (motivating incident shape): odd-hour, low-prior-tick peer within window of a session.count_drop anchor fires exactly one correlation candidate, with severity capped at warning even for a CRITICAL anchor", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs, { severity: "critical" })],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0), // establishes stream-wide maturity
      peerPoint(anchorTs, "peer.wireguard.9999999999999999", { hourBucket: "02", sourceType: "wireguard" }), // the rare/novel peer
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.equal(candidates.length, 1);
  const candidate = candidates[0];
  assert.equal(candidate.rule_id, CORRELATION_RULE_ID);
  assert.equal(candidate.severity, "warning", "stored severity must be capped at warning even though the anchor is critical");
  assert.equal(candidate.diagnostics.anchor_severity, "critical", "the anchor's real severity is preserved as a diagnostic");
  assert.equal(candidate.diagnostics.kill_rule_id, SESSION_COUNT_DROP_RULE_ID);
  assert.equal(candidate.diagnostics.peer_entity_key, "peer.wireguard.9999999999999999");
  assert.equal(candidate.diagnostics.peer_source_type, "wireguard");
  assert.equal(candidate.diagnostics.peer_observed_hour_bucket, "02");
  assert.equal(candidate.diagnostics.proximity_seconds, 0);
  assert.equal(candidate.diagnostics.peer_novelty_prior_tick_count, 0);
  assert.equal(candidate.diagnostics.candidate_pool_size, 1);

  // Candidate shape parity with the existing extraCandidates sources.
  for (const key of ["id", "rule_id", "fingerprint", "severity", "title", "summary", "diagnostics", "evidence_refs"]) {
    assert.ok(Object.hasOwn(candidate, key), `expected candidate to have key ${key}`);
  }

  // Every diagnostics field survives sanitizeDiagnostics unchanged (no redaction anywhere) —
  // proving the numeric/hash/closed-enum discipline holds by construction.
  for (const value of Object.values(candidate.diagnostics)) {
    assert.notEqual(value && typeof value === "object" && value.redacted, true, "no diagnostics field should be redacted");
  }
});

test("Slice 6 positive fixture, warning-anchor variant: severity stays capped at warning (proves the cap actually caps rather than coinciding with a warning fixture)", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs, { severity: "warning" })],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999"),
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].severity, "warning");
  assert.equal(candidates[0].diagnostics.anchor_severity, "warning");
});

test("Slice 6: a session.churn anchor also correlates, with its own entity-hash fingerprint carried through", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_CHURN_RULE_ID, anchorTs, { severity: "warning", fingerprint: "session.tmux.aaaaaaaaaaaaaaaa" })],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999"),
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].diagnostics.kill_rule_id, SESSION_CHURN_RULE_ID);
  assert.equal(candidates[0].diagnostics.anchor_fingerprint, "session.tmux.aaaaaaaaaaaaaaaa");
  assert.equal(candidates[0].fingerprint, "session.tmux.aaaaaaaaaaaaaaaa__peer.wireguard.9999999999999999");
});

test("Slice 6 distant-in-time non-fire: a peer observation outside DEFAULT_CORRELATION_WINDOW_MS of the anchor does not correlate", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(1, 2);
  const now = dayTs(1, 3); // keeps the anchor comfortably within the 24h lookback bound
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 1),
      peerPoint(dayTs(0, 3), "peer.wireguard.9999999999999999"), // ~23h before the anchor, far outside the 3h window
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, []);
});

test("Slice 6 not-odd-hour non-fire: an in-window, low-novelty peer whose login_hour_bucket is not in CORRELATION_ODD_HOURS does not correlate", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999", { hourBucket: "14" }), // ordinary daytime hour
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, []);
});

test("Slice 6 must-fix 6: login_hour_bucket === 'unknown' never qualifies as odd-hour", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999", { hourBucket: "unknown" }),
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, []);
  assert.equal(CORRELATION_ODD_HOURS.has("unknown"), false);
});

test("Slice 6 not-novel non-fire: a peer with many prior ticks (> CORRELATION_NOVELTY_MAX_PRIOR_TICKS) does not correlate even when in-window and odd-hour", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(10, 2);
  const now = dayTs(10, 3);
  const points = [];
  for (let day = 0; day <= 10; day += 1) points.push(peerPoint(dayTs(day, 2), "peer.wireguard.9999999999999999", { hourBucket: "02" }));
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: points,
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, []);
});

test("Slice 6 must-fix 4 week-1 cold-start no-fire: an otherwise-fully-qualifying pair does not correlate when the peer.presence stream as a whole is too young (fewer tick-groups/days than the minimum)", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    // Only ONE distinct tick-group exists in the entire fact-history window — well under
    // CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS/_DAYS, even though this specific observation is
    // itself odd-hour/in-window/zero-prior-ticks (otherwise fully qualifying).
    factPoints: [peerPoint(anchorTs, "peer.wireguard.9999999999999999", { hourBucket: "02" })],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, [], "a young peer.presence stream must gate out every peer, not just the flagged one");
});

test("Slice 6 must-fix 5 overflow-degraded-window no-fire: an otherwise-fully-qualifying pair does not correlate when the read window also contains an overflow-marker tick", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999"),
      overflowPoint(dayTs(-1, 0)), // a single overflow tick anywhere in the window degrades the whole window
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, []);
});

test("Slice 6 ranking/pool-size fixture: two qualifying peers for the same anchor -> exactly one candidate (closest wins), candidate_pool_size reflects the true qualifying count", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2, 0);
  const now = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(dayTs(0, 2, 30), "peer.wireguard.aaaaaaaaaaaaaaaa"), // 30 min after the anchor
      peerPoint(dayTs(0, 2, 5), "peer.wireguard.bbbbbbbbbbbbbbbb"), // 5 min after the anchor — closer
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].diagnostics.peer_entity_key, "peer.wireguard.bbbbbbbbbbbbbbbb", "the closest-in-time qualifying peer must win");
  assert.equal(candidates[0].diagnostics.candidate_pool_size, 2);
});

test("Slice 6 ranking tie-break: equal deltas are broken by lexicographically-smaller entity_key, for determinism", () => {
  const ts = dayTs(0, 2);
  const qualifying = [
    { point: { entity_key: "peer.wireguard.zzzzzzzzzzzzzzzz", ts, attributes: { source_type: "wireguard", login_hour_bucket: "02" } }, delta_ms: 1000, prior_tick_count: 0 },
    { point: { entity_key: "peer.wireguard.aaaaaaaaaaaaaaaa", ts, attributes: { source_type: "wireguard", login_hour_bucket: "02" } }, delta_ms: 1000, prior_tick_count: 0 },
  ];
  const ranked = rankAndSelectBestPeer(qualifying);
  assert.equal(ranked.poolSize, 2);
  assert.equal(ranked.best.point.entity_key, "peer.wireguard.aaaaaaaaaaaaaaaa");
});

test("rankAndSelectBestPeer returns undefined for an empty qualifying array", () => {
  assert.equal(rankAndSelectBestPeer([]), undefined);
  assert.equal(rankAndSelectBestPeer(), undefined);
});

test("Slice 6 lookback-bound / old-history no-storm: several weeks of old, otherwise-qualifying anchor+peer pairs entirely outside DEFAULT_CORRELATION_LOOKBACK_MS fire ZERO candidates on the first call", async () => {
  const paths = await tempPaths();
  const now = dayTs(60);
  const oldAnchorTs = dayTs(10, 2); // 50 days before "now" — well outside the 24h lookback
  await seed(paths, {
    alerts: [
      killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, oldAnchorTs),
      killSideAlertRecord(SESSION_CHURN_RULE_ID, dayTs(20, 3), { fingerprint: "session.tmux.cccccccccccccccc" }),
    ],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", 7, 20),
      peerPoint(oldAnchorTs, "peer.wireguard.9999999999999999"),
      peerPoint(dayTs(20, 3), "peer.wireguard.8888888888888888"),
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.deepEqual(candidates, [], "anchors weeks outside the lookback bound must not fire on the very first call");
});

test("Slice 6 recovery: a candidate that fired on tick N is absent on tick N+1 once its anchor ages past the lookback, and applyAlertCandidates marks it recovered via the existing, unmodified recovery path", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const nowTick1 = dayTs(0, 3);
  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.wireguard.9999999999999999"),
    ],
    now: nowTick1,
  });

  const tick1Candidates = await computeCorrelationCandidates(paths, { now: nowTick1 });
  assert.equal(tick1Candidates.length, 1);

  const existingAlerts = await readAlertRecords(paths);
  const applied1 = applyAlertCandidates(existingAlerts, [...existingAlerts.filter((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID), ...tick1Candidates], { now: nowTick1 });
  await writeAlertRecords(paths, applied1.alerts);

  const correlationAlertId = tick1Candidates[0].id;
  const afterTick1 = (await readAlertRecords(paths)).find((a) => a.id === correlationAlertId);
  assert.equal(afterTick1.status, "active");

  // Tick N+1: far enough past the anchor's first_seen that the 24h lookback has expired.
  const nowTick2 = dayTs(2, 0);
  const tick2Candidates = await computeCorrelationCandidates(paths, { now: nowTick2 });
  assert.deepEqual(tick2Candidates, [], "the anchor has aged out of the lookback bound; the join must not re-derive the candidate");

  const existingAlerts2 = await readAlertRecords(paths);
  const applied2 = applyAlertCandidates(existingAlerts2, [...existingAlerts2.filter((a) => a.rule_id === SESSION_COUNT_DROP_RULE_ID), ...tick2Candidates], { now: nowTick2 });
  await writeAlertRecords(paths, applied2.alerts);

  const afterTick2 = (await readAlertRecords(paths)).find((a) => a.id === correlationAlertId);
  assert.equal(afterTick2.status, "recovered", "applyAlertCandidates must recover the correlation alert once it is absent from the candidate array, with no new code required");
});

// ---------------------------------------------------------------------------------------------
// MUST-FIX 2: title/summary closed-form templates — no raw session name/peer host/IP/free-text.
// ---------------------------------------------------------------------------------------------

test("Slice 6 must-fix 2 (schema-pinned, strengthened per adversarial review): EVERY correlation candidate diagnostic + title/summary is a hash / integer / closed-enum — there is no free-form field a raw identifier could ride on", async () => {
  const paths = await tempPaths();
  const anchorTs = dayTs(0, 2);
  const now = dayTs(0, 3);

  await seed(paths, {
    alerts: [killSideAlertRecord(SESSION_COUNT_DROP_RULE_ID, anchorTs)],
    factPoints: [
      ...regularPeerPoints("peer.ssh.1111111111111111", -3, 0),
      peerPoint(anchorTs, "peer.ssh.9999999999999999", { sourceType: "ssh" }),
    ],
    now,
  });

  const candidates = await computeCorrelationCandidates(paths, { now });
  assert.equal(candidates.length, 1);
  const { title, summary, diagnostics } = candidates[0];

  // The real control is upstream hash-at-source (the fact translators hash every entity_key /
  // fingerprint before it ever reaches this module); sanitizeDiagnostics is only a charset
  // backstop and would NOT catch a charset-safe raw hostname/IP (see compactAlert's SCOPE note).
  // So the property that actually keeps a raw identifier out of the prompt is that the candidate
  // has NO free-form field at all — every field is a hash, an integer, or a closed-enum. Pin that
  // per-field, rather than asserting on unused string literals (which proved nothing).
  const HEX16 = /^[0-9a-f]{16}$/;
  const HOUR = /^([01][0-9]|2[0-3]|unknown)$/;
  assert.match(diagnostics.kill_rule_id, /^session\.(count_drop|churn)$/);
  assert.ok(diagnostics.anchor_fingerprint === "global" || HEX16.test(diagnostics.anchor_fingerprint),
    `anchor_fingerprint must be "global" or a 16-hex hash, got ${diagnostics.anchor_fingerprint}`);
  assert.match(diagnostics.peer_entity_key, /^peer\.[a-z_]+\.[0-9a-f]{16}$/);
  assert.ok(["wireguard", "ssh", "vpn_service", "unknown"].includes(diagnostics.peer_source_type));
  assert.match(diagnostics.peer_observed_hour_bucket, HOUR);
  assert.ok(Number.isInteger(diagnostics.proximity_seconds));
  assert.ok(Number.isInteger(diagnostics.peer_novelty_prior_tick_count));
  assert.ok(Number.isInteger(diagnostics.candidate_pool_size));
  assert.ok(["info", "warning", "critical"].includes(diagnostics.anchor_severity));
  // No unexpected free-form field crept in: exactly this closed key set.
  assert.deepEqual(Object.keys(diagnostics).sort(), [
    "anchor_fingerprint", "anchor_severity", "candidate_pool_size", "kill_rule_id",
    "peer_entity_key", "peer_novelty_prior_tick_count", "peer_observed_hour_bucket",
    "peer_source_type", "proximity_seconds",
  ]);
  // title/summary are closed-form templates over the same safe values only.
  assert.match(title, /^[A-Za-z0-9 ._-]+$/);
  assert.match(summary, /^[A-Za-z0-9 ():;,._-]+$/);
});

// ---------------------------------------------------------------------------------------------
// buildCorrelationCandidate: unit-level shape/severity-cap checks.
// ---------------------------------------------------------------------------------------------

test("buildCorrelationCandidate: severity is unconditionally 'warning' regardless of anchor.severity", () => {
  const anchor = { rule_id: SESSION_COUNT_DROP_RULE_ID, fingerprint: "global", severity: "critical", first_seen_ms: Date.now() };
  const bestPeer = {
    point: { entity_key: "peer.wireguard.9999999999999999", attributes: { source_type: "wireguard", login_hour_bucket: "02" } },
    delta_ms: 1000,
    prior_tick_count: 0,
  };
  const candidate = buildCorrelationCandidate(anchor, bestPeer, 1);
  assert.equal(candidate.severity, "warning");
  assert.equal(candidate.diagnostics.anchor_severity, "critical");
  assert.equal(candidate.rule_id, CORRELATION_RULE_ID);
  assert.equal(candidate.id, alertId(CORRELATION_RULE_ID, `global__peer.wireguard.9999999999999999`));
});

// ---------------------------------------------------------------------------------------------
// Constant sanity (Decision 1/6): confirms the documented defaults/reuse.
// ---------------------------------------------------------------------------------------------

test("DEFAULT_CORRELATION_WINDOW_MS reuses peer-signature-store.js's own DEFAULT_PEER_PRESENCE_WINDOW_MS value (3h) for consistency", () => {
  assert.equal(DEFAULT_CORRELATION_WINDOW_MS, 3 * 60 * 60 * 1000);
});

test("DEFAULT_CORRELATION_LOOKBACK_MS is 24h", () => {
  assert.equal(DEFAULT_CORRELATION_LOOKBACK_MS, 24 * 60 * 60 * 1000);
});

test("CORRELATION_ODD_HOURS is exactly {00..05}", () => {
  assert.deepEqual([...CORRELATION_ODD_HOURS].sort(), ["00", "01", "02", "03", "04", "05"]);
});

test("findQualifyingPeerObservations returns [] for an anchor with no finite first_seen_ms (defensive)", () => {
  assert.deepEqual(findQualifyingPeerObservations([peerPoint(dayTs(0), "peer.wireguard.9999999999999999")], undefined), []);
  assert.deepEqual(findQualifyingPeerObservations([peerPoint(dayTs(0), "peer.wireguard.9999999999999999")], { first_seen_ms: NaN }), []);
});

test("CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS/_DAYS/NOVELTY_MAX_PRIOR_TICKS are positive finite defaults", () => {
  assert.ok(Number.isFinite(CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS) && CORRELATION_MIN_PEER_HISTORY_TICK_GROUPS > 0);
  assert.ok(Number.isFinite(CORRELATION_MIN_PEER_HISTORY_DAYS) && CORRELATION_MIN_PEER_HISTORY_DAYS > 0);
  assert.ok(Number.isFinite(CORRELATION_NOVELTY_MAX_PRIOR_TICKS) && CORRELATION_NOVELTY_MAX_PRIOR_TICKS >= 0);
});
