// Context plan C2 (docs/plans/2026-10-06-context-aware-learned-baselines.md §4, §8.1, §8.2; I50, I68,
// I70; open item 20): tick_summary, its chain and certification, context transitions, created_vs_boot,
// host.daemon_gap and the long-lived statistics skeleton. DATA ONLY.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { CONTEXT_KEY_BYTES, contextHmac, contextKeyId } from "../src/context-key.js";
import { CONTEXT_FACT_SCHEMAS, unableContextAttributes, validateContextFact } from "../src/context-schemas.js";
import { appendFactPoints, MAX_FACT_ATTRIBUTE_COUNT, normalizeFactPoint, readFactPoints } from "../src/fact-store.js";
import { readFactIntegrityLedger } from "../src/fact-store-integrity.js";
import { FAMILY_TICK_SHAPES, FACT_FAMILY_BY_NAME } from "../src/fact-families.js";
import { factPointsFromSessionEvidence, factPointsFromVpnPeerEvidence, hashSessionIdentity } from "../src/fact-translators.js";
import { emptyDaemonGap, observeBootProbe } from "../src/boot-ledger.js";
import {
  certifySourcePasses,
  deriveContextTransitions,
  deriveCreatedVsBoot,
  deriveStats,
  deriveTickSummary,
  extractTickSnapshot,
  factPointsFromDaemonGap,
  isValidSummaryChainState,
  readStatsState,
  readSummaryChainState,
  TICK_SUMMARY_MAX_RECORD_BYTES,
  tickSummaryDigest,
  verifyTickSummaryChain,
  wallCrossCheck,
  writeStatsState,
  writeSummaryChainState,
} from "../src/context-summary.js";

const KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 9);
const T0 = Date.parse("2026-10-11T10:00:00.000Z");
const HOUR = 3_600_000;

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-c2-summary-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

// One structural tick's evidence: tmux sessions (name -> created second), VPN peers, a host-lifecycle
// read (clocks), with the real incumbent translators producing the session/peer points.
function tick({ ms, sessions = {}, peers = [], wallMs, uptimeMs, bootId = "11111111-2222-3333-4444-555555555555", bootTimeS = 1_000_000, tz = "Europe/Paris", offset = 120, wake = 0 }) {
  const ts = new Date(ms).toISOString();
  const evidence = [
    { id: "sessions", status: "ok", trace: { tool: "collect_sessions" }, observation: { start_ms: ms + 100, end_ms: ms + 200 }, result: {
      multiplexers: [{ multiplexer: "tmux", status: "ok" }, { multiplexer: "screen", status: "not_found_on_known_paths" }],
      sessions: Object.entries(sessions).map(([name, created]) => ({ multiplexer: "tmux", session_name: name, window_count: 1, attached: false, created_at_epoch_seconds: created })),
    } },
    { id: "vpn-peer-status", status: "ok", trace: { tool: "collect_vpn_peer_status" }, observation: { start_ms: ms + 200, end_ms: ms + 300 }, result: {
      sources: Object.fromEntries(["ssh_who", "ssh_last", "wireguard", "vpn_services", "established_inbound"].map((k) => [k, { status: "ok" }])),
      peers: peers.map((host) => ({ source_type: "ssh", presence_state: "observed_active", remote_user: "u", remote_host: host, origin: "who" })),
      census_status: "ok", truncated: false,
    } },
    { id: "host-lifecycle", status: "ok", observation: { start_ms: ms + 400, end_ms: ms + 500 }, result: {
      platform: "darwin", status: "ok", boot: { boot_id: bootId, boot_time_s: bootTimeS },
      clocks: { wall_ms: wallMs ?? ms + 450, os_uptime_ms: uptimeMs, uv_hrtime_ns: "123456789", kern_monotonicclock_usecs: "1 2", kern_waketime_s: wake, machdep_wake_abstime: "0", machdep_wake_conttime: "0", tz_id: tz, utc_offset_min: offset },
    } },
  ];
  const points = [...factPointsFromSessionEvidence(evidence, { ts }), ...factPointsFromVpnPeerEvidence(evidence, { ts })];
  return { ts, ms, evidence, points };
}

function snapshotOf(t, hostFacts = {}) {
  return extractTickSnapshot({ evidence: t.evidence, points: t.points, hostFacts, ts: t.ts, hmacKey: KEY });
}

// Runs the pure summary derivation for consecutive ticks, threading the chain state as the daemon does.
function chainTicks(ticks) {
  let prior = { status: "missing" };
  const out = [];
  for (const [index, t] of ticks.entries()) {
    const snapshot = snapshotOf(t, t.hostFacts);
    const transitions = deriveContextTransitions(prior.status === "valid" ? prior.state : undefined, snapshot);
    const summary = deriveTickSummary({ snapshot, prior, storeHadSummaries: index > 0, transitions, hmacKey: KEY, version: "0.0.50", cfg: "0123456789abcdef", certification: { cert: "certified", certd: "fedcba9876543210" } });
    out.push({ snapshot, transitions, summary });
    prior = { status: "valid", state: summary.nextState("gen", index + 1) };
  }
  return out;
}

test("C2 tick_summary T8: the worst-case record is at most 1 KiB (pinned), carries no entity key, and stays under the attribute cap", () => {
  const schema = CONTEXT_FACT_SCHEMAS.get("tick.summary");
  const attributes = {};
  for (const [field, spec] of Object.entries(schema.fields)) {
    if (field === "rejected_field") continue;
    const candidates = spec.kind === "enum" ? [...spec.values] : [...spec.sentinels];
    if (spec.kind === "hmac") candidates.push("f".repeat(16));
    if (spec.kind === "int") candidates.push(String(spec.max));
    if (spec.kind === "pattern") candidates.push("9".repeat(spec.maxLength));
    attributes[field] = candidates.sort((a, b) => b.length - a.length)[0];
  }
  const size = (attrs) => {
    const record = normalizeFactPoint({ ts: "2026-10-11T00:00:00.000Z", fact_name: "x".repeat(12), entity_key: "tick.summary", attributes: attrs });
    record.fact_name = "tick.summary";
    return Buffer.byteLength(`${JSON.stringify(record)}\n`);
  };
  const longestField = Object.keys(schema.fields).sort((a, b) => b.length - a.length)[0];
  const worst = Math.max(size(attributes), size(unableContextAttributes("tick.summary", { rejectedField: longestField })));
  assert.equal(worst, 1013, "a schema change must revisit the tick_summary record bound");
  assert.ok(worst <= TICK_SUMMARY_MAX_RECORD_BYTES);
  assert.equal(FAMILY_TICK_SHAPES.get("tick_summary").worstTickBytes, worst);
  assert.ok(Object.keys(schema.fields).length <= MAX_FACT_ATTRIBUTE_COUNT);
  assert.equal(FACT_FAMILY_BY_NAME.get("tick.summary"), "tick_summary");
  const [{ summary }] = chainTicks([tick({ ms: T0, sessions: { work: 1_000_100 }, uptimeMs: 50_000_000 })]);
  assert.equal(summary.point.entity_key, "tick.summary");
  assert.deepEqual(validateContextFact("tick.summary", summary.point.attributes), { ok: true });
  assert.ok(Buffer.byteLength(`${JSON.stringify(normalizeFactPoint(summary.point))}\n`) <= TICK_SUMMARY_MAX_RECORD_BYTES);
  assert.ok(!JSON.stringify(summary.point).includes("session.tmux."), "no entity keys in a summary record");
});

test("summary_chain_no_double_count: departures and arrivals for (r_{i-1}, r_i] are computed once, against the immediately preceding record", () => {
  const ticks = chainTicks([
    tick({ ms: T0, sessions: { a: 1, b: 2 }, peers: ["h1"], uptimeMs: 10_000_000 }),
    tick({ ms: T0 + HOUR, sessions: { a: 1, c: 3 }, peers: ["h1", "h2"], uptimeMs: 10_000_000 + HOUR }),
    tick({ ms: T0 + 2 * HOUR, sessions: { a: 1, c: 3 }, peers: ["h2"], uptimeMs: 10_000_000 + 2 * HOUR }),
    // Same name, new creation second: a recreation is one departure and one arrival.
    tick({ ms: T0 + 3 * HOUR, sessions: { a: 99, c: 3 }, peers: ["h2"], uptimeMs: 10_000_000 + 3 * HOUR }),
  ]);
  const attrs = ticks.map(({ summary }) => summary.point.attributes);
  assert.deepEqual(attrs.map((a) => [a.sa, a.sd, a.pa, a.pd]), [
    ["unknown", "unknown", "unknown", "unknown"],
    ["1", "1", "1", "0"],
    ["0", "0", "0", "1"],
    ["1", "1", "0", "0"],
  ]);
  assert.deepEqual(attrs.map((a) => a.chain), ["started", "continued", "continued", "continued"]);
  assert.equal(attrs[1].prev, ticks[0].summary.digest);
  assert.equal(attrs[0].prev, "none");
  assert.deepEqual(attrs.map((a) => a.sn), ["2", "2", "2", "2"]);
  assert.equal(attrs[0].scs, "c");
});

test("C2 review H1: an OS VPN service is VPN context, never a peer in the summary's peer population (no target leakage)", () => {
  const withService = (ms, connected) => {
    const t = tick({ ms, peers: ["h1"], uptimeMs: 1000 + ms - T0 });
    t.evidence[1].result.peers.push({ source_type: "vpn_service", presence_state: connected ? "observed_active" : "observed_historical", service_uuid: "AAAA-BBBB", service_name: "Work VPN" });
    t.points = [...factPointsFromSessionEvidence(t.evidence, { ts: t.ts }), ...factPointsFromVpnPeerEvidence(t.evidence, { ts: t.ts })];
    return t;
  };
  const [off, on] = chainTicks([withService(T0, false), withService(T0 + HOUR, true)]);
  assert.equal(off.snapshot.peer.count, 1);
  assert.equal(on.snapshot.peer.count, 1, "a connected VPN service is not a peer");
  assert.ok(![...on.snapshot.peer.entities.keys()].some((key) => key.startsWith("peer.vpn_service.")));
  const attrs = on.summary.point.attributes;
  assert.deepEqual([attrs.pn, attrs.pa, attrs.pd], ["1", "0", "0"], "connecting a VPN is no peer arrival");
});

test("C2 review M6: the peer fields' provenance names every object their value or knownness depends on (I5 input)", () => {
  const tags = (name, field) => [...CONTEXT_FACT_SCHEMAS.get(name).fields[field].provenance].sort();
  // Values: the peer objects themselves (who/last rows, the WireGuard peer table).
  const values = ["login.utmp", "net.wireguard"];
  // Knownness and universe: every source in the incumbent availability signature and census status.
  const knownness = ["login.utmp", "net.socket_table", "net.wireguard", "vpn.service_config"];
  for (const field of ["pn", "pa", "pd", "ps"]) assert.deepEqual(tags("tick.summary", field), values, field);
  for (const field of ["pcs", "pu"]) assert.deepEqual(tags("tick.summary", field), knownness, field);
  for (const stat of ["pre", "post", "same", "recr", "dep", "arr"]) assert.deepEqual(tags("stats.episode", `p_${stat}`), values, stat);
  for (const field of ["p_arr", "p_dep"]) assert.deepEqual(tags("stats.daily", field), values, field);
  assert.deepEqual(tags("stats.daily", "p_known"), knownness);
});

test("summary_chain_broken_unknown: a missing or invalid chain state makes the interval's transitions unknown, never zero, and the chain restarted", () => {
  const t = tick({ ms: T0, sessions: { a: 1 }, uptimeMs: 1000 });
  const snapshot = snapshotOf(t);
  for (const prior of [{ status: "missing" }, { status: "invalid" }, { status: "lineage_mismatch" }, { status: "key_changed" }]) {
    const summary = deriveTickSummary({ snapshot, prior, storeHadSummaries: true, lastSeq: 41, transitions: deriveContextTransitions(undefined, snapshot), hmacKey: KEY, version: "0.0.50", cfg: "unknown" });
    assert.equal(summary.point.attributes.chain, "restarted", prior.status);
    assert.equal(summary.point.attributes.prev, "unknown");
    assert.equal(summary.point.attributes.seq, "42", "seq keeps increasing across a restart");
    assert.equal(summary.point.attributes.sa, "unknown");
    assert.equal(summary.point.attributes.sd, "unknown");
    assert.equal(summary.point.attributes.ev, "unknown", "no previous context: events unknown, never none");
  }
  // A universe change (a multiplexer moved aside) is a different census: unknown, never a departure count.
  const [first] = chainTicks([tick({ ms: T0, sessions: { a: 1 }, uptimeMs: 1 })]);
  const moved = tick({ ms: T0 + HOUR, sessions: {}, uptimeMs: 2 });
  moved.evidence[0].result.multiplexers = [{ multiplexer: "tmux", status: "not_found_on_known_paths" }, { multiplexer: "screen", status: "ok" }];
  moved.points = factPointsFromSessionEvidence(moved.evidence, { ts: moved.ts });
  const next = deriveTickSummary({ snapshot: snapshotOf(moved), prior: { status: "valid", state: first.summary.nextState("g", 1) }, storeHadSummaries: true, transitions: { transitions: [], events: "-" }, hmacKey: KEY });
  assert.equal(next.point.attributes.sd, "unknown");
});

test("l1_clock_step_detected and l1_no_false_step_on_suspend: a wall step against the uptime delta is a clock_step transition; a suspend (both clocks advance) is not", () => {
  const base = { sessions: { a: 1 } };
  const [first] = chainTicks([tick({ ms: T0, ...base, wallMs: T0, uptimeMs: 5_000_000 })]);
  const prev = first.summary.nextState("g", 1);
  // A forward wall step of ~59 minutes (the uptime advanced 60 s).
  const stepped = snapshotOf(tick({ ms: T0 + HOUR, ...base, wallMs: T0 + HOUR, uptimeMs: 5_060_000 }));
  const step = deriveContextTransitions(prev, stepped);
  const clock = step.transitions.find((t) => t.dimension === "clock_step");
  assert.ok(clock, "l1_clock_step_detected");
  assert.equal(clock.new_value, "forward");
  assert.equal(clock.magnitude, "1m_1h");
  assert.equal(clock.semantics, "clock_semantics_unverified");
  assert.equal(step.events, "c");
  // An 8-hour suspend: wall and uptime (which includes suspended time) both advance by 8 h.
  const suspended = snapshotOf(tick({ ms: T0 + 8 * HOUR, ...base, wallMs: T0 + 8 * HOUR + 1500, uptimeMs: 5_000_000 + 8 * HOUR }));
  const noStep = deriveContextTransitions(prev, suspended);
  assert.equal(noStep.transitions.length, 0, "l1_no_false_step_on_suspend");
  assert.equal(noStep.events, "-");
  assert.equal(wallCrossCheck(prev.context, suspended).code, "c");
  // Across a boot no clock delta is taken (F2): unknown, never a step.
  const rebooted = snapshotOf(tick({ ms: T0 + HOUR, ...base, wallMs: T0 + 10 * HOUR, uptimeMs: 10_000, bootId: "99999999-2222-3333-4444-555555555555" }));
  assert.equal(wallCrossCheck(prev.context, rebooted).code, "u");
  assert.ok(!deriveContextTransitions(prev, rebooted).transitions.some((t) => t.dimension === "clock_step"));
  assert.ok(deriveContextTransitions(prev, rebooted).transitions.some((t) => t.dimension === "boot"));
});

test("C2 context.transition: old/new with the interval (previous observation, this observation]; only between two known readings", () => {
  const [first] = chainTicks([tick({ ms: T0, uptimeMs: 1000 })]);
  const prev = first.summary.nextState("g", 1);
  const next = tick({ ms: T0 + HOUR, uptimeMs: 1000 + HOUR, tz: "America/New_York", offset: -240 });
  const { transitions, events } = deriveContextTransitions(prev, snapshotOf(next));
  assert.deepEqual(transitions.map((t) => t.dimension), ["timezone", "utc_offset"]);
  const offset = transitions.find((t) => t.dimension === "utc_offset");
  assert.deepEqual([offset.old_value, offset.new_value], ["120", "-240"]);
  assert.equal(offset.interval_start_ms, T0 + 500);
  assert.equal(offset.interval_end_ms, T0 + HOUR + 500);
  assert.equal(events, "zo");
  const timezone = transitions.find((t) => t.dimension === "timezone");
  assert.equal(timezone.new_value, contextHmac(KEY, "timezone_id", "America/New_York"), "the timezone id is HMAC'd, never raw");
  // An unknown reading on either side is no transition (the context is unknown, not changed).
  const unknownTz = tick({ ms: T0 + HOUR, uptimeMs: 1000 + HOUR, tz: undefined, offset: undefined });
  assert.equal(deriveContextTransitions(prev, snapshotOf(unknownTz)).transitions.length, 0);
});

test("summary_suspend_bounds_recomputable: the raw clock readings and boot id kept in consecutive records recompute the exposure bound", () => {
  const ticks = chainTicks([
    tick({ ms: T0, uptimeMs: 7_000_000 }),
    Object.assign(tick({ ms: T0 + HOUR, uptimeMs: 7_000_000 + HOUR }), { hostFacts: { suspend: { interval_basis: "same_boot_uptime_delta", exposure_upper_s: Math.ceil(HOUR / 1000) + 2 } } }),
  ]);
  const [a, b] = ticks.map(({ summary }) => summary.point.attributes);
  assert.equal(a.boot, b.boot, "the boot id HMAC is in every record");
  for (const field of ["upm", "hr", "mono", "wab", "wct", "wak", "wo"]) assert.notEqual(b[field], "unknown", field);
  const recomputed = Math.ceil((Number(b.upm) - Number(a.upm)) / 1000) + 2;
  assert.equal(b.ex, `0-${recomputed}`);
  assert.equal(b.exb, "ud", "macOS: the uptime delta is now - kern.boottime (wall-derived), labelled so");
  assert.equal(b.wx, "c", "wall time only as a cross-check");
});

test("summary_valid_after_source_byte_eviction and summary_own_chain_break_is_loss (I70)", async () => {
  const paths = await tempPaths();
  const ticks = chainTicks([0, 1, 2, 3].map((i) => tick({ ms: T0 + i * HOUR, sessions: { a: 1 }, uptimeMs: 1000 + i * HOUR })));
  for (const [i, { summary }] of ticks.entries()) {
    // The source family is appended, then byte-evicted hard (a budget smaller than one tick).
    await appendFactPoints(paths, tick({ ms: T0 + i * HOUR, sessions: { a: 1 } }).points.filter((p) => p.fact_name === "session.presence"), { family: "session", now: new Date(T0 + i * HOUR).toISOString(), maxBytes: 10 });
    await appendFactPoints(paths, [summary.point], { family: "tick_summary", now: new Date(T0 + i * HOUR).toISOString() });
  }
  const sessionRead = await readFactPoints(paths, { family: "session", now: new Date(T0 + 4 * HOUR).toISOString() });
  assert.equal(sessionRead.points.length, 0, "the source facts are gone (intentional byte eviction)");
  const read = await readFactPoints(paths, { family: "tick_summary", now: new Date(T0 + 4 * HOUR).toISOString() });
  assert.equal(read.points.length, 4);
  assert.deepEqual(verifyTickSummaryChain(read.points).losses, [], "summary_valid_after_source_byte_eviction");
  // Remove a middle record: a break in the summary's own chain is loss, never silence.
  const broken = read.points.filter((_, i) => i !== 1);
  assert.deepEqual(verifyTickSummaryChain(broken).losses.map((l) => l.reason), ["prev_mismatch"], "summary_own_chain_break_is_loss");
  // Edit a record's content: its digest no longer matches the next record's prev.
  const edited = read.points.map((p, i) => (i === 1 ? { ...p, attributes: { ...p.attributes, sn: "7" } } : p));
  assert.deepEqual(verifyTickSummaryChain(edited).losses.map((l) => l.reason), ["prev_mismatch"]);
  // Age eviction of the oldest summaries is not loss: the first retained record's predecessor is gone on purpose.
  assert.deepEqual(verifyTickSummaryChain(read.points.slice(2)).losses, []);
  assert.equal(tickSummaryDigest(read.points[0]), ticks[0].summary.digest, "the digest is recomputable from the stored record");
});

test("C2 chain state: ledger-stamped like a seen-set; a mismatched pass, a pending pass, another key or any shape error is not valid", async () => {
  const paths = await tempPaths();
  const [{ summary }] = chainTicks([tick({ ms: T0, sessions: { a: 1 }, uptimeMs: 1 })]);
  const appended = await appendFactPoints(paths, [summary.point], { family: "tick_summary", now: new Date(T0).toISOString() });
  const state = summary.nextState(appended.retention.ledger_generation, appended.retention.pass_id);
  assert.ok(isValidSummaryChainState(state));
  await writeSummaryChainState(paths, state);
  const { ledger } = await readFactIntegrityLedger(paths, "tick_summary");
  assert.equal((await readSummaryChainState(paths, { ledger, hmacKeyId: contextKeyId(KEY) })).status, "valid");
  assert.equal((await readSummaryChainState(paths, { ledger, hmacKeyId: "0000000000000000" })).status, "key_changed");
  await appendFactPoints(paths, [], { family: "tick_summary", now: new Date(T0 + 1).toISOString() });
  const { ledger: advanced } = await readFactIntegrityLedger(paths, "tick_summary");
  assert.equal((await readSummaryChainState(paths, { ledger: advanced, hmacKeyId: contextKeyId(KEY) })).status, "lineage_mismatch");
  assert.equal((await readSummaryChainState(paths, { ledger: undefined, hmacKeyId: contextKeyId(KEY) })).status, "no_ledger");
  assert.ok(!isValidSummaryChainState({ ...state, extra: 1 }));
  assert.ok(!isValidSummaryChainState({ ...state, session: { ...state.session, entities: [["k", "x"], ["k", "x"]] } }));
  assert.ok(!isValidSummaryChainState({ ...state, seq: -1 }));
  await assert.rejects(writeSummaryChainState(paths, { ...state, seq: "1" }));
  await fs.writeFile(path.join(paths.stateDir, "learned", "facts", "tick_summary", "chain-state.json"), "{not json");
  assert.equal((await readSummaryChainState(paths, { ledger: advanced, hmacKeyId: contextKeyId(KEY) })).status, "invalid");
});

test("C2 certification at derivation (I70): every contributing family's committed pass must be the ledger's and the tick inside its span", () => {
  const ok = (generation, passId) => ({ retention: { ledger_generation: generation, pass_id: passId } });
  const ledger = (generation, passId, extra = {}) => ({ generation, continuity: { last_committed_pass_id: passId, continuity_ok: true }, bytecap_floor_ts: null, age_floor_ts: null, ...extra });
  const contributed = new Set(["session", "host_lifecycle"]);
  const certified = certifySourcePasses({ familyResults: { session: ok("g1", 4), host_lifecycle: ok("g2", 9) }, ledgers: { session: ledger("g1", 4), host_lifecycle: ledger("g2", 9) }, contributed, tsMs: T0 });
  assert.equal(certified.cert, "certified");
  assert.match(certified.certd, /^[0-9a-f]{16}$/);
  assert.equal(certified.families.peer.verdict, "not_contributing");
  const mismatch = certifySourcePasses({ familyResults: { session: ok("g1", 4), host_lifecycle: ok("g2", 9) }, ledgers: { session: ledger("g1", 5), host_lifecycle: ledger("g2", 9) }, contributed, tsMs: T0 });
  assert.equal(mismatch.cert, "uncertified");
  assert.equal(mismatch.families.session.verdict, "ledger_mismatch");
  assert.notEqual(mismatch.certd, certified.certd, "the digest commits to every cited pass");
  const outside = certifySourcePasses({ familyResults: { session: ok("g1", 4), host_lifecycle: ok("g2", 9) }, ledgers: { session: ledger("g1", 4, { bytecap_floor_ts: new Date(T0).toISOString() }), host_lifecycle: ledger("g2", 9) }, contributed, tsMs: T0 });
  assert.equal(outside.families.session.verdict, "outside_certified_span");
  const failed = certifySourcePasses({ familyResults: { session: { append_error: "x" }, host_lifecycle: ok("g2", 9) }, ledgers: {}, contributed, tsMs: T0 });
  assert.equal(failed.families.session.verdict, "pass_failed");
});

test("C2 session.created_vs_boot: raw relation to the reported boot time; the verified value only after a VERIFIED boundary; arrivals only, capped", () => {
  const t = tick({ ms: T0, sessions: { old: 999_000, fresh: 1_000_500, edge: 999_999 }, uptimeMs: 1 });
  const snapshot = snapshotOf(t);
  const unverified = deriveCreatedVsBoot({ evidence: t.evidence, snapshot, arrivedKeys: undefined, bootVerdict: "unverified", ts: t.ts, hmacKey: KEY });
  const byKey = Object.fromEntries(unverified.map((p) => [p.attributes.session_key, p.attributes]));
  assert.equal(byKey[hashSessionIdentity("tmux", "fresh")].relation, "after_boot_time");
  assert.equal(byKey[hashSessionIdentity("tmux", "old")].relation, "before_boot_time");
  assert.equal(byKey[hashSessionIdentity("tmux", "edge")].relation, "unknown", "within the resolution: unknown");
  for (const attrs of Object.values(byKey)) {
    assert.equal(attrs.created_vs_boot, "unknown", "an unverified boundary never yields after/before_boot");
    assert.equal(attrs.basis, "boundary_unverified");
    assert.equal(attrs.arrivals_total, "3");
  }
  const verified = deriveCreatedVsBoot({ evidence: t.evidence, snapshot, arrivedKeys: [`session.tmux.${hashSessionIdentity("tmux", "fresh")}`], bootVerdict: "verified", ts: t.ts, hmacKey: KEY });
  assert.equal(verified.length, 1);
  assert.equal(verified[0].attributes.created_vs_boot, "after_boot");
  const stepped = deriveCreatedVsBoot({ evidence: t.evidence, snapshot, arrivedKeys: undefined, bootVerdict: "verified", clockStep: true, ts: t.ts, hmacKey: KEY });
  assert.ok(stepped.every((p) => p.attributes.created_vs_boot === "unknown" && p.attributes.basis === "clock_step_in_interval"));
  for (const p of verified) assert.deepEqual(validateContextFact(p.fact_name, p.attributes), { ok: true });
  const many = tick({ ms: T0, sessions: Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`s${i}`, 1_000_100])), uptimeMs: 1 });
  const capped = deriveCreatedVsBoot({ evidence: many.evidence, snapshot: snapshotOf(many), bootVerdict: undefined, ts: many.ts, hmacKey: KEY });
  assert.equal(capped.length, 8);
  assert.equal(capped[0].attributes.arrivals_total, "12");
  assert.equal(capped[0].attributes.basis, "no_boundary_observed");
  assert.deepEqual(deriveCreatedVsBoot({ evidence: t.evidence, snapshot, arrivedKeys: [], bootVerdict: "verified", ts: t.ts, hmacKey: KEY }), []);
});

test("C2 host.daemon_gap: the boot ledger folds the longest gap between daemon observations per interval; restarts and boots counted; the cause stays unknown", () => {
  const daemonA = { nonce: "a".repeat(16), start_ms: 0 };
  const daemonB = { nonce: "b".repeat(16), start_ms: 0 };
  const probe = (uptime, bootId = "11111111-2222-3333-4444-555555555555") => ({ boot: { boot_id: bootId, boot_time_s: 1 }, clocks: { os_uptime_ms: uptime } });
  let ledger = observeBootProbe(undefined, probe(1000), { nowMs: T0, daemon: daemonA }).ledger;
  ledger.daemon_gap = emptyDaemonGap(T0);
  ledger = observeBootProbe(ledger, probe(61_000), { nowMs: T0 + 60_000, daemon: daemonA }).ledger;
  ledger = observeBootProbe(ledger, probe(4_000_000), { nowMs: T0 + 4_000_000, daemon: daemonB }).ledger;
  assert.equal(ledger.daemon_gap.observations, 2);
  assert.equal(ledger.daemon_gap.restarts, 1);
  assert.equal(ledger.daemon_gap.max_gap_ms, 3_940_000);
  assert.equal(ledger.daemon_gap.max_gap_uptime_ms, 3_939_000);
  const [point] = factPointsFromDaemonGap(ledger.daemon_gap, { ts: new Date(T0).toISOString(), hmacKey: KEY, intervalMs: 60_000 });
  assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true });
  assert.equal(point.attributes.max_gap_s, "3940");
  assert.equal(point.attributes.max_gap_uptime_s, "3939");
  assert.equal(point.attributes.daemon_restarts, "1");
  assert.equal(point.attributes.cause, "unknown", "a fact only: no cause until host.suspend can split the gap");
  assert.equal(FACT_FAMILY_BY_NAME.get("host.daemon_gap"), "host_lifecycle");
  // A boot change: the uptime gap is not applicable; a backward wall step makes the wall maximum unknown.
  ledger = observeBootProbe(ledger, probe(5000, "99999999-2222-3333-4444-555555555555"), { nowMs: T0 + 9_000_000, daemon: daemonB }).ledger;
  ledger = observeBootProbe(ledger, probe(6000, "99999999-2222-3333-4444-555555555555"), { nowMs: T0 + 8_000_000, daemon: daemonB }).ledger;
  const [after] = factPointsFromDaemonGap(ledger.daemon_gap, { ts: new Date(T0).toISOString(), hmacKey: KEY, intervalMs: 60_000 });
  assert.equal(after.attributes.boot_changed, "true");
  assert.equal(after.attributes.max_gap_uptime_s, "not_applicable");
  assert.equal(after.attributes.max_gap_s, "unknown");
  const [none] = factPointsFromDaemonGap(undefined, { ts: new Date(T0).toISOString(), hmacKey: KEY });
  assert.equal(none.attributes.max_gap_s, "unknown");
  assert.equal(none.attributes.collector_state, "unable");
});

test("C2 statistics skeleton: per-episode identity statistics at offsets 0..2 from the pre-event set; dated daily counts; a lost state is a cold start recorded as memory_lost", async () => {
  const ticks = [
    tick({ ms: T0, sessions: { a: 1, b: 2 }, uptimeMs: 1000 }),
    // A reboot between tick 0 and tick 1: a restored by tmux-resurrect (new creation second), b gone, c new.
    tick({ ms: T0 + HOUR, sessions: { a: 50, c: 60 }, uptimeMs: 500, bootId: "99999999-2222-3333-4444-555555555555" }),
    tick({ ms: T0 + 2 * HOUR, sessions: { a: 50, c: 60, b: 70 }, uptimeMs: 500 + HOUR, bootId: "99999999-2222-3333-4444-555555555555" }),
    tick({ ms: T0 + 3 * HOUR, sessions: { a: 50 }, uptimeMs: 500 + 2 * HOUR, bootId: "99999999-2222-3333-4444-555555555555" }),
    tick({ ms: T0 + 4 * HOUR, sessions: { a: 50 }, uptimeMs: 500 + 3 * HOUR, bootId: "99999999-2222-3333-4444-555555555555" }),
    // Next UTC day.
    tick({ ms: T0 + 14 * HOUR, sessions: { a: 50 }, uptimeMs: 500 + 13 * HOUR, bootId: "99999999-2222-3333-4444-555555555555" }),
  ];
  const chained = chainTicks(ticks);
  let prior = { status: "missing" };
  const emitted = [];
  for (const [index, { snapshot, transitions, summary }] of chained.entries()) {
    const prevChain = index > 0 ? chained[index - 1].summary.nextState("g", index) : undefined;
    const stats = deriveStats({ prior, storeExisted: index > 0, prevChain, snapshot, transitions, summary, nowIso: snapshot.ts });
    for (const p of stats.points) assert.deepEqual(validateContextFact(p.fact_name, p.attributes), { ok: true });
    emitted.push(...stats.points);
    prior = { status: "valid", state: stats.nextState("sg", index + 1) };
  }
  const episodes = emitted.filter((p) => p.fact_name === "stats.episode").map((p) => p.attributes);
  assert.deepEqual(episodes.map((e) => [e.kind, e.off, e.eseq]), [["boot", "0", "1"], ["boot", "1", "1"], ["boot", "2", "1"]]);
  assert.deepEqual([episodes[0].s_pre, episodes[0].s_post, episodes[0].s_same, episodes[0].s_recr, episodes[0].s_dep, episodes[0].s_arr], ["2", "2", "0", "1", "1", "1"]);
  assert.deepEqual([episodes[1].s_recr, episodes[1].s_same, episodes[1].s_dep, episodes[1].s_arr], ["2", "0", "0", "1"], "b came back under its name as a new instance: a same-name recreation, not a survivor");
  assert.equal(episodes[0].p_st, "ok");
  const daily = emitted.filter((p) => p.fact_name === "stats.daily").map((p) => p.attributes);
  assert.equal(daily.length, 1, "the first day closes when the UTC day changes");
  assert.equal(daily[0].day, "2026-10-11");
  assert.equal(daily[0].memory, "first_run");
  assert.equal(daily[0].intervals, "5");
  assert.equal(daily[0].s_known, "4", "the first interval (no previous record) is unknown, not zero");
  assert.equal(daily[0].p_known, "4");
  // Persisted stats state, ledger-stamped; a lost state over an existing store is a cold start.
  const paths = await tempPaths();
  const pass = await appendFactPoints(paths, emitted, { family: "context_stats", now: new Date(T0 + 14 * HOUR).toISOString() });
  await writeStatsState(paths, prior.state.ledger_generation ? { ...prior.state, ledger_generation: pass.retention.ledger_generation, ledger_pass_id: pass.retention.pass_id } : prior.state);
  const { ledger } = await readFactIntegrityLedger(paths, "context_stats");
  assert.equal((await readStatsState(paths, { ledger })).status, "valid");
  await fs.rm(path.join(paths.stateDir, "learned", "facts", "context_stats", "stats-state.json"));
  const lostRead = await readStatsState(paths, { ledger });
  assert.equal(lostRead.status, "missing");
  const last = chained.at(-1);
  const cold = deriveStats({ prior: lostRead, storeExisted: true, prevChain: undefined, snapshot: last.snapshot, transitions: last.transitions, summary: last.summary, nowIso: last.snapshot.ts });
  assert.equal(cold.memoryLost, true);
  const state = cold.nextState("g", 1);
  assert.equal(state.memory_lost_count, 1);
  assert.equal(state.daily.memory, "cold_start_after_loss");
});

test("C2 statistics: each source's daily counts accumulate on its own knownness (a chronically incomplete peer census never hides session churn)", () => {
  const ticks = [0, 1, 2].map((i) => {
    const t = tick({ ms: T0 + i * HOUR, sessions: i === 2 ? { a: 1, b: 2 } : { a: 1 }, uptimeMs: 1000 + i * HOUR });
    t.evidence[1].result.census_status = "partial";
    t.points = [...factPointsFromSessionEvidence(t.evidence, { ts: t.ts }), ...factPointsFromVpnPeerEvidence(t.evidence, { ts: t.ts })];
    return t;
  });
  const chained = chainTicks(ticks);
  let prior = { status: "missing" };
  let state;
  for (const [index, { snapshot, transitions, summary }] of chained.entries()) {
    const stats = deriveStats({ prior, storeExisted: index > 0, prevChain: index > 0 ? chained[index - 1].summary.nextState("g", index) : undefined, snapshot, transitions, summary, nowIso: snapshot.ts });
    state = stats.nextState("sg", index + 1);
    prior = { status: "valid", state };
  }
  assert.equal(state.daily.s_known, 2);
  assert.equal(state.daily.s_arr, 1);
  assert.equal(state.daily.p_known, 0, "the peer census was never complete");
  assert.equal(state.daily.p_arr, 0);
});

test("C2 context_stats T8: at most one episode and one daily record per tick, at their exact worst cases (pinned)", () => {
  const exact = (name) => {
    const schema = CONTEXT_FACT_SCHEMAS.get(name);
    const attributes = {};
    for (const [field, spec] of Object.entries(schema.fields)) {
      if (field === "rejected_field") continue;
      const candidates = spec.kind === "enum" ? [...spec.values] : [...spec.sentinels];
      if (spec.kind === "hmac") candidates.push("f".repeat(16));
      if (spec.kind === "int") candidates.push(String(spec.max));
      if (spec.kind === "pattern") candidates.push("9".repeat(spec.maxLength));
      attributes[field] = candidates.sort((a, b) => b.length - a.length)[0];
    }
    const size = (attrs) => {
      const record = normalizeFactPoint({ ts: "2026-10-11T00:00:00.000Z", fact_name: "x".repeat(name.length), entity_key: `${name}.4294967296`, attributes: attrs });
      record.fact_name = name;
      return Buffer.byteLength(`${JSON.stringify(record)}\n`);
    };
    const longestField = Object.keys(schema.fields).sort((a, b) => b.length - a.length)[0];
    return Math.max(size(attributes), size(unableContextAttributes(name, { rejectedField: longestField })));
  };
  assert.deepEqual([exact("stats.episode"), exact("stats.daily")], [516, 427], "a schema change must revisit the context_stats tick shape");
  assert.equal(FAMILY_TICK_SHAPES.get("context_stats").worstTickBytes, 516 + 427);
});
