// R0b: the fact-store coverage contract (docs/plans/2026-10-05-fact-store-capacity-and-sliding-
// anchor.md §4.1, §6 I1-I3/I8/I10, §8 T3-T6). Byte-cap eviction is suffix-preserving and
// tick-aligned, so it narrows coverage instead of breaking it; the ledger records an exclusive
// floor (`bytecap_floor_ts`), and readFactPoints never returns a point at or below it.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveDescartesPaths } from "../src/paths.js";
import { appendFactPoints, enforceFactRetention, readFactPoints, resolveFactStorePaths } from "../src/fact-store.js";
import {
  factPointsFromServiceEvidence,
  factPointsFromSessionEvidence,
  factPointsFromTailscaleStatusEvidence,
  factPointsFromVpnPeerEvidence,
} from "../src/fact-translators.js";

async function tempPaths() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "descartes-fact-coverage-test-"));
  return resolveDescartesPaths({
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
  });
}

const HOUR_MS = 60 * 60 * 1000;
const BASE_MS = Date.parse("2026-10-01T00:00:00.000Z");
const hour = (index) => new Date(BASE_MS + index * HOUR_MS).toISOString();
const lineBytes = (point) => Buffer.byteLength(`${JSON.stringify(point)}\n`);

function envelope(id, tool, result, status = "ok") {
  return { id, status, layer: "L0", source: "test", result, confidence: 1, review_hint: "none", trace: { tool, target: null, latency_ms: 0, ts: hour(0) } };
}

// Real per-family record order, produced by the REAL translators (§4.1 "Why the boundary must be
// strict"): service = presence..., census LAST; session = presence..., census, overflow; peer = VPN
// presence..., VPN census, VPN overflow, then the Tailscale presence..., Tailscale overflow
// (concatenated in that order by daemon.js:1024-1028).
function serviceTick(ts) {
  return factPointsFromServiceEvidence([envelope("services", "collect_services", {
    manager: "systemd",
    services_census: ["alpha.service", "beta.service", "gamma.service", "delta.service"].map((name) => ({ name, running: true })),
    truncated: false,
  })], { ts });
}

function sessionTick(ts) {
  return factPointsFromSessionEvidence([envelope("sessions", "collect_sessions", {
    multiplexers: [{ multiplexer: "tmux", status: "ok" }],
    total_count: 205,
    sessions: ["one", "two", "three"].map((name, index) => ({ multiplexer: "tmux", session_name: name, attached: false, window_count: 1, created_at_epoch_seconds: 1_700_000_000 + index })),
    truncated: true,
    cap: 200,
  })], { ts });
}

function peerTick(ts) {
  const vpn = factPointsFromVpnPeerEvidence([envelope("vpn-peer-status", "collect_vpn_peer_status", {
    sources: { ssh_who: { status: "ok" }, ssh_last: { status: "ok" }, wireguard: { status: "ok" }, vpn_services: { status: "ok" }, established_inbound: { status: "ok" } },
    total_count: 205,
    peers: ["alice", "bob", "carol"].map((user) => ({ source_type: "ssh", presence_state: "observed_active", remote_user: user, remote_host: "203.0.113.5" })),
    truncated: true,
  })], { ts });
  const tailscale = factPointsFromTailscaleStatusEvidence([envelope("tailscale-status", "collect_tailscale_status", {
    total_count: 205,
    peers: ["k1", "k2"].map((key) => ({ source_type: "tailscale", presence_state: "observed_active", node_public_key: `${key}-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDE=`, latest_handshake_epoch_seconds: 0 })),
    truncated: true,
  })], { ts });
  return [...vpn, ...tailscale];
}

function groupByTs(points) {
  const groups = new Map();
  for (const point of points) {
    const key = new Date(point.ts).toISOString();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(`${point.fact_name}|${point.entity_key}`);
  }
  for (const list of groups.values()) list.sort();
  return groups;
}

// ---------------------------------------------------------------------------------------------
// T3: a split tick is never readable. For each real per-family order, size the cap so the PRE-R0b
// newest-first suffix loop keeps all of the newest tick plus the TAIL of the oldest tick (its
// census/overflow markers and some presence facts) while evicting the oldest tick's first presence
// facts -- a tick that would read "complete" but miss entities.
// ---------------------------------------------------------------------------------------------

for (const [family, buildTick] of [["service", serviceTick], ["session", sessionTick], ["peer", peerTick]]) {
  test(`T3 (${family}): byte-cap eviction is tick-aligned in the real record order -- no partial tick survives`, async () => {
    const paths = await tempPaths();
    const older = buildTick(hour(0));
    const newer = buildTick(hour(1));
    // Keep everything from the newer tick + all but the FIRST record of the older tick.
    const cap = [...newer, ...older.slice(1)].reduce((sum, point) => sum + lineBytes(point), 0) + 1;
    await appendFactPoints(paths, older, { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
    await appendFactPoints(paths, newer, { now: hour(1), maxBytes: Number.MAX_SAFE_INTEGER });
    const retention = await enforceFactRetention(paths, { now: hour(1), maxBytes: cap });

    // The whole older tick is evicted (tick alignment), not just its first record.
    assert.equal(retention.bytecap_evicted_count, older.length, "tick-aligned: the entire split tick is evicted");
    assert.equal(retention.kept_count, newer.length);
    const raw = (await fs.readFile(resolveFactStorePaths(paths).factsFile, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(raw.some((record) => record.ts === hour(0)), false, "no record of the split tick is physically kept");

    const read = await readFactPoints(paths, { now: hour(1) });
    const groups = groupByTs(read.points);
    assert.deepEqual([...groups.keys()], [hour(1)]);
    assert.deepEqual(groups.get(hour(1)), groupByTs(newer.map((point) => ({ ...point }))).get(hour(1)));
  });
}

// ---------------------------------------------------------------------------------------------
// T5: assertions and edge cases (eviction half; the ledger half lives with the v2 ledger tests).
// ---------------------------------------------------------------------------------------------

test("T5: a non-suffix eviction (forced through the candidate-order seam) throws before anything is written", async () => {
  const paths = await tempPaths();
  await appendFactPoints(paths, [...serviceTick(hour(0)), ...serviceTick(hour(1)), ...serviceTick(hour(2))], { now: hour(2), maxBytes: Number.MAX_SAFE_INTEGER });
  const before = await fs.readFile(resolveFactStorePaths(paths).factsFile);
  const oneTick = serviceTick(hour(2)).reduce((sum, point) => sum + lineBytes(point), 0);
  await assert.rejects(
    () => enforceFactRetention(paths, {
      now: hour(2),
      maxBytes: oneTick,
      // Stub the sort: newest-first, so the newest-first keep loop would keep the OLDEST tick.
      orderRetentionCandidates: (candidates) => [...candidates].reverse(),
    }),
    /suffix/,
  );
  const after = await fs.readFile(resolveFactStorePaths(paths).factsFile);
  assert.deepEqual(after, before, "a refused pass must not rewrite the store");
});

test("T5: the accounting sum holds with tick-aligned eviction counted as byte-cap", async () => {
  const paths = await tempPaths();
  const ticks = [0, 1, 2, 3].map((index) => serviceTick(hour(index)));
  await appendFactPoints(paths, ticks.flat(), { now: hour(3), maxBytes: Number.MAX_SAFE_INTEGER });
  // Room for 2.5 ticks: tick alignment must drop the half tick too.
  const tickBytes = ticks[0].reduce((sum, point) => sum + lineBytes(point), 0);
  const retention = await enforceFactRetention(paths, { now: hour(3), maxBytes: Math.floor(tickBytes * 2.5) });
  assert.equal(retention.kept_count, ticks[0].length * 2);
  assert.equal(retention.bytecap_evicted_count, ticks[0].length * 2);
  assert.equal(retention.kept_count + retention.age_evicted_count + retention.bytecap_evicted_count + retention.future_fact_dropped_count, ticks.flat().length);
});
