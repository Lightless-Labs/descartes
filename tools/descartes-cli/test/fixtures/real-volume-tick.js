// Seeded generator for a structural tick shaped like the real macOS host measured on 2026-10-05
// (docs/plans/2026-10-05-fact-store-capacity-and-sliding-anchor.md §2): ~722 fact records and
// ~185 KB per structural tick, dominated by service.presence (518 launchd labels) and
// process.lineage_edge (175 edges), plus a handful of scheduled jobs, listening ports, one VPN
// peer and an empty session census. At scale 1 this yields 714 records / ~191 KB per tick (no
// provenance.warning records), so a 5 MiB store fills after ~27.5 ticks.
//
// The real tick is NOT committed (public repo; it carries cleartext launchd labels). This builds
// synthetic structural-collector envelopes with the same per-family counts and roughly the same
// average record sizes, so the REAL translators turn them into fact points (census markers in
// their real per-family order). Deterministic: a seeded PRNG, the same entities every tick.

export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function envelope(id, tool, result, status = "ok") {
  return {
    id,
    status,
    layer: "L0",
    source: "test",
    result,
    confidence: 1,
    review_hint: "none",
    trace: { tool, target: null, latency_ms: 0, ts: "2026-10-05T00:00:00.000Z" },
  };
}

function hex(random, length) {
  let out = "";
  while (out.length < length) out += Math.floor(random() * 16).toString(16);
  return out;
}

/**
 * Returns structural-collector fakes for runDaemonIteration's options.structuralCollectors plus
 * the matching structural profile collector toggles. `scale` (default 1) multiplies per-family
 * entity counts; volume per tick scales with it.
 */
export function realVolumeStructuralCollectors({ seed = 20261005, scale = 1 } = {}) {
  const random = mulberry32(seed);
  const serviceCount = Math.round(518 * scale);
  const edgeCount = Math.round(175 * scale);
  const jobCount = Math.max(1, Math.round(7 * scale));
  const portCount = Math.max(1, Math.round(8 * scale));
  // launchd labels ~40-60 chars (sanitized cleartext); average service.presence record ~254 B.
  const services = Array.from({ length: serviceCount }, (_, index) => ({
    label: `com.vendor${index % 37}.agent.${hex(random, 12 + Math.floor(random() * 24))}.${index}`,
    state: random() < 0.6 ? "running" : "not_running",
  }));
  const edges = Array.from({ length: edgeCount }, (_, index) => ({
    parent_comm: `parent-${hex(random, 8)}-${index}`,
    child_comm: `child-${hex(random, 8)}-${index}`,
  }));
  const jobs = Array.from({ length: jobCount }, (_, index) => ({
    kind: "launchd_scheduled_job",
    source: "launchd_plist",
    label: `com.vendor.job.${hex(random, 10)}.${index}`,
  }));
  const sockets = Array.from({ length: portCount }, (_, index) => ({
    protocol: "tcp",
    state: "LISTEN",
    local_address: "127.0.0.1",
    local_port: 40000 + index,
    command: `daemon${index}`,
  }));

  const collectors = {
    services: async () => envelope("services", "collect_services", { manager: "launchd", services_census: services, truncated: false }),
    network: async () => envelope("network-basics", "collect_network", { listening_sockets: sockets }),
    "scheduled-jobs": async () => envelope("scheduled-jobs", "collect_scheduled_jobs", { jobs, summary: { unavailable_count: 0 }, truncated: false }),
    sessions: async () => envelope("sessions", "collect_sessions", {
      platform: "darwin",
      multiplexers: [{ multiplexer: "tmux", status: "ok" }, { multiplexer: "screen", status: "not_found_on_known_paths" }],
      any_binary_available: true,
      total_count: 0,
      sessions: [],
      truncated: false,
      cap: 200,
    }),
    "vpn-peer-status": async () => envelope("vpn-peer-status", "collect_vpn_peer_status", {
      platform: "darwin",
      sources: {
        ssh_who: { status: "ok" },
        ssh_last: { status: "ok", requested_n: 50 },
        wireguard: { status: "ok", elevation_candidate: false, interfaces: [] },
        vpn_services: { status: "ok" },
        established_inbound: { status: "ok" },
      },
      any_source_available: true,
      total_count: 1,
      peers: [{ source_type: "ssh", presence_state: "observed_active", remote_user: "alice", remote_host: "203.0.113.5", origin: "who" }],
      truncated: false,
      cap: 200,
    }),
    "process-lineage": async () => envelope("process-lineage-edges", "collect_process_lineage", { edges, edge_count: edges.length, truncated: false }),
  };
  const structuralCollectorToggles = {
    services: { enabled: true },
    network: { enabled: true },
    "scheduled-jobs": { enabled: true },
    sessions: { enabled: true },
    "vpn-peer-status": { enabled: true },
    "process-lineage": { enabled: true },
  };
  return { collectors, structuralCollectorToggles };
}
