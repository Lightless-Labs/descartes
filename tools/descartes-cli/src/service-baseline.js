// Service-disappearance ALERT — new opt-in baseline slice (docs/plans/2026-07-23-service-
// disappearance-alert.md). Turns Slice C's already-shipped service.census marker (8c3d70d) plus
// the pre-existing service.presence fact-history into a DETERMINISTIC set-membership diff alert
// (service.disappeared): a previously-established service stops appearing in a fresh, complete
// service census. NO LLM anywhere in this file.
//
// Orchestrator resolutions (2026-07-23) of the plan's two Stage-1 blocking operator decisions,
// implemented here exactly:
//   (1) Detection SHAPE = SET-DIFF (session.churn-shaped edge-triggered set-membership diff), NOT
//       windowed Welford. welford-stats.js stays untouched except for reusing the generic
//       DEFAULT_BASELINE_FACT_WINDOW_MS read-window bound.
//   (2) Alert body/diagnostics = HASH-ONLY (entity_key_hash) as originally shipped. SUPERSEDED
//       2026-07-24 by an explicit operator decision: for `service.disappeared` ONLY, the
//       notification body/diagnostics now carry the SANITIZED (charset-bounded, NOT hashed)
//       service name in cleartext -- this is a LOCAL notification to the machine's own operator,
//       and which service vanished is the entire operational point (unlike session/peer identity,
//       where the specific one is irrelevant and hashing loses nothing). `entity_key_hash` is
//       retained alongside it for the `fingerprint`/`id` dedup/edge-trigger keys, which stay
//       hashed. See "Cleartext service name (2026-07-24 operator decision)" below for the full
//       rationale and scoping. session.churn/session.count_drop/peer.count_spike/peer.count_drop
//       are UNCHANGED and remain hash-only -- this reversal is scoped to service.disappeared alone.
//   (3) Severity = UNCONDITIONALLY "warning" (hard cap, peer.count_spike-style; no critical tier).
//
// Sibling to session-baseline.js/peer-baseline.js: this module performs NO host execFile/I/O of
// its own — it only reads already-persisted fact-history (fact-store.js) and its own small state
// file. Unlike those two siblings, this module is DELIBERATELY STATELESS for detection purposes
// (no persisted Welford accumulator, no persisted per-entity map): detectServiceDisappearances
// recomputes fully fresh from the bounded read window on every call, mirroring
// detectSessionChurn's own statelessness. The tiny store persists only genuinely-cumulative
// bookkeeping that is NOT re-derivable from a bounded window alone (last_folded_ts,
// skipped_partial_tick_count, disappearance_event_count) — see the plan's "Deliberately lean state
// shape" section for the full rationale (a persisted known_services map was considered and
// rejected as a self-inflicted leak/staleness risk the sibling modules don't have).
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { alertId } from "./alert-store.js";
import { loadLearnedConfig } from "./constraint-store.js";
import { sanitizeDiagnostics, sanitizeIdentityString } from "./diagnostics-sanitizer.js";
import { readFactPoints } from "./fact-store.js";
import { SERVICE_CENSUS_FACT_NAME, SERVICE_CENSUS_MARKER_ENTITY_KEY } from "./fact-translators.js";
import { DEFAULT_BASELINE_FACT_WINDOW_MS } from "./welford-stats.js";

// Re-exported for convenience (mirrors session-baseline.js's own SESSION_CENSUS_MARKER_ENTITY_KEY
// / DEFAULT_BASELINE_FACT_WINDOW_MS re-exports) — consumers/tests of this module's tick-grouping
// should not need to reach into fact-translators.js/welford-stats.js directly for these.
export { SERVICE_CENSUS_MARKER_ENTITY_KEY, DEFAULT_BASELINE_FACT_WINDOW_MS };

const SERVICE_PRESENCE_FACT_NAME = "service.presence";

export const SERVICE_DISAPPEARED_RULE_ID = "service.disappeared";

// PROVISIONAL (mirrors session-baseline.js's/peer-baseline.js's own must-fix-7-style constants) —
// a placeholder default chosen to unblock shipping v0, NOT a tuned value; tuned post-ship like
// DEFAULT_DEVIATION_SIGMA/DEFAULT_STDDEV_FLOOR. Cold-start protection: an entity_key must appear in
// at least this many COMPLETE tick-groups in the window before it is eligible to fire a
// disappearance (option (b) from the recon seam-map's open question — see the plan's "Established
// gate" section for why a single-prior-census check was rejected as too flap-prone and
// "present-since-first-observation" was rejected as too strict).
export const DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT = 3;

// Small, LOCALLY-defined constant (NOT imported from daemon.js — daemon.js already imports THIS
// module, so importing daemon.js's own ACTIVE_FRESHNESS_MULTIPLE/DEFAULT_STRUCTURAL_INTERVAL_MS
// back would create an import cycle). Matches Slice B's documented default (3h). Only used as a
// fallback for direct/unit-test invocation that doesn't thread options.activeFreshnessMs —
// daemon.js's real wiring threads the SAME activeFreshnessMs already resolved once per tick for
// computeActiveConstraintCandidates, so this fallback is never load-bearing in production.
export const DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS = 3 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------------------------
// Store I/O (atomic tmp+rename 0o600, corrupt-tolerant — mirrors session-baseline.js's/
// peer-baseline.js's own load*BaselineStore/write*BaselineStore convention exactly).
// ---------------------------------------------------------------------------------------------

export function resolveServiceBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  return { dir, storeFile: path.join(dir, "service-baseline.json") };
}

async function ensureServiceBaselineDir(descartesPaths) {
  await fs.mkdir(resolveServiceBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshServiceBaselineState() {
  return {
    version: 1,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    disappearance_event_count: 0,
  };
}

function finiteOrDefault(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

export function normalizeServiceBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    disappearance_event_count: finiteOrDefault(base.disappearance_event_count, 0),
  };
}

async function readJsonFile(file) {
  let contents;
  try {
    contents = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { parsed: undefined, missing: true };
    throw error;
  }
  try {
    return { parsed: JSON.parse(contents), missing: false };
  } catch {
    return { parsed: undefined, missing: false, corrupt: true };
  }
}

/**
 * ENOENT-tolerant (fresh state -> empty counters) and corrupt-tolerant (mirrors
 * session-baseline.js's loadSessionBaselineStore exactly): a corrupt/malformed file yields a fresh
 * baseline rather than throwing out of a daemon tick, with `corrupt:true` surfaced to the caller).
 * Never load-bearing for detection itself (see module header) — only for cross-process
 * observability and the fold-time-only counters.
 */
export async function loadServiceBaselineStore(descartesPaths) {
  const { storeFile } = resolveServiceBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: freshServiceBaselineState(), corrupt: false };
  if (corrupt) return { state: freshServiceBaselineState(), corrupt: true };
  return { state: normalizeServiceBaselineState(parsed), corrupt: false };
}

export async function writeServiceBaselineStore(descartesPaths, state) {
  await ensureServiceBaselineDir(descartesPaths);
  const { storeFile } = resolveServiceBaselineStorePaths(descartesPaths);
  const normalized = normalizeServiceBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

// ---------------------------------------------------------------------------------------------
// Tick-grouping — groupServiceFactsByTick(points). Unlike session-baseline.js's
// groupSessionFactsByTick (which only ever sees one fact_name, since sessions' census marker
// deliberately reuses session.presence's own fact_name), this module's read window carries TWO
// distinct fact_names (service.presence and service.census — Slice C's own must-fix reasoning
// about entity_key collision required a distinct fact_name for services), so grouping must itself
// discriminate on point.fact_name.
// ---------------------------------------------------------------------------------------------

/**
 * Groups service.presence + service.census fact points by their shared `ts` (one structural tick
 * = one shared ts string). Returns tick-groups ORDERED ascending by ts, each
 * `{ ts, censusState, entityKeys: Set<string> }`:
 *   - `censusState`: "complete" | "partial" (per this tick's own service.census marker, matched
 *     EXACTLY, not by elimination) | "unknown" (a service.census marker DID land for this tick,
 *     but its `attributes.census_state` is neither the literal string "complete" nor "partial" —
 *     e.g. disk corruption of facts.jsonl, or a future/garbled marker value; classified as a
 *     fail-closed fourth disposition rather than defaulting to "complete", per the module's own
 *     degrade-not-fabricate contract: an unrecognized census-state value must never be silently
 *     upgraded into a trusted complete census) | undefined (no marker landed for this tick at
 *     all — a markerless/legacy tick-group, mirroring session-baseline.js's own censusState
 *     semantics, now extended one state further here for the same reason).
 *   - `entityKeys`: the set of service.presence entity_keys observed in this tick. The census
 *     marker's own reserved entity_key is never added to this set — it never can be, since the
 *     marker lives on the distinct "service.census" fact_name, not "service.presence" (Slice C's
 *     own collision-avoidance design).
 * A tick-group exists whenever ANY service.presence OR service.census point shares that ts — a
 * genuine zero-service census still produces `{censusState:"complete", entityKeys: new Set()}`,
 * never silently skipped, matching Slice C's own "zero-service tick still gets a marker"
 * precedent. Points from an unrelated fact_name sharing the read window are ignored entirely.
 */
export function groupServiceFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || typeof point.ts !== "string") continue;
    if (point.fact_name !== SERVICE_PRESENCE_FACT_NAME && point.fact_name !== SERVICE_CENSUS_FACT_NAME) continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, censusState: undefined, entityKeys: new Set() });
    }
    const group = byTs.get(point.ts);
    if (point.fact_name === SERVICE_CENSUS_FACT_NAME) {
      // Strict three-way match on the marker's own value — NEVER an else-defaults-to-"complete"
      // ternary. An unrecognized census_state value (corruption, future schema drift, a bug
      // upstream) must degrade to the fail-closed "unknown" disposition, not the max-trust one;
      // detectServiceDisappearances' `=== "complete"` filter already excludes "unknown" exactly
      // like "partial"/undefined, so no downstream change is needed to keep it out of the
      // established/comparison set.
      const rawState = point.attributes?.census_state;
      group.censusState = rawState === "complete" ? "complete" : rawState === "partial" ? "partial" : "unknown";
      continue;
    }
    group.entityKeys.add(point.entity_key);
  }
  return [...byTs.values()].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}

// ---------------------------------------------------------------------------------------------
// Established-set + disappearance detection — detectServiceDisappearances(groups, options). Pure
// function, no I/O, mirrors detectSessionChurn's shape and statelessness: recomputed fully fresh
// from `groups` on every call, no persisted per-entity map.
// ---------------------------------------------------------------------------------------------

/**
 * 1. Filters to censusState === "complete" tick-groups only — "partial", "unknown" (a garbled/
 *    unrecognized census_state marker value), and undefined/markerless groups are ALL excluded
 *    WHOLESALE from both the established-count accumulation and the disappearance comparison
 *    (degrade-not-fabricate: an undercounted, garbled, or markerless census must never manufacture
 *    a false disappearance, mirroring session-baseline.js's must-fix-2 partial-exclusion
 *    discipline).
 * 2. Fewer than 2 complete tick-groups in the window -> [] (no claim; nothing to diff against).
 * 3. Established gate (cold-start protection): an entity_key is "established" iff it appears in at
 *    least `minEstablishedCount` of the complete tick-groups in the window.
 * 4. Trigger (edge, K=1, mirrors detectSessionChurn's own recency bound exactly): for each
 *    established entity_key present in the second-most-recent complete tick-group AND ABSENT from
 *    the single most recent complete tick-group, it fires. Edge-triggered: once the freshest-
 *    complete pointer moves past this pair, it stops firing on its own (no forever-firing
 *    candidate, no dedicated "resolved" bookkeeping needed — alert-store.js's existing cooldown/
 *    resolution machinery, already proven by session.churn, handles the rest).
 * 5. Freshness gate (Slice B's own reasoning, reimplemented independently — this module never
 *    calls buildShadowFactLookup): the disappearance is only emitted if the most recent complete
 *    tick-group's ts is itself fresh relative to `nowMs`, within `freshnessMs`. A stale-but-
 *    technically-"complete" tick-group must never be read as "the service is missing NOW" — it
 *    degrades to no-claim instead.
 *
 * Returns `[{ entity_key, disappeared_at_ts, last_seen_ts, complete_census_seen_count }]`.
 */
export function detectServiceDisappearances(groups = [], options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS,
    minEstablishedCount = DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT,
  } = options;

  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length < 2) return [];

  const latest = completeGroups[completeGroups.length - 1];
  const previous = completeGroups[completeGroups.length - 2];

  // Freshness gate (step 5): a stale freshest-complete tick-group degrades to no-claim, checked
  // independent of the presence/absence logic below.
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return [];

  // Established-count accumulation (step 3): over EVERY complete tick-group in the window, not
  // just the latest pair — an entity re-established after a prior disappearance is eligible to
  // fire again on a later genuine disappearance (no permanent one-shot flag).
  const sightingCounts = new Map();
  for (const group of completeGroups) {
    for (const entityKey of group.entityKeys) {
      sightingCounts.set(entityKey, (sightingCounts.get(entityKey) ?? 0) + 1);
    }
  }

  const disappearances = [];
  for (const entityKey of previous.entityKeys) {
    if (latest.entityKeys.has(entityKey)) continue; // still present -- not a disappearance
    const sightings = sightingCounts.get(entityKey) ?? 0;
    if (sightings < minEstablishedCount) continue; // cold-start gate (step 3)
    disappearances.push({
      entity_key: entityKey,
      disappeared_at_ts: latest.ts,
      last_seen_ts: previous.ts,
      complete_census_seen_count: sightings,
    });
  }
  return disappearances;
}

// ---------------------------------------------------------------------------------------------
// Candidate builder — buildDisappearedCandidates(entries). Mirrors buildChurnCandidates'/
// buildCountSpikeCandidate's shape.
// ---------------------------------------------------------------------------------------------

// Dedup/edge-trigger keys (`fingerprint`/`id`) stay HASHED (orchestrator resolution 2, 2026-07-23 /
// plan Stage-1 review must-fix 1; widened 2026-07-23 by adversarial-review finding to cover
// `fingerprint` too, not diagnostics alone; UNCHANGED by the 2026-07-24 cleartext-name decision
// below -- that decision is scoped to the DISPLAYED diagnostics/body only, not to dedup keys).
// entity_key is sanitized-but-NOT-hashed at source (fact-translators.js:sanitizeEntityKey). No
// shared entity-key-hash helper exists yet (fact-translators.js:hashSessionIdentity/
// constraint-store.js/alert-store.js each hash their own domain-prefixed string with
// crypto.createHash("sha256")...slice(0, 16)), so this adds a small local hash helper following the
// SAME convention: a domain-prefixed sha256, truncated to 16 hex chars.
function hashServiceEntityKey(entityKey) {
  return createHash("sha256").update(`service.disappeared:${entityKey}`).digest("hex").slice(0, 16);
}

// Cleartext service name (2026-07-24 operator decision, SUPERSEDES the plan's original fail-closed
// hash-only default for THIS diagnostics field only): the displayed diagnostics now carry the
// SANITIZED (charset-bounded via sanitizeIdentityString/sanitizeEntityKey's own
// `[A-Za-z0-9._:-]`-only output) service name in cleartext, never a raw/unsanitized string --
// re-sanitized here defensively even though entity_key already arrives sanitized from
// fact-translators.js, so no newline/control-char/injection can ever reach the notification
// banner. Rationale (operator, 2026-07-24): this is a LOCAL notification to the machine's own
// operator, and knowing WHICH service vanished is the entire operational point of this alert --
// unlike session/peer identity, where the specific session/peer is irrelevant and hashing loses no
// signal. `entity_key_hash` is retained alongside `service_name` for parity with `fingerprint`/`id`
// (which stay hashed, see above) and for any tooling that still keys off the hash. This scoping is
// intentionally narrow: session.churn/session.count_drop/peer.count_spike/peer.count_drop are
// UNCHANGED elsewhere and remain hash-only -- do not generalize this pattern to those rule_ids.
export function buildDisappearedCandidates(entries = []) {
  return entries.map((entry) => {
    const entityKeyHash = hashServiceEntityKey(entry.entity_key);
    const serviceName = sanitizeIdentityString(entry.entity_key);
    const diagnostics = sanitizeDiagnostics({
      service_name: serviceName,
      entity_key_hash: entityKeyHash,
      last_seen_ts: entry.last_seen_ts,
      complete_census_seen_count: entry.complete_census_seen_count,
    });
    return {
      id: alertId(SERVICE_DISAPPEARED_RULE_ID, entityKeyHash),
      rule_id: SERVICE_DISAPPEARED_RULE_ID,
      // `fingerprint` stays HASHED, never the raw entity_key (adversarial-review finding,
      // 2026-07-23; unaffected by the 2026-07-24 cleartext-diagnostics decision above): alert-
      // store.js's normalizeAlertRecord copies `fingerprint` verbatim onto the persisted alert
      // record, and the generic `descartes alerts list/watch/ack --json` CLI surfaces dump the full
      // record with no compaction (unlike the LLM path, which uses compactAlert and already omits
      // `fingerprint`). Keeping `fingerprint`/`id` hash-derived keeps dedup/edge-triggering stable
      // and unchanged by this reversal -- only the DISPLAYED `service_name` diagnostics field is
      // cleartext now.
      fingerprint: entityKeyHash,
      // Severity capped at "warning" UNCONDITIONALLY (orchestrator resolution 3, 2026-07-23) —
      // mirrors buildCountSpikeCandidate's hard cap (peer-baseline.js), NOT session.count_drop's
      // two-tier warning/critical model. No critical tier is ever emitted by this rule in v0.
      severity: "warning",
      title: "Service disappeared",
      summary: "A previously-established service stopped appearing in the latest complete service census.",
      diagnostics,
      evidence_refs: ["service-baseline"],
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Fast-tick side — the daemon.js extraCandidates entry.
// ---------------------------------------------------------------------------------------------

/**
 * Same signature/short-circuit shape as every sibling: gated by the same
 * loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O.
 *
 * Fold-time-only increment semantics (plan's Stage-1 review must-fix 3, pinned here as a normative
 * rule): skipped_partial_tick_count and disappearance_event_count increment ONLY at fold time —
 * i.e. only for tick-groups newly observed beyond persistedState.last_folded_ts on THIS call —
 * never per candidate computation. detectServiceDisappearances recomputes fresh from the whole
 * read window on EVERY call, including calls where no new tick-group has landed since
 * last_folded_ts (the daemon's fast-tick re-emission convention re-evaluates the SAME
 * complete-census pair straddling a disappearance transition on every fast tick until the next
 * structural tick moves the window forward) — so both counter increments, and last_folded_ts's
 * advance, are gated behind newGroups.length > 0, using only the newly-folded groups/events for
 * the increment amount, never the full recomputed `disappearances` array length. On a tick with
 * zero new tick-groups, no counter changes and no store write happens, even though
 * detectServiceDisappearances still reports the same event as it did last tick.
 *
 * The candidate list itself is rebuilt fresh from `disappearances` on EVERY call (load-bearing,
 * mirrors session/peer's own "re-emission every tick" behavior) — never dependent on whether a
 * store write happened that tick.
 */
export async function computeServiceBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return []; // default-OFF kill switch, checked before ANY I/O

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS; // reused from welford-stats.js — generic read-window bound, not a Welford use
  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupServiceFactsByTick(points);

  const loadStore = options.loadServiceBaselineStore ?? loadServiceBaselineStore;
  const { state: persistedState } = await loadStore(descartesPaths);

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS;
  const minEstablishedCount = options.establishedMinCensusCount ?? DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT;

  const disappearances = detectServiceDisappearances(groups, { nowMs, freshnessMs, minEstablishedCount });

  const lastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const newGroups = groups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  if (newGroups.length > 0) {
    const newGroupTsSet = new Set(newGroups.map((group) => group.ts));
    const newPartialCount = newGroups.filter((group) => group.censusState === "partial").length;
    const newDisappearanceCount = disappearances.filter((entry) => newGroupTsSet.has(entry.disappeared_at_ts)).length;
    const lastFoldedTs = newGroups[newGroups.length - 1].ts;

    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + newPartialCount,
      disappearance_event_count: persistedState.disappearance_event_count + newDisappearanceCount,
    };
    const writeStore = options.writeServiceBaselineStore ?? writeServiceBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  return buildDisappearedCandidates(disappearances);
}
