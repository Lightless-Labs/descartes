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
import { factHistoryTrustworthy } from "./fact-store-completeness.js";
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

// Fact-store completeness hardening (docs/plans/2026-08-21-fact-store-completeness-hardening.md,
// Slice 6): the number of genuinely-new, complete (censusState === "complete") tick-groups that
// must accumulate strictly AFTER a cold-start lockout's cold_start_since_ts anchor before the
// lockout clears and service.disappeared novelty resumes. Mirrors session-baseline.js's
// DEFAULT_SESSION_MIN_HISTORY_TICK_COUNT / peer-baseline.js's DEFAULT_PEER_MIN_HISTORY_TICK_COUNT /
// process-lineage-baseline.js's DEFAULT_LINEAGE_MIN_HISTORY_TICK_COUNT exactly -- independently
// defined, not imported, per each detector owning its own re-establishment tuning.
export const DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT = 6;

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
    // Persistent cold-start lockout (fact-store completeness hardening, Slice 6 -- ports the
    // mechanism process-lineage-baseline.js/session-baseline.js/peer-baseline.js already carry, see
    // the extended comment on computeServiceBaselineCandidates below for the full rationale). A
    // brand new store starts pending, exactly like a genuine day-1 cold start.
    cold_start_pending: true,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
  };
}

function finiteOrDefault(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function isValidIsoTimestamp(value) {
  return typeof value === "string" && value.length > 0 && Number.isFinite(new Date(value).getTime());
}

const COMPLETENESS_LOSS_TIMESTAMP_FIELDS = [
  "last_corrupt_ts",
  "last_schema_invalid_ts",
  "last_bytecap_evict_ts",
  "last_continuity_break_ts",
];

function hasCompletenessLossAfterAnchor(readResult, anchorTs, nowMs) {
  const completeness = readResult?.completeness;
  if (!completeness || typeof completeness !== "object" || Array.isArray(completeness)) return false;
  const anchorMs = isValidIsoTimestamp(anchorTs) ? new Date(anchorTs).getTime() : -Infinity;
  const upperBoundMs = Number.isFinite(nowMs) ? nowMs : Infinity;
  return COMPLETENESS_LOSS_TIMESTAMP_FIELDS.some((field) => {
    const timestamp = completeness[field];
    if (timestamp === undefined || timestamp === null) return false;
    const timestampMs = new Date(timestamp).getTime();
    return !Number.isFinite(timestampMs) || (timestampMs > anchorMs && timestampMs <= upperBoundMs);
  });
}

export function normalizeServiceBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 1,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    disappearance_event_count: finiteOrDefault(base.disappearance_event_count, 0),
    // Fail-closed default (mirrors process-lineage-baseline.js's/session-baseline.js's/
    // peer-baseline.js's own normalizeXBaselineState exactly): cold_start_pending is trusted
    // "false" only when the store explicitly and validly recorded it as such. Any other value --
    // missing (a pre-Slice-6 store predating this field), non-boolean garbage, or an explicit true
    // -- is treated as still pending. This IS the per-detector P8-style migration: a pre-migration
    // store cold-starts once on first read. Lenient per-field normalization (not process-lineage's
    // exact-schema rejection) is deliberately kept here -- see the plan's "Shared schema-extension
    // spec for Slices 4-7".
    cold_start_pending: base.cold_start_pending !== false,
    cold_start_reason: typeof base.cold_start_reason === "string" ? base.cold_start_reason : undefined,
    cold_start_since_ts: typeof base.cold_start_since_ts === "string" ? base.cold_start_since_ts : undefined,
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
 * Cross-process observability and the fold-time-only counters were the only load-bearing use of
 * this store before Slice 6; since Slice 6 the store also carries the persisted cold-start
 * lockout, so `missing`/`corrupt` are now distinctly surfaced (mirrors process-lineage-baseline.js's/
 * session-baseline.js's/peer-baseline.js's own loadXBaselineStore) so computeServiceBaselineCandidates
 * can tell "no store yet / store I/O loss this tick" (storeLossThisTick) apart from a genuinely-read,
 * lenient-normalized store -- both cases already default cold_start_pending:true via
 * freshServiceBaselineState, but storeLossThisTick additionally forces the arming branch to
 * re-synthesize a real anchor every tick the store stays lost, rather than silently reusing a
 * stale/undefined one.
 */
export async function loadServiceBaselineStore(descartesPaths) {
  const { storeFile } = resolveServiceBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) return { state: { ...freshServiceBaselineState(), cold_start_reason: "missing_store" }, corrupt: false, missing: true };
  if (corrupt) return { state: { ...freshServiceBaselineState(), cold_start_reason: "corrupt_store" }, corrupt: true, missing: false };
  return { state: normalizeServiceBaselineState(parsed), corrupt: false, missing: false };
}

export async function writeServiceBaselineStore(descartesPaths, state) {
  await ensureServiceBaselineDir(descartesPaths);
  const { storeFile } = resolveServiceBaselineStorePaths(descartesPaths);
  const normalized = normalizeServiceBaselineState(state);
  // FAIL-SAFE (mirrors process-lineage-baseline.js's/session-baseline.js's/peer-baseline.js's own
  // writeXBaselineStore exactly): normalizeServiceBaselineState's own defaulting deliberately leaves
  // cold_start_since_ts undefined when a caller doesn't supply one -- but a store actually
  // PERSISTED to disk with cold_start_pending:true and no anchor can never re-establish (the
  // re-accumulation gate in computeServiceBaselineCandidates has nothing to compare tick timestamps
  // against). Compute paths must set the anchor from their injected clock before persisting
  // pending state.
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
  const minHistoryTickCount = options.minHistoryTickCount ?? DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT;

  // Fact-store completeness hardening (Slice 6): the FULL read result is captured (not just
  // `points`) so factHistoryTrustworthy can see corrupt_count/schema_invalid_count/completeness —
  // exactly what process-lineage-baseline.js/session-baseline.js/peer-baseline.js do for their own
  // candidate computations.
  const readFacts = options.readFactPoints ?? readFactPoints;
  const readResult = await readFacts(descartesPaths, { windowMs, now: options.now });
  const { points, corrupt_count: corruptFactCount } = readResult;
  const groups = groupServiceFactsByTick(points);

  const loadStore = options.loadServiceBaselineStore ?? loadServiceBaselineStore;
  const { state: persistedState, corrupt: corruptBaselineStore, missing: missingBaselineStore } = await loadStore(descartesPaths);

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS;
  const minEstablishedCount = options.establishedMinCensusCount ?? DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT;
  const currentGroups = groups.filter((group) => {
    const groupMs = new Date(group.ts).getTime();
    return Number.isFinite(groupMs) && groupMs <= nowMs;
  });

  // BOUNDED fix, ported from process-lineage-baseline.js's/session-baseline.js's/peer-baseline.js's
  // persistent cold-start lockout (fact-store completeness hardening plan, Slice 6 — service-
  // baseline.js did not have this mechanism at all before this slice; see
  // computeSessionBaselineCandidates for the full deception/anomaly-detector-review rationale this
  // ports verbatim): an unreadable/corrupt fact-history this tick, a lost/corrupt service-baseline
  // store, or fact-history whose completeness cannot be trusted since this detector's own last
  // re-established anchor, must never be treated as authoritative "this really is all the
  // service-census history" — that could make a perfectly normal, still-present service read as
  // vanished purely because retention scrubbed the tick that would have shown it as established,
  // fabricating a service.disappeared alert. Corrupt/missing/unrecognizable store state (or
  // degraded fact-history) enters (or keeps) a PERSISTENT cold_start_pending lockout that survives
  // across ticks: while pending, this detector emits ZERO service.disappeared novelty — not just
  // this tick, but every tick — until minHistoryTickCount genuinely NEW complete ticks (ts strictly
  // after cold_start_since_ts) have been observed. Re-establishment cannot be satisfied
  // retroactively by fact-history that already existed before/during the loss.
  const factsCorruptThisTick = Boolean(corruptFactCount);
  const storeLossThisTick = corruptBaselineStore === true || missingBaselineStore === true;
  // FAIL-SAFE, additional to the shared 3-term arming formula (process-lineage-baseline.js avoids
  // this exact gap via its OWN exact-schema store validator, which rejects on disk any
  // cold_start_pending:true store missing a valid anchor before it is ever normalized — service-
  // baseline.js deliberately keeps LENIENT per-field normalization instead, per the plan's "Shared
  // schema-extension spec for Slices 4-7", so that guard does not exist here). Without this term, a
  // pre-Slice-6 store migrated in place (cold_start_pending defaults to true, cold_start_since_ts
  // stays undefined) reading against an already-pristine, loss-free fact-history ledger would see
  // factHistoryTrustworthy return trust:true even with no anchor (anchorTs undefined has nothing to
  // compare against) — landing in the re-accumulation branch with sinceMs permanently Infinity, an
  // unrecoverable lockout. This term forces that first post-migration tick to (re-)arm with a REAL
  // anchor instead, so the migration cold-start is bounded ("cold-starts once"), never a silent
  // permanent latch — the exact class of bug this whole plan exists to close.
  const persistedAnchorMissingOrFuture = (persistedState.cold_start_pending && !isValidIsoTimestamp(persistedState.cold_start_since_ts))
    || (isValidIsoTimestamp(persistedState.cold_start_since_ts)
      && new Date(persistedState.cold_start_since_ts).getTime() > nowMs);
  const historyTrust = factHistoryTrustworthy(readResult, { anchorTs: persistedState.cold_start_since_ts, nowMs });
  const completenessLossAfterAnchor = hasCompletenessLossAfterAnchor(readResult, persistedState.cold_start_since_ts, nowMs);
  const enteringColdStart = factsCorruptThisTick
    || storeLossThisTick
    || persistedAnchorMissingOrFuture
    || completenessLossAfterAnchor
    || (!persistedState.cold_start_pending && !historyTrust.trust);

  // Gate THIS tick's detection using the state as it stood BEFORE any update below — a tick cannot
  // self-heal and alert in the same breath it (re)establishes trust.
  const coldStartPendingThisTick = persistedState.cold_start_pending || enteringColdStart || !historyTrust.trust;

  let nextColdStartPending = persistedState.cold_start_pending;
  let nextColdStartReason = persistedState.cold_start_reason;
  let nextColdStartSinceTs = persistedState.cold_start_since_ts;

  if (enteringColdStart) {
    // (Re-)arm the lockout. Any in-progress re-accumulation is discarded — it cannot be trusted to
    // have been continuous once corruption/loss is observed again.
    nextColdStartPending = true;
    nextColdStartReason = storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts";
    nextColdStartSinceTs = nowIso;
  } else if (persistedState.cold_start_pending && historyTrust.trust) {
    // Re-accumulating: count complete ticks genuinely observed strictly after the lockout began.
    // Recomputed fresh from the live window every call (not an incrementing counter) so a missed
    // or re-ordered tick can never double count, and so re-establishment cannot be satisfied by
    // ticks that already existed before the reset.
    //
    // Counted against `group.censusState === "complete"` — the SAME predicate
    // detectServiceDisappearances itself already uses as "the" notion of a complete tick.
    // Service-disappearance subtlety (flagged per the Slice 6 dispatch): peer-baseline.js (Slice 5)
    // had to choose between TWO disposition functions for its own re-accumulation counter
    // (tickGroupDisposition, marker-agnostic; dropTickGroupDisposition, marker-gated) because
    // peer.count_spike has NO census-marker concept at all in v0 — a live, ongoing peer.presence
    // stream can structurally lack an availability_signature marker forever on some hosts (e.g. the
    // `wg` command permanently unavailable), so gating re-accumulation on the marker-only
    // disposition would have permanently latched that host's lockout. service-baseline.js has no
    // such second disposition to choose from: groupServiceFactsByTick already folds the census
    // marker's own state directly into each group's `censusState` (complete/partial/unknown/
    // undefined), and service.disappeared has ALWAYS required a service.census marker to treat a
    // tick as "complete" since that marker shipped (Slice C, 8c3d70d) — this is not a Slice-6
    // addition. A markerless service.presence-only tick-group was already unable to establish or
    // fire service.disappeared before this slice (fact-translators.js only omits the marker on an
    // "unknown"/unsupported-platform envelope, which also emits no service.presence facts at all —
    // there is no live, ongoing scenario, analogous to peer's `wg`-failure case, where a supported
    // host keeps emitting real service.presence facts every tick with the census marker
    // structurally and permanently absent). Gating re-accumulation on `censusState === "complete"`
    // therefore cannot regress an existing detection capability the way using the marker-gated
    // disposition would have for peer.count_drop — it is simply the one and only notion of
    // "complete tick" this detector has ever had.
    const sinceMs = persistedState.cold_start_since_ts ? new Date(persistedState.cold_start_since_ts).getTime() : Infinity;
    const reestablishedTickCount = currentGroups.filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return group.censusState === "complete" && groupMs > sinceMs && groupMs <= nowMs;
    }).length;
    if (reestablishedTickCount >= minHistoryTickCount) {
      nextColdStartPending = false;
    }
  }

  const disappearances = detectServiceDisappearances(currentGroups, { nowMs, freshnessMs, minEstablishedCount });

  const persistedLastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const lastFoldedWasFuture = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs > nowMs;
  const lastFoldedMs = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs <= nowMs ? persistedLastFoldedMs : -Infinity;
  const effectiveLastFoldedTs = lastFoldedMs === -Infinity ? undefined : persistedState.last_folded_ts;
  const newGroups = currentGroups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  const coldStartStateChanged = nextColdStartPending !== persistedState.cold_start_pending
    || nextColdStartReason !== persistedState.cold_start_reason
    || nextColdStartSinceTs !== persistedState.cold_start_since_ts;
  if (newGroups.length > 0 || coldStartStateChanged || lastFoldedWasFuture) {
    const newGroupTsSet = new Set(newGroups.map((group) => group.ts));
    const newPartialCount = newGroups.filter((group) => group.censusState === "partial").length;
    const newDisappearanceCount = disappearances.filter((entry) => newGroupTsSet.has(entry.disappeared_at_ts)).length;
    // Stays at the persisted value when newGroups is empty (an enteringColdStart-only call) --
    // mirrors session-baseline.js's/peer-baseline.js's own loop-accumulated lastFoldedTs, which
    // likewise only advances across newly-observed groups.
    const lastFoldedTs = newGroups.length > 0 ? newGroups[newGroups.length - 1].ts : effectiveLastFoldedTs;

    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + newPartialCount,
      disappearance_event_count: persistedState.disappearance_event_count + newDisappearanceCount,
      cold_start_pending: nextColdStartPending,
      cold_start_reason: nextColdStartReason,
      cold_start_since_ts: nextColdStartSinceTs,
    };
    const writeStore = options.writeServiceBaselineStore ?? writeServiceBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  if (coldStartPendingThisTick) return [];

  // Re-emission every tick (load-bearing, mirrors session/peer's own "re-emission every tick"
  // behavior): built fresh from `disappearances` on EVERY call — never dependent on whether a store
  // write happened that tick.
  return buildDisappearedCandidates(disappearances);
}

// ---------------------------------------------------------------------------------------------
// Persistence baseline, Slice C (docs/plans/2026-08-21-agent-intrusion-detection-gaps.md) —
// service.appeared, the appearance-direction twin of service.disappeared above. Reuses the SAME
// service.presence/service.census fact-history and groupServiceFactsByTick unchanged — no new
// collector, no new fact translator.
//
// GATE DECISION (per-signal, stated explicitly — see the task's CRITICAL SECURITY-SEMANTICS
// LESSON): service.appeared is an ABSENCE/NOVELTY claim ("this service unit was never seen before
// in this host's fact-history"), the exact same shape as scheduled_job.appeared
// (persistence-baseline.js) and canary-baseline.js's own canary_vanished — an incomplete/
// truncated fact-history CAN fabricate it (a long-standing service reads as "new" purely because
// retention/corruption dropped the earlier tick that would have shown it as established). It is
// therefore COMPLETENESS-GATED via its OWN persistent cold-start lockout, adopting the hardened
// exact-schema store shape (mirrors process-lineage-baseline.js's/persistence-baseline.js's
// PROCESS_LINEAGE_BASELINE_STORE_KEYS-style validation) — NOT the older lenient
// normalizeServiceBaselineState the sibling DISAPPEARANCE path above still uses (that path
// predates the fact-store-completeness hardening; retrofitting it is a separate, out-of-scope
// follow-up per the plan's O5). Behavior on incomplete history: emit NOTHING, never fabricate.
// ---------------------------------------------------------------------------------------------

export const SERVICE_APPEARED_RULE_ID = "service.appeared";

export function resolveServiceAppearanceBaselineStorePaths(descartesPaths) {
  const dir = path.join(descartesPaths.stateDir, "learned");
  // [O3] A SEPARATE store from service-baseline.json (not shared with the disappearance path):
  // keeps the two directions' last_folded_ts checkpoints independent — a shared checkpoint would
  // risk one fold advancing past the other's unprocessed tick.
  return { dir, storeFile: path.join(dir, "service-appearance-baseline.json") };
}

async function ensureServiceAppearanceBaselineDir(descartesPaths) {
  await fs.mkdir(resolveServiceAppearanceBaselineStorePaths(descartesPaths).dir, { recursive: true, mode: 0o700 });
}

function freshServiceAppearanceBaselineState() {
  return {
    version: 2,
    last_folded_ts: undefined,
    skipped_partial_tick_count: 0,
    appeared_event_count: 0,
    cold_start_pending: true,
    cold_start_reason: undefined,
    cold_start_since_ts: undefined,
  };
}

export function normalizeServiceAppearanceBaselineState(raw) {
  const base = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  return {
    version: 2,
    last_folded_ts: typeof base.last_folded_ts === "string" ? base.last_folded_ts : undefined,
    skipped_partial_tick_count: finiteOrDefault(base.skipped_partial_tick_count, 0),
    appeared_event_count: finiteOrDefault(base.appeared_event_count, 0),
    cold_start_pending: base.cold_start_pending !== false,
    cold_start_reason: typeof base.cold_start_reason === "string" ? base.cold_start_reason : undefined,
    cold_start_since_ts: typeof base.cold_start_since_ts === "string" ? base.cold_start_since_ts : undefined,
  };
}

// [REVIEW 2026-08-21, must-fix] Exact-schema validation (mirrors
// process-lineage-baseline.js's isValidProcessLineageBaselineStoreShape byte-for-byte — see that
// module's own extended comment for the full fabrication-class rationale): a closed key set, a
// cold_start_pending:true store MUST carry a valid cold_start_since_ts anchor, and an established
// (cold_start_pending:false) store MUST carry the complete established-state schema (a valid
// last_folded_ts). This is DELIBERATELY stricter than the sibling disappearance path's own
// normalizeServiceBaselineState (lenient per-field defaulting) — see the module-section header
// above for why the two paths carry different store-trust postures.
const SERVICE_APPEARANCE_BASELINE_STORE_KEYS = new Set([
  "version",
  "last_folded_ts",
  "skipped_partial_tick_count",
  "appeared_event_count",
  "cold_start_pending",
  "cold_start_reason",
  "cold_start_since_ts",
]);

function isNonNegativeFiniteInteger(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value >= 0;
}

export function isValidServiceAppearanceBaselineStoreShape(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  for (const key of Object.keys(raw)) {
    if (!SERVICE_APPEARANCE_BASELINE_STORE_KEYS.has(key)) return false;
  }
  if (raw.version !== 2) return false;
  if (typeof raw.cold_start_pending !== "boolean") return false;
  if (!isNonNegativeFiniteInteger(raw.skipped_partial_tick_count)) return false;
  if (!isNonNegativeFiniteInteger(raw.appeared_event_count)) return false;
  if (raw.cold_start_reason !== undefined && typeof raw.cold_start_reason !== "string") return false;
  if (raw.cold_start_pending) {
    if (!isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
    if (raw.last_folded_ts !== undefined && !isValidIsoTimestamp(raw.last_folded_ts)) return false;
  } else {
    if (!isValidIsoTimestamp(raw.last_folded_ts)) return false;
    if (raw.cold_start_since_ts !== undefined && !isValidIsoTimestamp(raw.cold_start_since_ts)) return false;
  }
  return true;
}

export async function loadServiceAppearanceBaselineStore(descartesPaths) {
  const { storeFile } = resolveServiceAppearanceBaselineStorePaths(descartesPaths);
  const { parsed, missing, corrupt } = await readJsonFile(storeFile);
  if (missing) {
    return { state: { ...freshServiceAppearanceBaselineState(), cold_start_reason: "missing_store" }, corrupt: false, missing: true };
  }
  if (corrupt) {
    return { state: { ...freshServiceAppearanceBaselineState(), cold_start_reason: "corrupt_store" }, corrupt: true, missing: false };
  }
  if (!isValidServiceAppearanceBaselineStoreShape(parsed)) {
    return { state: { ...freshServiceAppearanceBaselineState(), cold_start_reason: "invalid_store_schema" }, corrupt: true, missing: false };
  }
  return { state: normalizeServiceAppearanceBaselineState(parsed), corrupt: false, missing: false };
}

export async function writeServiceAppearanceBaselineStore(descartesPaths, state) {
  await ensureServiceAppearanceBaselineDir(descartesPaths);
  const { storeFile } = resolveServiceAppearanceBaselineStorePaths(descartesPaths);
  const normalized = normalizeServiceAppearanceBaselineState(state);
  const tmpFile = `${storeFile}.${process.pid}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(normalized, null, 2), { mode: 0o600 });
  await fs.rename(tmpFile, storeFile);
  return normalized;
}

/**
 * The appearance-direction twin of detectServiceDisappearances, over the SAME groups (reuses
 * groupServiceFactsByTick unchanged). Shape mirrors process-lineage-baseline.js's/
 * persistence-baseline.js's own novelty detection (historical union across every complete group
 * EXCEPT latest; fire for latest-group keys absent from that union) — the only self-consistent
 * "detect NEW" semantics: a per-entity established-sightings gate (detectServiceDisappearances'
 * own minEstablishedCount) cannot sensibly invert for the appearance direction (an entity cannot
 * be required to have PRIOR established sightings to be flagged as newly appeared). The
 * `minHistoryTickCount` default REUSES DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT (per the
 * plan's own instruction) as this detector's window-size/cold-start-style gate — a value distinct
 * from, and not to be confused with, the SEPARATE persistent-lockout re-accumulation gate
 * (DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT) computeServiceAppearanceCandidates applies below.
 */
export function detectServiceAppearances(groups = [], options = {}) {
  const {
    nowMs = Date.now(),
    freshnessMs = DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS,
    minHistoryTickCount = DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT,
  } = options;
  const completeGroups = groups.filter((group) => group.censusState === "complete");
  if (completeGroups.length < minHistoryTickCount + 1) return [];

  const latest = completeGroups[completeGroups.length - 1];
  const latestMs = new Date(latest.ts).getTime();
  if (!(nowMs - latestMs <= freshnessMs)) return [];

  const historical = new Set();
  for (const group of completeGroups.slice(0, -1)) {
    for (const entityKey of group.entityKeys) historical.add(entityKey);
  }

  const appearances = [];
  for (const entityKey of latest.entityKeys) {
    if (historical.has(entityKey)) continue;
    appearances.push({ entity_key: entityKey, first_seen_ts: latest.ts });
  }
  return appearances;
}

// Own domain-separated hash — deliberately NOT hashServiceEntityKey (which is
// "service.disappeared"-domain-prefixed): a distinct rule-scoped domain keeps
// service.appeared's fingerprints from ever coinciding with service.disappeared's for the same
// entity_key, mirroring hashLineageEdgeEntityKey's/hashScheduledJobEntityKey's own per-rule_id
// domain-separation convention.
function hashServiceAppearedEntityKey(entityKey) {
  return createHash("sha256").update(`${SERVICE_APPEARED_RULE_ID}:${entityKey}`).digest("hex").slice(0, 16);
}

// [O1] Hash-only diagnostics by default (unsigned) — mirrors buildDisappearedCandidates' hashed
// fingerprint/id discipline but deliberately does NOT extend service.disappeared's scoped
// 2026-07-24 cleartext-service-name exception to this new rule_id (that exception is explicitly
// narrow, "do not generalize"). A future operator sign-off can add a sanitized `service_name`
// diagnostics field the same way service.disappeared did, without a redesign.
export function buildAppearedCandidates(entries = []) {
  return entries.map((entry) => {
    const entityKeyHash = hashServiceAppearedEntityKey(entry.entity_key);
    const diagnostics = sanitizeDiagnostics({
      entity_key_hash: entityKeyHash,
      first_seen_ts: entry.first_seen_ts,
    });
    return {
      id: alertId(SERVICE_APPEARED_RULE_ID, entityKeyHash),
      rule_id: SERVICE_APPEARED_RULE_ID,
      fingerprint: entityKeyHash,
      // Severity capped at "warning" UNCONDITIONALLY, mirroring buildDisappearedCandidates' own
      // hard cap — no critical tier in v1.
      severity: "warning",
      title: "New service appeared",
      summary: "A service unit not seen in this host's recent history just appeared in the latest complete service census.",
      diagnostics,
      evidence_refs: ["service-baseline"],
    };
  });
}

/**
 * Same signature/short-circuit shape as computeServiceBaselineCandidates: gated by the same
 * loadLearnedConfig(...).enabled short-circuit-to-[] BEFORE any I/O. Threads its OWN persistent
 * cold-start lockout (separate store, see resolveServiceAppearanceBaselineStorePaths/O3) so an
 * appearance fold and a disappearance fold can never mutually skip a tick.
 */
export async function computeServiceAppearanceCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS;
  // Persistent-lockout re-accumulation gate (distinct from detectServiceAppearances' own
  // window-size gate below) — reuses DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT, the SAME value/
  // semantics the sibling disappearance path already applies to its own lockout over this
  // identical fact stream (see the module-section header above for the full rationale).
  const minHistoryTickCount = options.minHistoryTickCount ?? DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT;
  // detectServiceAppearances' own window-size gate — reuses DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT
  // per the plan's explicit instruction ("Reuse DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT").
  const establishedMinCensusCount = options.establishedMinCensusCount ?? DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT;

  const readFacts = options.readFactPoints ?? readFactPoints;
  const readResult = await readFacts(descartesPaths, { windowMs, now: options.now });
  const { points, corrupt_count: corruptFactCount } = readResult;
  const groups = groupServiceFactsByTick(points);

  const loadStore = options.loadServiceAppearanceBaselineStore ?? loadServiceAppearanceBaselineStore;
  const { state: persistedState, corrupt: corruptBaselineStore, missing: missingBaselineStore } = await loadStore(descartesPaths);

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS;
  const currentGroups = groups.filter((group) => {
    const groupMs = new Date(group.ts).getTime();
    return Number.isFinite(groupMs) && groupMs <= nowMs;
  });

  const factsCorruptThisTick = Boolean(corruptFactCount);
  const storeLossThisTick = corruptBaselineStore === true || missingBaselineStore === true;
  const persistedAnchorMissingOrFuture = (persistedState.cold_start_pending && !isValidIsoTimestamp(persistedState.cold_start_since_ts))
    || (isValidIsoTimestamp(persistedState.cold_start_since_ts)
      && new Date(persistedState.cold_start_since_ts).getTime() > nowMs);
  const historyTrust = factHistoryTrustworthy(readResult, { anchorTs: persistedState.cold_start_since_ts, nowMs });
  const completenessLossAfterAnchor = hasCompletenessLossAfterAnchor(readResult, persistedState.cold_start_since_ts, nowMs);
  const enteringColdStart = factsCorruptThisTick
    || storeLossThisTick
    || persistedAnchorMissingOrFuture
    || completenessLossAfterAnchor
    || (!persistedState.cold_start_pending && !historyTrust.trust);

  const coldStartPendingThisTick = persistedState.cold_start_pending || enteringColdStart || !historyTrust.trust;

  let nextColdStartPending = persistedState.cold_start_pending;
  let nextColdStartReason = persistedState.cold_start_reason;
  let nextColdStartSinceTs = persistedState.cold_start_since_ts;

  if (enteringColdStart) {
    nextColdStartPending = true;
    nextColdStartReason = storeLossThisTick ? persistedState.cold_start_reason : "corrupt_facts";
    nextColdStartSinceTs = nowIso;
  } else if (persistedState.cold_start_pending && historyTrust.trust) {
    const sinceMs = persistedState.cold_start_since_ts ? new Date(persistedState.cold_start_since_ts).getTime() : Infinity;
    const reestablishedTickCount = currentGroups.filter((group) => {
      const groupMs = new Date(group.ts).getTime();
      return group.censusState === "complete" && groupMs > sinceMs && groupMs <= nowMs;
    }).length;
    if (reestablishedTickCount >= minHistoryTickCount) {
      nextColdStartPending = false;
    }
  }

  const appearances = coldStartPendingThisTick
    ? []
    : detectServiceAppearances(currentGroups, { nowMs, freshnessMs, minHistoryTickCount: establishedMinCensusCount });

  const persistedLastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const lastFoldedWasFuture = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs > nowMs;
  const lastFoldedMs = Number.isFinite(persistedLastFoldedMs) && persistedLastFoldedMs <= nowMs ? persistedLastFoldedMs : -Infinity;
  const effectiveLastFoldedTs = lastFoldedMs === -Infinity ? undefined : persistedState.last_folded_ts;
  const newGroups = currentGroups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);
  const coldStartStateChanged = nextColdStartPending !== persistedState.cold_start_pending
    || nextColdStartReason !== persistedState.cold_start_reason
    || nextColdStartSinceTs !== persistedState.cold_start_since_ts;
  if (newGroups.length > 0 || coldStartStateChanged || lastFoldedWasFuture) {
    const newGroupTsSet = new Set(newGroups.map((group) => group.ts));
    const newPartialCount = newGroups.filter((group) => group.censusState === "partial").length;
    const newAppearedCount = appearances.filter((entry) => newGroupTsSet.has(entry.first_seen_ts)).length;
    const lastFoldedTs = newGroups.length > 0 ? newGroups[newGroups.length - 1].ts : effectiveLastFoldedTs;
    const nextState = {
      version: 2,
      last_folded_ts: lastFoldedTs,
      skipped_partial_tick_count: persistedState.skipped_partial_tick_count + newPartialCount,
      appeared_event_count: persistedState.appeared_event_count + newAppearedCount,
      cold_start_pending: nextColdStartPending,
      cold_start_reason: nextColdStartReason,
      cold_start_since_ts: nextColdStartSinceTs,
    };
    const writeStore = options.writeServiceAppearanceBaselineStore ?? writeServiceAppearanceBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  if (coldStartPendingThisTick) return [];

  return buildAppearedCandidates(appearances);
}
