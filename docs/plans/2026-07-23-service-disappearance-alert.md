# Service-disappearance ALERT — new opt-in baseline slice

**Created:** 2026-07-23
**Purpose:** design + sequence a new, opt-in, deterministic `service.disappeared` alert that diffs
an expected-vs-seen service set and fires when a previously-established service stops appearing in
a fresh, complete census — the deferred #1 "Next-action option" in `docs/HANDOFF.md`, consuming the
already-shipped Slice C `service.census` marker (`8c3d70d`) and Slice B freshness bound (`924d819`)
from `docs/plans/2026-07-16-codex-findings-hardening.md`.
**Status:** IMPLEMENTED (step 1 of Sequencing) 2026-07-23 — `service-baseline.js` + its own test
file landed, plus the `daemon.js`/`alert-intelligence.js` wiring (step 2), per orchestrator
resolution of both blocking operator decisions the same day (see "Operator decisions required
before implementation" below). Sequencing steps 3-5 (full `npm test`/escalation-lint, adversarial
verifier pass, HANDOFF update) remain open — owned by the orchestrator, not this sub-agent.
**Reviewed:** 2026-07-23 (Stage 1 adversarial gate) — GO_WITH_CHANGES. Must-fixes folded into this
plan: (1) entity_key cleartext-vs-hash decision resolved with fail-closed (hash/counts-only) as the
shipped default pending explicit operator override; (2) set-diff-vs-Welford deviation now a
blocking operator sign-off, not an implicit default; (3) store-counter fold semantics pinned
(increment only at fold time, never per candidate computation) with a dedicated regression test
added to the test plan.
**Addendum:** 2026-07-23 — 3-lens adversarial verify pass surfaced 4 findings; orchestrator
resolutions:
  1. (high, FIXED) `buildDisappearedCandidates`'s `fingerprint` field carried the RAW entity_key,
     which `alert-store.js`'s `normalizeAlertRecord` persists verbatim and the generic
     `descartes alerts list/watch/ack --json` CLI surfaces dump uncompacted — a real cleartext leak
     of the raw service identity distinct from (and beyond) the diagnostics/body hash-only path.
     Fixed by hashing `fingerprint` (and the `id` derived from it) with the same
     `hashServiceEntityKey` already used for `diagnostics.entity_key_hash`, in
     `service-baseline.js`. This also resolves the related low-severity finding (raw `fingerprint`
     contradicting the hash-only framing) as a side effect — no separate action needed there.
  2. (medium, FIXED) `groupServiceFactsByTick` treated any `census_state` value other than the
     literal string `"partial"` as `"complete"`, so a garbled/unrecognized marker value (disk
     corruption, future schema drift) would silently upgrade to a trusted complete census instead
     of degrading safely. Fixed with a strict three-way match (`"complete"` / `"partial"` / a new
     fail-closed `"unknown"` disposition for anything else), excluded from the
     established/comparison set exactly like `"partial"`/markerless today.
     `session-baseline.js`'s `groupSessionFactsByTick` shares the identical latent gap but is out
     of scope for this task's file list (touch-only `service-baseline.js`) — flagged as a residual
     follow-up.
  3. (low, test-coverage gap, SKIPPED for this task) The plan's own test plan committed to a
     `daemon.test.js` regression pinning `service.disappeared` in `runDaemonIteration`'s
     `extraCandidates` output and the `activeFreshnessMs` threading. `daemon.test.js` is not in
     this fix task's allowed file list; the `daemon.js`/`alert-intelligence.js` wiring itself was
     re-verified correct by inspection (`git diff` shows the seventh `extraCandidates` entry
     threading `activeFreshnessMs` identically to `computeActiveConstraintCandidates`). Flagged as
     a residual for the orchestrator to add in a follow-up touching `daemon.test.js`.
  4. (high, covered by fix #1) The CLI cleartext-exposure finding shares its root cause with #1
     above; hashing `fingerprint` at the source in `service-baseline.js` means the raw entity_key
     never enters `alerts.json` or any `--json` CLI surface in the first place, so no separate
     `alerts.js`/`alert-store.js` change was needed. Regression coverage added in
     `service-baseline.test.js` (asserts the raw entity_key appears nowhere in the full persisted
     candidate object, not just `diagnostics`) rather than a CLI-level test, since `alerts.js` is
     out of scope for this task's file list.

## Context

The observed-incident-collectors milestone shipped `session-baseline.js` (`session.count_drop` +
`session.churn`) and `peer-baseline.js` (`peer.count_spike`) as deterministic, non-LLM baseline
alerting slices over already-persisted fact-history. The Codex-findings-hardening plan closed a
prerequisite gap for services specifically: before Slice C, a service that vanished simply stopped
producing `service.presence` facts, indistinguishable from "collector didn't run this tick." Slice C
(`8c3d70d`) added a `service.census` marker fact (distinct `fact_name`, reserved
`SERVICE_CENSUS_MARKER_ENTITY_KEY`, `confidence:0`, `attributes.census_state: "complete"|"partial"`)
so "the services collector ran, and here is whether its enumeration was complete" is representable.
Slice B (`924d819`) added an opt-in freshness bound (`ACTIVE_FRESHNESS_MULTIPLE = 3` × the
STRUCTURAL interval) so a vanished service's stale `running:"true"` fact stops reading "satisfied"
in constraint eval. Neither shipped the disappearance *alert* itself — both plans explicitly deferred
it as "a new opt-in baseline slice analogous to session-baseline," which is this plan.

## Operator decisions required before implementation (BLOCKING)

**RESOLVED by the orchestrator on 2026-07-23 — both decisions below, prior to dispatching
TDD-IMPLEMENT #1:**

1. **entity_key cleartext vs hash/counts-only:** HASH-ONLY (the fail-closed default already folded
   into this plan's text below). The alert body/diagnostics carry `entity_key_hash` only; the raw
   service name is NEVER delivered or placed in the notification body. Cleartext exposure remains
   explicitly DEFERRED pending a future, separately-approved operator decision, which would also
   require same-commit updates to the `emitSessionAlertSignals` / `buildSessionAlertNotificationDecision`
   invariant doc-comments plus any pinning tests (unchanged from this plan's own text below).

   **RESOLVED (superseding the above) — OPERATOR DECISION 2026-07-24: CLEARTEXT/SANITIZED NAME
   APPROVED, scoped to `service.disappeared` only.** The `service.disappeared` notification
   body/diagnostics now name the disappeared service in cleartext, using the SANITIZED
   (charset-bounded via `sanitizeIdentityString`/`sanitizeEntityKey`, never raw/unsanitized) service
   name — `diagnostics.service_name` in `service-baseline.js`'s `buildDisappearedCandidates`, and
   `alert-intelligence.js`'s `buildSessionAlertNotificationDecision` service.disappeared branch
   interpolates it into the delivered body. `entity_key_hash` is retained alongside it, and
   `fingerprint`/`id` (the dedup/edge-trigger keys) stay hash-derived, unaffected by this decision.
   **Rationale:** this is a LOCAL notification to the machine's own operator, and knowing WHICH
   service vanished is the entire operational point of the alert — unlike session/peer identity,
   where the specific session/peer is irrelevant and hashing loses no signal. **Scope:** this
   REVERSES the fail-safe hash-only default shipped in commit `47e6637` for `service.disappeared`
   ONLY. `session.churn`/`session.count_drop` and `peer.count_spike`/`peer.count_drop` are
   UNCHANGED and remain hash-only/counts-only — this is not a blanket relaxation of the module's
   general hash-only body discipline. Both `emitSessionAlertSignals`'s and
   `buildSessionAlertNotificationDecision`'s invariant doc-comments in `alert-intelligence.js`, and
   `service-baseline.js`'s own header/FAIL-CLOSED-DEFAULT comments, were updated in the same change
   to describe this scoped exception precisely (not as a general relaxation). Tests in
   `service-baseline.test.js`/`alert-intelligence.test.js` were flipped from "raw entity_key never
   appears" to "the sanitized service name IS shown, and is charset-sanitized (no control chars)",
   with new/kept regression coverage asserting session/peer delivery paths remain hash-only.
2. **set-diff vs literal windowed-Welford:** SET-DIFF (session.churn-shaped edge-triggered
   set-membership diff), NOT a windowed Welford mirror. `welford-stats.js` stays untouched except
   for reusing the generic `DEFAULT_BASELINE_FACT_WINDOW_MS` constant. The review chain converged on
   this design decision being sound (disappearance is inherently a set-membership question, not a
   count distribution).
3. **Severity:** UNCONDITIONALLY `"warning"` (hard cap, peer.count_spike-style; no critical tier) —
   already the plan's stated design, reconfirmed as-is, not one of the two blocking decisions above.

Implemented exactly to these resolutions in `tools/descartes-cli/src/service-baseline.js` +
wiring, landed same day.

---

Two decisions below must be explicitly confirmed by the operator BEFORE any code in this plan is
written. Neither is resolved by silent default in the plan text anymore — both must-fixes from the
Stage 1 adversarial review land here.

1. **entity_key cleartext vs hash/counts-only in the notification banner body — fail-closed is the
   shipped default.** `emitSessionAlertSignals`'s header comment (`alert-intelligence.js` ~line 343)
   states the delivered body is "counts/hash-only — never a raw session name," and
   `buildSessionAlertNotificationDecision`'s header comment (~line 370) states every interpolated
   field is "a finite number or a short closed-enum/hash string." `service.presence` entity_keys are
   sanitized (charset-gated) but explicitly **NOT hashed** at source
   (`fact-translators.js:24-25`) — unlike session/peer identity, which is hashed before it ever
   reaches a fact point. `sanitizeDiagnostics` is a charset gate, not a hashing step, so a raw
   service name flows through it unchanged; nothing downstream catches it. Shipping the plan's
   original cleartext-by-default body would be the first raw identity ever pushed through the
   deterministic delivery path and would directly contradict both documented invariants above.
   **Resolution:** this plan now ships the **fail-closed, counts/hash-only body by default** (see
   the updated `buildSessionAlertNotificationDecision` branch and `buildDisappearedCandidates`
   diagnostics below). If the operator explicitly wants the cleartext service name surfaced instead
   (arguably more actionable for an operator-facing alert than a hash), that is a separate,
   explicitly-approved decision that must (a) be recorded here before implementation and (b) update
   both invariant doc-comments above plus any tests pinning them, in the SAME commit that introduces
   the cleartext body — never as a silent default.
2. **set-diff over `session.churn`'s shape vs a literal windowed-Welford mirror of
   `welford-stats.js` — requires explicit sign-off.** The task brief's literal wording was "mirror...
   windowed Welford." This plan's design decision (below) instead mirrors `session.churn`'s
   set-membership/edge-triggered shape, leaving `welford-stats.js` untouched apart from reusing its
   generic `DEFAULT_BASELINE_FACT_WINDOW_MS` constant. The design argument is sound (disappearance
   is inherently set-membership, not a count distribution), but it is a deviation from the literal
   brief and must not ship on an implicit default. **This must be confirmed by the operator before
   `service-baseline.js` is written.** If the operator instead wants a literal Welford companion
   metric (e.g., a windowed z-score over the count of present services, as a second, additive
   signal), that is out of scope for this plan and would need its own follow-up decision.

Both decisions are also cross-referenced at their point of use below (`needs_operator_input`
markers throughout this plan point back to this section).

## Design decision: set-diff, not Welford (deviation from the literal task wording, documented)

The task brief says "mirror... windowed Welford (`welford-stats.js`)." The actual detection this
slice needs — a service present in an established recent census, absent from the newest complete
census — is a **set-membership diff**, not a count-distribution trigger. It is genuinely closer in
shape to `session.churn`'s per-entity fingerprint comparison (edge-triggered, per-entity, computed
fresh from fact-history every call, no persisted Welford accumulator) than to `session.count_drop` /
`peer.count_spike`'s windowed z-score.

**Decision:** this slice does NOT use `welford-stats.js`'s Welford/z-score math (no statistical
"count of services dropped" companion metric — that would be a second, separate concern outside this
slice's scope, YAGNI). It mirrors `session.churn`'s shape: stateless-per-call detection over a bounded
read window, edge-triggered (fires on the tick where a service's presence transitions from
seen→absent), not a continuously-active state. `welford-stats.js` is untouched by this plan — flagged
here explicitly rather than silently resolved, per the recon seam-map's own open question. Per Stage 1
review, this is now a BLOCKING operator sign-off (see "Operator decisions required before
implementation" above), not an implicit default — the operator must confirm this design decision, or
request a literal Welford companion metric instead/in addition, before `service-baseline.js` is
written.

The module still **mirrors the sibling MODULE SHAPE** required by the recon seam-map: its own
store file (`learned/service-baseline.json`, atomic tmp+rename 0o600, corrupt-tolerant,
load/write/normalize functions), its own tick-grouping function, its own candidate builder(s), its
own `computeServiceBaselineCandidates(descartesPaths, options)` `extraCandidates` entry gated by the
same `loadLearnedConfig(...).enabled` short-circuit-to-`[]` before any I/O — just with set-diff logic
in place of Welford where the sibling would have folded a windowed mean/stddev.

## New module: `tools/descartes-cli/src/service-baseline.js`

### Facts consumed

- `service.presence` (existing, `fact-translators.js:factPointsFromServiceEvidence`) — one point per
  service per structural tick, `entity_key` = sanitized (NOT hashed) service name/label,
  `attributes.running`/`attributes.manager`.
- `service.census` (Slice C, `8c3d70d`) — one marker point per structural tick the services collector
  ran with status `ok`/`warning`, `entity_key = SERVICE_CENSUS_MARKER_ENTITY_KEY`, `confidence:0`,
  `attributes.census_state: "complete"|"partial"`. Import `SERVICE_CENSUS_FACT_NAME` and
  `SERVICE_CENSUS_MARKER_ENTITY_KEY` directly from `fact-translators.js` (no re-implementation).

Both fact_names are read from the SAME `readFactPoints` window (it returns every fact_name in range,
confirmed against `fact-store.js:169-186` — there is no fact_name filter parameter), so
`groupServiceFactsByTick` must itself discriminate on `point.fact_name`, unlike
`session-baseline.js`'s `groupSessionFactsByTick` (which only ever sees one fact_name because
sessions' census marker deliberately reuses `session.presence`'s own fact_name — services can't do
that, per Slice C's own must-fix reasoning about entity_key collision, hence the distinct
`service.census` fact_name).

### Store I/O — `resolveServiceBaselineStorePaths` / `loadServiceBaselineStore` / `writeServiceBaselineStore`

Mirrors `session-baseline.js`/`peer-baseline.js` exactly: `path.join(stateDir, "learned",
"service-baseline.json")`, `fs.mkdir(..., {recursive:true, mode:0o700})`, atomic
`tmp+rename` write at `0o600`, ENOENT → fresh state, corrupt JSON → fresh state with
`corrupt:true` surfaced (never throws out of a daemon tick).

**Deliberately lean state shape (scope decision, documented):** unlike `session-baseline.js`'s
persisted Welford accumulator (which exists because Welford wants a running mean/variance),
service-disappearance detection is recomputed **fully fresh from the read window on every call**,
exactly like `detectSessionChurn`'s own statelessness — the read window (bounded by
`DEFAULT_BASELINE_FACT_WINDOW_MS`, already ≤ fact-store's 30-day retention) is sufficient to
recompute "is this entity_key established" and "did it just disappear" without any persisted
per-entity map. A persisted per-entity map (`known_services: {...}`) was considered and rejected:
services come and go over a machine's lifetime, and an unbounded-growth per-entity map is a
self-inflicted leak/staleness-tracking problem the sibling modules don't have (they only ever
persist scalar Welford state). The store therefore persists only cheap, genuinely-cumulative
bookkeeping that is NOT re-derivable from a bounded window alone (mirrors
`session-baseline.js`'s own stated rationale for `skipped_overflow_tick_count`):

```js
{
  version: 1,
  last_folded_ts: string | undefined,
  skipped_partial_tick_count: number,   // partial-census tick-groups seen and excluded
  disappearance_event_count: number,    // cumulative count of service.disappeared firings, ages out of the window but is a useful lifetime counter
}
```

**Fold-time-only increment semantics (Stage 1 review must-fix 3, pinned here as a normative rule):**
`skipped_partial_tick_count` and `disappearance_event_count` increment ONLY at fold time — i.e. only
for tick-groups newly observed beyond `last_folded_ts` on a given call, exactly once per genuinely new
tick-group/event, never per candidate computation. This matters because `computeServiceBaselineCandidates`
recomputes `detectServiceDisappearances` fresh from the whole read window on every call (see above),
including calls where no new tick-group has landed since `last_folded_ts` — under the daemon's
fast-tick re-emission convention, the SAME complete-census pair straddling a disappearance transition
is re-evaluated on every fast tick until the next structural tick moves the window forward. If either
counter were incremented per candidate computation (i.e. once per `detectServiceDisappearances` call
that returns a hit) rather than per fold, `disappearance_event_count` would inflate by roughly
fast-ticks-per-structural-tick for every genuine event — the counter must increment exactly once per
event, matched 1:1 against tick-groups actually newly folded past `last_folded_ts`. The write path
(step in `computeServiceBaselineCandidates` below) must gate both counter increments behind
`newGroups.length > 0`, using only the newly-folded groups/events for the increment amount, never the
full recomputed `disappearances` array length.

`computeServiceBaselineCandidates` still writes this store on every tick that finds a new
tick-group since `last_folded_ts` (mirrors siblings' "at-most-one write per batch of unchanged
history" convention) purely for cheap cross-process observability (`descartes learned`-style
tooling) — never load-bearing for the candidate computation itself, which recomputes fresh from
`groupServiceFactsByTick(points)` every call, matching session-baseline.js's own "Implementation
note on re-derives fresh" doc-comment posture.

### Tick-grouping — `groupServiceFactsByTick(points)`

Returns tick-groups ordered ascending by `ts`, each `{ ts, censusState, entityKeys: Set<string> }`:

- `censusState`: `"complete"` | `"partial"` | `undefined` (no census marker landed for this tick —
  a markerless/legacy tick-group, exactly mirroring `session-baseline.js`'s own three-way
  `censusState` semantics).
- `entityKeys`: the set of `service.presence` entity_keys observed in this tick (the census marker's
  own reserved entity_key is never added to this set — mirrors sessions/peers excluding their
  markers from the "real" count/set).
- A tick-group exists whenever ANY `service.presence` OR `service.census` point shares that `ts`
  (mirrors `peer-baseline.js`'s "a tick-group exists whenever any point shares that ts, even an
  all-excluded tick" — a genuine zero-service census still produces `{censusState:"complete",
  entityKeys: new Set()}`, never silently skipped, matching Slice C's own "zero-service tick still
  gets a marker" precedent).

### Established-set + disappearance detection — `detectServiceDisappearances(groups, options)`

Pure function, no I/O, mirrors `detectSessionChurn`'s shape and statelessness:

1. Filter to `censusState === "complete"` tick-groups only (`"partial"` and `undefined`/markerless
   groups are excluded WHOLESALE from both the established-count accumulation and the disappearance
   comparison — degrade-not-fabricate: an undercounted or markerless census must never manufacture a
   false disappearance, mirroring `session-baseline.js`'s must-fix-2 partial-exclusion discipline).
2. If fewer than 2 complete tick-groups exist in the window → return `[]` (no claim; nothing to
   diff against).
3. **Established gate (cold-start protection, PROVISIONAL constant like every sibling sigma/floor):**
   an entity_key is "established" iff it appears in at least
   `DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT` (default **3**, PROVISIONAL, exported, tuned
   post-ship like `DEFAULT_DEVIATION_SIGMA`/`DEFAULT_STDDEV_FLOOR`) of the complete tick-groups in
   the window — option (b) from the recon seam-map's open question, chosen over a single-prior-census
   check (too flap-prone: one missed census tick would look identical to a genuine disappearance) and
   over "present since first observation" (too strict: would never fire for a service the collector
   started tracking mid-window, and drifts toward requiring the full 31-day window to be populated).
4. **Trigger (edge, K=1, mirrors `detectSessionChurn`'s own recency bound exactly):** for each
   entity_key established per step 3, if it is present in the second-most-recent complete tick-group
   AND ABSENT from the single most recent complete tick-group, it fires — a pairwise newer-vs-older
   set comparison, the direct set-membership analogue of churn's fingerprint comparison. This is
   edge-triggered (fires once, on the tick where the transition happens), not a continuously-active
   state — if the service stays gone, later ticks see it present in neither of the two ticks being
   compared and the pair no longer straddles the transition, so it stops firing on its own (no
   forever-firing candidate, no dedicated "resolved" bookkeeping needed here — `alert-store.js`'s
   existing cooldown/resolution machinery, already proven by `session.churn`, handles the rest).
5. **Freshness gate (Slice B's own reasoning, reimplemented independently — NOT via
   `buildShadowFactLookup`, which this module never calls):** the disappearance is only emitted if
   the most recent complete tick-group's `ts` is itself fresh relative to `now` — within
   `options.activeFreshnessMs` (see wiring below). A stale-but-technically-"complete" tick-group
   (the daemon hasn't run structurally in a while, or `readFactPoints`'s window boundary happens to
   land on an old complete tick) must never be read as "the service is missing NOW" — it degrades to
   no-claim instead. This directly satisfies the "degrade-not-fabricate" invariant Slice B already
   established for constraint eval, reimplemented here because this module's own read path
   (`readFactPoints` → `groupServiceFactsByTick`) is independent of `buildShadowFactLookup`'s data
   shape (confirmed not reusable — the seam-map's own finding).

Returns `[{ entity_key, disappeared_at_ts, last_seen_ts, complete_census_seen_count }]`.

### Candidate builder — `buildDisappearedCandidate(entry)`

Mirrors `buildChurnCandidates`/`buildCountSpikeCandidate`'s shape:

```js
export const SERVICE_DISAPPEARED_RULE_ID = "service.disappeared";

export function buildDisappearedCandidates(entries = []) {
  return entries.map((entry) => {
    // FAIL-CLOSED DEFAULT (Stage 1 review must-fix 1): entity_key is sanitized-but-NOT-hashed at
    // source (fact-translators.js:24-25). Per "Operator decisions required" above, diagnostics
    // carry a HASH of entity_key, never the raw string, unless/until the operator explicitly
    // approves a cleartext exposure (which would additionally require updating the
    // emitSessionAlertSignals / buildSessionAlertNotificationDecision invariant doc-comments in the
    // same commit). `hashEntityKey` mirrors whatever short-hash helper session/peer identity
    // hashing already uses at fact-emission time. No shared entity-key-hash helper exists yet
    // (fact-translators.js:hashSessionIdentity/constraint-store.js/alert-store.js each hash their
    // own domain-prefixed string with `crypto.createHash("sha256")...slice(0, 16)`), so this adds a
    // small local `hashServiceEntityKey(entityKey)` following the SAME convention: a
    // domain-prefixed sha256, truncated to 16 hex chars, e.g.
    // `createHash("sha256").update(\`service.disappeared:${entityKey}\`).digest("hex").slice(0, 16)`.
    const diagnostics = sanitizeDiagnostics({
      entity_key_hash: hashServiceEntityKey(entry.entity_key),
      last_seen_ts: entry.last_seen_ts,
      complete_census_seen_count: entry.complete_census_seen_count,
    });
    return {
      id: alertId(SERVICE_DISAPPEARED_RULE_ID, entry.entity_key),
      rule_id: SERVICE_DISAPPEARED_RULE_ID,
      fingerprint: entry.entity_key,
      // Severity capped at "warning" UNCONDITIONALLY — mirrors buildCountSpikeCandidate's
      // MUST-FIX-1-style hard cap (peer-baseline.js), NOT session.count_drop's two-tier
      // warning/critical model. Confirmed against the task brief's explicit "severity capped at
      // warning" wording, read as the unconditional-cap reading — not one of the two Stage 1
      // blocking operator decisions (see "Operator decisions required before implementation"),
      // kept here as-is.
      severity: "warning",
      title: "Service disappeared",
      summary: "A previously-established service stopped appearing in the latest complete service census.",
      diagnostics,
      evidence_refs: ["service-baseline"],
    };
  });
}
```

No critical tier is ever emitted by this rule in v0 — matches `peer.count_spike`'s posture exactly,
not `session.count_drop`'s two-tier model, per the task's explicit "severity capped at warning."

### Fast-tick entry point — `computeServiceBaselineCandidates(descartesPaths, options)`

Same signature/short-circuit shape as every sibling:

```js
export async function computeServiceBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];   // default-OFF kill switch, checked before ANY I/O

  const windowMs = options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS; // reused from welford-stats.js — generic read-window bound, not a Welford use
  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupServiceFactsByTick(points);

  const loadStore = options.loadServiceBaselineStore ?? loadServiceBaselineStore;
  const { state: persistedState } = await loadStore(descartesPaths);
  // Fold-time-only counters (must-fix 3): identify tick-groups with ts strictly newer than
  // persistedState.last_folded_ts ("newGroups"). skipped_partial_tick_count increments by the
  // count of newGroups with censusState === "partial"; disappearance_event_count increments by the
  // count of disappearance events whose disappeared_at_ts falls within newGroups (computed against
  // this call's own detectServiceDisappearances() result below, filtered to newGroups' timestamps —
  // NOT the full disappearances array, which may re-report the same still-fresh event across many
  // fast ticks). Both increments — and last_folded_ts's advance — are gated behind
  // newGroups.length > 0; write only when newGroups.length > 0 (mirrors siblings' "at-most-one
  // write per batch" convention). On a tick with zero new tick-groups, no counter changes and no
  // store write happens, even if detectServiceDisappearances still reports the same event as it
  // did last tick.

  const nowMs = options.now !== undefined ? new Date(options.now).getTime() : Date.now();
  const freshnessMs = options.activeFreshnessMs ?? DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS;
  const minEstablishedCount = options.establishedMinCensusCount ?? DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT;

  const disappearances = detectServiceDisappearances(groups, { nowMs, freshnessMs, minEstablishedCount });
  return buildDisappearedCandidates(disappearances);
}
```

**No circular import:** `DEFAULT_SERVICE_FRESHNESS_FALLBACK_MS` is a small, LOCALLY-defined constant
in `service-baseline.js` (`3 * 60 * 60 * 1000` = 3h, matching Slice B's documented default), NOT
imported from `daemon.js` — `daemon.js` already imports `session-baseline.js`/`peer-baseline.js`, so
`service-baseline.js` importing `daemon.js`'s `DEFAULT_STRUCTURAL_INTERVAL_MS`/
`ACTIVE_FRESHNESS_MULTIPLE` would create an import cycle. Instead, mirror the exact pattern
`computeActiveConstraintCandidates` already uses: `daemon.js` resolves the real
`activeFreshnessMs = ACTIVE_FRESHNESS_MULTIPLE * structuralIntervalMs` once per tick (already
computed at `daemon.js:411`) and threads that SAME value in via `options.activeFreshnessMs` at both
call sites — `computeServiceBaselineCandidates` reads `options.activeFreshnessMs` first, falling back
to its own local 3h constant only for direct/unit-test invocation that doesn't thread it. This
reuses the single already-correct freshness horizon rather than inventing a second knob that could
drift from Slice B's.

## Wiring edits (exact files, exact insertion points)

### 1. `tools/descartes-cli/src/daemon.js` — new `extraCandidates` entry

- Import: `import { computeServiceBaselineCandidates } from "./service-baseline.js";` alongside the
  existing `computeSessionBaselineCandidates`/`computePeerBaselineCandidates` imports (~lines 18-20).
- In `runDaemonIteration`'s `extraCandidates` array (currently lines ~526-554, six entries), add a
  seventh entry threading the SAME `activeFreshnessMs` already resolved at line 411 (the same value
  passed to `computeActiveConstraintCandidates` at line 527):

  ```js
  ...await computeServiceBaselineCandidates(descartesPaths, { ...options, activeFreshnessMs }),
  ```

  No other daemon.js change — no new gating besides the module's own `loadLearnedConfig` check
  (matches every sibling entry's convention exactly).

### 2. `tools/descartes-cli/src/alert-intelligence.js` — deterministic local delivery + fail-closed-by-omission

- **`classifyAlertNamespace` (lines 637-654): NO new branch added, deliberately.** `service.` falls
  through the closed map to `{ namespace: undefined, hardExcluded: false }` → `reason:
  "unknown_namespace"` in `classifyAlertEligibility` → structurally can never reach
  `adjudicateAlertNotifications`'/LLM path, exactly like `session.*`/`peer.*`/`correlation.*` — wait,
  `correlation.*` DOES have a branch (it's the one namespace deliberately opted toward eventual LLM
  adjudication via S13's per-namespace consent). `service.*` follows the `session.*`/`peer.*`
  precedent instead: fail-closed BY OMISSION, no branch, no `PROMPT_TEMPLATES` entry, no
  `enabled_namespaces` opt-in path exists for it at all. This is the correct precedent per the task's
  explicit "fail-closed `service.*` namespace" requirement.
- **Deterministic local delivery allowlist** — import `SERVICE_DISAPPEARED_RULE_ID` from
  `service-baseline.js` (new import line, alongside the existing `PEER_COUNT_SPIKE_RULE_ID` /
  `session-baseline.js` imports at lines 5-10) and widen the module-private
  `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (line 22) from
  `[...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, PEER_COUNT_SPIKE_RULE_ID]` to
  `[...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, PEER_COUNT_SPIKE_RULE_ID, SERVICE_DISAPPEARED_RULE_ID]`
  — mirrors the exact must-fix-4 pattern peer-baseline's own rule_id followed (composed HERE, not in
  the sibling module, to avoid a forbidden `service-baseline.js` ↔ `session-baseline.js` coupling).
- **`buildSessionAlertNotificationDecision` (~lines 375-410): new `if (alert?.rule_id ===
  SERVICE_DISAPPEARED_RULE_ID)` branch**, inserted before the generic fail-closed fallback at the
  end. Body text is **fail-closed, hash-only by default** per "Operator decisions required before
  implementation" above — the module header invariants ("counts/hash-only — never a raw session
  name"; "a finite number or a short closed-enum/hash string") are preserved unmodified, not
  relaxed:

  > **SUPERSEDED 2026-07-24** — this code block and the "If the operator later approves..."
  > paragraph below it describe the pre-resolution, hash-only-by-default design and the
  > never-shipped `diagnostics.entity_key` field name. The operator decision was resolved the same
  > day (see the top-of-file header and "Operator decisions required before implementation" below):
  > the shipped branch names the service in cleartext via the SANITIZED `diagnostics.service_name`
  > field (never `diagnostics.entity_key`), with a fallback to `diagnostics.entity_key_hash` when
  > `service_name` isn't a plain string. See `src/alert-intelligence.js`'s actual
  > `SERVICE_DISAPPEARED_RULE_ID` branch for the live implementation. Left below for historical
  > context only — do not use it as a spec.

  ```js
  if (alert?.rule_id === SERVICE_DISAPPEARED_RULE_ID) {
    return {
      notify: true,
      severity: "warning",
      title: "Descartes: service disappeared",
      body: `A previously-established service (id ${diagnostics.entity_key_hash}) stopped appearing in the latest complete census (last seen ${diagnostics.last_seen_ts}).`,
    };
  }
  ```

  If the operator later approves cleartext service names (see "Operator decisions required"
  above), this branch's `diagnostics.entity_key_hash` becomes `diagnostics.entity_key` and BOTH
  `emitSessionAlertSignals`'s and `buildSessionAlertNotificationDecision`'s header doc-comments must
  be updated in the same commit to describe the new exception, along with any test that currently
  pins the old "hash-only" wording.

### 3. `tools/descartes-cli/src/fact-translators.js` — NO CHANGE

`SERVICE_CENSUS_FACT_NAME`/`SERVICE_CENSUS_MARKER_ENTITY_KEY`/`factPointsFromServiceEvidence` already
shipped (`8c3d70d`) and are imported as-is.

### 4. `tools/descartes-cli/src/welford-stats.js` — NO CHANGE

Confirmed by the design decision above: this slice is set-membership, not count-statistical. Only
`DEFAULT_BASELINE_FACT_WINDOW_MS` is reused (already a generic, domain-agnostic read-window bound,
not Welford math) — a plain import, no modification.

### 5. `tools/descartes-cli/src/alerts.js` — NO CHANGE

`KNOWN_ALERT_NAMESPACES` stays untouched (`service.*` is fail-closed by omission, mirrors
`session.`/`peer.`, not a new consentable namespace like `correlation` was). No new CLI subcommand
(mirrors session/peer, which expose no dedicated CLI surface).

### 6. `tools/descartes-cli/src/alert-store.js` — NO CHANGE

`evaluateAndPersistAlerts`'s `extraCandidates` merge (line ~287) already generically accepts any
candidate array via `[...candidates, ...extraCandidates]`; the new module's candidates flow through
`daemon.js`'s `extraCandidates` concat exactly like every sibling.

## Collision risk with the other in-flight slice

Per the recon seam-map: `daemon.js`'s `extraCandidates` array (lines ~516-556) and
`alert-intelligence.js`'s `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (line ~22) +
`buildSessionAlertNotificationDecision` (~lines 375-410) are the two files every prior
observed-incident-collectors alerting slice (4, 4b, 6) also touched. **If any other task dispatched
in this batch also adds an `extraCandidates` entry or a new deterministic-delivery `rule_id`, it will
collide on the SAME small append-only hunks of these two files.** Both edits are mechanically simple
(append one array/import line) but risky under blind parallel dispatch to two agents at once.

**Recommendation:** serialize this slice against any other task in flight that also touches
`daemon.js`'s `extraCandidates` array or `alert-intelligence.js`'s
`ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS`/`buildSessionAlertNotificationDecision`/
`classifyAlertNamespace` — land one, rebase the other, rather than dispatching both writes
concurrently. If `classifyAlertNamespace`'s closed map is also being extended by a sibling task in
this batch (e.g. adding some OTHER new namespace), the two edits are on adjacent-but-distinct `if`
branches and should merge cleanly as long as they're not developed against a stale base.

## Safety invariants this slice must preserve

- **Default-OFF / opt-in.** `computeServiceBaselineCandidates` short-circuits to `[]` via
  `loadLearnedConfig(...).enabled` BEFORE any I/O — identical to every sibling, single `learned.json`
  kill switch, no independent flag.
- **Deterministic, no LLM.** No LLM call anywhere in `service-baseline.js`. The only path to a human
  notification is the hand-built, deterministic `emitSessionAlertSignals` branch in
  `alert-intelligence.js` — never `adjudicateAlertNotifications`.
- **Fail-closed namespace.** `service.*` has no `classifyAlertNamespace` branch → `unknown_namespace`
  → structurally excluded from `classifyAlertEligibility`'s `eligible` path regardless of
  `enabled_namespaces` content, exactly like `session.*`/`peer.*` today.
- **Degrade-not-fabricate.** A partial or markerless (no-marker) census tick-group is excluded
  wholesale from both the established-count accumulation and the disappearance comparison (never
  read as "these are all the services"). A stale-but-technically-complete latest census (beyond the
  freshness horizon) degrades to no-claim rather than firing. A cold-start entity_key (fewer than
  `DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT` complete-census sightings) can never fire — day-1 /
  first-run silence, matching every sibling's cold-start discipline.
- **Minimal scope (YAGNI).** No persisted per-entity map (leak/growth risk avoided — recomputed fresh
  from the bounded read window every call, mirroring `detectSessionChurn`'s own statelessness). No
  Welford/statistical companion metric (explicitly out of scope per the design decision above). No
  new CLI surface, no new `alerts.js` namespace registration.
- **No new execFile/shell/privilege-escalation surface.** This module performs zero host I/O of its
  own — it only reads already-persisted fact-history (`fact-store.js`) and its own small state file,
  exactly mirroring `session-baseline.js`'s/`peer-baseline.js`'s own posture.
- **Sanitize identity strings at source.** `entity_key` values arrive already sanitized (charset
  `[A-Za-z0-9._:-]`) via `fact-translators.js:sanitizeEntityKey` at fact-emission time — this module
  never re-derives or widens that sanitization; it only reads already-sanitized strings.
- **Hash, don't cleartext, in the delivered diagnostics/body (Stage 1 review must-fix 1).** Unlike
  session/peer identity (hashed at source), `service.presence` entity_keys are sanitized but NOT
  hashed at source. This module hashes `entity_key` locally (`hashServiceEntityKey`) before it ever
  reaches `diagnostics`/`sanitizeDiagnostics` or the notification body, so `emitSessionAlertSignals`'s
  "counts/hash-only — never a raw session name" and `buildSessionAlertNotificationDecision`'s
  "finite number or short closed-enum/hash string" invariants hold for this new rule_id exactly as
  they do for every existing one, by default. Raw `entity_key` is used ONLY as the internal
  `fingerprint`/dedup key (never delivered), matching how session/peer fingerprints are also
  internal-only. Shipping cleartext instead is a separate, explicitly-operator-approved decision —
  see "Operator decisions required before implementation." **Resolved 2026-07-24:** the operator
  approved cleartext, scoped to `service.disappeared` only; the shipped diagnostics field is named
  `service_name` (sanitized cleartext), not `entity_key` — see the SUPERSEDED note in the
  `alert-intelligence.js` section above.

## Test plan (TDD — mirror `session-baseline.test.js`/`peer-baseline.test.js`'s own structure)

New file `tools/descartes-cli/test/service-baseline.test.js`:

**Store I/O** (mirrors `session-baseline.test.js`'s store-I/O describe block):
- fresh state on ENOENT; corrupt JSON → fresh state + `corrupt:true`; atomic write (tmp file removed,
  final file `0o600`); `normalizeServiceBaselineState` rejects malformed shapes field-by-field.

**`groupServiceFactsByTick`:**
- a tick with `service.presence` points + a `"complete"` census marker → correct `entityKeys`
  set + `censusState:"complete"`, marker's own entity_key excluded from the set.
- `"partial"` census marker tick → `censusState:"partial"`.
- no marker at all for a tick (legacy/markerless) → `censusState:undefined`.
- an all-marker, zero-presence tick still produces a tick-group with `entityKeys: new Set()`
  (genuine zero-service census, never silently skipped — mirrors Slice C's own precedent).
- points from an unrelated `fact_name` (e.g. `session.presence`, `network.listening_port.owner`)
  sharing the read window are ignored entirely (regression-locks the "readFactPoints returns every
  fact_name" fact).

**`detectServiceDisappearances`:**
- fewer than 2 complete tick-groups in the window → `[]`.
- an entity_key seen in fewer than `DEFAULT_SERVICE_ESTABLISHED_MIN_CENSUS_COUNT` complete censuses,
  then absent → NOT fired (cold-start gate).
- an established entity_key present in the second-most-recent complete census, absent from the
  freshest complete census, freshest census fresh → FIRES.
- an established entity_key absent from a `"partial"` freshest-in-time tick-group → does NOT fire off
  that partial tick; only a genuinely `"complete"` tick-group counts as "the freshest complete
  census" (the partial tick is skipped over, not treated as a disappearance observation).
- a stale freshest-complete tick-group (beyond `activeFreshnessMs` relative to `now`) → does NOT
  fire, even though the entity_key is genuinely absent from it (freshness gate proven independent
  of the presence/absence logic).
- edge-triggered, not sticky: an established entity_key that disappeared on tick N and stays absent
  through tick N+1 fires ONLY on tick N's candidate computation (once the freshest-complete pointer
  has moved past N, the pair being compared no longer straddles the transition) — assert it does NOT
  re-fire indefinitely.
- a service that reappears after a fired disappearance is eligible to fire again on a LATER genuine
  disappearance (re-establishment via the same N-of-M gate, not a permanent one-shot flag).
- different entity_keys never interfere (parity with `detectSessionChurn`'s own per-entity isolation
  test).

**`buildDisappearedCandidates` / `computeServiceBaselineCandidates`:**
- `learned.json` disabled → `[]`, zero I/O (assert `readFactPoints`/`loadServiceBaselineStore` mocks
  are never called — matches every sibling's own short-circuit test).
- severity is ALWAYS `"warning"` (assert no code path can produce `"critical"` for this rule_id — a
  direct regression lock on the unconditional-cap decision, mirroring
  `peer-baseline.test.js`'s own MUST-FIX-1 assertion).
- `diagnostics` passes through `sanitizeDiagnostics` (assert shape, not raw passthrough).
- store write skipped on a tick with zero new tick-groups since `last_folded_ts` (at-most-one-write
  convention, mirrors sibling tests).
- **fold-time-only counter increment (Stage 1 review must-fix 3, dedicated regression lock):**
  simulate one genuine disappearance event followed by N repeated `computeServiceBaselineCandidates`
  calls against the SAME unchanged fact window (i.e. `last_folded_ts` does not advance because no
  new tick-group has landed — the fast-tick re-emission scenario) and assert
  `disappearance_event_count` increments by exactly 1 total, not once per call; then advance the
  window by one new complete tick-group and assert it does not increment again for the same
  already-counted event. Assert the analogous exactly-once-per-fold behavior for
  `skipped_partial_tick_count` against repeated calls spanning one newly-observed partial tick-group.
- re-emission every call: candidate list rebuilt fresh from the current window on every invocation,
  not dependent on whether a store write happened that tick (mirrors session/peer's own
  "re-emission every tick" test).

**Wiring tests (existing files, additive):**
- `daemon.test.js`: `runDaemonIteration` includes `service.disappeared` in `extraCandidates` output
  when the module's mock reports a candidate; assert `activeFreshnessMs` is threaded through
  identically to `computeActiveConstraintCandidates`'s own call (same value, single source).
- `alert-intelligence.test.js`: `classifyAlertNamespace("service.disappeared")` →
  `{namespace: undefined, hardExcluded: false}` (fail-closed-by-omission, direct regression lock);
  `service.disappeared` is `unknown_namespace` in `classifyAlertEligibility` even with every
  namespace in `enabled_namespaces` (airtight-even-with-consent test, mirrors the existing
  `session.*`/`peer.*` airtight tests); `emitSessionAlertSignals` delivers a due
  `service.disappeared` alert via `deliverNotificationDecision` (mocked), never via
  `adjudicateAlertNotifications`/an LLM path.

## Sequencing

0. **BLOCKING:** obtain explicit operator sign-off on both decisions in "Operator decisions required
   before implementation" (entity_key cleartext-vs-hash default; set-diff-vs-Welford design). Do not
   start step 1 until both are confirmed.
1. Land `service-baseline.js` + its own test file in isolation (no wiring yet) — TDD, all pure/I/O
   logic testable standalone against fixture fact-points, no daemon.js/alert-intelligence.js edits
   needed for this step.
2. Wire `daemon.js`'s `extraCandidates` entry + `alert-intelligence.js`'s allowlist/notification
   branch in one commit (the two touch the batch's known collision surface — see above; confirm no
   other in-flight task is mid-edit on either file before landing).
3. `node --check` on every touched file + full `npm test` (0 fail) + escalation-lint.
4. Adversarial verifier subagent pass (OVERALL_SAFE) focused on: fail-closed namespace airtightness
   even with `enabled_namespaces` fully opened; degrade-not-fabricate on partial/markerless/stale
   census ticks; cold-start gate; no unbounded store growth.
5. Fold findings, atomic commit, push, update `docs/HANDOFF.md` + the tracking todo.

## Non-goals

- No Welford/statistical companion metric for service counts (see design decision above; flagged as
  an open question for the operator, not silently added).
- No new CLI surface (`descartes services ...`) — mirrors session/peer's own no-dedicated-CLI
  posture.
- No change to `constraint-miner.js`/`buildShadowFactLookup` — this module does its own independent
  freshness reasoning over `service.presence`/`service.census` points; it does not go through
  constraint-eval at all.
- No fix to the separate `reduceLatestProvenanceWarnings` `>=` latest-wins copy (HANDOFF's
  "Next-action option #2") — distinct, self-contained follow-up, not touched here.
