# Slice 4c — Peer-Baseline Robust Fix Bundle (peer.count_drop + regime-keyed baseline + peer census-marker)

**Created:** 2026-07-23
**Reviewed:** 2026-07-23 (Stage 1 adversarial gate) — GO_WITH_CHANGES, must-fixes folded (see addendum at end of §2c, §2b, §1, and §4/§6 below).
**Completed:** 2026-07-23 — implemented via TDD-IMPLEMENT #4: `fact-translators.js` (peer census marker + availability signature), `peer-baseline.js` (regime-keyed fold for both `peer.count_spike` and new `peer.count_drop`, `PEER_COUNT_DROP_RULE_ID`), `calibration.js` (`CLOSED_RULE_IDS`), `alert-intelligence.js` (delivery allowlist + branch, additive, `classifyAlertNamespace` untouched), `daemon.js` confirmed no-change (existing sixth `extraCandidates` entry already covers both directions). All test files (`fact-translators.test.js`, `peer-baseline.test.js`, `calibration.test.js`, `alert-intelligence.test.js`, `daemon.test.js`) extended TDD-first; full run of the five touched suites is green (311/311).
**Addendum:** 2026-07-23 (adversarial verify, Stage 2, fix-apply pass) — two gaps surfaced:
1. **A sibling defect-class fix to `session-baseline.js` landed in a SEPARATE atomic commit this same session** (the session-baseline census-hardening commit), **NOT this Slice-4c commit.** An earlier draft of this addendum stated it was bundled into this change-set — that was a shared-working-tree artifact (the two tasks were implemented concurrently in one working tree, then committed separately). That sibling fix hardened `session-baseline.js`'s `groupSessionFactsByTick`/`tickGroupDisposition` `census_state` match from an else-catch-all (`return "complete"`) to a strict three-way match (`"complete"` | `"partial"` | fail-closed `"unknown"`) — the same defect class this slice's own `availability_signature` gap (item 2) exhibited. §5/§7's "zero edits to `session-baseline.js`" claim is therefore accurate FOR THIS COMMIT.
2. **The identical defect class existed in THIS slice's own `peer-baseline.js`**, and had NOT been fixed: `groupPeerFactsByTick`'s `availability_signature` marker match only checked `typeof === "string"` (§2a below), never the closed-enum SHAPE `buildPeerAvailabilitySignature` actually produces (`v1:<5 closed-enum codes>`) — so a garbled-but-string-typed value (e.g. `""`, or any other well-typed junk) was accepted verbatim as a legitimate, poolable regime key, letting both `peer.count_spike` and `peer.count_drop` establish an `established` baseline and fire real alerts off corrupted census-marker data. Fixed by adding `PEER_AVAILABILITY_SIGNATURE_PATTERN` (a regex mirroring `buildPeerAvailabilitySignature`'s own closed-enum output shape exactly) and requiring a full match, not just a type check — coercing anything that doesn't match to the same `undefined` markerless sentinel used throughout this slice. Regression-tested in `test/peer-baseline.test.js` (the exact PoC from the adversarial review: 30 established ticks + 1 drop tick, all sharing a garbled `""` signature, must never fire).
3. **A cross-module regression this slice introduced was found and fixed IN this commit** (Stage-2 adversarial verify, HIGH): the new unconditional peer census marker (`PEER_CENSUS_MARKER_ENTITY_KEY`, emitted with `fact_name === "peer.presence"`) was not excluded by `incident-correlation.js`'s peer-fact filters, so marker-only (zero-peer) ticks inflated that module's MUST-FIX-4 cold-start tick-group/day-span counts and could let `correlation.login_kill_proximity` fire on a peer's genuine first-ever appearance during a cold-start window. Fixed by excluding `PEER_CENSUS_MARKER_ENTITY_KEY` in both peer-fact filters (`findQualifyingPeerObservations` realPoints and `computeCorrelationCandidates` peerPoints), symmetric with the existing `PEER_OVERFLOW_ENTITY_KEY` exclusion — the overflow marker is deliberately KEPT visible for the `hasOverflowTick` check. A tree-wide audit confirmed `incident-correlation.js` is the ONLY external consumer of `peer.presence` facts (`peer-baseline.js` is the intended consumer). Regression-tested in `test/incident-correlation.test.js` (marker-only cold-start still blocked; a real established peer still correlates). `incident-correlation.js`/`.test.js` are part of THIS commit.
**Purpose:** Implementation plan for the deferred "robust fix bundle" named in `docs/plans/2026-07-13-observed-incident-collectors.md` Decision 2(c) (the Slice 4b section) and tracked as option #4 in `docs/HANDOFF.md`'s RESUME HERE block. Ships three things together, because all three share one fact-schema addendum:
1. a `PEER_CENSUS_MARKER_ENTITY_KEY` fact addendum (mirrors Slice 1's `SESSION_CENSUS_MARKER_ENTITY_KEY`) that also carries a per-tick **source-availability signature**;
2. `peer.count_drop` — the sign-flipped mirror of `session.count_drop`, gated by that new marker;
3. a **regime-keyed baseline** — the windowed Welford/EWMA fold (for *both* `peer.count_spike` and the new `peer.count_drop`) only pools tick-groups whose availability signature matches the current tick's signature, closing the accepted `peer.count_spike` false-positive class named in the Slice 4b plan (Decision 2, MUST-FIX 1/2).

**Extends:** `docs/plans/2026-07-13-observed-incident-collectors.md` Decision 2 (Slice 4b section) — this is that plan's own named Slice 4c, not a new initiative. Read that Decision 2 block (lines ~469-484) before implementing; this document assumes it as background and does not repeat its incident-motivation reasoning.

**Non-negotiable invariants (apply to every piece below, no exceptions):**
- **Opt-in / default-OFF:** every new code path is gated by the existing single `learned.json` kill switch (`loadLearnedConfig(...).enabled`), checked before any I/O — no new kill switch, no new config surface.
- **Deterministic, NO LLM:** this entire slice is arithmetic (Welford/EWMA/z-score) and closed-enum bucketing. Nothing in this slice ever constructs a prompt or calls `createSession`.
- **Fail-closed namespace:** `peer.count_drop` MUST classify as `unknown_namespace` in `classifyAlertNamespace`, exactly like its siblings `session.count_drop`/`session.churn`/`peer.count_spike`. No `classifyAlertNamespace` edit is needed or permitted (see Decision 3 below for why).
- **Degrade-not-fabricate:** a tick-group lacking the new census marker (pre-Slice-4c fact-history, or a marker-less transitional period) must never be folded into `peer.count_drop`'s baseline, and must never be treated as a confident zero. An unresolvable/`"unknown"` source status is bucketed as its own closed-enum value, never guessed into a known status.
- **Minimal scope (YAGNI):** no new PROVISIONAL sigma/floor/alpha constants for the drop direction — `peer.count_drop` reuses `peer-baseline.js`'s existing `DEFAULT_PEER_DEVIATION_SIGMA`/`DEFAULT_PEER_STDDEV_FLOOR`/`DEFAULT_PEER_MIN_SAMPLE_COUNT` (same underlying population as `peer.count_spike`, opposite tail — see Decision 4).
- **TDD:** every behavioral change below is landed test-first, mirroring the exact fixture patterns already shipped for `session.count_drop`'s must-fix-1/2 census-marker migration (`test/session-baseline.test.js`, `test/fact-translators.test.js`).
- **Zero net-new execFile/host I/O, zero new privilege surface:** this slice reads only already-persisted `peer.presence` fact-history (`fact-store.js`) plus its own state file — identical posture to `peer-baseline.js` today.
- **Sanitize identity strings at source:** unchanged — this slice never touches raw peer identity (pubkey/host/user/uuid); it only ever handles closed-enum source-status codes and counts.

---

## 0. Decisions pinned by this plan (resolving the recon seam-map's open questions)

These were left open in the originating Decision 2(c) text and the recon pass; pinned here so implementation has no ambiguity left to resolve mid-flight.

1. **Overflow-tick posture for `peer.count_drop`:** mirrors `session.count_drop`'s *stricter* exclude-from-scoring-AND-folding (not `peer.count_spike`'s score-but-never-fold). A capped/truncated count is a poor lower bound for a genuine *drop* — the same reasoning `session-baseline.js` already used, and the reasoning `peer.count_spike`'s own MUST-FIX-3 explicitly said does not transfer to the drop direction. See Decision 4.
2. **Availability-signature encoding:** a single closed-enum bucketed string (not a structured per-source object), consistent with every other bucketed attribute in `fact-translators.js`. See Decision 1.
3. **Does `peer.count_drop` join the deterministic local-delivery allowlist?** Yes. The task's own framing ("mirror … session.count_drop … AND peer.count_spike") covers both detection *and* delivery symmetry; leaving `peer.count_drop` delivery-silent would regress it to the pre-must-fix-3 state Slice 4/4b already fixed for its siblings. See Decision 6.
4. **Regime re-warm-up mechanics:** a brand-new regime (no prior same-signature tick-groups in the window) simply reuses `DEFAULT_PEER_MIN_SAMPLE_COUNT` — no distinct/smaller threshold. Simplest, matches the plan text's own "mirroring the existing cold-start gate" wording, and mirrors `session.count_drop`'s already-shipped cold-start convention. See Decision 4.
5. **New INERT critical-tier constants for `peer.count_drop`?** No new constants. `DEFAULT_PEER_CRITICAL_SIGMA` (already exported, already inert for `peer.count_spike`) is reused as the same future-facing placeholder for the drop direction too — both directions measure the same population, so one shared (still-inert) critical-sigma constant is enough. Adding a second, identically-inert `DEFAULT_PEER_DROP_CRITICAL_SIGMA` would be YAGNI.
6. **Malformed-marker sentinel (Stage 1 review must-fix, 2026-07-23):** `groupPeerFactsByTick`'s coercion for a marker point carrying a non-string/missing `availability_signature` attribute is `undefined` — i.e. it degrades identically to a genuinely marker-less tick-group — not a distinct `"unknown"` string. This is separate from, and must not be confused with, `buildPeerAvailabilitySignature`'s own per-source-slot `"unknown"` bucketing in §1 (a well-formed signature string with one or more `"unknown"` slots is still a real, comparable, poolable regime). See §2a for the full rationale.

---

## 1. `tools/descartes-cli/src/fact-translators.js` — peer census marker + availability signature

**New exports (append to the existing Slice 3 peer section, after `PEER_OVERFLOW_ENTITY_KEY`):**

```js
// Slice 4c (observed-incident collectors plan) — peer census-marker addendum, mirrors
// SESSION_CENSUS_MARKER_ENTITY_KEY exactly: emitted unconditionally on every successful
// vpn-peer-status envelope (including a zero-peer tick), so a true zero is foldable by
// peer.count_drop. Unlike the session marker, it ALSO carries a closed-enum per-tick
// source-availability signature (Decision 1 below) so peer-baseline.js's regime-keyed fold can
// bucket ticks by which peer sources were up this tick.
export const PEER_CENSUS_MARKER_ENTITY_KEY = "peer.census-marker.v1";
```

**Availability-signature builder (module-private, mirrors `censusStateFor`'s non-exported convention):**

```js
// Decision 1 (plan pinned): a single closed-enum bucketed string, versioned, built from the
// 5 fixed source keys vpn-peer-status.js's envelope always produces (sources.{ssh_who,ssh_last,
// wireguard,vpn_services,established_inbound}.status). Grounded against tools/vpn-peer-status.js's
// real closed status vocabulary (confirmed by direct read): "ok" | "partial" | "absent" |
// "missing_permission" | "unable" | "not_applicable" (not every source can emit every value --
// e.g. only wireguard emits "partial", only vpn_services emits "not_applicable" -- but the bucket
// function below is defensive against ANY future status literal, mapping anything outside this
// closed set to "unknown" rather than embedding an unrecognized raw string).
const CLOSED_PEER_SOURCE_STATUS_VALUES = new Set([
  "ok", "partial", "absent", "missing_permission", "unable", "not_applicable",
]);

function normalizedSourceStatus(status) {
  return CLOSED_PEER_SOURCE_STATUS_VALUES.has(status) ? status : "unknown";
}

// Fixed order, never derived from Object.keys (whose iteration order is an accident of insertion,
// not a contract) -- a stable, versioned signature format lets peer-baseline.js compare two
// signatures with simple string equality.
const PEER_AVAILABILITY_SOURCE_ORDER = ["ssh_who", "ssh_last", "wireguard", "vpn_services", "established_inbound"];
const PEER_AVAILABILITY_SIGNATURE_VERSION = "v1";

// Degrade-not-fabricate: a missing/malformed `sources` object (e.g. a simplified test fixture)
// degrades every source to "unknown" rather than throwing -- mirrors censusStateFor's own
// "absent multiplexers array carries no evidence of degradation either way" posture.
function buildPeerAvailabilitySignature(sources) {
  const codes = PEER_AVAILABILITY_SOURCE_ORDER.map((key) => normalizedSourceStatus(sources?.[key]?.status));
  return `${PEER_AVAILABILITY_SIGNATURE_VERSION}:${codes.join("-")}`;
}
```

**Marker builder + wiring (mirrors `buildSessionCensusMarkerFactPoint` exactly):**

```js
// Emitted unconditionally on every successful vpn-peer-status envelope, including a genuinely
// zero-peer tick -- so peer-baseline.js's fold always has a real tick-group to see for the drop
// direction. confidence:0, non-hashed fixed entity_key literal (mirrors PEER_OVERFLOW_ENTITY_KEY's
// own convention -- it carries no peer identity, nothing needs hashing).
function buildPeerCensusMarkerFactPoint(result, envelope, ts) {
  return {
    ts,
    fact_name: PEER_FACT_NAME,
    entity_key: PEER_CENSUS_MARKER_ENTITY_KEY,
    attributes: {
      availability_signature: buildPeerAvailabilitySignature(result?.sources),
    },
    source_envelope_id: envelope.id,
    source_tool: envelope.trace?.tool,
    sensitivity: "operational",
    confidence: 0,
  };
}
```

In `factPointsFromVpnPeerEvidence`, append the marker after the real peer points and *before* the overflow marker (matches `factPointsFromSessionEvidence`'s own append order — census marker first, overflow marker second):

```js
export function factPointsFromVpnPeerEvidence(evidence, { ts } = {}) {
  const envelope = (evidence ?? []).find((e) => e.id === "vpn-peer-status" && e.status !== "unable");
  if (!envelope) return [];
  const peers = envelope.result?.peers ?? [];

  const points = peers.map((peer) => buildPeerFactPoint(peer, envelope, ts));
  points.push(buildPeerCensusMarkerFactPoint(envelope.result, envelope, ts)); // NEW
  if (envelope.result?.truncated) {
    points.push(buildPeerOverflowMarkerFactPoint(envelope.result, envelope, ts));
  }
  return points;
}
```

**Breaking-change alert for existing tests (must be fixed in the SAME commit, not a follow-up):** every existing `factPointsFromVpnPeerEvidence` fixture in `test/fact-translators.test.js` that asserts an exact `points.length`, iterates `points` directly, or maps over `points` expecting only real-peer entries will now see one extra marker point per call. Confirmed by direct read — the following existing tests need updating (filter out `PEER_CENSUS_MARKER_ENTITY_KEY`, mirroring the exact `sessionPoints = points.filter((p) => p.entity_key !== SESSION_CENSUS_MARKER_ENTITY_KEY)` pattern already used at `fact-translators.test.js:313` for the analogous Slice-1 migration):
- `:511-524` ("maps a WireGuard peer…") — asserts `points.length === 1`, now 2.
- `:532-537` ("SSH peer and vpn_service peer never collide") — asserts `new Set(...).size === 3` and a 3-element `.sort()`; now 4 points.
- `:613-625` ("truncated result emits an overflow marker…") — asserts `points.length === 6` (5 peers + overflow), now 7 (5 peers + census + overflow).
- `:627-632` ("non-truncated never emits an overflow marker") — asserts `points.length === 1`, now 2.
- `:636-653` ("every persisted attribute is closed-enum or 16-hex hash") — this generic schema test iterates every point's every attribute against a fixed `CLOSED_ENUM_VALUES` set; either filter out the marker point before the loop, or add the marker's own closed-enum literals (`"v1:ok-ok-ok-ok-ok"`-shaped strings don't match the existing `HEX16_RE`/`CLOSED_ENUM_VALUES`/`HOUR_BUCKET_RE` regexes) — filtering is the minimal-diff choice, matching how session's own equivalent test (if any) would have handled the Slice-1 addendum.

No other existing `factPointsFromVpnPeerEvidence` test is affected (the hash-at-source negative tests at `:547-609` index `points[0]`, which stays the real peer since the marker is always appended after; the `unable`/missing-envelope test at `:539-543` returns `[]` before the marker logic ever runs).

**New tests to add (mirrors `test/fact-translators.test.js`'s existing session-census-marker block at `:423-469`):**
- Marker is present, `attributes.availability_signature` matches `/^v1:(ok|partial|absent|missing_permission|unable|not_applicable|unknown)-.../ ` (5 dash-joined codes), on a successful envelope with all 5 sources `"ok"`.
- A genuinely zero-peer tick (`peers: []`, envelope still `status: "ok"` because e.g. `ssh_last` resolved) still emits exactly the marker — no fabricated peer facts, one real, complete zero observation representable via `count:0` once `peer-baseline.js` groups it.
- The signature reflects a degraded source correctly: `sources.wireguard.status: "missing_permission"` with the other 4 `"ok"` yields a signature whose wireguard slot differs from the all-`"ok"` case, and the SSH-only/`who`-fails-`last`-succeeds fixture already used for `groupPeerFactsByTick` tests (mirrors `vpn-peer-status.js:431`'s `any_source_available` semantics) produces its own distinct signature.
- An unrecognized/future status literal in any source slot degrades to `"unknown"` in that slot, never throws, never embeds the raw literal.
- A malformed/missing `result.sources` object (simplified test fixture) degrades every slot to `"unknown"` rather than throwing (mirrors `censusStateFor`'s missing-`multiplexers` tolerance).
- No raw source status leaks anything beyond the 6-value closed set — schema-level test extending the existing closed-enum coverage test (`:636`) to include the marker's own attribute.

---

## 2. `tools/descartes-cli/src/peer-baseline.js` — census recognition, regime-keyed fold, `peer.count_drop`

### 2a. Tick-grouping (`groupPeerFactsByTick`)

Import `PEER_CENSUS_MARKER_ENTITY_KEY` from `fact-translators.js` alongside the existing `PEER_OVERFLOW_ENTITY_KEY` import. Extend the per-tick-group shape to `{ ts, count, hasOverflow, availabilitySignature }` (new field, `undefined` when no marker is present in that tick-group — i.e. pre-Slice-4c/legacy fact-history):

```js
export function groupPeerFactsByTick(points = []) {
  const byTs = new Map();
  for (const point of points ?? []) {
    if (!point || point.fact_name !== PEER_FACT_NAME || typeof point.ts !== "string") continue;
    if (!byTs.has(point.ts)) {
      byTs.set(point.ts, { ts: point.ts, count: 0, hasOverflow: false, availabilitySignature: undefined });
    }
    const group = byTs.get(point.ts);
    if (point.entity_key === PEER_OVERFLOW_ENTITY_KEY) {
      group.hasOverflow = true;
      continue;
    }
    if (point.entity_key === PEER_CENSUS_MARKER_ENTITY_KEY) {
      // Sentinel unification (Stage 1 review must-fix, 2026-07-23): a non-string
      // availability_signature attribute (malformed/corrupt fact point) coerces to `undefined`,
      // NOT the bare string "unknown" the earlier draft used here. Rationale: `undefined` is the
      // exact same value groupPeerFactsByTick already produces for a tick-group that never saw a
      // marker point at all (the "markerless" disposition, §2b/§2c). Reusing that value for "saw a
      // marker but its payload was malformed" means both cases degrade through the identical,
      // already-tested "markerless" code path (excluded from peer.count_drop's fold via
      // dropTickGroupDisposition, excluded from peer.count_spike's regime match unless the current
      // tick is ALSO undefined) instead of introducing a second, distinct never-pooling regime
      // string that would need its own parallel test coverage. This is the stricter of the two
      // options the review flagged (bare "unknown" would still be a distinct, comparable regime
      // string that COULD accumulate its own 30-sample pool and eventually fire) -- undefined can
      // never accumulate a pool on its own once any real marker exists in the window, which is the
      // more conservative, fail-toward-silence choice. Distinct from buildPeerAvailabilitySignature's
      // OWN "unknown" bucketing in §1 below, which is a per-SOURCE-SLOT closed-enum code embedded
      // inside a well-formed signature string (e.g. "v1:unknown-ok-ok-ok-ok") -- that is a different
      // concern (one source's status is unrecognized) from this one (the whole marker attribute is
      // missing or malformed) and both are pinned by their own dedicated tests (§1's "unrecognized
      // status literal" test; this file's own malformed-marker test below).
      group.availabilitySignature =
        typeof point.attributes?.availability_signature === "string" ? point.attributes.availability_signature : undefined;
      continue;
    }
    if (point.attributes?.presence_state !== "observed_historical") {
      group.count += 1;
    }
  }
  return [...byTs.values()].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}
```

**Backward compatibility, load-bearing:** every existing `groupPeerFactsByTick` test fixture (none of which include a `PEER_CENSUS_MARKER_ENTITY_KEY` point) continues to produce `availabilitySignature: undefined` for every group, exactly as before this change added the field at all — zero existing assertion on `{ts, count, hasOverflow}` breaks.

### 2b. Two disposition functions (deliberately NOT unified — see rationale)

**Do not modify the existing `tickGroupDisposition` function** (used only by the already-shipped `computeWindowedPeerStats`/`peer.count_spike` path). It stays exactly `hasOverflow ? "overflow" : "complete"` — a 2-way classification, unaware of `availabilitySignature`. This is intentional: if this function were extended to a 3-way disposition that treats a marker-less group as anything other than `"complete"`, every existing (marker-less) `peer.count_spike` test fixture — and every real, already-persisted `peer-baseline.json` production baseline — would suddenly exclude 100% of its own fold history, resetting every live baseline to `provisional` on upgrade. That is an unacceptable, unrequested regression to an already-shipped, unrelated-to-this-slice detector. The regime filter (2c below) achieves the desired behavior change for `peer.count_spike` (closing its accepted false-positive class) without touching disposition classification at all.

**Clarification (Stage 1 review must-fix, 2026-07-23) — this is NOT the same reset the regime filter (2c) accepts:** a 3-way `tickGroupDisposition` that permanently classified marker-less groups as non-`"complete"` would exclude that history from the fold *forever* — a static per-group classification, never revisited once the window rolls past the upgrade instant, so pre-upgrade fold history would never again count even after the window is 100% marker-bearing. The regime filter's `availabilitySignature === currentSignature` predicate, by contrast, causes only a *transient, one-time, self-healing* reset: it excludes marker-less groups only while the rolling window still contains a mix of marker-less-and-marker-bearing (or differing-signature) ticks; once `windowMs` has fully rolled over past the deploy instant (or past any given regime change), every group back in scope shares one signature again and the filter reverts to a no-op. §2c below states this transitional cost explicitly and pins it with a dedicated test — it is accepted as an intended, one-time cost, not swept under the "100% backward-compatible" claim.

**Add a new, `peer.count_drop`-only disposition function**, mirroring `session-baseline.js`'s own `tickGroupDisposition` (3-way: overflow > markerless > complete) but keyed on the marker's *presence*, not a partial/complete boolean (peers have no binary partial-census concept — degradation is captured entirely by the signature's own content, which is what the regime key exists for):

```js
// peer.count_drop-only disposition (Decision 0.1 above: mirrors session.count_drop's own
// STRICTER exclude-from-scoring-AND-folding posture for overflow, transplanted from
// session-baseline.js's tickGroupDisposition; "markerless" additionally excludes any
// pre-Slice-4c tick-group, exactly mirroring session.count_drop's own must-fix-1/2 "an honest
// ~30-sample re-warm-up, never fabricated" pattern -- a marker-less peer.presence tick-group
// carries the identical "real zero vs. never observed" ambiguity Slice 1's own addendum was
// built to close for sessions, now closed for peers by THIS marker.
function dropTickGroupDisposition(group) {
  if (group.hasOverflow) return "overflow";
  if (group.availabilitySignature === undefined) return "markerless";
  return "complete";
}
```

### 2c. Regime-keyed fold

**`computeWindowedPeerStats` (existing, `peer.count_spike`) gets ONE additive change:** the `completeGroups` filter gains a second predicate — the group's `availabilitySignature` must equal the most recent tick-group's own `availabilitySignature`. Everything else (the existing `tickGroupDisposition`, the existing score-but-never-fold overflow handling, the existing pre-score/post-score split) is unchanged:

```js
export function computeWindowedPeerStats(groups, { stddevFloor = DEFAULT_PEER_STDDEV_FLOOR, ewmaAlpha = DEFAULT_PEER_EWMA_ALPHA, minSampleCount = DEFAULT_PEER_MIN_SAMPLE_COUNT } = {}) {
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const currentSignature = mostRecentGroup?.availabilitySignature;

  // Slice 4c regime-keyed fold (Decision 2(c), retroactive fix for peer.count_spike's own
  // accepted false-positive class): only tick-groups whose availability signature matches the
  // CURRENT tick's own signature are eligible to fold. Chronic degradation now establishes its
  // own baseline WITHIN its own regime; a recovery flips the regime and triggers an honest
  // re-warm-up (empty completeGroups for the new signature until minSampleCount is met again)
  // instead of scoring a recovery-driven jump against a stale, differently-conditioned baseline.
  const completeGroups = groups.filter(
    (group) => tickGroupDisposition(group) === "complete" && group.availabilitySignature === currentSignature,
  );
  // ...unchanged from here: mostRecentIsOverflow / preScoreGroups / preScoreStats / lastObservation
  // / stats / ewmaState / confidence_state, all exactly as shipped.
}
```

**Backward compatibility — corrected claim (Stage 1 review must-fix, 2026-07-23):** the earlier draft of this section claimed the regime filter was "100% backward-compatible... for every real, already-persisted baseline." That is only half true and the false half must be stated honestly. Two distinct scenarios:
- **Test fixtures / a window that stays entirely marker-less end to end:** true no-op, exactly as argued below — every pre-Slice-4c tick-group has `availabilitySignature === undefined`, `currentSignature` for a marker-less most-recent tick-group is therefore also `undefined`, `undefined === undefined` is `true`, so the predicate is a no-op and every existing marker-less `peer.count_spike` test fixture stays green unmodified.
- **A real, already-persisted, live baseline the moment this slice deploys:** FALSE that nothing changes. The first tick after deploy is marker-*bearing* (`currentSignature` becomes a real `"v1:..."` string), while 100% of that baseline's prior fold history is marker-*less* (`availabilitySignature === undefined`). `"v1:ok-ok-ok-ok-ok" === undefined` is `false`, so `completeGroups` collapses to zero eligible groups on that very first post-upgrade tick — a **one-time reset of the live `peer.count_spike` baseline to `provisional`**, requiring `DEFAULT_PEER_MIN_SAMPLE_COUNT` (~30) fresh same-signature ticks to re-establish. This is the exact "resetting every live baseline to provisional on upgrade" outcome §2b explicitly refuses to accept for `tickGroupDisposition` — but the regime predicate reintroduces it by a different mechanism. It is accepted here as an intended, one-time cost (not a bug to route around) because: (1) it fails toward silence, never toward a false alert — a `provisional` baseline simply cannot emit a candidate; (2) it is directly precedented by the Slice 1 session-census-marker migration's own honest re-warm-up, which this plan already treats as the template pattern throughout §1/§2b/§6; (3) the alternative (special-casing `undefined` to always match, i.e. treating "no marker yet" as its own permanently-compatible regime) would silently keep pooling pre-upgrade unconditioned history into the post-upgrade regime-keyed fold forever for any tick-group whose marker never arrives, which defeats the entire point of Decision 2(c)'s fix. **This is a one-time cost at the moment of upgrade only** — once every group in the rolling window is marker-bearing (i.e., `windowMs` has fully rolled over past the deploy instant), the regime filter behaves exactly as the "no-op once fully marker-less OR fully marker-bearing-and-matching" argument describes, with no further resets.
- A dedicated transitional test must cover this directly (added to §6's `peer-baseline.test.js` list below): mixed-window fixture — N marker-less tick-groups (legacy history) followed by ONE marker-bearing tick-group — asserts `computeWindowedPeerStats`'s `confidence_state` for that final tick is `"provisional"` (not `"established"`, even though the marker-less history alone would have satisfied `minSampleCount`), asserts no false spike candidate is built off of it, and asserts no crash/throw on the mixed-`undefined`/string comparison.

**Add a new, sibling function `computeWindowedPeerDropStats`** for the drop direction — NOT a parameterized variant of `computeWindowedPeerStats` (their overflow-handling policies diverge: score-but-never-fold for spike vs. exclude-from-both for drop — Decision 0.1), mirroring `session-baseline.js`'s `computeWindowedSessionStats` fold+score-at-tail shape verbatim, plus the same regime filter as 2c above, using `dropTickGroupDisposition`:

```js
export function computeWindowedPeerDropStats(groups, { stddevFloor = DEFAULT_PEER_STDDEV_FLOOR, ewmaAlpha = DEFAULT_PEER_EWMA_ALPHA, minSampleCount = DEFAULT_PEER_MIN_SAMPLE_COUNT } = {}) {
  const mostRecentGroup = groups.length > 0 ? groups[groups.length - 1] : undefined;
  const currentSignature = mostRecentGroup?.availabilitySignature;
  const mostRecentIsOverflow = mostRecentGroup ? dropTickGroupDisposition(mostRecentGroup) === "overflow" : false;

  const eligibleGroups = groups.filter(
    (group) => dropTickGroupDisposition(group) === "complete" && group.availabilitySignature === currentSignature,
  );

  let stats = emptyWelfordStats();
  let ewmaState = { ewma: undefined, ewma_variance: undefined };
  let lastObservation;

  eligibleGroups.forEach((group, index) => {
    if (index === eligibleGroups.length - 1) {
      const zScore = computeZScore(group.count, stats.mean, stats.stddev, stddevFloor);
      lastObservation = {
        ts: group.ts, count: group.count, z_score: zScore,
        mean_before: stats.mean, stddev_before: stats.stddev,
        has_overflow: mostRecentIsOverflow, // purely observational, mirrors session-baseline.js's own nice-to-have (ii)
      };
    }
    stats = foldWelford(stats, group.count);
    ewmaState = updateEwma(ewmaState, group.count, ewmaAlpha);
  });

  const confidence_state = stats.count >= minSampleCount ? "established" : "provisional";
  return {
    stats: { ...stats, ewma: ewmaState.ewma, ewma_variance: ewmaState.ewma_variance },
    confidence_state,
    last_observation: lastObservation,
  };
}
```

**Note on when `peer.count_drop` can first activate:** if the current tick is itself `"markerless"` (pre-Slice-4c or transitional), `eligibleGroups` is *always* empty (a `"markerless"` group can never also be `"complete"`), so `confidence_state` stays `"provisional"` and no candidate is ever emitted — an honest, unavoidable cold-start gate exactly matching `session.count_drop`'s own pre-Slice-1-addendum era. `peer.count_drop` simply cannot fire until the census marker has been live and accumulating for `DEFAULT_PEER_MIN_SAMPLE_COUNT` same-signature ticks. This is intended, not a bug to route around.

### 2d. `PEER_COUNT_DROP_RULE_ID` + candidate builder

```js
export const PEER_COUNT_DROP_RULE_ID = "peer.count_drop";

export function buildCountDropCandidate(state, { deviationSigma = DEFAULT_PEER_DEVIATION_SIGMA } = {}) {
  if (state?.confidence_state !== "established") return undefined;
  const obs = state.last_observation;
  if (!obs || !Number.isFinite(obs.z_score) || !Number.isFinite(obs.mean_before)) return undefined;
  if (!(obs.z_score <= -deviationSigma)) return undefined;
  if (!(obs.count < obs.mean_before)) return undefined; // defense-in-depth guard, redundant given a negative z

  const diagnostics = sanitizeDiagnostics({
    observed_count: obs.count,
    mean_before: obs.mean_before,
    stddev_before: obs.stddev_before,
    z_score: obs.z_score,
    confidence_state: state.confidence_state,
  });
  return {
    id: alertId(PEER_COUNT_DROP_RULE_ID, "global"),
    rule_id: PEER_COUNT_DROP_RULE_ID,
    fingerprint: "global",
    // Decision 0 (plan pinned), mirrors peer.count_spike's own MUST-FIX-1 cap: severity is
    // HARDCODED "warning" -- never escalates to "critical" in v0, regardless of z magnitude.
    // Peer-count variance dynamics remain an untuned PROVISIONAL surface for BOTH directions.
    severity: "warning",
    title: "Peer count drop",
    summary: "Currently-observed VPN/SSH peer count dropped significantly below its established (regime-matched) baseline.",
    diagnostics,
    evidence_refs: ["peer-baseline"],
  };
}
```

Note the naming collision to watch for during implementation: `session-baseline.js` already exports a function named `buildCountDropCandidate`. `peer-baseline.js`'s own new function of the same name is a *different module's* export — no import collision exists today (neither module imports the other's candidate builders), but name it `buildCountDropCandidate` here only if grepping confirms zero same-file collision; if a reviewer prefers disambiguation, `buildPeerCountDropCandidate` is the safe alternative. Either name is fine; pick one and keep it consistent with the rest of this file's existing `buildCountSpikeCandidate` naming (no `Peer` infix there either, so `buildCountDropCandidate` is the more consistent choice).

### 2e. Store schema (`peer-baseline.json`)

Extend `freshPeerBaselineState`/`normalizePeerBaselineState`/the write path with:
- `drop: { confidence_state: "provisional", stats: <same shape as top-level stats>, last_observation: <same shape as top-level last_observation> }` — a nested sibling of the existing (unchanged, spike-owned) top-level `confidence_state`/`stats`/`last_observation`.
- `availability_signature: undefined` — the CURRENT regime, top-level, for `descartes learned`-style observability (which regime is the baseline currently keyed to).
- `skipped_markerless_tick_count: 0` — new counter, increments once per new tick-group whose `dropTickGroupDisposition` is `"markerless"`, mirroring `skipped_overflow_tick_count`'s existing bookkeeping convention. (`skipped_overflow_tick_count` itself is unchanged/shared — both spike and drop agree on what counts as an overflow tick.)

Corrupt/missing-tolerant normalization (`normalizePeerBaselineState`) must default all three additions safely (missing `drop` object → fresh nested state; non-string `availability_signature` → `undefined`; non-finite `skipped_markerless_tick_count` → `0`) — same discipline as every other field in that function today.

### 2f. `computePeerBaselineCandidates` wiring

```js
export async function computePeerBaselineCandidates(descartesPaths, options = {}) {
  const loadConfig = options.loadLearnedConfig ?? loadLearnedConfig;
  const learnedConfig = await loadConfig(descartesPaths);
  if (!learnedConfig.enabled) return [];

  // ...existing option defaults, unchanged...

  const readFacts = options.readFactPoints ?? readFactPoints;
  const { points } = await readFacts(descartesPaths, { windowMs, now: options.now });
  const groups = groupPeerFactsByTick(points); // SHARED by both spike and drop below

  const loadStore = options.loadPeerBaselineStore ?? loadPeerBaselineStore;
  const { state: persistedState } = await loadStore(descartesPaths);

  const lastFoldedMs = persistedState.last_folded_ts ? new Date(persistedState.last_folded_ts).getTime() : -Infinity;
  const newGroups = groups.filter((group) => new Date(group.ts).getTime() > lastFoldedMs);

  const windowed = computeWindowedPeerStats(groups, { stddevFloor, ewmaAlpha, minSampleCount });        // spike, now regime-keyed
  const windowedDrop = computeWindowedPeerDropStats(groups, { stddevFloor, ewmaAlpha, minSampleCount }); // NEW, drop

  if (newGroups.length > 0) {
    let skippedOverflow = persistedState.skipped_overflow_tick_count;
    let skippedMarkerless = persistedState.skipped_markerless_tick_count; // NEW
    let lastFoldedTs = persistedState.last_folded_ts;
    for (const group of newGroups) {
      lastFoldedTs = group.ts;
      if (tickGroupDisposition(group) === "overflow") skippedOverflow += 1;
      if (dropTickGroupDisposition(group) === "markerless") skippedMarkerless += 1; // NEW, independent counter
    }
    const nextState = {
      version: 1,
      last_folded_ts: lastFoldedTs,
      confidence_state: windowed.confidence_state,
      stats: windowed.stats,
      last_observation: windowed.last_observation,
      skipped_overflow_tick_count: skippedOverflow,
      availability_signature: groups.length > 0 ? groups[groups.length - 1].availabilitySignature : undefined, // NEW
      drop: { // NEW
        confidence_state: windowedDrop.confidence_state,
        stats: windowedDrop.stats,
        last_observation: windowedDrop.last_observation,
      },
      skipped_markerless_tick_count: skippedMarkerless, // NEW
    };
    const writeStore = options.writePeerBaselineStore ?? writePeerBaselineStore;
    await writeStore(descartesPaths, nextState);
  }

  const candidates = [];
  const spikeCandidate = buildCountSpikeCandidate(
    { confidence_state: windowed.confidence_state, last_observation: windowed.last_observation },
    { deviationSigma },
  );
  if (spikeCandidate) candidates.push(spikeCandidate);
  const dropCandidate = buildCountDropCandidate(
    { confidence_state: windowedDrop.confidence_state, last_observation: windowedDrop.last_observation },
    { deviationSigma },
  );
  if (dropCandidate) candidates.push(dropCandidate);
  return candidates;
}
```

Re-emission-every-tick (Decision 3's existing precedent, unchanged): both candidates are re-derived fresh from `windowed`/`windowedDrop` on every call, including ticks where nothing new folded — never gated on the store write happening this tick. This preserves `applyAlertCandidates`' recovery semantics identically for both signals.

---

## 3. `tools/descartes-cli/src/calibration.js`

Import `PEER_COUNT_DROP_RULE_ID` from `peer-baseline.js` alongside the existing `PEER_COUNT_SPIKE_RULE_ID` import, and add it to `CLOSED_RULE_IDS`:

```js
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
// ...
const CLOSED_RULE_IDS = new Set([
  UNKNOWN_IDENTITY_RULE_ID,
  IDENTITY_DRIFT_RULE_ID,
  NEW_PUBLIC_BIND_RULE_ID,
  SESSION_COUNT_DROP_RULE_ID,
  SESSION_CHURN_RULE_ID,
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID, // NEW
  CORRELATION_RULE_ID,
]);
```

This is load-bearing, not cosmetic: `isCalibratedRuleId` (private, gates `computeCalibrationReport`'s per-alert inclusion at `calibration.js:193`) silently *excludes* any rule_id not in this set from every calibration report row. Without this addition, a `peer.count_drop` alert would be silently invisible to `descartes learned calibration` forever — a real, easy-to-miss gap, not a hypothetical one.

---

## 4. `tools/descartes-cli/src/alert-intelligence.js`

**No `classifyAlertNamespace` change** — confirmed by direct read of the closed, ordered `startsWith` chain (`learned.` → `daemon./system./disk.` → `constraint.` → `provenance.` → `baseline.` → `identity.` → `correlation.` → fallback `{namespace: undefined, hardExcluded: false}`). `peer.count_drop` does not match any named branch (`peer.` is disjoint from all seven, same argument already verified for `peer.count_spike`/`session.*`), so it falls through to the `unknown_namespace` fallback automatically — no edit needed or permitted here.

**Widen the locally-composed delivery allowlist** (this file, not `session-baseline.js` — same forbidden-dependency-direction reasoning as Slice 4b's own MUST-FIX 4, now extended):

```js
import { PEER_COUNT_DROP_RULE_ID, PEER_COUNT_SPIKE_RULE_ID } from "./peer-baseline.js";
// ...
const ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS = [
  ...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, // session-baseline.js's own unchanged 2-id export
  PEER_COUNT_SPIKE_RULE_ID,
  PEER_COUNT_DROP_RULE_ID, // NEW
];
```

**Fourth delivery branch in `buildSessionAlertNotificationDecision`** (mirrors the existing `PEER_COUNT_SPIKE_RULE_ID` branch exactly, peer-flavored drop wording; reads `alert.severity` defensively rather than hardcoding, matching the existing spike branch's own stated rationale — "a future cap-lift doesn't need a second edit here"):

```js
if (alert?.rule_id === PEER_COUNT_DROP_RULE_ID) {
  return {
    notify: true,
    severity: alert.severity === "critical" ? "critical" : "warning",
    title: "Descartes: peer count drop",
    body: `Peer count ${diagnostics.observed_count} vs baseline mean ${diagnostics.mean_before} (z=${diagnostics.z_score}, ${diagnostics.confidence_state}).`,
  };
}
```

**Tests that pin the allowlist shape and must NOT be edited in the wrong place** (named explicitly so an implementer doesn't mistake widening `session-baseline.js`'s own export for the fix, exactly the trap Slice 4b's MUST-FIX 4 called out):

**Anchors corrected by Stage 1 review (2026-07-23) — grep-confirm anchors BEFORE editing is a binding implementation step, not optional hedging.** The prior draft cited `test/session-baseline.test.js:677-678` and `test/alert-intelligence.test.js:965-967` as the pin locations, and instructed extending a non-existent module-private `deepEqual` pin of `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (that constant is module-private/non-exported in `alert-intelligence.js:22` — there is no `deepEqual` of it anywhere to extend). Confirmed by direct grep on 2026-07-23, the real anchors are:
- `test/session-baseline.test.js:647-648` (not 677-678) — `test("DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS is exactly [SESSION_COUNT_DROP_RULE_ID, SESSION_CHURN_RULE_ID]"...)`, pinning `session-baseline.js`'s own unchanged 2-id export. **Unchanged, stays green as-is** — do not touch.
- `test/alert-intelligence.test.js:1146-1151` — a parallel, file-local `DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` pin (also unchanged/2-id, re-imported from `session-baseline.js`, not the widened constant). **Unchanged, stays green as-is** — do not touch.
- `test/alert-intelligence.test.js:1178-1184` — test `"(c) invariant: every exported PEER_*_RULE_ID classifies to namespace undefined"`, currently iterating `[PEER_COUNT_SPIKE_RULE_ID]`. **Implementation step:** widen the array literal to `[PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID]`.
- `test/alert-intelligence.test.js:1280-1299` — this is the actual **behavioral** pin of `alert-intelligence.js`'s locally-composed, module-private allowlist (there is no `deepEqual` of the constant itself; the module-private constant is pinned indirectly by asserting `emitSessionAlertSignals` actually delivers one alert per id in a hand-built `expectedIds` array). **Implementation step:** change `const expectedIds = [...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, PEER_COUNT_SPIKE_RULE_ID];` to `const expectedIds = [...DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS, PEER_COUNT_SPIKE_RULE_ID, PEER_COUNT_DROP_RULE_ID];`, update the companion `assert.deepEqual(expectedIds, [...])` literal to the 4-id shape, and update the test's own title/comment (it currently says "three-id" and names only MUST-FIX 4 / two prior anchors) to reflect the 4-id shape and this slice.
- Extend the existing `classifyAlertNamespace`/`adjudicateAlertNotifications` fail-closed regression tests (which already assert `peer.count_spike` is `unknown_namespace` under the most-permissive `enabled_namespaces`, at `test/alert-intelligence.test.js:1158-1176`) with a parallel `peer.count_drop` assertion — same public-seam shape (config `enabled: true`, `enabled_namespaces` = ALL of `KNOWN_ALERT_NAMESPACES`, one due `peer.count_drop` alert, assert `status === "no_eligible_alerts"`, `excluded.unknown_namespace` counts it, injected LLM factory never invoked).
- **Before editing any of the above, re-run the grep confirming these line numbers against the working tree at implementation time** — this plan's own line-number citations are a point-in-time snapshot (2026-07-23) and drift with any intervening edit to these files; treat every line-number anchor in this plan as a hint to `grep -n`, not a substitute for it.

---

## 5. No-change files (confirmed, wiring already generic)

- **`tools/descartes-cli/src/daemon.js`** — `computePeerBaselineCandidates` is already the sixth `extraCandidates` spread entry (`...await computePeerBaselineCandidates(descartesPaths, options)`); a `peer.count_drop` candidate returned from the same function flows through automatically. No edit.
- **`tools/descartes-cli/src/alert-store.js`** — `applyAlertCandidates`'s `mergedCandidates = [...candidates, ...extraCandidates]` merge is generic, no per-`rule_id` special-casing. No edit.

---

## 6. Test plan (mirrors the named sibling modules, file-by-file)

### `tools/descartes-cli/test/fact-translators.test.js`
- New `describe`-style block mirroring the existing Slice-1-addendum session census tests (`:423-469`), adapted for `factPointsFromVpnPeerEvidence` + `PEER_CENSUS_MARKER_ENTITY_KEY` + `availability_signature` — see the concrete list under §1 above.
- Fix the 5 existing tests broken by the marker's unconditional append (§1's breaking-change list) in the SAME commit — this is not optional cleanup, the suite will not compile green otherwise.

### `tools/descartes-cli/test/peer-baseline.test.js` (extend in place — this file already has its own tick-grouping/windowed-stats/candidate-shape blocks at `:112-530`, per the existing convention; do not create a new file)
- `groupPeerFactsByTick`: a marker-bearing tick-group surfaces `availabilitySignature`; the marker itself is never counted (mirrors the existing overflow-marker-never-counted test at `:134`); a marker-less legacy tick-group still produces `availabilitySignature: undefined` (backward-compat pin); **NEW (Stage 1 review must-fix, 2026-07-23)** — a marker point present but with a non-string/missing `attributes.availability_signature` (malformed/corrupt fact point) also coerces the group's `availabilitySignature` to `undefined`, exercising the exact same code path as (and producing output indistinguishable from) a genuinely marker-less group — pins the sentinel-unification decision above.
- `computeWindowedPeerStats` (spike, regime-keyed): (a) a fully marker-less fixture behaves byte-identically to today (regression pin, run the EXACT existing gradual-drift/regime-change fixtures unmodified and assert unchanged output); (b) a mixed-regime fixture — N ticks at signature A (degraded, e.g. `wireguard: missing_permission`), then a recovery tick at signature B (all `ok`) — does NOT fire a false spike on the recovery tick (this is the retroactive false-positive-class fix from Decision 2(c), the actual regression test for the accepted FP class named in the Slice 4b plan); (c) `confidence_state` for the new regime resets to `"provisional"` immediately on a regime flip (re-warm-up), even though the OLD regime was `"established"`; (d) **NEW (Stage 1 review must-fix, 2026-07-23) — transitional post-upgrade mixed-window test:** a fixture with `DEFAULT_PEER_MIN_SAMPLE_COUNT`+ marker-less legacy tick-groups (`availabilitySignature: undefined` throughout, would already satisfy `minSampleCount` on its own) followed by exactly ONE marker-bearing tick-group appended at the tail — asserts the resulting `confidence_state` is `"provisional"` (not `"established"`, despite the legacy history alone being large enough), asserts no spike candidate is built off that tick, and asserts no throw/crash from the `undefined`-vs-string comparison. This is the pinned, honest regression test for the one-time post-upgrade baseline reset documented in §2c/§2b above — it must show the reset happening exactly once and safely, not silently or via a fabricated confidence.
- `computeWindowedPeerDropStats` (new): mirrors `computeWindowedPeerStats`'s own existing test shapes, sign-flipped — self-dampening-avoidance ordering, STDDEV_FLOOR guard, overflow EXCLUDED from both scoring and folding (contrast test explicitly asserting this differs from spike's score-but-never-fold), a marker-less-only fixture NEVER reaches `"established"` (cold-start-forever-without-the-marker pin), day-1/cold-start no-storm.
- `buildCountDropCandidate` (peer): no candidate below `min_sample_count`; fires at `z <= -DEVIATION_SIGMA` AND `count < mean_before`; severity is HARDCODED `"warning"` even at an extreme z crossing `DEFAULT_PEER_CRITICAL_SIGMA`-equivalent magnitude (mirrors the existing spike MUST-FIX-1 hard-cap test at `:296` exactly, drop-flavored).
- Synthetic fixtures: a mass peer-drop-to-near-zero fires; an EXACT-ZERO drop (the marker's whole reason for existing) fires as a real, foldable zero, not a fabricated/skipped one; a chronic-degradation-then-recovery sequence that WOULD have false-fired `peer.count_spike` pre-Slice-4c now recovers cleanly on both directions.
- Re-emission-every-tick for `peer.count_drop`, mirroring the existing spike re-emission test at `:384`.
- Store round-trip: `loadPeerBaselineStore`/`writePeerBaselineStore` correctly persist/restore the new `drop`/`availability_signature`/`skipped_markerless_tick_count` fields; corrupt-JSON reset still yields a fresh, safe default for all three; `resolvePeerBaselineStorePaths` unchanged (same file, additive schema only).
- `computePeerBaselineCandidates`: returns BOTH candidates when both conditions are independently met (spike direction AND drop direction can never both fire on the same population/tick simultaneously in practice, since they require opposite-sign z — but the array-return shape itself, `[]`/`[spike]`/`[drop]`, needs direct coverage); short-circuits to `[]` before any I/O when `learned.json` is disabled (existing test pattern, extend assertion to also confirm no drop-path I/O).
- Sanitized-diagnostics assertion for `buildCountDropCandidate`'s output (mirrors the existing spike test at `:447`).
- No raw peer identity reachable from `peer.count_drop`'s diagnostics either (mirrors `:462`).

### `tools/descartes-cli/test/alert-intelligence.test.js`
- Extend the behavioral 3-id-to-4-id pin at `:1280-1299` (the `expectedIds` composition test) per §4's corrected anchors — this is the actual load-bearing test for the widened module-private allowlist, not a `deepEqual` of the constant itself.
- Widen the `[PEER_COUNT_SPIKE_RULE_ID]` invariant loop at `:1178-1184` to include `PEER_COUNT_DROP_RULE_ID`.
- Leave `:1146-1151` (this file's own 2-id `DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` pin) and `test/session-baseline.test.js:647-648` (session-baseline.js's own 2-id export pin) untouched — both are correctly unwidened.
- Extend the `classifyAlertNamespace`/fail-closed regression coverage (`:1158-1176`) with a `peer.count_drop` counterpart to the existing `peer.count_spike` assertions (§4's last bullet).
- New `buildSessionAlertNotificationDecision`/`emitSessionAlertSignals` delivery test for `PEER_COUNT_DROP_RULE_ID` — a due `peer.count_drop` alert reaches `deliverNotificationDecision` with the expected counts/hash-only body shape (mirrors the existing spike delivery test).
- Re-grep all four line-number anchors above against the working tree immediately before editing (§4's binding grep-confirm step) — they are a 2026-07-23 snapshot, not a promise.

### `tools/descartes-cli/test/calibration.test.js`
- Extend the existing `"attribution: session.*/peer.*/correlation.* -> rule_id, granularity family"` test (`:143-156`) with a 5th fixture alert `{ rule_id: "peer.count_drop", diagnostics: {} }`, bump `report.artifacts.length` from 4 to 5, keep the existing per-row `granularity === "family"`/`artifact_ref === rule_id_family` assertions unchanged (they already generalize).
- This test is the load-bearing regression for `CLOSED_RULE_IDS` membership (§3) — without the `calibration.js` addition, this extended fixture would silently produce only 4 artifacts instead of 5, catching the exact "invisible to calibration forever" gap named in §3.

---

## 7. Collision / integration order with other in-flight work

Per the recon seam-map: `alert-intelligence.js` (`ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS`, `KNOWN_ALERT_NAMESPACES`) and `calibration.js` (`CLOSED_RULE_IDS`) are flat list/set literals that ANY sibling slice adding its own new alert `rule_id` would also touch (e.g. a hypothetical service-disappearance-alert slice, HANDOFF option #1). This is a textual, not logical, merge-conflict risk — safe to resolve by rebase/serialization, not a design coupling. `daemon.js`'s `extraCandidates` array is append-only; a collision there is only possible if a sibling slice's new source also lands as the array's tail in the same window — again textual, not logical.

`fact-translators.js`'s edit is scoped entirely to `factPointsFromVpnPeerEvidence` and its own new private helpers — distinct from `factPointsFromSessionEvidence` (already shipped, Slice 1) and `factPointsFromServiceEvidence`/its own `service.census` marker (already shipped, Slice C) — no logical overlap with either.

**Recommended integration order if run concurrently with another slice that also adds a `rule_id`:** land this slice's `calibration.js`/`alert-intelligence.js` edits first (or last) as a single, small, easy-to-rebase diff — do not attempt to interleave two `rule_id`-adding slices' edits to the same array literal in parallel branches without a rebase step immediately before merge.

`peer-baseline.js`/`session-baseline.js` themselves are not expected collision surfaces with any other named in-flight task (per the recon's own confirmation) — this slice's only production edits to `peer-baseline.js` are additive (new exports, new function, extended existing function bodies).

**Note (see the header Addendum, 2026-07-23):** the "zero edits to `session-baseline.js`" claim above holds for THIS Slice-4c commit. A sibling fix to `session-baseline.js`'s `tickGroupDisposition` (a garbled `census_state` marker value now fail-closes to `"unknown"` instead of silently defaulting to `"complete"`) — the same defect class the Stage 2 adversarial review also found in this slice's own `availability_signature` handling — landed in a SEPARATE atomic commit the same session. Both are fixed; see the header Addendum item 1.

---

## 8. Definition of Done

- All three pieces (marker + signature, `peer.count_drop`, regime-keyed fold for BOTH `peer.count_spike` and `peer.count_drop`) ship in one coherent change-set — not piecemeal (per the originating plan's own explicit "should ship together, not piecemeal" instruction).
- Every existing test (peer-baseline, fact-translators, alert-intelligence, calibration, session-baseline) stays green, including the 5 explicitly-identified breaking fixtures in `fact-translators.test.js` fixed in the same commit.
- The retroactive `peer.count_spike` false-positive-class fix (Decision 2(c)) has its OWN dedicated regression test (§6, `computeWindowedPeerStats` mixed-regime fixture) — this is the actual point of the regime-keyed baseline and must not ship unverified.
- `peer.count_drop` never fires without the census marker present and `DEFAULT_PEER_MIN_SAMPLE_COUNT` same-signature ticks accumulated (cold-start-forever-without-the-marker pinned by test).
- `peer.count_drop`'s stored severity is unconditionally `"warning"` — pinned by a hard-cap test mirroring `peer.count_spike`'s own MUST-FIX-1 test.
- `peer.count_drop` classifies as `unknown_namespace` under the most permissive `enabled_namespaces` config — pinned by a public-seam `adjudicateAlertNotifications` test, not merely the private `classifyAlertNamespace` unit.
- `peer.count_drop` reaches an operator via the deterministic non-LLM delivery path (`emitSessionAlertSignals`) — pinned by a delivery test.
- `peer.count_drop` is visible to `descartes learned calibration` — pinned by the extended calibration attribution test.
- Zero LLM anywhere in this slice's own code (grep confirms no `createSession`/prompt-building import in `peer-baseline.js`, `fact-translators.js`, or the new `calibration.js`/`alert-intelligence.js` lines).
- Zero new execFile/host I/O surface (grep confirms no new `execFile`/`spawn` import anywhere touched by this slice).
- Whole `tools/descartes-cli` suite green; `learned.json` kill switch still gates the entire path end-to-end (short-circuit-to-`[]`-before-I/O test for `computePeerBaselineCandidates` still passes with the new drop path folded in).
