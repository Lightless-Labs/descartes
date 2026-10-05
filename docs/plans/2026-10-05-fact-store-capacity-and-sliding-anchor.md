# Fact-Store Capacity and Sliding Anchor: Make Default-On Watching Work on Real Hosts

**Created:** 2026-10-05
**Status:** PLAN. Awaiting operator decisions (§12) and a pre-build multi-model plan review (Fable code-grounded, daybreak-blue, Astra) per `docs/solutions/2026-09-14-multi-model-review-and-planning-playbook.md`.
**Reviewed:** 2026-10-05 (adversarial plan review, NEEDS-REVISION(7) → folded)
**Addendum:** 2026-10-05: S0 grounding (§15), then S1 and S2 built on `feat/fact-store-capacity-2026-10` (§16). G1 ran; Q6 pulled in as S3b (§17).
**Addendum:** 2026-10-05: S3 (eligibility horizon) and S3b (first/last-seen set) built, plus the G1 re-gate LOWs (§18). S4 not started; the branch awaits G2 after S4.
**Closes:** `todos/2026-09-06-f2-tier2-fact-store-sliding-anchor.md` (F2-Tier2), including the F2-Tier1 over-claim carve-out (todo lines 18-22).
**Related:** `docs/plans/2026-09-20-detector-reported-recovery-coverage.md` (§7.7 intersection, §7.8 atomic landing, §8 build spec), `docs/plans/2026-09-10-watch-by-default-slice-1.md`, `docs/reviews/2026-09-06-trusted-state-step1-grounded-review.md` (F2-Tier2 section).
**Severity:** watch-by-default ships default-ON, but on a real host the six watch-tier detector families lock out within about a day and never recover. The feature does nothing on real hosts today.

Line numbers below are from HEAD `134e811` (read 2026-10-05). The KEY CODE REFS in the 2026-09-20 plan are stale (for example, its `daemon.js:637-665` is now `:810-851`). Do not reuse them.

---

## 0. Summary

- **What goes wrong.** On a real macOS host each hourly structural tick writes 185,139 bytes of facts. The shared 5 MB store (`fact-store.js:19`) fills after 28 ticks. From then on, every structural tick byte-evicts records. Byte-cap eviction is treated as a loss channel, so two things happen. History reads as `degraded` until 31 days after the last eviction. Every eviction also re-arms every detector's cold-start anchor. The count rules could never establish even without the loss: they need 30 samples, and a 5 MB store holds at most 28 ticks.
- **R0b: coverage contract (every store).** Eviction always removes the oldest records first, so it narrows coverage rather than breaking it. Treat it that way. The store records an exclusive floor: the newest evicted `ts`. Eviction becomes tick-aligned. `readFactPoints` never returns a point with `ts <= floor` and reports `certified_after_ts`. `last_bytecap_evict_ts` leaves every loss list. Detectors gain a per-rule **eligibility horizon** check. It can only remove an evaluation; it never extends what the store claims.
- **R0a: per-family stores.** Each family gets its own store (service, process-lineage, scheduled-job, session, peer, canary, network, provenance), with its own ledger and its own budget sized from the measured volumes. The daemon's §7.7 history veto becomes **per family**. Without that, an eviction in one family freezes every other family, and a veto that reads only one file can authorize a recovery it never checked. With isolation and bounded per-tick volume, inflating one family can narrow only that family, and only down to a floor we can prove.
- **Migration.** Per-family stores start fresh and the legacy `facts.jsonl` is quarantined. The 31-day tail disappears on the next read. Detector lockout clears through the normal 6-tick re-accumulation. Count rules establish after 30 complete ticks (about 30 h).
- **What we give up.** Novelty memory becomes "certified history" (about 5 days for service and 8 days for lineage at default budgets) instead of a 30-day window. Real hosts never had that window: they had zero detection. §5 covers this directly.

---

## 1. Goal and non-goals

**Goal.** On a host producing real per-tick volume, every default-on watch detector family establishes within bounded time, keeps evaluating through routine eviction, and recovers its alerts. Never-fabricate must hold throughout (§6), the §7.7 recovery intersection must stay intact, and every status surface must agree with what the detectors actually do.

**Non-goals.**
- Restoring 30-day novelty memory for service and process-lineage. The compact first/last-seen set is a follow-up (§5.4, §12 Q6).
- Any change to `integrity_level` (`daemon.js:174`). The new floor field can be forged by a same-UID process, like everything else in the store. This plan adds no protection claims.
- Changing the corrupt, schema-invalid, continuity-break, or future-fact loss channels. All of them stay losses.
- Performance work beyond the budget and read-cost guard. Incremental tail-reads and caching are a possible follow-up. Sharing one read between the daemon and the detectors is ruled out because it would weaken §7.7 independence.

---

## 2. Measured volume and read cost (real host, 2026-10-05)

**Per-tick volume.** Measured from `~/.local/state/descartes/learned/facts/facts.jsonl`: one structural tick, 722 records, 185,139 B. This confirms the "~186KB" figure.

| fact_name | records/tick | bytes/tick | avg B/record | B/day (24 ticks) | B/31 d (744 ticks) |
|---|---:|---:|---:|---:|---:|
| `service.presence` + `service.census` | 518 + 1 | 132,007 | 254 | 3.17 MB | 98.2 MB |
| `process.lineage_edge` + `.census` | 175 + 1 | 44,223 | 251 | 1.06 MB | 32.9 MB |
| `provenance.warning` | 8 | 3,254 | 407 | 78 KB | 2.4 MB |
| `scheduled_job.presence` + `.census` | 7 + 1 | 2,605 | 333 | 62.5 KB | 1.94 MB |
| `network.listening_port.owner` | 8 | 2,150 | 269 | 51.6 KB | 1.6 MB |
| `peer.presence` (incl. markers) | 2 | 646 | 323 | 15.5 KB | 0.48 MB |
| `session.presence` (marker only) | 1 | 254 | 254 | 6.1 KB | 0.19 MB |
| **total** | 722 | **185,139** | | **4.44 MB** | **137.7 MB** |

Peer plus session is about 900 B/tick, or 0.65 MB over 30 days. This confirms R0a's figure. These peer and session numbers are a **lower bound**: this host has one peer and no sessions. Budgets below are sized with headroom.

**Correction to the review's grouping.** On this host, `scheduled_job` is not a bulk family. At 2.6 KB/tick it needs about 1.9 MB for 31 days, so it fits 30 days in its own store. It still needs R0b because its worst case is about 67 KB/tick (`job_limit` is clamped to 1-200 at `tools/scheduled-jobs.js:23`). Only **service** and **process-lineage** cannot hold 30 days at an affordable budget.

**Worst-case per-tick bytes.** Per-tick entity counts are capped by the collectors, so worst-case bytes per tick are bounded. The "avg" column is entity cap × measured average record size. The "max-key" column uses an estimated ~470 B maximum record (`MAX_FACT_ENTITY_KEY_LENGTH = 256`, `fact-store.js:37`). That is the figure the budget invariant must use. **Both columns are provisional; step S0 pins exact values** from maximum-length keys and attributes:

| family | cap (source) | worst B/tick (avg) | worst B/tick (max-key est.) |
|---|---|---:|---:|
| service | `DEFAULT_SERVICE_CENSUS_CEILING = 1000` (`tools/services.js:27`); hard clamp 5000 (`:31-36`) | ~254 KB (hard clamp: ~1.27 MB) | ~470 KB (hard clamp: ~2.35 MB) |
| process-lineage | `MAX_LINEAGE_EDGES_PER_TICK = 200` (`tools/processes.js:187`) | ~50 KB (this host is at 175, near the cap) | ~94 KB |
| scheduled-job | `job_limit` default 80 (`tools/scheduled-jobs.js:11`), clamp 1-200 (`:23`) | ~67 KB | ~94 KB |
| session | `DEFAULT_SESSION_ENTITY_LIMIT = 200` (`tools/sessions.js:33`) + markers | ~51 KB | ~94 KB |
| peer | VPN 200 (`tools/vpn-peer-status.js:40`) + Tailscale 200 (`tools/tailscale-status.js:23`) + markers | ~130 KB | ~188 KB |
| canary | `MAX_CANARIES = 200` (`tools/canary.js:9`) | ~60 KB | ~94 KB |

**The session and peer limits are not clamps.** `tools/sessions.js:200`, `tools/vpn-peer-status.js:395` and `tools/tailscale-status.js:111` all use `Math.max(1, Number(opt) || DEFAULT)`, with no upper bound. The 200s above are defaults, not caps. S4 either adds an upper clamp to each one, or T8 pins the values the daemon path actually passes. Without one of those, the per-family worst case is unbounded.

**Read cost.** Benchmarked on this dev machine with the real tick replicated, using `readFactPoints` and `enforceFactRetention` (scratch bench, not committed):

| store size | `readFactPoints` (31 d window) | retention rewrite |
|---:|---:|---:|
| 5 MB | ~74 ms | ~0.38 s |
| 16 MB | ~235 ms | ~1.4 s |
| 32 MB | ~520 ms | ~2.7 s |
| 64 MB | ~1.07 s | ~4.5 s |
| 128 MB | 2.2-7.1 s | ~15 s |

`readFactPoints` reads and parses the whole file and hashes the committed prefix (`fact-store-integrity.js:281-285`) on **every** call. Today about 8-9 full reads happen per 60 s fast tick: the daemon history read plus six detectors, plus correlation, active-constraint and provenance-warning (`tools/provenance-warnings.js:329-336`) when learned is on. A store holding 31 days (~138 MB) would cost 15-50 s of CPU per 60 s tick, which is infeasible. That rules out "just raise the cap" as a full fix. Retention runs on the structural tick after collection, outside the 45 s collection deadline (`daemon.js:984-988`). At 128 MB it would still take about 15 s per hour.

---

## 3. How the lockout happens

The daemon passes `now: options.now ?? ts` to the fact append (`daemon.js:1053`). The retention pass's `nowIso` therefore equals the tick's own `ts`.

**Leg A: the 31-day tail.**
1. Once full, `enforceFactRetention` byte-evicts the oldest candidates (`fact-store.js:272-285`).
2. `prepareFactIntegrityLedger` stamps `last_bytecap_evict_ts = nowIso` (`fact-store-integrity.js:439`) and sets `first_degraded_ts` (`:445`).
3. `buildCompleteness` scans `LOSS_CHANNEL_FIELDS`, which includes `last_bytecap_evict_ts` (`:505-511`), with `lossAtOrAfter(.., asOfMs)` (`:588`). `asOfMs` is `now − 31 d` (`welford-stats.js:20`, `daemon.js:1144`), so the result is `status: "degraded"` / `in_window_loss` for 31 days after the last eviction.
4. `factHistoryTrustworthy` returns `history_degraded` at `fact-store-completeness.js:83`. That check runs before the anchor comparison at `:84`, so no anchor can rescue it.

**Leg B: the anchor re-arms every tick.**
1. Six detectors each keep their own copy of `COMPLETENESS_LOSS_TIMESTAMP_FIELDS`, which includes `last_bytecap_evict_ts`: session `:146-157`, peer `:150`, service `:120-131`, process-lineage `:90` (field at `:93`), persistence `:107` (field at `:110`), canary `:86`. Each also has its own copy of `hasCompletenessLossAfterAnchor`: session `:159`, peer `:160`, service `:133`, process-lineage `:103`, persistence `:120`, canary `:101`.
2. On each hourly structural tick the marker is newer than the detector's `cold_start_since_ts`. `completenessLossAfterAnchor` is true, so `enteringColdStart` fires (e.g. `session-baseline.js:751-756`) and the anchor moves to this tick's `nowIso` (`:766-771`).
3. Between structural ticks, Leg A keeps `historyTrust.trust` false. The re-accumulation branch (`:772-785`) never runs, so the detector stays pending.
4. The next structural tick evicts again and the cycle repeats. The same pattern appears at `service-baseline.js:566-581` and `:936-955` (lockout blocks centred on `:578` and `:948`), `peer-baseline.js:777-798`, `process-lineage-baseline.js:408-423`, `persistence-baseline.js:358-373`, and `canary-baseline.js:623-624`.

**Leg C: recovery stays frozen and the no-anchor consumers go silent.**
- The daemon makes its own call with no anchor (`daemon.js:1151`). It gets `trust:false`, so `computeCoveredAlerts` vetoes all ten `HISTORY_DEPENDENT_ALERT_RULE_IDS` (`:101-112`, `:824-827`). Those alerts stay frozen even if a detector reports coverage.
- `constraint-miner.js:366`, `shadow-store.js:303` and `incident-correlation.js:323` take the no-anchor branch and go silent.

**Leg D: count rules can never establish at the 5 MB default, even with no loss.** `DEFAULT_MIN_SAMPLE_COUNT = 30` (`session-baseline.js:83`) and `DEFAULT_PEER_MIN_SAMPLE_COUNT = 30` (`peer-baseline.js:66`). At 185 KB/tick, a 5 MB shared store holds 28 ticks, or at most 27 complete ones once the oldest split tick is excluded. So R0b over the shared store **at today's cap** does not fix session and peer. *(Review fold:)* R0b with a larger shared cap would: at 16 MB it holds about 88 ticks, which is at least 30. Leg D therefore argues for a bigger budget, not specifically for R0a. The case for R0a is in §4.7: per-family isolation, a per-family §7.7 veto, and smaller per-store reads.

**Leg E: the CLI status is wrong.** `baseline status` computes its phase from persisted store state and the count of complete groups after the anchor (`baseline.js:112-133`). It never consults history trust. While evictions continue, the anchor keeps moving, so status shows "still learning — 0/1 of 6". If evictions stop (for example, the operator raises the cap), the anchor stays put. Status then shows **"watching"** once 6 groups land, while Leg A keeps the detector gated for up to 31 days.

**Why raising the cap alone fails.** A bigger cap only delays when eviction starts; Leg B resumes once it is full. Already-evicted installs keep Leg A for 31 days (the blackout). Avoiding eviction entirely needs about 138 MB, which is ruled out by read cost (§2).

---

## 4. Design

### 4.1 R0b: the store coverage contract (applies to every store)

**Why this is sound.** The kept set is always a suffix of the candidates sorted by `tsMs`:
- The sort is at `fact-store.js:268-270`.
- The loop at `:274-281` keeps from the newest record backwards and `break`s at the first record that does not fit. It never skips a record to fit an older one.
- So byte-cap eviction can only remove an oldest-end prefix. It narrows coverage; it cannot open a gap inside the retained range.
- Truncation by another process remains a **continuity break**, caught by the prefix-digest check (`fact-store-integrity.js:276-290`). Reclassifying eviction covers only the store's own suffix-preserving eviction. It does not weaken tamper detection.

**Why the boundary must be strict.** V8's sort is stable, so records with the same `ts` keep file order, and an eviction can split a tick. The census marker usually comes **after** the tick's presence facts, but not always last:
- service `fact-translators.js:141`, scheduled-job `:359`, process-lineage `:384` and canary `:504` emit it last.
- Session (`:773`) emits presence facts, then the census marker, then an optional overflow marker.
- Peer emits VPN presence facts, the VPN census marker (`:984`), and an optional VPN overflow marker. The daemon then appends the Tailscale `peer.presence` facts and an optional Tailscale overflow marker after that (`fact-translators.js:998-1007`, concatenated at `daemon.js:1024-1028`). The Tailscale translator emits no census marker of its own.

An oldest-first trim of a split tick removes the earliest records first. It can remove presence facts and keep the marker, plus whatever follows it. The result is a tick that looks `complete` but is missing entities, which would produce a false `service.disappeared` or `peer.count_drop`. Today the lockout hides this. R0b would expose it unless the boundary is strict.

The safety argument rests on **tick-alignment** (item 1 below), not on marker order. With tick-alignment, no part of a split tick survives, whatever the order. T3 fixtures must use the real per-family order above.

**Changes.**
1. **Tick-aligned eviction plus an assertion.**
   - After the suffix loop: if the oldest kept record's `ts` equals the newest evicted record's `ts`, evict every kept record with that `ts` too.
   - Add a defense-in-depth throw next to the accounting check (`:290-292`): `max(evicted tsMs) < min(kept tsMs)`, or abort the pass. The coverage claim depends on this suffix property, so it is pinned in code.
   - The degenerate cases follow from this. A single tick larger than the cap (`:278`) evicts the whole tick. `maxBytes: 0` evicts everything. Both leave an empty store with a set floor, which reads as "no coverage / ineligible". It never reads as intact-with-history.
2. **A new ledger field `bytecap_floor_ts`** (exclusive; `null` means byte eviction has never happened in this ledger lineage).
   - Each pass sets it to `max(prior floor, max ts evicted this pass)`, so it never decreases **within a continuous ledger lineage**.
   - `prior floor` comes from the existing ledger, including a pending pass's value. It is never recomputed from scratch, which keeps crash and retry (`alreadyCounted`/`pending_pass`, `:361-366`, `:476`) idempotent.
   - **A missing ledger over a non-empty store is a continuity break.** *(Review fold, HIGH-1.)* Today a missing ledger (`bootstrap = ledger === null`, `fact-store-integrity.js:318-323`) is deliberately left out of the continuity-break stamp (`:337`: only `invalid`, `unreadable` and pass-id exhaustion stamp one). Under R0b that would reset the floor to `null` while `facts.jsonl` survives, for example after an operator cleanup, a partial restore, or a half-done M3 move. Two passes later the store reads intact with `certified_after_ts: null`. `certifiedHorizonOk` would then pass at once, and post-rollback ticks with `ts <= F` would become readable again.
     - Fix: extend `invalidLedgerBootstrap` to cover `ledgerReason === "missing" && live.exists && live.record_count > 0`. That case stamps `last_continuity_break_ts = nowIso`, exactly like `invalid`.
     - A missing ledger over an absent or empty store (first run, and M2's fresh per-family stores) still bootstraps clean.
     - Cost: after ledger loss, that family reads `degraded` for 31 days, the same bounded recovery as an invalid ledger. This also closes the pre-existing hole where deleting the ledger let a truncated store re-certify itself.
     - **Superseded (review fold, LOW-1/LOW-4, post-S2).** "Absent or empty" above is too permissive: an *existing* 0-byte store with no ledger can only be our own prior retention output (the rewrite always writes a ledger alongside it; a genuine first run never writes `facts.jsonl` before its first ledger exists) -- so it is never a genuine first run, only an evicted-then-emptied store whose ledger was separately deleted. The shipped rule drops the emptiness clause entirely: `missingLedgerOverExistingStore = ledgerReason === "missing" && live.exists === true`. Only a genuinely absent store (`live.exists === false`, ENOENT) still bootstraps clean. `appendFactPoints` resolves the first-run shape by running one retention pass against the pre-append store whenever the ledger is missing, before its own append -- so this check is never contaminated by the same call's own new data, and the old `appendedToEmptyStore` carve-out is removed with no exception left in the rule.
     - Rejected alternative: seeding the floor from `live.newest_ts`. It breaks the `total > 0 ⇔ floor !== null` validation, and it would leave established detectors un-re-armed over a store whose lineage has just broken (contrary to I8).
   - **The floor is never clamped backwards *silently*.** It is never passed through `clampForward` (`:393-404`), because moving it backwards without a loss would certify evicted records.
   - **Future-dated floor.** *(Review fold, MEDIUM-3; replaces "bounded by the size of the skew".)* Eviction can set the floor to at most pass `nowIso + FUTURE_FACT_TOLERANCE_MS` (`fact-store.js:265-270`). With a clock that is N days fast, the floor is about real time + N days. Once the clock is corrected, the family would be blind for N days while reading intact with coverage "narrowed". That is an unbounded blind, which reverses Fix 1 (`fact-store-integrity.js:378-392`).
     - Fix: when the prior floor exceeds the pass's `nowIso + FUTURE_FACT_TOLERANCE_MS`, clamp it to `nowIso` **and in the same pass stamp an in-window loss** (`last_continuity_break_ts = nowIso`).
     - The stamp is what makes the backwards move safe. The store reads `degraded` and detectors re-arm, so nothing between the clamped and the original floor is ever trusted. The blind becomes Fix 1's bounded one: one 31-day window plus a cold-start re-arm.
     - Do not drop the stamp in a later edit. Without it, the clamp certifies evicted records.
   - New validation in `isValidFactIntegrityLedger` (`:170-209`): `bytecap_evicted_total > 0 ⇔ bytecap_floor_ts !== null`.
   - **Floor plausibility validation.** When the store is non-empty, require `bytecap_floor_ts < continuity.last_rewrite_newest_ts`, because the floor is below every kept record. A ledger that fails this is `invalid`, so a forged far-future floor is rejected, not silently accepted. The empty, all-evicted case has `last_rewrite_newest_ts === null`, so there is no in-ledger bound. **S0/G1 item:** decide its bound, for example the last committed pass's `nowIso + 6h`, which would need a new ledger field, or rely on the future-floor clamp above.
   - Bump the schema version. `hasExactKeys` (`:179`) and the canonical writer (`:237-247`) both need the key.
   - **The upgrade must go through `migrateLedgerShape` (`:100-118`, the Fix-0 precedent).** It must set `schema_version: 2` and add `bytecap_floor_ts` (via M4, §4.6) **before** validation runs at `:222-223`.
   - Why: the validator rejects any `schema_version !== FACT_INTEGRITY_SCHEMA_VERSION` (`:180`). A rejected ledger is treated as `reason: "invalid"`. `prepareFactIntegrityLedger` then takes the invalid-ledger bootstrap path (`:337`) and stamps `last_continuity_break_ts = nowIso` (`:440`). That is an in-window loss, so the store would read `degraded` for 31 days, recreating exactly the tail this plan removes. T6 pins that a valid v1 ledger upgrades to intact and never to a continuity break.
3. **The read side enforces the floor.** `readFactPoints` drops every point with `ts <= bytecap_floor_ts` before the window filter (`fact-store.js:406`). `buildCompleteness` reports two separate fields:
   - the raw `bytecap_floor_ts`, which is what I1, I2 and the horizon predicate use;
   - `certified_after_ts = max(bytecap_floor_ts, retention cutoff)` (or `null` when the floor is `null`), which is what status and the novelty diagnostics display. *(Review fold, LOW.)* The range between the floor and `now − 30 d` has been age-evicted, so reporting the bare floor would over-claim. Horizon math is unaffected, since every `H_max` is far below 30 days.

   It also reports `oldest_certified_ts`, the oldest returned point.
   - This filter lives **only** in the store. Six copies of a filter in six detectors means six chances for one to be missing and fabricate.
   - Points at or below the floor are physically absent anyway once eviction is tick-aligned. The filter is a second layer that also covers ticks appended later with `ts <= floor` after a clock rollback.
4. **Reclassify byte-cap eviction.**
   - Remove `last_bytecap_evict_ts` from `LOSS_CHANNEL_FIELDS` (`fact-store-integrity.js:505-511`), from `LOSS_TIMESTAMP_FIELDS` (`fact-store-completeness.js:1-16`), and from the six detector arrays (§3 Leg B).
   - Stop stamping `first_degraded_ts` on byte-cap eviction (`:445`).
   - Keep `last_bytecap_evict_ts` and `bytecap_evicted_total` as informational fields. `constraint-store.js:302` and `:450` (`LOSS_TS_FIELD_NAMES`) must stop labeling it a loss.
   - Before editing, inventory `last_bytecap_evict_ts` across `src` and `test`, and record the exact list. This is a "same value in N places" change; follow `plan-before-dispatch`.
   - **Use `grep -a` or ast-grep, never plain `grep`.** *(Review fold.)* `canary-baseline.js` contains a literal NUL byte (`:258`), and so do `fact-translators.js` and `peer-signature-store.js`. Plain `grep -rl last_bytecap_evict_ts src` treats them as binary. On this machine it returns 8 files and misses the canary copy; `grep -a` returns 9. The same rule applies to every S0 inventory, including `continuity_oldest_ts`, `readFactPoints`, `appendFactPoints` and `enforceFactRetention`.
5. **Do not add a fourth `status` value.** `factHistoryTrustworthy` maps any status other than intact/degraded/unknown to `history_unknown` (`fact-store-completeness.js:69-70`), which would recreate the lockout. `status` stays loss-based and three-valued. Narrowing is reported only through `certified_after_ts`, together with a `coverage: "full" | "narrowed"` display field.
6. **Fold in the F2-Tier1 over-claim.** `continuity.oldest_ts` only ever moves older (`:356-359`) and can predate the retained facts. It is not a coverage boundary. `certified_after_ts` and `oldest_certified_ts` replace `continuity_oldest_ts` (`:545`) on operator surfaces. A code comment and a test enforce that no trust path reads `oldest_ts`.
7. **Deduplicate before changing behavior.** Move the six detector copies of the loss-field list and `hasCompletenessLossAfterAnchor` into `fact-store-completeness.js` exports, so the next channel change is one edit (step S1). The trust semantics of corrupt, schema-invalid, continuity, and future-fact losses are unchanged.

### 4.2 Eligibility horizon (separate from cold start)

The grounded review requires that a minimum-span floor gate **detector eligibility only** and never extend what the store claims. So:

- **A shared registry** declares `horizonMs` per rule_id in a new `fact-families.js` (§4.3). Both the detector predicate and the daemon veto (§4.4) read it. §7.7 needs an independent daemon-side check that still fires if a detector forgets the gate.
- **The predicate** is `certifiedHorizonOk(readResult, { nowMs, horizonMs })`, pure and fail-closed:
  - `bytecap_floor_ts === null` → `true`. Nothing was narrowed, so the existing per-detector minimum-history gates govern, and day-1 behavior is unchanged.
  - Otherwise it requires `nowMs − floor_ms >= horizonMs`, using the raw floor (§4.1 item 3).
  - *(Review fold, Q2 consequence.)* Under "applies only once narrowing has happened", a family whose budget holds fewer ticks than its horizon is eligible on day 1, when the floor is `null` and 6 h of novelty memory exists. It becomes ineligible at its first eviction. The §4.5 config floor (budget ≥ the T8 invariant) prevents this at configured budgets. Note also that every M2-upgraded host, not only low-volume ones, starts with day-1 novelty memory of about 6 h.
  - Missing or malformed completeness, or a floor in the future, → `false`.
  - **(LOW-2, review fold.)** `bytecap_floor_ts === null` is ambiguous on its own: it also means "no ledger at all" (`buildCompleteness` now reports `coverage: "unknown"` in that case, not `"full"` -- fixed post-S2). S3 must gate `certifiedHorizonOk` on a VALID ledger (`coverage !== "unknown"`), not merely on the floor being `null`, or a missing/invalid ledger would read as day-1-eligible instead of failing closed.
- **Per-detector gating.** A rule is evaluable when `!coldStartPendingThisTick && certifiedHorizonOk(...)`. When it is not evaluable the detector emits no candidates for that rule and reports no `evaluatedAlertKeys` for it (`session-baseline.js:831`, `peer-baseline.js:882`, `service-baseline.js:455-475`, …). The horizon is **per rule**: `session.count_drop` (statistical) and `session.churn` (fingerprint diff) have different horizons.
- **No cold-start re-arm.** Narrowing is not a trust loss. Data in `(floor, now]` is complete. Re-accumulation counts only points above the floor, so it is automatically conservative. A detector whose horizon recovers resumes immediately and does not need 6 more ticks. A distinct reason (`history_horizon_short`) goes to status surfaces, so they say "history horizon below minimum" rather than "still learning".
- **A short horizon is not fail-closed for novelty rules.** *(Review fold, MEDIUM-4.)* `service.appeared` builds `historical` from every prior complete group (`service-baseline.js:837-846`); process-lineage (`process-lineage-baseline.js:291`) and persistence (`persistence-baseline.js:247`) work the same way. Suppose an entity first appears while its rule is horizon-ineligible. By the time the rule resumes, the entity is already in `historical`, so it never alerts. A sustained short horizon is therefore a **novelty-absorbing window**, like a cold-start lockout. It suppresses alerts; it does not fabricate any. Consequences:
  - The budget config floor is the T8 invariant (§4.5 Config), so configured budgets cannot leave a family permanently horizon-short.
  - An operator-visible signal fires when any rule stays horizon-ineligible for more than `N` consecutive structural ticks (proposed `N = 24`). It shows in status (`history_horizon_short` with a since-timestamp) and as a fixed daemon alert. The alert's rule_id and `N` are pinned at S3.
  - §5 N5 records the loss. The §5.4 first/last-seen set is what would allow retroactive evaluation of entities first seen during such a window.
- **Non-detector readers get explicit horizon entries.** *(Review fold, MEDIUM-5.)* `constraint-miner.js:364-366` deliberately refuses untrustworthy history: "A truncated or otherwise untrustworthy history can hide counterexamples and mint an over-strong draft." Once byte-cap eviction is no longer a loss, the miner's no-anchor trust check would pass on narrowed history. That silently reverses the guard. So the registry gives the miner, shadow and tuning readers horizon entries:
  - **miner:** mine only when `bytecap_floor_ts === null` or `now − floor ≥` its mining span (`DEFAULT_MIN_OBSERVATION_DAYS = 7`, `:23`, or the configured value);
  - **shadow:** the same horizon as the constraint it shadows;
  - **tuning:** no gate needed for correctness (`tuning-store.js:621-622` makes no absence or novelty claim), but it reports `certified_after_ts` with its backtest so the window is visible.
  - Consequence (§5 N6): at the default 16 MB service budget (~5.3-day typical horizon), service-presence mining never runs.
- **Novelty diagnostics** (`service.appeared`, `process.lineage.novel_edge`, `scheduled_job.appeared`) carry `history_certified_after_ts`. That turns "not seen in this host's recent history" (`service-baseline.js:885`) into a claim with a stated scope. Confirm `sanitizeDiagnostics` (`diagnostics-sanitizer.js:138`) passes ISO strings through.

Recommended `horizonMs` (structural interval 1 h, `daemon.js:66`; operator Q2):

| rule_id | horizon | grounding |
|---|---|---|
| `service.disappeared` | 6 h | `DEFAULT_SERVICE_MIN_HISTORY_TICK_COUNT` 6 (`service-baseline.js:79`), established ≥3 sightings (`:62`) |
| `session.churn`, `canary.tampered` (`canary_vanished`) | 6 h | ≥2 complete observations plus the 6-tick lockout |
| `service.appeared`, `process.lineage.novel_edge`, `scheduled_job.appeared` | **24 h** | minimum novelty memory, so daily cycles do not register as novel (new policy; Q2) |
| `session.count_drop`, `peer.count_spike`, `peer.count_drop` | 30 h | `MIN_SAMPLE_COUNT` 30 (`session-baseline.js:83`, `peer-baseline.js:66`) |
| `correlation` | 3 d | `CORRELATION_MIN_PEER_HISTORY_DAYS = 3` (`incident-correlation.js:71`) |

### 4.3 R0a: per-family stores

**Registry.** A new `fact-families.js` is a **leaf module**: it imports nothing from `daemon.js` or any detector. Every detector and the daemon import it. `service-baseline.js:64-69` documents why detectors cannot import from `daemon.js` (import cycle). It holds:
- A closed `FACT_FAMILY_BY_NAME`:
  - `service.presence`, `service.census` → `service`
  - `process.lineage_edge`, `process.lineage_edge.census` → `process_lineage`
  - `scheduled_job.presence`, `scheduled_job.census` → `scheduled_job`
  - `session.presence` → `session`
  - `peer.presence` → `peer`
  - `canary.presence`, `canary.census` → `canary`
  - `network.listening_port.owner` → `network`
  - `provenance.warning` → `provenance`
- Per-family `defaultBudgetBytes` (§4.5).
- Per-rule `{ families, horizonMs }` for every `HISTORY_DEPENDENT_ALERT_RULE_IDS` member, plus the non-detector reader entries (miner, shadow, tuning; §4.2).
- **Rule IDs as string literals.** *(Review fold, LOW.)* The rule-ID constants are exported by the detectors (`service-baseline.js:53`, `:711`; `session-baseline.js:59-60`; `peer-baseline.js:46`, `:48`; …). A leaf module cannot import them without creating an ESM cycle.
- Module-init throws, mirroring the duplicate-owner throw at `daemon.js:714-716`:
  - a fact_name mapped twice;
  - a rule referencing an unknown family.
- The "history-dependent rule with no registry entry" check cannot run inside the leaf module. It runs at `daemon.js` init, comparing `HISTORY_DEPENDENT_ALERT_RULE_IDS` and the imported detector constants against the registry's literals. That also catches a literal that has drifted from its constant.

**Paths.** `resolveFactStorePaths(descartesPaths, family)` → `learned/facts/<family>/facts.jsonl`, and `resolveFactIntegrityPaths` → `…/<family>/integrity.json` (today `fact-store.js:44-47`, `fact-store-integrity.js:51-54`). Family IDs come only from the closed registry, so there is no path-traversal surface. Each store has its own ledger `generation`. The retention sweep, status surfaces and every reader **iterate the closed registry, never the filesystem**. Nothing may treat a directory under `learned/facts/` as a family because it exists.

**`family` is a required argument.** *(Review fold, HIGH-2.)* `readFactPoints`, `enforceFactRetention` and `appendFactPoints` take `family` (or `families`) as a required argument and **throw when it is missing or unknown**. The legacy single-file path is removed, not defaulted. A reader that is not migrated then fails loudly. Without this, after M3 quarantines the legacy file, it would get ENOENT, read an empty point set, and silently lose detection. The S0 inventory of every `readFactPoints` call site (via `grep -a` or ast-grep) is checked against the reader list below, and T12 asserts the throw.

**Write path.**
- `appendFactPoints` routes points by fact_name. An **unknown fact_name throws before anything is written**, so a translator emitting an unregistered name fails loudly as a storage error. It is never misrouted or dropped silently.
- The daemon (`daemon.js:1004-1058`) groups `factPoints` by family and appends each group with that family's budget.
- Errors are reported per family and combined into `storage_write_error`/`retention_error` (`:1196-1210`).
- Retention runs for **every existing family store** on each structural tick, even with no new points. Today any append triggers a global retention pass; without this, a family with no new points would never age-evict and would keep data past 30 days.
- **A retention failure must be visible.** *(Review fold, LOW.)* `appendFactPoints` treats a retention throw as non-fatal (`fact-store.js:358-371`), and continuity stays ok. So a retention pass that keeps failing, including on the new suffix assertion, lets the file grow without limit and read cost climb with it. This happens today too; larger budgets make it costlier. Each family's status record carries `retention_error` with a since-timestamp. If retention has failed for more than `N` consecutive structural ticks, or the file exceeds its budget by more than one worst-case tick, status reports `retention_failing`.

**Readers move to their own family:**
- session (`:693-694`), peer (`:729-730`), service ×2 (`:517-518`, `:915-916`), process-lineage (`:360-361`), persistence (`:338-339`), canary (`:536-537`)
- correlation → `peer` (it filters `peer.presence`, `incident-correlation.js:331-333`)
- active-constraint (`daemon.js:524`), shadow (`shadow-store.js:300`) and the miner (`constraint-miner.js:362`) → `service` + `network` (`constraint-miner.js:32-35`)
- **provenance-warning** (`tools/provenance-warnings.js:329-336`, 3 h window at `:69`) → `provenance`. *(Review fold, HIGH-2.)* It reads facts on every fast tick when learned is on. `reduceLatestProvenanceWarnings` (`:218-221`) filters on `provenance.warning`. The result drives `deleted_exe_running` and `public_bind_no_supervisor`.
- **tuning** (`learned tuning mine`, `tuning-store.js:620-631`) → `service` + `network`, the constraint-target families. *(Review fold, HIGH-2.)* It reads the whole store today.
- **learned status** (`constraint-store.js:380`) → every family, reported per family (§4.4). *(Found while verifying HIGH-2.)* It is a whole-store read with no family today.
- `baseline.js:238-242` → per domain

A multi-family read returns:
- merged points;
- per-family completeness;
- a combined completeness: worst status, latest of each loss timestamp, newest floor.

Trust holds only if every family is trusted.

*(Review fold, HIGH-2: corrects an earlier false claim.)* `provenance.warning` **does** have a fact reader: `tools/provenance-warnings.js`, on every fast tick. Its store carries live detection, not just symmetry. Stopping the write would permanently remove `deleted_exe_running` and `public_bind_no_supervisor` detection (§12 Q8).

### 4.4 Per-family daemon history veto

**Why per family.** Two problems arise otherwise:
- A veto that reads only one file has no independent check on the other stores. A buggy peer detector could report coverage despite a loss in the peer store and its alert would recover, a fabrication the daemon should have caught (§7.7).
- A global veto across all stores would let any service-store loss freeze peer and session recovery. That is an over-freeze, which costs availability.

**Changes.**
- Replace the single read at `daemon.js:1136-1171` with one read per family that has at least one dependent rule whose owning tier is enabled. This keeps the "no I/O when disabled" invariant per family. Each read produces `familyTrust: Map<family, { trust, reason, certifiedAfterTs }>`, where `trust = factHistoryTrustworthy(read)` with no anchor (unchanged semantics).
- `computeCoveredAlerts` (`:810-851`) changes its veto set at `:824-827` to:
  `vetoed = alwaysExcluded ∪ failedLabelRules ∪ { r ∈ HISTORY_DEPENDENT : ∃ f ∈ families(r) : familyTrust.get(f)?.trust !== true } ∪ { r : !certifiedHorizonOk(familyRead(r), horizonMs(r)) }`
  - A family that was not read (missing map entry) counts as untrusted. This fails closed and covers the both-off branch (`:1170`) per family.
  - The tier veto (`tierVetoedRuleIds`, `:740-748`) is unchanged.
- Thread the result into both persistence passes (`:1387-1395`, `:1460-1465`).
- The final eligibility is the intersection: coverage ∩ tier veto ∩ per-family history veto ∩ per-rule horizon veto ∩ failed-label veto. §7.7 is preserved, now at family granularity.
- `FIXED_ALERT_RULE_IDS` and `containment.recommend.*` semantics are untouched.

**Why the reads stay separate.** The daemon and the detectors keep separate reads, on purpose (§7.7: "separate reads with different windows"). Budget for the extra cost (§4.5).

**Status surfaces become per family:**
- `fact_store_completeness` (`:1150`, `:1211`), as `{ <family>: {status, certified_after_ts, coverage, bytes, budget_bytes, cap_below_tick, retention_error?, horizon_short_since?} }`;
- `descartes learned status` (`constraint-store.js:338-363`, `:380`);
- `baseline status/inspect` (`baseline.js`), **per rule** rather than per domain where a domain mixes rules with different gates (§8 T11).
- **A family store that was never created**, such as peer on a host with no VPN or Tailscale, or canary with none configured, shows `not observed (no store)`. It does not show "still learning" or `unknown`. Its rules are still vetoed for recovery, since an unread family counts as untrusted.
- The horizon-short signal from §4.2 (`history_horizon_short` with its since-timestamp, plus the fixed daemon alert after `N` ticks).

### 4.5 Budgets

**Formula.** `budget_f = max(31 d × typical_f × headroom, H_max(f) × worst_f × 1.25)`, then bounded by read cost. `worst_f` is the **maximum-record-size** worst case (§2, max-key column), not cap × average.
- The second term makes "inflating volume can narrow but never blind" a **provable** property for the default configuration. T8 pins `budget_f ≥ (H_max(f)/interval) × worst_tick_bytes(f) × 1.25`.

**Superseded by S0 (§15.4; Q1/Q2 operator-accepted, §12).** The table below was provisional pending S0's measurement of exact worst-case tick sizes against pinned max-length-key record sizes (not the ~470 B estimate this section originally used) and Q2's accepted horizons (service.appeared/scheduled_job.appeared 48 h, process.lineage.novel_edge 6 d -- longer than this section's original 24 h placeholder). Re-running the T8 arithmetic with both inputs breaks three of the figures below even though the pinned max records are smaller than the ~470 B estimate, because the accepted horizons are longer. **The table's budget and H_max columns are updated to the S0-revised values** (service 18 MiB/48 h, process_lineage 10 MiB/6 d, scheduled_job 5 MiB/48 h, peer 16 MiB/72 h, session/canary/network/provenance unchanged at 4 MiB); see §15.4 for the full per-family arithmetic and the read-cost re-check (it does not trip T9's bound). The paragraphs immediately below (sized against the original 24 h/~470 B inputs) are kept for the historical record of why the original figures were picked, not as the current defaults:
- service: 24 × ~470 KB × 1.25 ≈ 14.1 MB, under 16 MB with about 13% margin. 16 MB holds ~35 worst ticks.
- process_lineage (~2.8 MB), scheduled_job (~2.8 MB) and canary (~0.7 MB) are comfortably inside their budgets.
- session: 30 × ~94 KB × 1.25 ≈ 3.5 MB, under 4 MB but thin.
- **peer fails at 12 MB.** 72 × ~188 KB × 1.25 ≈ 16.9 MB. The 3 d `H_max` comes only from correlation. S0 decided 16 MiB (§15.4), below the ~18 MB estimated here, because the pinned max peer record (392 B) is smaller than this section's ~188 KB-per-tick estimate implied.

**Decision rule if S0 breaks the read-cost bound.** If the pinned worst-case budgets push T9 past its bound, **stop before S4** and escalate to the operator. The options:
1. accept the higher read cost and raise T9's bound, with the measured figure;
2. lower that family's `H_max`, which narrows eligibility as recorded in §5;
3. pull incremental tail-read caching (a §1 non-goal today) into scope.

Do not quietly shrink a budget below the T8 invariant.
- Inflation is also visible: injected entities trigger novelty alerts, and a census over its ceiling is marked partial (`tools/services.js:31-36`).

**Original (provisional) table, kept for the historical record.** `typical horizon`/`worst-case horizon` below were computed against the budgets in THIS table, which Q1/Q2 (§12) superseded; they are stale for the three rows the S0-revised budget/H_max columns below changed (service, process_lineage, scheduled_job), and are not recomputed here -- see §15.4 for the current per-family arithmetic instead of trusting these two columns for those three rows.

| family | typical B/tick | worst B/tick | default budget (original) | typical horizon | worst-case horizon | H_max (original) |
|---|---:|---:|---:|---|---|---|
| service | 132 KB | ~254 KB | 16 MB | ~5.3 d (127 ticks) | ~2.75 d (66 ticks) | 24 h (yes) |
| process_lineage | 44 KB | ~50 KB | 8 MB | ~7.9 d | ~6.9 d | 24 h (yes) |
| scheduled_job | 2.6 KB | ~67 KB | 4 MB | 30 d (age-limited; needs 1.9 MB) | ~2.6 d | 24 h (yes) |
| session | ≥0.25 KB | ~51 KB | 4 MB | 30 d up to ~22 sessions | ~3.4 d | 30 h (yes) |
| peer | ≥0.65 KB | ~130 KB (max-key ~188 KB) | 12 MB (S0: likely ~18 MB) | 30 d up to ~52 peers | ~4.0 d (max-key ~2.7 d) | 3 d (**no** at max-key; see above) (correlation) |
| canary | 0 (AUTHOR off) | ~60 KB | 4 MB | 30 d | ~2.9 d | 6 h (yes) |
| network | 2.2 KB | S0 | 4 MB | 30 d (needs 1.6 MB) | S0 | n/a (AUTHOR; 3 h freshness) |
| provenance | 3.3 KB | S0 | 4 MB | 30 d (needs 2.4 MB) | S0 | n/a |

**S0-revised table (current defaults; §15.4, Q1/Q2 §12).** Worst B/tick is the pinned, real-translator figure (§15.3); H_max is the operator-accepted Q2 horizon. `required` is the T8 invariant, `(H_max/interval) × worst B/tick × 1.25`.

| family | worst B/tick (pinned) | H_max (accepted) | required | **default budget** |
|---|---:|---|---:|---:|
| service | 291,251 B | 48 h | 17,475,060 B (16.7 MiB) | **18 MiB** |
| process_lineage | 50,497 B | 6 d | 9,089,460 B (8.7 MiB) | **10 MiB** |
| scheduled_job | 71,075 B | 48 h | 4,264,500 B (4.07 MiB) | **5 MiB** |
| session | 67,130 B | 30 h | 2,517,375 B (2.4 MiB) | **4 MiB** |
| peer | 157,733 B | 72 h (correlation) | 14,195,970 B (13.5 MiB) | **16 MiB** |
| canary | 100,447 B | 6 h | 753,353 B (0.7 MiB) | **4 MiB** |
| network | S0 (not pinned; AUTHOR-tier) | n/a | -- | **4 MiB** |
| provenance | S0 (not pinned) | n/a | -- | **4 MiB** |

**Totals.** The S0-revised budgets sum to **65 MiB** (service 18 + process_lineage 10 + scheduled_job 5 + session 4 + peer 16 + canary 4 + network 4 + provenance 4), versus the original table's 56 MB (62 MB at peer's original ~18 MB estimate), versus 5 MB today. The read-cost decision rule (above) does not trip against the S0-revised figures: §15.4 re-checks T9's bound at ~2.1 s per fast tick, well under the 5 s bound. Steady state on this host is well below every budget; at typical volume, peer and session are only ever age-evicted, so they get the full 30 days. This is R0a's intent. R0b covers the adversarial case.

**Read cost per 60 s fast tick at defaults:**
- service: 3 reads (disappearance, appearance, daemon veto) × ~235 ms ≈ 0.7 s;
- process_lineage: 2 reads × ~120 ms;
- other families: negligible.

That totals about 1 s per minute (~1.6% of a core), versus about 0.55 s per minute today. Retention at 16 MB is about 1.4 s per structural hour. This count covers the watch-tier reads only. With learned on, active-constraint, provenance-warning, correlation and canary also read whole files every fast tick, against their own families. T9 must include them.

**Coupling.** If an operator raises the service census ceiling toward 5000 (about 1.27 MB/tick at the average record size), the 16 MB service store holds about 13 ticks. Service novelty becomes horizon-ineligible and `service.disappeared` (6 h) still works. *(Review fold, MEDIUM-4.)* That ineligibility is **not fail-closed**. It is a novelty-absorbing window (§4.2, §5 N5): services first seen during it never alert. The horizon-short signal (§4.4) surfaces it. Options are in §12 Q7.

**Config.** `watch.json` replaces the single `fact_store_max_bytes` (`watch-store.js:41-55`; mirrored in `learned.json`, `constraint-store.js:219-228`) with a per-family `fact_store_budgets` map.
- A missing, non-finite, or too-small value falls back to that family's default.
- **"Too small" means below the T8 invariant**, `(H_max(f)/interval) × worst_tick_bytes(f) × 1.25`, not below one worst-case tick. *(Review fold, MEDIUM-4.)* A budget between one tick and the invariant would be accepted under the old rule, and would leave the family permanently horizon-short, which is a novelty-absorbing window. Status reports a rejected value as `budget_below_horizon_floor`. `cap_below_tick` remains for the case where live per-tick volume exceeds the effective budget, for example a raised census ceiling.
- The legacy key is handled per §12 Q5. Note that `writeWatchConfig` (`watch-store.js:104-110`) runs `normalizeWatchConfig`, which fills in the 5 MB default (`:41-55`). Every written `watch.json` therefore carries `fact_store_max_bytes` whether or not the operator chose it. Q5's handling must tell the written-in default (`=== DEFAULT_FACT_MAX_BYTES`) apart from a deliberate operator value. Silently ignoring a value the operator raised would undo their decision; at minimum, surface it in status.

### 4.6 Migration (for installs that are already locked out)

- **M1: the 31-day tail.** Removing byte-cap eviction from the loss lists clears it on the next read. Status becomes intact unless another loss channel fires in the window. No timestamp rewriting is needed.
- **M2: fresh per-family stores (recommended).** New stores start at the existing missing-ledger bootstrap:
  - The first read is `unknown`. The second pass produces `continuity_ok: true` and `intact` (`fact-store-integrity.js:337`, `:348-355`, `:476`).
  - Detectors already pending keep their old anchor and clear after 6 complete ticks past it.
  - Established detectors (`cold_start_pending: false`, rare: only hosts that never evicted) re-arm once on the `unknown` read and clear after 6 ticks.
  - Count rules establish after 30 complete ticks.
  - Novelty memory starts over, the same as a fresh install.
  - **Cost.** On evicting hosts, nothing is lost, because they were locked out anyway. That covers the one real macOS host measured, and very likely typical Linux hosts too: about 200-300 systemd units plus lineage is an estimated ~110 KB/tick, which fills 5 MB in about 2 days. That Linux figure is not measured; S0 should confirm it on a Linux host. Low-volume hosts lose established baselines: about 30 h of statistical warm-up, plus a burst of possible false novelty alerts like a day-1 install.
  - No detector-store schema changes.
- **M3: quarantine the legacy store.** On first run, rename `learned/facts/facts.jsonl` and `integrity.json` into a quarantine directory **outside the facts tree**: `learned/facts-legacy-<iso>/`, not inside `learned/facts/`. *(Review fold, LOW.)* Inside the tree it would sit next to the family directories, and any filesystem walk would see it. Every reader and the sweep already iterate the closed registry (§4.3), so this is a second layer. No trust path reads it again. Deleting it (immediately or after 31 days) is §12 Q4.
  - **M3 is idempotent per file.** If a crash leaves only one of `facts.jsonl` / `integrity.json` moved, the next run moves whichever remains into the same quarantine directory, recorded by a marker file. It never treats the half-moved state as a live store. HIGH-1's missing-ledger stamp would also catch a leftover non-empty `facts.jsonl`, but no new code reads that path anyway.
- **M4: legacy ledger floor.** *(Review fold, LOW: M4 is dead code under the recommended M2.)* Under M2, the legacy ledger is quarantined before any v2 code reads it. The per-family ledgers are born as v2, and the S2 interim store never ships (§7). So **Q3 must be decided before S2**:
  - **Under M2:** M4 collapses to "a v1 ledger with `bytecap_evicted_total > 0` → start fresh", and "a v1 ledger with no evictions → v2 with `bytecap_floor_ts: null`". The schema bump still goes through `migrateLedgerShape`. This only matters in tests and for the S2 interim store.
  - **Under M2′:** the derivation below applies, but its pre-Fix-0 detection is **unsound** and must be replaced at G2′. Re-derive the bound through the future-drop loss channel instead.
  - The original M4 design, kept for M2′: `migrateLedgerShape` sets `bytecap_floor_ts = last_bytecap_evict_ts (L) + FUTURE_FACT_TOLERANCE_MS` when `bytecap_evicted_total > 0`, and `null` otherwise.
  - **Why it is a safe upper bound, unclamped case.** Every byte-cap candidate at a pass with time P satisfies `ts <= P + 6h` (`fact-store.js:265-270`). Byte-cap eviction only ever removes candidates, so every evicted record is `<= L + 6h`.
  - **Clamped case.** `clampForward` (`fact-store-integrity.js:394-398`) lowers L to a later pass's time N whenever `L > N`. Future drops need `ts > nowMs + 6h` (`fact-store.js:265-266`), so any retained record with `ts > N + 6h` at that pass would have been future-dropped, which is an in-window loss. Every record still retained is therefore `<= L + 6h`.
  - **The bound depends on the Fix-0 candidate filter.** The original plan detected a pre-Fix-0 ledger by the absence of `future_fact_dropped_total` / `last_future_fact_ts` on disk (the keys `migrateLedgerShape` adds at `:103-107`), and started such a store fresh. **That check is unsound.** *(Review fold.)* It looks at the ledger's last *write*, not its last *eviction*. An L stamped before Fix 0 survives later post-Fix-0 rewrites that do not evict, and those rewrites re-add the keys. So the check can pass while L still carries no upper bound.
  - **Why not "oldest retained ts".** After a clock rollback, appended records can sit below the true floor, and each retention pass re-sorts the file, so file order cannot reveal it.
  - The rule is pure (no file access) and conservative by up to 6 h.
- **Alternative M2′ (Q3): conditional split with inheritance.** Copy the legacy records into the family stores only if:
  - the legacy 31-day read is intact, with no corrupt or schema-invalid records and `continuity_ok`; and
  - either it never byte-evicted, or `last_bytecap_evict_ts + 6 h < now − 30 d`, so any partially evicted tick has aged out.

  Otherwise start fresh. This keeps baselines on low-volume hosts, but it adds a one-time copy path that carries trust. It must inherit every non-byte-cap loss marker into every family ledger and needs its own daybreak gate.

### 4.7 Rejected alternatives

- **Raise the cap only.** See §3. The lockout returns once the store is full, already-evicted installs stay blacked out for 31 days, and a 31-day store is ruled out by read cost.
- **Record service/lineage only on change.** It breaks four gates that assume a full census every tick:
  - sightings counted across complete groups (`service-baseline.js:354-358`, established ≥3 at `:62`);
  - `minHistoryTickCount + 1` complete groups (`:837`);
  - 3 h freshness of the latest complete group (`:349`, `:841`);
  - re-accumulation counting complete groups after the anchor (`:967-970`).

  The real need behind it is novelty memory, which is better served by a compact first/last-seen set (§5.4).
- **Anchor arithmetic only, or a minimum-span floor that keeps claiming lost coverage.** Both grounded reviewers rejected these. They either wedge or fabricate.
- **Split only peer and session, keep a shared bulk store.** Service would be read by lineage and scheduled-job too (read cost). Lineage volume would narrow service history. The veto would be coarser. The per-family design costs about the same and isolates more.
- **R0b plus a larger shared cap, no R0a.** *(Review fold, LOW; evaluated honestly.)* This would work on the count-rule axis: a 16 MB shared store holds about 88 ticks, enough for 30-sample rules (§3 Leg D). It is rejected on these grounds, not on Leg D:
  - **Isolation.** Inflating service or lineage volume would narrow peer, session and canary history too.
  - **The §7.7 veto.** One shared ledger means either a global veto, where any loss freezes every family's recovery, or no independent per-family check.
  - **Read cost.** Every detector would parse the whole shared file. At 56 MB that is about 4-5× the per-family figure.

  Its advantage is a much smaller change: no routing, no registry-driven paths, no per-family migration. If S0's read-cost numbers or the G2 review make R0a look disproportionate, this is the fallback, with the global veto accepted as a known availability cost.
- **A fourth completeness status (`narrowed`).** See §4.1 item 5: it would recreate the lockout through `:69-70`.

---

## 5. What this narrows, and why that is acceptable (why F2-Tier2 was deferred)

The todo deferred F2-Tier2 because "a monitor keyed off that store sees a shorter history than really exists on disk" and the fix "genuinely narrows detection strength". The concrete effects:

**N1: novelty memory equals certified history.** `service.appeared` treats the union of every complete group except the latest as its memory (`service-baseline.js:843-846`). The module header (`:700-708`) says truncated history can fabricate novelty. Under R0b, memory is the certified span: about 5.3 days for service and 7.9 days for lineage at default budgets, and 30 days for scheduled-job at typical volume. Entities that recur less often than the horizon will read as novel again (false positives, never misses).

**N2: the `service.disappeared` established set** is computed over the horizon. A service needs ≥3 sightings inside it, which takes about 3 h at hourly ticks. An alert for an entity that has left the union freezes until the entity reappears or the operator acknowledges it. That is the existing behavior at the 30-day retention edge (2026-09-20 plan §8.C), now reached at the horizon instead.

**N3: statistical baselines under inflation.** At typical volume, peer and session have their full 30 days (no change). Under adversarial inflation the baseline becomes "the last ≥30 h", still at least `MIN_SAMPLE_COUNT`.

**N4: adversarial narrowing has a floor.** The budget invariant (§4.5) guarantees worst-case horizon ≥ the eligibility horizon at default collector caps, so inflation cannot push any family below eligibility. Today, inflating service or lineage volume makes all six families lose detection; afterwards it affects only that family, only partially, and visibly. This holds **only at budgets at or above the T8 invariant**, which is why §4.5 enforces it as the config floor, and only once S0 has pinned the max-record-size worst case (§4.5: peer currently fails it).

**N5: a short-horizon window absorbs novelty.** *(Review fold, MEDIUM-4.)* A cold-start lockout absorbs novelty, and so does any period in which a novelty rule (`service.appeared`, `process.lineage.novel_edge`, `scheduled_job.appeared`) is horizon-ineligible. An entity first seen during it lands in `historical` and never alerts once the rule resumes. This is a missed detection, not a fabrication. It is bounded by the config floor and surfaced by the horizon-short signal (§4.2, §4.4). Retroactive evaluation of such entities needs the §5.4 first/last-seen set.

**N6: service-presence constraint mining is off at default budgets.** *(Review fold, MEDIUM-5.)* `DEFAULT_MIN_OBSERVATION_DAYS = 7` (`constraint-miner.js:23`) is longer than service's ~5.3-day typical horizon at 16 MB. With the miner's horizon entry (§4.2), service-presence mining never runs at default budgets. Network-port mining is unaffected, since that store holds 30 days. Restoring it needs either a service budget of about 22 MB or more, or the §5.4 set. Without the horizon entry, the miner would mint drafts while counterexamples older than the floor are invisible, which is exactly what `constraint-miner.js:364-366` guards against.

**Why this is acceptable.**
1. **The status quo on real hosts is zero detection** (§3). R0b moves every family from locked out to a bounded, reported horizon. It is never worse than today.
2. **The 30-day memory was never guaranteed.** After a cold start the code already fires novelty with about 6 h of history (`detectServiceAppearances` needs `minHistoryTickCount + 1` complete groups, `:837`, plus the 6-tick lockout). 30 days was a ceiling, not something the code assured.
3. **The store never claims more than it can back up.** With tick-aligned eviction, the raw floor (`bytecap_floor_ts`) exactly separates retained-and-complete data from evicted data, and any backwards move of the floor stamps a loss (I2). Coverage is never narrower than what is on disk (no unreadable remnant tick is kept), and never wider (oracle, §8). That satisfies both of the todo's acceptance criteria and the review's correction: the eligibility floor never extends store-claimed coverage.
4. **Novelty claims carry their scope.** Diagnostics include `history_certified_after_ts`, so the claim reads "not seen since X" rather than an unstated "never seen".
5. **Long novelty memory can come back without bulk retention** (§5.4).

**5.4 Follow-up (not in this plan): a compact first/last-seen set** for each novelty family. It would store an entity → `{first_seen_ts, last_seen_ts}` map, folded only from complete, certified ticks. That is O(#distinct entities); for service on this host that is about 518 × ~100 B. It would also become a new store that carries trust: deleting it means a cold start, and the fold must skip partial and uncertified ticks. It needs its own plan and daybreak gate (Q6).

---

## 6. Never-fabricate invariants (each pinned by a test)

- **I1.** `readFactPoints` never returns a point with `ts <= bytecap_floor_ts` (coverage oracle). The reported `certified_after_ts = max(floor, retention cutoff)` is never older than the floor.
- **I2.** `bytecap_floor_ts` never decreases across passes within a continuous ledger lineage, including crash/retry, clock rollback, and `clampForward`. It moves backwards in exactly two cases, and each one stamps an in-window loss in the same pass:
  - a ledger re-bootstrap over an existing store (missing, invalid or unreadable ledger, or pass-id exhaustion; §4.1 item 2, HIGH-1; *review fold LOW-1/LOW-4: "existing", not "non-empty" -- an existing 0-byte store with no ledger can only be our own prior output, never a genuine first run*);
  - the future-floor clamp (`floor > nowIso + FUTURE_FACT_TOLERANCE_MS` → `nowIso`; MEDIUM-3).

  A floor that fails the plausibility check (`floor < last_rewrite_newest_ts` for a non-empty store) makes the ledger `invalid`.
- **I3.** Byte-cap eviction keeps a strict suffix by timestamp (asserted in code), and is tick-aligned, so no kept record shares a `ts` with an evicted one. A split tick is never readable.
- **I4.** Corrupt, schema-invalid, continuity-break, and future-fact losses keep their current trust semantics: in-window degraded, and they re-arm anchors. External truncation is still a continuity break.
- **I5.** The eligibility horizon only removes evaluation. It never adds points, never extends `certified_after_ts`, and never re-arms or clears cold start.
- **I6.** Recovery requires coverage ∩ tier veto ∩ per-family history veto ∩ per-rule horizon veto ∩ failed-label veto. A family that was not read counts as untrusted.
- **I7.** An unknown fact_name throws before any write. Every fact_name maps to exactly one family, and every history-dependent rule maps to known families (fact_name and family checks at module init; rule coverage at `daemon.js` init). A `readFactPoints`, `appendFactPoints` or `enforceFactRetention` call with no `family`, or an unknown one, throws. There is no legacy-path default.
- **I8.** A store identity change (fresh per-family store) never carries trust over. The first read is `unknown`, and established detectors re-arm. A ledger lost over a surviving non-empty store is a continuity break, never a clean bootstrap.
- **I9.** No I/O when disabled: a family store is read only if some dependent rule's tier is enabled.
- **I10.** Per-family accounting (`kept + age + bytecap + future = valid`, `fact-store.js:290-292`) holds, with tick-aligned eviction counted as byte-cap.
- **I11.** `baseline status` reports "watching" for a rule only if that rule **would evaluate** on the same inputs. "Would evaluate" means: not cold-start pending, history trusted, horizon OK, and a fresh complete latest group. This is the per-rule predicate, not "the detector reports non-empty coverage". A domain with legitimately zero entities, such as no sessions, no jobs, no canaries configured, or no VPN, evaluates with empty coverage and must still read "watching". A family store that was never created reads `not observed (no store)`.
- **I12.** *(Review fold.)* Novelty-rule horizon ineligibility is reported, never silent. A rule horizon-short for more than `N` ticks raises the operator-visible signal (§4.2).

---

## 7. Sequencing (TDD, landing atomically)

This follows the precedent in 2026-09-20 §7.8: commit early and atomically on a branch, but push and ship S2-S6 together. **R0b alone is a safe state (it does not fabricate) but an incomplete fix** (§3 Leg D), so the branch is never shipped part-way.

- **S0: Ground and write the failing tests.**
  - Re-verify the line references above.
  - Compute exact worst-case tick bytes per family, using maximum-length entity keys.
  - Write the end-to-end lockout test (§8 T1) and confirm it fails on HEAD.
  - Inventory `last_bytecap_evict_ts`, `continuity_oldest_ts`, and every `readFactPoints` / `appendFactPoints` / `enforceFactRetention` call site across `src` and `test`, and record the full list of edits. **Use `grep -a` or ast-grep** (NUL bytes in `canary-baseline.js`, `fact-translators.js` and `peer-signature-store.js`; §4.1 item 4). Check the reader list against §4.3.
  - Pin the max-record-size worst case per family (§2), re-run the T8 arithmetic (§4.5: peer currently fails), and apply the read-cost decision rule if T9 breaks.
  - Decide the bound for the empty-store floor plausibility check (§4.1 item 2).
  - **Q3 is decided before S2** (§4.6 M4).
- **S1: Refactor with no behavior change.** Move the six loss-field lists and the `hasCompletenessLossAfterAnchor` copies into `fact-store-completeness.js` exports. The suite stays green.
- **S2: R0b over the existing single store.**
  - Ledger v2 with `bytecap_floor_ts`, M4 in whichever form Q3 selected, tick-aligned eviction, and the suffix assertion.
  - The missing-ledger-over-non-empty-store continuity stamp (HIGH-1), the future-floor clamp and stamp (MEDIUM-3), and floor plausibility validation.
  - Read-side exclusion; `certified_after_ts`, `oldest_certified_ts` and `coverage` in completeness.
  - Byte-cap reclassification everywhere, including no longer stamping `first_degraded_ts`.
  - Tests: T3 split tick (red then green), T4 oracle, T5 assertions and edge cases, T6 legacy ledger migration.
  - Zero-cap expectations: `evidence-freeze.test.js:374` asserts only that evidence bundles are isolated, and `fact-store.test.js:223` asserts only `kept_count === 0`. Neither pins completeness status, so both should survive unchanged. **Grep for any test asserting `degraded` / `in_window_loss` after an eviction that is byte-cap only. Verify each one, then either update it with a written rationale or escalate it to G1 if it pins a deliberate fail-closed property.**
  - Raise one question at G1 explicitly: should a zero-cap or all-evicted store read as `status: intact` with `coverage: narrowed` and an empty certified span? The alternative is a fail-closed `unknown`. That alternative would re-lock any store whose per-tick volume exceeds its budget, and the `cap_below_tick` status reason exists to surface that case instead.
  - **Daybreak gate G1.**
- **S3: Eligibility horizon.** Add the `fact-families.js` rule-horizon registry (string literals) and `certifiedHorizonOk`. Gate each rule in the eight producers: session, peer, service, service-appearance, process-lineage, scheduled-job, canary and correlation. Add horizon entries for the miner, shadow and tuning readers, the horizon-short signal (status plus the fixed daemon alert), and the novelty diagnostics field.
  - Tests: horizon too short → no candidates, no coverage, no re-arm; horizon restored → resumes on the same tick.
  - Horizon-short for more than `N` ticks → the signal fires.
  - Miner refuses to mine when `now − floor <` its mining span.
- **S4: R0a.**
  - Family registry, per-family paths and ledgers, routing with unknown-name throws, and a required `family` argument that throws when missing.
  - All readers switched (§4.3), including provenance-warning, tuning and learned status. Daemon per-family appends, the registry-driven retention sweep, and retention-failure status.
  - Session and peer limit clamps, or T8 pinned to the daemon-path values (§2).
  - Per-family veto in `computeCoveredAlerts` at both passes.
  - Per-family status surfaces and `fact_store_budgets`.
  - Tests: T7 per-family veto matrix, T8 budget invariant, T9 read-cost guard.
  - **Daybreak gate G2.**
- **S5: Migration.** Fresh stores and quarantine (M2/M3, quarantine outside the facts tree and idempotent per file), or M2′ if the operator chooses it. Q5's legacy-key handling must tell the written-in default apart from an operator value (§4.5 Config). Test T10 (already-locked-out fixture).
- **S6: CLI consistency.** `baseline.js` derives phase per rule from the shared "would evaluate" predicate (pending ∧ trust ∧ horizon ∧ fresh complete latest group). It shows the certified horizon, and adds the `cap_below_tick`, `budget_below_horizon_floor`, `history_horizon_short`, `retention_failing` and `not observed (no store)` reasons. Test T11.
- **S7: Real-host soak.** Run the daemon against a **copy** of `~/.local/state/descartes` with real collectors for at least 36 structural ticks. Alternatively, run the slow T2 replay with default budgets. Watch domains reach "watching"; service evicts every tick once full while still evaluating; read cost stays inside T9's bound.
- **S8: Final re-gate and docs.** Daybreak gate G3 on the whole slice. Then update `docs/HANDOFF.md`, this plan's **Completed:** header, the F2-Tier2 todo (closed, pointing here), and the fact-store sections of `README.md` and `AGENTS.md`. Finally, the operator-confirmed push.

---

## 8. Tests

**Fixtures.** The repo is public, and the real tick contains cleartext launchd labels. **Do not commit it.** Add a seeded generator that matches its shape: per-family counts and average record sizes from §2, census markers last, hashed keys where the translators hash. Use a seeded PRNG inside the test. The suite is `node --test` with no property-testing dependency (`tools/descartes-cli/package.json`).

- **T1: End-to-end lockout at real volume (red on HEAD).**
  - Setup: drive `runDaemonIteration` with injected structural collectors producing the generated tick (185 KB) and the real fact store, detectors, and `computeCoveredAlerts`. Run 40 hourly structural ticks, with fast ticks between them, at the 5 MB default.
  - Assert on HEAD: from about tick 28, `last_bytecap_evict_ts` is set every structural tick; every detector's `cold_start_since_ts` advances each hour; `evaluatedAlertKeys` is empty; and the daemon's `historyTrust.trust === false`.
- **T2: Recovery-liveness on the real code path (green after the change).**
  - Fast variant (in the suite): scale the **structural interval itself**, together with budgets and horizons, by one factor, so eviction starts early. *(Review fold, LOW.)* Scaling only budgets and horizons is not enough. The 6-tick lockout, 30-sample and 3 h freshness gates count ticks or use wall time, so the interval must scale with them, or the test must assert in ticks.
  - Slow variant (`test:soak` script): default budgets and real volume.
  - Assert:
    - service, lineage, and scheduled-job report coverage within 8 structural ticks and **keep reporting** while service evicts every tick;
    - session and peer establish after at least 30 complete ticks;
    - a persisted `service.disappeared` recovers within one structural tick after its edge passes, while eviction continues;
    - a persisted `session.count_drop` recovers once the count normalizes;
    - while a horizon is short, the matching alert stays frozen (negative control).
- **T3: Split tick.** Build each fixture in the **real per-family record order** (§4.1).
  - Service: presence, then census last. Build a store where an oldest-first trim would split a tick, evicting presence and keeping the census marker. Assert no `service.disappeared` candidate and no coverage key for that tick.
  - Peer: VPN presence, VPN census marker, optional VPN overflow, Tailscale presence, optional Tailscale overflow. A trim that evicts VPN peers and keeps the marker, overflow and Tailscale facts → no `peer.count_drop`.
  - Session: presence, census, optional overflow. A trim that evicts some presence and keeps the census and overflow → no `session.count_drop` or `session.churn`.
- **T4: Coverage oracle.**
  - Generate seeded sequences of: append (varied sizes), oversize tick, budget change, injected corrupt or schema-invalid line, future-dated append, clock rollback, **clock N days fast then corrected**, crash between ledger write and rename (`beforeFactsRename`/`afterFactsRename` hooks, `fact-store.js:331-333`), ledger deletion (with `facts.jsonl` surviving), forged far-future floor, external truncation.
  - Keep a reference model of what was appended per `ts`.
  - Assert after every operation:
    - every returned `ts` group equals the full appended set for that `ts` (no partial ticks);
    - every appended, non-aged, non-future `ts > bytecap_floor_ts` is returned whenever status is `intact` (claimed ⊆ justified);
    - **the floor never decreases, OR an in-window loss is stamped in the same pass** (status not `intact`). Ledger deletion over a non-empty store and the future-floor clamp must take the second branch. A clean bootstrap with `floor: null` over a store that had evicted is a failure;
    - `certifiedHorizonOk ⇒ now − floor ≥ H`;
    - after a fast clock is corrected, the family is never blind for longer than one retention window (the bounded blind of Fix 1);
    - a forged floor at or above `last_rewrite_newest_ts` makes the ledger `invalid`.
- **T5: Assertions and edge cases.** A non-suffix eviction (forced by stubbing the sort) throws. The accounting sum holds. `maxBytes: 0` and a single tick over the cap both give an empty store with a set floor and an ineligible horizon. The ledger validates `total > 0 ⇔ floor !== null`.
- **T6: Legacy ledger migration.**
  - A valid v1 ledger upgrades to v2 and reads **intact**. It must never be treated as invalid, never stamp `last_continuity_break_ts`, and never read degraded.
  - A v1 ledger with `bytecap_evicted_total > 0` migrates to floor = `last_bytecap_evict_ts + 6h`. A v1 ledger with no evictions migrates to `null`.
  - A ledger with a clamped marker is covered.
  - Under M2 (per Q3), any v1 ledger with `bytecap_evicted_total > 0` leads to a fresh start. Under M2′, the pre-Fix-0 case is covered by the replacement bound from G2′, not the unsound key-absence check.
  - Already-migrated ledgers round-trip.
  - A missing `integrity.json` over a non-empty `facts.jsonl` stamps a continuity break and reads `degraded`, never `intact`. A missing ledger over an absent or empty store bootstraps clean: `unknown`, then `intact`.
- **T7: Per-family veto matrix.**
  - Each family in turn untrusted (corrupt line or continuity break), while the others are intact. Only that family's rules are vetoed.
  - A family not read (tier off) → vetoed.
  - Each family's horizon short → only its rules are vetoed.
  - Regression for the single-file veto: a peer-store loss plus a buggy peer producer that reports coverage → still frozen.
  - The BLOCKER-3 / Fix-3 regression tests in `daemon.test.js` stay unchanged and green.
- **T8: Budget invariant.** For every family, `default_budget ≥ (H_max/interval) × worst_tick_bytes × 1.25`, where `worst_tick_bytes` uses maximum-length keys and attributes and the entity limits the daemon path actually passes (or the new clamps; §2). If a collector cap is raised without updating budgets, this test fails. The same formula is the `fact_store_budgets` config floor; assert that a configured value below it is rejected.
- **T9: Read-cost guard.** With every family at its default budget, the sum of per-fast-tick reads stays under a generous bound (for example 5 s), so a budget increase with large performance impact shows up in review. Count **every** fast-tick reader with learned on, not only the watch tier: active-constraint, provenance-warning, correlation and canary as well as the detectors and the daemon veto.
- **T10: Already-locked-out install.**
  - Fixture: a legacy shared store and ledger with an in-window `last_bytecap_evict_ts`, plus detector stores with `cold_start_pending: true` and old anchors.
  - Upgrade, then run clean ticks. Assert: the legacy store is quarantined outside `learned/facts/` and unread; lockout clears at ≤8 structural ticks; count rules establish at ≤32; there is no 31-day tail.
  - Half-done quarantine (only one of the two files moved): the re-run completes the move into the same directory.
  - `provenance-warnings` still produces `deleted_exe_running` / `public_bind_no_supervisor` candidates after the upgrade.
- **T11: Status agrees with the detector.** *(Review fold, MEDIUM-7: oracle changed.)* For each **rule**, over a matrix (pending or not, trusted or not, horizon short or not, census incomplete, latest group stale, **zero entities**, **family store absent**), `baseline status` reports "watching" exactly when the per-rule "would evaluate" predicate holds (I11), using the same injected `readFactPoints` and `now`.
  - "Non-empty coverage" is the wrong oracle: it would fail on a host with no sessions, no jobs, no canaries or no VPN.
  - Mixed-rule domains are reported per rule, for example session's `count_drop` (30 samples) against `churn` (6 ticks).
  - An absent family store shows `not observed (no store)`.
  - This fails on HEAD (Leg E).
- **T12: Routing.**
  - An unknown fact_name throws before any family file changes.
  - **Every fact_name each translator can emit is in the registry**, asserted by enumerating the translators' emitted names. An unregistered name would throw during grouping and lose the whole tick for every family.
  - A `readFactPoints` / `appendFactPoints` / `enforceFactRetention` call with no `family` throws.
  - The daemon's per-family append failure is reported and other families still persist.
  - A store with no new points still age-evicts.
  - A persistently failing retention pass surfaces `retention_failing`.
  - A directory under `learned/facts/` that is not in the registry is ignored by readers and the sweep.

---

## 9. Daybreak gates

| gate | when | scope | why |
|---|---|---|---|
| Plan review | before S1 | this plan (Fable code-grounded, daybreak, Astra) | direction before execution; F2-Tier2 asked for a plan and a daybreak review |
| **G1** | end of S2 | byte-cap reclassification, floor semantics (including the missing-ledger stamp, the future-floor clamp and stamp, and plausibility validation), read exclusion, ledger v2 and M4 | widens what detectors trust (todo lines 23-26) |
| **G2** | end of S4 | per-family `computeCoveredAlerts` veto, family registry, routing, required-`family` reader contract, non-detector reader horizons | recovery authorization: the class covered by §7.7, BLOCKER-1, BLOCKER-3 |
| (G2′) | if M2′ is chosen | conditional-split migration | one-time copy path that carries trust |
| **G3** | S8, before shipping | whole slice, including CLI consistency and the soak results | standing rule: daybreak re-gate on security-critical code before shipping |

---

## 10. Surfaces and docs to update

- `daemon.js` status record (`fact_store_completeness` per family), `constraint-store.js` `selectFactStoreCompleteness`/`LOSS_TS_FIELD_NAMES`, and the CLI help for `descartes learned status` and `descartes baseline status/inspect`.
- `watch-store.js` and `constraint-store.js` config normalization (`fact_store_budgets`).
- The `daemon.js:1045-1053` comment, which calls the cap "the only lever an operator has to stop routine bytecap eviction". That comment becomes obsolete.
- `AGENTS.md` safety invariants (the fact-store section), `README.md`, `docs/HANDOFF.md`, and the F2-Tier2 todo and its tracking parent (`todos/2026-09-04-codex-project-audit-follow-up.md`).

---

## 11. Rollback

The per-family stores sit in new paths. The legacy store is only quarantined (if Q4 chooses retention), so a downgrade to the old binary finds `learned/facts/facts.jsonl` missing and bootstraps fresh, which is honest. A downgrade does not restore the old store automatically. Document this; the operator restores it manually if needed.

---

## 12. Open questions for the operator

1. **Budgets.** Accept the §4.5 defaults (56 MB worst case, about 30 MB steady state on this host, versus 5 MB today)? Or trade a smaller service budget (for example 8 MB, about 2.6 days of novelty memory) for disk? *(Factual note from the review fold: the defaults are provisional until S0. At max-record size, peer needs about 18 MB, so the total is about 62 MB. At 16 MB service, service-presence constraint mining never runs; §5 N6.)*
2. **Novelty horizon.** Use 24 h (recommended, avoids daily-cycle false positives), or 6 h to match the current post-cold-start behavior? Should the horizon apply only once narrowing has happened (recommended; keeps day-1 behavior), or always?
3. **Migration.** Fresh per-family stores (recommended: simplest, no copy path that carries trust, near-zero cost because real hosts evict within 1-2 days: measured on macOS, estimated on Linux), or the conditional split M2′ (keeps low-volume hosts' baselines, extra daybreak gate)?
4. **Legacy store.** Delete immediately, or quarantine for 31 days for forensics, then delete?
5. **Legacy `fact_store_max_bytes`** in `watch.json` and `learned.json`: ignore it with a deprecation note in status (recommended), or use it as a floor for the service budget? *(Factual note from the review fold: `writeWatchConfig` writes the 5 MB default into every `watch.json`, so the key being present is not evidence that the operator chose it. Only a non-default value is.)*
6. **First/last-seen set** (§5.4): schedule it next to restore 30-day novelty memory, or defer until real-host false-positive data exists?
7. **Census ceiling coupling.** Should raising `services` `censusCeiling` scale the service budget automatically, or keep the fixed budget and accept novelty ineligibility (status reports `history_horizon_short`)? *(Corrected premise: that ineligibility is not fail-closed. It is a novelty-absorbing window, so services first seen during it never alert; §4.2, §5 N5.)*
8. **Network and provenance stores.** *(Corrected premise: `provenance.warning` **is** read, on every fast tick, by `tools/provenance-warnings.js:329-336`, and it drives `deleted_exe_running` and `public_bind_no_supervisor`.)* Keep writing it into its own `provenance` store (the plan's default), or stop? Stopping is an explicit **detection-removal** decision for those two rules, not a storage clean-up, and would need its own change.

### Operator answers (2026-10-05)

- **Q1 Budgets:** **superseded by the S0-revised defaults** (§15.4, measured against pinned worst-case record sizes, not the provisional ~470 B estimate): service 18 MiB, process_lineage 10 MiB, scheduled_job 5 MiB, peer 16 MiB, session 4 MiB, canary 4 MiB, network 4 MiB, provenance 4 MiB -- **65 MiB total** (versus the ~62 MB figure below, which predates S0's measurement and is kept here only for the record of what was asked). §4.5's table is updated to match. This lands in S4 (R0a); it does not block S1-S3.
- **Q2 Novelty horizon: ACCEPTED.** The operator asked "Isn't 24 h short?". The answer given: the horizon is the *minimum* certified memory before a novelty rule may claim "new". It is not the memory length, which the budget sets. A horizon above a family's worst-case span blinds that family during volume spikes. Accepted, to be applied at S3:
  - `service.appeared`: 48 h;
  - `scheduled_job.appeared`: 48 h;
  - `process.lineage.novel_edge`: 6 d, to cover weekly runtime edges; stays below the ~6.9 d worst case.

  Each stays below its family's worst-case certified span (re-confirmed against the S0-revised budgets at §15.4). The horizon applies only after narrowing (the default).
- **Q3 Migration:** fresh per-family stores. This removes M2′ and M4 (§14).
- **Q4 Legacy store:** quarantine for 31 days, outside the facts tree, then delete.
- **Q5, Q7, Q8:** the recommended defaults (Q5 ignore + deprecation note; Q7 fixed budget + `history_horizon_short`; Q8 keep the `provenance` store).
- **Q6 First/last-seen set: IN SCOPE (operator, 2026-10-05, after G1).** G1 showed that novelty over a narrowed window fabricates "new" for an entity last seen before the floor (§16). The operator chose to pull §5.4 into R0 as **S3b** rather than keep novelty silent under narrowing or accept re-flags. See §17.

---

## 13. Key code refs (HEAD `134e811`)

- **Store:**
  - `fact-store.js:18-19` (retention and cap), `:27` (future tolerance), `:44-47` (paths), `:265-270` (candidate partition), `:272-285` (suffix loop), `:290-292` (accounting), `:305-334` (ledger prepare/rename/finalize), `:351-373` (append), `:380-427` (read; window filter `:406`).
  - `fact-store-integrity.js:7-25`, `:100-118`, `:170-209`, `:237-247`, `:276-290` (prefix digest), `:337`, `:356-359` (`oldest_ts`), `:393-404` (clamp), `:439`, `:445`, `:476`, `:495-511`, `:545`, `:588-596`.
  - `fact-store-completeness.js:1-16`, `:36-48`, `:69-79`, `:83-84`.
- **Daemon:** `daemon.js:66`, `:101-112`, `:144-153`, `:661-673`, `:710-722`, `:740-748`, `:810-851` (`:824-827` veto), `:984-988`, `:1004-1058`, `:1136-1171`, `:1196-1211`, `:1387-1395`, `:1460-1465`.
- **Detectors:**
  - `session-baseline.js:83`, `:92`, `:146-170`, `:693-694`, `:739-785`, `:831`
  - `peer-baseline.js:66`, `:80`, `:150-171`, `:729-730`, `:777-828`, `:882`
  - `service-baseline.js:62`, `:79`, `:120-144`, `:340-358`, `:455-475`, `:517-518`, `:566-581`, `:700-708`, `:837-846`, `:885`, `:915-916`, `:936-974`
  - `process-lineage-baseline.js:20`, `:93-103`, `:360-361`, `:408-423`
  - `persistence-baseline.js:42`, `:110-120`, `:338-339`, `:358-373`
  - `canary-baseline.js:86-101`, `:536-537`, `:623-624`
  - `incident-correlation.js:67`, `:71`, `:311-325`, `:331-333`
- **Translators (census marker last):** `fact-translators.js:141`, `:359`, `:384`, `:504`, `:773`, `:984`.
- **Collector caps:** `tools/services.js:27`, `:31-36`; `tools/processes.js:187`; `tools/scheduled-jobs.js:11`, `:23`; `tools/sessions.js:33`; `tools/vpn-peer-status.js:40`; `tools/tailscale-status.js:23`; `tools/canary.js:9`.
- **Other readers and surfaces:** `constraint-miner.js:23`, `:32-35`, `:362-366`; `shadow-store.js:300-303`; `constraint-store.js:219-228`, `:302`, `:338-380`, `:450`; `tools/provenance-warnings.js:69`, `:218-221`, `:305-313`, `:329-336`; `tuning-store.js:620-631`; `watch-store.js:41-55`, `:104-110`; `baseline.js:112-133`, `:236-242`; `welford-stats.js:20`.
- **Added by the review fold:** `fact-store-integrity.js:318-323`, `:337` (missing-ledger bootstrap, `invalidLedgerBootstrap`), `:378-392` (Fix 1 rationale); `fact-store.js:37` (`MAX_FACT_ENTITY_KEY_LENGTH`), `:358-371` (non-fatal retention); `fact-translators.js:998-1007` (Tailscale), `daemon.js:1024-1028` (peer concatenation); `tools/sessions.js:200`, `tools/vpn-peer-status.js:395`, `tools/tailscale-status.js:111` (unclamped limits); `process-lineage-baseline.js:90`, `:291`; `persistence-baseline.js:107`, `:247`. NUL bytes: `canary-baseline.js:258`, `fact-translators.js`, `peer-signature-store.js`.
- **Tests that pin current behavior:** `evidence-freeze.test.js:374`, `fact-store.test.js:223` (`maxBytes: 0`), and the `daemon.test.js` BLOCKER-3 / Fix-3 regression tests.

---

## 14. Addendum: review fold (2026-10-05)

**Addendum:** 2026-10-05. An adversarial plan review against HEAD `134e811` returned **NEEDS-REVISION(7), no BLOCKER**. Every finding was re-verified against the code before it was folded in (verify-don't-worship). All held. The changes are folded into the sections they touch, marked *(Review fold)*. Summary:

- **HIGH-1: a missing ledger reset the floor.** A missing-ledger bootstrap over a non-empty store now stamps a continuity break, like `invalid` (§4.1 item 2). I2 is restated as "non-decreasing within a ledger lineage; every backwards move stamps a loss" (§6). T4 asserts "floor non-decreasing OR loss stamped", and T6 covers the missing-ledger cases. Seeding the floor from `live.newest_ts` was considered and rejected; the reason is in §4.1.
- **HIGH-2: fact readers were missing from the migration.** provenance-warning → `provenance`, tuning → `service` + `network`, and learned status → per family are added (§4.3). The last was found during verification; the review did not list it. `family` is now a required argument that throws when missing (§4.3, I7, T12). The false "no fact reader" claim is corrected (§4.3, Q8). S0 inventories must use `grep -a` or ast-grep (§4.1 item 4, §7).
- **MEDIUM-3: a future-dated floor was an unbounded blind.** A floor past `nowIso + 6h` is now clamped to `nowIso` with a loss stamped in the same pass. Floor plausibility validation is added. The empty-store bound is an S0/G1 item (§4.1 item 2, I2, T4).
- **MEDIUM-4: a short horizon is not fail-closed.** The plan now says so: it is a novelty-absorbing window (§4.2, §5 N5, Q7 premise). The config floor is now the T8 invariant (§4.5). An operator-visible horizon-short signal is added (§4.2, §4.4, I12).
- **MEDIUM-5: readers outside the detectors had no narrowing policy.** The miner, shadow and tuning readers get registry horizon entries (§4.2). The loss of service-presence mining at default budgets is recorded (§5 N6, with a pointer from Q1).
- **MEDIUM-6: the budget invariant used average record size.** A max-key worst-case column is added (§2). §4.5 is marked provisional until S0, and peer fails T8 at 12 MB. The session and peer limits were found to be unclamped defaults (§2, S4). A read-cost decision rule is added (§4.5). T9 now counts learned-on readers.
- **MEDIUM-7: T11's oracle was wrong for empty domains.** The oracle is now the per-rule "would evaluate" predicate (I11, T11). A `not observed (no store)` status is defined (§4.4).
- **LOW items, all applied:**
  - Leg D's claim about R0a is narrowed, and "R0b plus a larger shared cap" is evaluated honestly (§3, §4.7).
  - `certified_after_ts = max(floor, cutoff)` is split from the raw floor (§4.1 item 3).
  - The real census-marker order is used for peer and session (§4.1, T3).
  - Registry rule IDs are string literals, the rule-coverage check moves to daemon init, and the producer count is eight (§4.3, S3).
  - Quarantine moves outside the facts tree and is idempotent per file; iteration is registry-driven (§4.3, §4.6 M3, T10, T12).
  - M4 is dead under M2, so Q3 is decided before S2. The pre-Fix-0 check is unsound and is replaced at G2′ (§4.6 M4, T6, S0).
  - The written-in `fact_store_max_bytes` default is handled (§4.5 Config, Q5 premise).
  - T12 checks that every translator fact_name is registered.
  - The Q2 inconsistency is noted in §4.2.
  - T2's fast variant scales the interval itself.
  - Retention failure is surfaced (§4.3, T12).
  - Line nits are fixed (§2, §3).

**Review disposition (findings not applied, or applied with qualification):**
- None rejected.
- *Qualified, HIGH-1:* of the reviewer's two options, the continuity-break stamp was chosen. The plan states its cost: 31 days `degraded` for that family after ledger loss, the same as an invalid ledger.
- *Qualified, MEDIUM-3:* the reviewer's suggested bound `floor <= continuity.last_rewrite_newest_ts` is tightened to `<` for a non-empty store, since the floor is below every kept record. It has no in-ledger referent when the store is empty, so that case is left as an S0/G1 decision rather than asserted.
- *Qualified, MEDIUM-6:* the ~470 B maximum record size is the reviewer's estimate. It is carried as an estimate pending S0, and the peer T8 failure it implies is flagged, not resolved.
- *Qualified, tuning reader (HIGH-2):* routed to `service` + `network`, following the constraint-target families. S0 confirms whether `buildFactHistoryByTarget` (`tuning-store.js:256`) needs any other family.

**§12 premises corrected (questions otherwise unchanged):**
- **Q8:** false premise ("no fact reader").
- **Q7:** "fail-closed" was wrong.
- **Q5:** added that the 5 MB default is written into every `watch.json`.
- **Q1:** added that budgets are provisional, peer is about 18 MB, and service-presence mining is lost.

---

## 15. Addendum: S0 grounding (2026-10-05)

**Addendum:** 2026-10-05. Step S0 run on branch `feat/fact-store-capacity-2026-10` (base `b951cb7`, which differs from `134e811` only in `docs/`, so every `src` line reference above still holds). Everything below was derived from the code and from §2's already-measured host numbers. No live host measurement was taken; every test and command ran with scratch `XDG_*` directories.

### 15.1 Line references

Re-verified against the branch base: `fact-store.js` (`:19`, `:27`, `:37`, `:44-47`, `:265-270`, `:272-285`, `:290-292`, `:331-333`, `:351-373`, `:380-427`, `:406`), `fact-store-integrity.js` (`:100-118`, `:170-209`, `:179-180`, `:222-223`, `:237-247`, `:276-290`, `:318-323`, `:337`, `:356-359`, `:361-366`, `:393-404`, `:439`, `:445`, `:476`, `:505-511`, `:545`, `:588`), `fact-store-completeness.js` (`:1-16`, `:69-70`, `:83-84`), the six detector loss-list and `hasCompletenessLossAfterAnchor` copies (§3 Leg B), and `daemon.js` (`:984-988`, `:1004-1058`, `:1053`, `:1136-1171`, `:1144`, `:1151`, `:1196-1211`). All hold. One correction: the `readFactPoints` call itself is one line below several of the `readFacts =` seam lines cited in §4.3 (for example `shadow-store.js:300` is the call, `:282` the seam). The inventory below cites the call lines.

### 15.2 Inventory (`grep -a`; plain `grep` misses `canary-baseline.js`, confirmed: it reports `canary-baseline.js` as binary and drops its `readFacts(` call at `:537`)

- **`last_bytecap_evict_ts`, `src` (9 files, 22 lines):**
  - `fact-store-integrity.js`: `LEDGER_KEYS` `:16`, `createFactIntegrityLedger` `:80`, validation `:182`, `:205`, `clampForward` `:401`, stamp `:439`, comment `:443`, `LOSS_CHANNEL_FIELDS` `:509`, `commonCompletenessFields` `:532`;
  - `fact-store-completeness.js:4` (`LOSS_TIMESTAMP_FIELDS`);
  - detector copies: session `:149`, peer `:150`, service `:123`, process-lineage `:93`, persistence `:110`, canary `:86`;
  - `constraint-store.js`: `LOSS_TS_FIELD_NAMES` `:302`, `unknownFactStoreCompleteness` `:317`, `selectFactStoreCompleteness` `:350`, `renderFactStoreCompletenessText` `:450`.
- **`last_bytecap_evict_ts`, `test` (12 files):** `fact-store-completeness.test.js` (`:26` loss-channel list, `:106`/`:111` anchor fixtures, `:186-194` "byte-cap eviction degrades completeness"), `constraint-store.test.js` (6 lines, incl. `:566-590`), `fact-store-integrity.test.js:613`, and one `degradedReadResult`-style fixture each in the session, peer, service, process-lineage, persistence, canary, shadow, miner and correlation tests (they use the field as a generic loss marker).
- **`continuity_oldest_ts`:** `src`: `fact-store-integrity.js:545`, `constraint-store.js:318`, `:351`, `daemon.js:170` (comment). `test`: `fact-store-integrity.test.js:90-128`, `constraint-store.test.js:515-590`, `daemon.test.js:691` (comment). No trust path reads it.
- **`readFactPoints` call sites, `src` (16), checked against the §4.3 reader list (complete; nothing missing, nothing extra):** session `:694`, peer `:730`, service `:518` and `:916`, process-lineage `:361`, persistence/scheduled-job `:339`, canary `:537`, correlation `incident-correlation.js:313`, active-constraint `daemon.js:524`, daemon history veto `daemon.js:1144`, shadow `shadow-store.js:300`, miner `constraint-miner.js:362`, provenance-warning `tools/provenance-warnings.js:332`, tuning `tuning-store.js:631`, learned status `constraint-store.js:380`, `baseline.js:239`.
- **`readFactPoints` direct calls, `test`:** `daemon.test.js` 35, `fact-store-integrity.test.js` 30, `fact-store.test.js` 20, `fact-store-completeness.test.js` 17, and one each in the miner, peer, service and session tests.
- **`appendFactPoints`:** one `src` writer, `daemon.js:1043`/`:1053`. `test`: 263 direct calls across 13 files (`daemon.test.js` 111).
- **`enforceFactRetention`:** one `src` caller, `fact-store.js:368` (inside `appendFactPoints`). `test`: 74 direct calls across 7 files.

### 15.3 Worst-case tick bytes (pinned)

Computed by running the **real translators** and `normalizeFactPoint` on maximum-length inputs (scratch script, not committed). The ~470 B estimate in §2 was too pessimistic for most families, because the translators bound entity keys well below `MAX_FACT_ENTITY_KEY_LENGTH = 256`: `sanitizeIdentityString` truncates to `MAX_STRING_LENGTH = 64` (`diagnostics-sanitizer.js:23`), and the lineage, session, peer and scheduled-job keys are fixed-length hashes. Canary is the exception: its stat attributes make it the largest record.

| family | max record (B) | markers per tick (B) | entity cap used | **worst B/tick** |
|---|---:|---:|---:|---:|
| service | 291 | 251 | 1000 (ceiling; hard clamp 5000 gives 1,455,251) | **291,251** |
| process_lineage | 251 | 297 | 200 | **50,497** |
| scheduled_job | 354 | 275 | 200 (clamp) | **71,075** |
| session | 333 | 530 (census + overflow) | 200 (default, unclamped) | **67,130** |
| peer | 392 | 933 (VPN census + VPN overflow + Tailscale overflow) | 400 (200 VPN + 200 Tailscale defaults, unclamped) | **157,733** |
| canary | 501 | 247 | 200 | **100,447** |

Session and peer still use the unclamped defaults (§2); S4 must clamp them or pin these values in T8.

### 15.4 T8 arithmetic, re-run with the pinned values and the Q2 horizons

`required = (H_max / 1 h) × worst B/tick × 1.25`, with `H_max` per family from §12 Q2 (service 48 h, scheduled_job 48 h, process_lineage 6 d) and §4.2 (session 30 h, peer 72 h from correlation, canary 6 h):

| family | H_max | required | §4.5 budget | verdict | minimum MiB-rounded budget |
|---|---|---:|---:|---|---:|
| service | 48 h | 17,475,060 B (16.7 MiB) | 16 MiB | **fails** | 18 MiB |
| process_lineage | 6 d (144 ticks) | 9,089,460 B (8.7 MiB) | 8 MiB | **fails** | 10 MiB |
| scheduled_job | 48 h | 4,264,500 B (4.07 MiB) | 4 MiB | **fails** (just) | 5 MiB |
| session | 30 h | 2,517,375 B (2.4 MiB) | 4 MiB | passes | 4 MiB |
| peer | 72 h | 14,195,970 B (13.5 MiB) | 12 MiB (~18 MiB proposed) | fails at 12, passes at 14+ | 16 MiB |
| canary | 6 h | 753,353 B (0.7 MiB) | 4 MiB | passes | 4 MiB |

The §4.5 budgets were sized for 24 h novelty horizons. Q2's longer horizons (48 h, 6 d) break T8 for service, process_lineage and scheduled_job, even though the measured max record is smaller than the estimate. Peer needs less than the ~18 MiB proposed. **Revised defaults for S4:** service 18, process_lineage 10, scheduled_job 5, session 4, peer 16, canary 4, network 4, provenance 4: **65 MiB** in total (versus ~62 MiB in Q1). This is an operator item (Q1 follow-up), surfaced at G1; it does not block S1-S3.

**Read-cost decision rule (§4.5).** It does not trip. Worst case with every family at its revised budget, interpolating §2's measurements at ~15 ms/MiB: service 3 reads × 18 MiB ≈ 0.8 s, peer 3 reads (detector, correlation, veto) × 16 MiB ≈ 0.7 s, lineage 2 × 10 MiB ≈ 0.3 s, the rest under 0.3 s, for ~2.1 s per fast tick. That is under T9's 5 s bound. At typical volume most families sit far below budget.

**Linux volume** (§4.6 M2 cost note) is not confirmed: no Linux host is available to this run, and the hard rule forbids live measurement. It stays an estimate.

### 15.5 Decisions

1. **Empty-store floor bound (§4.1 item 2, S0/G1 item).** No new ledger field. Two layers instead:
   - write side: the future-floor clamp runs on **every** retention pass (prior floor `> nowIso + FUTURE_FACT_TOLERANCE_MS` → `nowIso`, plus `last_continuity_break_ts = nowIso` in the same pass), so a forged far-future floor on an empty store survives at most until the next pass, which stamps a loss;
   - read side: `buildCompleteness` reports `status: "unknown"` (`degraded_reason: "future_floor"`) whenever the floor is more than `FUTURE_FACT_TOLERANCE_MS` ahead of the read's `nowMs`. That fails closed between the forgery and the next pass.
   - The non-empty case keeps the in-ledger check (`floor < last_rewrite_newest_ts`, else `invalid`).
2. **Below-floor records are evicted physically (refinement of §4.1 items 1 and 3).** After a clock rollback, a retention pass can see candidates with `ts <= floor` (appended after the eviction that set the floor). Keeping them would make "every kept record is above the floor" false. A store whose only records are below the floor would then fail the `floor < last_rewrite_newest_ts` validation inside `writeFactIntegrityLedger`, and retention would fail on every pass from then on. So each pass evicts every candidate with `ts <= prior floor` (after the clamp) and counts it as byte-cap eviction. The read filter already hides these records, so dropping them changes no trust outcome. It also makes the floor bound, the suffix assertion and the validation hold by construction.
3. **Missing ledger over a non-empty store (HIGH-1): first-run carve-out.** `appendFactPoints` writes `facts.jsonl` **before** the first retention pass creates the ledger, so on a genuine first run the ledger is missing while the store is non-empty. Read literally, HIGH-1 would stamp a continuity break on every fresh install. The rule is therefore "missing ledger **and** the store held bytes **before this call's own append**". `appendFactPoints` observes that (ledger missing and `facts.jsonl` absent or empty before appending) and passes it to its internal retention pass. The exported `enforceFactRetention` cannot assert it. A crash between the first append and the first retention pass therefore reads as a lineage break (fail-closed, 31 days degraded), never as a clean bootstrap.
   - **Superseded (review fold LOW-1/LOW-4, post-S2).** This decision's `appendedToEmptyStore` carve-out could not tell a genuine first run (ENOENT) apart from an evicted-then-emptied store (0 bytes, but WITH history the now-deleted ledger used to certify) whose ledger was separately lost -- both present as "store held 0 bytes before this append". That let the floor reset to `null` with no stamp in the second case, and a later normal append would silently re-certify as intact/`coverage: full` with no trace anything was ever lost (LOW-1). Fix: drop the emptiness clause entirely (`missingLedgerOverExistingStore = ledgerReason === "missing" && live.exists === true`), and resolve the genuine-first-run shape differently -- `appendFactPoints` now runs one retention pass against the **pre-append** store whenever the ledger is missing, strictly before its own append, so the check always sees the true prior state. The `appendedToEmptyStore` parameter is removed; HIGH-1's rule has no exception left. The crash-reads-as-a-lineage-break consequence in the paragraph above is unchanged.
4. **Q3 = fresh per-family stores, so M4 and M2′ do not apply.** S2 implements no floor derivation for legacy ledgers. The schema bump still goes through `migrateLedgerShape`:
   - a v1 ledger with `bytecap_evicted_total === 0` → v2 with `bytecap_floor_ts: null` (reads intact; T6);
   - a v1 ledger with `bytecap_evicted_total > 0` is **not** migrated. It stays v1, fails validation as `invalid`, and takes the existing continuity-break bootstrap: never intact, never a clean `floor: null`. In the shipped slice S5 quarantines the legacy store before any v2 code reads it, so this only ever governs the never-shipped S2 interim state and tests. **G1 question.**
5. **T1 on HEAD.** `test/fact-store-lockout-e2e.test.js` drives `runDaemonIteration` for 40 hourly structural ticks, plus half-hour fast ticks from tick 26, using the seeded real-volume generator (`test/fixtures/real-volume-tick.js`: 714 records and ~191 KB per tick, against the real 722 records and 185 KB; it omits `provenance.warning`). The 5 MB store starts evicting at tick index 27, the 28th tick. From tick 28 on, it reports all three legs: every structural and fast history read is `degraded` (Leg A); the service, lineage and persistence anchors re-arm on every tick (Leg B); none of them reports coverage (Leg C). It is committed as `todo` (red) in S0 and flips to a normal test in S2. Runtime is about 29 s.

---

## 16. Addendum: S1, S2, and G1 blocker rework (2026-10-05)

**Addendum:** 2026-10-05. S1 and S2 are built on `feat/fact-store-capacity-2026-10`, and the two daybreak G1 blockers are being closed on this branch. Nothing is pushed or merged. Full-suite runs use fresh scratch `XDG_*` directories. After the amended blocker-1 commit: 2088 tests, 2032 pass, 22 fail, 34 skipped, 0 todo; the 22 failures are sandbox-only (17 notifier loopback-listen `EPERM`, 3 tap-token loopback-listen `EPERM`, and 2 live-host provenance checks returning `unknown`).

**Commits.**
- `4d5eea1`: S0, plus T1 committed as `todo`.
- `db7e5a8`: S1, the dedupe.
- `953027a`: tick-aligned eviction and the suffix assertion (T3, T5 eviction half).
- `4c11f9f`: ledger v2 and the floor. Includes HIGH-1, MEDIUM-3, plausibility, below-floor eviction and the first-run carve-out (T5 ledger half, T6).
- `0d1fb80`: read-side exclusion, coverage fields, the F2-Tier1 fold-in, and the T4 oracle.
- `9f3f510`: byte-cap reclassification. T1 turns green.

**T1 after S2/G1 blocker 1.** It passes. From tick 28 on, the 5 MB store evicts on every structural tick. The daemon's history read remains `intact` on structural and fast ticks, and the ordinary service baseline stays established. The three retained-window novelty paths deliberately report no evaluated keys and re-arm through their existing cold-start state under narrowed coverage; this is the safe pre-S3 behavior. Leg D (count rules can't reach 30 samples at 5 MB) still stands, as expected. T2 covers it after S4.

**G1 Blocker 1 disposition (interim S2).** The three retained-window novelty producers now call `factHistoryTrustworthy` with `requireFullCoverage: true`: `service.appeared`, `scheduled_job.appeared`, and `process.lineage.novel_edge`. A narrowed store therefore emits no novelty candidate and re-arms an established detector through its existing cold-start path, matching the pre-S2 byte-cap-loss behavior. The regression is pinned for the daybreak reproduction: an entity present at t0, absent at t1–t3, and present again at t4 must not be called first-seen when t0 is evicted. The inventory found no additional detector that makes this same retained-window first-seen claim; miner, shadow, and correlation already use the interim full-coverage gate, while disappearance/churn/count/deviation paths have different recent-evidence semantics.

This is intentionally an **interim S2** gate. **S3 must not simply lift it by adding a horizon.** G2 must decide whether novelty over a narrowed window may still re-flag an entity whose last sighting was before the floor. The proper durable fix is the §5.4 first/last-seen set (Q6), and that operator decision remains open; a horizon alone cannot recover the missing first/last-seen fact.

**G1 Blocker 2 disposition.** Ledger v2 now persists `age_floor_ts`, the monotonic newest timestamp removed by age retention. Validation requires the floor exactly when `age_evicted_total > 0`, rejects implausible floors against a non-empty committed rewrite, and migrates older v2/v1 shapes only when no age floor is needed; a legacy ledger with recorded age eviction but no recoverable floor fails closed. Retention carries the maximum age floor forward and classifies records reintroduced at or below it after a wall-clock rollback as already age-evicted. Reads exclude both the byte-cap and age floors. Completeness exposes both raw floors and reports `coverage: "narrowed"` with `certified_after_ts = max(bytecap floor, age floor, retention cutoff)` whenever the relevant floor intersects the read window. The two-hour rollback regression pins t0 evicted at t4, then read at t2: t0 remains absent and the result is never `intact`/`full`.

**Deviations from the plan text (each also stated in code comments and commit messages).**
1. **Below-floor eviction** (§15.5 decision 2): records with `ts <= floor` are evicted physically and counted as byte-cap. The plan only filtered them on read.
2. **First-run carve-out for HIGH-1** (§15.5 decision 3): `appendFactPoints` observes before appending. "Non-empty" means `bytes > 0 || record_count > 0`, which is stricter than the plan's `record_count > 0`: a file holding only corrupt lines also counts as non-empty.
3. **`future_floor`.** A new `degraded_reason`; the read reports status `unknown`. It is the empty-store floor bound (§15.5 decision 1). It takes precedence over the in-window-loss attribution; both outcomes are untrusted.
4. **`continuity_oldest_ts` is removed from `buildCompleteness`, not just from the operator surfaces** (§4.1 item 6). A test pins that no `src` file other than the ledger writer reads `continuity.oldest_ts`.
5. **`selectFactStoreCompleteness` reports `coverage: "unknown"`** when there is no read to report (fact history never enabled, or a malformed shape), instead of defaulting to `"full"`.
6. **T3 is store-level.** Each real per-family record order (service; session with overflow; peer VPN plus Tailscale) is produced by the real translators, and the test asserts that no part of a split tick is physically kept or returned. It makes no detector-candidate assertions: with tick-aligned eviction the store can no longer produce a split tick for a detector to read.
7. **T4 omits the horizon assertion** (`certifiedHorizonOk`, which is S3). The "blind for at most one window after a fast clock is corrected" property is pinned by a dedicated MEDIUM-3 test rather than inside the oracle. The oracle treats a ledger `generation` change as a new lineage (I8); the T6 tests pin the HIGH-1 stamp separately.
8. **T5's "ineligible horizon" half is deferred to S3.** S2 asserts coverage `narrowed` and an empty certified span instead.
9. **S1 removed `canary-baseline.js`'s deliberately independent copy** of the re-arm check. Its own comment called that copy defense-in-depth against a widening of the shared helper. The removal follows §4.1 item 7.
10. **Test fixtures that used `last_bytecap_evict_ts` as a stand-in loss** (the six detector `degradedReadResult` helpers, plus the shadow and miner "future loss is ignored" tests) now use `last_continuity_break_ts` or `last_corrupt_ts`, so they still exercise a real loss channel. Two tests pinned the old trust semantics; both are rewritten with the reason stated in place:
    - "byte-cap eviction degrades completeness";
    - "missing-ledger bootstrap over a pre-existing non-empty store reaches intact".

**Review-fold fixes applied before G1 (2026-10-05).** An adversarial review of S0-S2 found six items; all six are fixed on this branch before the G1 gate review runs, each its own atomic commit:
- **MEDIUM-1.** Reclassifying byte-cap eviction as narrowing widened what the no-anchor path of `factHistoryTrustworthy` trusts. `constraint-miner.js:366`, `shadow-store.js:303` and `incident-correlation.js:323` all call it with no anchor and, on `main`, used to refuse after ANY byte-cap eviction ever (a loss); they would now accept a merely-narrowed read with no horizon of their own to bound what they mine/evaluate over. Fixed with an explicit opt-in on the shared primitive, `opts.requireFullCoverage` (`fact-store-completeness.js`), which those three readers alone pass, with reason `coverage_narrowed`. The daemon's per-family history veto (`daemon.js:1153`, called with no opts at all) and the six watch-tier detectors behind it deliberately do NOT opt in -- they rely on their own retained-union/S3-horizon semantics -- confirmed by a new `daemon.test.js` test that a genuinely NARROWED (not degraded) read still recovers a persisted `session.count_drop` alert. **This corrects §7's claim that "R0b alone is a safe state (it does not fabricate)": R0b alone, unfixed, widened these three non-detector readers' trust beyond what they could support for the span S3's horizons will eventually bound -- a real widening, not merely an "incomplete fix" in the Leg-D sense §7 meant. The six detectors and the daemon veto were never affected; §7's claim holds for them.** See G1 question 8.
- **LOW-1/LOW-4.** The `appendedToEmptyStore` carve-out (§15.5 decision 3) could not tell a genuine first run (ENOENT) apart from an evicted-then-emptied store (every record byte-cap-evicted, floor set) whose ledger was separately deleted -- both read back as 0 bytes. The carve-out let the floor silently reset to null with no stamp in the second case, certifying the evicted history as intact/`coverage: full` within one more normal tick. Fixed by dropping the carve-out's emptiness clause entirely (`fact-store-integrity.js`'s `missingLedgerOverExistingStore` now requires only `live.exists === true`, with no exception) and having `appendFactPoints` run one retention pass against the TRUE pre-append state whenever the ledger is missing, so the check is never contaminated by the same call's own new data.
- **LOW-2.** `buildCompleteness` reported `coverage: "full"` whenever there was no ledger at all (missing/unreadable/invalid), because its fallback is a fresh ledger whose floor is always null -- over-claiming that byte-cap eviction never narrowed a store there is no ledger to vouch for either way. Fixed: `coverage: "unknown"` when `ledger === null`, scoped narrowly so a ledger with a merely-unresolvable continuity observation this read still reports its real floor.
- **LOW-5.** `orderRetentionCandidates` (the T5 non-suffix-eviction test seam) was read straight off `options`, which `appendFactPoints` forwards into `runFactRetention` verbatim -- technically reachable from it too, even though no production caller sets it. Moved behind a separate `internal` parameter that only `enforceFactRetention` populates from its own options.
- **LOW-6.** `certified_after_ts`'s retention-cutoff term hardcoded `DEFAULT_FACT_RETENTION_MS` rather than the read's own retentionMs. `readFactPoints` now takes a validated `options.retentionMs`, defaulting to the same constant, so every existing caller is unaffected.
- **Operator decisions (§12).** Q1's S0-revised budgets and Q2's accepted horizons are folded into §4.5's table as the plan's current defaults (not merely a G1-question follow-up); see §4.5 and §12's updated "Operator answers".

**G1 questions.**
1. **Zero-cap or all-evicted status (§7 S2).** Today such a store reads **`unknown`** (fail-closed), not intact. This was established in code, not decided. The root cause is `observeFactContinuity`: it returns `"unknown"` whenever the committed rewrite was empty and records were appended afterwards (`expectedNewest === null`), so a store that is fully evicted on every pass never reaches `continuity_ok: true`.
   - For it to read intact with coverage `narrowed`, as the plan leans, that continuity rule must change. The argument for changing it: an empty committed prefix makes all live content a pure append.
   - Consequence if left as is: a family whose per-tick volume exceeds its budget (`cap_below_tick`) is permanently untrusted. That is an over-freeze, never a fabrication. Pinned by a test.
2. **Empty-store floor bound.** Is the two-layer answer acceptable: a clamp plus loss stamp on every pass, and a fail-closed `future_floor` read in between? The alternative is a new ledger field holding the last committed pass's `nowIso`.
3. **v1 ledger that has evicted** → continuity-break bootstrap in the S2 interim (never certified). S5 quarantines it in the shipped slice.
4. **Below-floor eviction counted as byte-cap.** It bumps `bytecap_evicted_total` and `last_bytecap_evict_ts` after a rollback.
5. **The first-run carve-out**, and its consequence: a crash between the very first append and the first retention pass reads as a 31-day lineage break.
6. **Removing canary's independent re-arm copy** (deviation 9).
7. **For the operator (Q1 follow-up):** the S0 budget revision. Service 18, process_lineage 10, scheduled_job 5 and peer 16 MiB, so 65 MiB in total (§15.4). This lands in S4.
8. **MEDIUM-1's interim full-coverage gate shape.** Is `requireFullCoverage` (opt-in on `factHistoryTrustworthy`, consumed only by the miner, shadow evaluator and correlation) the right INTERIM shape for S2-S3, or should S3's per-reader horizons for those three specifically be pulled forward rather than shipping a blunter gate first? The gate has no anchor-relative carve-out and no horizon of its own: it refuses outright on ANY narrowing, which is strictly more conservative than any per-reader horizon S3 would set (a reader could still be refused long after its own horizon would have cleared it). The six watch-tier detectors and the daemon's per-family history veto are unaffected either way -- they never called `factHistoryTrustworthy` with an anchor-equivalent widening problem in the first place, since their own re-arm/coverage logic already gates on the loss channels directly, not on this generic check's coverage field.

---

## 17. Addendum: S3b first/last-seen set (2026-10-05)

**Addendum:** 2026-10-05 — G1 blocker 1 (novelty over a narrowed window) plus operator decision Q6 = in scope. Adds step **S3b** between S3 and S4.

- **What:** one compact, trust-bearing seen-set per novelty family (`service`, `scheduled_job`, `process_lineage`): entity key → `{first_seen_ts, last_seen_ts}`, retained 30 days past `last_seen_ts`, bounded by an entry cap with overflow ⇒ that family's novelty goes ineligible (never silently drops an entry).
- **Fold rule:** folded only from complete, certified, non-future ticks, in the same pass as the fact append (crash-consistent with the fact ledger: a seen-set generation stamp tied to the family ledger lineage; a mismatch or a missing/corrupt set ⇒ cold start for that family's novelty, never "everything is new").
- **Read rule:** `service.appeared`, `scheduled_job.appeared` and `process.lineage.novel_edge` decide novelty against the seen-set, not the retained fact window. With the seen-set valid, the interim `requireFullCoverage` novelty gate (§16) is lifted for these three rules; without it, the gate stays.
- **Invariants (new):** I13 eviction from the fact store never changes a seen-set answer; I14 a seen-set that cannot prove continuity yields no novelty claim (re-arm), never a claim.
- **Tests:** G1's reproduction (entity at t0, absent t1–t3, back at t4, t0 evicted ⇒ no candidate) passes via the seen-set; seen-set loss ⇒ re-arm; partial tick never folded; cap overflow ⇒ ineligible + status reason.
- **Gate:** covered by G2 (S3b lands before S4).

---

## 18. Addendum: S3 and S3b execution (2026-10-05)

**Addendum:** 2026-10-05. S3 (eligibility horizon) and S3b (first/last-seen set) are built on `feat/fact-store-capacity-2026-10`, plus the two G1 re-gate LOWs. Nothing is pushed. S4 (per-family stores) is **not** started. Every test and command ran with fresh scratch `XDG_*` directories; full suites ran on a `git archive` snapshot of each commit so concurrent edits could not leak in. Baseline before S3: 2089 tests, 2055 pass, 0 fail, 34 skipped (no sandbox failures on this run, unlike §16's 22).

### 18.1 Commits and full-suite totals

| commit | step | tests | pass | fail | skipped |
|---|---|---:|---:|---:|---:|
| `9581332` | S3: `fact-families.js` registry, `certifiedHorizonOk`, `certifiedReadWindowOk`, daemon-init registry check | 2103 | 2069 | 0 | 34 |
| `da35bc7` | S3: per-rule horizon gate in the watch-tier producers | 2107 | 2073 | 0 | 34 |
| `2e9ffdc` | S3: miner/shadow/correlation via `certifiedReadWindowOk`; tuning reports its boundary | 2111 | 2076 | 0 | 34 (one T4 run hit its 120 s timeout under concurrent load; it passes in ~5 s alone and in every later run) |
| `7656cf5` | S3: daemon per-rule horizon veto, `history_horizon_short`, fixed alert | 2116 | 2082 | 0 | 34 |
| `30d2b35` | S3: novelty diagnostics `history_certified_after_ts` | 2117 | 2083 | 0 | 34 |
| `2e79956` | G1 re-gate LOWs (learned status age floor + causes; HANDOFF refs) | 2118 | 2084 | 0 | 34 |
| `9a306c7` | S3b: seen-set, novelty gate lifted when valid, daemon referent | 2136 | 2102 | 0 | 34 |
| `d1f96c6` | S3/S3b: novelty horizon measured against the seen-set's certified span (test) | 2137 | 2103 | 0 | 34 |

### 18.2 What landed

**S3.**
- `src/fact-families.js` (leaf, imports nothing): the closed `FACT_FAMILY_BY_NAME`, `RULE_HORIZONS` (string literals; Q2 horizons: `service.appeared` 48 h, `scheduled_job.appeared` 48 h, `process.lineage.novel_edge` 6 d; the rest per §4.2), `READER_COVERAGE` (miner, shadow, correlation, tuning), `NOVELTY_FAMILIES` (the S3b census shape), and the horizon-short rule id and N. Module-init throws on a duplicate fact_name, an unknown family, a bad horizon, or a novelty family inconsistent with the other tables. `daemon.js` init checks `HISTORY_DEPENDENT_ALERT_RULE_IDS` against `RULE_HORIZONS` in both directions (catches a literal drifting from its constant).
- `certifiedHorizonOk(read, {nowMs, horizonMs})` in `fact-store-completeness.js`: pure, fail-closed. LOW-2: requires a **valid ledger** (`coverage` is `full` or `narrowed`; `unknown` fails). See deviation 1 for the floor it uses.
- Per-rule gate in the producers: session (`count_drop` 30 h and `churn` 6 h, independently), peer (spike and drop, 30 h), `service.disappeared` (6 h), canary (`canary_vanished` only, 6 h), the three novelty rules, and correlation. A horizon-short rule emits no candidate and reports no `evaluatedAlertKeys`; the cold-start state machine and the fold run unchanged, so it never re-arms (I5) and resumes on the tick the span recovers. Pinned per detector: persisted lockout stays `false`, `last_folded_ts` advances, the same tick with an older floor evaluates.
- Non-detector readers: see deviation 3.
- Daemon: per-rule horizon veto at both `computeCoveredAlerts` passes (deviation 4); `history_horizon_short` on the status record; fixed rule `daemon.fact_history.horizon_short` (deviation 5).
- Novelty diagnostics carry `history_certified_after_ts` (deviation 7). The sanitizer passes ISO strings and redacts `null`, so the field is omitted rather than null.

**S3b** (`src/novelty-seen-set.js`): per §17, with these concrete rules.
- **Shape:** `learned/facts/seen-sets/<family>.json` = `{schema_version, family, ledger_generation, ledger_pass_id, certified_since_ts, folded_through_ts, overflow, entries: {key: [first_ts, last_ts]}}`, exact-key validated.
- **Fold:** by `runFactRetention`, after the ledger finalize, in the same pass as the append, for every novelty family. Complete census ticks only (strict grouping; parity-tested against all three detector groupers, including contradictory, garbled and markerless ticks), `ts <= pass now` only, from candidates above the **prior** pass's floors. Entries expire 30 days past `last_seen`. A fold failure is non-fatal and reported as `seen_set_fold[family].status = "error"`.
- **Lineage:** the set is *continuous* only if its `ledger_generation` matches the prior and the new ledger and its `ledger_pass_id` equals the prior ledger's `last_committed_pass_id`. Otherwise it is **re-seeded** (deviation 9).
- **Read:** `readFactPoints({seenSetFamilies})` validates each set against the **same** ledger it just read (generation, committed pass id, no pending pass). Statuses: `valid`, `missing`, `unreadable`, `invalid`, `no_ledger`, `pending_pass`, `lineage_mismatch`, `overflow`. Only `valid` carries entries.
- **Decision:** novel ⇔ not in the window's prior complete groups **and** not seen-before in the set. The set is folded in the same pass as the append, so the latest tick's own entities are already in it: an entry whose only observation is the latest tick is still novel; any other observation, earlier or later (a future-dated entry surviving a rollback), is a prior sighting. The union only ever suppresses.
- **Gate lift:** with a valid set the three novelty detectors call `factHistoryTrustworthy` **without** `requireFullCoverage`. Without one (any non-valid status, or an injected read carrying none) the §16 interim gate stays, so under narrowing they re-arm and claim nothing (I14).
- **Cap:** 20,000 entries per family (§2's host: ~518 services, ~175 lineage edges, ~7 jobs per tick; expected distinct keys over 30 days are hundreds to low thousands; ~2 MB worst file). Overflow writes `{overflow: true, entries: {}}`, which is never valid, and every later pass retries a fresh re-seed. Status reason: `novelty_seen_sets[family].status = "overflow"` on the daemon status record, and the rule shows in `history_horizon_short`.
- **Invariants pinned by tests:** I13 (the same append sequence under a 10 MiB and a one-tick budget gives identical entries and `certified_since`); I14 (set deleted over a narrowed store → re-arm, no keys, no candidate); the G1 reproduction for all three rules (t0 evicted, returner absent t1-t3, back at t4 → no candidate, **with** `evaluatedAlertKeys` non-empty and no re-arm, plus a control proving the window alone would have called it new); a lost fold write followed by eviction still remembers the entity; partial/garbled/markerless/future ticks are never folded; overflow → not valid → recovery; expiry and scope; day-1 first run → valid, `certified_since: null`.
- **T1 updated:** at the 5 MB default the three novelty paths now keep evaluating through routine eviction (sets stay `valid` on structural and fast ticks, no anchor re-arms). Before S3b, T1 pinned the S2-interim behavior (re-arm, zero keys).

**G1 re-gate LOWs.**
- (a) `selectFactStoreCompleteness` no longer strips `age_floor_ts`. The `learned status` text names the actual cause(s): "byte-cap eviction (floor …)" and/or "age retention (floor …)".
- (b) HANDOFF: Q6 is in scope as S3b; Blocker 2 is `dc117ca`.

### 18.3 Finding: the interim `requireFullCoverage` gate went permanently silent on every host

`coverageFields` reports `narrowed` whenever a byte-cap floor exists at all, or the age floor falls inside the read window. Combined with §16's interim gate:
- the novelty detectors and correlation read a 31 d window against 30 d retention, so once a store is older than 30 days the age floor is always inside the window and they were silenced for good, on **every** host, with no byte-cap eviction at all;
- the 3 h shadow soak refused forever after the first byte-cap eviction ever, however old;
- the miner's unbounded read refused on any age floor, so it never mined after 30 days.

This was never shipped (the branch is unpushed). It is fixed by deviation 3 (readers) and S3b (novelty), and pinned by tests: a store older than 30 days still evaluates novelty; correlation and the miner accept an age-only narrowing; shadow accepts a byte-cap floor older than its window. The interim gate is still the fallback when a set is not valid. In that case a store older than 30 days loses novelty until the next structural pass re-seeds the set and the detector's 6-tick re-establishment completes.

### 18.4 Deviations from the plan text

1. **`certifiedHorizonOk` uses `max(bytecap_floor_ts, age_floor_ts)`**, not the raw byte-cap floor alone. The predicate must never be looser than what `readFactPoints` excludes (both floors since `dc117ca`). In normal operation the age floor sits about 30 days back and never binds. A completeness report with `coverage: "full"` and no floor fields reads as floor-null; a `narrowed` report with no floor fails closed.
2. **Detector test fixtures** whose hand-built completeness lacked `coverage` now say `coverage: "full"` (a real intact store always reports it). Otherwise the LOW-2 rule makes the horizon fail closed on them.
3. **Miner, shadow and correlation use `certifiedReadWindowOk`, not the §4.2 horizons.** The plan said: miner = 7 d mining span, shadow = the shadowed constraint's horizon, correlation = 3 d. The task required a replacement for the interim gate that is provably no weaker. The referent, stated: *a store that never byte-evicted, under the same age retention*. The predicate passes exactly when byte-cap eviction is invisible to the reader's own read: no byte-cap floor, or the floor strictly before the window start, or the floor at or below the age floor. The last case is the only way an unbounded read can pass. It is proved on two real stores: whenever it passes, the read returns byte-identical points. Consequences:
   - The miner's default read is unbounded, so on a byte-evicting store it mines only when the byte-cap floor is at or below the age floor. That is stricter than a 7 d horizon, and pre-S4 it means it never mines on an evicting host (§5 N6 already conceded service-presence mining at default budgets).
   - Correlation additionally requires its registered 3 d horizon, which can bind on a rolled-back age floor.
   - An age floor alone never refuses; age retention narrowed every reader on `main` too.
4. **The daemon per-rule horizon veto landed in S3, not S4.** Computing per-rule eligibility for the I12 signal *is* the veto computation, so it is wired into both `computeCoveredAlerts` passes now as single-read defense in depth. A producer that reports coverage for a horizon-short rule is still frozen (pinned). S4 makes it per family.
5. **The horizon-short signal is time-based, with N = 24 structural intervals.** `history_horizon_short = {threshold_ms, rules: {rule: {since_ts}}}` is written only when a rule is short over a **valid ledger report**; an untrusted read is a different condition and is reported as such. `since_ts` is carried forward from the previous status record (injectable `readDaemonStatus`). A missing or corrupt prior status, or a future `since_ts`, restarts the clock at now: that can only delay the signal, never raise it early. The fixed rule `daemon.fact_history.horizon_short` (in `FIXED_ALERT_RULE_IDS`) fires in `evaluateAlertRules` once `now - since_ts >= threshold_ms`, from the status record alone, so the CLI's read-only view agrees.
6. **canary:** the detector gates only `canary_vanished`. `canary.tripped` (positive evidence) and the manifest/store tamper reasons (direct I/O signals) stay ungated. The daemon's horizon veto is rule-level, so `canary.tampered` is vetoed wholesale while canary is horizon-short, mirroring its wholesale `HISTORY_DEPENDENT` inclusion.
7. **Novelty diagnostics scope:** `history_certified_after_ts` = the valid set's `max(certified_since, now - 30 d)`. Without a valid set it is `certified_after_ts` when narrowed, else the oldest retained point. The field is omitted when no scope is known; it is never null.
8. **S3b fold source = pre-eviction candidates.** §17 says "complete, certified ticks". The fold uses every candidate above the prior pass's floors *before* this pass's byte-cap eviction, so a tick this pass evicts is still folded. Added memory can only suppress a claim, never create one. It also closes the "tick kept at pass P, fold write lost, evicted at P+1" gap by construction rather than relying on the pass-id check (pinned).
9. **Re-seed boundary (`certified_since_ts`)** on any loss of continuity (missing, invalid or mismatched set, overflow):
   - `max(prior byte-cap floor, prior age floor, every loss marker)` when this pass's own continuity observation is ok;
   - the pass time otherwise (for example a re-bootstrapped ledger);
   - `null` only on a genuine first run (ENOENT store), or when the lineage never evicted or lost anything, in which case the seed really is complete.
   Over a narrowed store, memory before the floor is gone; the boundary says so and the novelty horizon is measured from it.
10. **Novelty horizon referent after S3b:** the valid set's certified span (`noveltyHorizonOk`). `certified_since: null` is eligible, like a never-narrowed store. Without a valid set it is the fact floor, plus the interim full-coverage gate. The daemon uses the **same** predicate (`noveltyRuleEligible`), reading the sets in its own history read, so novelty recovery is not frozen at the 5 MB cap just because the fact floor is under 48 h. Pinned: narrowed store + valid set → a covered `service.appeared` recovers; set lost → frozen and reported.
11. **Seen-set location** is `learned/facts/seen-sets/<family>.json`. S4 changes only `resolveSeenSetPaths` (and which family ledger the fold and read pair with). **S5/M3 must quarantine or delete legacy seen-set files too:** a generation mismatch already makes them non-valid, but orphaned files under `learned/facts/` break the "iterate the registry, never the filesystem" rule.
12. **Tuning** reports `fact_history_certified_after_ts` in its mine summary, not per backtest.
13. **The MEDIUM-1 confirmation fixture** in `daemon.test.js` actually evicted *every* record: its cap was the raw record size, below the normalized size. It now sizes the cap from `normalizeFactPoint` and sits 31 h back so the 30 h horizon is met. The horizon-short case has its own test.

### 18.5 G2 questions

1. **Re-seed boundary (deviation 9).** After a set is lost over a narrowed store and the detector re-establishes, an entity last seen *before* the boundary that returns is claimed new, scoped "not seen since `<boundary>`". The alternative boundary (pass time) only delays eligibility by the horizon; it does not recover the lost memory either. Is a scoped claim acceptable here, or should a re-seeded family stay ineligible for longer, for example until 30 days past the boundary so the set's memory is again the full retention?
2. **`certifiedReadWindowOk` as the reader policy (deviation 3).** Is "byte-identical to a never-byte-evicted store under the same age retention" the right referent? It is stricter than the plan's 7 d miner horizon, and the miner will not mine on an evicting host until S4 gives service its own budget.
3. **`canary.tampered` wholesale daemon horizon veto (deviation 6).** It freezes `manifest_unreadable` / `baseline_store_error` recoveries while canary is horizon-short, which at the 4 MiB budget happens only if `cap_below_tick`. Split the veto per reason, or accept?
4. **Horizon-short signal (deviation 5).** Time-based N × interval, `since_ts` carried in the same-UID-writable status record (can only delay, never raise early). Is that acceptable, or does it need its own ledger-tied state?
5. **Pre-eviction fold (deviation 8).** It folds ticks the pass then evicts, which were never readable as certified history. That is the safe direction for never-fabricate, but it departs from §17's "certified" wording.
6. **A pending pass at read makes the set non-valid.** After a crash mid-pass on a narrowed store, the novelty detectors re-arm (6 ticks) rather than trusting a set folded at the previous committed pass. Accept the availability cost?
7. **Cap and overflow:** 20k entries per family; overflow makes that family's novelty ineligible under narrowing until a re-seed fits. Is the cap right, and should overflow raise its own fixed alert rather than ride on `history_horizon_short`?
8. **Read cost for T9 (S4).** The daemon and each novelty detector now also parse their seen-set every fast tick: three small files at this host's volume, at most about 2 MB each at the cap. T9 must count them.
9. **Folding under a continuity break.** A pass whose prefix digest broke (an external edit) still folds that pass's candidates. Injected records can only *suppress* novelty, and that is already within a same-UID attacker's reach. Confirm.
10. **Trust surface of the set itself.** The set is a new same-UID-writable store that can suppress novelty: forged entries hide a new entity. That is the same `integrity_level` class as everything else in `learned/` (§1 non-goal), but it is a new instance of it. Recorded for G2/G3.

### 18.6 Final state

The final code commit is `d1f96c6`; this addendum and the HANDOFF update follow as a docs-only commit. Full suite on `d1f96c6` (snapshot, fresh scratch `XDG_*`): 2137 tests, 2103 pass, 0 fail, 34 skipped, 0 todo. T1 runtime is about 60 s on this machine both before and after S3b; the seen-set fold and read add roughly 8 %.

**Expected pre-S4 behavior on the current single 5 MB store (Leg D, not a bug).** Once eviction starts (~28 h), the certified span stays near 27 h, below the 30 h horizon of `session.count_drop`, `peer.count_spike` and `peer.count_drop`. So on every real host running this branch, those three rules are permanently horizon-short: `history_horizon_short` lists them, and `daemon.fact_history.horizon_short` fires 24 h later. Novelty is NOT affected, because with a valid seen-set it measures its horizon against the set. S4's per-family budgets (T8) resolve this. Expect it in any S7 soak or status read before S4.
