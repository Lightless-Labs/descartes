# Fact-Store Capacity and Sliding Anchor: Make Default-On Watching Work on Real Hosts

**Created:** 2026-10-05
**Status:** PLAN. Awaiting operator decisions (§12) and a pre-build multi-model plan review (Fable code-grounded, daybreak-blue, Astra) per `docs/solutions/2026-09-14-multi-model-review-and-planning-playbook.md`.
**Reviewed:** 2026-10-05 (adversarial plan review, NEEDS-REVISION(7) → folded)
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

**The table below is provisional until S0** pins exact worst-case tick sizes. *(Review fold, MEDIUM-6.)* The figures were sized with the average record size. Re-checked against the ~470 B max-key estimate:
- service: 24 × ~470 KB × 1.25 ≈ 14.1 MB, under 16 MB with about 13% margin. 16 MB holds ~35 worst ticks.
- process_lineage (~2.8 MB), scheduled_job (~2.8 MB) and canary (~0.7 MB) are comfortably inside their budgets.
- session: 30 × ~94 KB × 1.25 ≈ 3.5 MB, under 4 MB but thin.
- **peer fails at 12 MB.** 72 × ~188 KB × 1.25 ≈ 16.9 MB. The 3 d `H_max` comes only from correlation. S0 decides between raising the peer budget to about 18 MB, which puts the worst-case total at about 62 MB, and a shorter correlation horizon (§4.2 table).

**Decision rule if S0 breaks the read-cost bound.** If the pinned worst-case budgets push T9 past its bound, **stop before S4** and escalate to the operator. The options:
1. accept the higher read cost and raise T9's bound, with the measured figure;
2. lower that family's `H_max`, which narrows eligibility as recorded in §5;
3. pull incremental tail-read caching (a §1 non-goal today) into scope.

Do not quietly shrink a budget below the T8 invariant.
- Inflation is also visible: injected entities trigger novelty alerts, and a census over its ceiling is marked partial (`tools/services.js:31-36`).

| family | typical B/tick | worst B/tick | **default budget** | typical horizon | worst-case horizon | H_max |
|---|---:|---:|---:|---|---|---|
| service | 132 KB | ~254 KB | **16 MB** | ~5.3 d (127 ticks) | ~2.75 d (66 ticks) | 24 h (yes) |
| process_lineage | 44 KB | ~50 KB | **8 MB** | ~7.9 d | ~6.9 d | 24 h (yes) |
| scheduled_job | 2.6 KB | ~67 KB | **4 MB** | 30 d (age-limited; needs 1.9 MB) | ~2.6 d | 24 h (yes) |
| session | ≥0.25 KB | ~51 KB | **4 MB** | 30 d up to ~22 sessions | ~3.4 d | 30 h (yes) |
| peer | ≥0.65 KB | ~130 KB (max-key ~188 KB) | **12 MB (S0: likely ~18 MB)** | 30 d up to ~52 peers | ~4.0 d (max-key ~2.7 d) | 3 d (**no** at max-key; see above) (correlation) |
| canary | 0 (AUTHOR off) | ~60 KB | **4 MB** | 30 d | ~2.9 d | 6 h (yes) |
| network | 2.2 KB | S0 | **4 MB** | 30 d (needs 1.6 MB) | S0 | n/a (AUTHOR; 3 h freshness) |
| provenance | 3.3 KB | S0 | **4 MB** | 30 d (needs 2.4 MB) | S0 | n/a |

**Totals (provisional).** Budgets sum to 56 MB, or about 62 MB if S0 raises peer, versus 5 MB today. Steady state on this host is about 30 MB. At typical volume, peer and session are only ever age-evicted, so they get the full 30 days. This is R0a's intent. R0b covers the adversarial case.

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
  - a ledger re-bootstrap over a non-empty store (missing, invalid or unreadable ledger, or pass-id exhaustion; §4.1 item 2, HIGH-1);
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
