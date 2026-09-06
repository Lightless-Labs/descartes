# Grounded external review — trusted-state step ① sign-off + F2-Tier2

**Date:** 2026-09-06
**Reviewers (independent, code-grounded):** `gpt-6-astra` ×2 (via codex, read-only, high effort) + Fable 5.1 (native repo reads; ran patched-copy simulations in scratchpad).
**Subject:** the operator sign-off for `docs/plans/2026-09-06-trusted-state-step-1.md` (R1/R2/R4/D) and the F2-Tier2 shape.
**Bottom line:** **R4 and D are clean sign-offs. R1 is conditional — the plan understates a real, code-confirmed detector-suppression gap. R2 is safe (a status no-op once R1 lands). F2-Tier2 should be reshaped (coverage-contract, not sliding-anchor) and F2-Tier1 as shipped over-claims.**

> Provenance note: an earlier **ungrounded** Astra pass (its file reads timed out under `-s read-only`; fixed here with `--approve-for-me`) had returned a clean R1/R2 sign-off. The grounded passes overturned it. This is why the operator asked for grounding — verify-don't-worship earned its keep.

## Convergence (all three reviewers, independently)

### The crux — R1/R2 propagate to indefinite detector suppression (confirmed GAP)

`factHistoryTrustworthy` returns `{trust:false,"history_degraded"}` on `completeness.status === "degraded"` — both without an anchor (`fact-store-completeness.js:66`) and with one (`:73`), **before** `hasLossEventAfter` is consulted. That `completeness` is `buildCompleteness`'s output (`fact-store.js:401`). So R1/R2 (which flip `buildCompleteness` to `degraded` for a future-dated loss/break) suppress every completeness-gated detector via the **status gate**.

- **Loss markers are ledger fields, not age-evictable records.** Clean passes carry the ledger forward (`fact-store-integrity.js:280`); a `last_*_ts` changes only when a *new* delta lands on that channel (`:360-363`); age-eviction only filters fact *records* (`fact-store.js:251`). So a **far-future** marker keeps `buildCompleteness` degraded until `now − window > markerTs` — **no fixed recovery bound**, and clean passes don't shorten it.
- **Worse for default unwindowed mining** (`asOfMs = −∞`): `constraint-miner.js:366` returns zero candidates whenever trust fails — *permanent*, no age-out at all.
- **Fable empirical (patched R1+R2 copy, real `enforceFactRetention`/`readFactPoints`):** one retention pass at a clock +1 year with a corrupt line → `last_corrupt_ts = 2027-…`; then 20 clean passes at real time (`continuity_ok` durably repaired) → `buildCompleteness` = `degraded` at now / +29d / **+364d**; `history_degraded` throughout; first `intact` only at markerTs + window. Current code returns `intact` for the whole period.
- **§5.6 point 5 is wrong to attribute the blinding to R3 alone.** R1 delivers the *same* fail-STUCK suppression through the status gate — the very shape the plan rejects R3 for. Point 2 admits the propagation but the plan then treats it as benign.
- **The §8.2 "six assertions stay green" is not evidence of safety:** those tests inject `status:"intact"` via `intactReadResult` and never call the real `buildCompleteness`; the real-path rollback-recovery *property* is reversed by R1, invisibly to the suite.
- **Scope refinement:** "every detector" overstates it — **positive canary trips are computed off fact-history and stay outside the lockout** (`canary-baseline.js:637`; `canary_vanished`/disappearance keeps its own gate `:766-774`). The suppression hits history-*dependent* judgments (service/session/peer/process-lineage/mining).

### Phase-1 "recovery" is an escape hatch, not closure

- The cited test (`fact-store-integrity.test.js:574`) is a **brand-new store**, not deletion of an established degraded ledger. Deleting an established `integrity.json` takes the missing-ledger branch (`:294`) that omits the loss marker; two clean passes prove consistency with the *new* bytes but **discard historical proof** and give **no unattended recovery bound**.
- **It is undiscoverable.** `descartes learned status` (`constraint-store.js:316-331`) strips `last_corrupt_ts`/`last_schema_invalid_ts`/`last_continuity_break_ts`, and reads with **no window** (`:335`, `asOfMs=−∞`) so it says only "degraded" for *any* loss ever — an operator cannot see that a marker is future-dated. No daemon-status or alert surface exposes `history_degraded`.
- **Fable found it doesn't even cover the realistic event (pre-existing HIGH, independent of R1):** a forward-clock tick also writes future-*dated facts* (`daemon.js:616` → `appendFactPoints:336`). Once a future fact is the committed newest, `observeFactContinuity:252-256` returns `unknown` on every appending pass (newest can't advance) → `buildCompleteness:452` reads `unknown` → `history_unknown`; and the daemon only runs retention when `factPoints.length>0` (`daemon.js:602`), so an append-less repair pass never happens in production. **Simulated: deleting `integrity.json` does NOT recover — `unknown` persists.** Honest (`unknown`), but fail-STUCK.

### A second interaction — suppression can fabricate *recovery* (never-fabricate)

Astra + the 2026-09-05 critique (Finding #1) independently: a suppressed detector returns `[]`; the daemon merges baseline candidates (`daemon.js:745`); an absent candidate flips an existing active/acknowledged alert to `"recovered"` (`alert-store.js:303`). **Confirmed the mechanism exists** (`alert-store.js:301-309`); whether R1/R2's suppression triggers it depends on whether `coveredRuleIds` (the earlier F1-fix scoping) excludes suppressed baseline rules — **this must be settled by a real-path test**, not assumed either way.

## Per-reversal consensus

| Item | Verdict | Basis |
|---|---|---|
| **R1** | **conditional** | Doctrinally right (a hidden real loss reported `intact` violates never-fabricate), but introduces the unbounded status-gate suppression above. Sign only with the minimal fix below. |
| **R2** | **sign-off (as a no-op / dead-code removal)** | Fable verified on the `:157` fixture: current `{intact,false}`; R1-only `{degraded,false}`; **R1+R2 `{degraded,false}` — byte-identical**. R2 removes the now-dead future-break override; it adds no suppression beyond R1. |
| **R4** | **sign-off** | `detectCanaryTrips` never reads the manifest (`canary-baseline.js:267-326`); A1 only un-suppresses an already-computed genuine trip; garbage-key guard verified (negative control `:816-840` stays `[]`); dedup by `canaryIdHash` (`:430`). Residual (state it): a same-uid attacker can now inject a false `canary.tripped` for a never-configured id — noise, not fabrication (they could already read the real canary). |
| **D** | **sign-off** (surface fix) | `unprotected_same_uid` accurately labels the missing boundary; writer/reader impose no closed-key schema (`history-store.js:270/:285`). **Correction:** acceptance #6 targets the wrong surface — `descartes daemon status --json` calls `daemonServiceStatus` (`daemon.js:1038-1051`), which never reads `daemon-status.json`; add `integrity_level` there and/or the `history`/`triage` surfaces that do read the record. |
| **R3 withdrawal** | **correct — but fix the stated reason** | Keep `hasLossEventAfter` unchanged. But the real reasons are (a) its anchor-relative gate is what lets a detector re-establish after a loss / repair a future anchor (the five pinned rollback tests) and (b) the local duplicates (`canary-baseline.js:95-106`) would need matching edits — **not** the DoS argument (point 5), which R1 also violates. Rewrite §5.6 accordingly. |

## Minimal fix to require before signing R1 (consensus)

1. **A bounded blind.** Pull a **Phase-1** retention-time clamp of forward-dated `last_*_ts` down to `nowIso` into `prepareFactIntegrityLedger`. Fable argues the plan's "naive clamp is a NEW fail-open" (§5.2) is overstated — `:360-363` *already* overwrites a genuine marker with a stepped-back `nowIso` on any fresh delta (same clock-control attacker). **Decide that attacker's scope once**; if it's out of scope for Phase 1, a bounded blind (one window) beats an unbounded one. **Ordering constraint:** fix the future-*fact* continuity wedge first, or `last_rewrite_newest_ts` (itself future) defeats a `nowIso >= last_rewrite_newest_ts` guard.
2. **Surfacing.** Additive `future_loss_fields`/`degraded_reason` on `buildCompleteness` (same precedent as `continuity_oldest_ts`), through `selectFactStoreCompleteness`, plus a fact-store-completeness line in the daemon status record, and stop `learned status` reading unwindowed / stripping the loss-ts fields.
3. **A real-path regression test** (real `readFactPoints`, no `intactReadResult`): forward-clock tick with a routine loss → restore → assert `degraded` + `history_degraded` → recovery → `intact` within N passes. Also asserts a suppressed detector does **not** flip its alert to `recovered`.

Surfacing + a recovery command *without a bound* is acceptable only if the operator explicitly accepts "unbounded-until-manual" as the Phase-1 trade — which §5.6 point 5 itself calls "strictly worse", so signing R1 on that basis contradicts the plan's own standard.

## F2-Tier2 — reshape (both grounded reviewers)

- **Shape:** detector-declared **evidence horizon** + store **certified-coverage** reporting; the minimum-span floor gates **detector eligibility only**, it never extends store coverage. The todo's "sliding anchor recovery must never re-anchor below a floor" is the wrong shape — read literally it either **wedges** (post-break span < floor, store can't manufacture span) or **fabricates** (extends the claimed span backward across the break). Requiring the store to keep claiming a span it lost violates never-fabricate.
- **Byte-cap eviction is today a *loss* channel** (`fact-store-integrity.js:472`); eviction from the *old* end is coverage-narrowing, not an interior gap — it should move a `certified_from_ts`, not break trust. This is the discriminating design point and the biggest detection-strength win; **it widens what detectors trust → daybreak review** before landing.
- **F2-Tier1 as shipped OVER-CLAIMS.** `continuity_oldest_ts` mirrors `ledger.continuity.oldest_ts`, which only moves *older* (`fact-store-integrity.js:313-316`) and can **predate retained facts**; the test asserts only `typeof === "string"` (`constraint-store.test.js:569`) though its comment says "advancing". Fable simulated it reporting `00:00` with a single on-disk point at `00:09`. **Do not treat Tier-1 as a coverage boundary; fix `oldest_ts`/add `certified_from_ts = max(oldest retained, in-window loss markers)` as the small standalone carve-out.**
- **Verdict:** Astra — GO standalone as a coverage-*contract* change; Fable — FOLD the horizon-declaration + byte-cap-reclassification into the critique-§6 claim change / transactional-store move and carve out only the reporting fix now. Both reject an anchor-arithmetic-only fix. Either way: **fix the Tier-1 over-claim + reshape as a coverage contract; do not build the floor as a store-span mechanism.**

## Plan-missed list (code-grounded, for the implementer)

1. **Forward-dated facts wedge continuity** — pre-existing HIGH fail-stuck, silent; Phase-1 recipe does not recover it (`observeFactContinuity:252-256` + `daemon.js:602/:616`). Fix direction: retention treats `ts > now + tol` as an observable counted drop stamped at real `now`, or prove appends by parsing the suffix beyond `committedBytes` rather than by newest-ts advance.
2. `:360-363` already overwrites markers under a stepped-back clock — the §5.2 clamp-guard rationale is inconsistent with existing code; decide the clock-attacker scope once.
3. `continuity_oldest_ts` over-claims (above).
4. `learned status` reads unwindowed (`constraint-store.js:335`) and strips the three loss-ts fields — the only operator surface for the store cannot diagnose the R1 blind.
5. §8.2's evidence is mock-based; the real-path F4 rollback-recovery property is reversed by R1 and needs its own test.
6. Component D surface mismatch (`daemonServiceStatus` never reads the status record).
7. Minor: `detectCanaryTrips:278` treats a future-dated latest census as fresh indefinitely; `:630` excludes future groups from re-accumulation but the trip path does not.

_Fable simulation artifacts (scratchpad, not in repo): `q1b-sim.mjs`, `q1b-sim-g.mjs`, `q2-oldest.mjs`, `r2-noop.mjs`._
