# Trusted-State Step ① — Monotonic-Continuity + Honest-Labeling Floor

**Date:** 2026-09-06
**Status:** PLAN — operator sign-off required for the test-pinned reversals in §8.1 (three assertions: R1, R2, R4). Phase 0 (D) and Phase 2 (C) are autonomous; §8.2 lists six further assertions the *naive* form of this plan would have flipped and which the corrected design keeps green (no sign-off, but recorded so the operator sees what was avoided and why).
**Owner:** operator signs off the §8.1 reversals; agent implements per-phase once signed off.

**Inputs / authorities:**
- Threat model (ordering authority): [`docs/design/state-integrity-threat-model.md`](../design/state-integrity-threat-model.md) — architecture-fixes-first → privilege-separation → authenticated ledger → witness → interactive HW approval → **attestation LAST**.
- Security sweep (behaviors, code refs, test-pins): [`docs/reviews/2026-09-04-daybreak-security-sweep.md`](../reviews/2026-09-04-daybreak-security-sweep.md) — fact-store #3 (Deferred/architectural + the two-part read/retention fix recipe, sweep §fact-store) and canary clean-delete (sweep §positive-evidence-canary "Deferred / architectural").
- Operator sign-off ledger (this plan is its "updated (d)"): [`todos/2026-09-06-trusted-state-step1-operator-signoff.md`](../../todos/2026-09-06-trusted-state-step1-operator-signoff.md).
- Doctrine the step must respect: [`docs/design/autonomy-doctrine.md`](../design/autonomy-doctrine.md) — autonomy scales with `reversibility × corroboration`, never fabricate, fail-closed, attestation-gated authority.
- Cross-referenced sibling slice sharing the trusted-time root: [`todos/2026-09-06-llm-budget-trusted-time.md`](../../todos/2026-09-06-llm-budget-trusted-time.md).

> **Re-verification note (2026-09-06):** every code and test line below was re-checked against the working tree, not the 2026-09-04 sweep numbering. Two corrections to the earlier draft of this plan are load-bearing and are called out in §8: (1) the fact-store #3 fix is scoped to `buildCompleteness` (`fact-store-integrity.js`) **only** — it deliberately does **not** touch `hasLossEventAfter` (`fact-store-completeness.js:36`), because doing so flips five deliberately-pinned detector rollback-recovery tests and reintroduces a clock-rollback blind spot; (2) the canary A1 change replaces the manifest-membership filter with an **empty-key guard**, not an unconditional removal, so a garbage-sanitizing id still cannot emit a `canary.tripped`.

---

## 1. Header / summary

Ship the **first** rung of daybreak's trusted-state ladder: dissolve two of the four deferred "trusted-same-user-state" items as **architecture fixes**, and add one **honest label**, without any off-host infrastructure. It is a **monotonic-continuity + honest-labeling floor**, not tamper-proofing. Two behaviors reverse deliberately test-pinned expectations — a **future-dated fact-store loss/break resolving `intact`** (Component B, fact-store #3) and a **clean-deleted canary's genuine trip being suppressed** (Component A, clean-delete) — which is why the operator must sign off (§8.1).

## 2. Goal & scope

Four components:

- **A — canary-trip fires on genuine fact-history evidence regardless of current manifest membership.** A genuine, already-observed two-snapshot canary trip is never retroactively suppressed by a later manifest edit (clean-delete) — while a garbage/empty-sanitizing id still cannot produce a trip (never-fabricate).
- **B — future/regressed wall time fails closed in the fact-store's own integrity read.** A future-dated loss or continuity break resolves `degraded`/`unknown`, never `intact`, in `buildCompleteness`.
- **C — baselines as disposable caches.** Derived stores whose loss triggers cold-start, never a change to historical truth or a fabricated signal.
- **D — the honest `integrity_level: unprotected_same_uid` label.** Say out loud that same-uid state is not yet protected.

### What this is NOT

- **NOT off-host / hardware attestation.** That is **step 6** of the ladder, not step 1. Nothing here claims tamper-proofing, root-resistance, or that a same-uid attacker is defeated.
- **NOT privilege separation** (`_descartes` service UID / system daemon) — step 2; **NOT** an authenticated/signed ledger (step 3), a witness (step 4), or interactive HW approval (step 5).
- **NOT a trusted *time* source, and NOT a change to the detector-facing trust gate.** Step 1 hardens the fact-store's *own* integrity surface (`buildCompleteness`) and introduces a boot *uuid* for continuity ordering later (Phase 3). It deliberately does **not** change `factHistoryTrustworthy` / `hasLossEventAfter`'s future-loss tolerance (see §5.6) and does **not** introduce a monotonic *clock* for aging (see §5's reverted-`CLOCK_MONOTONIC` note).

Step 1 raises the floor (a real loss or a real trip is no longer silently swallowed by a clock artifact or a manifest delete) and keeps the public label honest about what is still unprotected. It raises **alerting** (the on-host ceiling the doctrine permits), never **authority** (which stays attestation-gated).

## 3. Background — the trusted-same-user-state boundary, and why step 1 is safe before attestation

Descartes runs as the login UID; its state (`facts.jsonl`, `integrity.json`, the baseline stores, `canaries.json`) is writable by that same user. The declared threat model treats that as out of scope for *tamper-proofing* (`promotion-store.js:30-31`: "friction against mistakes/stale reviews, not an attacker model"; `SEED_CONSTRAINTS` are hand-authored `status:"active"` records — file-authored activation is a **supported** path, not a bypass). daybreak's independent analysis sharpened this: three of the four deferred items are **architectural bugs** — cases where *current, mutable config re-interprets already-observed positive evidence* — so fixing them **removes integrity dependency** rather than pretending storage is trusted.

Two of those are in scope here:

- **fact-store #3** — wall time currently establishes continuity in the fact-store's own read: a future-dated loss reads back `intact`. An architecture bug (trusting an untrusted clock), fixable now in `buildCompleteness`.
- **canary clean-delete** — a historical trip is currently reinterpreted through *current* manifest membership: delete the entry and the trip vanishes. Also an architecture bug (current config rewriting historical evidence).

Both are safe to fix before attestation because the fixes only ever move reads in the **fail-closed** direction (a real loss/trip surfaces; nothing new is claimed trustworthy) and honor `reversibility × corroboration`. The `integrity_level` label makes the residual gap explicit rather than implied — daybreak's "acceptable **only** for an explicitly-labeled best-effort mode."

### 3.1 Threat-model ordering alignment

Per the build order, step 1 == **"1. Remove mutable-current-state dependencies (the architectural-bug fixes) — before any cryptography"** + the standalone honest-labeling change. It builds **no** cryptography, **no** new principal, **no** witness. Everything above additive alerting (recommend, sticky adaptation, acting) remains attestation-gated and untouched.

---

## 4. Component A — canary-trip fires on genuine evidence regardless of current manifest membership

### 4.1 Current behavior (verified against the working tree)

`canary.tripped` is POSITIVE two-snapshot evidence computed **entirely off completeness-proven fact-history**:

- `canary-baseline.js:637` — `const rawTrips = detectCanaryTrips(currentGroups, { nowMs, freshnessMs, minEstablishedCount })`. `detectCanaryTrips` **never reads the manifest**; a trip requires two `complete` census groups, `minEstablishedCount` sightings under a **stable `identity_fingerprint`** (`:300-305`), a watched-attribute change (`computeStatDiffTripReason`, `:313`), and the latest snapshot within `freshnessMs` (`:278`, default `DEFAULT_CANARY_FRESHNESS_FALLBACK_MS`) — otherwise it returns `[]`.
- `canary-baseline.js:663-667` — the manifest is loaded; `currentCanaryIds` = the sanitized ids of the **current** manifest; `manifestReadOk = manifestResult?.read_ok !== false`.
- `canary-baseline.js:709-717` — the suppression:
  ```js
  const isolatedEntityKeys = new Set(/* entity_key_collision | manifest_oversized | schema_invalid */); // :709-714
  const trips = manifestReadOk                                                                            // :715
    ? rawTrips.filter((entry) => currentCanaryIds.has(entry.canary_id) || isolatedEntityKeys.has(entry.canary_id))
    : rawTrips;
  const outputTrips = trips;                                                                              // :718
  ```
  Rounds 2–4 carved out *present-but-isolated* entries (collision / oversized / schema_invalid) so an attacker-forced **isolation** of an established entry no longer suppresses its genuine trip. **What remains** is the clean case: an entry **deleted outright** from `canaries.json` (`{canaries:[]}`, `read_ok:true`, no `invalid_entries`). Its id is absent from both `currentCanaryIds` and `isolatedEntityKeys`, so a genuine `rawTrip` is filtered out → **suppressed**.

**The attack:** an adversary who can write `canaries.json` clean-deletes the tripped entry to silence its already-observed alert — a plain-JSON suppression path against a positive detector (sweep §positive-evidence-canary "Deferred / architectural").

### 4.2 Target design (Phase 1)

Fire a genuine `rawTrip` **regardless of current manifest membership**, while preserving the one legitimate exclusion the current filter also happens to enforce: a canary_id that sanitizes to **nothing** (garbage) can never correspond to a real canary and must never emit a trip. Replace the manifest-membership filter with an **empty-key guard**:

```js
// A1 (Phase 1): a genuine two-snapshot trip is never suppressed by current manifest membership.
// The ONLY retained exclusion is the empty/garbage-id case (sanitizeEntityKey(...) -> undefined),
// which can never be a real canary — dropping it would emit a canary.tripped for a non-existent
// canary (fabrication-adjacent), and would flip the :816 negative control (see §8.2).
const outputTrips = rawTrips.filter((entry) => Boolean(sanitizeEntityKey(entry.canary_id)));
```

- **Verified:** `sanitizeEntityKey` delegates to `sanitizeIdentityString` (`fact-translators.js:14-16`); `sanitizeEntityKey("////")` returns `undefined` (confirmed by direct evaluation), so the guard keeps the garbage-key negative control at `:838` producing `[]`.
- **The manifest change is still surfaced on its own.** A read/parse/schema failure raises `canary.tampered(manifest_unreadable)` (`:730-732`); an isolated entry raises its own `canary.tampered` (`:754-756`); a clean legitimate decommission raises no tamper (correct). Retirement is thus observable via the tamper path, never via a silent filter on the trip.
- **On-disk footprint: none.** `facts.jsonl` and `integrity.json` record shapes are unchanged. No new field, no digest, no new event stream in Phase 1.
- **Bounding the trailing trip:** with membership no longer gating, a trip re-derives each tick only while its latest snapshot stays within `freshnessMs` (`:278`); once the canary stops being observed the trip stops re-deriving after `freshnessMs`, and `alertId` dedup collapses the interim to **one** alert that then resolves. Cost: "one trailing alert after a legitimate decommission" (arguably desirable), **freshness-bounded**, not an unbounded stream (acceptance #4).

### 4.3 A2 (durable `trip_observed` / `retired` events + manifest digest) — DEFERRED to Phase 3, NOT in the sign-off surface

The sweep's fuller resolution — record a trip as an append-only event bound to the manifest **digest that applied at observation**, retirement as a later event — is deferred. This is where any `loadCanaryManifest` `digest` field and an `observed_manifest_digest` diagnostic belong.

> **Scope correction (why NO digest in Phase 1):** the earlier draft proposed adding an optional `digest` to `loadCanaryManifest` and stamping a `current_manifest_digest` on the A1 trip. That is withdrawn from Phase 1. `loadCanaryManifest`'s `read_ok:true` return shape is contractually **byte-identical** across callers (`canary-manifest.js` comment at the `invalid_entries` return), and an always-present `digest` breaks the exact-shape `deepEqual` fixtures at `canary-manifest.test.js:16, :24, :38, :51, :59, :67, :77, :101, :128` (nine touches). More importantly, the honest `current_manifest_digest` (this-tick's manifest, i.e. the *empty* manifest's digest after a clean-delete) adds nothing an operator can trust, and the true `observed_manifest_digest` requires the durable event anyway (`applyAlertCandidates` overwrites `diagnostics` on dedup re-fire, preserving only `first_seen` — `alert-store.js:287`). All digest work moves to A2. **A1 = the filter→guard swap only.** The operator sign-off (R4) is satisfied entirely by A1.

### 4.4 Test-pinned reversal (→ §8.1)

`test/canary-baseline.test.js:363` "manifest-gated: a canary removed from the current manifest produces no further trips", assertion at **`:396`** `assert.deepEqual(decommissioned, [])`. The fixture is a genuinely established `credential` canary (`presence(3, "credential", { atime: "101" })` on `fp-stable-v1`, three complete censuses, `establishedMinCensusCount:3`) with the manifest cleared to `{ canaries: [] }`. Under A1 this flips: the clean-deleted canary's genuine `atime_advanced` trip fires → **one `canary.tripped` candidate**. Title reversed → rename.

### 4.5 Invariant preserved (never-fabricate)

- **A genuine trip is never silently suppressed** by a manifest edit (the property restored).
- **Never fabricate:** `detectCanaryTrips` still requires two completeness-proven snapshots + `minEstablishedCount` under a stable identity within `freshnessMs`. An attacker who manipulates **only** the manifest produces **zero** `rawTrips` to un-suppress — A1 can only un-suppress a trip already genuinely computed; it can never fabricate one.
- **`empty_entity_key` / garbage ids stay excluded** by the retained guard — `sanitizeEntityKey("////") === undefined` is falsy, so the negative control at `:838` (trip-shaped facts under `////`) stays `[]` (§8.2). This is the single reason the filter is *replaced by a guard*, not deleted.
- **`canary_vanished` unchanged** — an *absence* claim (fabricable from incomplete state) keeps its conservative `currentCanaryIds` gate (`detectCanaryVanished` :396, and the `manifestReadOk`/`coldStartPendingThisTick` gates at `:766-774`); A1 touches only the positive `trips` path.

---

## 5. Component B — future/regressed wall time fails closed in the fact-store's own integrity read

### 5.1 Where wall-clock continuity is trusted today (verified)

Two read-path sites in `buildCompleteness` allow a *future-dated* loss/break to resolve `intact`, plus one retention-path site that stamps losses with raw wall time:

- `fact-store-integrity.js:406-411` — `lossAtOrAfter(timestamp, asOfMs, nowMs)` returns `lossMs >= asOfMs && lossMs <= upperBoundMs` where `upperBoundMs = nowMs` (`:409-410`). The `<= upperBoundMs` clause **drops future-dated losses** in `buildCompleteness`'s loss-channel eval (`:469-474`) and in the degraded/unknown branch (`:454`).
- `fact-store-integrity.js:437-451` — `buildCompleteness`'s `continuityBreakIsFuture` **clock-rollback-artifact override**: when `last_continuity_break_ts > nowMs` and the live store observes `ok`, it flips a stale `continuity_ok:false` back to `true` (`:449-450`), so the read resolves `intact`.
- `fact-store-integrity.js:262-394` — `prepareFactIntegrityLedger` stamps loss timestamps with `nowIso` (`:360-363`); if retention runs under a stepped-forward clock those become **future** wall values that persist on the ledger carried forward.

**Already present (the monotonic counter):** the integrity ledger already carries a **strictly-increasing `pass_id`** — validated `Number.isSafeInteger(pass_id) && pass_id > 0` (`:111`), strict monotonicity `pending_pass.pass_id <= last_committed_pass_id ⇒ invalid` (`:154`), in the ledger schema key sets (`last_committed_pass_id` `:28`, `pass_id` `:33`). This is the local monotonic sequence Component B builds on; what is missing is **boot identity**.

### 5.2 Target — B-tactical (the reversal — Phase 1): `buildCompleteness` read path only

Two sub-fixes, shipped together:

1. **`lossAtOrAfter` (`:410`):** drop the `lossMs <= upperBoundMs` clause. A future-dated loss is a **real loss with an untrustworthy timestamp** → count it. This alone makes the loss-channel eval (`:469-474`) and the degraded/unknown branch (`:454`) resolve on a future loss.
2. **Remove the `continuityBreakIsFuture` override (`:444-451`):** a future continuity break with `continuity_ok:false` resolves through the normal path. **Dependency:** with the override removed but the `:410` clause still present, the future break lands on `"unknown"` at `:452-467`; shipping sub-fixes 1+2 together lands it on **`"degraded"`** via `lossAtOrAfter` at `:454`. They must ship as one unit.

The read-path-only change is strictly fail-closed and has **no fail-open vector**: at a stepped-back `now` the future loss counts, and it stays counted on restore. Its blast radius is exactly R1 + R2 (§8.1) — verified: `lossAtOrAfter` is used only inside `buildCompleteness`; the detector suites all mock `readFactPoints` (they never exercise the real `buildCompleteness`), and `test/fact-store.test.js` has **no** future-retention-then-earlier-read test.

> **Withdrawn from Phase 1 (was the draft's third sub-fix / R3): do NOT change `hasLossEventAfter` (`fact-store-completeness.js:36`).** See §5.6 — this is the single most important correction in this plan.

**⚠️ The retention-path clamp is deferred to Phase 3 and MUST be guarded — a naive clamp is a NEW fail-open.**
The sweep proposed clamping "any loss timestamp assigned `> nowIso` down to `nowIso`". A **naive** clamp creates a *permanent* fail-open the current transient behavior does not have: a genuine loss stamped `2026-09-01` → attacker steps the clock back to 1990 → one daemon tick runs retention (retention runs on every `appendFactPoints`, `fact-store.js:350`) → the clamp rewrites the real loss to 1990 → attacker restores the clock → `lossAtOrAfter(1990, asOfMs = 2026−window)` is false → **`intact`**. The loss is preserved but moved to an attacker-chosen time. So:
- The clamp lands only in **Phase 3, atop B-ledger**, and is **guarded**: refuse to clamp when this pass's wall `ts` is **below the prior pass's recorded `ts` within the same `boot_id`** — record a `clock_regression` loss instead of rewriting. Clamp only a forward-stamped value under a monotonic, same-boot-consistent sequence.
- **Fields the clamp touches** (carried forward on `next`, consulted at `:469-474`): `last_corrupt_ts`, `last_schema_invalid_ts`, `last_bytecap_evict_ts`, `last_continuity_break_ts`, plus `first_degraded_ts`. (Note: `:360-363` only ever *assigns* `= nowIso`; future values arrive on a *prior* ledger carried forward, or from retention run under a forward clock.)
- **Interim recovery** (Phase 1, no clamp): a store stuck `degraded` after a legitimate forward-clock retention pass recovers via the existing operator path — delete `integrity.json` → `ledgerReason:"missing"` → reaches `intact` after two clean passes (bootstrap comment `:289`; pinned at `fact-store-integrity.test.js:574`). Read-path-only never strands the operator permanently.

### 5.3 B-ledger (the honest continuity substrate) — Phase 3

Add `boot_id` to the ledger `continuity` record and a `clock_regression` loss channel keyed off `(boot_id, pass_id, wall ts)`, not the raw clock.
- Record `boot_id` + this pass's wall `ts` per pass. A wall `ts` that **regresses relative to the prior pass within the same `boot_id`** → `clock_regression` loss → `degraded` until it ages out.
- **Reboots:** the counter / process-local timing reset at reboot and `boot_id` **changes**. A changed `boot_id` is the **expected** signal a sequence reset is legitimate (reboot); a **same-boot** regression is tamper. This is the distinction the raw wall clock cannot make.
- **Not a clock.** The primitives are a *counter* (`pass_id`) and a *uuid* (`boot_id`) — **no `hrtime`/`CLOCK_MONOTONIC` as an aging time source.** A monotonic-clock anchor was tried and **reverted** in the LLM-budget work (2026-09-06) because `CLOCK_MONOTONIC` pauses across suspend and silently darkened a route after laptop sleep. Aging stays on wall time + the guarded clamp; **ordering/continuity** moves to counter + boot-id.
- **Schema addition to `integrity.json` (not `facts.jsonl`).** The validator (`isValidFactIntegrityLedger`/`isValidPendingPass`, `:105-166`) must accept `boot_id`; a ledger **lacking** it (pre-migration) must degrade-not-crash (bootstrap the field, do not fail the ledger). `facts.jsonl` record shape unchanged.
- **Platform note (verify before building, per the no-VM constraint):** `boot_id` — Linux `/proc/sys/kernel/random/boot_id`; macOS is **verify-first** (`kern.bootsessionuuid` vs. hashing `kern.boottime`); the Linux path is **CI-gated** (dev machine cannot run VMs — cross-target check + CI execution). See open question 2.

### 5.4 Cross-reference

The LLM-budget trusted-time slice (`todos/2026-09-06-llm-budget-trusted-time.md`) needs the **identical** primitive — a trusted monotonic sequence (monotonic counter + boot-id continuity) for its trailing-hour budget — and documents the same reverted-`CLOCK_MONOTONIC` lesson. B-ledger should expose counter+boot-id continuity as a **shared** substrate both this ledger and the budget audit consume; that slice's own design/tests stay out of scope here (§12) but must reuse, not re-invent, this primitive.

### 5.5 Test-pinned reversals (→ §8.1)

`fact-store-integrity.test.js:149` (test `:131`) and `:180` (test `:157`) flip `"intact" → "degraded"`. Details in §8.1.

### 5.6 Why `hasLossEventAfter` / `factHistoryTrustworthy` is deliberately UNCHANGED (the withdrawn R3)

The earlier draft included a third B-tactical sub-fix: drop the mirror `lossMs <= upperBoundMs` clause in `hasLossEventAfter` (`fact-store-completeness.js:36`), flipping `factHistoryTrustworthy` to `{trust:false,"history_degraded"}` on a future loss (its "R3", `fact-store-completeness.test.js:110`, expected value at `:118`). **This is withdrawn.** Reasons, in order of force:

1. **It is outside the sweep's own fix recipe.** The sweep's fact-store #3 fix names exactly two edits: read-path `lossAtOrAfter` and the retention clamp (sweep §fact-store "FIX ... two parts"). It never names `hasLossEventAfter`. The sweep *also* listed `fact-store-completeness.test.js:110` among "the three named tests to flip", but that listing is internally inconsistent with its own recipe: `:110` tests `factHistoryTrustworthy` (which uses `hasLossEventAfter`), and the recipe's `lossAtOrAfter` edit cannot flip it. The "three named tests" was loose grouping, not a traced consequence.
2. **It is unnecessary to close the repro'd bug.** The fact-store #3 repro is `buildCompleteness → intact` on a future-emptied store. R1+R2 close it fully. `factHistoryTrustworthy` is a downstream consumer; in the *real* path it already fails closed on a future loss via the completeness **status** (post-R1 a real read returns `status:"degraded"`, and `factHistoryTrustworthy:73` returns `{trust:false}` on a degraded status regardless of `hasLossEventAfter`). Changing `:36` adds nothing to the real-path guarantee.
3. **It flips five deliberately-pinned detector rollback-recovery tests.** `hasLossEventAfter` is the shared trust gate every detector consults with an injected `status:"intact"` + a **future** `last_corrupt_ts` to isolate the store-anchor-repair path. Dropping `:36`'s upper bound makes `factHistoryTrustworthy` return `{trust:false}` for those fixtures, so the detectors never re-accumulate and the recovery assertions break: `canary-baseline.test.js:1390` (test `:1371`), `session-baseline.test.js:909` (test `:896`), `service-baseline.test.js:743` (test `:729`), `peer-baseline.test.js:1070` (test `:1057`), `process-lineage-baseline.test.js:375` (test `:362`) — all use `intactReadResult(points, { status: "intact", last_corrupt_ts: <far-future> })`. See §8.2.
4. **Consistency would force three more changes and more reversals.** Each of canary/session/service also carries a **local duplicate** of the exclusion, `hasCompletenessLossAfterAnchor` (canary-baseline.js:95-106, upper bound at `:104`), kept intentionally as an independently-reviewed check. Making future losses count "everywhere" would require editing those too, flipping their coverage.
5. **It reintroduces a clock-rollback detection blind spot (fail-STUCK, not fail-closed).** An attacker who writes a single far-future loss ts into the ledger would then **permanently blind every detector** until wall time catches up — a denial-of-detection the current design (the F4 / rollback-recovery tests) specifically prevents. That is strictly worse than the transient `buildCompleteness` mislabeling B-tactical fixes.

**Conclusion:** Component B in Phase 1 is scoped to `buildCompleteness` only. The detector-facing future-loss handling is correct as-is and is deferred to B-ledger, where `boot_id` can distinguish a genuine future loss from a same-boot clock rollback. **R3 does not ship**; `fact-store-completeness.test.js:110` stays green.

### 5.7 Invariant preserved (never-fabricate)

`status:"intact"` stays reachable **only** by positive proof (sha256 committed-prefix digest with a trustworthy, non-future continuity ordering). A future or regressed wall clock now **fails closed** to `degraded`/`unknown` in `buildCompleteness`. The fact-store BLOCKER #1/#2 input-guards (`fact-store.js:204-224`, `:275` kept+evicted sum-assert) are untouched.

---

## 6. Component C — baselines as disposable caches

### 6.1 Which baselines

The derived per-detector stores: **canary**, **peer**, **session**, plus the sibling stat baselines **process-lineage**, **persistence**, **service**. All are **derived from** the authoritative fact-store; none is a source of historical truth.

### 6.2 Who actually reads them, and why disposal is safe (verified)

> **Correction to the earlier draft.** The draft named `tools/provenance-warnings.js` and `constraint-miner.js` as baseline-store consumers "that must not break." **Neither reads a baseline store.** `provenance-warnings.js` (`src/tools/`) exports process-provenance collectors (`listListeningSocketsWithPid`, `snapshotProvenanceProcesses`, `computeProvenanceWarningCandidates`); `constraint-miner.js` imports `readFactPoints` + `factHistoryTrustworthy` and mines **facts**, not baseline stores. Grepping the tree, **no file outside the `*-baseline.js` modules reads a baseline store** — each store is private to its own `compute*BaselineCandidates`. The only external consumer of the detector **output (candidates)** is `daemon.js` (the alert pipeline; `incident-correlation.js` mentions `computeSessionBaselineCandidates` only in a comment).

So "disposable cache" is safe because the loss is absorbed **inside each detector**, and the only downstream consumer sees the detector's ordinary cold-start/degraded output:

- **In-module cold-start (fail-closed) defaults, verified:** `canary-baseline.js:68,:123` (fresh state + lenient normalize both default `cold_start_pending`); `loadCanaryBaselineStore` distinctly surfaces `missing`/`corrupt` (`:156-158`) and `storeLossThisTick` is treated identically to a genuinely-read lenient store (`:559,:577-581`). Siblings mirror this exactly: `peer-baseline.js:126,:230`; `session-baseline.js:125,:204`; `process-lineage-baseline.js:41,:64`; `persistence-baseline.js:63,:85`; `service-baseline.js:104,:154`. Every path routes a missing/corrupt/unreadable store to a **persistent cold-start lockout** (positive `canary.tripped` remains observable; only fabricable *absence* claims are suppressed).
- **Downstream (`daemon.js`) tolerance:** disposal ⇒ the detector returns cold-start silence / no novelty ⇒ `daemon.js` sees an empty or reduced candidate list, which it already handles every tick. No consumer reads store internals, so no consumer can be "broken" by disposal.

### 6.3 Step-1 scope for C

A **doctrine/labeling affirmation + guardrail**, not a rewrite: (a) verify (and lock with a test) that **every** baseline-loss path routes to cold-start and **cannot** flip a read to a fabricated novelty/absence signal; (b) document the six stores as disposable caches derived from the fact-store, read only by their own `compute*BaselineCandidates`, with `daemon.js` as the sole downstream consumer of the candidates. **No test-pinned reversal originates in C** (nothing for §8). C is safe to land autonomously (Phase 2).

---

## 7. Component D — the honest `integrity_level: unprotected_same_uid` label

### 7.1 Where it surfaces

A **new**, additive, read-only field. **Verified: there is no existing `integrity_level` / `unprotected_same_uid` usage anywhere in `src/`.** Primary home: the **daemon status surface** — an installation **mode**, not a per-read property. The status writer is `writeDaemonStatus` (exported from `history-store.js`, called in `daemon.js`, e.g. `:691,:1293`); `daemon.js:319` is a comment about `readDaemonStatus`'s round-trip, not the writer. Optional mirror on `buildCompleteness` output. Make it an **enum with the future rungs named** so it is not a boolean in disguise:

```
integrity_level ∈ { "unprotected_same_uid", "protected_local", "witnessed", ... }   // step-1 value: "unprotected_same_uid"
```

Consulted by **no trust-decision code path** — exactly like `continuity_oldest_ts` (`fact-store-integrity.js:430-434`, "no trust-decision code path consults this field"), the rollout precedent for the additive-field-under-`deepEqual` test touch. **Verify** the daemon-status read/write path (`writeDaemonStatus`/`readDaemonStatus` in `history-store.js`) has no closed-key schema that would strip/reject the field; if one exists, the validator update is part of Phase 0.

### 7.2 Why it is autonomous-safe

It is **truthful, not a tamper-proof claim.** It **lowers** the implied assurance (states the mode is *unprotected*), so it can never over-claim or fabricate. Per the doctrine it is `reversibility × corroboration`-safe: a reversible label, notification-not-confirmation, that does not act. daybreak: "a small, high-integrity change we can make regardless."

### 7.3 Reversal status

No **test** flips for D (nothing pins the *absence* of the field). It is a **public-surface change** the operator should explicitly acknowledge (todo reversal #3) — carried in §8.3 as a surface-change ack. The literal introduced is `"unprotected_same_uid"`, **not** `status:"active"` (§10).

---

## 8. Test-pinned reversals — sign-off surface and avoided-reversal ledger (the consolidated "updated (d)")

### 8.1 Reversals requiring operator sign-off (THREE assertions)

| # | File:line | Current assertion | New assertion | Component |
|---|---|---|---|---|
| R1 | `test/fact-store-integrity.test.js:149` (test `:131` "buildCompleteness does not degrade an intact read for a future ledger loss timestamp") | `buildCompleteness(ledger, live, -Inf, {}, Date.parse(NOW)).status === "intact"` (future `last_corrupt_ts`) | `=== "degraded"` | B-tactical |
| R2 | `test/fact-store-integrity.test.js:180` (test `:157` "…treats a future continuity break… as a rollback artifact, not a permanent 'unknown'") | `buildCompleteness(...Date.parse(NOW)).status === "intact"` (future break, `continuity_ok:false`, live `ok`) | `=== "degraded"` (needs **both** removing the `:444-451` override **and** dropping the `:410` clause; override-only lands on `"unknown"`) | B-tactical |
| R4 | `test/canary-baseline.test.js:396` (test `:363` "manifest-gated: a canary removed from the current manifest produces no further trips") | `assert.deepEqual(decommissioned, [])` — a clean-deleted (`{canaries:[]}`, `read_ok:true`) established `credential` whose facts show a real `atime_advanced` trip | one `canary.tripped` candidate fires (`length === 1`, `trip_reason: "atime_advanced"`) | A1 |

**Titles at `:131`, `:157`, `:363` are reversed and must be renamed.** The Phase-3 guarded clamp additionally warrants a **net-new** test (acceptance #2b) — not a reversal (no current assertion pins the un-clamped retention behavior).

### 8.2 Reversals the NAIVE form of this plan would have flipped — AVOIDED by the corrected design (recorded, no sign-off)

These six assertions are **not** flipped by this plan. They are listed because the earlier draft's literal instructions (unconditional filter removal in A1; dropping `hasLossEventAfter:36` as "R3") **would** have flipped them, and a missed reversal here is the primary failure mode. The corrected design keeps every one of them green.

| File:line | Test | Current assertion | Would-flip cause (draft) | Why avoided (corrected) |
|---|---|---|---|---|
| `test/canary-baseline.test.js:838` | `:816` "[round-4] negative control: garbage id, trip-shaped facts under `////` → NO candidate" | `assert.deepEqual(candidates, [])` — genuine `atime 100→200` trip on stable-identity `////`, thrice sighted | Unconditional filter removal fires a `canary.tripped` for `canary_id "////"` | A1 keeps an **empty-key guard** `Boolean(sanitizeEntityKey(entry.canary_id))`; `sanitizeEntityKey("////") === undefined` ⇒ dropped ⇒ stays `[]` |
| `test/canary-baseline.test.js:1390` | `:1371` "rollback repairs a future anchor/watermark/**ledger loss ts**, resumes novelty" | recovers: `cold_start_pending===false`, novelty resumes | Dropping `hasLossEventAfter:36` ⇒ `factHistoryTrustworthy` `{trust:false}` on the injected future `last_corrupt_ts` ⇒ never re-accumulates | R3 withdrawn (§5.6); `:36` unchanged |
| `test/session-baseline.test.js:909` | `:896` "rollback repairs a future anchor and watermark, then persists re-established trust" | recovers / re-establishes trust | same as above (shared `factHistoryTrustworthy`) | R3 withdrawn; `:36` unchanged |
| `test/service-baseline.test.js:743` | `:729` "rollback repairs a future anchor and watermark…" | recovers / re-establishes trust | same | R3 withdrawn; `:36` unchanged |
| `test/peer-baseline.test.js:1070` | `:1057` "rollback repairs a future anchor and watermark…" | recovers / re-establishes trust | same | R3 withdrawn; `:36` unchanged |
| `test/process-lineage-baseline.test.js:375` | `:362` "rollback repairs a future anchor and watermark…" | recovers / re-establishes trust | same | R3 withdrawn; `:36` unchanged |

### 8.3 Additive test touches (NOT reversals) and assertions that keep passing but lose contrast

- **Kept-but-recontextualized (still pass):** `fact-store-integrity.test.js:152-154` (future loss, read **at** `futureLoss` → `"degraded"`) and `:184-187` (future break, read **at** `futureBreak` → `"degraded"`) still pass, but cease to be "controls contrasting with an intact read at NOW" (after R1/R2 both reads are `degraded`). Keep them; update comments. `fact-store-completeness.test.js:120-123` (in-window `currentLoss` → `{trust:false}`), `:124-128` (malformed ts → `{trust:false}`), and **`:116-119` (future loss → `{trust:true,"ok"}`, R3's would-have-target)** are all **unchanged and still meaningful** — R3 is withdrawn.
- **Additive fixture touches:** adding `integrity_level` to any `deepEqual`-compared daemon-status/completeness object (Component D) is an additive fixture update (follow the `continuity_oldest_ts` precedent). **No `loadCanaryManifest` `digest` fixture touch in Phase 1** — digest deferred to A2 (§4.3), so `canary-manifest.test.js:16/:24/:38/:51/:59/:67/:77/:101/:128` are untouched.
- **Canary negative controls — all stay `[]`/unchanged** (A1 un-suppresses only a *genuine, non-garbage* trip). Verified against the working tree:
  - `:838` — garbage `////` (genuine trip, garbage id): stays `[]` via the empty-key guard (§8.2).
  - `:862` (test `:845`, decommissioned **and gone**, no attribute change → no rawTrip), `:879` (`:865`, never-established), `:915` (`:889`), `:959` (`:943`), `:973` (`:964`, `points:[]`), `:1085` (`:1076`, no facts), `:1105` (`:1091`, unchanging `presence(1)/presence(2)` → no attribute diff → no rawTrip): all have **no genuine established-identity two-snapshot trip** → nothing to un-suppress → stay `[]`.
  - `:513/:547/:593/:633/:668/:709/:768` — isolated-entry trips already fire via `isolatedEntityKeys`; unchanged (a real canary_id sanitizes truthy, so the empty-key guard passes them).
- **Sweep/todo cross-refs `:749/:868/:995` do NOT flip.** In the current tree these fall inside a tamper-loop comment region (`:749`), a never-established-vanished body (`:868`), and a baseline-store-failure body that itself asserts a trip fires (`:995`) — none suppresses a genuine trip. **Among the sweep's listed canary refs, only `:363`/`:396` (R4) is a real reversal**; the corrected addition is `:838` (§8.2). (This corrects both the todo's grouping and the draft's §8.3 rationale for `:838`.)

### 8.4 Public-surface acknowledgement (Component D) — no test flips

Introducing `integrity_level: "unprotected_same_uid"` on the daemon status surface is a public-surface addition worth an explicit operator ack (todo reversal #3). No assertion reverses; additive fixture updates only.

---

## 9. Sequencing / phases (architecture-fixes-first)

- **Phase 0 — D (honest label).** Autonomous, zero behavioral risk: add the `integrity_level` enum to the daemon status surface (+ optional `buildCompleteness` mirror); verify no closed-key status validator (`history-store.js`'s `writeDaemonStatus`/`readDaemonStatus`) strips it. Additive fixture updates only.
- **Phase 1 — B-tactical (`buildCompleteness` read path) + A1 (filter→guard swap), the operator-gated reversals, as one TDD unit.** After sign-off: flip R1, R2, R4 first (write the failing expectations), then implement the two B read-path sub-fixes (§5.2) as one commit and the A1 empty-key-guard swap as another. Rename the reversed titles. **No change to `hasLossEventAfter` (§5.6), no retention clamp (§5.2 warning), no manifest digest (§4.3).**
- **Phase 2 — C (disposable-cache affirmation).** Autonomous: guardrail test locking every baseline-loss path to cold-start; document the six stores as caches read only by their own detectors with `daemon.js` the sole candidate consumer.
- **Phase 3 — B-ledger + the guarded clamp + A2 (durable substrate).** Add `boot_id` + the `clock_regression` channel; land the **guarded** retention clamp atop it (refuse to clamp on a same-boot backward step); add durable `trip_observed`/`retired` events + the `loadCanaryManifest` digest + `observed_manifest_digest` (A2, pending §12 open question 1). Expose counter+boot-id continuity as the shared primitive the LLM-budget slice reuses. No further operator-sign-off surface (no additional test reversals).

Each phase lands under review with the focused suites green (`node --test` on the touched files) before the next.

## 10. Invariants preserved

- **Never fabricate (cardinal).** `status:"intact"` reachable only by positive proof (sha256 committed-prefix digest with non-future continuity ordering — B); a `canary.tripped` reachable only by two completeness-proven snapshots + `minEstablishedCount` under a stable identity within `freshnessMs`, **and a non-empty sanitized id** (A1's retained guard — a garbage-sanitizing id can never emit a trip). Every corruption / retention / byte-cap / schema drop / manifest edit stays **observable and fail-closed**. Step 1 only moves reads fail-closed; the Phase-3 clamp is guarded specifically so it introduces no fail-open.
- **No new `status:"active"` string literal.** The source-grep guards at `test/constraint-store.test.js:765` (assertions `:774-775`, no `/["']active["']/` in `promoteDraftsToShadow`/`promoteShadowToReviewReady`) and `test/promotion-store.test.js:520-523` (no quoted `active` in `promotion-store.js` source) stay intact. Step 1 touches fact-store / canary / baseline / daemon-status code only; its sole new literal is `"unprotected_same_uid"` (an `integrity_level` value, **not** a status). No step-1 change is in a constraint-activation path.
- **Fail-closed everywhere.** Future/regressed clock → `degraded`/`unknown` in `buildCompleteness`; missing/invalid baseline → cold-start (silence); missing `boot_id` in a pre-migration ledger → degrade-not-crash; a clean-delete of a still-tripping canary → the trip surfaces + a retirement/tamper event, never silence; a garbage-id trip → dropped, never fabricated.
- **Attestation-gated authority untouched.** Step 1 raises **alerting** (the on-host ceiling), never authority. Recommend / sticky-adaptation / acting stay attestation-gated.
- **Byte-identical on-disk shape** for `facts.jsonl` and the atomic tmp+rename write discipline. Schema additions are confined to `integrity.json` (`boot_id`/continuity ledger, Phase 3) and additive fields (status `integrity_level`, Phase 0; A2's durable-event home an explicit open question, §12). `loadCanaryManifest`'s `read_ok:true` return shape is **unchanged in Phase 1** (digest deferred to A2).

## 11. Acceptance criteria

1. **R1, R2, R4 flipped and green; §8.2's six assertions stay green.** The three §8.1 assertions assert the new values (titles renamed); `canary-baseline.test.js:838`, `:1390`, and the four sibling rollback tests still pass unchanged, and `fact-store-completeness.test.js:110` still passes unchanged (R3 not shipped).
2a. **fact-store #3 read-path (Phase 1).** A future-dated ledger loss/continuity-break read at a pre-loss `now` resolves **`degraded`/`unknown`**, never `intact`, with **no clamp** in play; a store stuck degraded after a forward-clock retention pass recovers via delete-`integrity.json` → two clean passes (`:574`).
2b. **fact-store #3 guarded clamp (Phase 3, net-new test).** With B-ledger present: retention under a stepped-**forward** clock stamps a future loss; a later normal pass clamps it down (guard satisfied — monotonic, same boot) and it ages out. The **backward-step** attack (step clock back, run a tick, restore) does **NOT** clamp: it records `clock_regression` and the store stays **degraded**.
3. **B substrate (Phase 3).** A same-`boot_id` wall-`ts` regression across passes → `clock_regression` → `degraded` until aged; a **changed `boot_id`** (reboot) legitimizes a sequence reset → no false `degraded`. An explicit **suspend / `CLOCK_MONOTONIC`-pause** fixture passes (proving no monotonic-clock aging was reintroduced). A pre-migration ledger without `boot_id` degrades-not-crashes; the validator accepts the new field.
4. **Canary A1.** The clean-deleted established canary's genuine trip fires **once** (alertId-deduped, `trip_reason:"atime_advanced"`), freshness-bounded (`:278`) — it stops re-deriving within `freshnessMs` and resolves. All §8.3 negative controls (incl. the garbage-id `:838`) stay `[]`.
5. **Component C.** A guardrail test proves each of the six baseline loaders routes a missing/invalid/tampered store to cold-start (never a fabricated novelty/absence signal), and documents `daemon.js` as the sole downstream candidate consumer.
6. **Component D.** `descartes daemon status --json` reports `integrity_level: "unprotected_same_uid"`; consulted by no trust-decision path; `deepEqual` fixtures updated additively; no status validator strips it.
7. **Guards intact.** The two `status:"active"` source-grep guards and the fact-store BLOCKER #1/#2 input-guards still pass; `facts.jsonl` byte shape and `loadCanaryManifest`'s `read_ok:true` shape unchanged.
8. **daybreak re-gate.** A daybreak re-gate of the fact-store and positive-evidence-canary areas confirms fact-store #3 (buildCompleteness) and canary clean-delete are CLOSED (fail-closed, no new same-interplay residual — specifically that A1 introduced no garbage-id fabrication and B introduced no detector-blinding regression).

## 12. Out of scope / deferred

- **Full off-host / hardware attestation** (threat-model steps 3–6). Step 1 makes **no** root-resistance or tamper-proof claim; `integrity_level` stays `unprotected_same_uid` until those land.
- **Privilege separation** (`_descartes` service UID / minimal system daemon, closed typed RPC) — threat-model step 2.
- **The detector-facing future-loss trust gate** (`hasLossEventAfter` / `factHistoryTrustworthy` / the local `hasCompletenessLossAfterAnchor` duplicates) — deliberately unchanged in step 1 (§5.6); its correct hardening needs `boot_id` to distinguish a genuine future loss from a same-boot rollback, and belongs with B-ledger, not the read-path floor.
- **The LLM-budget clock class** (`todos/2026-09-06-llm-budget-trusted-time.md`) — shares Component B's counter+boot-id root and the reverted-`CLOCK_MONOTONIC` lesson; B-ledger should expose the shared primitive, but that slice's own design/tests are deferred there.
- **The other two "trusted-same-user-state" deferrals** — learned-promotion-tuning **F1** (file-authored `status:"active"` without the nonce path) and **F3/F7** (non-atomic authority writes / unbounded learned-store parse): require a trust anchor Descartes does not yet have and are **not** dissolvable as architecture bugs — they stay with the attestation / authority-store-locking owners.
- **Deferred store-hardening residuals** unrelated to step 1 (streaming reader, concurrent-writer locking, shadow-store copied NaN arithmetic) stay with their own slices.

### Open questions (for the operator / next planning pass)

1. **A2 event home** — fact-store new `fact_name` (completeness-gated, append-only) vs. canary baseline store (a §6 *disposable cache* — historical positive evidence must not live there). Resolve before A2; A1 (the sign-off surface) does not depend on it.
2. **macOS `boot_id` source** — `kern.bootsessionuuid` vs. hashing `kern.boottime`; verify on a real macOS host before B-ledger (Linux path `/proc/sys/kernel/random/boot_id`, CI-gated).
3. **`integrity_level` primary surface** — daemon status only, or also mirrored on every `buildCompleteness` read? (Plan proposes daemon-status primary + optional completeness mirror.)
4. **A2 durable-trip vs alert-store dedup** — whether to preserve first-seen `diagnostics` across dedup (`alert-store.js:287`) or carry the observed-manifest digest only on the durable event. Scoped to A2.

---

## Addendum: 2026-09-06 — grounded external review found a real R1/R2 gap (BEFORE implementing)

**→ 2026-09-06 (later): the required fixes below are now specified as a Phase-1 scope change — see the "Revision: R1 made signable" at the END of this doc.** It supersedes §5.2 (the clamp moves to Phase 1), §9 (Phase-1 scope), §11 items 2a/2b, and sharpens §5.6 point 5 (R1 — not R3 — causes the fail-STUCK suppression), and it surfaces **two operator design calls**: the clamp's clock-attacker scope (recommend: ship unguarded in Phase 1) and a `canary.tampered` rule-sharing call (recommend: cover wholesale).

Three independent code-grounded reviewers (`gpt-6-astra` ×2 + Fable 5.1, one with patched-copy simulations) reviewed the sign-off surface. Full findings: **`docs/reviews/2026-09-06-trusted-state-step1-grounded-review.md`**. Headline corrections to this plan, to apply before Phase 1 is implemented:

- **R1/R2 are NOT a cosmetic read-path relabel.** `buildCompleteness → "degraded"` propagates through `factHistoryTrustworthy` (`fact-store-completeness.js:66/:73`, which gates on the *status* before `hasLossEventAfter`) and **suppresses every completeness-gated detector** (service/session/peer/process-lineage/mining; positive canary trips excepted, `canary-baseline.js:637`). Because loss markers are ledger *fields* (not age-evictable records), a **far-future** marker holds the store `degraded` with **no fixed recovery bound** (permanent for unwindowed mining, `constraint-miner.js:366`). Fable demonstrated a **+364-day** blind from one forward-clock retention tick. **§5.6 point 5 is wrong** to pin the blinding on R3 alone — R1 causes the identical fail-STUCK shape via the status gate; rewrite §5.6's rationale (the real reasons R3 stays withdrawn are the anchor-relative re-establishment gate + the local `:95-106` duplicates, not the DoS argument).
- **The §5.2 Phase-1 recovery is an escape hatch, not closure** — its cited test (`:574`) is a brand-new store; the path is **undiscoverable** (`learned status` strips the loss-ts fields and reads unwindowed) and **does not cover the realistic event** (a forward-clock tick also writes future-dated *facts* → `observeFactContinuity` returns `unknown` forever; delete-`integrity.json` does not recover). **Stop calling the DoS "avoided."**
- **New interaction to close (never-fabricate):** a suppressed detector's `[]` can flip an active alert to `"recovered"` (`daemon.js:745` → `alert-store.js:303`) — mechanism confirmed; triggering depends on `coveredRuleIds` (F1) scoping and **must be settled by a real-path test**.
- **Before R1 sign-off, add to Phase 1:** (1) a **bounded blind** (retention-time clamp of forward-dated `last_*_ts` to `nowIso`, after fixing the future-*fact* wedge first — the §5.2 "naive clamp is a new fail-open" claim is overstated since `:360-363` already overwrites markers under a stepped-back clock); (2) **surfacing** (`degraded_reason`/`future_loss_fields` on completeness + a daemon-status line; `learned status` windowed + not stripping loss-ts); (3) a **real-path regression test** (real `readFactPoints`, no `intactReadResult`) asserting bounded recovery AND no fabricated alert recovery.
- **Verdicts:** R4 ✅, D ✅ (fix acceptance #6 — target `daemonServiceStatus`, not the unread `daemon-status.json`), **R2 ✅ as a no-op/dead-code removal** (byte-identical to R1-only), **R1 conditional** on the three items above. The operator decision surface (`todos/2026-09-06-trusted-state-step1-operator-signoff.md`) is updated to match.

---

## Revision: 2026-09-06 — R1 made signable (Phase-1 scope change)

**Trigger:** `docs/reviews/2026-09-06-trusted-state-step1-grounded-review.md` (three independent code-grounded reviewers). R1 (B-tactical, §5.2) is doctrinally correct but, unmodified, propagates through `factHistoryTrustworthy` (`fact-store-completeness.js:66,73` — both branches gate on `completeness.status === "degraded"` **before** `hasLossEventAfter` is consulted, verified) into an unbounded suppression of every history-dependent detector, with an undiscoverable, incomplete recovery path. This revision folds the review's three required fixes into **Phase 1**, in the order the wedge forces, so R1 ships as one signable unit alongside R2/R4/D. It **supersedes** §5.2's clamp deferral, §9's Phase-1 scope line, and §11 items 2a/2b (pointers below) and sharpens §5.6 point 5.

**Adversarial verification note (2026-09-06):** this revision was independently re-verified line-by-line against the working tree before sign-off. Two real gaps were found and are folded in below rather than left implicit: (1) Fix 3's alert-non-fabrication fix, as originally scoped, patched only ONE of daemon.js's TWO alert-persisting call sites — the unpatched second (containment) call runs unconditionally on every tick and would independently reproduce the fabricated-recovery bug regardless of the first fix; both are now in scope. (2) `canary.tampered`'s rule_id is shared between a history-gated reason (`canary_vanished`) and two non-history-gated reasons, and was silently omitted from the history-dependent rule_id set; this is now an explicit operator decision (open_decisions) rather than a silent gap. One citation error (which branch of `buildCompleteness` the future-fact wedge actually reaches) is corrected in Fix 0 below; the substantive dependency claim it supported was already correct.

**Ordering is load-bearing and is fix (0) → (1) → (2) → (3), not a checklist.** Fix (1)'s clamp only touches ledger loss-timestamp fields (`last_corrupt_ts`, `last_schema_invalid_ts`, `last_bytecap_evict_ts`, `last_continuity_break_ts`, `first_degraded_ts`); it never touches the continuity-*ordering* field (`last_rewrite_newest_ts`) that fix (0) repairs. A store already wedged to `"unknown"` by a future-dated **fact** (not a loss marker) sits outside every one of fix (1)'s clamped fields. Verified precisely: for this wedge, `observeFactContinuity`'s append-advance branch (`fact-store-integrity.js:252-256`) returns `"unknown"` (not `"broken"`) because the live newest timestamp — still dominated by the on-disk future fact — never exceeds the ledger's already-poisoned `last_rewrite_newest_ts`. `buildCompleteness` then takes its **second** branch (`continuityObservation === "unknown"`, lines 437-467, return statement at `:453`) — **not** the first branch (`continuityObservation === "broken"`, lines 417-435, a different, hardcoded-`"unknown"` path that this wedge never reaches). Either way, the loss-channel array at `:469-474` is never evaluated for this read, so a clamp of any degree of rigor over the loss-timestamp fields is inert against this wedge — the dependency is real, it just doesn't run through the `:417-435` branch a looser reading of the code might suggest. Fix (0) must land first because it is a **precondition for observability**, not because of a specific guard-implementation dependency (see fix (1)'s residual note for why the literal "`nowIso >= last_rewrite_newest_ts`" framing doesn't survive contact with the chosen Phase-1 design).

---

### Fix 0 (FIRST) — the future-fact continuity wedge (pre-existing HIGH, independent of R1)

**Verified mechanism.** A forward-clock tick writes future-dated *facts* via `daemon.js:616` → `appendFactPoints` (`fact-store.js:333`), which unconditionally calls `enforceFactRetention` (`:349-350`) on every invocation. The future record becomes `outputNewestTs`/`ledger.continuity.last_rewrite_newest_ts` (`fact-store-integrity.js:366-370`, `newestTimestamp` at `:211-216` has no upper bound). On a **later** append-triggering pass (once a genuinely new real fact is appended), `observeFactContinuity`'s append-advance branch (`fact-store-integrity.js:252-256`) compares the live newest (still the same future value — nothing real exceeds it, since the poisoned future fact is still on disk) against that same poisoned `expectedNewest`; `<=` holds, so it returns `"unknown"` — **every appending tick thereafter**, until real wall time exceeds the future stamp or a fix lands. `buildCompleteness`'s second branch (`:437-467`, return at `:453`) is reached before the loss array, so `history_unknown` results (`fact-store-completeness.js:47/51/60-62`), and `constraint-miner.js:366`'s default unwindowed mining sees zero candidates for the whole span. Deleting `integrity.json` does **not** recover this (confirmed by the review's simulation): a fresh ledger still observes the same poisoned `live.newest_ts` against its own newly-bootstrapped baseline the next time a future record is present on disk — the fact itself, not just the ledger, carries the poison, and `enforceFactRetention` never drops the record today (age-eviction only evicts by `tsMs < cutoff`, never touches a future `tsMs` — verified, `fact-store.js:251`).

**Fix (write path, `enforceFactRetention`, `fact-store.js`):** treat a fact whose `ts` exceeds `nowMs + tol` as untrustworthy provenance for continuity purposes — structurally the same class of problem the code already solves for corrupt/schema-invalid records — and apply the **identical idiom**: drop it from `candidates`/`outputRecords` (so it can never contaminate `last_rewrite_newest_ts`), count it in a new `future_fact_count`, and stamp `last_continuity_break_ts`'s sibling `last_future_fact_ts = nowIso` (real, current wall time — never the record's own claimed future ts) at the point mirroring `:360-363`. Extend the sum-invariant at `:274` (`kept + ageEvicted + bytecapEvicted !== validRecords.length` throw) to include the new evicted class. Thread `future_fact_count`/`future_fact_dropped_total` through `prepareFactIntegrityLedger`'s existing delta/saturating-total machinery (mirrors `corrupt_count` exactly, `:325-364`) and add `future_fact_dropped_total`/`last_future_fact_ts` to the ledger schema — additive fields, same precedent as `continuity_oldest_ts`; a pre-migration ledger lacking them degrades-not-crashes (bootstrap them, matching the `boot_id` migration discipline already specified for Phase 3 in §5.3, pulled one phase earlier for this one field). Fold `last_future_fact_ts` into the **same** degraded-array evaluation at `:469-474` (one more `lossAtOrAfter` term) — a future-fact anomaly now degrades honestly instead of wedging to `unknown`.

`tol` should be generous (hours, not minutes — enough to absorb NTP resync jitter, DST edge cases, and post-suspend catch-up) and is an **engineering default**, not an operator sign-off item; it does not appear in `open_decisions`.

**Recovery shape this produces (pin in the fix-3 test):**
- **A fresh incident, post-fix:** the future fact is evicted the same append-pass it lands on; `last_rewrite_newest_ts` is never contaminated, so there is **no wedge at all** — the store degrades immediately (via `last_future_fact_ts`) via `buildCompleteness`'s loss-array branch, exactly like any other loss channel.
- **A pre-existing (pre-fix) wedged ledger being migrated:** verified by tracing the transitional pass precisely — its `live` object (read from disk *before* this pass's rewrite) still contains the on-disk future fact, so `observeFactContinuity` still compares against the poisoned `expectedNewest` and returns `"unknown"` for that **one** pass; but that pass's own *output* (post-fix-0 eviction) is future-fact-free, so its committed `last_rewrite_newest_ts` is clean, and the **following** append-pass — and any read performed after this transitional pass completes, even with no further append — observes cleanly. One wedged pass, then resolved — not permanent.
- **A quiet daemon** (no new structural facts) runs no retention pass at all (`daemon.js:602`, `factPoints.length > 0` gates the call) — no channel in this design (old or new) ages out except across **append-triggering passes**, not wall-clock ticks. State this explicitly in the surfacing (fix 2) and the test (fix 3): "N passes" always means append-triggering retention passes, and separately, "ages out" for a WINDOWED read additionally requires that read's own `asOfMs` to advance past the marker plus the window (see fix 3's test-shape note below — pass count and read-time advancement are two different things and must not be conflated).
- **`descartes learned mine`'s default (no `--window`) invocation is a structurally different case, not fixed by this revision:** `readFactPoints` with no `windowMs` sets `asOfMs = Number.NEGATIVE_INFINITY` (`fact-store.js:404-407`), under which `lossAtOrAfter`/`hasLossEventAfter`-style checks have **no upper age bound** — any non-null loss timestamp, including the new `last_future_fact_ts` once resolved to a real past value, keeps that call's completeness `"degraded"` **forever**, exactly as every other pre-existing loss channel already does for unwindowed reads today. This is unrelated to R1 and this fix does not change it. State this plainly rather than implying unwindowed mining "ages out" — see the corrected Acceptance #9 below.

---

### Fix 1 — bounded blind: retention-time clamp in `prepareFactIntegrityLedger` (Phase 1, not Phase 3)

Pull the clamp forward from Phase 3 (superseding §5.2/§9/§11 below): on each pass, before `:360-363` stamps this pass's own fresh deltas, any of `last_corrupt_ts`, `last_schema_invalid_ts`, `last_bytecap_evict_ts`, `last_continuity_break_ts`, `first_degraded_ts` (and the new `last_future_fact_ts` from fix 0) that is **forward of `nowIso`** is pulled down to `nowIso`. This turns an unbounded fail-STUCK blind (the far-future-marker case the review measured at +364 days and growing) into a **bounded, one-window** blind for the case that actually matters day to day: an accidental forward-clock excursion (NTP glitch, misconfigured VM clock, DST/timezone bug) that is later corrected. (`first_degraded_ts` is not itself consulted by the loss array at `:469-474` — clamping it is cosmetic/audit-trail-only and carries no trust-decision consequence either way.)

**§5.2's "naive clamp is a NEW fail-open" warning, addressed honestly, not hand-waved.** The attack: a genuine loss is stamped with a real, recent `nowIso`; the same-uid attacker steps the *system* clock backward (e.g. to 1990); one retention tick runs (trivial — same-uid write access can always inject one fact); from that tick's (fake) vantage point the genuine marker now looks "forward-dated" relative to the fake `nowIso`, so the clamp rewrites it down to 1990; the attacker restores the real clock; `lossAtOrAfter(1990, recentWindow, realNow)` is false forever after — the loss is erased, not merely blinded.

**Why a wall-clock-only "backward-step" guard cannot close this in Phase 1 (verified by construction, not asserted).** Any guard of the shape "refuse to clamp when this pass's `nowIso` is lower than a previously-recorded ledger high-water-mark" is **poisoned by the exact excursion the clamp exists to fix**: a genuine forward-clock glitch first writes its own bad, high `nowIso` into whatever field tracks that high-water-mark (nothing about a wall-clock excursion looks anomalous to a wall-clock-only observer at the moment it happens); the *correction* back to real time is then, by construction, indistinguishable from an attacker's rollback — both are "this pass's `nowIso` is lower than a value already recorded." Breaking that symmetry requires an out-of-band signal uncorrelated with the wall clock — exactly what `boot_id` (Phase 3, §5.3) is for. **No Phase-1 wall-clock-only guard is real; specify none that pretends otherwise.** A friction-only guard (e.g. "require the forward-dated value to persist across ≥2 consecutive passes before it's clamp-eligible") was considered and is **not recommended**: a same-uid attacker forces two ticks as trivially as one, and it delays the legitimate/common recovery case for no real security gain — complexity that buys false confidence, not safety.

**The residual, stated precisely (this is the marginal capability, not a new attacker class):** the same-uid, clock-controlling attacker already has an equivalent capability today, gated on manufacturing a coincident fresh corrupt/schema-invalid/continuity-break delta on the same rolled-back tick (`fact-store-integrity.js:360-363`, unconditional overwrite of `last_*_ts = nowIso` whenever that channel's delta count is `> 0` this pass). The unguarded Phase-1 clamp removes that coincidence requirement — it fires on **any** pass, against an **already-recorded** marker, without needing a fresh delta this tick. That is the entire marginal widening: one fewer step, for the identical, already-accepted attacker (§3: "Nothing here claims tamper-proofing... a same-uid attacker is defeated"). It is not "not strictly worse" unconditionally — it is not strictly worse **for that specific, already-out-of-scope attacker class**, and it is a strict improvement for the far more common non-adversarial case this step actually targets.

**Operator design call (surfaced to `open_decisions`):** accept this residual and ship the clamp unguarded against a deliberate same-uid clock-control attacker in Phase 1 (**recommended** — see rationale above and in `open_decisions`), versus withholding the clamp entirely until Phase 3's `boot_id` can implement a guard with real teeth (leaving the accidental-forward-clock case unbounded-until-manual-intervention in the interim, which is exactly the trade-off §5.6 point 5 calls "strictly worse").

---

### Fix 2 — surfacing (additive, no trust-decision path touched)

- **`buildCompleteness` (`fact-store-integrity.js`, all three return sites — verified `:418`, `:453`, `:475`, the exact `return {` lines of the broken / unknown / degraded-or-intact branches respectively):** add `degraded_reason` (enum: `this_read_loss | in_window_loss | future_loss | continuity_break | continuity_unknown | future_fact | none`) and `future_loss_fields` (the subset of `last_*_ts` field names, including the new `last_future_fact_ts`, whose parsed value is `> nowMs`). Same shape on every branch — a `deepEqual` fixture diff across branches is the signal this was done inconsistently.
- **`selectFactStoreCompleteness` (`constraint-store.js:316-331`, verified it currently omits `last_corrupt_ts`/`last_schema_invalid_ts`/`last_continuity_break_ts` from its allow-list):** stop stripping those three fields, add `last_future_fact_ts`, `degraded_reason`, `future_loss_fields`.
- **`readFactStoreCompleteness` (`constraint-store.js:333-340`, verified it calls `readFactPoints(descartesPaths)` with **no** `windowMs`, so `buildCompleteness`'s `asOfMs` defaults to `Number.NEGATIVE_INFINITY` at `fact-store.js:404` — meaning `learned status` today reports "degraded" for *any* loss ever recorded, with no way to tell "just happened" from "years ago, long since aged out for every real detector"):** pass **`windowMs: DEFAULT_BASELINE_FACT_WINDOW_MS`** (`welford-stats.js`, 31 days) — verified this is the constant the completeness-gated baseline families (session/service/peer-baseline, and by the identical pattern process-lineage/persistence-baseline) resolve for their own `readFactPoints` calls (`options.baselineFactWindowMs ?? DEFAULT_BASELINE_FACT_WINDOW_MS`), so `learned status` reports what the detectors actually see by default. Residual: a detector invoked with a non-default `baselineFactWindowMs` override will still diverge from this fixed surface — acceptable (a diagnostic surface, not a trust decision), but state it in the CLI help text rather than implying exact per-detector parity. **And** still print the raw `last_*_ts` fields plus `future_loss_fields` alongside the windowed status, so an out-of-window or future-dated loss stays visible even when the windowed status itself reads `intact`. Windowing alone hides old losses from view; surfacing alone leaves the windowed status meaningless as a signal. Both are required.
- **Daemon status record (`daemon.js:679-690`, verified this is an unconditional plain-object literal built with `...(x ? {...} : {})` additive spreads, no closed-key schema):** add a `fact_store_completeness` line via the same idiom, sourced from **one** `readFactPoints` call this tick (shared with fix 3's alert-scoping check below — no second file read needed). `writeDaemonStatus`/`readDaemonStatus` (`history-store.js:267-290`, verified: plain object spread, no validator) pass it through untouched.
- **Correct the Addendum's Component-D surface note while here:** `fact_store_completeness` lands in `daemon-status.json`, which `daemonServiceStatus` (`daemon.js:1038-1051`, verified it reads only `spec.install_path` via `readFileIfPresent`, never `daemon-status.json`) does not read — same surface mismatch already flagged for `integrity_level` (acceptance #6). The CLI-visible surfaces for both fields are `descartes learned status` (fixed above) and the `history`/`triage` code paths that do read the status record — not `descartes daemon status --json`.

---

### Fix 3 — a real-path regression test, AND a required code fix it exposes (not test-only)

**The alert-fabrication interaction is confirmed live, not hypothetical — and confirmed to have TWO independent trigger points, not one.** `daemon.js` calls `evaluateAndPersistAlerts` **twice every normal tick**, and both calls omit `coveredRuleIds`:
1. The main call (`:752-761`) — `evaluateAndPersistAlerts(descartesPaths, { now, daemonStatus, windowMs, extraCandidates: mainExtraCandidates })`.
2. The containment call (`:775-781`) — runs unconditionally whenever the first one produced a result (`if (mainAlerts) { ... }`, true on every normal tick), re-merging `[...mainAlerts.candidates, ...mainExtraCandidates, ...containmentCandidates]`. Its result (`containmentAlerts`) becomes the tick's **final** persisted `alerts` (`:782-790`, `alerts = { ...containmentAlerts, ... }`).

`alert-store.js:272` defaults `coveredRuleIds` to `undefined` in **both** calls (they share the same `evaluateAlerts` → `applyAlertCandidates` path), so `isCovered` at `:302` is **always true** in both. Any active/acknowledged alert whose `rule_id` is absent from a call's merged candidates — which is exactly what a suppressed history-dependent detector produces (`[]`) — **will** flip to `"recovered"` (`:303-309`) on that call. Patching only the first call is insufficient: the second, unconditional containment call independently reproduces the identical bug regardless of what the first call decided, since it computes its own `isCovered` from its own (also-`undefined`) `coveredRuleIds`. This Phase-1 unit must patch **both** call sites, not one, or the fix does not close the gap it claims to close.

**Required code change:** in `daemon.js`, when this tick's fact-history is untrustworthy (reuse the single `factHistoryTrustworthy`/completeness read fix 2 already needs), compute the restricted `coveredRuleIds` **once** — `FIXED_ALERT_RULE_IDS` (`alert-store.js:64`, precedent already established for the CLI's read-only view at `alerts.js:311`) plus the rule_ids of detector families that do **not** gate on `factHistoryTrustworthy` this tick — and pass the **identical** value to **both** `evaluateAndPersistAlerts` calls (`:752-761` and `:775-781`). Enumerate the families that **do** gate on it (verified by direct read of each file, not grep alone): `canary-baseline.js` (non-trip paths only — `:575/:585`, `coldStartPendingThisTick` driven by `!historyTrust.trust`; R4/A1 already exempts genuine trips from the completeness lockout), `incident-correlation.js` (`:319`), `peer-baseline.js` (`:761`), `persistence-baseline.js` (`:316`), `process-lineage-baseline.js` (`:356`), `service-baseline.js` (`:520`, `:876`), `session-baseline.js` (`:679`) — and collect their alert-emitting rule_id constants into one exported set, e.g. `HISTORY_DEPENDENT_ALERT_RULE_IDS`: `SERVICE_DISAPPEARED_RULE_ID`/`SERVICE_APPEARED_RULE_ID` (service-baseline.js), `SESSION_COUNT_DROP_RULE_ID`/`SESSION_CHURN_RULE_ID` (session-baseline.js), `PEER_COUNT_SPIKE_RULE_ID`/`PEER_COUNT_DROP_RULE_ID` (peer-baseline.js), `PROCESS_LINEAGE_NOVEL_EDGE_RULE_ID` (process-lineage-baseline.js), `SCHEDULED_JOB_APPEARED_RULE_ID` (persistence-baseline.js), `CORRELATION_RULE_ID` (incident-correlation.js). Exclude that set from `coveredRuleIds` (both calls) whenever history is untrustworthy this tick — those alerts freeze in place (no recovery, no new fires beyond what the detector itself already gates) instead of being silently marked recovered.

**`canary.tampered` is a separate, unresolved case — see `open_decisions`, do not silently omit it.** `CANARY_TAMPERED_RULE_ID` (`canary-baseline.js:38`) is shared between the one history-gated canary output (`canary_vanished`, gated the same way as the families above) and two non-history-gated tamper reasons (`manifest_unreadable`, isolated entity — both explicitly ungated by `coldStartPendingThisTick` in the source). Including it wholesale in `HISTORY_DEPENDENT_ALERT_RULE_IDS` freezes those two legitimate reasons too during a history-degraded tick (fail-stuck, bounded, acceptable per doctrine); excluding it leaves `canary_vanished`'s own fabricated-recovery gap open. This revision recommends **including** it (see `open_decisions`) but does not silently decide it.

**Stated residual (don't hide it):** this closes the R1-induced case, where the `:66/:73` status gate fails *every* history-dependent family together regardless of anchor. A pre-existing, narrower case — a single detector's own `hasCompletenessLossAfterAnchor`/anchor-specific suppression (unrelated to R1, §5.6) recovering an alert while that one detector alone is blind — is not closed by this fix and stays open, tracked with B-ledger (§5.3/§12) where `boot_id` can eventually scope recovery per-detector rather than per-tick.

**Test shape (real-path, no `intactReadResult` mock, split across two levels):**
1. **Store level** (`fact-store.test.js`, real `appendFactPoints`/`readFactPoints`): a forward-clock append-pass writes a routine loss (a corrupt line) and a future-dated fact in the same tick → restore the clock → assert `status: "degraded"`, `degraded_reason` naming the future channel(s), `future_loss_fields` non-empty, `factHistoryTrustworthy(...).reason === "history_degraded"`. Then, **decoupling pass-count from read-time advancement (do not conflate the two):** one further append-triggering pass after clock restoration is what makes the clamp fire, pulling the marker down to that pass's real `nowIso` (2 append-triggering passes total from incident start to "clamped and bounded"); **separately**, assert `status: "intact"` only once a subsequent **windowed read**'s `asOfMs` (i.e. `now - windowMs` at read time, simulated via `options.now`) has advanced **past** `clampedTimestamp + windowMs` — this is a wall-clock/read-time condition, not something further append passes alone satisfy. Also assert the fix-0 case: a future-fact-only incident never produces `status: "unknown"` on the very next append-pass (confirming no wedge), only the pre-existing-ledger migration case does, bounded to exactly one pass. Also assert, for the CLI's unwindowed path (no `windowMs`), that `status` stays `"degraded"` indefinitely across further passes with no ledger reset — pinning the honest (not overstated) unwindowed-mining behavior below.
2. **Alert level, driving daemon.js's real two-phase tick** (via `runDaemonIteration`, `daemon.js:482`, or by explicitly issuing both calls in the same shape daemon.js does — a test built around a single direct `evaluateAndPersistAlerts` call does **not** exercise the containment call and must not be treated as sufficient): an existing active alert for a history-dependent rule_id, then a tick where that detector is suppressed (untrustworthy history) → assert the alert's `status` is **unchanged** (still `"active"`/`"acknowledged"`) **after both the main and containment phases have run**, never `"recovered"` — this assertion fails without the `coveredRuleIds` code fix applied to **both** call sites, and is the test that proves it. Add a parallel case for `canary.tampered`/`canary_vanished` matching whichever `open_decisions` resolution is taken.

---

### §11 Acceptance — additions (append; does not remove existing items)

9. **Future-fact wedge (fix 0).** A future-dated *fact* never produces a permanent `history_unknown`: a fresh incident resolves `degraded` (via `last_future_fact_ts`) on the same pass it occurs, and — for a **windowed** read — ages out once that read's `asOfMs` advances past the marker plus the window; a pre-existing wedged ledger migrated onto this fix resolves within exactly one transitional append-pass. **Corrected from the draft:** `constraint-miner.js`'s **default, unwindowed** invocation (`descartes learned mine` with no `--window`, `asOfMs = Number.NEGATIVE_INFINITY`) does **not** age out under this fix or any other loss channel — that is a pre-existing, structural property of unwindowed reads (no upper age bound in `lossAtOrAfter`), unrelated to and unchanged by this revision; its only recovery path remains an `integrity.json` reset, exactly as for any other loss type today. This fix's contribution for that invocation is observability (`degraded_reason`/`future_loss_fields` now show *why*, via fix 2) and non-worsening (the wedge no longer produces an opaque, unattributable `"unknown"` first) — not self-recovery.
10. **Bounded clamp (fix 1, Phase 1 — supersedes old 2b's Phase-3-only framing).** A genuine loss/break/future-fact marker stamped under a forward-clock excursion is clamped to `nowIso` on the next append-triggering pass and ages out, for **windowed** reads, once that read's `asOfMs` advances past the clamped timestamp plus the retention window once the clock is corrected — bounded to one window, not permanent. The unguarded-vs-deliberate-attacker residual (§ fix 1) is documented, not silently accepted.
11. **Surfacing (fix 2).** `buildCompleteness`'s `degraded_reason`/`future_loss_fields` are present and consistent across all three return branches; `learned status` reports a status windowed at `DEFAULT_BASELINE_FACT_WINDOW_MS` plus the raw loss-ts fields and `future_loss_fields`; the daemon status record carries `fact_store_completeness`; no field is stripped by `selectFactStoreCompleteness`; no closed-key validator rejects the new daemon-status field.
12. **No fabricated recovery (fix 3).** A suppressed history-dependent detector's absent candidate does **not** flip an existing active/acknowledged alert for that family to `"recovered"` — enforced by `daemon.js` scoping `coveredRuleIds` away from `HISTORY_DEPENDENT_ALERT_RULE_IDS` at **both** its `evaluateAndPersistAlerts` call sites (main `:752-761` and containment `:775-781`) whenever this tick's fact-history is untrustworthy, and pinned by a real-path test that exercises daemon.js's actual two-phase tick (not a single direct call), not a mock. The `canary.tampered`/`canary_vanished` case is covered per whichever `open_decisions` resolution is taken, and that resolution is recorded here once made — it is not assumed closed by default.

**With this revision, R1 is signable as ONE Phase-1 unit** (fixes 0–3 land together, TDD-first per §9's existing discipline: write the failing expectations for fixes 0/1/3, then implement) **alongside R2 (no-op given R1) and R4/D (unchanged, already clean).** The escape-hatch framing ("Phase-1 recovery" = delete `integrity.json`) is retired as the primary recovery path for **windowed** consumers — it remains true and harmless as a break-glass fallback for a genuinely-corrupted ledger, and remains the **only** recovery path for the CLI's unwindowed `learned mine` invocation (pre-existing, unrelated to R1) — the clamp + fix-0 wedge repair close R1's DoS gap for every windowed (i.e. real detector) consumer.