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
