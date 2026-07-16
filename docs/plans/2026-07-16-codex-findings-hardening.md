# Codex-findings hardening — collector/eval honesty (remaining deferred findings)

**Created:** 2026-07-16
**Reviewed:** 2026-07-16 (adversarial design review, Sonnet subagent — 2 must-fixes + 5 should-fixes/nits folded)
**Status:** REVIEWED — ready to implement
**Tracking todo:** `todos/2026-07-09-self-learning-stratified-monitoring.md` (Codex disposition, lines 69–75)
**Source review:** `docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`

## Context

Codex's external review (2026-07-11) left four findings filed under "real, larger/architectural —
deferred". Finding #1 (approval non-atomicity / spot C) shipped 2026-07-16 (`9264173`:
`reconcileOrphanedPendings`). This plan covers the remaining three, re-scoped after mapping the
*actual* current code (which differs materially from the findings' shorthand):

- **A — multi-owner port attribution.** The shorthand "first-PID-wins" is not literally the
  mechanism: Linux `ss` is invoked without `-p` (no PID/owner captured at all); macOS `lsof` *can*
  emit multiple `LISTEN` lines for one port. The real defect is downstream in
  `shadow-store.js:buildShadowFactLookup` (201–216): its `>=` latest-wins tie-break **silently
  collapses two same-`entity_key` fact points that carry *different* `owner` values at the same
  tick into whichever was processed last**, discarding the other with no ambiguity signal. The live
  active-constraint eval then reads only that one value — a conflicting second owner (SO_REUSEPORT
  same-address distinct binaries) is invisible, so a genuine violation can be masked or a satisfy
  spuriously granted. (Dual-stack v4/v6 already produce *distinct* entity_keys — different
  `local_address` — so they are not the collapse case; the residual case is same-address multi-owner.)

- **B — presence-fact staleness (disappearance invisibility).** `buildShadowFactLookup` keeps the
  latest value with **no expiry**. A service (or port) that stops being observed keeps resolving to
  its last `running:"true"` / owner value for up to the 30-day fact-retention window. A mined
  "service X running" constraint therefore reads *still satisfied* long after X vanished — a
  false-negative worse than a bare "no claim". (Note: `systemctl list-units --all` already emits
  `running:"false"` for a *loaded-but-stopped* unit, so the crash/stop case is already caught; the
  gap is a *fully-unloaded* unit / unloaded launchd job, plus the eval-side stale-true masquerade.)

- **C — service census / absence representability.** There is no service-presence census marker
  (sessions have `SESSION_CENSUS_MARKER_ENTITY_KEY`; services have no analogue), so "the services
  collector ran this tick and X was NOT in the set" is unrepresentable — a prerequisite for any
  future absence-diff/alerting.

- **D — Linux FD-scan bound (Rust root-helper).** The per-pid `/proc/<pid>/fd` scan is bounded only
  by a wall-clock *deadline that abandons but does not CANCEL* the in-flight scan, and there is no
  per-pid FD *count* cap — a pid with a pathological FD count can burn work past the deadline. This
  is Linux-only, in the privileged `descartes-root-helper` crate, and only exercised under the
  elevated Tart-VM CI step (this dev machine cannot run VMs). Design here; implement + verify under
  CI.

## Safety spine (unchanged, must hold for every slice)

Read-only agent; no privilege escalation; no LLM in any learned/collector module; single-writer
constraint activation via the human-gated authority nonce; whole learned subsystem default-OFF.
Every change below is **fail-safe = degrade to "no claim" / "skip", never fabricate a satisfy and
never fabricate a violation without fresh positive evidence.** No change may make a constraint fire
on absence *by default* (absence-alerting, if ever added, is a separate opt-in baseline slice).

---

## Slice A — surface same-tick multi-owner ambiguity (fail to skip, never silently pick)

**Change:** In `buildShadowFactLookup`, when two or more *distinct* values map to the same `target`
at the **same latest timestamp** (a genuine within-tick contradiction, since all facts from one
collector tick share that tick's `ts`), mark the target **ambiguous** and have the lookup return
`undefined` for it — so `evaluateConstraints` SKIPS it ("no unambiguous claim") instead of silently
reading last-processed. A later, strictly-newer tick that resolves to a single value clears the
ambiguity (newer observation legitimately supersedes; ambiguity is per-latest-ts, not sticky).

**Why this is safe:** returning `undefined` routes through the existing, audited "no fact, no claim
→ skip" path (`constraint-eval.js:110–125`). It can only ever *withhold* a satisfy/violation on
conflicting evidence — never invent one. The miner already refuses to mine contradictions
(`constraint-miner.js:200–201`), so this only tightens the *eval* side to match the miner's caution.

**Shape:** track per target `{ tsMs, value, ambiguous }`. On a strictly-newer ts → replace (not
ambiguous). On an equal ts with a differing value → set `ambiguous = true`. Lookup returns
`undefined` when `ambiguous`. Degraded-point exclusion (owner_known:"false"/confidence:0) stays
*before* this logic, unchanged.

**"Same ts = same tick" is a PROXY, not a guarantee** (review should-fix). There is no tick
identifier in a fact point; the live path threads one `ts` per `runDaemonIteration`, and
`tuning-store.js:bucketPointsByTick` independently treats exact-`ts`-string equality as "one tick".
Same-ts-different-value is therefore a *proxy* for within-tick contradiction — correct for every
real emission path, but a fixture/replay that manufactured two genuinely-distinct observations at an
identical `ts` would be misclassified as a contradiction. Add an explicit regression test locking
the proxy assumption; the plan claims it as a proxy, not a law.

**Observability (review should-fix): ambiguity must leave a trail, not silently vanish.** A real
same-tick multi-owner conflict (something new squatting on a port) is often the security-relevant
signal in its own right; today it fires 50/50 via last-processed-wins, and naive Slice A would make
it *always* silently skip — a regression in observability even as it fixes correctness. Every other
degrade-not-fabricate decision here leaves a trail (`census_state`, `owner_known:"false"`,
Slice D's `fd_scan_truncated`). So Slice A emits a cheap diagnostic signal (a counter / a
`confidence:0` ambiguity provenance marker fact, distinct from firing an alert) whenever it
suppresses a target for ambiguity, so an operator can see "N ambiguous targets skipped this tick".

**Tests (TDD):** two same-ts differing-owner points for one entity_key → lookup undefined (skipped)
+ diagnostic signal emitted; two same-ts *identical* values → not ambiguous (value returned, no
signal); a strictly-newer single value after an ambiguous tie → clears (newer value returned);
different entity_keys never interfere; a same-address SO_REUSEPORT-style pair end-to-end through
`evaluateConstraints` → the constraint is skipped, not fired/satisfied; the same-ts-proxy regression
test. Existing shadow/active parity tests must stay green (identical-value ties are the
overwhelmingly common real case and must be unaffected).

**Backtest interaction:** none — ambiguity is computed from the points themselves, no wall-clock.

**Second copy exists — explicitly DEFERRED (review should-fix).** `provenance-warnings.js:199-211`
(`reduceLatestProvenanceWarnings`) is a hand-reimplemented copy of the same `>=` latest-wins logic
feeding a *real* alert-candidate source (`computeProvenanceWarningCandidates`), not shadow-only. Its
collision surface is lower (its `entity_key` is `rule_id.identity`, so two different warning *types*
can't collide onto one key), but the same same-tick ambiguity class is structurally possible. This
plan does NOT fix it (keeping Slice A a single-function change); it is called out here so the audit
is honest and a follow-up can pick it up. Do not silently leave it as "handled".

---

## Slice B — eval-side freshness bound (stale fact ≠ live claim)

**Change:** Add an OPTIONAL freshness filter to `buildShadowFactLookup`:
`buildShadowFactLookup(factPoints, { now, freshnessMs } = {})`. When BOTH are provided, a target
whose latest contributing point is older than `now - freshnessMs` resolves to `undefined` (stale =
no live claim → eval skips). When omitted (the default, and every current caller including all
shadow backtests), behaviour is byte-identical to today — **no backtest may pass these options**, so
historical-window replay is untouched.

**Wire — MUST pin to the STRUCTURAL interval, not the fast tick (review must-fix #1).** The facts
this freshness bound governs (`service.presence`, `network.listening_port.owner`) are emitted
*exclusively* inside the `structuralDue` gate (`daemon.js:415,438–439`), which fires on
`profile.structural.interval_ms` (`DEFAULT_STRUCTURAL_INTERVAL_MS = 1h`, daemon.js:42). But the
active-constraint eval (`computeActiveConstraintCandidates`, daemon.js:351/505) runs on *every fast
tick* (`DEFAULT_DAEMON_INTERVAL_MS = 60s`, daemon.js:40). Therefore `freshnessMs` **must** derive
from `profile.structural.interval_ms` — a conservative **3×** (default **3h**) with a floor —
**never** `profile.interval_ms`. The only `interval_ms*3` precedent in the tree (`alert-store.js:72`,
`triage.js:62`) is keyed off the *fast* tick and is CORRECT there (metrics refresh every fast tick)
but would be CATASTROPHIC here: 3×60s = 180s would mark every structural fact stale for ~57 of every
60 minutes, destroying live violation detection. There is no pre-existing "session-presence 3×
window" (my earlier draft cited one that does not exist — removed). A test MUST assert the live
wiring reads the *structural* knob, not the fast-tick knob.

**Wire — the SHADOW-SOAK path suffers the identical bug and MUST also be fixed (review must-fix #2).**
`evaluateAndLogShadowConstraints` (shadow-store.js:242) calls `buildShadowFactLookup(points)` with no
options, so a `status:"shadow"` constraint being soaked toward promotion keeps reading a vanished
service's stale `running:"true"` as *satisfied* — it accumulates a clean "never fired" soak record
purely because its evidence went stale, gets promoted, and only *then* hits the live freshness filter
and immediately starts skipping. Leaving the soak path unfixed would let staleness *drive promotion*.
Fix: wire the SAME freshness bound into `evaluateAndLogShadowConstraints`. This is unambiguous there —
the shadow eval already runs INSIDE the `structuralDue` gate (daemon.js:475), so the structural
cadence is the natural, correct source. Both live-active and shadow-soak eval thus share one
freshness horizon; only true historical *backtests* (`tuning-store`/calibration replay) omit the
options and keep exact latest-wins.

**Companion (review nit): bound the read window too.** `computeActiveConstraintCandidates` reads the
*entire* retained fact-history every fast tick (`readFactPoints` with unbounded `windowMs`,
fact-store.js). Once `freshnessMs` exists, pass `factWindowMs = freshnessMs` (with margin) so the
read is bounded by the same horizon rather than scanning 30 days of history 1×/min.

**Why safe:** the freshness options are opt-in per call site; every existing caller that omits them
(all backtests) is byte-identical to today. The bound can only *withhold* a stale satisfy, never
fabricate. It skips (does not fire) on staleness — disappearance-*alerting* is explicitly NOT added
here (that is Slice C's census + a future opt-in baseline).

**Tests (TDD):** a fresh point within the window → value returned; a point older than `now -
freshnessMs` → undefined; boundary (exactly at the horizon); omitting the options → unchanged from
today (regression-lock the default); a backtest-style call (no options) over old points still
returns latest-wins; the live active tick AND the shadow-soak tick both pass the STRUCTURAL-derived
`freshnessMs` (assert the knob source); a disappeared service's constraint flips satisfied → skipped
after the horizon on BOTH the active and shadow paths; cross-slice: `ambiguous × stale` and
`ambiguous × fresh` both resolve to skip (A's `undefined` short-circuits before B's check).

---

## Slice C — service-presence census marker (make absence representable)

**Change:** Mirror `buildSessionCensusMarkerFactPoint`: on every successful services envelope emit
one `service.presence` fact at a reserved `SERVICE_CENSUS_MARKER_ENTITY_KEY`, `confidence:0`,
carrying `census_state` (`complete`/`partial` from per-manager collector status). This records "the
services collector ran this tick (and here is whether it was complete)", the prerequisite for a
future absence-diff. It does NOT itself alert on disappearance.

**Why safe (corrected — no cap mechanism is involved; review nit):** the service translator has NO
per-tick cap/overflow-marker machinery at the translator layer (unlike sessions' `SESSION_OVERFLOW`
path); service truncation happens silently upstream in the collector (`services.slice(0, limit)`).
The marker's protection is therefore SOLELY: (1) `confidence:0` → excluded by `isDegradedFactPoint`
(shadow-store.js:184) and by the miner's degrade exclusion (constraint-miner.js:48–49); AND (2) it
carries no `running` attribute, so `buildShadowFactLookup`'s `value === undefined` guard
(shadow-store.js:209–210) skips it regardless. Either alone suffices; together the marker can never
be mistaken for a presence claim or mined into a constraint. Do not claim a "cap exclusion" that
doesn't exist.

**Tests (TDD):** marker emitted on a non-empty tick, on a zero-service tick, and on a partial tick
(census_state:"partial"); marker excluded from fact-lookup and from mining; marker entity_key is
reserved/sanitized. NOTE (review nit): `test/fact-translators.test.js` asserts EXACT/sorted
`entity_key` lists from `factPointsFromServiceEvidence` (around lines 41 and 85) with no marker
present — adding the marker breaks BOTH of those exact-list assertions; they need explicit rework,
not just new fixtures appended.

**Deferred (documented, not in this plan):** the actual disappearance *alert* (diff expected-vs-seen
service set → fire on a service that left the census) is a new opt-in baseline slice analogous to
session-baseline; it consumes this marker + the freshness bound. Called out so the gap is explicit,
not silently "done".

---

## Slice D — Linux FD-scan work-bound (Rust, CI-gated) — DESIGN ONLY here

**Change (design):** In `descartes-root-helper`'s per-pid `/proc/<pid>/fd` scan: (1) add a per-pid
FD *count* cap (stop enumerating a single pid's fds past N, record `fd_scan_truncated:true` rather
than scanning unboundedly); (2) make the deadline **CANCEL** the in-flight scan (cooperative
cancellation checked between fds / directory-read batches), not merely abandon the awaited result
while the work continues. Emit an explicit `fd_scan_bounded`/`fd_scan_truncated` provenance signal
so a bounded scan is observable, never silently partial.

**Why safe:** tightens a resource bound in the privileged helper; no new capability, no new syscall
surface; degrades to an explicitly-flagged partial result (honest), never to a fabricated complete
one. Must pass the existing escalation-lint and the elevated Tart-VM CI smoke.

**Cannot iterate locally** (no Virtualization.framework on this dev machine): implement behind
`cross-target cargo check --tests` locally, then validate execution under the `:linux: … (elevated
provenance)` Buildkite step. Sequenced LAST; may split to its own Rust-focused plan if it grows.

---

## Sequencing & verification

1. **A** — ✅ SHIPPED 2026-07-16 (`accbc49`). same-tick ambiguity → skip + `lookup.ambiguousTargets`. Sonnet-verified OVERALL_SAFE (40k-permutation fuzz).
2. **B** — ✅ SHIPPED 2026-07-16 (`924d819`). opt-in freshness pinned to the structural interval, wired into active + shadow-soak, one-nowMs-snapshot skew fix folded. Sonnet-verified OVERALL_SAFE.
3. **C** — census marker. Sonnet review caught two must-fixes (folded before commit): distinct `fact_name:"service.census"` (kills the launchd entity_key collision / confidence-dilution class) + status gate `ok|warning` only (no false "complete" marker on an unsupported-platform `"unknown"` envelope).
4. **D** (Rust, CI-gated) — implement + verify under CI, or spin to its own plan.

Each slice: TDD (test first) → implement → `node --check` + full `npm test` (0 fail) +
escalation-lint → adversarial verifier subagent (OVERALL_SAFE) → fold findings → atomic commit →
push → update HANDOFF + todo. Per repo process, every design/plan change is independently reviewed
by a subagent before implementation.

## Non-goals

- No absence-*alerting* by default (would break "never fabricate a violation without fresh positive
  evidence"). Slice C only makes absence *representable*.
- No change to the miner's contradiction handling (already conservative).
- No Linux port→PID attribution added (that is the separate S3-priv elevated path, already shipped;
  the base `ss` collector deliberately captures no owner).
