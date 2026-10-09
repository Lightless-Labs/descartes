# Context plan v2 re-review — Opus 5.5 (max)

# Re-review: context-aware learned baselines plan v2 (Opus 5.5, max)

**Date:** 2026-10-06
**Plan:** `docs/plans/2026-10-06-context-aware-learned-baselines.md` (v2, e6be585)
**Code checked:**
- `main` @ e6be585
- `feat/fact-store-capacity-2026-10` @ c2d6f75
- `feat/notify-once-2026-10` @ 9ed0eb8
- the uncommitted `fix/collector-sources-2026-10` worktree, which changed while this review ran

**Method:** I read both v1 reviews first, then v2 in full, then checked every load-bearing claim against code. This was read-only: no repo file was modified, and one scratchpad draft was written.

## Summary

1. **Are the v1 BLOCKER/HIGH items closed?** Of the 22 items, 9 are closed, 10 are partly closed, 2 are reopened and 1 is open. The reopened pair is Opus B1 and Astra 2, both reopened by B1 below. The open item is Opus H5 (the macOS VPN parser), which is delegated and unverified. The full table is at the end.
2. **New fabrication paths and new hand-coded assumptions?** Yes, both.
   - New fabrication paths:
     - a recovery for event alerts on the next quiet interval (B1);
     - C1a absorbing a sustained shift as old data ages out (H2);
     - a one-write laundering of pending observations (H4);
     - a shared context term inflating cross-stream corroboration (M2);
     - `fired_count` inflation (M1);
     - an exposure bias toward alerting (M9).
   - New hand-coded assumptions:
     - the incumbent's z = −6 used as the adequacy bar (M3);
     - a bounded-quiet duration that controls admission (M4);
     - an unclassified split of dimensions into "state" and "calendar" for alert identity (H1).
3. **Is the core principle honoured?** Yes in direction and mostly in detail:
   - R4–R10 stay out;
   - context is data;
   - structure is soft (shrinkage), not hard selection;
   - time-to-override (TTO) is reported honestly;
   - long memory grows.

   The exceptions are M3, M4, and H1, where closing an alert by label only drifts into the doctrine's per-item-consent ("UAC") ditch.
4. **Is it buildable in the stated sequence?** No:
   - C1a depends on things built in C7a, C7b and the capacity branch (H3).
   - The source-fix dependency leaves census semantics unspecified (M7).
   - The C4a corpus lacks the context it is meant to evaluate (M8).
   - `tick_summary` cannot chain the extra samples (M5).
   - §9 and §12 describe a stale version of notify-once (M1).

   The C4a escape clause for `model-ir` (write down and justify a divergence) is adequate.

---

## BLOCKER

### B1. Coverage contract v2 has no recovery rule for event streams. As written, it recovers a departure alert on the next quiet interval, with the departed sessions still gone.

- **Plan:**
  - §6.1 CC3(e) (line 277): "the observation is unsurprising both under the current predictive and under the raising parameter snapshot. The evidence itself must have changed."
  - §7.1 (lines 326-333): the primary streams are departures, arrivals, churn, login arrivals and node-key novelty. All of these are event streams. Occupancy and the tailnet online count are the only level streams, and both are secondary.
  - §14 C5 (line 593): the first vertical learner is "session departures and arrivals".
  - "Stated consequence" (line 286) and the gate table (lines 290-300) are written in level terms: "0 sessions", "same count", "the sessions return".
- **Code:**
  - `alert-store.js:314-323`: an identity that is covered and absent from the candidates becomes `recovered`.
  - `session-baseline.js:897-915`: today's `count_drop` is a level alert. It is re-emitted on every tick while the count stays low, so recovering it requires the count to return. A departure stream has no such persistence.
- **Scenario:**
  1. Five tmux sessions are running, and an attacker kills four between ticks.
  2. Tick t has D = 4 of 5 at risk, so the learner raises.
  3. Tick t+1 is in the same cell with nothing new: D = 0 of 1 at risk.
  4. CC3 is now satisfied:
     - (a) the census is complete;
     - (b) lineage and `structure_id` are the same;
     - (c) the cell is the same;
     - (d) the evaluation is at leaf level with support;
     - (e) D = 0 is unsurprising under both the current predictive and the raising snapshot, and the evidence changed (4 → 0);
     - (f) there is no drift excursion.
  5. The alert is recovered while four sessions are still gone. This is the v1 Astra 2 / Opus B1 shape, now without even needing a context change.
- **Reboot case:**
  - Departures are only computed "within the same boot", so `cc2_reboot_freezes` passes vacuously.
  - Days later, once `since_boot` climbs back into the raising bucket, the alert clears on the first quiet interval.
  - The positive control `cc2_evidence_restored_recovers` cannot happen first. The alert has already cleared, and the returning sessions are arrivals scored by a different stream.
- **Fix:**
  - Define per stream kind what an alert asserts and what restores it.
  - **Event alert:** it recovers only when the departed entity keys or names are present again in a trusted complete census. Fingerprints are compared only within one boot. Otherwise it closes by label or explanation, under the same lifecycle Q4 proposes for novelty. "The next interval was quiet" must never recover it.
  - **Occupancy alert:** keep CC3 as written.
  - Split the `cc2_*` tests by stream kind, and add `cc2_quiet_interval_after_kill_no_clear` and `cc2_departed_entities_return_recovers`.

## HIGH

### H1. Most learned alerts become unrecoverable by evidence, and persistent anomalies multiply notifications. The identity design (CC1, CC3) causes both.

- **Plan:**
  - CC1 (lines 266-270): `stratum_class` covers `since_boot`, `since_wake`, `tailnet`, `vpn`, `net_config` and `presence`. "Calendar dimensions are excluded on purpose", because they change with time.
  - CC2 (line 271): back-off raises are allowed.
  - CC3(c) (line 275): "every state dimension is known and stable".
  - CC3(d) (line 276): recovery needs a leaf-level evaluation.
  - §5 (line 252): missing inputs map to `unknown`.
  - I22 (line 87) and CC7 (line 284).
- **Code:**
  - `alert-store.js:27-30`: every distinct `stratum_class` is a separate alert record.
  - notify-once branch, `alert-store.js:434`: a new identity starts a new episode (`!current`), which notifies.
  - Alert records are never evicted (`alert-store.js:248-261`).
- **Scenarios:**
  - (a) `since_boot` and `since_wake` advance with the clock, exactly like the calendar dimensions the plan excluded.
    - An occupancy alert raised at `since_boot` ∈ [1 h, 6 h) can meet CC3(c) only until 6 h of uptime.
    - After that it stays frozen until some later boot passes through the same bucket.
    - On a laptop, `since_wake` changes bucket several times a day.
  - (b) A persistent anomaly re-raises under a new identity whenever the cell changes, for example presence going active → locked → idle, or a `since_*` bucket edge.
    - Each new identity is a new notify-once episode, and therefore a new notification.
    - The previous identity freezes.
  - (c) A back-off raise carries a backed-off `stratum_class`. It can never meet CC3(c) and CC3(d) together.
    - On hosts where a dimension can never be observed, every raise is a back-off raise, so no learned alert ever recovers. Examples:
      - `presence` on a headless Linux host with no logind seat;
      - `vpn` on Linux without NetworkManager;
      - `since_wake` on a host that never sleeps, if it is encoded as unknown.
  - (d) The only way out is CC7: a per-item label on alerts that notify-once keeps silent. That is the UAC ditch (`autonomy-doctrine.md:39-50`). Meanwhile `alerts.json` grows by lineage × structure × stratum class.
- **Fix:**
  - Key identity only on state dimensions that do not advance with time.
  - Handle `since_*` the way calendar is handled: re-score the raising cell's predictive under CC3(e).
  - Exclude dimensions never observed on this host from the host's vocabulary; when one appears, that is a structure-version change.
  - Treat `not_applicable` and stable not-installed as known values.
  - Let a back-off alert recover at the same back-off level once the context is known.
  - Cap learned-alert identities per rule.

### H2. C1a on the incumbents absorbs a sustained shift as old data ages out, then recovers the alert on unchanged evidence.

- **Plan:**
  - §6.2 rule (lines 304-311).
  - Bounded quiet requires "with no further anomaly" (line 308).
  - "Applied to the existing detectors" (lines 315-317).
  - P5 (line 41).
- **Code:**
  - `session-baseline.js:407-438`: statistics are recomputed from the whole window on every call.
  - `:83`: N = 30.
  - `:741` and `:750`: a 31-day read window, while `fact-store.js:18` keeps 30 days.
  - `:661-662` and `:909-915`: an unestablished detector emits no candidate and no coverage.
  - `peer-baseline.js` (`computeWindowedPeerStats`) has the same shape.
- **Scenario:**
  1. A host is stable at 5 sessions. An attacker kills 2 and keeps them dead.
  2. Every hourly tick scores z = (3 − 5)/0.5 = −4. Each is alarmed and goes to pending. Bounded quiet never fires, because every tick is a further anomaly.
  3. At about day 28.75, fewer than 30 non-pending complete ticks remain. The detector turns provisional, reports no candidate and no coverage, and the active alert freezes. The detector is now blind.
  4. Provisional ticks raise nothing, so they are not pending, and they fold into the baseline.
  5. About 30 hours later the baseline re-establishes at 3, and the still-active alert recovers on unchanged evidence.
- **Effect:**
  - The attacker costs one notification (notify-once).
  - They get a predictable blind window of about 30 hours near day 29.
  - The shift is admitted with no label, no budget charge and no `admitted_unexplained` record.
  - This is the unarbitrated adaptation C1a exists to remove, plus the recovery on unchanged evidence that CC3(e) forbids for learners.
  - A benign permanent change goes the same way, silently.
  - The "stuck learner" problem (Opus M10, Astra 5) is closed only for challengers.
- **Fix:**
  - While a pending episode is open, score against a persisted, integrity-protected snapshot taken before the episode, not a sliding window that ages out.
  - Treat re-warm-up ticks during an open episode as pending.
  - Give incumbent alerts a CC3(e)-style rule.
  - Define how a sustained shift exits: a label, or `admitted_unexplained` after bounded quiet measured on the stability of the new level, within the budget.

### H3. C1a cannot be built in the stated sequence.

- **Plan:**
  - §6.2 admission paths 1-3 (lines 306-311).
  - §8.3 (line 455): snapshots are taken "at promotion and at ratification".
  - §9 label bound (b) (line 475): labels admit pending items only within the drift budget.
  - §11.3 (line 546).
  - §14: C1a "needs C1.1, C1.3" (line 587), while C7b builds the drift budget "only if Q2 is ratified" (line 596).
- **Code:**
  - `novelty-seen-set.js` exists only on `feat/fact-store-capacity-2026-10`; `main`'s source has no seen-set at all.
  - The capacity branch also rewrites the session, peer, service, process-lineage and persistence baselines (63 files, +10,801/−1,213).
- **Scenario:** built at C1 time, each admission path is missing a piece.
  - **Path 1:** there is no promoted learner (C7a), and the (F) class is not ratified.
  - **Path 2:** bound (b) admits only within a drift budget that nothing has built.
  - **Path 3:** it consumes a budget anchored to a reference snapshot that no step creates. The incumbents never get one, because they are never promoted or ratified.
  - **If Q2 is no:** C7b never runs, so paths 2 and 3 never become buildable.
  - **Seen-sets:** the §8.3 drift measure is undefined for a seen-set, and the seen-set half of C1a cannot land before capacity, yet it is sequenced ahead of C2.
- **Fix:**
  - Build into C1a an anchor for the incumbents: a snapshot ratified once when C1a lands.
  - Declare a drift measure per incumbent kind: |Δμ|/σ_anchor for Welford folds, admitted entities per family for seen-sets.
  - Decouple this from C7b.
  - Either list capacity as a C1a dependency, or split C1a into the fold change (on `main`) and the seen-set change (after capacity).

### H4. Pending state has no integrity-protected home. One same-user write launders pending observations into the baseline.

- **Plan:**
  - §6.2 (line 316): pending ticks go to "a bounded pending pool (S cap) stored with its alert".
  - Line 304: pending observations are "retained, never deleted".
  - I18 (line 83) and I27 (line 92).
- **Code:**
  - `alert-store.js:189-212`: `normalizeAlertRecord` rebuilds each record from a fixed field list, dropping extra fields.
  - `alert-store.js:229-237`: a malformed record is quarantined, which means dropped.
  - `alerts.json` has no integrity ledger, unlike the fact store.
  - `session-baseline.js:272-287`: a corrupt state store resets to fresh state.
  - capacity `novelty-seen-set.js:26-35`: a re-seed rebuilds entries from certified candidates.
- **Scenario:**
  1. A sustained shift lasts about three days, until pending ticks exceed about 10% of the window. Past that point, folding them keeps z above −3 for a two-point 5/3 mix.
  2. A same-user process then deletes the `session.count_drop` record from `alerts.json`, or corrupts it so that `readAlertRecords` quarantines it.
  3. On the next tick the alarmed ticks fold. There is no label, no budget charge, no `admitted_unexplained` record and no logged transition, which bypasses I27.
  4. For novelty, corrupting `seen-set.json` forces a re-seed that drops the pending marks.
  5. Separately, a capped pool must evict under a sustained shift (about 720 ticks a month), and "never deleted" does not say how.
- **Fix:**
  - Derive pending membership from the hash-chained transition log (§9) or from a ledger-stamped store.
  - Treat a lost pending state as an integrity event that stops admission (fail closed).
  - Make pool overflow fail closed, with a notice.

## MEDIUM

### M1. The plan's picture of notify-once is stale.

- **Plan:**
  - §9 (line 463) cites `newEpisode = !current || current.status === "recovered"` from 33084a6.
  - §12 (lines 561-566) describes notification on activation and escalation only.
  - CC1 `raise_ref` (line 269).
  - C1.2 (lines 464-467).
- **Code:**
  - Branch tip `alert-store.js:434`: `newEpisode` also includes `|| current.material_evidence_digest !== evidenceDigest`.
  - `:282-311`: the digest covers every diagnostic field except a per-rule list of volatile ones.
  - The branch README says "A digest change while an alert is active, acknowledged, or frozen starts a new episode."
- **Scenario:**
  - Suppose `raise_ref` (calendar cell, parameter-snapshot digest, evidence summary) rides in the diagnostics. Then a persistent learned alert re-notifies on every hour boundary and every refit.
  - If C1.2's `activated` transition is hooked at `newEpisode`, as §9 suggests, the digest churn inflates `fired_count`:
    - Constraint diagnostics include `actual` (`constraint-eval.js:89-97`).
    - So a violated constraint whose value fluctuates looks `chronically_firing` (`calibration.js:293`).
    - That yields retire proposals (`tuning-store.js:413`), which are applied on approval (`tuning-authority.js:390`).
    - The result is suppression proposals, and per-item approval load.
- **Fix:**
  - Re-ground §9 and §12 on the branch tip.
  - Keep `raise_ref` out of the digest: either a schema field pinned at episode start, or declared volatile per rule.
  - Define `activated` as a status transition from a non-active state, not as an episode.

### M2. Joint scoring counts one context event in every stream, which fabricates corroboration.

- **Plan:** §7.3 (lines 359-360) adds the context-transition term to each tick's score. §12 (line 573) and I29 map "corroboration across streams" to severity.
- **Scenario:** an unusual-hour reboot or a new network raises sessions, peers, logins and tailnet together. The severity mapping reads four "independent" streams that share one cause. The doctrine requires corroboration to be independent (`autonomy-doctrine.md:61-68`).
- **Fix:**
  - The context stream alerts on the transition term.
  - Response streams score the conditional term only.
  - Corroboration counts distinct evidence sources.

### M3. The adequacy gate uses the incumbent's placeholder constant as its bar.

- **Plan:** §7.2 `adequacy_stable3_to0` (line 350): "at least as surprising as the incumbent ... z = −6". See also I12 (line 77) and I35 (line 100).
- **Code:** `session-baseline.js:68-78` marks the 0.5 floor that produces z = −6 as "PROVISIONAL ... NOT tuned values".
- **Problems:**
  - An S gate inherits a constant the audits classed as A/C.
  - It compares a Gaussian z with a discrete predictive probability, which are different scales.
- **Illustrative arithmetic (the plan author should verify):**
  - Take three sessions stable for three weeks: about 1,512 session-hours, no departures.
  - With a Gamma prior of shape 1, the posterior predictive P(all 3 depart in 1 h) ≈ 6/1513³ ≈ 1.7e-9.
  - For z = −6 the Gaussian tail is about 9.9e-10, so the preferred hazard family fails its own mandatory fixture.
  - With shape 0.5 it passes, so the outcome is governed by the prior.
- **Fix:** define adequacy as:
  - PIT calibration;
  - the drop is flagged at the stream's α_i;
  - the verdict is stable across the ×0.1 / ×10 prior sensitivity check.

### M4. The O class contradicts itself, and bounded-quiet admission is a doctrine exception no question raises.

- **Plan:**
  - §0.4 (line 56) says O "never controls training admission".
  - Yet I19 (bounded quiet), I20 (drift-budget size) and I27 (label budget), all class O, control admission (lines 84, 85, 92).
  - §16 has no question about it.
- **Doctrine:** `autonomy-doctrine.md:103` (never adapt to unattested change) and `:126-129` (sticky adaptation is attestation-gated).
- **Scenario:**
  - Path 3 admits unexplained observations into the baselines of default-on WATCH detectors.
  - That is the "sticky adaptation" class that §11.2 sends to a doctrine amendment (Q2) for replacement.
  - Here it is an O constant presented as "notification, not confirmation".
  - It is better than today's ungated folding, but it does not conform to the doctrine.
- **Fix:**
  - Make the admission mechanism S, with O parameters, and amend the O definition.
  - Add Q7: bounded-quiet admission into the incumbents on-host, or label-only until attestation?

### M5. `tick_summary` cannot chain the extra samples, and its integrity model is borrowed from something that does not fit.

- **Plan:**
  - §8.1 (lines 433-445).
  - §7.6 transition samples (lines 399-403).
  - §7.1 departures are taken "from entity-key set differences in the census facts" (line 328).
  - §8.2 (lines 449-451).
- **Code (capacity branch):**
  - `novelty-seen-set.js:20-25`: a seen-set is valid only if it is stamped to the latest committed pass of its one family ledger.
  - `fact-families.js:335-344`: the T8 floor assumes one worst-case record per structural tick.
  - `fact-store.js:31`: a single 30-day retention applies to every family.
- **Scenarios:**
  - (a) The +2 and +10 minute samples carry no entity keys and no raw census. The next structural interval's departures, computed raw from t−1 to t, either re-count departures already recorded or cannot chain at all.
  - (b) A seen-set is one snapshot validated against its own family's latest pass. `tick_summary` is an append-only, cross-family history, and the extra samples make part of it primary data that cannot be re-derived.
  - (c) The T8 formula lacks a records-per-interval term (up to 5 per hour). "Outlives the raw window" needs per-family retention.
  - (d) The §8.2 store has no defined integrity home. Losing it silently cold-starts months of memory, which is now cheaper for an attacker than the H7 volume attack.
- **Fix:**
  - Carry the departure basis (an entity-set digest) for every sample.
  - Define a multi-ledger validity rule.
  - Add a records-per-interval term to T8, and support per-family retention.
  - Make loss of the long-lived store an integrity notice.

### M6. The leakage check (I5) cannot enforce what it promises.

- **Plan:**
  - §5: `contextAt(tick_summary_record)` (line 237).
  - The leakage rule (line 251) and I5 (line 70).
  - C0.2 adds Linux "tun/wg links" to the VPN context (line 179).
  - A §7.1 target is "WireGuard peers with an active handshake" (line 326).
- **Code:** WireGuard peers come from `wg show <if> latest-handshakes` (`vpn-peer-status.js:203`).
- **Scenario:**
  - Targets and context live in the same family, so a static check "over the source families" is vacuous.
  - On Linux, `vpn` (wg link up) restates the WireGuard-peer target. A user-level `nmcli con down wg0` then "explains" the departures.
- **Fix:**
  - Check I5 against field provenance, not families.
  - Ban any dimension derived from the same physical object as a target: a wg link and its peers, or the Tailscale network extension and the tailnet.

### M7. C0.1 does not say how "not found on known paths" affects census completeness.

- **Plan:** C0.1 (line 178), §4.4 (line 227), §14 C0 (line 585). The header (line 17) says the branch is not on this checkout.
- **Code:**
  - Today `fact-translators.js:730` (`censusStateFor`) maps `absent` to complete.
  - `fix/collector-sources-2026-10` now exists as a worktree (`.claude/worktrees/collector-sources`, at e6be585). Its uncommitted `censusStateFor` returns `unknown` if any multiplexer is not found, even when tmux is `ok`. Its modified `test/fact-translators.test.js` asserts exactly that.
- **Scenario:** the plan must choose a mapping, and both obvious choices fail.
  - The old mapping fabricates a complete zero for a tmux installed outside the allowlist.
  - The in-progress mapping makes every tmux-only or screen-only host's census permanently `unknown`. That freezes both incumbent session rules and starves C5.
- **Fix:**
  - Use per-source census universes, following the peer availability-signature pattern (`peer-baseline.js:537-548`).
  - A missing multiplexer leaves the universe and is recorded in `collector.binary_state`.
  - A change from resolved to not found is an unknown tick.

### M8. The C4a corpus lacks the context it is supposed to evaluate.

- **Plan:** §10.1 (lines 486-493), C3b (line 590), C4a (line 591).
- **Code:**
  - On `main`, nothing collects boot id, suspend, `net_config` or presence (`daemon.js:395-403`).
  - A non-running tailnet leaves no fact (`tailscale-status.js:164` → `fact-translators.js:999`).
  - `last` reboot rows are dropped (`vpn-peer-status.js:139`).
  - Uptime is kept only as a 24-hour metric.
- **Scenario:**
  - Models (ii) and (iii) need context, which must be rebuilt from the operator's labels.
  - Those labels are also the evaluation labels, which is circular.
  - The spike can therefore only measure an upper bound with perfect context.
- **Fix:** either:
  - run C4a after several weeks of C2 collection on that laptop; or
  - state that the go/no-go is an upper bound, and add a separate check against observed context.

### M9. C0.9 has no plan for a negative result, and the exposure rule leans toward alerting.

- **Plan:**
  - C0.9 (line 186).
  - §4.1 `host.suspend` (line 199).
  - §7.1 exposure = wall-clock Δ minus the *upper* bound on suspended time (line 328).
- **Host:**
  - `kern.monotonicclock_usecs` is readable without privileges. Its second field tracked uptime here, but this VM has never slept, so it cannot be validated.
  - `os.uptime` on macOS derives from `kern.boottime`, which moves when the calendar clock is set.
- **Scenario:**
  - If C0.9 finds no source, exposure is undefined for C5.
  - With only bounds, the minimum exposure inflates departure surprise after a wake. That is the R9 false-positive class, against `autonomy-doctrine.md:120`.
- **Fix:** give C0.9 a go/no-go with a defined fallback. Raise using the maximum exposure; recover using the minimum.

## LOW

- **L1. The TTO formula is not a time** (§7.6, line 396). "Pseudo-count ÷ observed event rate" mixes units. For a Gamma(a0, b0) rate, data outweighs the prior when accrued exposure ≥ b0 (independent of the rate) and when events ≥ a0. I23 makes this definition S, so pin it.
- **L2. The 1 KiB bound has no caps behind it** (§8.1, line 441; I2). The per-service VPN HMAC states have no count cap. Per-collector `obs_start`/`obs_end` pairs and the interval events are also unbounded. Without caps, "independent of entity count" fails T8.
- **L3. Good–Turing novelty can be gamed** (§7.3, line 362; I21). Toggling cheap dimensions (on Linux, nmcli resolver changes from an active session) inflates singletons, so that a new-network-then-act attack becomes unremarkable. Score the novelty rate's own drift against the anchor.
- **L4. The novelty half of C1a does nothing until Q4** (lines 317-318). With the one-tick `recovered` lifecycle kept, pending entities are still not re-alerted, and an exhausted budget blocks nothing visible. P5's "v2 fixes that early" (line 41) holds only for the statistical folds.

## v1 BLOCKER/HIGH closure

| v1 item | Status | Residual |
|---|---|---|
| Astra 1 (authority) | Closed: C7a/C7b split, Q2, per-host routing | M4 |
| Astra 2 (fallback recovery) | **Reopened** | B1, H1 |
| Astra 3 (lifecycle fabrication) | Closed: boot id, suspend as intervals, clock facts | M9 |
| Astra 4 (conditioning/leakage) | Partly closed | M2, M6 |
| Astra 5 (exclusion deadlock, slow poisoning) | Partly closed: challengers only | H2, H4 |
| Astra 6 (classification honesty) | Partly closed | M3, M4, H1 (state/calendar split unclassified) |
| Astra 7 (sample size, resolution) | Partly closed | M5(a) |
| Astra 8 (underdispersion) | Partly closed | M3 |
| Astra 9 (selection optimism) | Closed | — |
| Astra 10 (reconstruction) | Closed | M5 |
| Astra 11 (per-source census contracts) | Partly closed | M7 |
| Astra 12 (login learner) | Closed | — |
| Astra 13 (labels, evaluation) | Partly closed | M1, M8 |
| Opus B1 (context-change recovery) | **Reopened** | B1, H1 |
| Opus H1 (level families) | Closed: transitions with exposure | M3 |
| Opus H2 (rare events, prior is the rule) | Partly closed | M5 |
| Opus H3 (steerable context) | Partly closed | M2, M6, L3 |
| Opus H4 (hard selection) | Closed | — |
| Opus H5 (scutil parser) | Open: delegated; in progress on the worktree, not verified | — |
| Opus H6 (launchd PATH) | Partly closed | M7 |
| Opus H7 (memory vs budgets) | Closed for learners | M5 |
| Opus H8 (C7 is suppression) | Closed | M4 |

VERDICT: NEEDS-REVISION (5). n = 1 BLOCKER + 4 HIGH, following the v1 Opus convention; 9 MEDIUM and 4 LOW are also listed. Not RETHINK: the direction holds, and every finding is a contract or sequencing fix.