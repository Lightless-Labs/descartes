# Context plan v4 review — Opus 5.5 (max)

# Context plan v4 re-review (Opus 5.5, max)

**Date:** 2026-10-09
**Plan:** `docs/plans/2026-10-06-context-aware-learned-baselines.md` (DRAFT v4, e89c53a)

**Code checked:**
- `main` @ e89c53a (the capacity merge 1169d40, plus b60efc8).
- `feat/notify-once-2026-10` @ c461564 (the commit the plan cites). Its tip kept moving during the review: cd10972, then 71815b5.
- `fix/collector-sources-2026-10` @ 3c18739 (the commit the plan cites). Its tip also moved during the review: 25aeb89, then f668599, then 96a2399.

**Method:** I read the five prior reviews first, then v4 in full, then checked every load-bearing claim against code. This was read-only: no repo file was modified. Scratch copies of branch files are in the session scratchpad.

## Answers to the five questions

**1. Are the prior BLOCKER/HIGH items closed?**
- **v3 HIGH 3:** closed.
- **v3 HIGH 1:** closed for the journal itself:
  - entries cite the pass they scored;
  - the retention pass carries the checkpoint;
  - the journal is written first;
  - re-certification is automatic.

  I verified that a ledger generation changes only on bootstrap (`fact-store-integrity.js:95-97,449`), and that every completed structural tick runs the family passes (`daemon.js:1122`) before detection (`:1743`). It is not closed for the detector state that the exit relies on (HIGH 2).
- **v3 HIGH 2:** closed in steady state. Its "exit as a new normal" does not work for the window-based incumbents (HIGH 1), and one truncation reopens the muting (HIGH 2).
- **Older items:** see the table at the end.

**2. Is §6 coherent end to end?** These parts hold:
- membership from the journal alone;
- the write order;
- EVENT/LEVEL/NOVELTY recovery;
- pending data on recover, close and quarantine;
- compaction instead of a freeze;
- the per-incident records on the notify-once branch. At c461564 a new episode resets the incident map (`alert-store.js:554`), and a confirmed incident at or below its notified severity is not due (`:508`).

It breaks at four points:
- the LEVEL exits (HIGH 1);
- carrying state across a discontinuity (HIGH 2);
- the held-level definition (MEDIUM 1);
- the missing digest (MEDIUM 4).

**3. New fabrication or suppression paths?**
- muting by truncation, and a drift-budget reset by one write (HIGH 2);
- silent closure by a forged label (MEDIUM 5);
- a quarantined persistence item re-installs silently (MEDIUM 2);
- an interim blind path when a binary is moved aside (MEDIUM 3);
- a recovery that changes status only (LOW 7).

There is no new hand-coded rule, window or threshold about what is normal. R4–R10 stay out.

**4. Is the core principle honoured?** In direction, yes:
- data and context come first;
- F only constrains;
- structure is soft;
- memory is long;
- every number is classified.

There are two departures:
- C1a stops the default-on incumbents from learning any recurring benign pattern that alarms. A label per episode becomes the only exit, which is the per-item-consent ("UAC") ditch (HIGH 1).
- One write can reset the anchored drift bound (HIGH 2b).

**5. Is it buildable in the stated sequence?**
- CAP is met, and the merge order is sound.
- C0.1b's notice and arbitration cannot land on the collector branch before C1a, and that branch has moved on without them (MEDIUM 3).
- C1 and C1a need a digest that no step builds, and Q5 values that C3b only proposes later (MEDIUM 4).
- The branch citations are stale (LOW 8).

## BLOCKER

None.

## HIGH

### HIGH 1. The window-based incumbents have no working exit to a new normal: an admitted held level re-raises on the next tick, and a recurring dip that recovers is never admitted

**Plan:**
- §6.5.2: "The admission increments the serving generation. The next tick scores against the new serving state, and a later drop is a new episode".
- §6.2 CC7: "the admitted state is now the baseline that the next change is measured against".
- I60: "The serving state is the window statistics over folded ticks".
- §9: "Declaring a new normal".
- The §6.0 table: `recovered` leaves items pending.
- §6.3: bounded quiet needs a held level.
- I3: items compact to `excluded`, never folded.

**Code:**
- `session-baseline.js:385-416`: a 31-day Welford over every non-excluded complete tick.
- `welford-stats.js:84-89`: z = (x − μ) / max(σ, 0.5).
- `session-baseline.js:76-78,653-669`: warning at z ≤ −3, critical at z ≤ −5.
- Peers are identical: `peer-baseline.js:68,74,612-647`.
- c461564 `alert-store.js:542-554`: after `recovered`, and with C1.1's `closed` once that is added to `newEpisode`, a candidate opens a new episode that is due.

**Scenario (a): a held shift.** I computed this with the incumbent's own formula.
1. The window holds 720 ticks at 5 sessions.
2. A benign, permanent drop to 2 raises CRITICAL. This is the end-of-day cleanup that `session-baseline.js:68-75` itself names.
3. After one day, 25 ticks are admitted, by a label or by bounded quiet with Q = 24 h.
4. The window is now μ 4.90 and σ 0.55, so the next tick at 2 scores z = −5.27. That is a new episode and a new CRITICAL notification.
5. The level stops alarming only after about 73 admitted ticks, which is 10% of the window. Once σ clears the floor, z = −√((1−p)/p).

For peers dropping 6→4, z is still −3.86 after 25 admitted ticks. Two consequences follow:
- **Before DA3,** each `expected` label closes the episode and the next tick reopens it. The operator labels per episode for about three days of ticks. That is the per-item-consent ditch (`autonomy-doctrine.md:39-50`).
- **After DA3,** there is one notification per Q.

`level_admitted_shift_rearms` passes, but the realistic case, in which the level simply continues, loops.

**Scenario (b): a recurring dip.** The same 5→2 drop, 10 hours a night.
- **Today:** the alarmed ticks fold. z goes −5.92, −4.79, −3.05, −2.83 over successive nights: CRITICAL for about 3 nights, WARNING until about 7, quiet from about 8.
- **Under C1a:**
  - each night is an episode that recovers in the morning (CC3);
  - its ticks stay pending (§6.0);
  - bounded quiet never applies, because no held level survives the morning;
  - I3 compacts the ticks to `excluded`, never folded.

  The result is CRITICAL every night for the life of the install.
- **The only exit** is a label per night or per pending window. Absorbing the pattern still moves the warning trigger by about 3 anchor σ_eff (from 3.5 to 2.0 at 10% of the window), so a small drift budget refuses it.
- **No mapped `context_model` exists** before C7a plus DA3 plus an occupancy learner, and §6.3 says C5 "maps to no incumbent rule". The 2026-10-05 calibration noise therefore gets worse on the default-on detectors until C7b.

**Fix:**
- On admitting a held LEVEL shift, do one of two things:
  - re-base the serving state to the admitted level: a new serving generation seeded from the held-level statistics, with the trigger displacement charged to the drift budget; or
  - keep the episode open as `admitted` until the serving state itself accepts the level. Ticks at the held level are admitted on arrival, and further anomalies still mint incidents.
- State the recurring-dip consequence. Then either bring a mapped hour-of-week occupancy LEVEL learner into C5/C7a, or define an unattended, drift-budgeted path for recurring recovered episodes.
- Add the fixtures `level_admitted_shift_next_tick_no_reraise` and `level_recurring_recovered_dip_exit`.
- Add a C1a gate: replay the 2026-10-05 calibration through C1a and publish the change in notification count before C1a ships.

### HIGH 2. The discontinuity exit (§6.4.4) restores the journal, but not the detector state that "detection continues" depends on. One same-UID write can mute a LEVEL alert or reset the drift budget

**Plan:**
- §6.4.2: the journal payload holds the held-level statistics, and only a reference to the pre-episode snapshot.
- §6.4.4:
  - step 2: every tick goes into one `unexplained_discontinuity` item;
  - step 3: "The detectors keep raising against their last certified serving snapshot";
  - the attacker analysis claims "never a stopped detector".
- §6.1: LEVEL keys are `lvl:<serving generation>:<held-level ordinal>`.
- §6.5.1 and I58: anchors are "ledger-stamped" and are taken automatically "whenever it first establishes".
- §6.5.4: "Re-anchoring resets the anchor, and with it the budget".
- §8.3: names no store, integrity rule or loss rule for anchors and snapshots. The only loss rules are §8.2's `memory_lost` (long-lived statistics) and CC5's (`:466`, successor snapshots).

**Code:**
- c461564 `alert-store.js:508`: a confirmed incident at or below its notified severity is not due.
- `peer-baseline.js:730`: peer severity is capped at warning.
- `peer-baseline.js:55-61`: `v2:vpn` spans every marker-backed regime.
- `session-baseline.js:250-262`: a corrupt detector store resets to a fresh state ("an honest, documented cold-start").
- §6.4.1's own argument: a seen-set stamp (`novelty-seen-set.js:371`) cannot fit a writer that runs after the pass.

**(a) Muting.**
1. The host has 6 VPN peers. The operator retires 2 of them. z = −4, a warning; incident `lvl:g:0` is delivered and confirmed.
2. The attacker truncates `learned/pending/peer/`, which is the attack §6.4.4 analyses.
3. The epoch carries the incident forward from `alerts.json`. But the held level and the episode's tick membership are gone, because those ticks are re-filed under `unexplained_discontinuity`. The next pass re-certifies.
4. The attacker cuts the remaining 4 peers. Against the serving snapshot this scores as a warning, because of the cap. With no held level it is one of two things, and neither is due under `:508`:
   - a held tick under `lvl:g:0`; or
   - a re-derived `lvl:g:0`, if the generation and ordinal (stored only in the journal) restart.

This reopens v3 HIGH 2 with one write. The same key collision happens with no tampering when §6.5.3 freezes an open peer episode across a regime change and the new regime raises under the shared `v2:vpn` id. On the sessions side, the collector branch's 6ba7d80 already gives per-universe ids, which removes that variant.

**(b) Budget reset.**
1. A slow poisoner walks the level down with sub-threshold folds until I61 raises `baseline.drift_excursion`.
2. One write corrupts the store that holds the anchor. The plan names no store; if it is the detector store, `:250-262` resets it.
3. A cold start follows, then re-establishment.
4. I58 takes a fresh provisional anchor at the walked level, and §6.5.4 resets the budget with it.
5. The attacker repeats.

The doctrine's cumulative drift bound (`autonomy-doctrine.md:110-116`; Astra 5) is reset by each write. Separately, a literal "ledger-stamped" anchor written after the pass fails §6.4.1's own stamp test at the next pass.

**(c) I60's fallback.** At about day 29 of the v2 H2 sustained shift, I60 serves the "last certified snapshot". If that snapshot is deleted, the outcome is undefined:
- the detector goes provisional and is muted while the episode is open; or
- it falls back to the raw window, which absorbs the shift.

**Fix:**
- Keep these in the hash-chained journal and its checkpoint, under §6.4.3's cite-not-equal stamp, so that losing them is a discontinuity:
  - the anchors;
  - the serving, pre-episode and regime snapshots;
  - the serving generation;
  - each open episode's held level and ordinal.
- On a discontinuity, rebuild open episodes conservatively:
  - the held level from raw ticks since the open incident's `first_seen`;
  - the ordinal as the highest open key + 1;
  - the pre-episode snapshot from the anchor.
- Put the epoch, and the regime, into the LEVEL key.
- A surprising tick while an alert is open and its held level is unknown is a new incident.
- Never re-take a lost anchor automatically. While it is lost, raise against the last surviving anchor, keep unattended admission off, and let only the operator re-anchor.
- Add the fixtures `level_journal_truncated_new_drop_notifies`, `level_regime_freeze_new_regime_drop_notifies`, `anchor_store_corrupt_no_fresh_budget` and `serving_snapshot_deleted_no_absorb`.

## MEDIUM

### MEDIUM 1. "Re-base" is undefined, and superseded LEVEL incidents stay live

**Plan:** §6.5.2 steps 2–3; I55; I63.

**Scenario:** the pre-episode level is 6, a drop to 2 raises, then the count oscillates between 2 and 4. A tick at 4 scores z = −4, so it is not a recovery. Each reading of "re-base" fails.
- **If a re-base restarts the held Welford:**
  - every 4→2 is a further anomaly, so every cycle sends a notification;
  - the superseded `lvl:g:k` incidents stay `active`, because I63 exempts only closed incidents from the cap;
  - after 256 incidents the alert reaches `incident_storm` (c461564 `:565-567,:599,:608-617`), and per-key notification stops with no exit.
- **If the Welford runs "since its latest incident":** the oscillation widens σ to about 1. A later drop to 0 then scores about −2, a held tick, and is silent for the warning-capped peers.

**Fix:**
- Test further anomalies against the episode's running extreme in the raising direction, and never let a partial return widen it.
- Close a superseded incident as `closed(superseded)`.
- Add the fixture `level_oscillation_bounded_notifications`.
- I35's claim that the held-level rule "changes nothing about what the incumbent alerts on" is inaccurate: it decides when the incumbent notifies.

### MEDIUM 2. Quarantined NOVELTY entities stay suppressed

**Plan:** §6.4.5 says a quarantined item is "never folded into any normal-behaviour fit", yet also that the seen-set is "what stops it re-alerting". See also §6.6.

**Code:**
- `service-baseline.js:836-863`: novelty is the latest census minus (window history ∪ seen-before), checked at `:860`.
- `novelty-seen-set.js:6-8`: entries are kept 30 days past `last_seen`.

**Scenario:**
1. A LaunchAgent raises `service.appeared`.
2. The operator labels it `confirmed_incident` and removes it.
3. The attacker re-installs the same entity within 30 days.
4. No novelty claim is made, so nothing alerts.

**Fix:** drop quarantined keys from both suppression sets, so a reappearance opens a new episode and notifies. Add the fixture `novelty_quarantined_entity_reappears_alerts`.

### MEDIUM 3. C0.1b cannot be built as written before C1a, and the branch has already shipped the blind half

**Plan:** C0.1b; I49; I59; §6.5.3; §14 merge order.

**Code:** `fix/collector-sources-2026-10` @ f668599 and later, which already includes `main`:
- `session-baseline.js:461-489` (from 25aeb89) filters the fold by the current universe, with an honest re-warm-up;
- 6ba7d80 gives session alerts per-universe ids;
- `fact-translators.js:732-738`: with no usable multiplexer, the census is `partial`;
- `census.universe_changed` exists on no branch.

**Scenario:**
- Moving tmux aside while screen is present creates a new `v1:screen` universe and a new alert id: about 30 hours of blind re-warm-up.
- With no screen present, the census stays `partial` and the stale-census freeze applies.
- Neither case raises anything, and both ship before C1a under §14's merge order.

**Fix:**
- Make the notice a merge gate of C0.1b. It is a fixed, additive rule on a `binary_availability` change and needs no C1.4.
- State that §6.5.3 lands at C1a.

### MEDIUM 4. C1 and C1a depend on artifacts the sequence never builds, or builds later

**(a) The digest.**
- No producer exists on `main` or on either branch tip, and no §14 step builds one.
- It has no delivery semantics: push or pull, or whether it counts against N per week.
- Yet these all depend on it:
  - I63 (`storm_listed_in_digest`, a C1 merge gate);
  - DA3's "notification, not confirmation";
  - §6.2's bulk closing of EVENT alerts;
  - §6.5.2's list of open LEVEL episodes;
  - I54, I58 and I59.

**(b) The Q5 values.** C3b proposes:
- the label, provisional-label, drift and discontinuity budgets;
- the pending and quarantine caps;
- R.

C3b comes after C1a, yet C1a "admits by label from day one" and C1.4 needs the caps.

**Fix:**
- Add a C1 digest step: pushed, and not throttled by N.
- Move that Q5 subset into C1a's "Needs", with fail-safe defaults until it is ratified: zero unattended budget, a minimal label budget.

### MEDIUM 5. A forged label closes an alert silently

**Plan:**
- §9 (b)–(c): the label budget bounds admissions only.
- §6.0: quarantining labels close incidents.
- CC7: EVENT and NOVELTY alerts close only by label.
- §12: the digest lists `admitted_unexplained` admissions, not closures by label.
- I20: the novelty drift budget counts only unexplained admissions.

**Code:** c461564 `:505`: a `recovered` or `suppressed` incident is never retried. C1.1's `closed` is unspecified against this check.

**Scenario:**
1. A same-UID attacker installs a LaunchAgent; it sends one notification.
2. The attacker appends a `suspicious` label for that alert to `labels.jsonl`.
3. The alert closes. No budget is charged, and no digest line appears.
4. With MEDIUM 2, the entity never re-alerts either.
5. A close after a failed delivery would also cancel the retry.

**Fix:**
- Put every closure and every label admission in the digest, with its source.
- Charge every label, not only admissions, to the label budget.
- Never let a closure cancel an undelivered incident.
- Count every novelty admission toward the drift budget.

## LOW

1. **`level_open_alert_new_drop_notifies`.** One retired peer gives z = −1/0.5 = −2 (`peer-baseline.js:68,74`), so the alert never raises. Use at least 2 peers. The error is inherited from v3.
2. **Re-score on restart (§6.4.2).** Re-scoring assumes detectors are idempotent, but evaluation mutates detector stores (`daemon.js:1575-1578`). Complete step 2 from the journal payload instead. Also define what happens when a journal append fails (ENOSPC has been seen on the dev host): raise anyway, and open a discontinuity.
3. **C1a migration.**
   - An open `default` incident becomes a new `lvl:` key in the same active episode. That sends a duplicate notification (c461564 `:597-600`) and leaves `default` live.
   - The migrated snapshot comes from a window that has already folded the alarmed ticks (`session-baseline.js:394-408`).

   Rekey in place, and take the snapshot from the ticks before `first_seen`.
4. **"Inside the certified span" (§6.4.3).**
   - The ledger keeps only `last_committed_pass_id` (`fact-store-integrity.js:54,493`), so each entry must carry its pass time.
   - Check the span only when the checkpoint folds; otherwise rebuilding a 30-day episode fails.
   - Limit the "incident with no journal entry" trigger to open incidents.
5. **Drift displacement is unsigned (I20/I61).** A rise in sessions moves the drop trigger up and trips an excursion. Charge only the displacement that reduces sensitivity, per rule.
6. **The software_change example contradicts I57.** §6.6 and §6.5.3 give "a learned software_change model mapped to `service.appeared`" as an example, but I57 requires the same kind, target and universe. Reword it as a service-appearance learner conditioned on `software_change`.
7. **CC3-E instance identity can be forged at the same UID.** Restarting tmux under libfaketime can reproduce the old `#{session_created}` values (`tools/sessions.js:39-42`), which yields a fabricated `recovered`. The data stays pending, so the effect is on status only. State it as an evidence limit.
8. **Stale branch tips.**
   - notify-once is now at 71815b5, which still has no `closed` status, and its storm still resets only on a new episode (`:618`). Its README (c461564 `README:286-288`) says acknowledgement ends a storm; the code does not, and the plan reads the code correctly.
   - collector-sources' 6ba7d80 replaces the session `global` id that the plan describes in §6.1 and §6.5.3.

## Closure of prior BLOCKER/HIGH items

| Item | Status | Residual |
|---|---|---|
| v1 Astra 1–4 | Closed | LOW 6 |
| v1 Astra 5 (deadlock, slow poisoning) | Partly closed | HIGH 1, HIGH 2(b) |
| v1 Astra 6–10, 12 | Closed | LOW 4 |
| v1 Astra 11 (census contracts) | Partly closed | MEDIUM 3 |
| v1 Astra 13 (labels, evaluation) | Partly closed | MEDIUM 5 |
| v1 Opus B1, H1–H4, H7, H8 | Closed | — |
| v1 Opus H5 | Closed on the branch, not merged | LOW 8 |
| v1 Opus H6 | Partly closed | MEDIUM 3 |
| v2 B1 | Closed | LOW 7 |
| v2 H1 (identity) | Mostly closed | HIGH 2(a), MEDIUM 1 |
| v2 H2 (absorption as data ages out) | Closed in steady state | HIGH 2(c) |
| v2 H3 (C1a sequencing) | Partly closed | MEDIUM 4 |
| v2 H4 (home for pending state) | Closed for membership | HIGH 2 |
| v3 HIGH 1 | Closed for the journal | HIGH 2 |
| v3 HIGH 2 | Partly closed | HIGH 1, HIGH 2(a), MEDIUM 1 |
| v3 HIGH 3 | Closed | MEDIUM 2. HIGH 1(b) is its flip side. |

The v3 MEDIUMs and LOWs:
- MEDIUM 1, 2, 6, 7 and LOW 1–5: closed.
- MEDIUM 3: closed, apart from LOW 6.
- MEDIUM 4: partly closed (HIGH 2(b)).
- MEDIUM 5: partly closed (MEDIUM 3).

n = 0 BLOCKER + 2 HIGH, following the v1–v3 convention; 5 MEDIUM and 8 LOW are also listed. Not RETHINK: the direction holds, and every finding is a §6 contract fix or a sequencing fix.

VERDICT: NEEDS-REVISION (2)