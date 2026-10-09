# Context plan v5 review — Opus 5.5 (max)

# Context plan v5 review: Opus 5.5 (max)

**Date:** 2026-10-09
**Plan:** `docs/plans/2026-10-06-context-aware-learned-baselines.md` (DRAFT v5, d1a89e4)

**Code checked:**
- `main` @ d1a89e4. Its `tools/` tree is identical to 66d3a2b.
- `feat/notify-once-2026-10` @ 2e208df, the commit the plan cites. The branch tip is now 1e1228e.
- `fix/collector-sources-2026-10` @ 1c2b412, the commit the plan cites. The branch tip is now c062fed.

**Read first:** both v4 reviews, the Operator decisions section (D1–D5) and `docs/design/autonomy-doctrine.md`.

**Method:** read-only; no repo file was modified.

## Answers to the five questions

**1. Are the prior BLOCKER and HIGH findings closed?**
- **Opus v4 H1:** resolved by scope (D5). The held-shift loop is gone. The cost of the recurring dip remains (MEDIUM 2).
- **Opus v4 H2:**
  - (a) Closed for journal truncation, because I55 re-derives the extreme from the alert's keys. Losing the whole directory reopens it (HIGH 1).
  - (b) Partly closed (MEDIUM 1).
  - (c) Closed for open episodes. Not closed when no episode is open (HIGH 1).
- **Astra 1:** closed for the incumbents, because each of 4, 3, 2, 1, 0 is a new extreme. Not closed for context-conditioned learned streams (MEDIUM 3).
- **Astra 2:** closed in the design, apart from the fold predicate (HIGH 1).
- **Astra 3:** closed (LOW 6).
- **Astra 4:** closed.
- **Astra 5:** closed in structure. HIGH 2 and MEDIUM 5 are what remains.
- **Opus M1–M4 and Astra 7–9:** closed.
- **Opus M5:** mostly closed (MEDIUM 6).
- **v4's regime-key fix:** leaves a residual specific to peers (HIGH 3).

**2. Is earned adaptation sound against poisoning, with no approval step?**
- No operator approval step remains. The plan has "no ratification" statements only, and DA is a reviewed doc change.
- The vetoes, the pre-registered adaptive scenarios and membership provenance are all present.
- Gaps:
  - provenance is not kept up to date when an item's disposition changes later (HIGH 2);
  - the drift budget limits the rate of drift, not its total, and the doctrine is not amended to match (MEDIUM 1);
  - one label can lift the vetoes for many items at once (MEDIUM 6).

**3. Any new fabrication or suppression path, or hand-coded behaviour assumption?**
- Laundering and muting through journal loss (HIGH 1).
- Muting through a regime change (HIGH 3).
- A fabricated incident, and a masked drop (MEDIUM 3).
- A fabricated recovery (MEDIUM 4).
- A way round I57 (MEDIUM 5).
- No new hand-written behaviour rule: the running extreme adds no number, and Q comes from D1.

**4. Is the core principle honoured?** In direction, yes. D5 makes the incumbents non-adaptive by design and moves learning to their successors. MEDIUM 2 asks that this trade-off be made decidable. The human is on the loop, not in it.

**5. Is it buildable in the stated sequence?**
- The merge order is sound.
- The input to the C1a gate is a problem (MEDIUM 2).
- The first promotion has no defined anchor (MEDIUM 1).
- The C2 long pole has a hidden dependency (LOW 10).

## BLOCKER

None.

## HIGH

### HIGH 1. Losing the pending directory mutes an incumbent and then re-bases it; ticks that were never adjudicated fold

**Plan:**
- §6.4.4 step 2 (:763): "If no certified point survives, it covers the whole raw window".
- §6.5.1 (:834): any tick with a journal entry is not folded.
- I45 (:202) and §8.3 (:1132): an incumbent's only snapshots are the frozen snapshots of open episodes, carried in the journal.
- I60 (:217): "never turns provisional through exclusion".
- I69 (:226): a pass that "cannot be scored" becomes `excluded(unadjudicated)`.
- §6.4.4's attacker analysis (:781-785): "never a laundered tick … never a stopped or muted detector".
- §16.2 item 3 (:1402).

**Code (main):**
- `session-baseline.js:842` computes the Welford over every current tick group, even during a cold-start lockout.
- `:92`: the lockout lasts 6 new ticks.
- `:879-887`: during a lockout, the detector returns no candidates and no coverage.
- `:410` with `:654`: below 30 folded ticks the detector is provisional and emits no `count_drop` candidate.
- The peer fold has the same shape (`peer-baseline.js:523-534`).

**Scenario:**
1. No session episode is open. A same-UID attacker runs `rm -rf learned/pending/session/`, removing the journal and the checkpoint.
2. The next pass finds a discontinuity with no surviving certified point. One `unexplained_discontinuity` item covers the whole raw window, and the fold excludes every tick.
3. With no open episode, there is no snapshot for I60 to serve, so `session.count_drop` goes provisional. The integrity notice recovers one structural interval later.
4. The attacker kills 3 of 5 sessions and keeps them dead. What happens next depends on how a provisional tick is read, and both readings are wrong:
   - If a provisional tick counts as "never alarmed" and folds, the incumbent re-establishes at 2 sessions after 30 ticks (about 30 hours of silence). The kill is now the baseline.
   - If a provisional tick "cannot be scored" (I69), it never folds, and the detector stays provisional forever.

**Comparison with today.** Today the equivalent single write (deleting the detector store) causes a 6-tick lockout. The Welford still covers the full 30-day window (`:842`), so after the lockout the held kill raises CRITICAL. Today an attacker must keep deleting the store to keep the detector muted; v5 gives the same result for one write. §16.2 item 3's "exactly as a corrupt detector store does today" is therefore wrong, and the claims at :781-785 are false.

**A second way in.** The same negative predicate also folds ticks that no established detector adjudicated:
- lockout ticks, which an attacker can re-arm every tick (`:765-808`);
- a failed-append pass (:717) once its `alerts.json` record is deleted, which :753 says is not a discontinuity.

**Fix:**
- Make the fold predicate positive. Fold only ticks that an established detector adjudicated clean, at or below the verified `scored_through` watermark, plus first-install warm-up.
- On a discontinuity, re-derive incumbent membership and the snapshots of open episodes by replaying the raw window in order. The fold is a pure function of the tick groups (`:376-416`). Do not exclude the whole window.
- Keep a serving reference outside the journal for when no episode is open.
- Add the fixtures `pending_dir_wiped_no_episode_incumbent_stays_established`, `lockout_ticks_never_fold` and `failed_append_tick_never_folds`.

### HIGH 2. A version's training membership is fixed when it is fitted, but its items' dispositions keep changing

**Plan:**
- §6.3.1 items 2, 4 and 5 (:636-651). At :648 it claims "What was evaluated is exactly what is admitted, so there is no laundering path".
- §6.0 rows :447, :452 and :457.
- "Rebuilds the affected statistics" (:622, :457), which is undefined for a learned version.
- §6.4.5 (:800-802) and I72(d) (:229): quarantined data never enters a normal component.
- P7 (:124): labels "correct" learning.

**Scenario:**
1. A notify-only session lineage fits candidate v7 on day D. Its membership includes pending departures from a nightly kill pattern. No other source raised and the context was normal, so no veto applies.
2. v7 passes the replay within its budget and is promoted on D+1. Its items are admitted, and their alerts close as `closed(admitted_earned)`.
3. On D+2 the operator labels the episode `confirmed_incident`. The items are quarantined, but nothing demotes v7, so they stay in its normal component.

On a C7b host, that lineage is what alerts. The same thing happens if:
- the label arrives between the fit and the promotion: the quarantined item is skipped at admission, but it remains in v7's parameters;
- a member item is compacted to `excluded` before promotion;
- a slower stream later vetoes a member item before promotion.

This is the Astra v4 3 class.

**Fix:**
- At promotion, refuse any candidate with a member item whose disposition or veto status has changed since the fit.
- On quarantine or revocation of an admitted item, demote every version whose membership includes it to the latest earned snapshot that excludes it, with a notification. Define "rebuild" for learned versions as exactly that.
- Add the fixtures `earned_promotion_member_quarantined_after_fit_refused` and `confirmed_incident_on_admitted_item_demotes_version`.

### HIGH 3. All peer regimes share one alert row, and R3 recovers the whole row at once

**Plan:**
- §6.1 LEVEL row (:480): the regime goes in the key "where the alert id does not already carry it".
- :489: the shared `v2:vpn` id.
- §6.5.3 (:883-885): recovery happens only in the raising regime, and an open episode freezes across a regime change.
- I59 (:216).
- :548: "Nothing about an open alert mutes its detector".

**Code:**
- `peer-baseline.js:53-60`: every marker-backed regime gets the id `v2:vpn`.
- `:965` and `:1014-1016`: drop coverage reports that one id whenever the current regime is established.
- @ 2e208df `alert-store.js:695-705`: recovery marks the alert and every one of its incidents `recovered`.
- `:605-608` and `:617`: after a recovery, the next candidate starts a new episode with an empty incident map.

**Scenario:**
1. In regime A, peers drop from 6 to 4. Incident `lvl:A:4` is notified, and the episode freezes.
2. A VPN source becomes unavailable and stays that way, so the regime is now B. B re-warms and becomes established.
3. Either reading of §6.5.3 then goes wrong:
   - If the detector reports `v2:vpn` as evaluated in B (today's behaviour), R3 recovers A's episode on B's evidence. That is the fabricated recovery that `cc_l_incumbent_other_universe_no_recover` forbids.
   - If it withholds the id while A's episode is open (the literal §6.5.3), the row never recovers. B's first drop, `lvl:B:3`, notifies. The count is then restored, but the row cannot recover. Every later drop to 3 or more in B is either a frozen tick or an already-confirmed key (`:571`), so it is silent indefinitely.

No fixture covers restoring the count and then dropping again. Sessions avoid this problem only because 6ba7d80 puts the universe in the alert id.

**Fix:**
- Give peers per-regime alert ids, mirroring 6ba7d80, and freeze the old `v2:vpn` id as R8 froze `global`. Land this at C1a. Per-incident recovery in R3 is the alternative.
- Add the fixture `level_regime_new_regime_restore_then_repeat_drop_notifies`.

## MEDIUM

### MEDIUM 1. The drift budget limits a rate on a moving anchor, DA never amends doctrine :110-116, and two claims are false

**Plan:** DA1–DA3 (:86-99) cite doctrine :61-68, :103, :126-129 and :134 only. See also I20 (:177), I72(a) (:229), §8.3 (:1135-1138) and §6.3.2 (:661-663, :669-672).

**What the doctrine requires.** :114 asks for a cumulative drift budget "anchored to an *attested* baseline". In v5 the anchor is the last earned snapshot, which moves with every promotion. The sum over the horizon H is therefore a rate (budget per H), as :669-672 concedes. After DA merges, the doctrine text would still forbid what C7a and C7b do.

**Further gaps:**
- (a) The first promotion has no anchor under I20, and neither does a re-earn after a lost ledger (:1137). A re-earned lineage starts with an empty H window. So corrupting the learned store buys a fresh budget each cycle, at the cost of one `memory_lost` notice. "Never reset by a loss" is false, and Opus v4 H2(b) is only partly closed.
- (b) The snapshot cap (I3) can evict the first earned snapshot, so the walk cannot always be reversed back to its origin.
- (c) The plan does not say whether a demotion refunds its displacement to the H window.

**Fix:**
- Have DA amend :110-116 explicitly, stating what remains possible.
- Mirror a lifetime displacement ledger in the hash-chained transition log. If both copies are lost, treat the H window as spent.
- Define what the first promotion is measured against.
- Exempt the first earned snapshot from the cap.
- State what a demotion does to the ledger.

### MEDIUM 2. The incumbents' interim noise is measured, not bounded, and the data for measuring it is probably gone

**Plan:** §6.5.2 (:869-873), §14 C1a gate (:1315), §16.2 item 1 (:1400), C4a (:1319) and §10.7 (:1214, where "skip" is a valid outcome), §1.2 (:258).

**Why the bound is not real:**
- The C1a gate publishes a count, with no pass criterion and no consequence.
- Its input is the 2026-10-05 laptop history. That host held about one day of raw history at the time, and nothing in §14 exports it.
- The peers' recurring dips are not bounded until C8.
- If C4a says skip, the default-on incumbents never adapt and keep re-notifying for good. The plan does not state that outcome.

**Fix:**
- Export the history now (HMAC'd), or define the gate on C2's first weeks.
- Give the gate a reviewed default criterion and a stated consequence.
- Quantify the peer case, and consider bringing the peer successor into C5. C4a(ii) already prototypes a tailnet-state model.
- State what happens to the incumbents if C4a says skip.

### MEDIUM 3. The running extreme is a raw count, which does not track surprise for context-conditioned learned LEVEL streams

**Plan:** I55 (:212). §6.1 (:480) applies it to every LEVEL stream. The justification at :861 holds only for a single, context-free snapshot. See also §7.1 (:941), §11.2 (:1241) and C5 (:1321).

**Scenario:**
1. C5's occupancy successor raises at 17:00 on a drop from 8 to 5, so the extreme is 5. CC3(e) keeps the episode open.
2. At 03:00 the count is 1, which is normal for 03:00. But 1 is beyond the extreme, so `lvl:r:1` notifies: a fabricated "further deterioration".
3. The next day at 17:00 an attacker drops the count from 5 to 2. That is very surprising at 17:00, but 2 is not beyond 1, so this stream stays silent.

**Fix:**
- Define the extreme on the predictive tail probability: a tick opens a new incident only if it is surprising in its current cell and more surprising than every earlier incident of the episode. Keep the raw-count form for the incumbents only.
- Add fixtures for both directions.

### MEDIUM 4. CC3-E's "every open incident" test becomes vacuous once I63 closes delivered EVENT incidents

**Plan:** CC3-E (:516), I63 (:220), §6.1 (:495).

**Scenario:**
1. A departure incident (4 of 5 sessions killed) is delivered, and closes as `closed(event_delivered)`.
2. On the next quiet interval no incident is open, so the test passes vacuously.
3. The alert id is reported as evaluated, and R3 recovers it (`alert-store.js:695-705` @ 2e208df). This is the v2 B1 fabrication, reintroduced by I63.

**Fix:**
- Define CC3-E over the episode's cumulative set of departed sessions, whose authoritative copy is in the journal's `raise_ref`, delivered incidents included.
- Add the fixture `cc_e_delivered_incident_quiet_interval_no_clear`.

### MEDIUM 5. `earned_promotion` has no limit on which lineage's items it can admit

**Plan:** §6.0 (:447). §6.3.1 (:637) does not restrict membership to the lineage's own targets. §6.6 (:914) conflicts with CC7 (:532), §11.1 (:1222-1223) and I57 (:214).

**Scenario:** a C7a notify-only promotion whose membership includes an incumbent's pending items can:
- close the incumbent's LEVEL episode, which then re-raises and re-notifies;
- close incumbent NOVELTY alerts without I57's stream map or its daybreak re-gate.

That is a way round I57, and a notify-only lineage changing an incumbent's state.

**Fix:**
- Restrict membership to the candidate's own mapped target streams.
- Admit or close incumbent NOVELTY items only under I57's gates.
- Never close an incumbent LEVEL episode by promotion.

### MEDIUM 6. The label budget counts labels, not what they cover, and labels bypass the §6.3.2 vetoes

**Plan:** §6.3 item 4 (:617). §9 (:1165) allows a label to cover a whole pending window, applied in bulk. See also :1170 and §16.1 (:1385).

**Scenario:** one forged `benign` label over a pending window makes every item in that window admissible without the cross-stream or anomalous-context vetoes. That includes the peer response to an unexplained `tailscale down` at 03:00, and it costs one unit of a 50-per-week budget. The plan also does not say what happens to a label held back for exceeding the budget.

**Fix:**
- Charge the budget per admitted item, or let labels speed admission without lifting the vetoes.
- Define when a held label is released.

### MEDIUM 7. D1's pending novelty has no bound on active alerts

**Plan:** §6.6 (:910, :917). §16.1 (:1388-1389) admits 8 entities per family per 30 days, and none before DA (:1315). Compaction leaves the alert unchanged (§6.0, :454). Each entity has its own alert id (:497).

**Code:**
- @ 2e208df `alert-store.js:458-470` rewrites the whole alert collection on every write.
- `fact-families.js:261-265` caps entities per census at 1,000 for services and 200 for lineage edges.

**Scenario:** on an active host, new lineage edges and services exceed 8 per 30 days. Each one keeps a permanently active alert. `alerts.json` grows without bound and is rewritten every tick: the Astra 9 problem, at the level of alerts.

**Fix:**
- Bound active novelty alerts per rule, for example with one backlog alert per rule that carries a count.
- State what compaction does to an entity's alert.

## LOW

1. **The spike bound is misstated (:863).** A superseded incident closes and stops counting as live (:851), so the live cap never binds. A sustained benign rise notifies on every new maximum, up to the source's peer cap.
2. **`census.universe_changed` (:316, :886-888) has no closure rule.** It merges before C1.1 adds `closed`. With one alert id and one incident per transition, enough binary flips put it into a permanent storm. Give it the `recovered(edge_rearm)` exception (I42), or key it per transition and close each incident on delivery.
3. **Stale branch facts:**
   - At 2e208df, acknowledgement already ends a storm (`alert-store.js:935-941`). That contradicts :50 and :468.
   - notify-once is now at 1e1228e. Commit bf25f22 changes `:570`, and acknowledgement has moved to `:975`.
   - The collector branch is now at c062fed. Commits 10e9673 and c062fed extend writer-set trust to local group membership (`binary-resolver.js`), so C0.1 needs re-citing, and that branch's daybreak should cover the change.
4. **The earned path's persistence is unstated.** §11.1 says "on the existing ladder", but `model-ladder.js:1-9` is pure, and `promotion-store.js` is the `learned approve` flow. State that C7 has its own approval-free store.
5. **Every serving-version promotion pushes a notification (:650).** Daily refits would mean a push per lineage per day. Send routine refits to the digest instead.
6. **Discontinuity recovery honours the most restrictive disposition from the unverifiable label log (:761).** So forged quarantining labels that were held back or never ingested take effect without I27's charge or notice. The harm is limited to denying learning.
7. **On a replaced host, the incumbent-in-shadow's C1a journaling is unstated (:1240).** Without it, a rollback (:1237) resumes from an incumbent that has habituated.
8. **The runtime replay is bounded by raw retention,** about 2.6 days at worst-case volume (§1.6). §16.2 item 4 covers only the C3b corpus. Define the per-host minimum-evidence bar against what is retained.
9. **I74 needs a read-side exclusion.** The seen-set is folded by the retention pass (`novelty-seen-set.js:10-18`), so a quarantined entity must be excluded when `service-baseline.js:836-863` and its siblings read the sets. Say so.
10. **"Start C2 now" (:1302-1307) depends on C0.8 and C0.9.** C0.8's boot-identity primitive does not exist on `main` (only comments at `fact-store-integrity.js:118,542`), and C0.9 needs measurements on a real laptop. Record the raw boot id from day one, as I68 does for clocks, and verify it later.

n = 0 BLOCKER + 3 HIGH, following the v1–v4 convention. 7 MEDIUM and 10 LOW are also listed. This is not RETHINK: the direction holds, and every finding is a §6 or §11 contract fix or a sequencing fix.

VERDICT: NEEDS-REVISION (3)