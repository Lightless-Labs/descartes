# Context plan v3 re-review — Opus 5.5 (max)

# Context plan v3 re-review: Opus 5.5

**Date:** 2026-10-07
**Plan:** `docs/plans/2026-10-06-context-aware-learned-baselines.md` (DRAFT v3, commit a9a2856)

**Code checked:**
- `main` @ a9a2856
- `feat/notify-once-2026-10` @ 25cf225
- `feat/fact-store-capacity-2026-10` @ 2dce005
- `fix/collector-sources-2026-10` @ 3c18739
- this Darwin 25.2 host

**Method:** I read the v2 re-review, the v1 Astra review and the F-class opinions, then v3 in full, and checked every load-bearing claim below against code or the host. This was read-only: no repo file was modified. One scratchpad file was written: `/private/tmp/claude-502/-Users-thomas-Projects-lightless-labs-public-descartes/be295191-32e2-4267-93c6-9cf9026e593c/scratchpad/scutil-nc-list.txt`.

## Answers to the four questions

### 1. Are the prior BLOCKER and HIGH items genuinely closed?

- **Closed in the design:** B1 and H3.
- **Mostly closed:** H1 and H2.
- **Partly closed:** H4.

The residuals all sit in §6:
- what an open LEVEL alert does under notify-once (HIGH 2);
- what happens to pending data when an episode ends (HIGH 3);
- how the pending ledger's integrity actually works (HIGH 1).

The closure table is at the end.

### 2. Are there new hand-coded assumptions or fabrication paths?

**No new B1-shaped path:**
- No learned EVENT alert can recover on a quiet interval, or on restored names across a boot.
- F1 never recovers, closes or admits (CC8, A6).
- Shadow learners have no write path to alerts, coverage or pending state.

**v3's own arbitration adds three paths:**
- **Laundering (HIGH 3).** A `recovered` episode, or one closed as `confirmed_incident`, drops its ticks out of the pending store, and they then fold into the baseline.
- **Silence (HIGH 2).** A LEVEL alert that never recovers or closes mutes its host-global detector.
- **Learning denial of service (HIGH 1).** One same-user write freezes a family's adaptation, with no defined way back.

**Smaller paths:**
- a name-keyed departure recovery that the plan rejects elsewhere (MEDIUM 1);
- bounded-quiet admission of event data, which goes beyond D1 and DA3 (MEDIUM 2);
- admission authority granted at C7a without DA3 (MEDIUM 3);
- regime re-warm with no arbitration (MEDIUM 5);
- new unclassified numbers (MEDIUM 7).

**The areas the task singled out:**
- **F-class use** is clean apart from MEDIUM 1 and the F3 wording (LOW 1).
- **Default-on shadow** isolation is well specified (I47, `shadow_no_effect_on_incumbents`). Only a disk bound is missing (LOW 4).
- **Per-host replacement envelope.** C7b is gated on DA1 and per-host ratification. The earlier authority creep is at C7a (MEDIUM 3). Also, §11.2 says "a regression is visible" for the incumbent kept in shadow, but names no place where its logged alerts surface. C7b's gate should require one.

### 3. Is the core principle honoured?

Yes in direction, and mostly in detail:
- R4–R10 are absent; Appendix A checks out.
- Context is data, and structure is soft.
- Time-to-override is pinned.
- F is narrowed to OS semantics.
- Memory grows.

The exceptions:
- HIGH 2 makes a per-item label the only way to keep a LEVEL detector alive. That is the per-item-consent ("UAC") ditch (`autonomy-doctrine.md:39-50`).
- Ratifying an opaque per-host anchor has the same shape (MEDIUM 4).
- MEDIUM 2 extends on-host sticky adaptation without saying so.
- MEDIUM 7's numbers are unclassified, against §0.4's own rule.

### 4. Is it buildable in the stated sequence on this codebase?

The sequencing holds:
- C1a after the capacity branch (CAP) is right. CAP changes the session, peer and service baselines, `alert-store.js` and `daemon.js` (+715/−190 lines, verified).
- The C1 → C1a → C5 dependencies are consistent.

Not buildable as written:
- **§6.4's stamp rule.** The seen-set stamp rule does not fit the pending store's writer (HIGH 1).
- **C0.1b ownership.** C0.1b gives sessions regimes "as for peers". That needs regime filtering inside `session-baseline.js`, which CAP also rewrites, yet C0.1b is assigned to the collector branch before merge. Name the owner and the merge order.
- **Overlapping branches.** The branches touch the same files, so every branch line citation in the plan will move, and the C1a daybreak gate must re-verify after the merges:

  | File | notify-once | CAP | collector-sources |
  |---|---|---|---|
  | `alert-store.js` | about 264 lines changed | about 78 | — |
  | `daemon.js` | about 55 | about 445 | — |
  | `peer-baseline.js` | — | changed | changed |

## Claims verified as stated

**notify-once @ 25cf225:**
- `alertEpisodeKey` is at `alert-store.js:77-79`; the status list at `:220`; `newEpisode` at `:383-385`; `newIncident` at `:399`; the 256-key overflow at `:401`; recovery at `:442-451`.
- `normalizeAlertRecord` keeps `diagnostics` (`:269`), so a display copy of `raise_ref` survives.
- README:292-312: producers declare incident keys; session and peer deviations use `default`; churn is keyed per transition.

**main:**
- The status list is at `alert-store.js:200`, so the corrected citation is right.
- `daemon.js:834-850` and `:972-974`.
- `session-baseline.js:407-438`, `:661-686` and `:897-915`.
- `service-baseline.js:455-476`.
- `calibration.js:245,293,306`; `tuning-store.js:413,427`; `tuning-authority.js:390`.

**capacity @ 2dce005:**
- `fact-store.js:31`: one 30-day retention for every family.
- `fact-families.js:240-249`: the per-family budgets.
- `fact-families.js:335-344`: the T8 floor has no records-per-interval term.
- `novelty-seen-set.js:371`: a seen-set is valid only if stamped to the latest committed pass.
- `fact-store.js:455-477`: the seen-set is folded inside the retention pass.

**collector-sources @ 3c18739:**
- `censusStateFor` is at `fact-translators.js:728-731`; `binary_availability` at `:751`; the not-found statuses at `tools/sessions.js:153,179`.
- **Opus H5 re-verified independently.** On this host's `scutil --nc list`, `parseScutilNcListDetailed` returns 4 services and 0 unparsed lines, with Tailscale flagged `is_vpn` and `is_tailscale`. `main`'s parser returns `[]`.

**Host:**
- `kern.bootsessionuuid` and `kern.osversion` (`25C56`) are readable without privileges.
- The last boot was 2026-09-04.
- `kern.sleeptime` = `kern.waketime` = 0.

**§7.2 arithmetic:** 6/1513³ ≈ 1.73e-9, against Φ(−6) ≈ 9.87e-10.

## BLOCKER

None.

## HIGH

### HIGH 1. The pending ledger's fail-closed state has no exit, and its stamp rule trips on ordinary operation (v2 H4 is not closed in the design)

**Plan:**
- §6.4, lines 439-447:
  - The store is "lineage-stamped to that family's fact ledger exactly as seen-sets are", and the stamp is validated against the ledger the reader just read.
  - Two independent records must agree.
  - On any discontinuity, everything since the last certified state becomes pending and adaptation freezes. `context_model` and `bounded_quiet` are disabled "until continuity is re-certified", and an integrity notice is raised.
- Nothing defines re-certification, and I44 (line 139) has no re-certification fixture.

**Code:**
- A seen-set is folded *by the fact-store retention pass*, in the same pass as the append (capacity `fact-store.js:455-477`).
- A read is valid only if `ledger_pass_id === last_committed_pass_id` (`novelty-seen-set.js:371`).
- Its way out of a loss of continuity is an automatic re-seed (`:26-35`).
- The retention pass cannot know detector verdicts: those exist only after the pass. Alert transitions will come from the daemon's single alert writer (C1.1; notify-once `alert-command-queue.js`).

**Scenario:**
- **(a) As written.**
  - If detectors write the store (they are the only writers that know the verdicts), the next structural tick commits pass p+1 before the detectors run.
  - Every structural tick then reads as a lineage mismatch: a permanent fail-closed state, with an integrity notice per tick.
  - The alternative is that the implementer quietly relaxes the rule, which reopens H4.
- **(b) Even built correctly, a write order is needed.** A crash, power loss or shutdown SIGKILL between the pending write and the transition append leaves the two records disagreeing. Adaptation then freezes, with no defined way back.
- **(c) An attacker.**
  - One same-user write (truncating `learned/pending/session/`) disables `bounded_quiet` and `context_model` for the family indefinitely.
  - Every later observation becomes pending, and the incumbent stays pinned to an aging snapshot.
  - That is a denial of service on learning, and it is cheaper than the laundering H4 described.

**Fix:**
- The family retention pass carries the store forward and re-stamps it.
- Detector verdicts go into a hash-chained pending journal that cites the pass id it scored.
- Write the journal first, then the transition. On restart, re-score the latest tick to rebuild a missing verdict.
- Re-certification is automatic once the chain re-verifies over a fresh complete pass, and keeps "everything since the break is pending". It is never a re-seed that drops pending marks.
- Add the tests `pending_restamped_each_pass`, `pending_crash_between_writes_rebuilt` and `pending_recertifies_after_clean_pass`.

### HIGH 2. C1a leaves LEVEL alerts active indefinitely, and notify-once then silences that host-global detector

**Plan:**
- LEVEL streams use `incident_key = default` (§6.1, line 345).
- Incumbent recovery needs the observation to be unsurprising under the pre-episode snapshot (§6.5, line 459).
- A sustained shift exits by label or by bounded quiet (line 460).
- CC7 (line 373): a quiet interval never closes an alert. Only novelty closes by explanation, and Q7 asks about EVENT alerts only.
- CC4 (line 368) says "a new incident under the same id still notifies". That is true only for EVENT streams.
- The "Stated consequence" (line 378) calls a frozen LEVEL alert intended.
- The digest (§12, line 786) lists open EVENT alerts only.

**Code:**
- notify-once `alert-store.js:351-352` @ 25cf225: once `default` has been notified, a further raise notifies only if its severity exceeds the highest severity already notified.
- Branch README:305-306: session and peer deviations use `default`.
- `peer-baseline.js:702,744`: both peer rules hard-cap severity at `warning`, so escalation is impossible.
- `session-baseline.js:677`: there is one `session.count_drop` identity per host (`global`).

**Scenario:**
1. The operator permanently retires one WireGuard peer, or reopens only 3 of 5 tmux sessions after a reboot.
2. `peer.count_drop` / `v2:vpn` (or `session.count_drop`) raises and notifies once.
3. It never recovers, because the count never returns to the pre-episode snapshot. It never closes:
   - before DA3, only a label can close it;
   - after DA3, bounded quiet admits the new level, but CC7 forbids closure.
4. Weeks later an attacker cuts the remaining VPN peers. The candidate has the same id and the same key, so `notificationDue` is false and nothing is sent.
5. For sessions the same holds once a critical has been notified.

**Effect:** before C1a, aging out of the raw window recovered the alert and re-armed it; that was v2 H2's silent absorption. C1a replaces it with silent muting. Keeping the detector alive then needs a per-item label, which is the per-item-consent ditch.

**Fix:**
- Admitting a sustained shift, by label or by bounded quiet, closes the LEVEL alert with a reason, which re-arms it.
- Alternatively, scope the LEVEL incident key to the anchor generation, so that each admission starts a new key.
- List open LEVEL alerts in the digest.
- Add the tests `level_admitted_shift_rearms` and `level_open_alert_new_drop_notifies`.

### HIGH 3. What happens to pending data when an episode recovers or closes without admission is contradictory, and the literal §6.4 design launders it

**Plan:**
- §6.4, line 440: the store holds content "per **open** episode".
- Line 441: pending membership means `activated` or `incident_opened` "without a matching `recovered`, `closed` or `admitted`".
- This contradicts §6.0 lines 329-330: "Recovery never admits", and `suspicious` / `confirmed_incident` "close without admitting".
- It also contradicts §6.3 line 408: pending observations are not folded until they are admitted.

**Code:**
- The incumbents recompute from the raw window on every call and fold every complete tick that is not excluded (`session-baseline.js:407-438`, `peer-baseline.js:537-602`).
- C1a's exclusion can only come from the pending ledger.

**Scenario:**
- **(a) Recovery.** An attacker keeps 2 of 5 sessions dead for 10 hours, then restarts them. Any LEVEL recovery has the same effect:
  1. The alert is recovered, so the episode is no longer open.
  2. Its 10 alarmed ticks are now in no exclusion record.
  3. The next recompute folds them. The standard deviation widens, and the next kill scores as less surprising. This is the unarbitrated fold C1a exists to stop.
- **(b) Confirmed incident.** The operator labels an episode `confirmed_incident`. It becomes `closed`, its pending membership ends, and the attack's ticks fold into the baseline.
- **(c) The other reading also fails.** Suppose the ticks are kept as closed but unadmitted:
  - bounded quiet can never reach them, because they are no longer pending items;
  - they accumulate, one episode per reboot, until `pending_overflow_fails_closed` (I3) trips the freeze in HIGH 1;
  - if the store keeps them while the transition log drops them, the two-record check fails on every recovery.

**Fix:**
- Give observations their own lifecycle, separate from the alert's status: pending, admitted or quarantined.
- `recovered` leaves the observations pending.
- `closed(suspicious|confirmed_incident)` moves them to quarantined: never folded, but retained for challengers within the I3 caps.
- Derive pending membership from the observation records, not from alert transitions.
- Add the tests `recovered_episode_ticks_not_folded` and `confirmed_incident_ticks_quarantined`.

## MEDIUM

### MEDIUM 1. Within one boot, departure recovery is keyed on names: a same-name recreation "restores the departure"

**Plan:**
- CC3-E (lines 363-366) and the gate test `cc_e_recreated_same_name_scored_as_churn` (line 386) expect "The departure recovers".
- This contradicts:
  - §6.0's EVENT definition (line 322: "An event cannot un-happen");
  - §7.8.5's reject list (line 640: "matching names prove recovery");
  - Astra's F-class opinion §2: "Returning names alone cannot authenticate restoration".

**Code:**
- The entity key is a hash of the multiplexer and the session name (`fact-translators.js:651-654`).
- The creation fingerprint is a separate value (`:666-673`).

**Scenario:**
1. Four tmux sessions are killed at tick t, and the departure alert raises.
2. At t+1 they are recreated under the same names.
3. The departure alert is recovered. That re-arms it, and under HIGH 3 it also releases the pending data.
4. Visibility now rests on the churn stream finding four recreations surprising. A host that recreates sessions by script learns that it is not.

**Fix:**
- Within one boot, recover a departure only when the same instances return (the same entity key and the same creation fingerprint). That is the case where the census itself was wrong.
- A recreation leaves the departure frozen until a label, and the churn is scored.
- Alternatively, reword §6.0 so that a departure alert asserts "named entities absent", and remove the contradiction with the reject list.

### MEDIUM 2. The Q7 default admits event data under bounded quiet while the alert stays open, beyond D1 and beyond DA3's stated scope

**Plan:**
- CC7 (line 373) and Q7 (line 845): bounded quiet "admits their pending data" but does not close the alert.
- DA3 (line 48) covers novelty, plus an extension to the *incumbent statistical folds*. It does not cover learned EVENT streams.
- The bounded-quiet path (lines 413-414) requires that "the pending item persists, with no further anomaly", which is undefined for an event.

**Doctrine:** `autonomy-doctrine.md:101-104`: never adapt a model to unattested change.

**Scenario:**
1. A kill of 4 of 5 sessions raises an alert, and no further departures follow for the bounded-quiet period.
2. The kill is admitted as `admitted_unexplained` into that cell's departure hazard. It is charged to the budget and gets one digest line, while its alert is still open and unexplained.
3. Once the learner is promoted, the next identical kill in that cell is less surprising.
4. The model now treats as normal what the open alert still calls unexplained.

**Fix:**
- Make learned EVENT streams label-only until DA3 explicitly covers them and Q7 is answered.
- If bounded quiet is allowed for them, it should close the alert with a reason.
- Define "no further anomaly" per stream kind.

### MEDIUM 3. Notify-only promotion at C7a grants admission authority over the incumbents, without DA3

**Plan:**
- §14 C7a (line 810): the promoted learner "becomes a `context_model` explanation source". Its gate is the ladder plus a daybreak re-gate, with no dependency on DA3.
- §6.3 item 1 (line 411) and §6.6 (line 472): a `context_model` source admits pending data and closes novelty alerts.
- §11.1 (line 740) says a notify-only learner "cannot suppress anything".
- "For that stream" (line 411) is undefined. C5's learner models departures, arrivals and reboots (EVENT); the incumbent `session.count_drop` is an occupancy LEVEL stream.

**Doctrine:** `autonomy-doctrine.md:61-68`: on-host, the authority ceiling is additive alerting.

**Scenario:**
- Either the learner abstains forever for the incumbents, so C7a adds no explanation path, or it admits occupancy ticks on the strength of a departure model.
- Admitting them widens the incumbent's baseline, which reduces what alerts, with neither DA3 nor DA1 behind it.
- Separately, a successor challenger fitted on pending data with soft weights can, once promoted, explain its predecessor's pending data. Only the drift budget bounds that.

**Fix:**
- Make explanation authority depend on DA3.
- Map learner streams to incumbent rules explicitly: same stream kind, same target.
- Narrow §11.1's sentence.

### MEDIUM 4. Incumbent anchors depend on a per-host ratification, and what happens without it is undefined

**Plan:**
- §6.5 (line 457): the operator ratifies the anchors "once per host".
- I45 (line 140).
- §9 bound (b) (line 698): "the drift budget, which now exists from C1a on".
- §16 (line 852).

**Scenario:** in each of these cases there is no anchor, and so no drift budget:
- a new install, where the detector is not yet established when C1a lands;
- a host whose operator never ratifies;
- a peer regime or session universe that first appears after C1a.

**Effect:**
- Whether label admission is then blocked or unbounded is unspecified.
- v2 H3's "snapshot no step creates" survives as "a snapshot no operator ratified".
- Asking the operator to ratify an opaque summary (count, mean, M2, EWMA) per host has the per-item-consent shape the doctrine rejects (`autonomy-doctrine.md:39-50`).

**Fix:**
- Take a provisional anchor automatically at first establishment, with a notice.
- Until it is ratified, disable bounded quiet and keep labels within a minimal budget.
- Make ratification a one-time policy statement ("accept the first established window as the anchor on every host"), not a per-host review of statistics.
- Re-anchor each new regime the same way.

### MEDIUM 5. Regime and universe changes re-warm the incumbents with no arbitration, and the claimed visibility needs a C8 learner

**Plan:**
- C0.1b (line 225) and I49 (line 144): session regimes work "as for peers", and "the availability transition is itself a scored context event, so moving a binary aside … is visible".
- §6.5 (line 458) covers re-warm-up only during an open episode.
- Incumbent recovery cites CC3(e) only, not CC3(a)'s same-universe requirement.

**Code:**
- `peer-baseline.js:525-548`: a regime flip "triggers an honest re-warm-up", with no candidates and no coverage until 30 ticks.
- Peer alert ids are not regime-scoped: `v2:vpn` covers every marker-backed regime (`:50-61`).
- The binary resolver accepts paths the daemon's own user can write (`tools/binary-resolver.js:239-289` @ 3c18739).

**Scenario:**
- **(a) No open episode.**
  - `brew uninstall screen`, or a Homebrew binary moved aside, changes the universe.
  - That opens a blind re-warm of about 30 hours. The new regime's baseline folds whatever it is shown, with no anchor and no pending state.
  - Until C8, the "scored context event" exists only in a shadow learner, so it raises nothing.
- **(b) Open episode.** The incumbent keeps scoring every tick against a snapshot of the *old* universe (line 458):
  - a universe that shrinks fabricates alarms;
  - a universe that grows can satisfy CC3(e) on a count that is not comparable.

**Fix:**
- Carry CC3(a) over to the incumbents.
- During an open episode, freeze across a regime change: no scoring and no recovery.
- Arbitrate a new regime's first establishment against a per-regime anchor.
- State that before C8 an availability change is visible only as the `collector.binary_state` fact, or add an S-class integrity notice when a binary leaves a known path.

### MEDIUM 6. `structure_id` includes the learned top-K network mapping, so ordinary network churn mints new identities and demotes promoted learners

**Plan:**
- §6.1 (line 343): `structure_id` = "vocabulary mapping, model families, dimensions".
- §5 (line 305): "The vocabulary and top-K mapping are versioned".
- I7 (line 102): the frequency ranking is learned inside each fold.
- §11.4 (line 763): a structure change "enters shadow".
- CC5 (line 369).

**Scenario:**
1. Weeks of café visits reorder a laptop's top-5 networks. An attacker could do the same by toggling resolvers from a user session (re-review L3).
2. The mapping gets a new version, which changes `structure_id` and every alert id.
3. Persistent anomalies re-notify under the new ids, which is v2 H1(b) by another route.
4. The old ids freeze, and only the predecessor's snapshot can recover them.
5. A promoted lineage drops back to shadow.

**Fix:**
- Make top-K membership a parameter inside a version, with values outside it encoded as `other` or `new`.
- Reserve `structure_id` for changes to the dimension set, the model families and the bucket edges.
- Keep the serving version until its successor has been evaluated.

### MEDIUM 7. New thresholds are unclassified, against §0.4's own rule ("Anything unclassified is a defect", line 78)

- **"Stably `not_found_on_known_paths`"** (C0.1b line 225, I49). How many ticks? Does a symlink swap during `brew upgrade` count? This decides whether a source leaves the universe.
- **The bounded-quiet "stability of the new level" test** (§6.3 line 414, I19). Neither the statistic nor the threshold is stated, yet it is the only gate between a held attack level and admission.
- **"Uptime consistent with the gap"** (I41 line 136). The tolerance is not stated, yet it is one condition of a fail-closed security check.
- **"Repeated aborts auto-disable the learner"** (§7.7 line 580). The count is not stated.

**Fix:** add an inventory row for each, with its class and a fixture.

## LOW

**LOW 1. F3's wording is false on macOS** (§7.8.1 line 597; I37 line 132: "the monotonic clock pauses across suspend; the boottime clock does not").
- This host's macOS `clock_gettime(3)` says `CLOCK_MONOTONIC` "will continue to increment while the system is asleep". The clock that pauses is `CLOCK_UPTIME_RAW` (= `mach_absolute_time`).
- Under criterion A2, the F-card must name clock ids per platform:
  - Linux: `CLOCK_MONOTONIC` pauses; `CLOCK_BOOTTIME` does not.
  - macOS: `CLOCK_UPTIME_RAW` pauses; `CLOCK_MONOTONIC` and `mach_continuous_time` do not.
- C0.9's gating keeps F3 inactive until verified, so nothing is fabricated today.

**LOW 2. Two default-on incumbent EVENT rules are unclassified and still recover on a quiet interval** (§6.0 lines 322-323; I42 line 137).
- `session.churn` reports a fresh, unchanged entity as evaluated (`session-baseline.js:631-641`), so a churn alert recovers on the next tick.
- `service.disappeared` recovers through the union coverage (`service-baseline.js:455-476`).
- D1 reversed this behaviour for novelty only.
- Under notify-once each transition is a new incident (README:307-309), so the cost is a wrong `recovered` status, not a lost notification.
- **Fix:** classify both as EVENT, or record them as an explicit exception.

**LOW 3. C2 timing against the C4a corpus** (§14 C2 line 803; §8.1 line 656; §10.1 line 711).
- Clock and suspend facts are `unknown` until F2 and F3 are ratified, and `tick_summary` keeps only the derived suspend bounds.
- If ratification lags the start of the four-week collection on the calibration laptop, the corpus has no wake context, and re-review M8 reopens for wake.
- **Fix:** store the raw paired clock readings and the boot id in each record, so the bounds can be recomputed after ratification.

**LOW 4. The default-on shadow log and learned store have no disk bound** (§7.7 line 580; I47 line 142).
- The bounds cover CPU, wall time, memory and snapshots, but not bytes, and both stores run on every install.
- **Fix:** register them as families with budgets and a T8-style invariant.

**LOW 5. Citation nit** (§1.5 line 191).
- This host has *three* `PPP:Modem` services, not two: `com.redhat.spice.0`, `tart-version-2.30.1` and `tart-version-2.30.6`.
- The parser classifies all three as non-VPN.

## v2 BLOCKER/HIGH closure

| v2 item | Status | Residual |
|---|---|---|
| B1 (event recovery) | **Closed** for learned EVENT streams: a quiet interval never recovers; restored names never recover across a boot; gate tests split into `cc_e_*` and `cc_l_*` | MEDIUM 1, HIGH 3, LOW 2 |
| H1 (identity) | **Mostly closed**: alert id = rule + lineage + `structure_id`; `raise_ref` kept in diagnostics (`alert-store.js:269` @ 25cf225) and in the ledger; the raising cell is re-scored; host vocabulary; a back-off raise recovers at the same level | HIGH 2, MEDIUM 6 |
| H2 (absorption as data ages out) | **Closed** for open episodes: pre-episode snapshot; re-warm-up ticks pending; never provisional during an open episode | HIGH 2, HIGH 3, MEDIUM 5 |
| H3 (C1a sequencing) | **Closed**: C1a after CAP (overlap verified); anchors built at C1a; drift measure per kind; decoupled from C7b | MEDIUM 4 |
| H4 (pending state's home) | **Partly closed**: moved out of `alerts.json` into a ledger-stamped store plus a chained transition log, failing closed | HIGH 1, HIGH 3 |
| F-class conditions (8 Opus edits, 3 Astra changes) | **All applied**, each checked in the text | MEDIUM 1 (the same-boot name rule), LOW 1 |
| v1 Opus H5 (scutil parser) | **Closed** on `fix/collector-sources-2026-10`, re-verified on this host's output; not merged | LOW 5 |

VERDICT: NEEDS-REVISION (3). n = 0 BLOCKER + 3 HIGH, following the v1/v2 convention; 7 MEDIUM and 5 LOW are also listed. Not RETHINK: the direction holds, and every finding is a contract fix in §6 or in the inventory.