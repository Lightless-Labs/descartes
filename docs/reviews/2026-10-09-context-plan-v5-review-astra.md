# Context plan v5 review — gpt-6-astra (xhigh)

Read-only review; no files changed. I checked v5 and all named reviews against the code, including notify-once’s merge into `main` at `fe4302b` during this review. In-memory probes confirmed the incumbent-fold and peer-recovery failures below.

No BLOCKER found. **All three HIGH findings from the prior v5 review remain open.** Earlier fixes for lifecycle evidence, model adequacy, source completeness, and certification after intentional eviction hold at the design level. The learning direction remains sound, but §6 is not coherent end to end.

1. **HIGH — Pending-directory loss still disables or re-baselines an established incumbent.**  
   **§§6.4.4, 6.5.1:** [plan:763](docs/plans/2026-10-06-context-aware-learned-baselines.md:763), [plan:834](docs/plans/2026-10-06-context-aware-learned-baselines.md:834).

   With no open episode, deleting the pending journal and checkpoint puts the entire raw window into `unexplained_discontinuity`. No certified serving fallback is specified for this case. The [current fold](tools/descartes-cli/src/session-baseline.js:385) becomes provisional when everything is excluded. Subsequent ticks either establish the attacker’s reduced count as normal or remain unscorable indefinitely. The probe confirmed both the provisional empty fold and the quiet re-established baseline.

   Require positively adjudicated clean membership, a surviving serving reference outside the lost journal, and an automatic recovery procedure that preserves exclusions. This leaves v5 Opus HIGH 1 and the earlier pending-integrity findings open.

2. **HIGH — Quarantining training data does not revoke the versions that learned from it.**  
   **§§6.3.1, 6.4.5:** [plan:636](docs/plans/2026-10-06-context-aware-learned-baselines.md:636), [plan:800](docs/plans/2026-10-06-context-aware-learned-baselines.md:800).

   A candidate fits pending departures; those items become quarantined before promotion, or receive `confirmed_incident` after promotion. Updating their journal disposition does not remove their influence from the fitted parameters. Neither promotion-time membership revalidation nor cascading invalidation of affected serving versions is specified. “Rebuild affected statistics” does not define that lifecycle.

   Bind promotion to current membership dispositions and vetoes; quarantine or revocation must automatically invalidate dependent versions and select an uncontaminated fallback. V5 Opus HIGH 2 remains open.

3. **HIGH — Peer regimes still share one recovery unit, causing fabricated recovery or indefinite muting.**  
   **§§6.1, 6.5.3:** [plan:489](docs/plans/2026-10-06-context-aware-learned-baselines.md:489), [plan:883](docs/plans/2026-10-06-context-aware-learned-baselines.md:883).

   Regime A raises and freezes; regime B establishes, drops, restores, then drops again. Both use [`v2:vpn`](tools/descartes-cli/src/peer-baseline.js:54). Reporting coverage for B makes [R3 recover every incident](tools/descartes-cli/src/alert-store.js:695), including A. Withholding coverage leaves B’s confirmed key in the episode, so its repeated drop does not notify. Both outcomes reproduced with the merged code.

   Put the regime in the alert identity, or implement independent recovery and rearming per regime. V5 Opus HIGH 3 remains open.

4. **HIGH — NEW: reciprocal corroboration vetoes make correlated legitimate changes label-only.**  
   **§6.3.2:** [plan:664](docs/plans/2026-10-06-context-aware-learned-baselines.md:664).

   A legitimate new reboot schedule produces surprising reboot events and surprising session occupancy, from distinct evidence sources. Each pending item overlaps the other’s unadmitted incident, so each vetoes the other’s normal-component membership. The response additionally waits for context admission. Repeating the workflow supplies more mutually vetoed examples. EVENT/LEVEL bounded quiet is forbidden; `context_model` only handles NOVELTY. Labels become the only defined exit.

   Define an automatically earned, jointly evaluated admission transition for mutually dependent episodes. Shadow access alone does not solve this deadlock. This reopens the original anomaly-exclusion concern and violates D5’s no-required-labelling principle.

5. **MEDIUM — Raw running extremes encode an invalid assumption for learned LEVEL models.**  
   **§6.1/I55, §7.1:** [plan:480](docs/plans/2026-10-06-context-aware-learned-baselines.md:480), [plan:941](docs/plans/2026-10-06-context-aware-learned-baselines.md:941).

   Occupancy raises at 17:00 with five sessions. One session is normal overnight but becomes a new raw minimum; the next afternoon, two sessions are highly anomalous yet cannot exceed that minimum. The rule can manufacture deterioration and then suppress a real deterioration. Even one categorical predictive need not have monotonic surprise across counts.

   Keep raw extremes for the frozen incumbent models; define learned incident progression using calibrated surprise and current-cell eligibility. “Adds no number” does not make the assumption an S invariant.

6. **MEDIUM — Drift-budget continuity and bootstrap remain undefined.**  
   **§§6.3.2, 8.3, DA:** [plan:663](docs/plans/2026-10-06-context-aware-learned-baselines.md:663), [plan:1135](docs/plans/2026-10-06-context-aware-learned-baselines.md:1135).

   Losing the drift ledger and re-earning cannot reconstruct previously charged displacement. A newly earned anchor therefore does not substantiate “never reset by loss.” The first promotion also has no preceding earned anchor. A rolling H budget bounds drift rate, which D5 permits, but DA leaves the conflicting [attested cumulative-anchor requirement](docs/design/autonomy-doctrine.md:110) unamended.

   Specify bootstrap comparison, conservative treatment of lost charges, demotion accounting, and automatic recovery; amend the doctrine explicitly without introducing ratification.

7. **MEDIUM — `earned_promotion` can bypass the incumbent explanation boundary.**  
   **§§6.0, 6.3.1, 11.1:** [plan:447](docs/plans/2026-10-06-context-aware-learned-baselines.md:447), [plan:645](docs/plans/2026-10-06-context-aware-learned-baselines.md:645).

   Membership is expressed as item IDs without an explicit ownership boundary. A notify-only candidate containing incumbent items can consequently close their incidents through promotion, bypassing the reviewed NOVELTY map or the prohibition on closing incumbent LEVEL episodes through admission.

   Separate permission to train on an incumbent’s evidence from authority to admit or close that incumbent’s items.

8. **MEDIUM — One forged bulk label bypasses the claimed label-poisoning bound.**  
   **§§6.3, 9:** [plan:617](docs/plans/2026-10-06-context-aware-learned-baselines.md:617), [plan:1165](docs/plans/2026-10-06-context-aware-learned-baselines.md:1165).

   One `benign` label over an entire pending window removes both corroboration and anomalous-context vetoes for every covered item, while consuming one of fifty labels. Notification exposes the operation but does not bound its influence.

   Charge affected items or influence, or retain the vetoes for ordinary on-host labels. Define release and expiry for labels held over budget.

9. **MEDIUM — The watermark needs a durable observation-to-pass mapping that C1 does not specify.**  
   **§6.4.2, C1.4:** [plan:718](docs/plans/2026-10-06-context-aware-learned-baselines.md:718).

   Current [fact records](tools/descartes-cli/src/fact-store.js:169) carry timestamps, not committing pass IDs; the [ledger](tools/descartes-cli/src/fact-store-integrity.js:47) retains the latest pass, and [retention-only passes](tools/descartes-cli/src/fact-store.js:648) also advance it. After multiple commits without detection, a scalar watermark cannot identify every intervening pass’s observations and evaluation time.

   Add the durable commit mapping to C1.4. Otherwise conservative exclusion is possible, but the promised ordered replay and late-kill detection are not established.

10. **MEDIUM — Retained evidence does not support the runtime promotion protocol as stated.**  
    **§§8.1, 10, 16.2:** [plan:1118](docs/plans/2026-10-06-context-aware-learned-baselines.md:1118), [plan:1180](docs/plans/2026-10-06-context-aware-learned-baselines.md:1180).

    Every host must run coherent identity-dependent replay, including a sustained thirty-day kill. At maximum volume its session raw history covers about 2.6 days; summaries cannot reconstruct the identities. The proposed calibration-laptop export does not supply that evidence on other hosts.

    Specify bounded per-host replay retention or a protocol explicitly executable from retained evidence. Otherwise busy hosts can remain on incumbents indefinitely.

11. **MEDIUM — Pending novelty produces unbounded alert storage despite bounded journals.**  
    **§§6.1, 6.6, 16.1:** [plan:497](docs/plans/2026-10-06-context-aware-learned-baselines.md:497), [plan:910](docs/plans/2026-10-06-context-aware-learned-baselines.md:910).

    Each novel entity gets its own alert. An entity that disappears before bounded quiet, or whose item compacts to `excluded`, can leave an active alert indefinitely. Per-alert incident caps do not bound those rows, and [every write serializes the collection](tools/descartes-cli/src/alert-store.js:458).

    Define bounded archival/backlog representation that preserves unresolved status and reappearance semantics.

12. **MEDIUM — C1a’s recurring-noise “bound” is only a measurement.**  
    **§6.5.2, C1a/C4a:** [plan:869](docs/plans/2026-10-06-context-aware-learned-baselines.md:869), [plan:1315](docs/plans/2026-10-06-context-aware-learned-baselines.md:1315).

    Nightly benign dips notify forever if the successor never qualifies or C4a chooses “skip.” Publishing notification counts supplies no acceptance criterion or consequence; the specific October 5 replay input is also not secured by an export step.

    Keep D5’s narrowed scope, but give this gate an available corpus, a reviewed acceptance criterion, and a defined deployment consequence.

13. **MEDIUM — NEW: exposure still assumes wall-clock elapsed time is valid.**  
    **§§4.1, 7.1:** [plan:342](docs/plans/2026-10-06-context-aware-learned-baselines.md:342), [plan:932](docs/plans/2026-10-06-context-aware-learned-baselines.md:932).

    The design detects clock steps but defines exposure as wall-clock delta minus suspension. A forward 24-hour correction during one awake hour changes the specified hazard model’s probability of at least three departures from five, at λ = 0.01/hour, from approximately `0.0000097` to `0.0755`. A backward correction can produce negative exposure.

    Derive exposure from verified same-boot elapsed-clock deltas; define uncertainty handling when those clocks are unavailable.

14. **LOW — EVENT recovery has conflicting quantifiers after delivery closure.**  
    **§6.2 CC3-E versus I63:** [plan:516](docs/plans/2026-10-06-context-aware-learned-baselines.md:516).

    “Every open incident” becomes empty after delivery closes the incidents, whereas the following departure clause correctly requires the episode’s cumulative departed set. The stronger clause can prevent the prior review’s vacuous recovery, so this is an ambiguity rather than a demonstrated inevitable failure. Explicitly include delivered incidents in the authoritative recovery set and test it.

VERDICT: NEEDS-REVISION (4)