# Context plan v4 review — gpt-6-astra (xhigh)

**Not every prior HIGH is closed.** The earlier recovery, lifecycle-fabrication, and authority BLOCKERs are addressed in the design. The learning direction remains sound, but arbitration still has failure paths. No files were modified; the numerical probes below used the repo’s pure scoring functions.

1. **HIGH — The held-level estimator can absorb further deterioration and mute notifications.**  
   **§6.5.2:** [plan:696](docs/plans/2026-10-06-context-aware-learned-baselines.md:696). Code: [welford-stats.js:36](tools/descartes-cli/src/welford-stats.js:36), [peer-baseline.js:730](tools/descartes-cli/src/peer-baseline.js:730).

   **Scenario:** an established peer count drops `8→5`, notifying once. Subsequent counts are `4,3,2,1,0`. Scoring each against the proposed accumulating held-level Welford gives z-scores `−2, −2.12, −2, −1.94, −1.90`: **no new incident**. Peer severity remains warning, so escalation cannot rescue delivery. The serving baseline need not change, so its drift budget does not catch this.

   V3 HIGH 2 is therefore only partially closed. The notification reference needs protection against cumulative movement; recycling the incumbent’s constants does not make this additional adaptive detector a safety invariant.

2. **HIGH — Crash recovery omits the fact-commit-to-verdict gap.**  
   **§6.4.2:** [plan:592](docs/plans/2026-10-06-context-aware-learned-baselines.md:592). Code: [daemon.js:1124](tools/descartes-cli/src/daemon.js:1124), [session-baseline.js:394](tools/descartes-cli/src/session-baseline.js:394).

   **Scenario:** the daemon commits a census showing a kill, then crashes before detection journals it. On restart, a newer census shows the restored count. The existing recompute folds the earlier kill while scoring only the latest observation. There is no pending item, missing incident, or broken journal to trigger discontinuity handling.

   Journal-first ordering fixes crashes **after** a verdict exists. It needs a durable scored-through watermark and ordered replay—or conservative exclusion—of every committed but unadjudicated observation. “Re-score the latest tick” is insufficient. This leaves the prior pending-integrity HIGH incompletely closed.

3. **HIGH — Discontinuity recovery downgrades quarantined observations to pending.**  
   **§6.4.4 versus §6.4.5:** [plan:630](docs/plans/2026-10-06-context-aware-learned-baselines.md:630), [plan:665](docs/plans/2026-10-06-context-aware-learned-baselines.md:665). The resulting exclusion depends on the proposed predicate in [plan:682](docs/plans/2026-10-06-context-aware-learned-baselines.md:682), over the current [session fold](tools/descartes-cli/src/session-baseline.js:385).

   **Scenario:** an operator labels an episode `confirmed_incident`; its quarantined state survives in a checkpoint. Journal corruption then invokes the instruction to carry **every recoverable item forward as pending**. After automatic re-certification, that item is again eligible for ordinary pending admission despite its permanent quarantine.

   Preserve surviving terminal dispositions and their provenance. Only genuinely uncertain membership should become unexplained pending. V3 HIGH 3 remains open on this recovery path.

4. **HIGH — Long-memory certification still depends on raw history that capacity retention deliberately removes.**  
   **§6.4.3 and §8.1:** [plan:600](docs/plans/2026-10-06-context-aware-learned-baselines.md:600), [plan:959](docs/plans/2026-10-06-context-aware-learned-baselines.md:959). Code: [fact-store-integrity.js:697](tools/descartes-cli/src/fact-store-integrity.js:697), [fact-families.js:267](tools/descartes-cli/src/fact-families.js:267).

   **Scenario:** maximum session volume leaves roughly 2.6 days of raw history. A seven-day-old summary remains inside the nominal 30-day retention, but its source pass lies outside the current certified span. The literal multi-ledger check rejects it. Old pending entries face the same “pass inside certified span” requirement.

   Specify durable certification at derivation/checkpoint time that survives **intentional age and byte eviction**, while retaining actual-loss detection. Without that distinction, the original volume-eviction HIGH returns through validation rather than physical summary deletion.

5. **HIGH — EVENT adaptation has an unresolved choice between laundering through promotion and label-only learning.**  
   **§6.3, §11.1, C5–C7:** [plan:538](docs/plans/2026-10-06-context-aware-learned-baselines.md:538), [plan:551](docs/plans/2026-10-06-context-aware-learned-baselines.md:551). Code: [model-ladder.js:253](tools/descartes-cli/src/model-ladder.js:253).

   **Scenario:** C5’s departure learner repeatedly flags a legitimate new workflow. Its successors may train on those pending events, but no version may explain its own lineage, bounded quiet is forbidden, and the sequence supplies no independent same-target departure explanation source.

   Promoting the challenger’s fitted parameters makes pending data influence authority-bearing state without admission. Rebuilding it from admitted data removes the adaptation that was evaluated. Requiring labels avoids that bypass but makes labels the only implemented learning path.

   Define the serving-state handoff, training-membership provenance, and an evidence-earned adaptation path within the policy envelope. Challenger access alone does not close Astra 5 or avoid the UAC ditch.

6. **MEDIUM — The retained summary cannot support all promised replay and identity-dependent learning.**  
   **§8.1, §7.8.3, §10:** [plan:948](docs/plans/2026-10-06-context-aware-learned-baselines.md:948), [plan:953](docs/plans/2026-10-06-context-aware-learned-baselines.md:953). Code: [fact-families.js:204](tools/descartes-cli/src/fact-families.js:204).

   **Scenario:** a transition sample records departures; later samples overwrite the single census-chain snapshot and raw history expires. Counts plus a keyed set digest cannot reconstruct the departed identities, restoration matches, or a coherent kill-and-replace replay. Current seen-sets cover services, scheduled jobs, and lineage—not session instance history.

   Specify bounded retained event/episode identity evidence alongside the numerical summaries. Otherwise C5’s restoration work and C6’s replay need data the stated storage contract discards.

7. **MEDIUM — Warning-trigger displacement does not bound severity suppression.**  
   **§6.5.4:** [plan:739](docs/plans/2026-10-06-context-aware-learned-baselines.md:739). Code: [session-baseline.js:660](tools/descartes-cli/src/session-baseline.js:660).

   **Verified scenario:** changing `(μ,σ)` from `(10,1)` to `(13,2)` leaves the warning trigger at `7`, charging **zero** proposed drift. The critical trigger moves from `5` to `3`; an observed count of `4` changes from critical to warning.

   Budget all authority-relevant decision boundaries, or predictive divergence—not just the warning boundary.

8. **MEDIUM — Required early admission/resource values are scheduled too late.**  
   **§14 and §16:** [plan:1113](docs/plans/2026-10-06-context-aware-learned-baselines.md:1113), [plan:1167](docs/plans/2026-10-06-context-aware-learned-baselines.md:1167). Existing capacity enforcement: [fact-families.js:346](tools/descartes-cli/src/fact-families.js:346).

   **Scenario:** C1/C1a must ship bounded journals, quarantine, regime memory, provisional label admission, and drift enforcement. Their necessary caps and policy values are first proposed at C3b, which is not a dependency of either step.

   Move those decisions before C1/C1a, or make their ratification an explicit activation gate. The merged capacity prerequisite is satisfied; this dependency remains.

9. **MEDIUM — Closing incidents removes the live cap without bounding retained records.**  
   **§6.1/I63:** [plan:443](docs/plans/2026-10-06-context-aware-learned-baselines.md:443). Current R3 code: [alert-store.js:458](.claude/worktrees/r3-notify-once/tools/descartes-cli/src/alert-store.js:458).

   **Scenario:** bulk labels repeatedly drain a context-event storm. Closed records must remain forever to reject replay, but no longer count toward 256. The incident map grows indefinitely, and the store serializes the entire alert collection on writes.

   Define bounded archival/tombstone semantics that preserve deduplication. Pending-store compaction does not bound this separate delivery store.

10. **LOW — Dependency descriptions have already drifted.**  
    **Prerequisites/C0.1b:** [plan:43](docs/plans/2026-10-06-context-aware-learned-baselines.md:43). Current collector code: [fact-translators.js:728](.claude/worktrees/collector-sources/tools/descartes-cli/src/fact-translators.js:728).

    The collector branch is now `1c2b412`, with usable-multiplexer universes implemented; R3 is `71815b5`, with additional persisted-retry work. Following the plan’s older descriptions would repeat completed work and miss current integration behavior. Refresh the dependency contract before implementation.

The count below follows the prior reviews: BLOCKER plus HIGH findings.

VERDICT: NEEDS-REVISION (5)