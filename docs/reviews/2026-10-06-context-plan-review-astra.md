# Context-aware learned baselines plan review — gpt-6-astra (xhigh)

**Date:** 2026-10-06
**Plan:** docs/plans/2026-10-06-context-aware-learned-baselines.md (draft e4202cb)

---

The direction is sound, but the plan is **not ready for implementation as written**. Partial pooling and predictive scoring can support genuine learning; the current proposal leaves several fixed assumptions unlearnable and several suppression paths insufficiently governed.

I read the full plan, traced the cited code, and checked the governing documents. Findings below concern the proposed design unless explicitly identified as current behavior. No files were modified.

1. **BLOCKER — §§5.3, 7, C7: replacement and adaptation exceed the stated authority.**

   The plan would promote replacements and retire existing detectors, reducing what alerts. The [autonomy doctrine:103](docs/design/autonomy-doctrine.md:103) requires attested adaptation and a cumulative drift budget; the [behavioral-modeling plan:118](docs/plans/2026-09-03-proactive-behavioral-modeling.md:118) explicitly places suppression and predecessor retirement above the attestation gate. The existing [model-ladder.js:7](tools/descartes-cli/src/model-ladder.js:7) supports only additive notify-only promotion.

   **Scenario:** a successor learns that missing sessions after reboot are normal, passes local replay, and replaces the old detector. An attacker has gained suppression authority through endpoint-controlled training data. A daybreak review is not the required attestation. Moreover, only *structure* changes explicitly return to shadow; parameter refits can alter suppression just as substantially.

2. **BLOCKER — §5.4: parent fallback does not establish recovery of a child-context alert.**

   [alert-store.js:314](tools/descartes-cli/src/alert-store.js:314) recovers an alert whenever its ID is covered and absent from candidates. [daemon.js:838](tools/descartes-cli/src/daemon.js:838) checks the reporting owner and ID, not model version, stratum, confidence, or source-universe equivalence.

   **Scenario:** two sessions are anomalously few in a context normally containing five. Context becomes unavailable; the broad parent distribution accepts two. Returning the existing `global` ID as evaluated clears the alert without any sessions returning. “Lower confidence” provides no protection in this contract. I confirmed the underlying recovery behavior with an in-memory probe. The plan needs explicit recovery semantics across fallback, context changes, and model replacement.

3. **BLOCKER — §3.1: the proposed lifecycle facts can fabricate events and timestamps.**

   The paired clocks can measure **aggregate suspended duration between observations**, not exact sleep start/end or the number of intervening sleeps. Two twenty-minute sleeps at different positions inside an hourly interval produce the same duration delta. `since_wake` therefore cannot generally be reconstructed from that delta. Linux documents the suspend distinction in [clock_gettime](https://www.man7.org/linux/man-pages/man2/clock_gettime.2.html); Apple documents it in [mach_time.h](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/mach_time.h).

   “Changed boot time = reboot” is also unsafe: Apple’s [clock implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/clock.c) adjusts boot time when calendar time changes. The cited [system.js:65](tools/descartes-cli/src/tools/system.js:65) supplies only `os.uptime()`.

   **Scenario:** a clock correction creates a false reboot and enters a forgiving aftermath stratum. Use boot identity plus clock observations; represent unresolved transition times as intervals, not invented instants.

4. **HIGH — §§4, 5.1–5.3: conditioning can explain away the attack itself.**

   The model scores the response given context, but does not specify a learned probability for the context transition, its frequency, or its duration. Novelty guards catch *new* contexts, not malicious transitions into familiar ones.

   **Scenario:** an attacker toggles a familiar VPN off, forces another reboot, or recreates an established network fingerprint before killing sessions. The resulting counts fit an established conditional distribution. There is also direct target leakage: VPN-service connected state determines the VPN-service count in [vpn-peer-status.js:422](tools/descartes-cli/src/tools/vpn-peer-status.js:422). Selecting that dimension can achieve excellent likelihood by restating the response.

   Retain conditional learning, but also evaluate learned transition/duration behavior and independent evidence. No statistical method can distinguish benign and malicious events that produce identical observed evidence.

5. **HIGH — §5.3: anomaly exclusion creates an adaptation deadlock and does not stop slow poisoning.**

   “Don’t learn from anomalies” makes the incumbent model decide which evidence its successor may see. Existing [session-baseline.js:416](tools/descartes-cli/src/session-baseline.js:416) scores against preceding observations and subsequently folds observations; the proposed exclusion introduces a materially different, selectively censored training distribution.

   **Scenario:** every legitimate reboot fires the old count-drop detector, so precisely the aftermath examples needed by the replacement are quarantined. A permanent benign workload change can remain unlearnable unless the operator repeatedly adjudicates it.

   Conversely, small changes that never cross the anomaly threshold enter training. Recent and rolling 31-day estimates can both walk steadily while their difference remains small. A long window helps detect drift; it is not an immutable reference. The doctrine’s attested anchor and cumulative drift budget are missing.

6. **HIGH — §§0.5, 3.1, 4, 5.1: the S/P/O classification is not honest yet.**

   Fixed log buckets, weekday/weekend grouping, rare-location pooling, parent structure, and the offered feature vocabulary constrain what is learnable. A cap on cardinality can be **S**; the particular distinctions erased by that cap are not automatically safety invariants. Once only coarse buckets are retained, data cannot recover distinctions inside them.

   **Scenario:** this host has a Tuesday–Saturday work schedule. The learner may discard `day_type`, but cannot learn that schedule from a weekday/weekend-only dimension. Likewise, two distinct aftermath regimes inside one fixed time bucket remain inseparable.

   “The learner chooses strata” describes real feature selection within a human-selected representation—not unrestricted discovery. That is a legitimate starting scope, but must be stated accurately. [model-ir.js:261](tools/descartes-cli/src/model-ir.js:261) currently offers only a small primitive vocabulary; the doctrine’s [compositional requirement:33](docs/design/autonomy-doctrine.md:33) supplies the expansion path. Separately, declaring daemon downtime “never treated as normal” is an explicit behavior rule; reporting a coverage gap would be a safety invariant.

7. **HIGH — §§5.1–5.2, C4: the sample-size and temporal-resolution assumptions are too optimistic.**

   [daemon.js:66](tools/descartes-cli/src/daemon.js:66) samples structural state hourly. Even with perfect 31-day availability, there are only **744 ticks**. Hour × weekday/weekend gives 48 cells, averaging 15.5 observations; adding two connectivity states and three locations gives 288 cells, averaging 2.6—before boot, wake, origin mix, missingness, or entity-specific models. Autocorrelation further reduces independent information.

   **Scenario:** four observed reboots produce four independent aftermath episodes, not hundreds of independent reboot examples. Minute-scale reconnection or tmux restoration may happen entirely between samples.

   Partial pooling is appropriate, but cannot manufacture those observations. Cold-start behavior must acknowledge unlearned contexts, and eligibility should depend on predictive evidence and episode support—not reuse the current thirty-tick warm-up from [session-baseline.js:83](tools/descartes-cli/src/session-baseline.js:83).

8. **HIGH — §5.1: the proposed count families cannot represent some important normal behavior.**

   Poisson has variance equal to its mean; negative-binomial/Poisson-gamma permits additional dispersion. Neither represents strongly *underdispersed* occupancy counts.

   **Scenario:** a host has exactly three sessions for weeks, then loses all three. A fitted Poisson with mean three assigns zero probability mass `exp(-3) ≈ 4.98%`; negative-binomial dispersion can make zero still more likely. More identical observations do not remove this likelihood constraint. By comparison, the current floor-based detector would score that drop at approximately −6 ([session-baseline.js:76](tools/descartes-cli/src/session-baseline.js:76), [welford-stats.js:84](tools/descartes-cli/src/welford-stats.js:84)).

   These families are examples rather than commitments, but C4 needs an explicit model-adequacy gate. Also distinguish occupancy, event counts, and exposure-adjusted rates. Snapshot fingerprint differences do not count every intervening churn event.

9. **HIGH — §§5.1, 7: rolling-origin selection alone does not control overfitting or establish calibrated surprise.**

   Eight candidate dimensions already permit 256 inclusion subsets before interactions, bucket alternatives, priors, and distribution choices. Selecting and reporting the winner on the same rolling folds creates selection optimism. Average predictive likelihood can favor common-state accuracy while sacrificing rare attack sensitivity.

   **Scenario:** one location happens to coincide with two reboots. A location-conditioned model wins the month’s backtest but fails on the next location visit.

   Every fold must fit vocabulary/top-K, priors, exclusions, and structure using only preceding data; promotion needs separate chronological evaluation, with episodes kept intact. [Rolling-origin validation](https://otexts.com/fpp3/tscv.html) preserves temporal ordering but does not itself supply this separation. Preserve the current exclude-latest discipline in [peer-baseline.js:563](tools/descartes-cli/src/peer-baseline.js:563); the existing generic [model-ir.js:335](tools/descartes-cli/src/model-ir.js:335) instead uses inclusive scoring.

10. **HIGH — §§3–5.4: the historical reconstruction contract is incomplete.**

    A one-off boot event disappears from a bounded history while the machine remains running. Top-K membership changes with the fitting window; local-hour reconstruction changes with timezone configuration. Cross-family facts also have different observation times: [daemon.js:395](tools/descartes-cli/src/daemon.js:395) collects sources sequentially, while [daemon.js:1004](tools/descartes-cli/src/daemon.js:1004) assigns their translated facts a common tick timestamp.

    **Scenario:** a VPN reconnects between the session/peer and context reads, creating a context-response pair that never coexisted. Or day 32 loses its boot anchor and becomes `unknown`.

    Also, the checked-out store retains **30 days** ([fact-store.js:18](tools/descartes-cli/src/fact-store.js:18)); the **31-day query** in [welford-stats.js:20](tools/descartes-cli/src/welford-stats.js:20) is not proof of 31 days of evidence. Verify the capacity dependency’s actual retention and every joined family’s certified horizon.

11. **HIGH — §§1, 3.2, 5.2: per-source models need new evidence-completeness contracts, not merely source filters.**

    The current peer fold already stratifies by source-availability signature ([peer-baseline.js:544](tools/descartes-cli/src/peer-baseline.js:544)); §1’s “single global fold” overstates the situation. R8’s source-scoped fingerprints protect incompatible observation universes, a legitimate safety concern.

    Tailscale currently emits no census marker ([fact-translators.js:998](tools/descartes-cli/src/fact-translators.js:998)); its parser requires a `Peer` map even for a backend-state observation ([tailscale-status.js:81](tools/descartes-cli/src/tools/tailscale-status.js:81)). Linux VPN-service collection is `not_applicable`, while WireGuard queries can require privileges ([vpn-peer-status.js:23](tools/descartes-cli/src/tools/vpn-peer-status.js:23), [:339](tools/descartes-cli/src/tools/vpn-peer-status.js:339)).

    **Scenario:** an unavailable Linux VPN source becomes “none connected,” or missing Tailscale facts become zero online peers. Require independent source censuses and distinguish unavailable, disconnected, empty, and truncated. Tailscale `Online` means connected to its control plane, not proven peer reachability ([upstream schema](https://raw.githubusercontent.com/tailscale/tailscale/main/ipn/ipnstate/ipnstate.go)).

12. **HIGH — §§3.3, 5.2: the proposed login learner risks learning occupancy instead of login events.**

    [fact-translators.js:882](tools/descartes-cli/src/fact-translators.js:882) explicitly buckets the observation hour. [vpn-peer-status.js:406](tools/descartes-cli/src/tools/vpn-peer-status.js:406) deduplicates by user/host and repeatedly includes bounded historical `last` entries.

    **Scenario:** one persistent login supplies observations at every hour, making a later genuinely unusual login look normal. Repeated historical rows can also become fictitious repeated login events.

    Capturing tty does not identify SSH: `pts` can be local or remote, and `who` can report an X display rather than a remote hostname ([GNU documentation](https://www.gnu.org/software/coreutils/manual/html_node/who-invocation.html)). The current parser treats `(:0)` as a remote host; an in-memory BSD-shaped local `last` row produced `Tue` as its host. Login accounting is not a complete terminal/process census. Current process ancestry also cannot establish a creator that has exited; [provenance.js:140](tools/descartes-cli/src/tools/provenance.js:140) explicitly handles reparented processes.

13. **HIGH — §7, C6: the proposed labels and evaluation can certify the wrong thing.**

    A reboot/wake/flap is an observed event, not automatically a benign label for surrounding activity. Acknowledgement means receipt, not “false positive”: [alert-store.js:366](tools/descartes-cli/src/alert-store.js:366) records no disposition or reason. [calibration.js:300](tools/descartes-cli/src/calibration.js:300) also warns that alert snapshots undercount repeated episodes.

    **Scenario:** an operator acknowledges a real intrusion while investigating; training interprets this as permission to absorb it. Alternatively, synthetic kills change counts but omit coherent fingerprints, contexts, censuses, and integrity state, so replay tests an impossible observation sequence—or counts abstention as successful quietness.

    Require externally supplied episode labels, explicit unknowns, coherent chronological replay, and separate reporting of correct silence versus inability to evaluate. The existing [model-ladder.js:150](tools/descartes-cli/src/model-ladder.js:150) already distinguishes unsupported evaluation from a correct negative.

14. **MEDIUM — §§3.2, 3.4: “location identity” and sanitization promise more than the sources establish.**

    [network.js:81](tools/descartes-cli/src/tools/network.js:81) exposes interface addresses, not authoritative wifi/ethernet/tunnel classification. Routes and resolver reads have separate completeness limitations ([network.js:217](tools/descartes-cli/src/tools/network.js:217), [:241](tools/descartes-cli/src/tools/network.js:241)).

    **Scenario:** two networks share interface names, gateway `192.168.1.1`, and resolvers, producing the same fingerprint. Conversely, VPN changes produce several fingerprints at one physical location. Call this an observed network-configuration fingerprint, with explicit component availability.

    `sanitizeDiagnostics` is a charset filter, not a closed-enum validator ([diagnostics-sanitizer.js:44](tools/descartes-cli/src/diagnostics-sanitizer.js:44)); my probe passed both a raw username and IP address. Add actual field schemas and hash-at-source enforcement.

15. **MEDIUM — §§8, 10: tier, runtime limits, and integration must be settled before the broad estimator build.**

    Existing shadow evaluation requires both watch and learned enablement ([daemon.js:1061](tools/descartes-cli/src/daemon.js:1061)). The earned-trust ladder is still explicitly pure/offline ([model-ladder.js:3](tools/descartes-cli/src/model-ladder.js:3)). C4–C7 therefore require substantive lifecycle and daemon integration, not just estimator code.

    **Scenario:** all installs start repeated structure searches under default-on watch, despite an operator disabling learning; fitting delays evidence collection or the four stream implementations develop incompatible promotion state.

    Prefer one vertical shadow learner first. Specify fit cadence, candidate-admission limits, CPU/memory/time limits, abort behavior, durable versions, and kill-switch ownership. The [September plan:160](docs/plans/2026-09-03-proactive-behavioral-modeling.md:160) already requires this spike-first discipline.

16. **MEDIUM — §6, C1: R3 requires alert-episode state, not just a `notificationDue` edit.**

    [alert-store.js:295](tools/descartes-cli/src/alert-store.js:295) merges candidate severity into the existing record and preserves `last_notified` across reactivation. `notificationDue` receives only the resulting record.

    **Scenario:** replacing cooldown logic with “notify iff never notified” silences a second activation after recovery; severity escalation also needs comparison against prior/notified severity. Specify episode rearming and escalation semantics, including acknowledgement behavior. R3 is valid **O** policy and should remain independent of model truth and training eligibility.

The concrete revisions I recommend are:

- **Make §0.5 an executable inventory.** Classify each choice, identify whether data can override it, and require a counterexample fixture demonstrating that override:

  | Choice | Honest classification and required treatment |
  |---|---|
  | Retention, collection budgets, completeness, privilege and authority gates | **S**. Intentionally not learned away. Verify actual retained horizon and expose exhaustion. |
  | Log-scale bucket edges; weekday/weekend grouping | **P only if replaceable** from retained information. Otherwise fixed representational assumptions. Preserve sufficient time/day information for alternatives. |
  | Top-K | Cardinality ceiling **S**; frequency ranking and `other` pooling are modeling choices. Preserve bounded, auditable identity information and version the mapping. |
  | Candidate dimensions and interactions | A declared initial hypothesis space, not automatically S/P/O. Permit bounded compositions and alternative representations; do not claim discovery outside it. |
  | Priors, pooling strength, parent hierarchy, complexity penalty | Modeling assumptions. **P** requires specified strength/support, sensitivity checks, and evidence that contrary data can win. A hard search/resource ceiling is separately **S**. |
  | Aftermath shape | Learned hypothesis. The “zero then climb” narrative must be falsifiable, not embedded in initialization, fixtures, or admission rules. |
  | Anomaly quarantine | **S** when restricting adaptation authority; not an assertion that anomalous data is malicious. Preserve evidence and allow challenger analysis without promoting it. |
  | Drift windows, persistence, novelty handling | Must be specified and justified. Detection thresholds are not automatically safety invariants; novelty requires trustworthy prior observation coverage. |
  | Surprise threshold, severity, weekly notification budget, R3 | **O** at the delivery boundary. They must not silently redefine benign labels, authorize recovery, or control admission into trusted training. |

- **Correct and ship the evidence contract first.** Use boot IDs, paired clocks with uncertainty, event-time versus observation-time fields, explicit source coverage, and certified carried-forward lifecycle state. Native clock access is feasible without granting the daemon new privileges, but the current Node collector needs an explicit implementation path. Keep shutdown-cause logs optional; absent prior-boot logs must not imply a clean shutdown.

  Missing useful context includes daemon restart/configuration version, collector capability changes, timezone/UTC offset and clock corrections, session attachment/user-presence state where observable, and independently sourced maintenance/package/deployment events. Collect these as candidate evidence, not suppression switches.

- **Run a small model comparison before committing to the estimator family.** Compare a pooled global model, a partially pooled discrete-count model, and a parsimonious dynamic/additive model with cyclic time effects. Include underdispersion, excess zeros, stable occupancy, and regime changes. Model observed transition probabilities or survival where snapshot data cannot establish event rates. Partial pooling is a strong candidate; a full Cartesian stratum table is poorly matched to this sample size.

- **Separate exploratory learning from authority to replace active behavior.** Preserve quarantined observations; let challengers test whether the incumbent is wrong. Version preprocessing, parameters, training membership, and structure. Govern successors and cumulative drift under the doctrine’s attestation policy. Score context transitions as well as conditional outcomes, while acknowledging indistinguishable attacks as an evidence limit.

- **Specify recovery and evaluation before C4/C5.** Bind evaluation to observation time, source universe, model version, and recovery semantics. Test unknown context, parent fallback, known-context manipulation, unseen locations, repeated reboots, multi-day poison, history loss, and model replacement. No fallback or successor may clear a predecessor incident merely by accepting its unchanged evidence.

- **Move the evaluation protocol ahead of model selection.** Use independently labelled episodes, nested chronological selection, held-out episodes, and coherent end-to-end replay. Report predictive calibration, episode detection/delay, false alerts, abstention/coverage, resource costs, and uncertainty. Synthetic recall is scenario recall, never real-world recall. A weekly attention budget should organize delivery without deleting detections or raising thresholds during an attack flood.

- **Resolve the tier explicitly.** Context collection belongs under watch. Under the current documented contract, authoring and shadow-model evaluation belong under `learned.json`; default-on shadow learning requires an explicit policy amendment and its own bounded execution contract. Promotion remains evidence-driven within the authorized envelope.

VERDICT: NEEDS-REVISION (16)