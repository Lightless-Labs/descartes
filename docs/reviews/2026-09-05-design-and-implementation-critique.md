---
title: "Descartes: critique of the current design, implementation, and direction"
date: 2026-09-05
status: completed review; recommendations not adopted
reviewed_commit: 50a396d45a0a074064018cb463a476cb4869c221
companion: ../architecture/2026-09-05-purpose-first-design.md
---

# Descartes: what I would change

## Assessment

Descartes has useful collectors, substantial deterministic monitoring, carefully constrained model access, and a serious regression suite. It has moved well beyond a model that occasionally runs system commands.

Its largest weakness is that **the components have stronger individual contracts than the operating loop they form together**. Missing observations can become recovered alerts. Notification eligibility can become “last notified” before delivery. Metric summaries combine distinct resources on the same machine and lose their identity. Learning then consumes records that cannot fully describe what happened.

Meanwhile, the design is investing in agent-authored behavioral models and earned authority before it has established a dependable account of workload health, incident episodes, and confirmed outcomes. Those ambitions are reasonable. The order and the underlying semantics need work.

I would retain most of the useful implementation and change its organizing objects and boundaries. The next milestone should demonstrate a trustworthy unattended operating loop, with a bounded authorship experiment alongside it. A wholesale rewrite or a larger detector catalog would not address the central problems.

## Scope, method, and a correction to my independent proposal

I saved [the purpose-first proposal](../architecture/2026-09-05-purpose-first-design.md) before reading the handoff, manifests, design documents, or implementation. Its SHA-256 at that boundary was `cc53bb6492165c7407f7d664e187890ff5e93556a7c7af79c3893326fb7a906f`; I preserved it during this review. Its inputs were the supplied AGENTS.md and README introduction, which already contained some architectural constraints.

For this review I examined the current README and handoff, roadmap, autonomy and integrity doctrine, behavioral-model plans, package/crate manifests, CI configuration, and the main collection → storage → detection → notification and triage paths. I also examined the learning/calibration seams, evidence identity, recommendation boundary, and Rust helper entry point. This is a source-grounded architectural review, not an exhaustive audit of every platform adapter or a production field trial.

The source baseline is commit `50a396d`. Concurrent uncommitted edits to the alert-intelligence budget clock and its tests appeared during finalization. I checked that diff for overlap with these conclusions and left it intact; those edits were not authored or separately validated by this review. Source line references describe the reviewed baseline.

The later material reveals an explicit operator preference I did not have when writing the first document: **low-risk model promotion should become automatic under an operator-defined policy, without approving each model individually**. It also establishes adaptive defense and agent authorship as deliberate goals. Those are not accidental implementation drift. [The September 3 plan](../plans/2026-09-03-proactive-behavioral-modeling.md#L6) records the distinction between model promotion and host-action approval.

I would therefore revise my first document's blanket human gate for activating learned rules: automatic shadow admission and bounded, additive notification can be appropriate with independent evaluation and explicit standing policy. Changes that suppress existing protection, disclose more data, or authorize host mutations need their own policy tests. This is a revision to my recommendation, not permission to change the repository's current gates.

I also found and accounted for the September 4 fixes. In particular, alert list/watch now use non-persisting evaluation, service census is separated from the small presentation limit, core metrics have a deterministic delivery path when intelligence is disabled, model calls have deadlines, and deterministic findings resolve collector-owned evidence. I am not reporting those earlier defects as still unfixed.

## Priorities

| Priority | Finding | Nature |
|---|---|---|
| First | Unknown observations can become recovery | Confirmed implementation mismatch |
| First | Alert state conflates episodes, acknowledgment, and delivery | Confirmed representation limitation |
| First | History and citations lose resource or observation identity | Confirmed representation limitation |
| First | Define what Descartes is protecting and what coverage it promises | Product decision |
| Next | Separate collection, evaluation, notification, and model scheduling | Architectural change supported by current coupling |
| Next | Separate ordinary retention from lost evidence and serialize state ownership | Known unresolved storage limitations |
| Next | Judge learned models by operational outcomes, not primarily self-consistency | Evaluation and roadmap decision |
| Next | Separate authority, evidence authenticity, and recommendation quality | Design-doctrine correction I recommend |
| Next | Make disclosure policy and diagnosis structure explicit contracts | Boundary and interface improvement |
| Supporting | Extract the durable core deliberately; simplify continuity and validation | Implementation and development-process improvement |

“First” means these should shape the next useful milestone. It does not mean that every other initiative must stop or that these recommendations are already approved changes.

## 1. Unknown is lost between detection and alert state

**What exists.** `safeCandidates` catches a failed detector and returns an empty candidate list. Baseline detectors also return empty lists when their evidence is insufficient or untrustworthy. The daemon merges the lists and calls the alert store without identifying which rules actually completed an evaluation. `applyAlertCandidates` treats an existing active or acknowledged alert missing from that list as recovered.

**Why this is wrong.** These outcomes have different meanings:

- The condition was checked and is no longer present.
- The detector did not run or failed.
- The evidence no longer supports making a judgment.
- The detector was disabled.
- An observed event has ended, but its consequences remain unresolved.

An empty list cannot express those distinctions. The September 4 exception isolation helps other detectors keep working, but the failed detector's previous alert can still acquire a recovery state without recovery evidence. The fixed-rule path has the same conceptual problem when a particular metric disappears from the evaluation window while unrelated metrics remain fresh.

There is a related coverage mismatch: the common `timedEnvelope` error path maps every exception to `unable` and `missing_permission`, whereas daemon health checks specifically look for `status === "error"`. Treating unsupported capabilities as benign is reasonable; treating all unavailable observations as equivalent prevents a clean distinction between expected non-support and a broken required collector.

**What I would do.** Return a per-rule assessment containing `condition: present | absent | unknown`, evaluation coverage, evidence references, and a reason. Recover a condition only after an explicit, sufficiently fresh negative assessment. Disabled monitoring should be visible as disabled coverage. An unknown assessment should preserve the open incident while marking its current condition uncertain. Keep the exception isolation.

**Acceptance criterion.** A previously failing protected service remains unresolved when its observation becomes unavailable; other detectors continue working; the owner sees the coverage loss. A later successful health check can establish recovery.

Sources: [daemon.js](../../tools/descartes-cli/src/daemon.js#L463), [daemon health derivation](../../tools/descartes-cli/src/daemon.js#L675), [alert recovery](../../tools/descartes-cli/src/alert-store.js#L260), [shared envelope error mapping](../../tools/descartes-cli/src/tools/envelope.js#L19), [service baseline trust handling](../../tools/descartes-cli/src/service-baseline.js#L836).

## 2. The alert snapshot is doing the work of an incident log and a delivery queue

**What exists.** An alert is identified by rule and fingerprint. Repeated occurrences update the same record. Acknowledgment is one value in the same status field as active and recovered. `last_notified` and cooldown are advanced during candidate evaluation, before notification delivery is attempted. Delivery has a separate audit file, but no corresponding durable pending-delivery queue in this path.

**Consequences.** A recovered condition that fails again reuses its original `first_seen`. Historical episode counts and timing cannot be reconstructed accurately from the snapshot. An acknowledged warning that worsens retains its acknowledgment status, so escalation behavior is not expressed separately. A notification failure can consume the ordinary cooldown. Recovery is represented in local state, but the current candidate/delivery path does not queue a corresponding recovery notification.

This is not hypothetical bookkeeping debt: `calibration.js` explicitly describes its firing counts as a lower bound because the alert store is a snapshot. `incident-correlation.js` uses that snapshot's `first_seen` to select recent anchors. Reusing an old record for a new occurrence means the available timestamp does not describe the new episode.

**What I would do.** Keep a current alert view, derived from a small append-only event history. Give each recurrence an episode identity under a stable condition identity. Record observed, worsened, acknowledged, uncertain, recovered, and closed transitions separately. Acknowledgment records that someone saw a particular episode/severity; it does not establish health.

Create a delivery outbox from those transitions. Record queued, attempted, accepted by the local transport, failed, and retried delivery separately. Only claim the delivery assurance the channel can establish. A desktop helper starting is weaker evidence than a confirmed display, and neither proves the owner read it. Preserve bounded retries and explicit owner suppression policy.

**Acceptance criterion.** Two failures separated by verified recovery produce two episodes; a failed notification remains retryable; worsening can notify under policy; calibration can count episodes without interpreting mutable snapshots as history.

Sources: [alert record and state machine](../../tools/descartes-cli/src/alert-store.js#L179), [delivery implementation](../../tools/descartes-cli/src/notification-delivery.js#L269), [calibration's snapshot limitation](../../tools/descartes-cli/src/calibration.js#L175), [correlation anchor selection](../../tools/descartes-cli/src/incident-correlation.js#L87).

## 3. Evidence keeps facts but loses the identity needed to use them well

### Resource identity disappears in summaries

Metric points preserve dimensions such as mount and process command, but `summarizeMetricPoints` groups only by `metric_name`. Dimensions survive as a count of distinct combinations. Consequently, disk utilization from different filesystems becomes one set of min/mean/max values; process samples from different commands and ranks can become one summary. The fixed disk rule then emits one global alert about “at least one” filesystem.

That is sufficient to say something was full. It is insufficient to identify which protected job is affected, distinguish two simultaneous disk incidents, or explain one process's resource trend. The raw points still exist within retention; the problem is the summary consumed by alerting and triage.

I would key a time series by metric plus stable resource dimensions, with an explicit separately named host aggregate where useful. Alert fingerprints should identify the resource. Preserve unit, sample coverage, and collection quality alongside the values.

### Observation identity is reused

Triage's `flattenEvidence` and the harness's evidence registry store envelopes in maps keyed by IDs such as `system-overview`, `services`, or `process-<pid>`. A repeated collection replaces the earlier envelope in those maps. The final report retains tool traces, but it does not retain every earlier envelope value as an independently addressable observation.

The new collector-owned registry is a sound improvement over accepting model-supplied evidence. It still needs occurrence identity. A citation should identify a particular observation, not whichever result was last placed under a tool-shaped label.

I would separate `observation_id`, `subject_id`, `collector_id`, and a convenient display alias. Findings and claims would cite immutable observation IDs. Repeated reads could then support before/after reasoning and contradiction checks without overwriting their evidential basis.

### Health language sometimes exceeds the measurement

The system collector calculates memory occupancy from total minus free memory; the alert calls sustained high occupancy “memory pressure.” It has not measured allocation stalls or workload impairment in that rule. Similarly, inventory of a scheduled job establishes neither successful execution nor successful restoration of its backup.

I would name the measurement honestly and add workload health or platform pressure observations where the claimed diagnosis requires them. This is a semantic improvement before it is a collector expansion.

**Acceptance criterion.** A two-disk history names the affected disk and produces separate incidents when appropriate. Two service observations in one investigation retain distinct citations. Unknown or missing samples remain distinguishable from measured zero values.

Sources: [metric generation](../../tools/descartes-cli/src/daemon.js#L178), [summary grouping](../../tools/descartes-cli/src/history-store.js#L186), [fixed alert rules](../../tools/descartes-cli/src/alert-store.js#L75), [triage flattening](../../tools/descartes-cli/src/triage.js#L135), [evidence registry](../../tools/descartes-cli/src/pi-harness.js#L39), [memory measurement](../../tools/descartes-cli/src/tools/system.js#L53).

## 4. The product lacks an explicit protection contract

The code and interface are organized around tools, metric names, detector families, and learned artifacts. I did not find an application object that says: “this backup matters, this is its expected completion schedule, this is its dependency, and this is acceptable maintenance.” The normal daemon watches resources; enabling `learned` adds structural observation and defensive detectors. The CLI's incident command is an evidence freeze, not a general incident workspace.

This leaves several valid but different product stories competing:

| Story | What determines success |
|---|---|
| Interactive sysadmin assistant | Answer a question and prepare a justified next step |
| Unattended maintenance agent | Detect failure of an important job and follow it through recovery |
| Adaptive defense agent | Detect harmful behavior while controlling missed detections and false alerts |
| Operations gateway | Execute a scoped plan with authority, verification, and cleanup |

The [roadmap](../ROADMAP.md#L15) leads with temporary-environment provisioning. The [autonomy doctrine](../design/autonomy-doctrine.md#L11) leads with authoring models and earning authority. Both are legitimate future work. Neither supplies the missing definition of what this particular installation needs kept healthy.

I would introduce a small protection contract and coverage view. Discovery suggests jobs and dependencies; the owner names their importance and acceptable behavior. An agent can help draft this from a conversation. It should not equate “has always run here” with “must always run here,” or “new here” with “unwanted.” Observed normality and desired state are different knowledge.

For the next milestone, select one unattended job, such as a service with scheduled backups, and complete its operating loop. Keep model-led natural-language triage: the operator explicitly wanted it, and it is useful. Add a deterministic status/evidence route so users can still inspect current supported health without model credentials. Do not substitute keyword matching for natural-language understanding.

The design question to settle is what a user can reasonably believe after enabling Descartes. An enabled process is not automatically an enabled protection guarantee.

Sources: [daemon profile](../../tools/descartes-cli/src/daemon.js#L65), [CLI commands](../../tools/descartes-cli/src/index.js#L97), [current triage contract](../HANDOFF.md#current-first-slice), [current learning interface](../../README.md#L272).

## 5. Slow or optional work still shares the monitoring path

The daemon collects core evidence, optionally performs a structural collection batch, persists state, evaluates many detector producers sequentially, delivers notifications, and awaits model adjudication before sleeping for the next interval. The structural collectors run sequentially under one aggregate deadline. If the batch expires, all its evidence is discarded and its checkpoint advances; `withDeadline` does not cancel the underlying collection promise.

The recent model deadline fixes matter: I am not claiming model calls remain unbounded. But a bound is not scheduling isolation. At defaults, a structural pass can consume 45 seconds and an adjudicated model call can consume 30 seconds; these precede the next interval sleep, along with the rest of the iteration. This is source-derived scheduling behavior, not a measured host-latency claim.

There are two other coupling choices I would change:

- Services, scheduled jobs, sessions, and other structural observations are gated behind the `learned.json` switch. An operator should be able to request deterministic service monitoring without opting into the whole learning/defense subsystem.
- Enabling alert intelligence disables the deterministic metric fallback. The model then decides whether metric alerts notify, and a model-path failure has no equivalent per-alert deterministic fallback in that path. This preserves the current opt-in semantics, but it means an optional intelligence feature changes a basic delivery dependency.

I would give collection domains independent schedules, deadlines, and coverage results; persist successful domains without asserting a simultaneous complete-host snapshot; and cancel or isolate expired work. Evaluate bounded state snapshots. Queue notification and model work outside the collection loop. Use a monotonic schedule that measures lateness and avoids overlapping work.

For core protection rules, the deterministic incident transition should decide notification eligibility under explicit operator policy. The model can add explanation or group related notices. If the owner explicitly permits model suppression for a class of low-priority alerts, represent that as a distinct policy with an expiry and visible audit, rather than as a side effect of enabling richer explanations.

Sources: [structural collection and deadline](../../tools/descartes-cli/src/daemon.js#L256), [aggregate timeout handling](../../tools/descartes-cli/src/daemon.js#L549), [sequential evaluation and delivery](../../tools/descartes-cli/src/daemon.js#L739), [foreground loop](../../tools/descartes-cli/src/daemon.js#L1237), [metric fallback gate](../../tools/descartes-cli/src/alert-intelligence.js#L861), [model error handling](../../tools/descartes-cli/src/alert-intelligence.js#L1540).

## 6. Storage policy can prevent the detector from doing its job

The fact store retains up to 30 days subject to a default 5 MiB cap. Ordinary byte-cap eviction contributes to degraded completeness, and degraded history prevents novelty judgments. The README now openly documents that routine churn can keep a detector cold for longer than the nominal recovery window. September 4 added a configurable byte cap, which helps capacity tuning; it did not resolve the underlying conflict.

The invariant worth preserving is: **never claim novelty beyond the history that can support it**. Requiring a long window that the configured store cannot retain does not make the detector operationally safer overall; it can leave it indefinitely unable to supply its intended protection.

I would distinguish retention expiration, expected bounded-window eviction, unexpected continuity loss, and collection gaps. A detector declares its required evidence horizon and coverage. The store reports what horizon is available. Claims become explicit—“new within the last complete seven days,” for example—and degraded protection becomes a visible state. This needs a reviewed change to the claim itself, not simply weakening the existing completeness check.

There is also a known concurrent-writer limitation. File replacement can make an individual write atomic while two writers still overwrite each other's state. Several paths repeatedly read, normalize, sort, and rewrite local JSON/JSONL; detectors independently reread common fact history. Increasing retention alone increases that work.

I would establish a single state owner immediately, then move durable records and episode transitions into a transactional local store with indexed resource/time queries. Derive baseline caches from versioned evidence. Keep a scrubbed export format for replay. A database does not authenticate observations or defeat a compromised owner; it addresses transactions, query cost, and consistency.

Sources: [fact-store bounds](../../tools/descartes-cli/src/fact-store.js#L12), [retention and ledger update](../../tools/descartes-cli/src/fact-store.js#L225), [trust predicate](../../tools/descartes-cli/src/fact-store-completeness.js#L39), [documented limits](../../README.md#L337), [concurrent-writer follow-up](../../todos/2026-08-23-fact-store-concurrent-writer-locking.md), [metric retention](../../tools/descartes-cli/src/history-store.js#L83).

## 7. The learning machinery has a stronger implementation story than an effectiveness story

The existing miner extracts stable service-presence and port-owner constraints. Calibration measures proxies from alert state, model decisions, and shadow results. It explicitly cannot measure recall and cannot count every recurrence. The new model IR and promotion ladder are pure/offline foundations; the spike still needs daemon integration, authorship, and an end-to-end go/no-go.

Separating trusted test fixtures from model-authored records and requiring both positive and negative fixture performance are good decisions. These make promotion logic more meaningful than rewarding a detector merely for remaining quiet.

They do not yet establish that the detector is useful on a real machine. A synthetic step change can show that a statistic detects a step change. It cannot, by itself, tell us whether that change represents a failure, harmless new work, planned maintenance, or a poor feature choice. Repeatedly adapting models against the same known tests can also improve test fit without improving unseen-case performance.

I would keep the thin authorship spike, but evaluate it against a simple deterministic baseline on the same corpus. Include unseen normal workload changes, real or curated operational incidents, missing observations, and owner corrections. Record false notifications per machine-day, detection delay, missed cases in labeled replay, coverage, and resource/model cost. Use held-out cases and separate operational-fit results from program-conformance tests.

The current calibration terms should remain explicitly labeled proxies. Fast recovery and model suppression are not ground-truth false positives. A useful fast-recovering alert may have prompted a successful manual fix. Notification delivery is not proof of diagnosis quality. Add outcome and correction records before using these signals to support broader authority.

I also disagree with the doctrine's implication that a fixed detector is intrinsically “fake intelligence.” An authored model is valuable when it finds a useful relationship, explains it, and improves the owner's outcome. Its novelty is not itself a product success criterion. The stronger goal is economical competence: freely investigate and propose, compile confirmed understanding into reliable cheap mechanisms, and measure whether authored models improve on those mechanisms.

Sources: [constraint miner](../../tools/descartes-cli/src/constraint-miner.js#L1), [calibration contract](../../tools/descartes-cli/src/calibration.js#L20), [offline ladder contract](../../tools/descartes-cli/src/model-ladder.js#L1), [spike status and acceptance criteria](../plans/2026-09-03-slice-1-behavioral-model-spike.md#L3), [authorship doctrine](../design/autonomy-doctrine.md#L27).

## 8. The authority doctrine combines questions that need separate answers

The doctrine correctly recognizes consent fatigue, model drift, and the limits of evidence held by a compromised process. The plan correctly keeps actual execution outside the current model-promotion ladder. The implementation's recommendation module has no execution primitive; that boundary should remain.

Where I disagree is the broad production requirement that everything above additive notification—including recommendation—depends on off-host or hardware attestation. That is a recorded operator decision, so this is a proposed reconsideration, not an unnoticed implementation defect.

There are at least four independent questions:

| Question | Relevant evidence or control |
|---|---|
| Did the system retain the observation faithfully? | Integrity, continuity, trustworthy collection |
| Does the observation support this diagnosis? | Applicability, causal evidence, counterexamples |
| Is the proposed intervention appropriate? | Preconditions, impact, dependencies, alternatives |
| May this executor perform it? | Explicit policy, scoped authority, fresh target checks |

An external witness can strengthen continuity and liveness assurances. It cannot make a poorly chosen detector diagnostically correct or determine whether restarting an important service is acceptable. Likewise, different local signals can provide useful diagnostic corroboration during ordinary faults while sharing a compromise boundary. Those are two different meanings of independence.

I would define distinct operating postures: ordinary local maintenance, stronger local integrity using a protected service boundary, and independently witnessed defense. State the assurance of evidence and the allowed actions in each. Keep policy authority independent of a detector's score. A local recommendation can be useful if it explicitly presents its evidence and limitations; suppressing protection or carrying out a disruptive action deserves a stronger gate.

The newer [state-integrity analysis](../design/state-integrity-threat-model.md#L11) already makes much of this separation and puts architectural state corrections before attestation. I would reconcile the governing doctrine with that insight. I would also replace the heuristic `reversibility × corroboration` with an explicit decision considering disruption, target scope, cumulative effect, recovery confidence, and authority. Undoing a configuration does not necessarily undo its operational consequences.

Finally, the current containment surface maps anomaly classes to generic verbs with a hash or global target and “investigate first” caveats. That is safely bounded advice, but it is not yet an actionable plan. The next useful step is an investigation that resolves the relevant subject locally and establishes applicability, not adding an executor beneath the existing mapping.

Sources: [attestation doctrine](../design/autonomy-doctrine.md#L52), [promotion/action distinction](../plans/2026-09-03-proactive-behavioral-modeling.md#L110), [integrity threat-model separation](../design/state-integrity-threat-model.md#L11), [recommendation mapping](../../tools/descartes-cli/src/containment-recommend.js#L130).

## 9. Disclosure and diagnosis need stronger application contracts

### Local collection permission and model disclosure are different

The private Pi configuration is carefully isolated from the user's personal setup. The active tool allowlist is explicit. Keep both.

Privacy enforcement, however, is spread across collectors, fact translators, sanitizers, compact prompts, and a few tool-specific projections. `jsonToolResult` sends the JSON representation of its value as model-visible text. The enabled triage tool for services removes the large census but still sends the bounded service result. Thus the README table's service-name “not sent” entry describes less than the full enabled-tool path. The compact precollection summary is not a complete inventory of model-visible fields.

I would put data classification and projection in the observation broker: a useful local owner view, a retention view, and a model-disclosure view. Each capability declares what it may send. A triage request should disclose evidence within an established model-data policy; users need a preview and sensible persistent preferences, not a prompt for each harmless field. Domain-specific hashes are pseudonymous identifiers, not a universal anonymity guarantee.

### A resolvable citation is not a verified claim

The no-evidence guard now rejects `unable` results. That is useful but does not establish relevance or sufficiency. `unverifiedEvidenceRefs` checks whether an ID exists; it cannot establish that the cited observation supports the claim. JSON diagnosis output is parsed without a full application schema validation step, and human output is model-authored text.

I would keep free natural-language reasoning but require a structured result: observations, hypotheses, conflicting or missing evidence, and bounded next checks. Validate the shape and citation identities. Display model hypotheses distinctly from deterministic findings, and give deterministic threshold conclusions their own derivation record. Mechanical claim verification is possible for some typed numerical assertions, not arbitrary causal prose; the interface should not imply otherwise.

Sources: [private session construction](../../tools/descartes-cli/src/pi-harness.js#L461), [tool policy](../../tools/descartes-cli/src/tool-policy.js#L1), [model-visible tool serialization](../../tools/descartes-cli/src/pi-harness.js#L32), [service projection](../../tools/descartes-cli/src/pi-harness.js#L95), [data-handling table](../../README.md#L433), [evidence guard](../../tools/descartes-cli/src/triage-guard.js#L11), [diagnosis parsing and output](../../tools/descartes-cli/src/triage.js#L186).

## 10. Make the durable core a real boundary, and make progress mean an operating result

The Node choice had a practical purpose: deliver a private agent harness and subscription login. The manifest and handoff make that explicit. I would not spend the next milestone rewriting that functioning interface just to make the language distribution match AGENTS.md.

But the “temporary CLI” now owns scheduling, stores, alert state, detectors, calibration, and authority-related transitions. Meanwhile, the Rust workspace contains one narrow elevated-read helper. The intended durable-core boundary has not materialized. Continuing to add core behavior inside the harness package increases the eventual extraction cost and keeps model dependencies adjacent to operations that do not need them.

I would define a versioned core protocol and ownership boundary first. Extract state ownership, observation/assessment contracts, incident transitions, and scheduling into the Rust core as coherent slices. Leave Pi, subscription auth, and conversation handling in Node behind that protocol. Port collectors where the move improves correctness, overhead, or privilege separation; do not demand a one-shot collector rewrite. The existing fixed-argument Rust helper is a useful example of a boundary justified by responsibility.

The development record also needs a shorter authoritative present tense. HANDOFF.md has multiple dated “resume here” and “start here” sections, with warnings that some are stale. ROADMAP.md still lists completed early capabilities as future steps. Detailed implementation comments often preserve the history of reviews and patches around the current behavior. That history is valuable, but a maintainer should not need to reconstruct several sessions to discover the live contract.

Keep one short current-state handoff, move historical session records to an archive, maintain a capability/coverage matrix, and write current invariants beside code. Keep review provenance in review documents and commits. A model review verdict and a passing test count are evidence about a bounded review; they are not an operating guarantee.

CI's main platform jobs currently cover Linux ARM64 and macOS Apple Silicon, while the README names Linux x86_64 Tier 1. Those test jobs exclude tag builds. The existing follow-up already records the missing x86_64 and exact-release-commit gates. Complete that work before strengthening support claims; I did not inspect live CI results in this session. Separately, add an unattended scenario benchmark so the question is not only “did all regression tests pass?” but “did the owner receive the right incident and a justified recovery?”

Sources: [Node package](../../package.json), [Rust workspace](../../Cargo.toml), [helper entry point](../../crates/descartes-root-helper/src/main.rs#L1), [current handoff pointers](../HANDOFF.md#current-status), [roadmap sequencing](../ROADMAP.md#L179), [CI jobs](../../.buildkite/pipeline.yml#L1), [platform claims](../../README.md#L459), [existing audit follow-up](../../todos/2026-09-04-codex-project-audit-follow-up.md).

## What I would build next

These are sequential operating outcomes, rather than a request to implement every recommendation at once.

1. **A truthful coverage and assessment contract.** Preserve unknown through every rule and recovery path. Separate unsupported capabilities from required-but-failing collectors. Keep previous incidents unresolved when visibility disappears.
2. **Resource-specific incidents and reliable delivery.** Preserve series dimensions and observation identities. Add episode transitions and a delivery outbox. Verify recurrence, worsening, retry, and recovery notifications.
3. **One declared protection job.** Connect a service and its scheduled backup to an owner-approved success condition. Demonstrate failed work, missing evidence, a useful notification, grounded investigation, manual intervention, and verified recovery without requiring an LLM for detection.
4. **A durable scheduling and state boundary.** Serialize state ownership, separate expensive model/notification work, and make retention compatible with explicit detector evidence horizons. Begin Rust extraction at that boundary.
5. **One measured authorship experiment.** Complete the existing thin spike with independent labeled cases, a simple baseline comparator, cost/coverage measurements, and an actual go/no-go. Automate bounded promotion according to policy if the evidence justifies it.
6. **One prepared maintenance action.** Only after incident and outcome records are reliable, introduce a typed proposal with exact subject, disruption, authority, fresh preconditions, and postchecks. Keep broader defense execution and stronger integrity postures as separate reviewed work.

The target experience is concrete: Descartes notices that a job the owner relies on is failing, explains what it knows, keeps the incident open while evidence is uncertain, helps the owner choose a justified intervention, and records whether the job recovered. Its authored models should make that experience better over time.

## Validation and limits

Ran the existing Node test suites for alert-store, alerts, daemon, history-store, triage-guard, triage, calibration, and model-ladder: **280 passed, 0 failed, 0 skipped**. The test output remained outside the repository. No implementation changes or new tests were made by this review.

The findings above are based on the cited source contracts and their composition. Passing those suites does not validate all of the proposed operating scenarios. I did not run live model sessions, activate host monitoring, exercise privileged helpers, change notification settings, run intrusion simulations, or validate release infrastructure. Runtime overhead, real-world notification quality, and the effectiveness of authored models still need measured evidence.
