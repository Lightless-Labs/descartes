# OS-guaranteed facts (F class) — opinions

**Date:** 2026-10-06. Operator asked both reviewers. Both: **ALLOW, with conditions** (narrowed to process-instance semantics; constraint, not explanation authority).

## gpt-6-astra (xhigh)

**Recommendation: ALLOW (with conditions).** Descartes may use reviewed OS semantics as explanations. But I would narrow v2’s wording: **a reboot explains the end of process continuity; it does not establish that every missing session died because of that reboot, or that the loss was benign.**

1. **The line is between guaranteed semantics and assumptions about behaviour.**

   A legitimate F fact states a conditional implication: given a verified, ordinary kernel restart, processes from the previous kernel instance cannot continue executing as those same instances. That does not require learning this host’s habits. The doctrine already permits fixed, audited primitives beneath open-ended learned models. [Doctrine:33](docs/design/autonomy-doctrine.md:33)

   The implication stops before “therefore this departure was benign,” “zero sessions is normal afterward,” or “ignore churn for ten minutes.” Those are behavioural or policy judgments. The operator explicitly requires reboot aftermaths to be learned and rejects grace periods and severity guards. [Tuning decisions:13](todos/2026-10-06-session-peer-tuning.md:13)

   This permits an actual deterministic explanation: **the cross-boot discontinuity itself need not count as an unexplained process-kill anomaly.** Its surrounding episode remains observable and scored. Boot-crossing intervals must retain uncertainty about earlier departures; they must not become ordinary zero-departure or benign training samples.

2. **Security depends on preserving event boundaries, identity, and uncertainty.**

   | Attack | Required treatment |
   |---|---|
   | Kill sessions, then force a reboot | Score departures evidenced **before** the boundary. Preserve existing alerts and pending evidence across reboot. F cannot retroactively explain them. |
   | Kill just before a scheduled update reboot | Preserve the same distinction. An update explains a reboot’s possible cause, not every nearby action. If both the kill and reboot occur between censuses, their ordering may be unobservable. |
   | Fake a boot-identity change | Require a trusted, platform-specific boot source and protected observation continuity. Clock changes, daemon restarts, HMAC-key rotation, malformed values, and collector failure must not manufacture a boot transition. Uncertain evidence cannot invoke F. |
   | Act during the post-boot period | No grace window. Score new arrivals, subsequent departures, replacements, and deviations from the learned restoration pattern immediately when evidence permits. |

   The sampling limitation is fundamental: “sessions alive at 12:00; reboot at 12:30; absent at 13:00” cannot distinguish a 12:15 kill from termination during reboot without additional evidence. **Neither F nor a pure learner can recover information never observed.** The plan acknowledges this evidence limit. [Plan:46](docs/plans/2026-10-06-context-aware-learned-baselines.md:46)

   What stays scored: **the reboot’s timing, frequency and evidenced cause; arrivals and login origins; logical identity continuity of restored sessions; missing expected restorations; same-boot departures and churn; and suspicious activity surrounding the boundary.** Score the reboot context once: its appearance in several response streams is not independent corroboration. [Plan:359](docs/plans/2026-10-06-context-aware-learned-baselines.md:359), [re-review M2:223](docs/reviews/2026-10-06-context-plan-v2-rereview-opus.md:223)

   Returning names alone cannot authenticate restoration. Current entity keys hash multiplexer plus name, while creation fingerprints hash a timestamp; neither proves a returning session has the same trustworthy identity. [Identity code:644](tools/descartes-cli/src/fact-translators.js:644), [fingerprint code:666](tools/descartes-cli/src/fact-translators.js:666)

   Keep incident evidence, episode statistics and baseline anchors across boots and beyond the raw window. Otherwise reboot or history expiry becomes an adaptation bypass. The re-review demonstrates both false event recovery and absorption of persistent loss as old data expires. [B1:51](docs/reviews/2026-10-06-context-plan-v2-rereview-opus.md:51), [H2:120](docs/reviews/2026-10-06-context-plan-v2-rereview-opus.md:120)

3. **Learned alternatives are useful, but do not eliminate assumptions.**

   | Approach | Detection and false alarms | Compliance with learning principle |
   |---|---|---|
   | Strong, overridable reboot prior | Reduces initial noise; can underweight attacks near reboot. With few episodes, contrary evidence may take months to dominate. | Legitimate P if strength, uncertainty and override evidence are explicit. Practically resembles a hand rule while prior-governed. |
   | Cross-host/federated learned prior | More reboot examples sooner; transfer mismatch and poisoned contributing hosts can cause both missed attacks and false alarms. | Learned elsewhere, adapted locally. Needs provenance, compatibility checks, bounded influence and opt-in sharing. |
   | Boot-boundary feature only | Maximum flexibility; sparse local data leaves the effect uncertain or governed by pooling/prior choices. Can continue alerting on ordinary reboots—or become insensitive through a broad predictive distribution. | Closest to the operator’s original formulation, but cannot promise rapid calibration. |
   | Longer-lived local episode memory | Eventually improves calibration without importing behavioural expectations. Does not solve the first few reboots. | Strong fit; retain it regardless of F. Extra samples describe an aftermath but are not additional independent reboot episodes. |

   H2’s scarcity objection is persuasive: changing model terminology does not create reboot examples. V2 appropriately adds long-lived statistics and identifies prior-governed cells. F solves only the guaranteed discontinuity; restoration behaviour still needs those learners. [Original H2:68](docs/reviews/2026-10-06-context-plan-review-opus.md:68), [plan:388](docs/plans/2026-10-06-context-aware-learned-baselines.md:388)

4. **Admit facts individually, with an executable scope.**

   Each entry should specify: a stable ID/version; authoritative OS contract or source; supported platforms; exact premises and conclusion; trusted evidence requirements; exclusions; and permitted downstream uses. A statement that needs “usually,” a time allowance, or knowledge of normal workloads belongs outside F.

   Review both the semantic claim and its security consequences. Test the actual source on supported OSes, plus positive, negative and adversarial fixtures: real restart, clock step, daemon restart, missing/spoofed identity, restore/snapshot cases, pre-reboot kill, post-reboot kill, and kill-and-recreate under the same name. Integration tests must prove that F neither clears unrelated alerts nor admits entire suspicious episodes into training. Log each application with its evidence and scope; contradictory observations disable applicability pending review.

   | Candidate | Judgment |
   |---|---|
   | A verified ordinary kernel restart ends previous local process-instance continuity | **Admit**, with explicit platform and restore exclusions. |
   | Kernel process identifiers require their documented boot/namespace/lifetime scope | **Admit** as identity semantics; preserve separate logical-session matching. |
   | Documented boot-relative counters require a common epoch for subtraction | **Admit** as measurement semantics. |
   | “Creation fingerprint bytes cannot survive reboot” | **Reject as stated.** Values can recur or be restored; they cannot establish continuous process identity across boots. |
   | “Reboot explains every departure since the previous census” | **Reject.** It invents causal timing. |
   | “Sessions restore within N minutes,” “VPN disconnection makes peer loss benign,” “update reboots are safe,” or “matching names prove recovery” | **Reject.** These smuggle behavioural or trust assumptions into F. |

   “Reboot” needs precise scope: Linux hibernation can boot a restore kernel and then restore the old kernel and userspace. A power cycle alone is insufficient. Likewise, Linux documents `boot_id` stability, not cryptographic attestation of observations. [Linux hibernation semantics](https://docs.kernel.org/admin-guide/pm/sleep-states.html#hibernation), [boot-ID contract](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random)

5. **Allow the class, but do not ratify v2 unchanged.**

   Three changes are necessary:

   - Narrow **§6.2’s F admission path**: explaining one semantic consequence cannot certify an entire pending observation as normal or bypass adaptation authority. [Plan:304](docs/plans/2026-10-06-context-aware-learned-baselines.md:304)
   - Reconcile **§7.1’s same-boot-only transitions and cross-boot comparison wording** with §7.6. Currently, line 332 says comparison occurs if F is ratified, while line 406 says fingerprints are not compared across boots. Specify process-instance identity separately from learned logical-session continuity. [Plan:326](docs/plans/2026-10-06-context-aware-learned-baselines.md:326), [plan:405](docs/plans/2026-10-06-context-aware-learned-baselines.md:405)
   - Fix event recovery before giving explanations operational effect: today, covered alerts absent from candidates become recovered. A quiet interval, reboot, or returning name must not automatically resolve an earlier security episode. [Recovery code:314](tools/descartes-cli/src/alert-store.js:314)

   **ALLOW** is preferable because learning should determine this machine’s behaviour while verified semantics determine what its observations mean. F ratification does not separately authorize replacing incumbent detectors or granting sticky adaptation authority. [Doctrine:126](docs/design/autonomy-doctrine.md:126)

No files modified.

## Opus 5.5 (max)

**Verdict: ALLOW, with conditions.** Allow it as an OS-semantics constraint: it fixes what an identifier can mean, which observations carry information about which parameter, and what is impossible. Do not allow it as an "explanation" with arbitration authority. It must also be narrowed. "Session departures across a boot are explained" becomes "process instances do not survive a verified boot." Everything behavioural on either side of the boundary stays learned, through a boot-boundary feature.

Two facts decide most of this.

- **v2 already applies the fact silently.** §7.1 computes departures and arrivals only "between consecutive complete censuses within the same boot" (`plan:326`). Cross-boot intervals therefore never reach the departure likelihood. That is F without any of F's obligations: the boot need not be scored, there is no tripwire, the boundary is not verified, and unobserved gaps are not reported. The re-review saw the effect: `cc2_reboot_freezes` "passes vacuously" (`rereview:74`). So rejecting Q3 honestly means deleting `:326` and alerting at every reboot until the data overrides the prior. Rejecting F while keeping `:326` would keep an unreviewed hand rule.
- **The integrity layer already relies on the same fact.** Trusted-state §5.3 says: "A changed `boot_id` is the expected signal a sequence reset is legitimate (reboot); a same-boot regression is tamper" (`2026-09-06-trusted-state-step-1.md:145`). The clamp-guard todo depends on it too. Banning the fact for learners while the integrity substrate uses it would be inconsistent.

## 1. Behaviour rule in disguise, or knowledge?

It is legitimate knowledge, as long as it stays on one side of this line: **an F fact constrains what observations are possible and what an identifier denotes. It never says what is usual, expected or benign on this host.** A candidate must pass all four tests:

| Test | An F fact passes when | A behaviour rule fails because |
|---|---|---|
| Host-invariance | No correctly working instance of the stated OS/version can violate it, under any configuration or user habit | Some host or configuration makes it false (resurrect, `KillUserProcesses`, tmpfs `/tmp`) |
| Meaning of a violation | A contradicting observation means forgery, a snapshot restore or a collector bug, so it fires an integrity tripwire | A contradicting observation means "this host is different", so it is a learning signal |
| No parameters | No rate, duration, window, threshold, "usually", "expected" or "benign" | R6 ("uptime < gap"), R7 (≥4 sessions and ≥75%), R9 (first tick after wake) |
| Evidence is conserved | It only does two things: scope identity comparisons, and remove observations that are certain given an event from the likelihood of parameters they cannot inform. That event is itself scored. | It silences, recovers, closes, admits or lowers severity |

**Why the original R6 failed these tests.** R6 (commit 7b533fc) detected a reboot by "uptime < gap since the previous structural tick", which a clock correction can fake (Astra review `:28-30`). It then suppressed `session.churn` and made `count_drop` non-notifying. That is a suppression of detector output, implicitly time-windowed, with no tripwire. F1 says nothing about what happens after the boot and nothing about what is normal.

**The example wording over-claims.**
- Sessions are keyed by name (`fact-translators.js:651-654`).
- The creation second is a separate, opaque hashed fingerprint (`:666-673`), taken from tmux `#{session_created}` (`tools/sessions.js:38`). Screen names embed the pid (`:133`).
- The OS guarantees that the *instances* end. Whether the *names* come back depends on resurrect/continuum, which is behaviour.
- So "session departures are explained" is half fact and half smuggled behaviour. F1 must be worded on instances only.

**The fact cuts both ways.** Pids, and logind session ids, are per-boot counters (logind: verify per platform), so equality across a boot is not continuity. F1 therefore also forbids a fabricated continuity or recovery.

## 2. Security

| Attack | Effect of F | What closes the gap |
|---|---|---|
| Kill sessions, then force a reboot. A macOS GUI restart typically needs no password; logind's polkit `allow_active` needs verifying. | No new blind spot. The post-boot census cannot tell "killed" from "ended by the reboot" for any model (evidence limit, `plan:46`). A pure learner alerts on every reboot, benign or not, so it does not discriminate either. | Score the reboot itself. Score restoration. The attacker pays a visible disruption and a wtmp record, and loses every non-persistent foothold, so they must rely on persistence, which activates at boot and is watched by the novelty detectors. |
| Kill timed just before an OS-update reboot | The reboot looks expected, and a kill inside the unobserved pre-shutdown gap is invisible | This is the accepted evidence limit. Shrink the gap with data: a fast-tick session-set digest, written only when it changes. Report the gap as abstention. A restoration deficit catches it only if the resurrect save postdates the kill. |
| Fake a boot boundary, by: tampering with stored state; interposing the read (PATH, which C0.1 fixes; DYLD/LD_PRELOAD through the user-writable plist); stepping the clock (boot *time* moves); a VM snapshot revert or clone | One forged field could launder a whole batch of departures | Verify the boundary by conjunction and fail closed (§4, A4). An attacker who can inject code at the daemon's UID can already forge the census itself, so F adds no capability at the top. Against an attacker who can only write state files, the conjunction holds. |
| Act in the post-boot window | F has no window. The risks are the sparse, prior-governed aftermath cell and the unobserved time between boot and the first census. | The daemon is a gui LaunchAgent, so it starts only at GUI login. The structural census runs only after a full interval (`daemon.js:972`), so after a quick reboot the first census can be up to about an hour late. Fix: a boundary-triggered census at +0 min, plus the existing +2/+10 samples (I15). F helps here, because boundary departures no longer inflate the post-boot hazard cell. |
| Reboot flooding, to make reboots look normal | None | The reboot stream sits under arbitration: pending state, and a drift budget anchored to a snapshot. |
| Scope creep: a behaviour rule registered as "F" | This is the class's real long-term risk | A closed registry of fixed primitives that the agent can never author, plus daybreak review and ratification per fact (§4). |
| Poisoning the resurrect save file | None (restoration is behaviour) | Restored does not mean trusted. Score restoration content and foreign names. |

**What must stay scored.** F1 may not activate in a learner unless items 1–5 are live in that same learner.

1. **The reboot itself:**
   - how often it occurs, given hour-of-week and presence;
   - uptime at the time of the reboot;
   - cause corroboration: whether a shutdown row exists (missing means `unknown`, `plan:203`), whether the OS build changed across the boundary (`kern.osversion` is readable unprivileged on this host), and `software_change` events later;
   - drift in reboot frequency against the anchor.
2. **Every interval that does not cross the boundary:** ordinary hazard scoring up to the last pre-boot census and from the first post-boot census onward, with no grace period.
3. **The unobserved straddle.** Report two exposures as abstention, with their durations:
   - pre-shutdown: from the last census to the boot;
   - post-boot: from the boot to the first census.

   These intervals are "unobserved", never "explained", and they never recover anything.
4. **Post-boot arrivals and identity continuity**, learned per host and labelled prior-governed until data overrides:
   - restoration deficit: a pre-boot name that does not come back on a host that has learned to restore;
   - foreign names arriving during the restore ramp;
   - content changes in restored sessions (window-count bucket).
5. **Tripwires.** Each of these is an integrity event:
   - a pre-boot instance appears in a post-boot census;
   - the boot id changes under a daemon process that never restarted;
   - the boot id regresses to an old value or is duplicated;
   - the boot time is not inside (last observation, now];
   - uptime is inconsistent with the gap.
6. **Unchanged streams:** logins, peer re-handshakes, tailnet transitions, and service/persistence novelty at boot.
7. **Pre-boot alerts.** F1 never recovers or closes them. Across a boundary, a restored name is a new instance. The re-review's B1 fix ("entity keys or names are present again", `rereview:79`) must therefore be limited to within one boot. Such an alert stays frozen until a label closes it (CC7, `plan:284-286`).

**Long memory.** F never resets, partitions or ages statistics by boot; only instance identity is scoped. Otherwise a forced reboot would become a memory-wipe tool.

## 3. Alternatives that keep it learned

All numbers are illustrative, from my own arithmetic: a within-boot hazard of 0.01 per hour, 5 sessions, all of which end at each reboot.

| Option | False alarms at reboot | Detection | Principle | Use |
|---|---|---|---|---|
| **A.** Pure learner: the boundary interval goes into the hazard, with a boot covariate shrunk toward "no effect" (the §7.4 default) | P(all 5 depart) ≈ 1e-10 at the first reboot. After k reboots, with the boot effect drawn from N(0, τ²): at τ=1, 3e-6 / 0.04 / 0.26 for k=0/1/2; at τ=0.5, 2e-9 / 7e-7 / 9e-5 / 2e-3 / 0.016 for k=0–4. The hyperprior (a P) sets the time-to-override, so at 0–3 reboots per 30 days that is about 1–6 months of per-reboot alerts, plus alerts on the resurrect ramp. | No gain: it fires for benign and malicious reboots alike, and names the wrong cause. It is also worse: boundary departures inflate the post-boot hazard, which hides post-boot kills, and the boot is counted again in every stream (re-review M2). | Not assumption-free. Its prior asserts "reboots don't end processes", which is false on every machine. Inflated surprise is the never-fabricate concern raised in re-review M9 (doctrine `:120`). An attacker can also train how far the learned effect reaches (Astra review `:16`). | Reject |
| **B.** Strong but overridable prior, e.g. Beta(50, 0.5) | Same as F (P ≈ 0.95) | Same as F, minus the tripwire | Dishonest as a P. Its required "contrary data wins" fixture (`plan:55`) needs physically impossible data, which means demonstrating a forgery path. Evidence of survival would be absorbed instead of raising an alarm. | Reject |
| **C.** Federated / cross-host prior | Low, once it exists | Same as F | Learned. But the fleet would only re-derive an OS spec, and a prior that reduces alerts needs an attested, signed feed (doctrine `:61-68, :126-129`). Not available now. | Use for behaviour: restoration rates, the restore ramp, reboot rates per OS or update channel |
| **D.** Feature only: a separate boundary regime that is not shrunk, with a weak prior (Beta(1,1) gives 1/6; Jeffreys gives 0.25) | Same as F at the first reboot | Same as F for restoration. No tripwire, and the boundary still has to be verified. | Looks learned, but exempting the boot from shrinkage *is* the OS fact, hidden in a prior choice. It also learns a parameter whose value is already known. | Use for behaviour across the boundary |
| **E.** F1 as a constraint, D for behaviour, C later | No session-stream alert at the boundary. One correctly labelled reboot event, which gets quieter as the reboot stream learns. | Best of the five: the same evidence limit, no contamination, tripwires, and honest gap reporting | Declared, tested, and honest in the inventory | **Recommended** |

## 4. If F is allowed

**Admission criteria.** Every one must hold.

- **A1.** Passes the four tests in §1.
- **A2.** Cites the OS source or specification, scoped to platform and version. On an unknown platform or version the fact is inactive.
- **A3.** Independent of configuration. If configuration can change it, measure the configuration as a fact instead.
- **A4.** Its precondition is attested by the kernel and established independently of the consequences it covers. For F1, all of the following must hold:
  - the boot id has never been seen before in the ledger;
  - the daemon process restarted;
  - the kernel boot time lies inside (last observation, now];
  - uptime is consistent with the gap;
  - no pre-boot instance appears after the boundary.

  Any inconsistency makes the fact inactive (departures are scored normally) and raises an integrity notice.
- **A5.** It has a tripwire.
- **A6.** Its effects come from a closed set: scope identity comparisons; exclude certain-given-the-event observations from the likelihood of parameters they cannot inform; fire its tripwire. It may never:
  - recover or close an alert;
  - admit or fold pending observations (remove F from `plan:306`);
  - change severity or define what is normal;
  - open any time window, or act after the first post-boot census;
  - reset memory.
- **A7.** The event that absorbs the evidence is scored in the same learner, and is no cheaper for an attacker to produce than the evidence it absorbs.
- **A8.** Necessity: show that the learned alternative is degenerate (the value is known and the same on every host) or harmful.

**Review process.**
1. Write one F-card per fact: statement, spec references, platforms and versions, preconditions, consequences, tripwire, and the broader wordings that were rejected.
2. daybreak-blue adversarial review. The two questions: can the precondition be made true without the consequence, and does the fact absorb anything behavioural?
3. Operator ratification, once per fact. That is setting the policy envelope, not per-item consent (doctrine `:39-50`).
4. Add a registry entry as a fixed, audited primitive that the agent can never author (doctrine `:33-37`), plus an inventory row.
5. Give each fact a kill switch that reverts to option D.
6. Re-verify on every OS major version. Any tripwire that fires in the field triggers re-review.

**Tests.**
- **Real-OS conformance:**
  - Linux CI VM reboot: `boot_id` changes; no pre-boot pid/starttime survives; no process starts before btime. Also test kexec, and check that soft-reboot leaves `boot_id` unchanged.
  - macOS tart VM reboot: `bootsessionuuid` changes; no tmux session has a created time before boot time.
  - macOS `launchctl reboot userspace`: record whether `bootsessionuuid` changes. `kern.willuserspacereboot` exists on this host, so the behaviour is unverified.
  - Snapshot revert: the boot-id regression is detected.
  - Laptop sleep and hibernate: measure as part of C0.9.
- **Model fixtures:**
  - `f1_boundary_excluded_from_hazard`
  - `f1_boot_event_scored` (a 03:00 reboot, screen locked, no update: it raises in the reboot stream)
  - `f1_restoration_deficit_raises`
  - `f1_foreign_arrival_raises`
  - `f1_no_cross_boot_fingerprint_compare` (unevaluated, frozen, never "clear")
  - `f1_recycled_id_not_continuity`
  - `f1_tripwire_preboot_instance` (`unknown` if a clock step was recorded)
  - `f1_fail_closed_daemon_not_restarted`
  - `f1_boot_id_regression`
  - `f1_never_changes_alert_status_or_pending`
  - `f1_straddle_reported_unobserved`
  - `f1_no_grace_after_first_census`
  - `f1_kill_switch_reverts`
- **Data needed:** a closed-enum attribute `created_vs_boot` ∈ {`after_boot`, `before_boot`, `unknown`}, computed at collection time. The fingerprint is an opaque hash and cannot be compared afterwards.

**Candidates to accept:**
- **F1.** Process instances are boot-scoped.
- **F2.** Clock domains are boot-scoped. This is already relied on in trusted-state §5.3 and the clamp guard.
- **F3.** Suspend clock semantics: the monotonic clock pauses during suspend and the boottime clock does not. This is the A5 lesson (`trusted-state:146`); C0.9 verifies it per platform.
- **F4.** Suspend and hibernate preserve process instances and boot identity. This one rules an explanation out: a sleep never explains a session departure.
- **F5.** Volatile kernel network state (sockets, WireGuard handshakes, interface instances) is boot-scoped. Keep it narrow and defer it until a learner needs it.

**Candidates to reject** (each smuggles behaviour or fails a criterion):
- "Names, sessions or peers come back after boot or wake (within N)."
- "A reboot, or an update reboot, is benign or expected."
- Any window: "the first tick after boot", "N minutes after boot".
- "A boot-id change is a reboot." This is a precondition to verify: snapshots, clones and forgery all break it.
- "Logout ends the user's processes." It depends on `KillUserProcesses` and the launchd session type.
- "A userspace reboot or soft-reboot is a boot." The kernel survives; measure it as its own fact.
- "`/tmp` or `/run` is empty after boot." Measure the mounts instead (Astra audit `:44`).
- "utmp/wtmp is complete." Use a time-confidence field instead.
- "A clock step is benign."
- "tmux server death explains all of its sessions' departures." True by construction, but the server death is a user-level, unattested event, and it is itself the mass-kill shape. It fails A4 and A7.

## 5. Recommendation

**ALLOW, with the conditions above.**

**Not REJECT.** Rejecting F does not take OS knowledge out of Descartes; it hides it. It already sits in `plan:326` and in trusted-state §5.3. Rejection would replace a reviewed, testable fact with either a known-false prior (option A: months of per-reboot criticals that cannot tell an attack from a reboot) or the same knowledge disguised as a prior choice (option D).

**Not feature-only.** For instance survival there is nothing to learn: the value is known and the same on every host. A feature can only be noise or a hidden F. For behaviour across the boundary, a feature is the right tool, and the plan should use it.

**Plan edits:**
1. Rename I33 to "process instances are boot-scoped", and rewrite §7.6 (`:405-409`) and Q3 (`:623`) around instances.
2. Remove F as an admission path in §6.2 (`:306`).
3. Fix `:332`, which is inverted ("compared only if Q3 ratifies" should read "not compared").
4. Make `:326` cite F1. If Q3 is rejected, delete `:326` and publish the boot covariate's time-to-override instead.
5. Move the reboot-event stream into C5; it is currently in C8 (`:597`). Otherwise keep F1 off until C8.
6. Narrow the re-review's B1 fix: no recovery by restored names across a boundary.
7. Add `created_vs_boot`, the OS build at the boundary, and a +0 boundary census.
8. Keep the incumbents unchanged (I35). F1 would also remove the cross-boot resurrect false positives in `session.churn` (`session-baseline.js:456-644`; Opus audit `:33`). That changes an incumbent and overlaps R6's mechanism, so it is a separate operator decision, and only with the verified boundary.

**Files.** No repo files were modified. I wrote one scratchpad script for the numbers in §3: `/private/tmp/claude-502/-Users-thomas-Projects-lightless-labs-public-descartes/be295191-32e2-4267-93c6-9cf9026e593c/scratchpad/fclass_calc.py`