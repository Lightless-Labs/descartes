# Context-aware learned baselines plan review — Opus 5.5 (max)

**Date:** 2026-10-06
**Plan:** docs/plans/2026-10-06-context-aware-learned-baselines.md (draft e4202cb)

---

# Review: docs/plans/2026-10-06-context-aware-learned-baselines.md

**Method.** I read the plan in full, then the four referenced docs. I checked every cited code location on `main` and on `feat/fact-store-capacity-2026-10` (for `fact-families.js` and `novelty-seen-set.js`). Some claims I could only check on this dev host: Darwin 25.2, a VM that has never slept. Those are marked as host observations. No repo file was modified. The only file I created is a scratch copy of `scutil --nc list` output in the session scratchpad.

**Summary.** The direction is right and matches the operator's principle: data first, context as observed facts, per-context learning, shadow before promotion, earned promotion, and the 30/31-day memory kept. It needs revision before C4 and C5:

- **Recovery contract.** It does not cover a change of context, which allows fabricated recoveries.
- **Statistics.** The proposed count model cannot represent the data. Rare-event aftermaths are controlled by the prior, not by data.
- **Attackable context.** Context is open to attacker steering, and one dimension is derived from the target stream itself.
- **Strata selection.** "The learner chooses strata" is mostly a penalty constant at work.
- **L1 sources.** Two sources are broken today: the macOS VPN parser, and how missing binaries are interpreted under launchd's PATH.
- **Memory.** Long memory conflicts with the capacity branch's budgets.
- **C7.** Replacing and retiring detectors is suppression, which the doctrine places above the on-host ceiling.

---

## Findings

### BLOCKER

**B1 (Q3). A change of context can turn an active alert into a fabricated recovery.**

- **Plan.** §5.4 says "unchanged contract" and "Context unknown or untrusted → evaluate at the parent stratum". §5.1 adds aftermath strata; §5.2 conditions tailnet peers on tailnet state.
- **Code.**
  - Alert identity is `alertId(rule_id, fingerprint)` (alert-store.js:27-30).
  - The daemon recovers any covered identity that is absent from the candidates (`applyAlertCandidates` / `coveredAlertIds`, alert-store.js:270-283).
  - A detector reports an identity as evaluated whenever it reached a verdict (session-baseline.js:904-915).
  - The codebase already treats "same rule, different scope" as a different identity for exactly this reason: peer-baseline.js:50-61 (`v2:vpn` / `v2:markerless`: "can never be recovered by a differently-scoped detector").
- **Scenario (a): reboot.**
  1. A promoted learner raises `session.count_drop` after 4 of 5 tmux sessions die, in a stratum where `since_boot` is days.
  2. The host reboots. This could be an OS-update reboot the attacker waited for, or one they trigger. On logind desktops an active local session can typically reboot through polkit without a password (verify).
  3. The first post-boot structural tick runs immediately (daemon.js:972, checkpoint due). It lands in the first `since_boot` bucket, where 0 sessions is the learned normal.
  4. The stream is reported "evaluated, clear", so the alert is recovered. The resurrect churn that follows is aftermath-normal.
- **Scenario (b): tailnet off.** A peer-drop alert is raised while `tailnet=Running`. The logged-in macOS GUI user runs `tailscale down`. The context becomes `tailnet=Stopped`, where 0 peers is normal, so the alert is recovered.
- **Scenario (c): unknown context.** The tailscale probe fails (or hits ENOENT, see H6), so `tailnet=unknown`. §5.4 sends this to the parent stratum, whose marginal includes Stopped. The alert is recovered through the plan's own fallback.
- **Fix: coverage contract v2.**
  - Alert identity carries the model/structure version.
  - An alert may recover only when it is re-evaluated, with trusted inputs, in the stratum class that raised it.
  - A context change, `unknown`, `new`, or a parent-level evaluation may raise an alert but never recover one (it freezes instead).
  - Transition and aftermath strata are additive-only until H8 is settled.
  - The C5 daybreak gate tests scenarios (a) to (c) by name.

### HIGH

**H1 (Q2). Count-level distributions are the wrong family for persistent counts that vary less than their mean. They would miss the incident the detector exists for.**

- **Plan.** §5.1 bullet 3 and §5.2 row 1 propose negative-binomial / Poisson-gamma models of the session count, with §0.5 calling the priors weak.
- **Code.** session-baseline.js:407-438 folds every complete hourly tick as an independent draw. A tmux population is a persistent state, so consecutive ticks are nearly identical and the effective sample size is far below the tick count.
- **Arithmetic.** Negative-binomial and Poisson-gamma variance is at least the mean. A host that has stably run 5 sessions gets a predictive variance of at least 5:
  - P(Y≤2 | Poisson(5)) = e⁻⁵·(1+5+12.5) ≈ 0.125.
  - P(Y=0) ≈ 0.007.
  - A 60% mass kill (5→2) is therefore unremarkable. Today's detector flags it at z = (2−5)/0.5 = −6, which is critical (session-baseline.js:76-78).
- **Effect.** The swap trades R4's false criticals for blindness to partial kills.
- **Fix: model transitions, not levels.**
  - Count departures and arrivals per interval per context, read from entity-key set differences between consecutive complete census ticks.
  - Treat churn as fingerprint-change events.
  - Use Poisson or negative-binomial rates with hierarchical priors.
  - Condition on what happened inside the interval: boot identity changed, sleep inside the interval, a transition inside the interval.
  - Then "3 departures in an hour" against a learned rate is calibrated and sensitive, and "1 departure an hour at 18:00" stays quiet with no stddev floor.

**H2 (Q1/Q2). Event aftermaths cannot be learned at this cadence and window. For them, the "weak prior" is the rule.**

- **Plan.** §0.5 (P), §5.1 bullet 4 ("peers reconnect within some learned time"), §1.
- **Cadence.** The first post-boot or post-wake structural tick fires on the first fast tick (daemon.js:972). Each event therefore yields one sample at +0–60 s and the next at +60 min. The reconnect curve and the tmux-resurrect ramp happen between ticks and cannot be seen.
- **Counts (host observation, `last reboot shutdown`).** Reboots on Jul 13, Jul 26, Aug 23, Aug 24, Aug 26 and Sep 4. Checked on Oct 6, that is zero reboots inside the 30-day retention (fact-store.js:18).
- **Effect.** The `since_boot` aftermath stratum holds 0–3 observations, so its predictive is the hyperprior or parent. That means either alerting on every reboot (the status quo) or whatever the prior encodes. Either way it is a (P) that §0.5 requires to be "shown to be overridden", and it never will be within the window.
- **Fix.**
  1. For each stream, publish a time-to-override: how many events are needed before the posterior predictive departs from the prior. Classify honestly wherever that exceeds the window.
  2. Add a class (F) for semantic facts the OS guarantees. A reboot ends every process, so departures across a boot-identity change are explained. Creation fingerprints cannot survive a boot, so comparing fingerprints across a boot is meaningless. There are no time windows and no claims about normal. Arrivals and identity continuity after reboot (resurrect restores the same session names) stay learned and scored. This is narrower than the rejected R6/R7, but the operator must ratify the class.
  3. Keep long-lived per-stratum sufficient statistics for rare-event strata beyond the 30-day raw window, under the seen-set's lineage and integrity discipline.
  4. If aftermath shape matters, take extra cheap census samples triggered by transitions (+2 and +10 min).
  5. Below support, abstain to the parent; classify that rule as (S).

**H3 (Q3). Context can be steered by an attacker, and one dimension is derived from the target. Scoring only conditionally lets an anomaly choose its own context.**

- **Plan.** §4 (`session_origin_mix`), §5.2 (tailnet peers conditioned on tailnet state), §5.3 ("the learner claims nothing about normal there"), §5.4 ("or not at all").
- **Target leakage.** `session_origin_mix` is computed from live sessions, so a kill changes the context it is scored in.
- **Thin strata during intrusion.** "Remote origin present" is a rare context created by the attacker's own login. Its stratum is the thinnest and its predictive the widest, exactly during an intrusion.
- **Toggled context.** tailnet and VPN state can be toggled from user level: GUI `tailscale down` on macOS, `scutil --nc stop`, nmcli in active Linux sessions. The attacker toggles, then acts in a stratum where loss is normal.
- **Location.** A never-seen location becomes `new`, and in `new` the detector goes silent. Joining any new network, such as a phone hotspot, blinds it. `rare → other` pools unrelated places into the widest stratum.
- **Fix.**
  1. Exclude any dimension computed from the target stream (S).
  2. Model the joint, not just the conditional. Every context dimension an attacker can influence is itself a scored stream (transition rates given the other context), so "tailnet stopped at 03:00, then peers vanish" is surprising as a pair.
  3. `new`, `unknown` and `other` must back off to the parent for raising alerts, never go silent, and never recover (B1).
  4. Learn the probability of novelty (Good–Turing: singletons / N) instead of hand-surfacing every new location.

**H4 (Q1/Q2). "The learner chooses the strata" is mostly hard selection driven by a penalty, over a hand-picked menu.**

- **Plan.** §5.1 bullets 1–2.
- **The penalty decides.** The complexity penalty is unclassified, yet it decides which context matters.
- **Hidden back-off order.** In a lattice, a stratum over k dimensions has k parents. The plan does not say which one shrinkage uses, so an implementation will impose a hand back-off order. S12's "specific → day-type → global" (roadmap line 183) is exactly that.
- **Multiple comparisons.** Keep/drop over 8 dimensions × about 8 streams, on about 400–720 autocorrelated ticks.
- **Wrong objective.** Aggregate log-likelihood is dominated by bulk ticks. Each post-boot tick gains about 5 nats (log 0.9 − log 0.007), against a BIC-like penalty of about (5/2)·ln 700 ≈ 16 nats for 5 parameters. So `since_boot`, the dimension the calibration actually needed, sits on the penalty's borderline. Out of sample it is often unlearnable, because the first reboot in a fold cannot be predicted.
- **Instability.** Selection flaps across refits, and each flip "enters at shadow" (§5.3), leading to perpetual shadow. It is also recent history, which an attacker controls, that chooses the structure.
- **Fix.** Use soft structure instead of hard selection:
  - a hierarchical log-linear model with shrinkage on all candidate effects (irrelevant dimensions shrink toward zero), or
  - Bayesian model averaging over the lattice (context-tree-weighting style), with weights shown in `baseline inspect`.
  - Use blocked, day-level temporal cross-validation only to check calibration.
  - Create a new structure version only when weights shift materially.

**H5 (Q4). `net.vpn_service_state` is not "already parsed". The macOS parser matches nothing on real output.**

- **Plan.** §1 and §3.2 ("already parsed in `vpn-peer-status.js:321-351`").
- **Code.** `SCUTIL_NC_LINE_RE` (vpn-peer-status.js:324) requires the quoted name immediately after the UUID. The test fixtures (test/vpn-peer-status.test.js:160 and :393) use that synthetic shape.
- **Host observation (`scutil --nc list`).** Real lines carry a type token between the UUID and the name:
  - `* (Connected) B91A…A702 VPN (io.tailscale.ipn.macsys) "Tailscale" [VPN:io.tailscale.ipn.macsys]`
  - `* (Disconnected) EA7E… PPP --> com.redhat.spice.0 "…" [PPP:Modem]`
- **Parser result.** Running `parseScutilNcList` on this output returned `[]`: 4 services present, 1 connected, none parsed.
- **Effect.** The source reports "ok" with zero services. That is an existing never-fabricate defect: the `vpn_service` peer source (:422-427) is silently empty on macOS, while the census marker vouches for it as "ok".
- **Also.** The list includes PPP modem services that are not VPNs, and Tailscale itself, so `vpn` and `tailnet` would be collinear on macOS. Linux has no VPN source at all (:341 returns `not_applicable`).
- **Fix.**
  - Fix the parser and add real-output fixtures as a standalone reviewed fix, independent of this plan.
  - Classify services by the bracketed type (VPN:, IPSec, PPP:L2TP versus PPP:Modem).
  - Remove the Tailscale duplicate against `tailnet`.
  - On Linux, use `nmcli -t connection show --active` and tun/wg links.

**H6 (Q4/Q3). Under the daemon's launchd PATH, a missing binary (ENOENT) is not "not installed". L1 would persist fabricated facts.**

- **Plan.** §3.2 ("`unable` / `not_installed` distinct from `Stopped`") and §3.4 ("Degrade, never fabricate").
- **Code.**
  - `daemon install` writes a plist with no EnvironmentVariables (daemon.js:1588-1597).
  - Collectors call bare binary names: tailscale-status.js:115/117 (ENOENT → absent), sessions.js:157-158 (tmux ENOENT → absent).
  - The census counts "absent" as complete (fact-translators.js:730-733).
- **Host observations.**
  - `launchctl print gui/502/com.lightless-labs.descartes.daemon` shows the agent's environment is `PATH => /usr/bin:/bin:/usr/sbin:/sbin`.
  - `tailscale` is at /usr/local/bin and `tmux` at /opt/homebrew/bin, so neither is reachable from the daemon.
  - The only persisted structural tick (2026-10-05T10:57Z) has zero tailscale-source facts while `scutil` shows Tailscale connected. That is consistent with ENOENT but not proof: the installed daemon is the Homebrew build and may not be `main`.
  - `docs/HANDOFF.md` already lists "ambient collector PATH" as a follow-up.
- **Effect.** L1 would record `tailnet=not_installed` while Tailscale is running. The existing session census would record a "complete" zero wherever tmux is Homebrew-only (not confirmed on the calibration host).
- **Fix (C0 prerequisite).**
  - Resolve every collector binary from a pinned allowlist of absolute paths. This also closes PATH hijacking.
  - Persist per-binary availability as a context fact: `resolved` / `not_found_on_known_paths` / `unable`.
  - Never emit `not_installed` from ENOENT.

**H7 (Q2/Q5). Long memory for the learners conflicts with the capacity branch's budgets, and an attacker can shorten it with volume.**

- **Plan.** §0.3, §5.3 ("why the long window stays"), §5.4.
- **Code (capacity branch, `fact-families.js`).**
  - Session budget 4 MiB (:244); peer budget 16 MiB (:245).
  - Worst-case ticks: 200×333+530 = 67,130 B (:267) and 400×392+933 = 157,733 B (:270).
  - Budget ceiling is 4× (:358). Statistical horizons are 30 h (:119).
  - Module init throws if a default budget is below its horizon floor (:348).
- **Arithmetic.**
  - At worst-case volume, 4 MiB holds about 62 ticks (≈2.6 d) and 16 MiB about 106 ticks (≈4.4 d).
  - A 30-day horizon needs 720×67,130×1.25 ≈ 58 MiB and 720×157,733×1.25 ≈ 135 MiB.
  - Both exceed the 4× ceilings (16 and 64 MiB), so registering such a horizon hits the init throw.
- **Attack.** A user-level attacker can push session count to the 200 cap. The store already holds about 1.6 MB of normal history; another ~2.6 MB of inflated ticks fills it (~39 h), after which further ticks evict the 30 days the drift guard compares against. This is visible (horizon_short or cold-start), but the long memory is gone.
- **Also.**
  - Retention is 30 days (fact-store.js:18), not 31.
  - Capacity S5 starts fresh per-family stores and quarantines legacy history (fact-store-migration.js:1-3), so learner history restarts at that upgrade.
- **Fix.**
  - Learners read a compact per-tick summary family: per-source counts, arrivals and departures, churn events, the context vector, collector availability. Its bytes per tick are bounded regardless of entity count; under 1 KB per tick keeps 30 days under 1 MB.
  - Stamp it to the family ledgers the way the seen-set is.
  - Give it its own T8 shape and a horizon of at least 30 days, and declare learner horizons in `RULE_HORIZONS`.

**H8 (Q5/Q3). C7 (replace and retire) is suppression plus sticky adaptation, which the doctrine reserves for attested settings. The plan treats it as a ladder step.**

- **Plan.** §7 ("follows the earned-trust ladder"), §8 C7, §10 Q1.
- **Doctrine.** On-host, the ceiling is additive alerting; sticky adaptation above it needs attestation. Adaptation must be bounded by a drift budget anchored to an attested baseline (autonomy-doctrine.md:110-116, :126-129).
- **Ladder.** `model-ladder.js` implements shadow → notify-only only.
- **What C7 produces.** A learner that replaces `session.count_drop` exists to stay quiet where the old detector fired. It also keeps re-fitting from rolling history. That is suppression plus continuous adaptation.
- **Tier conflict.** Session and peer detectors are WATCH-tier, default on (session-baseline.js:713-716). The doctrine keeps learned models default-OFF (autonomy-doctrine.md:134). A replacement must itself be default-on, which crosses that line.
- **Cold start.** "Retiring the hand rules" as a code deletion leaves fresh installs with neither the old detector nor a promoted learner for weeks. The roadmap §11 says "Fixed rules never weakened".
- **Fix.** Split C7:
  - (a) shadow → notify-only, additive, on the existing ladder.
  - (b) Replacement is an operator-ratified, recorded, reversible policy decision per detector family per host. That is a policy envelope, not per-item consent. It needs an explicit doctrine amendment for default-on learned replacements.
  - (c) Old detectors stay in code and keep running for any host without a promoted learner, including new installs. Retirement is per-host routing, not deletion.
  - (d) Re-fitting after promotion is bounded by a cumulative-drift budget anchored to the ratified snapshot. A rolling 30-day window is not an anchor.

### MEDIUM

**M1 (Q4). Reboot identity should be the boot ID, shared with trusted-state Phase 3.**

- **Plan.** §3.1 says "a changed boot time = a reboot".
- **Problem.** Linux btime is the realtime-minus-boottime offset (`getboottime64` = offs_real − offs_boot), so it moves with wall-clock steps. macOS `kern.boottime` is likely also adjusted when the calendar clock is set; verify in C0. A clock step could then read as a reboot.
- **Host observation.** `sysctl kern.bootsessionuuid` is readable unprivileged here. Linux has `/proc/sys/kernel/random/boot_id`.
- **Existing plans.** The repo already plans this primitive (2026-09-06-trusted-state-step-1.md:141-148; open question :301, "macOS boot_id source — verify") and has a dependent todo (todos/2026-09-08-clamp-boot-identity-guard.md). The plan mentions neither.
- **Fix.** One boot-identity primitive, owned by the B-ledger and consumed by `host_lifecycle`. The observation above answers trusted-state open question 2 for Darwin 25.2.

**M2 (Q4). Suspend and wake sources need re-grounding. DarkWake and multiple sleeps between ticks are missing.**

- **Plan.** §3.1 `suspend_interval` and `daemon_gap`.
- **Node.** Node exposes neither `mach_continuous_time` nor `CLOCK_BOOTTIME` directly.
- **macOS (host observation).** These sysctls exist unprivileged, but all read zero on this never-slept VM; verify non-zero values on a laptop in C0:
  - `kern.sleeptime` / `kern.waketime`
  - `kern.sleep_abs_time` / `kern.wake_abs_time`
  - `machdep.wake_conttime` / `machdep.wake_abstime` (their difference is the cumulative sleep at the last wake)
  - `kern.useractive_abs_time` / `kern.userinactive_abs_time`
- **Only the last event is visible.** Several sleeps between ticks collapse into one. This host's `pmset -g log` shows powerd "Holding in darkwake" assertions every hour. A tick taken during DarkWake is its own context.
- **Linux.** Total suspend ≈ `/proc/uptime` (BOOTTIME) − `process.hrtime` (MONOTONIC). Confirm libuv's clock sources in C0. `/sys/power/suspend_stats/success` counts suspends.
- **Repo history.** CLOCK_MONOTONIC pausing across suspend already caused the A5 revert (todos/2026-09-06-llm-budget-trusted-time.md).
- **Consequence.** Without a working sleep measure, `daemon_gap` cannot separate sleep from daemon-down.
- **Cadence.** Unspecified. Lifecycle reads are cheap and belong on the fast tick, aggregated into the next structural record. Hourly capture misses transitions inside the hour.

**M3 (Q4). Session origin from `who`/`last` is wrong in known cases, and the plan re-introduces a parse the code deliberately avoided.**

- **Plan.** §3.3.
- **Code.** `parseWhoOutput` (vpn-peer-status.js:89-101) has no local-host filter; `parseLastOutput` does (`LAST_LOCAL_HOST_RE`, :129). Any parenthetical is treated as remote (:409).
- **Parser run.**
  - `(:0)` → remote host ":0".
  - `(:pts/3:S.0)` (screen) → remote.
  - `(mosh [4242])` → a unique "host" per session.
  - The tty is discarded.
- **macOS.** Local logins are `console` and `ttysNNN`, not "pts without remote host".
- **Linux.** Many terminal emulators no longer write utmp, and distributions are moving to logind/wtmpdb (Y2038).
- **Login time.** A "login time bucket" means parsing yearless, locale-dependent text such as `Sep  4 16:17` (host `who`). fact-translators.js:883-886 records the decision not to do that.
- **Fix.**
  - Linux: `loginctl list-sessions` / `show-session` (Remote, RemoteHost, Service, Type, Class, IdleHint, LockedHint).
  - macOS: `who` plus IOConsoleUsers.
  - Explicit local-host patterns; keep the tty class; prefer first-observed tick over a parsed login time.

**M4 (Q2). The "per-entity login-hour distribution" is really presence hours weighted by session length.**

- **Plan.** §5.2 row 4.
- **Code.** `login_hour_bucket` is the tick hour of every presence observation (fact-translators.js:881-890), and incident-correlation.js:195-196 consumes it.
- **Effect.** A peer logged in for 10 h contributes 10 hours. Long sessions flatten the distribution and mask odd-hour arrivals.
- **Fix.** Score arrival (first-appearance) events per entity and per host. Keep presence hours as a separate, weaker stream.

**M5 (Q4). The network location fingerprint is collision-prone, confounded with tailnet state, and reversible.**

- **Plan.** §3.2 `net.location`, §4.
- **Code.**
  - `parseScutilDns` collects every nameserver regardless of interface (network.js:136-142).
  - Linux reads /etc/resolv.conf (network.js:241-246), which is the 127.0.0.53 stub on systemd-resolved hosts.
- **Host observation (`scutil --dns`).** Resolver #1 is 100.100.100.100 on utun4 (MagicDNS) and #2 is 192.168.64.1 on en0. The resolver-set hash therefore flips with tailnet state. Gateways like 192.168.64.1 or 192.168.1.1 collide across networks.
- **Hashing.** Identity hashes are unkeyed sha256 with a public domain tag (peer-signature-store.js:60, :82, :126). IPv4 addresses (2³²) and MAC addresses (about 2²⁴ per vendor prefix) can be reversed by dictionary. Default-on L1 would persist a recoverable travel log.
- **Fix.**
  - Derive location only from the physical default-route interface: gateway MAC via `arp -n` / `ip neigh`, IPv6 router-advertisement prefix, DHCP domain.
  - HMAC with a per-install secret kept outside fact history and never federated.
  - Document it in the README data table.

**M6 (Q5). L1 is not behaviour-neutral.**

- **Plan.** §2 ("Behaviour change: None") and §3.1 (`daemon_gap` "surfaced").
- **Code.** Structural collectors run one after another under a 45 s all-or-nothing deadline. On timeout, all evidence is discarded (daemon.js:989-993).
- **Effect.** More collectors, especially slow ones just after wake (network not up, 3 s tailscale timeouts), raise the odds of losing the session/peer census on exactly the ticks this plan needs most.
- **Unclassified rule.** `daemon_gap` "surfaced" is a new alert rule inside a "data only" layer.
- **Fix.**
  - Per-collector sub-deadlines (record `unable`, keep the rest), or a separate context tick.
  - Classify `daemon_gap` as (S) integrity and ship it as its own reviewed rule.

**M7 (Q5). The evaluation is not yet honest enough to promote on.**

- **Plan.** §7. calibration.js:22-23 confirms there is no ground truth.
- **Benign corpus.**
  - Real events are labelled benign by assumption, yet §7's own attack list includes a kill timed after a reboot.
  - It must be evaluated out of sample, or the benign-alert counts are optimistic.
- **No corpus on this host.** Host observations:
  - 0 reboots in the window.
  - `kern.waketime` = 0 (never slept).
  - The structural checkpoint has been stale since 2026-10-05T10:57Z.
  - Daemon stderr shows earlier ENOSPC (disk-full) errors.

  The corpus must come from the calibration laptop, with operator-confirmed labels.
- **Replay scenarios.**
  - They are written by the model's own authors, which is circular.
  - Pre-register them and add adaptive attacks: toggle-then-act, new-network-then-act, drift kept below threshold, volume eviction (H7), context-switch recovery (B1).
- **Promotion bar.**
  - There is no numeric bar, which is itself unclassified.
  - The comparison is against a detector already known to be noisy.
  - Detection delay has a floor of about one structural interval.

**M8 (Q1). Unclassified numbers and choices.** These are defects under §0.5; see the Q1 table.

**M9 (Q2/Q5). An attention budget derived "from its own history" can be gamed, and multiple testing is unaddressed.**

- **Plan.** §10 Q3, §5.1.
- **Gaming.** A threshold set as the quantile that yields N notifications a week over the model's own surprise history rises after a noisy week, or after an attacker produces benign-looking surprises.
- **Multiplicity.** Per-entity login-hour and per-source tests on every tick multiply false alarms.
- **Fix.**
  - Use calibrated predictive p-values, checked with a probability-integral-transform (PIT) histogram on held-out ticks.
  - Notify at α = N / (tests per week), allocated across tests.
  - Classify the surprise-to-severity mapping as (O).

**M10 (Q3/Q5). How the contamination guard works.**

- **Plan.** §5.3 bullet 1.
- **Ack is not a benign label.** Alert statuses are active, recovered, acknowledged, suppressed (alert-store.js:198); there is no "benign".
- **Label poisoning.** A same-user write to alerts.json can release quarantined observations into the fit. The doctrine says labels must be fed, not minted on the endpoint (autonomy-doctrine.md:126-129).
- **Stuck learners.** With R3 notify-once, alerts stay active silently, so "exclude while a related alert is active" can freeze a learner indefinitely after a legitimate change. "Related" is undefined.
- **Drift and bias.** Drift kept below threshold is admitted by construction, and excluded points bias the backtest.
- **Fix.**
  - Soft contamination weights from a mixture component.
  - An explicit `benign` label separate from ack.
  - An explicit operator path to declare a new normal.
  - The drift budget from H8(d).

**M11 (Q5). Fit cadence, compute, and a second modelling substrate.**

- **Plan.** §5 and §8 C4.
- **Cadence.** Today's detectors re-read the 31-day window on every 60 s fast tick (session-baseline.js:749-750). Hierarchical fits plus backtests at that cadence collide with the capacity branch's T9 read-cost guard.
- **Second substrate.** The estimator is a bespoke library next to `model-ir.js` (ops fact/latest/window/zscore/cusum/threshold, :249-455) and `model-ladder.js`.
- **Runtime budget.** Stratification is a cardinality-sensitive group-by, which the proactive-modeling plan (B3 / must-fix 4) requires to carry a runtime budget.
- **Fix.**
  - Fit on the structural or daily cadence; score on the fast tick from cached parameters.
  - Express stratification and the count/transition kernels as `model-ir` kernels with a budget, or justify the divergence.

### LOW

- **L1 (Q4).** Linking each multiplexer session to its creating login is mostly infeasible. The tmux server daemonizes and is re-parented, and sessions have no creator process of their own. Feasible alternative: join `tmux list-clients -F '#{client_tty} #{session_name}'` to the tty from `who`.
- **L2 (Q4). Shutdown cause.**
  - On this host, `last reboot shutdown` shows only `reboot` rows.
  - `pmset -g log` is readable unprivileged but is 1.4 MB and takes about 2.1 s here, above the collectors' 256–512 KB maxBuffer.
  - On Linux, `last -x` gives shutdown rows unprivileged. `journalctl -b -1` system logs need adm or systemd-journal group membership, so they are not unprivileged in general.
  - The existing `last` collector already reads reboot/shutdown rows and drops them (vpn-peer-status.js:124, :151).
- **L3 (Q4). Missing context worth adding.**
  - User presence and screen lock: IOConsoleUsers `CGSSessionScreenIsLocked` was readable unprivileged here (currently true); `kern.useractive_abs_time`/`kern.userinactive_abs_time`; logind IdleHint/LockedHint.
  - Power source (AC/battery) and lid state.
  - DarkWake.
  - OS and package-update events, which are the doctrine's own corroboration example.
  - Descartes restarts and upgrades.
  - Timezone and DST changes; clock steps.
  - Per-binary availability (H6).
  - Tailscale `Self.Online`, `ExitNodeStatus`, `Health` and `CurrentTailnet`. These keys are present in the live status JSON, but the parser at tailscale-status.js:76-89 keeps only BackendState and Peer. Today a non-Running backend yields no facts at all, because the envelope is "unable" (tailscale-status.js:164 → fact-translators.js:999).
- **L4 (accuracy). Two plan statements are inaccurate.**
  - §1 says there is "no context dimension" (peer-baseline.js:393-460). In fact peer-baseline already stratifies by availability-signature regime with an honest re-warm-up (:537-548), and versions identity per scope (:50-61). That is the plan's own precedent.
  - "31-day fact windows": retention is 30 days (fact-store.js:18), while the window constant is 31 days (welford-stats.js:20).
- **L5 (Q5). Sequencing.**
  - Land C2 in the same release as the capacity migration. History restarts there anyway, so context and target histories start aligned.
  - The first meaningful C6 is at least landing + 30 days; for rare events, months.
  - Add a time-boxed C4a go/no-go: replay the 2026-10-05 calibration through the current detectors, a minimal boot-ID/tailnet-state model, and the full design, before building the full machinery.
  - Linux sources need CI execution, because the dev host cannot run VMs.
- **L6 (Q2).** The tailnet "online peers" stream mostly measures the operator's other devices going to sleep. Its security value is mainly in new node keys and inbound sessions, not the online count.

---

## Answers by question

### Q1. Principle compliance

The plan adds no explicit suppress-after-X rules, and it is right to make context data. But several hand assumptions come in through classification gaps:

| Choice | Plan says | Honest class | Can data override it? |
|---|---|---|---|
| Candidate dimension menu (§4) | "candidates" | Hand-chosen hypothesis space. Acceptable if derived mechanically: every closed-enum attribute of the context families becomes a candidate. | No. A dimension not on the menu can never be learned. |
| `session_origin_mix` | candidate | Defect: derived from the target (H3) | — |
| `since_*` log-scale bucket edges | P/S | S (cardinality) plus a structural prior on where effects live. Edges finer than one tick are unobservable (H2). | No. The learner can drop the dimension, not re-bin it. |
| top-K location, rare → `other` | P/S | K is S. Pooling all rare places is a modelling choice that creates the widest stratum (H3). | Partly |
| never-seen → `new` → "claims nothing" | guard | A behaviour rule: the detector is off in a novel context (H3) | No |
| weekday/weekend `day_type` | candidate | Hand calendar assumption. Offer day-of-week and let pooling merge days. Only about 4 samples per weekday in 30 days. | Only by dropping it |
| Lattice back-off order | implicit | Hidden hand order (H4) | No |
| Prior and hyperprior strength | P | P for dense strata. For rare-event strata it is effectively the rule, never overridden within 30 days (H2). | Not within the window |
| Complexity penalty | unclassified | A magic number that decides "which context matters" (H4) | No; a defect under §0.5 |
| Anomaly-exclusion cut, "related alert" | guard | Unclassified threshold that refers to the model itself (M10) | No |
| Drift "sustained shift" magnitude and duration | guard | Unclassified, and anchored to rolling memory (H8d) | No |
| Novelty "surfaced as an event" | guard | A new hand alert rule. It should be a learned novelty rate (H3). | No |
| Surprise → notify threshold | O | O only if the model is calibrated. The history-derived version can be gamed (M9). | n/a |
| Surprise → severity | unstated | Should be O | — |
| Support needed to count as "evaluated" | unstated | S, and it governs recovery (B1) | — |
| `daemon_gap` "never normal" | rule | S (integrity) is legitimate, but it is not "data only" (M6) | — |
| Aftermath event set (boot, wake, transitions) | data | Fine as data. The shape is P but unobservable at hourly cadence (H2). | Shape: no |
| Promotion bars, refit cadence | unstated | S, unstated (M7, M11) | — |
| 30/31-day window, budgets, entity caps | S | S, correct | — |

**Is "the learner chooses strata" real?** Only partly. The learner selects among hand-chosen candidates, at hand-chosen resolutions, along an unspecified back-off order, using a criterion whose penalty is unclassified. With this data, the outcome is decided as much by the penalty as by the host, and the dimension the calibration needed (`since_boot`) is the one hard selection is least likely to keep (H4). Soft shrinkage over all candidates makes the claim true and explainable.

### Q2. Learning design

Partial pooling and predictive-surprise scoring are the right ideas, but four things undermine them here:

- **Level model on state.** The level model is misspecified for persistent counts that vary less than their mean, and makes partial kills invisible (H1).
- **Rare events.** They are controlled by the prior in a 30-day window, and aftermath shapes cannot be observed with hourly sampling (H2).
- **Hard selection.** It is unstable and suffers from multiple comparisons (H4).
- **Leakage and conditional-only scoring** (H3).

**Sample-size reality:**

- At most 720 hourly ticks in 30 days of retention; about 400 on a laptop that sleeps.
- `hour` alone gives about 17–30 ticks per bin, and night bins are near-empty.
- `hour × day_type` gives about 8–9 ticks per weekend bin.
- `since_boot` first bucket: one sample per reboot. This host had 0 in the window.
- `since_wake`: one sample per wake, so about 30–150 a month on a laptop. This is the only usable aftermath.
- The full cross product is far larger than the tick count, so the hierarchy does all the work.

**Cold start and history resets:** capacity S5 restarts history (H7), so the learners start from zero.

**Non-stationarity:** a rolling window plus hard exclusion produces either stuck models or admitted drift (M10).

**Better alternatives:**

- Birth–death (arrival and departure rate) models with interval-event conditioning (H1).
- Hierarchical log-linear models or Bayesian model averaging over the lattice (H4).
- Conformal or PIT-calibrated p-values (M9).
- The existing `cusum` kernel in model-ir.js for slow drift.
- A compact tick-summary store for memory (H7).
- First, the C4a spike measuring how much of the 2026-10-05 noise a minimal model removes (L5).

### Q3. Never-fabricate and poisoning

**Fabricated recovery.** Yes, the learners can fabricate a recovery, through context relabeling and through the unknown → parent fallback (B1).

**Suppressing alerts in a chosen context:**

- Target leakage: the kill rewrites its own context.
- Toggling tailnet or VPN from user level.
- Joining any new network, which makes the context `new` and blinds the detector.
- Hiding inside an aftermath, using a forced reboot or a predictable OS-update reboot (H2, H3).

**Shortening memory.** Inflating volume evicts the long memory (H7).

**The guards:**

- "Don't learn from anomalies" refers to the model itself and has an unclassified cut. The label channel can be forged at same-user privilege (M10).
- The drift guard is anchored to rolling memory, not to a ratified baseline (H8d).
- "Novelty surfaced" is itself a hand rule (H3).
- "Structure changes enter at shadow" is legitimate governance, but shadow fit measures recent history, which an attacker controls.

Until C7, shadow learners cannot fabricate anything. The contract still has to be fixed before C5's daybreak gate.

### Q4. L1 data

| Fact | Unprivileged source | Status |
|---|---|---|
| Boot | `kern.bootsessionuuid` / `boot_id` | Use these instead of boot time (M1). bootsessionuuid verified present here. |
| Suspend | macOS sysctls (present here, zero on this VM); Linux /proc/uptime − hrtime, suspend_stats | Last-event-only on macOS; DarkWake; verify in C0 (M2) |
| Daemon gap | Own checkpoint | Needs the suspend measure (M2, M6) |
| Shutdown cause | pmset log (readable here, 1.4 MB) / `last -x` | Linux journal needs group membership (L2) |
| Tailnet | `tailscale status --json` (Self, Health, ExitNodeStatus keys verified) | Binary path under launchd (H6) |
| VPN | `scutil --nc list` | Parser broken on real output; no Linux source (H5) |
| Location | route, arp, scoped DNS | Confounded with tailnet; collisions; reversible hashes (M5) |
| Logins | who/last → logind / IOConsoleUsers | Misclassifies local hosts; time parse is fragile (M3) |

Missing context is listed in L3. The most valuable additions are user presence and screen lock, DarkWake, and update events.

### Q5. Sequencing, evaluation, tier, other

**Sequencing.**

- Put the PATH fix (H6), the scutil fix (H5), the boot-ID/B-ledger primitive (M1) and the summary-family budget (H7) in C0 or C2.
- Land C2 together with the capacity release.
- Add C4a as a go/no-go (L5).

**Evaluation (M7).** Pre-register scenarios, include adaptive attacks, keep benign evidence out of sample, and set explicit promotion bars.

**Tier.**

- L1 under watch: yes. Collecting data is what default-on is for, once H6, M5 and M6 are fixed.
- L3 shadow under watch: acceptable only as shadow with bounded compute and no path to alerts, and with an explicit note against the doctrine's default-OFF invariant (autonomy-doctrine.md:134).
- Replacing the watch-tier session and peer detectors is an authority question (H8), not a tier choice. The correlation replacement stays learned-tier.

**Corpus host.** The corpus must come from a healthy collection host. This dev host's daemon is stale (M7).

---

## Recommended changes

1. **Coverage contract v2 (B1).**
   - Version alert identity by model structure.
   - Recover only in the stratum class that raised the alert.
   - Context change, `unknown`, `new` or parent-level evaluation may raise but never recover.
   - Aftermath strata are additive-only.
2. **Transition models (H1).** Arrivals, departures and churn per interval per context, conditioned on interval events. Levels become secondary.
3. **Semantic facts class (F) (H2).**
   - Add it alongside S/P/O for consequences the OS guarantees (cross-boot fingerprints, departures at reboot), for the operator to ratify.
   - Publish time-to-override per stream; abstain to the parent below support.
   - Keep long-lived rare-stratum statistics under the seen-set's integrity discipline.
4. **Joint context modeling (H3).**
   - Score attacker-influenceable context dimensions as streams.
   - Exclude dimensions derived from the target.
   - Back off to the parent, never go silent.
   - Use a learned (Good–Turing) novelty rate.
5. **Soft structure (H4).** Shrinkage or model averaging over all candidates; derive the candidate set mechanically; show learned effect sizes in `baseline inspect`.
6. **L1 source fixes.**
   - Fix the scutil parser with real-output fixtures, VPN versus modem typing, and a Linux nmcli source (H5).
   - Pinned absolute binary paths plus a binary-availability fact (H6).
   - Boot ID shared with the B-ledger (M1).
   - Re-grounded suspend sources; DarkWake; lifecycle reads on the fast tick (M2).
   - logind or IOConsoleUsers for origins (M3).
   - Physical-interface location with HMAC'd identifiers (M5).
   - User presence and lock, and update events (L3).
7. **Isolate L1 from the census.** L1 collectors outside the all-or-nothing structural deadline. Classify `daemon_gap` as its own reviewed (S) rule (M6).
8. **Compact tick-summary family (H7).** Bounded bytes per tick, a 30-day or longer horizon in `RULE_HORIZONS`, and learner horizons declared.
9. **Calibration and budget (M9).** Calibrated p-values checked by PIT, an α budget allocated over the number of tests, and a classified severity mapping.
10. **Contamination (M10).** Soft weights, a `benign` label separate from ack, an operator path to declare a new normal, and the drift budget anchored to the ratified snapshot.
11. **Split C7 (H8).**
    - Notify-only promotion uses the existing ladder.
    - Replacement is an operator-ratified, per-family, per-host policy decision with a doctrine amendment.
    - Old detectors stay as the floor and as rollback.
    - Post-promotion drift is budgeted.
12. **Evaluation (M7).**
    - Pre-registered and adaptive scenarios.
    - Corpus from the calibration laptop with operator-confirmed labels.
    - Out-of-sample only.
    - Numeric promotion bars classified as (S).
13. **Cadence and substrate (M11).** Fit on the structural or daily cadence and score from cache. Express the kernels in `model-ir` with a runtime budget, or justify the divergence.
14. **Sequencing (L5).** Run C4a as a time-boxed spike. Land C2 with the capacity release. Run Linux sources in CI.

---

## Ledger of claims checked

**Confirmed:**

- welford-stats.js:20, 36-89; session-baseline.js:330-368; peer-baseline.js:393-460; peer-baseline.js:54-61 (fingerprint split) and :451-453 (R8 exclusion).
- incident-correlation.js:58, 63, 67, 71.
- tools/system.js:65 and daemon.js:307 (uptime, which no model reads; metric retention is only 24 h, history-store.js:4, so no retroactive bootstrap is possible).
- tailscale-status.js:76-89 (parsed, then dropped; non-Running states emit no facts at all because of :164 and fact-translators.js:999).
- network.js:81-261 (routes and DNS collected, not persisted; only listening sockets are persisted, fact-translators.js:532-573).
- vpn-peer-status.js:87-97 (tty matched, not captured).
- fact-translators.js:882-891 (tick hour).
- alert-store.js:6, 263-268.
- model-ir.js ops fact/latest/window/zscore/cusum/threshold, with no context op.
- `fact-families.js` and `novelty-seen-set.js` exist only on `feat/fact-store-capacity-2026-10`.

**Qualified:**

- "no context dimension": peer-baseline.js:537-548 already has a regime filter.
- "31-day windows": retention is 30 days (fact-store.js:18).
- "a changed boot time = a reboot": not robust to clock steps (M1).
- "mach_continuous − mach_absolute": not callable from Node; sysctls exist (M2).
- "local sessions = pts without remote host": wrong on macOS and for utmp-less terminals (M3).

**Disproved:**

- "`net.vpn_service_state` already parsed in vpn-peer-status.js:321-351": `parseScutilNcList` returns `[]` on this host's real `scutil --nc list` output (H5).

**Not verifiable here, flagged "verify in C0":**

- libuv clock sources behind `os.uptime`/`process.hrtime` on Linux.
- polkit `allow_active` for reboot.
- macOS `kern.boottime` adjusting when the calendar is set.
- Whether the calibration host's daemon hits the launchd PATH issue.

**Files.** No repo files were modified. One scratchpad file was written (`scutil.txt`, the raw `scutil --nc list` output).

VERDICT: NEEDS-REVISION (9). n = 1 BLOCKER + 8 HIGH. The direction is sound (data first, shadow, earned promotion), so this is not RETHINK.