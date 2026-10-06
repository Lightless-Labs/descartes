# Context-aware learned baselines

**Created:** 2026-10-06
**Status:** DRAFT v2. Revised after two plan reviews and two principle audits. The operator questions in §16 are still open.
**Reviewed:** 2026-10-06 (gpt-6-astra xhigh + Opus 5.5 max; v1 NEEDS-REVISION 16 / 9)
**Revised:** 2026-10-06 (v2)
**Origin:** `todos/2026-10-06-session-peer-tuning.md` (operator reframe, 2026-10-06). This plan realizes Slice 12 of `docs/plans/2026-07-09-self-learning-stratified-monitoring.md:183` and generalizes it from time to all context.
**Inputs to v2:**
- Plan reviews: `docs/reviews/2026-10-06-context-plan-review-astra.md` (findings Astra 1–16) and `docs/reviews/2026-10-06-context-plan-review-opus.md` (findings B1, H1–H8, M1–M11, L1–L6).
- Principle audits: `docs/reviews/2026-10-06-learning-principle-audit-astra.md` and `docs/reviews/2026-10-06-learning-principle-audit-opus.md`.
- `docs/design/autonomy-doctrine.md`.
- Every finding is dispositioned in Appendix A.

**Depends on / relates to:**
- `feat/fact-store-capacity-2026-10`: per-family stores, `fact-families.js`, `RULE_HORIZONS`, seen-sets. C2 lands in the same release, because capacity S5 restarts history anyway (Opus L5, H7).
- `feat/notify-once-2026-10` (commits 33084a6 and 6af66e0): R3 episode delivery. This plan references it and does not duplicate it.
- `fix/collector-sources-2026-10`: the scutil parser (Opus H5) and absolute-path collector binaries (Opus H6), being fixed now as standalone defects. **This branch is not on this checkout at the time of writing.** This plan references it and does not duplicate it.
- The trusted-state Phase 3 boot-identity primitive (`docs/plans/2026-09-06-trusted-state-step-1.md` §5.3, :141-148, open question 2 at :301) and `todos/2026-09-08-clamp-boot-identity-guard.md`. The primitive is built once and shared.

**Verification note.** Claims marked *(verified 2026-10-06)* were re-checked against `main` @ daff6ed or on this dev host. The dev host is a Darwin 25.2 VM and is **not a corpus**:
- Its last boot was 2026-09-04 (`kern.boottime`), which is outside the 30-day retention.
- It has never slept (`kern.sleeptime` = `kern.waketime` = 0).
- Opus M7 found its structural checkpoint stale since 2026-10-05.

---

## 0. Core principle

### 0.1 The test every section must pass

Descartes is a system that **learns and adapts**. It needs **data**, **context awareness** and **the ability to learn**. It must not become an expert system, meaning a growing set of hand-written rules and magic thresholds that encode a human's (or an AI assistant's) guesses about what is normal on this machine. Real attacks unfold over days, so memory must be long.

### 0.2 What that means here

- **P1. Data, not behaviour rules.** This plan adds data and the ability to use it. It adds no "suppress X after reboot", no "ignore peers after wake", no "critical only if ≥ N". The rejected R4–R10 stay rejected. Appendix A checks that v2 reintroduces none of them.
- **P2. The machine weighs context, within a declared hypothesis space.** The plan offers candidate context and the learner decides how much each candidate matters. v2 states plainly what the learner *cannot* learn: the representation is a declared hypothesis space (class H, §0.4). Raw resolution is retained so that alternative representations can be learned later.
- **P3. Long memory stays and grows.**
  - Raw facts are kept for 30 days (`fact-store.js:18`). The 31-day constant at `welford-stats.js:20` is a read window, not retention (Opus L4).
  - On top of that come a compact per-tick summary family, long-lived sufficient statistics, and durable reference snapshots that outlive the raw window (§8).
- **P4. Safety invariants stay**: never fabricate; completeness, freshness, coverage and integrity gates; resource bounds; privilege hardening. The doctrine's authority ceiling also stays: on-host, the ceiling is additive alerting (`autonomy-doctrine.md:61-68`). Anything that reduces what alerts is governed by §11.
- **P5. Adaptation is arbitrated, never automatic** (`autonomy-doctrine.md:101-116`). Today the default tier adapts with no gate at all (§1.3). v2 fixes that early (§6.2, C1a).
- **P6. Process rule.** A calibration finding becomes a missing-data or missing-context work item. It never becomes a new threshold or suppression (Opus audit §4 item 5).

### 0.3 Evidence limit (stated, not hidden)

No statistical method can tell a benign event from a malicious one when both produce identical observed evidence (Astra 4). Context-aware scoring raises the attacker's cost: they must reproduce a familiar transition, at a familiar time, with the familiar response. It does not make attacks impossible. Attacks that are indistinguishable from benign behaviour are an accepted evidence limit, not a defect to be patched with a rule.

### 0.4 Classes

Every choice in the design is classified as one of the following. Anything unclassified is a defect.

| Class | Meaning | Obligation |
|---|---|---|
| **S** | Safety, integrity or authority invariant, or a resource bound | Never learned away. Exhaustion is visible. |
| **P** | A bootstrap prior that data overrides | Publish its strength and its time-to-override (§7.6). Provide a fixture showing contrary data wins. |
| **O** | Operator attention or authority policy | Set once in the policy envelope. It is never a claim about the machine, and it never controls training admission, recovery, or what counts as a benign label. |
| **H** | Declared hypothesis space: the vocabulary, model families and resolutions | Stated as a limit of what can be learned. Raw resolution is retained so the space can be widened later through `model-ir` composition (doctrine :33). |
| **F (proposed)** | A semantic fact the OS guarantees | Applies only if the operator ratifies it (§16 Q3). No step depends on it. |

### 0.5 Executable inventory

Each row becomes a named test in C0. Tests start pending, and the step that implements a row turns its test green. "Data can override" asks whether this host's own data can change the outcome.

| # | Choice | Class | Data can override? | Counterexample fixture |
|---|---|---|---|---|
| I1 | 30-day raw retention (`fact-store.js:18`), per-family budgets and entity caps (capacity `fact-families.js:240-249`) | S | No, by design. Exhaustion surfaces as `horizon_short`. | `inv_retention_exhaustion_visible` |
| I2 | `tick_summary` record ≤ 1 KiB; horizon ≥ 30 d registered in `RULE_HORIZONS` | S | No | `t8_tick_summary_worst_case`, `inv_summary_horizon_registered` |
| I3 | Caps on long-lived statistics and reference snapshots | S | No | `inv_longlived_cap_evicts_visibly` |
| I4 | Candidate context vocabulary (§5) | H | Partly. Any dimension can shrink to ~0; a dimension outside the vocabulary can never be added. | `inv_irrelevant_dim_shrinks`, `inv_outside_vocab_documented` |
| I5 | No dimension derived from its target stream. `session_origin_mix` is removed and VPN-service state leaves the peer population. | S | No | `inv_no_target_derived_dim` (static check on source families) |
| I6 | `since_*` bucket edges | H | Not within one structure version. A new version can re-bin from the retained raw seconds. | `inv_rebin_from_summary` |
| I7 | `net_config` top-K | K is S. The frequency ranking is learned in-fold. Pooling rare values into `other` is H. | Ranking yes, pooling no | `inv_topk_fitted_in_fold`, `cc2_new_network_raises` |
| I8 | Hour-of-week (168 cells) partially pooled toward hour and day-of-week. This replaces weekday/weekend. | H | Yes: pooling merges days the host treats alike | `inv_tue_sat_schedule_learned` |
| I9 | Lattice back-off order | Eliminated by soft structure (§7.4) | n/a | `inv_dim_order_invariant` |
| I10 | Pooling strength (hyperprior) | P | Yes in dense cells. Time-to-override (TTO) is published, and prior-governed cells are labelled as such. | `inv_prior_overridden_dense_cell`, `inv_tto_reported` |
| I11 | Complexity penalty for hard selection | Removed (no hard keep/drop) | n/a | none |
| I12 | Model families (hazard, Poisson, smoothed categorical) | H, plus an S adequacy gate | A family that fails adequacy is ineligible | `adequacy_stable3_to0`, `adequacy_5_to_2`, `adequacy_excess_zeros` |
| I13 | Aftermath shape | Learned. No shape is placed in initialisation, fixtures or admission rules. | Yes | `inv_inverse_aftermath_learned` (a host whose sessions *rise* after boot learns that) |
| I14 | Interval-event covariates (boot, suspend or transition inside the interval) | H | Their effects are learned and may be ~0 | `inv_boot_flag_effect_learned` |
| I15 | Transition-triggered extra census samples at +2 and +10 min | Offsets H; cost cap S (≤ 2 per transition, ≤ 4 per hour) | No | `inv_extra_samples_capped` |
| I16 | Support floor before a stratum counts as "evaluated" for recovery | S | No | `cc2_*` (§6.1) |
| I17 | Recovery contract CC1–CC7 | S | No | `cc2_*` (§6.1) |
| I18 | Pending state under arbitrated adaptation. It restricts authority; it is not a claim that the data is malicious. | S | No | `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_challenger` |
| I19 | Bounded-quiet period before admission without explanation | O | No (policy) | `arb_quiet_admission_consumes_budget` |
| I20 | Drift budget: mechanism, size and measure | Mechanism S; size O; measure H | No | `drift_chain_exhausts_budget` |
| I21 | Novelty probability | Learned (Good–Turing) | Yes | `inv_novelty_rate_learned` |
| I22 | Handling of `new`, `unknown`, `other` and `unstable` | S: they back off for raising, never go silent, and never recover | No | `cc2_unknown_context_freezes`, `cc2_new_network_raises` |
| I23 | TTO definition (data weight ≥ prior weight) | S (an honesty-reporting rule) | No | `inv_tto_reported` |
| I24 | Clock-step detection resolution | S (measurement resolution, not a claim about normal) | No | `l1_clock_step_detected`, `l1_no_false_step_on_suspend` |
| I25 | Per-collector sub-deadlines | S | No | `c0_context_timeout_keeps_census` |
| I26 | Components of the network-configuration fingerprint | H | No | `c0_fingerprint_component_availability` |
| I27 | Label-poisoning bound | Mechanism S; label budget O | No | `label_burst_held_pending` |
| I28 | Surprise → notification (α allocation, N per week) | O. It never deletes a detection. | No | `budget_does_not_delete_detection`, `budget_not_raised_by_flood` |
| I29 | Surprise → severity mapping | O | No | `severity_mapping_declared` |
| I30 | Promotion bars | Minimum evidence S; operator tolerance O | No | `ladder_rejects_without_preregistered_evidence` |
| I31 | Fit cadence and runtime limits | S | No | `fit_abort_keeps_last_version`, `t9_read_cost` |
| I32 | `host.daemon_gap` | A fact only, never an alert from L1 | n/a | `l1_no_alert_candidates` |
| I33 | "A boot ends all processes" | F (proposed) | n/a until ratified | `f_boot_departures_explained` (only if Q3 is yes); otherwise `f_off_departures_learned` |
| I34 | R3 notify-once | O | No | Tests on `feat/notify-once-2026-10` |
| I35 | Incumbent constants: σ 3/5, floor 0.5, N 30, `CORRELATION_ODD_HOURS`, R8 | Unchanged by this plan (the audits class them A/C) | No | None. They are retired only by per-host routing under C7b. |

## 1. Problem (corrected from v1)

### 1.1 Symptom

The real-host calibration on 2026-10-05 showed the session and peer detectors alerting on ordinary events:
- reboots (sessions 3 → 0, then tmux-resurrect churn);
- wake from sleep (the tailnet not yet reconnected);
- tailnet devices coming and going.

The cause is missing context and missing learning machinery. Wrong thresholds are not the cause.

### 1.2 What exists today (with v1's inaccuracies corrected)

- **Session counts: one global fold.** Session counts use a single Welford fold over every complete tick (`session-baseline.js:407-438`), scored at fixed σ 3/5 with floor 0.5 (`:76-78`).
- **Peer counts: already one context stratum.** v1's claim of "no context dimension" was wrong (Opus L4, Astra 11):
  - Peer counts are already stratified by the regime of collector-availability signatures (`peer-baseline.js:544-548`).
  - Identities are already versioned per scope (`:50-61`).
  - That regime pattern is this plan's precedent.
- **Context that is collected and then thrown away** *(verified 2026-10-06)*:
  - Uptime is read (`tools/system.js:65`) and stored as a 24-hour metric (`daemon.js:307`, `history-store.js:4`). No model reads it.
  - `last` reboot/shutdown rows are fetched and then dropped (`vpn-peer-status.js:124,151`).
  - Tailscale's non-Running states are parsed (`tools/tailscale-status.js:137`, `logged_out`) but the envelope becomes `unable` (`:164`) and the translator skips it (`fact-translators.js:999`). As a result, "tailnet stopped" leaves no fact.
  - Interfaces, routes and DNS are collected (`tools/network.js:81-261`), but only listeners are persisted (`fact-translators.js:532`).
  - `login_hour_bucket` is the hour of the *tick*, not of the login (`fact-translators.js:887,937`).
- **Retention.** Raw facts are kept 30 days (`fact-store.js:18`) while the read window is 31 days (`welford-stats.js:20`). On `main` the 5 MB shared store (`:19`) holds about one day at measured volume (Opus audit §1d).

### 1.3 Adaptation without arbitration (both audits; Opus audit §1g)

- **Novelty detectors.** They report every entity in the historical union as evaluated (`service-baseline.js:455-476`). A new service or lineage edge therefore fires once, and its alert flips to `recovered` on the next tick. HANDOFF 2026-09-27 adjudicated this as "edge-triggered transition notices": it is safe against fabrication, but it absorbs an installed persistence as normal one hour later with no arbitration.
- **Statistical detectors.**
  - Sessions score a tick and then fold it on the next call even when it alarmed (`session-baseline.js:415-428`).
  - Peers exclude only overflow and invalid-marker ticks (`peer-baseline.js:563-594`).
- **Result.** This inverts the doctrine's "never adapts a model to unattested change" (`autonomy-doctrine.md:103`).

### 1.4 The outcome loop is broken (Astra audit rank 3)

- **The counting defect.** `fired_count` is `row.alerts.length` over the `alerts.json` snapshot (`calibration.js:245`). Alert identity is stable, so repeated fire/recover cycles collapse into a single record.
- **The effect.** Retuning needs at least 2 fires (`tuning-store.js:427`), so it can never trigger for a flapping constraint. The Astra audit verified that ten cycles yield `fired_count: 1` and no proposal.
- **No labels.** Acknowledgement records receipt only (`alert-store.js:366-376`). The only statuses are active, recovered, acknowledged and suppressed (`:198`). No label reaches any learner, and recall is `null` by design (`calibration.js:64`).

### 1.5 Data sources that are defective today *(verified 2026-10-06)*

- **macOS VPN services.** `parseScutilNcList` returns `[]` on this host's real `scutil --nc list` output. The output has 4 services, 1 of them connected. The parser regex (`vpn-peer-status.js:324`) fails because real lines carry a type token between the UUID and the name (Opus H5).
- **Login origin.** `parseWhoOutput` turns `(:0)` into the remote host `":0"` (`vpn-peer-status.js:89-102`; Opus M3, Astra 12).
- **Binary lookup under launchd.**
  - The daemon's launchd PATH is `/usr/bin:/bin:/usr/sbin:/sbin`.
  - The installed plist carries no `EnvironmentVariables` (`daemon.js:1596`).
  - Collectors `execFile` bare binary names (`tools/sessions.js:40-47`), so `tailscale` in /usr/local/bin and `tmux` in /opt/homebrew/bin resolve to ENOENT, which is reported as `absent` (Opus H6).
- **Sanitizer.** `isSafeEnumString` checks charset and length only (`diagnostics-sanitizer.js:30,44-46`). It does not validate against a schema (Astra 14).
- **Collection deadline.** Structural collectors run one after another (`daemon.js:395-403`) under one 45-second all-or-nothing deadline that discards every result on timeout (`daemon.js:984-993`; Opus M6).

### 1.6 Memory versus budgets (Opus H7)

- **Capacity-branch budgets.** On the capacity branch, the session budget is 4 MiB and the peer budget 16 MiB (`fact-families.js:244-245`).
- **Worst-case horizon.** At worst-case ticks of 67 KB and 158 KB, those budgets hold only ~2.6 days and ~4.4 days of history.
- **No room for 30 days.** A raw 30-day horizon at worst case exceeds the 4× budget ceiling (`:358`).
- **Volume attack.** An attacker who inflates volume can evict the long memory.

## 2. Design overview

| Part | What | Behaviour change |
|---|---|---|
| **C0 Prerequisites** (§3) | Source fixes, absolute-path binaries, field schemas, per-collector sub-deadlines, boot identity, suspend grounding | Removes existing fabrications. A failure now loses one collector's evidence, not the whole tick's. |
| **Outcome substrate** (§9) | Append-only alert transitions, labels, the `fired_count` fix | None on detection. Calibration counts become correct. |
| **Arbitrated adaptation** (§6.2) | Alarmed observations go to `pending`, which is retained but not folded | Changes the existing detectors: they stop silently absorbing alarmed evidence. The novelty alert lifecycle depends on Q4. |
| **L1 Context facts** (§4) | Lifecycle, network and session context as facts with event-time intervals | Data only. No alert candidates. |
| **L1s Long memory** (§8) | `tick_summary` family, long-lived sufficient statistics, reference snapshots | Data only. |
| **L2 Context vector** (§5) | A pure, versioned function from `tick_summary` | None. Visible in `baseline inspect`. |
| **L3 Learners** (§7) | Transition models; context dimensions as scored streams; soft structure | Shadow only, one vertical learner first. |
| **Coverage contract v2** (§6.1) | Recovery semantics for every learned alert | Applies from the first shadow record. |
| **Authority** (§11) | Additive promotion on the ladder; replacement only by a ratified envelope | Per §11 and Q2 |

## 3. C0: data-source prerequisites

| Id | Defect | Fix | Owner | Gate |
|---|---|---|---|---|
| C0.1 | ENOENT under launchd is read as "not installed" (Opus H6) | Resolve every collector binary from a pinned allowlist of absolute paths, which also closes PATH hijacking. Never emit `not_installed` from ENOENT. | `fix/collector-sources-2026-10` (in progress). This plan adds the fact `collector.binary_state` ∈ {`resolved`, `not_found_on_known_paths`, `unable`}. | daybreak (on that branch) |
| C0.2 | The scutil parser matches nothing on real output (Opus H5) | Real-output fixtures; classify by the bracket token (`VPN:`, `IPSec`, `PPP:L2TP` versus `PPP:Modem`); dedupe the Tailscale NE service against the tailnet. Linux: `nmcli -t connection show --active` plus tun/wg links, CI-gated. | `fix/collector-sources-2026-10` for the parser; the classification and Linux source here | daybreak |
| C0.3 | The Tailscale envelope drops non-Running state (`tailscale-status.js:137,164` → `fact-translators.js:999`); the parser requires `Peer` even to observe backend state (`:81`) | Emit `net.tailnet_state` for every probe outcome. Parse `BackendState` without requiring `Peer`. Add `Self.Online`, exit-node-in-use, a health-issue count bucket and an HMAC of `CurrentTailnet`. | this plan | daybreak |
| C0.4 | Login-origin parsing (Opus M3, Astra 12): `(:0)`, `(:pts/3:S.0)` and `(mosh [pid])` all become remote; macOS local sessions are `console` and `ttysNNN`; `last` re-reads the same rows on every tick | Linux: `loginctl list-sessions` and `show-session` (Remote, RemoteHost, Service, Type, Class, IdleHint, LockedHint). macOS: `who` plus IOConsoleUsers. Explicit local-host patterns; keep the tty class; use the first-observed tick, never a parsed login time (decision kept from `fact-translators.js:882-886`). Dedupe `last` rows by row digest across ticks. | this plan | daybreak |
| C0.5 | The "location" fingerprint collides, is confounded with the tailnet, and is reversible (Opus M5, Astra 14) | Rename it `net.config_fingerprint`. Components: physical default-route interface kind; gateway MAC (`arp -n` / `ip neigh`); IPv6 router-advertisement prefix; DHCP domain; resolvers scoped to the physical interface only (not MagicDNS). Each component carries its own availability. HMAC with a per-install key stored outside fact history (state dir, 0600, never federated). Document it in the README data table. | this plan | daybreak |
| C0.6 | The sanitizer is not a schema validator (Astra 14) | A closed per-field schema for each new family: enum sets, hash/HMAC formats, integer ranges. Validated at the translator. A rejected field yields `unable`, never a write. Hash at source. | this plan | daybreak |
| C0.7 | The all-or-nothing structural deadline (Opus M6) | Per-collector sub-deadlines inside the 45 s budget. Context collectors run after the session/peer census and record `unable` on timeout. They never cost the census. Cheap context reads bracket the census (§4.4). | this plan | daybreak |
| C0.8 | Reboot inferred from boot *time* (Astra 3, Opus M1) | One boot-identity primitive owned by the trusted-state B-ledger: macOS `kern.bootsessionuuid` (*verified 2026-10-06* readable unprivileged on Darwin 25.2, which answers trusted-state open question 2 for this OS version); Linux `/proc/sys/kernel/random/boot_id`, CI-gated. `todos/2026-09-08-clamp-boot-identity-guard.md` consumes the same primitive. | shared with trusted-state Phase 3 | daybreak |
| C0.9 | Suspend sources are ungrounded (Opus M2) | Measure on a real laptop and write up the result: the macOS sysctls (`kern.sleeptime`/`waketime`, `kern.sleep_abs_time`/`wake_abs_time`, `machdep.wake_abstime`/`wake_conttime`; all zero on this never-slept VM); Linux `/proc/uptime` − `process.hrtime` (confirm libuv's clock sources) and `/sys/power/suspend_stats/success`; whether DarkWake is detectable cheaply. The A5 revert (`todos/2026-09-06-llm-budget-trusted-time.md`) is the cautionary precedent: CLOCK_MONOTONIC pauses during suspend. | this plan | review |
| C0.10 | Inventory | Land the §0.5 rows as pending named tests | this plan | review |
| C0.11 | Horizons | Re-verify the capacity branch's real retention and every joined family's certified horizon (Astra 10) | this plan | review |

## 4. L1: context facts

New families in the `fact-families.js` registry. Each family gets its own budget (pinned worst-case bytes per tick × horizon), its own ledger and trust gate, and a seen-set where useful.

### 4.1 `host_lifecycle`

| Fact | Source | Semantics (honest) |
|---|---|---|
| `host.boot` | Boot identity (C0.8), plus the reported boot time (`kern.boottime`, `/proc/stat btime`) as an attribute | A reboot is a **boot-identity change**, never a boot-time change. Boot time moves with wall-clock steps (Linux btime = realtime − boottime; macOS adjusts it when the calendar is set). Every `tick_summary` record carries the boot id and the seconds since boot, so `since_boot` never depends on a single event surviving retention (Astra 10). |
| `host.suspend` | Fast-tick (60 s) paired-clock deltas, aggregated into the next structural record | Aggregate suspended duration within (t_prev, t_now], as `[lower, upper]` bounds, and the number of suspends only where the OS exposes a counter. **No invented start or end instants** (Astra 3): two 20-minute sleeps and one 40-minute sleep in the same interval are indistinguishable. A "last wake" sysctl bounds one wake; it does not prove there was only one. |
| `host.darkwake` | Only if C0.9 finds a cheap unprivileged signal | Its own context value; absent otherwise. Never guessed. |
| `host.clock` | Fast tick: wall-clock Δ versus boottime-clock Δ; timezone id (hashed) plus UTC offset | A `clock_step` event (magnitude bucket) when the gap exceeds measurement resolution (I24); timezone and DST change events. Local-time features are computed from the **stored** offset, never from the current timezone (Astra 10). |
| `host.daemon_gap` | The daemon checkpoint versus now, split using `host.suspend` | Cause ∈ {`suspended`, `daemon_not_running`, `unknown`}. **A fact only** (Opus M6). An integrity alert on unexplained gaps, if wanted, is a separate reviewed (S) rule outside this plan. v1's "never treated as normal" was a behaviour rule and is withdrawn (Astra 6). |
| `host.lifecycle_record` | `last` reboot/shutdown rows, already fetched and dropped today (`vpn-peer-status.js:124,151`); `last -x` on Linux | Historical records with a time-confidence field, deduped by row digest. A missing shutdown row is `unknown`; it means neither "unclean" nor "clean". `pmset -g log` is dropped from v2: it is 1.4 MB and takes ~2.1 s, above the collectors' maxBuffer. Reading `journalctl -b -1` needs group membership, so it is not used (Opus L2). |

### 4.2 `network_context`

| Fact | Source and notes |
|---|---|
| `net.tailnet_state` | `BackendState` (closed enum), `Self.Online`, exit node in use, health-issue count bucket, `CurrentTailnet` HMAC. Emitted for every probe outcome: `logged_out`, `binary_not_found_on_known_paths` and `unable` are values (C0.3). `Online` means the node is connected to the control plane. It does not prove peer reachability (Astra 11). |
| `net.vpn_service_state` | Per-service state with HMAC'd uuid and typed kind (C0.2). **Leaves the peer population for the learners**, because a connected VPN service is currently counted as a "peer" (`vpn-peer-status.js:420-427`), so using its state as context would restate the target (Astra 4). The incumbent detector is unchanged. |
| `net.config_fingerprint` | C0.5. Renamed from "location", because it is an observed configuration, not a place. |
| `collector.binary_state` | C0.1 |
| `context.transition` | Old → new for any of the above, with the event-time interval (prev_obs_ts, obs_ts]. Never an instant. |

### 4.3 `session_context`

| Fact | Source and notes |
|---|---|
| `session.login_arrival` | The first-observed tick of a login record (C0.4). Origin class ∈ {`console`, `local_tty`, `local_display`, `remote`, `remote_mosh`, `unknown`}; remote host HMAC'd; tty class. Repeated sightings are not repeated logins (Astra 12). |
| `session.attachment` | `tmux list-clients -F '#{client_tty} #{session_name}'` joined to the login tty (Opus L1). This replaces v1's "creator lineage", which is infeasible: the tmux server daemonizes, and exited creators cannot be recovered (`tools/provenance.js:140`). |
| `user.presence` | Screen locked and idle bucket where readable unprivileged (IOConsoleUsers `CGSSessionScreenIsLocked`; logind `LockedHint`/`IdleHint`) (Opus L3) |
| Later candidate families (not C2) | `software_change` (package and update events, the doctrine's own corroboration example at `autonomy-doctrine.md:105`); power source and lid. The Descartes version and config hash ride in `tick_summary` from C2. |

### 4.4 Rules for all L1 facts (S)

- **Closed schemas** (C0.6); hash or HMAC at source.
- **Degrade, never fabricate.** The states are `ok`, `partial`, `unable`, `not_applicable` and `binary_not_found_on_known_paths`, and an unavailable value is recorded as such.
- **Event time is distinct from observation time.**
  - Today the daemon stamps every family with the same tick `ts` (`daemon.js:1017-1028`), even though collectors run one after another (`:395-403`). So a VPN can reconnect between the census read and the context read, producing a context/response pair that never coexisted (Astra 10).
  - Fix: each fact carries per-collector `obs_start` and `obs_end`.
  - Cheap context is read both before and after the session/peer census. If it changed in between, the tick's context is `unstable` (§6.1: it may raise, never recover).
- **Bounded** per-tick counts and bytes, with a T8 invariant per family.
- **No new privilege, and no alert candidates from L1.**

## 5. L2: context vector

`contextAt(tick_summary_record) → ContextVector` is pure and versioned, and it can be recomputed from the `tick_summary` family alone (§8.1).

| Dimension | Raw value retained | Default encoding | Notes |
|---|---|---|---|
| `since_boot` | Seconds since boot plus the boot id | Log-scale buckets (H, I6) | The edges can be re-derived from the raw value |
| `since_wake` | Interval bounds | Bucket, or `uncertain` when the interval straddles an edge | `uncertain` counts as unknown for recovery |
| `tailnet` | Enum | Enum | Also a scored stream (§7.3) |
| `vpn` | Per-service HMAC state | Any / none, and per service | Also a scored stream |
| `net_config` | HMAC fingerprint | Frequency-ranked identity (K: S), `other`, `new` | `new` and `other` may raise, never recover |
| `hour_of_week` | Local time plus the stored UTC offset | 168 cells, partially pooled toward hour-of-day and day-of-week | Replaces weekday/weekend, so a Tuesday–Saturday schedule is learnable (Astra 6) |
| `presence` | Locked, idle or active | Enum | |
| Interval events | Boot, suspend, transition or clock step inside the interval | Flags | Covariates for the transition models (§7.1) |

- **Removed.** `session_origin_mix` is removed because it was computed from live sessions, so a kill rewrites its own context (Opus H3).
- **Leakage rule (S).** No dimension may be derived from the families of the stream it conditions. A static check over the source families enforces this (I5).
- **Missing values.** `unable`, `unstable` and missing inputs give `unknown`. `new` (never seen) and `other` (rare) are values in their own right. None of them is ever silence.
- **Versioned mapping.** The vocabulary and top-K mapping are versioned. In evaluation they are fitted inside each fold from preceding data only (Astra 9, Astra 10).

## 6. Coverage contract v2 and arbitrated adaptation (security-critical)

### 6.1 Coverage contract v2 (Astra 2, Opus B1)

**Today.**
- An alert's identity is `alertId(rule_id, fingerprint)` (`alert-store.js:27-30`).
- Any covered identity that is absent from this tick's candidates is recovered (`:313-321`).
- The daemon checks only the owner and the identity (`daemon.js:834-850`).

**The risk.** A context-conditioned learner that reports an identity as evaluated after a context change fabricates a recovery. Opus B1 gives three scenarios: a reboot, `tailscale down`, and the unknown → parent fallback that v1 itself proposed.

- **CC1 Identity.** For a learned alert, fingerprint = `v3:<lineage>:<structure_id>:<stratum_class>`.
  - `structure_id` versions the representation and structure: the vocabulary mapping, the model families and the dimensions.
  - `stratum_class` is the canonical hash of the raising cell over the *state* dimensions (`since_boot`, `since_wake`, `tailnet`, `vpn`, `net_config`, `presence`), plus the evaluation level (leaf or backed-off). Calendar dimensions are excluded on purpose; CC3(e) covers them.
  - The record carries `raise_ref`: the full raising cell including calendar, the digest of the parameter snapshot, and an evidence summary (for example the at-risk count and the departures).
  - Precedent: the scope-versioned `v2:vpn` / `v2:markerless` identities (`peer-baseline.js:50-61`).
- **CC2 Raise.** Any trusted evaluation may raise, including a backed-off one (`unknown`, `new`, `other`, `unstable`, below support). It then uses the wider backed-off predictive and is never silent (Opus H3).
- **CC3 Recover.** All of the following must hold:
  - (a) a fresh, complete census and trusted fact history (the existing gates);
  - (b) the same lineage and the same `structure_id`;
  - (c) the current state cell equals `stratum_class`, and every state dimension is known and stable;
  - (d) a leaf-level evaluation with support at or above the floor (I16);
  - (e) the observation is unsurprising **both** under the current predictive **and** under the raising parameter snapshot. The evidence itself must have changed: a refit, a change of hour or a slow walk between raise and re-evaluation can never clear an alert on unchanged evidence (Astra 5);
  - (f) the lineage is not in a drift-budget excursion (§11.3).
- **CC4 Otherwise freeze.** The identity is not reported in `evaluatedAlertKeys`, and the alert keeps its status. Under notify-once a frozen alert is silent.
- **CC5 Successors.** A successor version or replacement never reports a predecessor's identity as evaluated.
  - Predecessor parameter snapshots are retained, within bounds (§8.3), so the predecessor's own pure re-score can still recover its alerts under CC3.
  - If the snapshot is gone (history loss), the alert stays frozen until a label closes it.
- **CC6 Raise-only cells.** Transition and aftermath cells are raise-only until replacement authority is settled (§11, Q2).
- **CC7 Closure without recovery.** An operator label (§9) closes an alert, with a reason. Time, context change and model change never close one.

**Stated consequence.** After a reboot, a pre-reboot alert in the session-departure family **freezes**. It stays frozen until the host is back in the raising stratum class with the evidence restored, or until the operator labels it (`descartes alerts label <id> expected|benign|mine|suspicious`, §9). This is the intended behaviour, not a bug.

**Named gate tests (C5 daybreak):**

| Test | Setup | Expected |
|---|---|---|
| `cc2_reboot_freezes` | Alert raised with `since_boot` = days. The boot id changes, and the first post-boot tick has 0 sessions, which is normal in the first `since_boot` bucket. | Not recovered; frozen. A new alert appears only if the post-boot cell itself finds the tick surprising. |
| `cc2_tailscale_down_freezes` | Peer-departure alert raised with `tailnet=Running`. Then `tailscale down`, and 0 peers online. | Frozen. The tailnet transition is scored as its own stream (§7.3). |
| `cc2_unknown_context_freezes` | The tailnet probe fails (`unable`) → `tailnet=unknown`; the backed-off predictive accepts the current count | Frozen. May raise. |
| `cc2_new_network_raises` | A never-seen `net_config`, then a session kill | Raises through the backed-off predictive; never silent |
| `cc2_model_replacement_no_clear` | v1 alert active; structure v2 promoted; evidence unchanged | v2 does not recover it. The v1 alert stays frozen and recovers only through the v1 snapshot once the evidence is restored. |
| `cc2_refit_no_clear` | A refit widens the predictive between raise and re-evaluation; evidence unchanged | Frozen (CC3e) |
| `cc2_hour_change_no_clear` | Raised at 17:00; at 18:00 the same count is normal for 18:00 | Not recovered: still surprising under the raising snapshot |
| `cc2_unstable_context_freezes` | Context changes between the bracketing reads | Frozen |
| `cc2_evidence_restored_recovers` (positive control) | Same cell; the sessions return | Recovered |

### 6.2 Arbitrated adaptation (audit §1g; Astra 5; Opus M10). Early and security-critical

**Rule (S).** An observation that raised an alert enters `pending`. Pending observations are **retained**, never deleted. They are not folded into any authority-bearing baseline, and not added to a seen-set as normal, until one of the following explains them:

1. **Context.** The explanation must come from a model with the authority to explain: a promoted learner whose predictive finds the observation unsurprising in its stratum class. If Q3 ratifies the (F) class, an OS-guaranteed fact can also explain. A hand rule such as "a reboot explains it" never can.
2. **Label.** `expected`, `mine` or `benign` (§9), subject to the label-poisoning bound.
3. **Bounded quiet.** The pending item persists, with no further anomaly, for the bounded-quiet period (O, I19).
   - Admission consumes the cumulative drift budget anchored to the reference snapshot (§8.3).
   - Each admission is logged as `admitted_unexplained` and listed in a digest: notification, not confirmation (`autonomy-doctrine.md:46-50`).
   - When the budget is exhausted, admission needs a label.

**Challengers still see everything.** Shadow challengers fit on all trusted data, pending included, with soft contamination weights from a mixture component (Opus M10). The incumbent therefore does not decide what a successor may learn, which resolves the deadlock in Astra 5 where every legitimate reboot fires the old detector and quarantines exactly the aftermath data the successor needs. Only authority-bearing state is restricted.

**Applied to the existing detectors (step C1a):**
- **Session and peer Welford folds.** An alarmed tick is no longer folded on later calls (today it is: `session-baseline.js:415-428`, `peer-baseline.js:589-594`). It moves into a bounded pending pool (S cap) stored with its alert.
- **Novelty seen-sets (service, lineage, scheduled job).** A novel entity is recorded as `pending`: it is not re-alerted, and it does not count as learned-normal.
- **Novelty alert lifecycle.** Keeping the alert `active` until it is explained, instead of today's one-tick `recovered`, reverses a design adjudicated on 2026-09-27 (`service-baseline.js:455-476`; HANDOFF 2026-09-27). That reversal is **operator question Q4**. Until Q4 is answered, C1a ships only the fold and seen-set changes and leaves the alert lifecycle as it is.

**Fixtures:** `arb_alarmed_tick_not_folded`, `arb_pending_retained_for_challenger`, `arb_quiet_admission_consumes_budget`, `arb_budget_exhausted_requires_label`, `label_burst_held_pending`.

## 7. L3: learners

### 7.1 Model transitions, not levels (Opus H1, Astra 8)

Sources: sessions, SSH logins, WireGuard peers with an active handshake, tailnet node keys. VPN services are context, not a source. For each source, between consecutive complete censuses within the same boot:

- **Departures** D_t = |S_{t−1} \ S_t|, taken from entity-key set differences in the census facts. They are modelled as a hazard on the at-risk set: D_t ~ Binomial(|S_{t−1}|, 1 − exp(−λ(ctx)·e_t)). The exposure e_t is the awake seconds in the interval: wall-clock Δ minus the upper bound on suspended time.
- **Arrivals** A_t ~ Poisson(μ(ctx)·e_t).
- **Churn.**
  - Within one boot, churn is a name that reappears with a new creation fingerprint.
  - Across a boot, it is compared only if Q3 ratifies (F). Otherwise it is learned with the boot flag as a covariate.
- **Interval events as covariates**: a boot, a suspend, or a transition inside the interval. Exposure adjusts every rate.
- **Why transitions.** A level model is the wrong family for this data:
  - Under a level model, a host that has stably run 5 sessions gets Poisson(5), so P(Y ≤ 2) ≈ 0.125: a 60% kill is unremarkable.
  - Under the hazard model, with a learned per-session hazard of ~0.01 per hour, three departures in one hour have probability ≈ C(5,3)·0.01³ ≈ 1e-5.
  - A single departure at 18:00 stays quiet if this host's 18:00 hazard is high, with no stddev floor involved.
- **Levels (occupancy)** become a secondary stream. Its model may be underdispersed: for example, a Dirichlet-smoothed categorical over the counts observed per cell.
- **Logins** are scored as arrival events, per entity and per host. Presence hours become a separate, weaker stream (Opus M4).
- **Tailnet online count** becomes a secondary stream, since it mostly measures the operator's own devices sleeping. Node-key novelty and inbound sessions are the primary tailnet streams (Opus L6).

### 7.2 Model-adequacy gate (S mechanism over the H family set)

**Gate.** Before a family is eligible for a stream, it must pass three checks:
- a dispersion index;
- PIT calibration on held-out days;
- the mandatory fixtures below.

**Mandatory fixtures:**
- `adequacy_stable3_to0`: the drop must be at least as surprising as the incumbent finds it today. The incumbent scores z = −6 (Astra 8, `session-baseline.js:76`).
- `adequacy_5_to_2`: the 5 → 2 drop must be flagged.
- `adequacy_excess_zeros`.
- `adequacy_regime_change`.

**On failure.** A family that fails is ineligible, and the stream stays on its incumbent.

### 7.3 Learn the joint, not only the conditional (Opus H3, Astra 4)

- **Context dimensions are scored too.** Context an attacker can influence (`tailnet`, `vpn`, `net_config`, `presence`, boot, suspend, clock) is itself a scored stream: transition rates and dwell times, given the other context (`hour_of_week`, `since_boot`).
- **How a tick is scored.** A tick's surprise combines the log-surprise of the context transition with that of the response given the context. "Tailnet stopped at 03:00, then peers vanish" is therefore surprising as a pair, even if each part alone is familiar.
- **`new`, `unknown` and `other`** back off for raising, never go silent, and never recover (CC2, CC4).
- **Novelty probability is learned with Good–Turing** (singletons / N, per dimension):
  - A host that joins new networks often finds a new network unremarkable.
  - A host that never does finds it surprising.
  - This replaces v1's hand rule of surfacing every novelty.

### 7.4 Soft structure, not hard selection (Opus H4, Astra 6, Astra 9)

- **The model.** A hierarchical log-linear model with shrinkage on every main effect and a bounded set of pairwise interactions. The alternative is Bayesian model averaging over the lattice (context-tree-weighting style).
  - There is no hard keep/drop decision and no hand back-off order.
  - Effect sizes, or model weights, are shown in `baseline inspect`.
- **The numbers did not disappear.** The pooling strength (hyperprior) is a P:
  - It is fitted by empirical Bayes inside each training fold.
  - It is sensitivity-checked at ×0.1 and ×10, and the evaluation report states the result.
- **When a new version is created.** A new structure version (`structure_id`) is created only when the representation changes. Parameter refits stay inside one version and are bounded by the drift budget (§11.3).
- **What the learner can and cannot do.**
  - It weighs declared candidates at declared resolutions; it does not discover dimensions outside them.
  - Raw resolution is retained (§8.1), so alternative representations can be fitted later through the doctrine's compositional path (`model-ir` kernels).

### 7.5 Selection and evaluation kept apart (Astra 9)

- **Nested chronological evaluation.**
  - The outer loop uses rolling origins with day-blocked folds, and keeps episodes intact: a reboot aftermath is never split across a fold boundary.
  - The inner loop fits the vocabulary/top-K, priors and hyperparameters on preceding data only.
- **Exclude-latest scoring.** Each tick is scored against a model fitted on strictly earlier data. This follows the discipline at `peer-baseline.js:563`. The `model-ir` z-score is deliberately inclusive (`model-ir.js:335-341`), so it must not be reused as-is.
- **Objective.** Average likelihood is reported, but it is not the only objective, because it can trade away rare-attack sensitivity. Scenario detection is evaluated separately (§10).

### 7.6 Rare events (Opus H2, Astra 7)

- **Sample sizes, honestly.**
  - There are at most 720 hourly ticks in 30 days, and about 400 on a laptop that sleeps.
  - Hour-of-week therefore averages at most 4.3 ticks per cell.
  - Each reboot gives one first-post-boot sample, and this dev host had zero reboots in the window.
  - Ticks are autocorrelated, so episodes, not ticks, are the unit of evidence.
- **Eligibility** depends on predictive evidence and episode support, not on the current 30-tick warm-up (`session-baseline.js:83`).
- **Time-to-override (TTO)** is computed per stream and cell: n* = the prior pseudo-count (exposure units for Gamma, trials for Beta) divided by the host's observed event rate. It is published in `baseline inspect` and in the evaluation report.
  - A cell whose TTO exceeds the horizon of available statistics is labelled `prior-governed`: it behaves like a rule and says so.
- **Long-lived per-episode statistics** (§8.2) let rare cells accumulate over months. TTO is then measured against long memory, not against the 30-day raw window.
- **Transition-triggered samples.**
  - Trigger: a boot-id change, a wake, or a tailnet, VPN or network transition.
  - Action: take cheap session and peer censuses at +2 and +10 minutes (I15).
  - Destination: `tick_summary` only.
  - Why: the hourly cadence cannot see reconnects or a tmux-resurrect ramp (`daemon.js:66`).
- **Abstention (S).** Below the support floor, the model backs off for raising and never recovers (CC3d).
- **(F) proposed, operator question Q3:** "a boot ends all processes".
  - Under it, departures across a boot-identity change are explained, and creation fingerprints are not compared across boots.
  - Arrivals and post-boot identity continuity (resurrect restoring the same names) stay learned and scored.
  - It is narrower than the rejected R6/R7: no time window and no claim about normal, only an OS guarantee.
  - Without ratification, these cells are learned and stay prior-governed for months, and the plan says so.

### 7.7 Runtime and substrate (Opus M11, Astra 15)

- **Cadence.** Fit on the structural cadence or daily, and score on the fast tick from cached parameters. The T9 read-cost model is respected, because learners read the small `tick_summary` family, not the 30-day raw stores (today's detectors re-read the whole window on every fast tick).
- **Kernels in `model-ir`.** The kernels are expressed as new `model-ir` ops, each with a runtime budget (fuel, memory, time), as the proactive-modeling plan requires for cardinality-sensitive group-bys:
  - a context group-by with a cardinality budget;
  - set-difference transitions;
  - conjugate hazard, Poisson and categorical models;
  - shrinkage.
  - If the C4a spike shows that the `model-ir` series contract cannot carry these, the divergence is written down and justified there.
- **Limits (S).**
  - Maximum candidate dimensions, interactions and cells.
  - CPU-ms and memory per fit. An abort keeps the last version and records `fit_aborted`.
  - Durable, versioned parameter snapshots.
  - Kill switch: `learned.json`, or whatever Q1 decides.
- **Integration is new work.**
  - Today `model-ir.js` is imported only by `model-ladder.js`, and nothing imports `model-ladder.js` *(verified 2026-10-06)*.
  - C5 is therefore the first daemon integration of the model substrate, which is substantive lifecycle work. That is why one vertical learner comes first.

## 8. Long memory without the capacity conflict (Opus H7; both audits)

### 8.1 The `tick_summary` family

- **One record per structural tick and per transition-triggered sample**, holding:
  - per-source counts, arrivals, departures and churn;
  - per-source census states;
  - the raw-resolution context: boot id HMAC, seconds since boot, suspend bounds, tailnet/VPN states, `net_config` HMAC, local time plus UTC offset, presence, clock and timezone events;
  - collector states and observation times;
  - the Descartes version and config hash.
- **No entity keys.** Entity memory stays in the seen-sets.
- **Size.**
  - A record is at most **1 KiB** at worst case, pinned by a T8-style test.
  - At worst-case cadence (5 records per hour), 30 days takes ≈ 4.4 MiB including the 1.25 headroom; at the typical 1 record per hour it takes ≈ 0.9 MiB.
  - Record size is independent of entity count, so volume inflation cannot evict this memory.
- **Integrity.** Records are lineage-stamped to the family ledgers the way seen-sets are (capacity `novelty-seen-set.js`), with their own T8 shape.
- **Horizon.** A horizon of **at least 30 days is declared in `RULE_HORIZONS`** (S floor). A longer default budget is a resource choice made in C0.

### 8.2 Long-lived sufficient statistics

- **What is kept.** Per stream and cell, conjugate statistics (counts, exposure) plus per-episode records for rare events (boot, wake and network-change aftermaths).
- **Dated records.** Records are dated, so a forgetting rate can itself be learned later.
- **Bounds and integrity.** Capped (I3), and kept under the same integrity and continuity discipline. A history loss cold-starts the affected statistics. It never declares "everything normal".

### 8.3 Reference snapshots and drift

- **Snapshots kept.** Durable, versioned parameter snapshots at promotion and at ratification; the ratified one is the drift anchor. A bounded number of periodic references are kept as well.
- **Slow drift** is the cumulative divergence of the current predictive from the anchor's, on reference cells. It is not "recent versus rolling 30 days", which a slow poisoner walks along with (Astra 5; `autonomy-doctrine.md:110-116`). The `cusum` kernel (`model-ir.js:366`) is the candidate detector.

## 9. Labels and the outcome loop (both audits; Astra 13; Opus M10)

- **Append-only alert transitions** (`alert-transitions.jsonl`).
  - Each record is one per-identity episode event: `activated`, `escalated`, `frozen`, `recovered` (evidence), `closed` (label, with reason), or `admitted_unexplained`.
  - The log is hash-chained, so it is tamper-evident at the same UID, though not tamper-proof.
  - The natural hook is notify-once's `newEpisode = !current || current.status === "recovered"` (`feat/notify-once-2026-10`, 33084a6). That branch adds `episode_started_at`, `notified_severity_max` and `episode_notified_at`, but **no transition log and no episode counter**.
- **Fix the verified tuning-loop defect (C1.2).**
  - The fix: count `fired_count` from `activated` transitions, not from snapshot records (`calibration.js:245`, `tuning-store.js:427`).
  - For transition-backed rows, `fired_count_is_lower_bound` (`calibration.js:306`) then becomes false.
  - No standalone todo exists for this defect. This plan owns it as a prerequisite unless the operator splits it out.
- **Labels, separate from acknowledgement.**
  - Acknowledgement is receipt only (`alert-store.js:366-376`).
  - The labels are `benign`, `suspicious`, `expected` (an explained change), `mine` (the operator's own action), `confirmed_incident`, and `missed_incident` (for recall).
  - They are stored as append-only records with their source (CLI, uid) and scope (an alert episode or a pending window).
  - Neither an LLM `notify:false` nor a fast recovery is a label (Astra audit).
- **Label-poisoning bound** (mechanism S, label budget O). Labels are writes at the same UID, so a same-user attacker can forge them. Therefore:
  - (a) Labels never raise a model's authority above notify-only.
  - (b) Labels admit pending items only within the drift budget.
  - (c) Label volume is itself a scored stream. A burst beyond the label budget leaves its items pending and raises an integrity notice.
  - (d) Promotion evidence counts only labels gathered under the calibration protocol (§10).
  - The doctrine requires that ground truth be fed, never minted (`autonomy-doctrine.md:126-129`). On-host labels are fed but forgeable, and are bounded accordingly.
- **Declaring a new normal** means labelling a pending window `expected`, within the drift budget. Going beyond the budget needs re-ratification (§11.3).
- **Reports separate four outcomes:** correct silence; abstention; frozen; unsupported. The precedent is `model-ladder.js:150`, which already separates unsupported evaluation from a correct negative.

## 10. Evaluation protocol, written before model selection (Astra 13; Opus M7)

All of this is pre-registered and frozen in step C3b, before the C4a spike runs.

1. **Corpus.**
   - Source: the 2026-10-05 calibration laptop's history, copied with identifiers HMAC'd.
   - Labels: operator-confirmed, covering its reboots, wakes, tailnet flaps and the events behind R4–R10.
   - Reboots and wakes are *events*. They are not benign labels for whatever surrounds them.
   - This dev host is not a corpus:
     - it has had 0 reboots in the window (last boot 2026-09-04, verified);
     - it has never slept (verified);
     - its daemon is stale, and its stderr shows earlier ENOSPC errors (Opus M7).
2. **Scenarios**, written before any model exists:
   - Base set:
     - mass session kill (the 2026-07-11 shape);
     - kill and replace;
     - an odd-hour unattributed login;
     - drift over several days kept below threshold;
     - a kill inside a reboot aftermath.
   - Adaptive set:
     - toggle-then-act (`tailscale down` or `scutil --nc stop`, then kill);
     - new-network-then-act;
     - a sub-threshold drift chain across refits;
     - volume eviction (Opus H7);
     - context-switch recovery (the three Opus B1 scenarios);
     - a label burst.
3. **Coherent chronological replay.** An injection changes the whole observation sequence consistently: census markers, entity keys, creation fingerprints, context facts and the integrity ledger. The result is replayed through the real translators and detectors. An impossible observation sequence counts as a test bug.
4. **Metrics.**
   - Predictive calibration (PIT).
   - Per-episode detection and delay. The delay floor is about one structural interval, lower with transition samples.
   - False alerts per week on labelled benign episodes, measured out of sample.
   - Rates of abstention, freezing and correct silence, reported separately.
   - Resource cost and uncertainty intervals.
   - Synthetic recall is scenario recall, never real-world recall.
5. **Promotion bar (numeric and classified).**
   - Minimum evidence (S): every pre-registered scenario has run; held-out days and labelled benign episodes per event type meet the protocol's minimum.
   - Operator tolerance (O): the maximum false alerts per week, and the minimum scenario detection relative to the incumbent.
   - Proposed values are written in C3b for the operator to ratify (Q5).
6. **Compare against the incumbent, knowing it is noisy.** Fewer alerts is a win only if scenario detection holds.

## 11. Authority (Astra 1; Opus H8)

### 11.1 Additive promotion

Shadow → notify-only on the existing ladder, whose ceiling is notify-only (`model-ladder.js:1-9`). A notify-only learner alerts alongside the incumbent and cannot suppress anything.

### 11.2 Replacement and retirement: not decided here

**Why it is not a ladder step.** Replacing a detector reduces what alerts. That is suppression plus sticky adaptation, which the doctrine places above the on-host ceiling (`autonomy-doctrine.md:61-68,126-129`; behavioral-modeling plan `:118-121`).

**What would be needed.**
- The session and peer detectors are WATCH-tier and default-on.
- The doctrine keeps learned models default-OFF (`autonomy-doctrine.md:134`).
- So a learned replacement needs **an explicit doctrine amendment** (Q2).

**Proposal, if Q2 is yes.**
- **Policy envelope.** An operator-ratified, recorded and reversible per-host envelope, set per detector family. Example: "on this host, session-departure alerting routes to lineage L at ratified snapshot R." It is set once per family per host, not item by item.
- **Old detectors stay in code**, and routing is per host.
- **New installs**, and any host without a ratified envelope, run the incumbents.
- **On a replaced host**, the incumbent keeps running in shadow with its alerts logged, so a regression is visible.
- **Rollback** is a routing flip. No code is deleted, which honours roadmap §11 ("Fixed rules never weakened", `2026-07-09-self-learning-stratified-monitoring.md:224`).

### 11.3 Post-promotion refits

Refits are bounded by a cumulative drift budget anchored to the ratified snapshot (§8.3); a rolling window is not an anchor. Exceeding the budget has three effects:
- The lineage drops back to notify-only, and the incumbent is re-routed.
- A notice is raised.
- Re-ratification is required.

### 11.4 Structure changes

A structure change creates a new version, which enters shadow.

### 11.5 Auto-demotion

The anomaly-of-anomaly guard applies (behavioral-modeling plan `:120`). Without it, an attacker who poisons a good detector's inputs could get that detector auto-quarantined.

## 12. Delivery (Opus M9; Astra 16)

- **R3 notify-once** is built separately on `feat/notify-once-2026-10`, with episode semantics:
  - it notifies on activation and on escalation above the highest severity already notified;
  - it rearms after recovery;
  - acknowledgement does not block a later escalation.

  It is O policy, independent of model truth and training eligibility.
- **Attention budget as a calibrated α allocation.**
  - A test notifies when its calibrated predictive p-value is ≤ α_i.
  - The α_i are allocated across streams so that the expected notifications per week ≈ N (O).
  - Calibration is checked by PIT on held-out data.
  - The budget is never a threshold that deletes detections: every detection is recorded and visible, and the budget governs only push delivery.
  - It is never re-derived from recent surprise history (which an attacker can game), and never raised during a flood; a flood produces a digest notice instead.
- **Severity** is a mapping from calibrated surprise, and from corroboration across streams (O, I29).

## 13. Tier (Astra 15; Opus Q5)

- **Watch tier.** L1 context collection and `tick_summary` run under `watch.json` (default-on). They are data only, and turn on once the C0 fixes land.
- **Learned tier.** Shadow learning runs under `learned.json`. That is the current contract: shadow evaluation is nested inside both `watch` and `learned` (`daemon.js:1061-1079`). Moving it to default-on needs an operator amendment (Q1), the bounded execution contract of §7.7, and an explicit note against the doctrine's default-OFF rule (`autonomy-doctrine.md:134`).
- **Replacement** is an authority question (§11), not a tier choice.

## 14. Sequencing and gates

| Step | Content | Gate | Needs |
|---|---|---|---|
| **C0** | Prerequisites (§3) | daybreak (collectors, schemas, sanitization, sub-deadlines); review (inventory, C0.9 write-up) | `fix/collector-sources-2026-10` |
| **C1** | Merge R3 from its branch. C1.1 append-only transitions. C1.2 `fired_count` fix. C1.3 label store with poisoning bound. | daybreak (alert-store) | `feat/notify-once-2026-10` |
| **C1a** | Arbitrated adaptation for the existing detectors (no folding of alarmed ticks; pending seen-set entries). The novelty lifecycle follows Q4. | **daybreak (security-critical)** | C1.1, C1.3 |
| **C2** | L1 facts, `tick_summary`, long-lived statistics skeleton. Same release as capacity. | daybreak | C0, capacity |
| **C3** | L2 vector and `baseline inspect` | review + property tests (recomputable; stable across timezone changes; no target-derived dimension) | C2 |
| **C3b** | Pre-register the evaluation protocol; collect the calibration corpus and labels | review + operator | Q6 |
| **C4a** | **Time-boxed spike (≤ 1 week, written go/no-go).** Replay the calibration corpus through (i) the incumbents, (ii) a minimal boot-id + tailnet-state transition model, and (iii) as much of the full design as the spike can build. Decide whether the `model-ir` fit holds or the divergence is justified. "Skip the full design" is a valid outcome. | review | C3b corpus |
| **C4** | Estimator kernels in `model-ir` with runtime budgets; the adequacy gate | review + property tests | C4a go |
| **C5** | **One vertical shadow learner** (session departures and arrivals), with the coverage contract enforced in the shadow log, plus daemon integration and runtime limits | **daybreak** (the named `cc2_*` tests; poisoning; runtime) | C4, Q1 |
| **C6** | Evaluation report per §10. Earliest at C2 landing + 30 days; for rare-event cells, months. | review + operator | C5 |
| **C7a** | Notify-only (additive) promotion | ladder + daybreak re-gate | C6 |
| **C7b** | Per-host replacement and the drift budget, **only if Q2 is ratified** | daybreak + operator ratification | Q2 |
| **C8** | Repeat C5–C7 for peers per source, login arrivals and context streams | as above | C7a |

- **Linux sources are CI-gated**, because the dev host cannot run VMs.
- **C2 is the urgent step.** The learners need weeks of context history, so collecting it early matters more than anything else.

## 15. Non-goals

- No new hand-written behaviour rules, thresholds or suppressions. R4–R10 stay rejected.
- No shorter memory.
- No LLM in the detection path.
- No new privilege. The root helper remains optional.
- No change to the incumbents' constants. They are retired only by per-host routing under C7b.
- Some audit findings are out of scope here and remain follow-ups that reuse this substrate:
  - the fixed resource reflexes (`alert-store.js:88-96`, `tools/findings.js`);
  - the provenance launch-path lists;
  - the credential path list;
  - the constraint miner.

## 16. Open questions for the operator

1. **Tier for shadow learning.** Keep it under `learned.json` (recommended, because it matches the current contract), or amend it to run default-on under `watch`?
2. **Replacement authority (a doctrine amendment).** Two options:
   - Permit an operator-ratified, reversible, per-host envelope that routes the watch-tier session/peer families to a learned lineage, drift-budgeted to the ratified snapshot.
   - Keep learned models additive (notify-only) until off-host attestation exists.

   Without a yes, v2 still delivers correct data, arbitrated adaptation and additive learned alerts, but it does not reduce the incumbents' noise.
3. **(F) class.** Ratify "a boot ends all processes" as an OS-guaranteed fact? Departures across a boot-id change would then be explained, and cross-boot fingerprints would not be compared. Otherwise these cells stay learned and prior-governed for months.
4. **Novelty alert lifecycle.** Keep the 2026-09-27 one-tick `recovered` notice, or make novelty alerts stay active until a label, an explanation, or bounded quiet? Under notify-once they would be silent while open.
5. **Policy-envelope values (O).** The values in question are:
   - the bounded-quiet period;
   - the drift-budget size;
   - the label budget;
   - N notifications per week;
   - the promotion-bar tolerances.

   Accept the defaults that C3b will propose, or set them yourself?
6. **Calibration corpus.** Copy the calibration laptop's history (HMAC'd), and spend about an hour labelling its reboots, wakes and flaps? C4a cannot run without it.

## 17. Key code refs

All refs were verified on `main` @ daff6ed unless marked otherwise.

- **Global folds and scoring:** `welford-stats.js:20`; `session-baseline.js:76-83,407-438,904-915`; `peer-baseline.js:50-61,447-452,537-602`.
- **Recovery path:** `alert-store.js:27-30,263-323,366-376`; `daemon.js:834-850`; `service-baseline.js:455-476`.
- **Dropped context:**
  - `tools/tailscale-status.js:81,137,164` → `fact-translators.js:998-1007`;
  - `tools/network.js:81-261` → `fact-translators.js:532`;
  - `vpn-peer-status.js:89-102,124,151,324,341,420-427`;
  - `fact-translators.js:887,937`;
  - `tools/system.js:65`, `daemon.js:307`.
- **Daemon:** cadence `daemon.js:64-67`; sequential collection `:395-403`; all-or-nothing deadline `:984-993`; common tick ts `:1017-1028`; learned-nested shadow `:1061-1079`; plist `:1596`.
- **Outcome loop:** `calibration.js:57-64,245,306`; `tuning-store.js:427`.
- **Model substrate:** `model-ir.js:262-455` (ops; inclusive z-score `:335-341`; cusum `:366`); `model-ladder.js:1-9,150`.
- **Capacity branch:** `fact-families.js:108-149` (`RULE_HORIZONS`), `:240-249` (budgets), `:258-273` (tick shapes), `:358` (4× ceiling); `novelty-seen-set.js:58-59`.
- **Doctrine:** `autonomy-doctrine.md:46-50,61-68,101-116,126-129,134`.

---

## Appendix A: Review disposition

Every finding is **Accepted** unless noted. "Where" points to the v2 section that addresses it.

### Astra plan review (`2026-10-06-context-plan-review-astra.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| Astra 1 | BLOCKER: replacement and adaptation exceed authority | Accepted. Promotion is split: additive on the ladder; replacement only via a ratified envelope plus a doctrine-amendment question; refits drift-budgeted to the ratified snapshot. | §11, Q2, C7a/C7b |
| Astra 2 | BLOCKER: parent fallback fabricates recovery | Accepted. Fallback may raise but never recover; identity is versioned; recovery is evidence-based. | §6.1 CC1–CC7, named tests |
| Astra 3 | BLOCKER: lifecycle facts fabricate events and timestamps | Accepted. Boot identity, not boot time; suspend as aggregate-duration intervals; clock and timezone facts. | §4.1, C0.8, C0.9 |
| Astra 4 | HIGH: conditioning explains the attack away; VPN target leakage | Accepted. Context dimensions are scored streams; VPN service leaves the peer population; the evidence limit is stated. | §7.3, §5, §4.2, §0.3 |
| Astra 5 | HIGH: anomaly exclusion deadlocks and lets slow poisoning through | Accepted. Pending data is retained and challengers see it; only authority-bearing state is restricted; drift is anchored to a snapshot, not a rolling window. | §6.2, §8.3, §11.3 |
| Astra 6 | HIGH: the S/P/O classification is not honest | Accepted. New H class; executable inventory; the daemon-downtime rule is withdrawn. | §0.4, §0.5, §4.1 |
| Astra 7 | HIGH: sample size and temporal resolution | Accepted. Honest counts; episode support; TTO; transition samples; eligibility no longer uses the 30-tick warm-up. | §7.6 |
| Astra 8 | HIGH: count families cannot represent underdispersion | Accepted. Transition and hazard models; underdispersed occupancy; adequacy gate; exposure-adjusted rates. | §7.1, §7.2 |
| Astra 9 | HIGH: selection optimism; no separate evaluation | Accepted. Soft structure; nested chronological, day-blocked evaluation with in-fold vocabulary; exclude-latest scoring. | §7.4, §7.5, §10 |
| Astra 10 | HIGH: historical reconstruction contract | Accepted. Boot id carried on every record; stored UTC offset; per-collector observation time with bracketing reads; versioned top-K; horizons re-verified. | §4.4, §5, §8.1, C0.11 |
| Astra 11 | HIGH: per-source evidence contracts | Accepted. Independent census states (unavailable, disconnected, empty, truncated); tailnet state for every outcome; `Online` semantics stated. R8 stays as the incumbent's scope fix (B) until C7b. | §4.2, §7.1, C0.3 |
| Astra 12 | HIGH: login learner learns occupancy | Accepted. Arrival events; `last` dedupe; tty is not taken to mean SSH; creator lineage dropped. | §4.3, §7.1, C0.4 |
| Astra 13 | HIGH: labels and evaluation certify the wrong thing | Accepted. Labels separate from acknowledgement; events are not labels; coherent replay; abstention reported separately. | §9, §10 |
| Astra 14 | MEDIUM: location identity; sanitizer is not a schema | Accepted. Network-configuration fingerprint with component availability; real field schemas. | C0.5, C0.6 |
| Astra 15 | MEDIUM: tier, runtime limits, integration | Accepted. Shadow under `learned.json` unless amended; runtime limits; one vertical learner; daemon integration acknowledged as new work. | §13, §7.7, C5, Q1 |
| Astra 16 | MEDIUM: R3 needs episode state | Accepted and delegated: `feat/notify-once-2026-10` implements episodes. | §12, C1 |

### Opus plan review (`2026-10-06-context-plan-review-opus.md`)

| Id | Finding (short) | Disposition | Where |
|---|---|---|---|
| B1 | Context change fabricates recovery (reboot, tailnet, unknown) | Accepted, all three scenarios as gate tests | §6.1 |
| H1 | Level families miss partial kills | Accepted. Transitions (arrivals, departures, churn) with exposure; levels secondary. | §7.1, §7.2 |
| H2 | Aftermaths are unlearnable at this cadence; the prior is the rule | Accepted. TTO; prior-governed labelling; long-lived statistics; transition samples; abstention (S). (F) is posed as Q3 only. | §7.6, §8.2, Q3 |
| H3 | Attacker-steerable context; target leakage | Accepted. Joint scoring; `session_origin_mix` removed; `new` and `unknown` raise-only; Good–Turing novelty. | §5, §7.3 |
| H4 | Hard selection driven by a penalty | Accepted. Shrinkage or model averaging; no back-off order; pooling strength classified as P and sensitivity-checked. | §7.4, I9–I11 |
| H5 | macOS scutil parser broken (verified `[]`) | Accepted, referenced. Parser fix on `fix/collector-sources-2026-10` (in progress, not on this checkout); type classification and Linux nmcli here. | C0.2 |
| H6 | ENOENT under launchd PATH (verified PATH) | Accepted, referenced. Absolute paths on the same branch; `collector.binary_state` fact here. | C0.1 |
| H7 | Long memory versus capacity budgets; volume eviction | Accepted. `tick_summary` at ≤ 1 KiB per record, ≥ 30 d in `RULE_HORIZONS`, lineage-stamped; long-lived statistics. | §8 |
| H8 | C7 is suppression plus sticky adaptation | Accepted. C7 split into (a)–(d); doctrine-amendment question; per-host routing; drift budget. | §11, Q2 |
| M1 | Boot identity shared with trusted-state Phase 3 | Accepted. `bootsessionuuid` verified on this host. | C0.8 |
| M2 | Suspend sources, DarkWake, multiple sleeps | Accepted. Aggregate intervals; fast-tick reads aggregated into structural records; verified on a laptop in C0.9. | §4.1, C0.9 |
| M3 | Session origin via `who`/`last` is wrong (verified `(:0)`) | Accepted. loginctl / IOConsoleUsers; first-observed tick. | C0.4 |
| M4 | Login-hour distribution is really presence hours | Accepted. Arrival events; presence hours a weaker stream. | §7.1 |
| M5 | Location fingerprint collides, is confounded and reversible | Accepted. Physical-interface components; HMAC with a per-install key; README table. | C0.5 |
| M6 | L1 is not behaviour-neutral | Accepted. Per-collector sub-deadlines; `daemon_gap` is a fact only. | C0.7, §4.1 |
| M7 | Evaluation not honest enough | Accepted. Pre-registered and adaptive scenarios; corpus from the calibration laptop; out of sample; numeric bars classified. | §10 |
| M8 | Unclassified numbers | Accepted. Every row of the Opus Q1 table appears in the inventory, plus v2's new numbers. | §0.5 |
| M9 | Gameable attention budget; multiplicity | Accepted. Calibrated α allocation checked by PIT; never deletes a detection; not derived from recent history. | §12 |
| M10 | Contamination guard mechanics | Accepted. Soft weights for challengers; `benign` separate from acknowledgement; label-poisoning bound; declaring a new normal within the drift budget. | §6.2, §9 |
| M11 | Fit cadence, compute, second substrate | Accepted. Structural or daily fits with cached scoring; `model-ir` kernels with runtime budget, or a divergence justified at C4a. | §7.7 |
| L1 | Creator lineage is infeasible | Accepted. `tmux list-clients` joined to the login tty. | §4.3 |
| L2 | Shutdown-cause cost and privilege | Accepted. `pmset` log dropped; `last` rows and Linux `last -x` used; journal not used. | §4.1 |
| L3 | Missing context | Accepted. Presence/lock, DarkWake, clock and timezone, binary availability and Tailscale Self/Health in C2; software change and power deferred to later families. | §4.1–4.3 |
| L4 | Two inaccurate statements | Accepted and corrected (the regime stratum exists; retention is 30 days). | §1.2, P3 |
| L5 | Sequencing | Accepted. C2 lands with the capacity release; C4a spike; Linux sources CI-gated. | §14 |
| L6 | Tailnet online count has low security value | Accepted. Secondary stream; node-key novelty and inbound sessions primary. | §7.1 |

### Principle audits (structural findings in scope)

| Finding | Disposition | Where |
|---|---|---|
| Adaptation without arbitration (Opus audit §1g, rank 4) | Accepted as an early security-critical step. The change to the novelty lifecycle is posed as Q4. | §6.2, C1a |
| Tuning loop counts repeated incidents as 1 (Astra audit rank 3, verified) | Accepted as prerequisite C1.2, with an append-only transition log | §9, C1 |
| No independent labels (both audits) | Accepted | §9 |
| No durable behavioural memory or reference baselines (Astra rank 4; Opus §4 item 4) | Accepted for session/peer/context streams | §8 |
| Context collected then discarded (both audits, §3 tables) | Accepted for lifecycle, network and session context | §4 |
| Peer regime key is the right pattern to generalize (Opus audit 1a) | Accepted as the precedent | §1.2, CC1 |
| Process rule: calibration findings become data work items | Accepted | P6 |
| Fixed resource reflexes, provenance lists, credential paths, constraint miner, metric retention | Out of scope; follow-ups reuse this substrate | §15 |

### R4–R10 non-reintroduction check

| Item | v2 status |
|---|---|
| R4 (floor 0.5 → 0.75) | Absent. No stddev floor exists in L3; the incumbent is unchanged. |
| R5 (14-day window) | Absent. Memory grows (§8). |
| R6/R7 (reboot suppression or CRITICAL guard) | Absent. Reboots are facts and covariates. (F) is an operator question with no time window and no claim about normal. |
| R9 (wake grace) | Absent. Wake is an interval fact; reconnect behaviour is learned or prior-governed and labelled as such. |
| R10 (lone-churn rule) | Absent. Churn rate is learned per context. |
