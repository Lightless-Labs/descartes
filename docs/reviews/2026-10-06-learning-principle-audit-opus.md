# Learn-and-adapt principle audit of past work — Opus 5.5 (max)

**Date:** 2026-10-06
**Scope:** main @16d0ed9, capacity + root-helper worktrees. Read-only.

---

# Descartes "learns and adapts" audit (read-only, 2026-10-06)

**Scope.** `main` @ `16d0ed9` (`tools/descartes-cli/src`, `crates/`), plans, designs, todos. Unmerged: `feat/fact-store-capacity-2026-10` (worktree `wf_fff34f30-56c-1`, 71 commits, merge-base `b951cb7`; it does **not** contain the `ca94c04` watch-fabrication merge) and `harden/root-helper-2026-10` (worktree `wf_cdc95c7b-4c0-1`). Evidence comes from code. Doc claims are cited as claims.

**Legend.** **A** = an assumption about normal behaviour that should be learned or conditioned on context. **B** = a safety invariant or resource bound (legitimate). **C** = a bootstrap prior, acceptable only if the system can learn past it ("LP" = can it today?). **D** = delivery/UX policy. **Tier:** WATCH is default-on (`watch-store.js:52`, `enabled !== false`). AUTHOR is opt-in through `learned.json`, default off (`constraint-store.js:226`, `enabled === true`).

**One rule applies to every C row: nothing can learn past any prior today.**
- Every detector constant is a module literal. The daemon passes detectors only freshness and interval options (`daemon.js:1296-1317`). Sigma, floor, N and K are not operator-configurable; tests can inject them, nothing else can.
- The only tuning loop covers `constraint.violation.*` only and can only loosen by a 5% margin (`tuning-store.js:11-14, :58, :403`). Slice 14b (session/peer/correlation) was never built.
- The fixed reflexes are excluded from calibration by design (`calibration.js:69`: "Never the fixed, hand-authored zero-learning reflexes").
- No label reaches any learner. `acknowledg*` is used only by the alert-state transitions in `alert-store.js` and `alerts.js` (grep). Calibration recall is hard-coded `null`, with the reason "no ground-truth incident signal available" (`calibration.js:64`).

Rule for this report: separate the **gate** from its **value**. "Make no claim before N complete ticks" is a never-fabricate gate (B). The particular N is a prior (C).

---

## 1. Code audit

### 1a. WATCH tier (default-on for every install)

| Location | What it hard-codes | Assumes | Class | LP |
|---|---|---|---|---|
| `session-baseline.js:76-78` (self-labelled "PROVISIONAL… NOT tuned values", `:68-75`) | σ=3 warning, σ=5 **critical**, stddev floor 0.5 | tmux/screen count varies around one global mean; drop size measured in σ = urgency | A (σ, critical tier), C (floor) | no |
| `session-baseline.js:83, :432` | N=30 samples before "established" | 30 hourly samples describe normal | B gate / C value | no |
| `session-baseline.js:407-438` | one Welford accumulator over every complete tick in the window; a tick is scored, then folded on the next call even when it alerted | no context strata (hour-of-week, post-boot, attached vs detached, origin); no robust or quarantined fold | **A** | no |
| `session-baseline.js:456-644`, `:467` (K=3), `:539-540`/`:634` ((K+1)×interval) | `session.churn`: same session name, new creation second, earlier observation within 3 complete ticks | the "kill-then-resurrect" shape of one 2026-07 incident; recreating sessions after a reboot looks the same | A (rule), C (K) | no |
| `peer-baseline.js:68-79` | spike/drop σ=3, floor 0.5, N=30; critical σ=5 present but unused (`:73`) | same as session | A/C | no |
| `peer-baseline.js:443-455` (R8, `c25cc4b`) | Tailscale peers left out of the count whenever a VPN census marker is present | the source emitted nothing when logged out or "unable", so the fix drops the source | **an A-shaped fix to a B problem** (coverage). A source-specific hack. | — |
| `peer-baseline.js:537-548, :626-633` | baseline keyed by regime = the availability signature of 5 collectors | conditions on which collectors were up | **correct pattern** (the only context stratum in the code), but it keys on collector state, not host state | partial |
| `vpn-peer-status.js:286, :424`; `tailscale-status.js:64` | a configured WireGuard key is always `observed_active` (handshake recency kept only as an attribute); a connected VPN service counts as a "peer" | one count mixes configured keys, tunnels and SSH logins | A (mixed population) | no |
| `service-baseline.js:62, :333-374` | "established" after ≥3 complete censuses; disappeared = in the previous census, missing from the latest (one-step edge) | every service is always on; 3 h of presence makes a service established | A (no model of how often an entity is present), C (3) | no |
| `service-baseline.js:830-853`; `process-lineage-baseline.js:278-293`; `persistence-baseline.js:226-249` | novelty = latest census minus the union of earlier complete censuses | seen once in memory ⇒ normal | C, plus a structural issue (§1g) | n/a |
| re-accumulation after cold start = 6 ticks (`session :92`, `peer :93`, `service :79`, `process-lineage-baseline.js:20`, `persistence :42`, `canary :47`) | — | — | B gate / C value | no |
| freshness = 3× structural interval (`daemon.js:74`; fallbacks `session :101`, `peer :101`, `service :70`, `lineage :21`) | — | — | B | — |
| severity hard-capped at `"warning"` (`peer :702/:744`, `service :432/:883`, `lineage :337`, churn `:699`, `incident-correlation.js:274`) | — | untuned detectors must stay out of the critical lane | D (honesty cap). Severity should become an output of the model. | — |

### 1b. Fixed reflexes (evaluated every tick, outside both tiers)

- **`alert-store.js:88-96, :149-184`.** Memory used ≥0.9 (critical ≥0.95). Load1 ≥1.5×CPU count (critical ≥2×). Disk ≥0.9 / ≥0.95. At least 2 samples inside a 15-minute window (`:7`). **Class A, LP: no.**
  - **Reach:** always evaluated and persisted. They reach the operator only through `alerts list` or opt-in intelligence, because they are not on the deterministic local-delivery allowlist (`alert-intelligence.js:40-60`).
  - **Verified on this host.** Descartes computes memory used as `(totalmem − freemem) / total` (`tools/system.js:56, :72`). On this macOS host that gives **0.985** (11.0 GB total, 0.17 GB free; `vm_stat` shows about 4.7k free pages against 175k inactive ones). `system.memory.sustained_high` would sit at CRITICAL permanently. A universal threshold carries the wrong idea of normal for the platform.
  - Even a learner could not fix this: metric history is kept for **24 h only** (`history-store.js:4`).
- **`alert-store.js:94, :100`.** Daemon status and samples go stale after max(5 min, 3×interval). Class B (the daemon's own liveness).
- **`tools/findings.js:13-80`** (triage path). Load >1.5×CPU, memory ≥0.9 / 0.97, swap >1 GiB, disk ≥0.9 / 0.97, top-process CPU ≥300%, top-process memory ≥40%. Class A. The critical cutoff here (0.97) disagrees with `alert-store.js` (0.95).

### 1c. AUTHOR tier (opt-in)

- **`incident-correlation.js`.** Proximity ±3 h (`:47`). Anchor lookback 24 h (`:52`). `CORRELATION_ODD_HOURS = {00..05}` in local time (`:58`). "Unattributed-looking" means seen in ≤1 earlier tick (`:63`). Cold start needs 4 tick-groups over 3 days (`:67, :71`). Filters at `:193, :196, :200`.
  - Class: **A** (odd hours, novelty proxy, proximity), C (cold start), B (the lookback as a storm bound).
  - The lookback and proximity values also cap the attack timeline at hours. A login on day 1 and a kill on day 3 can never correlate.
  - Recovery is deferred, so these alerts stay frozen (`:293, :350`). LP: no.
- **`tools/provenance.js`.** Comm-name sets for cron, shell, supervisor and container, `RECOGNIZED_SUPERVISOR_SOURCE_TYPES`, and `PUBLIC_BIND_ADDRESSES` (`:36-49`). `classifySourceFromAncestry` (`:134-176`). `detectWarnings` (`:202-237`): `deleted_exe_running` is "high", `public_bind_no_supervisor` has confidence 0.8, `unexpected_parent` has 0.5.
  - **Class A**: a hand-written list of legitimate launch paths. An executable deleted by a package upgrade is normal, and there is no package-event context to explain it.
  - These are fixed by design (roadmap §3.2 calls them "zero-learning") and excluded from calibration (`calibration.js:69-70`). LP: no.
  - `tools/provenance-warnings.js:71` (3 h read window): B.
- **`provenance-store.js`.** An identity becomes known_good after 3 samples over 2 iterations (`:54-55`). The presence window is 3 h (`:70`). `unknown_identity` fires for identities promoted through the grace window, i.e. those outside the operator snapshot (`:618-670`).
  - **Class A, UAC pattern.** Normal is declared by a human snapshot, not learned. Every new identity that persists alerts until the next snapshot, and recovery stays frozen until it is acknowledged (`:69`).
- **`tools/credential-access.js:13-41`.** 8 literal paths. High-churn credential files (gcloud, kube, docker, npmrc) are excluded (`:17-22`). atime is never watched (`:24-29`).
  - **Class A**: a hand guess about which files churn. The detector sees modification, not reads.
- **`canary-baseline.js`.** Established after ≥3 censuses (`:36`), 6-tick re-accumulation (`:47`): class C.
  - The canary trips themselves are B-like: an operator-declared decoy is "never normal" by construction.
  - Missing: who touched the file. Without the accessor, it cannot learn which touches are benign (backup, Spotlight, antivirus).
- **Constraint mining and promotion.**
  - Miner: at least 3 samples spanning at least 7 days (`constraint-miner.js:23-24`), zero contradictions (`:246`), two families only (`:32-35`), run only from the CLI (`:331-372`).
  - Promotion: `constraint-store.js:468` (2 fixtures), `:472` (7-day soak), `:534` (one fire means the constraint never promotes). Approval is a single-use human nonce valid for 24 h (`promotion-store.js:32`).
  - **Class C plus UAC.** The system can learn only exceptionless invariants, never "usually" or "given this context".
  - The 2026-09-03 doctrine superseded per-item approval, yet the code still requires it.
- **`calibration.js:57-59`** (fast recovery 30 min, chronic = 5 fires, noise ≥0.3) and **`tuning-store.js:55-63`** (2 fires, +5% margin, 10 backtest samples). Class C meta-priors. They cover constraints only and use no labels.
- **`containment-recommend.js:130-147`.** Maps rules to recommendations: a peer spike becomes "block", a lineage edge becomes "throttle". Class D (authority policy). It ties a z≥3 count to a containment verb.
- **`alert-intelligence.js:74, :79, :88, :108`.** 3 LLM calls per hour, a critical reservation, a 30 s deadline, metric namespace only by default. B/D.
- **`model-ir.js` / `model-ladder.js`.** The only model substrate an agent could author is **unwired**. Only `model-ladder.js` imports `model-ir.js`, and nothing imports `model-ladder.js`.

### 1d. Data-plane choices that set what any learner can see

- **Bucket edges chosen by hand.** `fact-translators.js:657-667` window-count buckets (0 / 1 / 2-4 / 5-9 / 10+). `:677-683` and `:912-918` overflow totals. `:898-909` handshake age (5 m / 1 h / 1 d / 7 d). `:887-891` `login_hour_bucket`, which is the local hour of the **tick**, not of the login. **Class C.** The identity hashing next to them is B.
- **Process lineage.** `tools/processes.js:187-228` records only (parent comm, child comm) pairs from an hourly `ps` snapshot, capped at 200 edges taken in hash order.
  - As a bound this is B, but short-lived spawns are invisible.
  - A host with more than 200 distinct edges reports a "partial" census every tick, which leaves the lineage detector permanently blind. The measured host already has 175.
  - Lineage carries no executable path, uid or origin.
- **Cadence.** `daemon.js:66`: hourly structural collection. Every WATCH model sees one sample per hour.
- **Memory on `main`.**
  - Nominal: `fact-store.js:18-19` (30 days, **5 MB**) and `welford-stats.js:20` (31-day window).
  - Arithmetic (verified): 5 MiB divided by the measured 185,139 B per tick is about 28 ticks, fewer than the N=30 needed to establish. Byte-cap eviction also counts as a loss channel (`session-baseline.js:163`; `fact-store-completeness.js` `LOSS_TIMESTAMP_FIELDS`). The capacity plan's §0 reaches the same conclusion: "the feature does nothing on real hosts today."
  - **On real hosts, effective memory on `main` is about one day, and WATCH locks out.** The 31 days are nominal only.

### 1e. Unmerged branches

**`feat/fact-store-capacity`**
- **B:** `fact-families.js:240-249` (per-family budgets, 65 MiB total), `:275` (1.25 headroom), `:358` (4× ceiling), and the new collector clamps.
- **B gates with C values (operator Q2):** `RULE_HORIZON_ENTRIES` (`:108-130`): 48 h for appeared, 6 d for lineage, 30 h for count rules, 6 h for set-diff rules, 3 d for correlation. These are eligibility floors only: "only ever REMOVES an evaluation".
- **B/D:** `:427` raises the horizon-short alert after 24 ticks.
- **`novelty-seen-set.js` (first/last-seen per novelty family) is the correct long-memory structure.** It is lineage-stamped to the fact ledger, capped at 20k entries (`:58`), and keeps an entity 30 days past its last sighting (`:59`).
  - The 30-day TTL is a C value: monthly and quarterly entities become "new" again.
  - It covers only service, scheduled_job and process_lineage. Sessions, peers and ports have no compact memory.
- The plan states the trade honestly: §0 "what we give up", and §5 N1 says raw novelty memory is about 5 days for services and 8 days for lineage.
- **Merge hazard:** the branch predates `ca94c04` (no R8, A2, A3 or v2 peer identities; its peer keys are still `"global"`). Expect conflicts in session, peer and `baseline.js`.

**`harden/root-helper`**
- B throughout: seccomp, (tgid, start_time) process identity, pid-namespace guard, argv-preserving redaction. The secret-argv regex added to `tools/processes.js` is a privacy allowlist, not detection logic.
- Relevance to learning: it is the prerequisite for a complete cross-UID socket census. Provenance-identity recovery is frozen until that census exists.

### 1f. Never-fabricate machinery and allowlists (B or D: keep, do not "simplify" away)

- census markers with a strict three-way `census_state`
- the completeness ledger and `factHistoryTrustworthy` (`fact-store-completeness.js:54-92`)
- persistent cold-start lockouts
- future-fact tolerance of 6 h (`fact-store.js:27`)
- detector-reported `evaluatedAlertKeys` with recovery freeze (`alert-store.js:285-323` and the daemon tier veto)
- the diagnostics sanitizer
- collector caps
- the LLM budget
- per-family coverage contracts and horizon eligibility (branch)
- shape validators `SESSION_CHURN_ENTITY_KEY_PATTERN` (`session-baseline.js:456`) and `PEER_AVAILABILITY_SIGNATURE_PATTERN` (`peer-baseline.js:44`): B

Class D:
- the delivery allowlists `ALL_DETERMINISTIC_LOCAL_DELIVERY_RULE_IDS` (`alert-intelligence.js:40`), `KNOWN_ALERT_NAMESPACES` (`:99`) and `DEFAULT_ENABLED_NAMESPACES` (`:108`)
- the alert cooldown of 15 minutes (`alert-store.js:6, :263-310`) and R3 notify-once

### 1g. Structural finding: adaptation without arbitration

The default tier already "learns", but naively:
- **Novelty.** A new service, job or lineage edge fires once. On the next tick it belongs to the historical union, the detector reports it as evaluated (`service-baseline.js:470-474`, `process-lineage-baseline.js:307-317`), and the alert flips to **"recovered"**. The HANDOFF (2026-09-27 entry, line 41) records this as an adjudicated design: "edge-triggered transition notices". It is safe against fabrication, but the persistence an attacker installed becomes "normal" an hour later, with or without an acknowledgement.
- **Statistics.** Welford folds alarmed ticks into the baseline (`session-baseline.js:416-430`). `peer-baseline.js:589-594` excludes only overflow and invalid-marker ticks; alarmed ticks are folded.

This is the inverse of the doctrine: "never adapts a model to unattested change" (`docs/design/autonomy-doctrine.md:103`). The principled learner is blocked behind attestation, while the default tier adapts with no gate at all.

---

## Ranked offenders

Ranking = (decides alerting directly) × (encodes a guess about this machine) × (no way to learn past it today) × (reach).

| # | Offender | file:line | Class | Tier | LP | Why it ranks here |
|---|---|---|---|---|---|---|
| 1 | Session and peer count models: fixed σ=3 (session critical σ=5), floor 0.5, N=30, **one global stratum**, every tick folded | `session-baseline.js:76-83, 407-438, 661-668`; `peer-baseline.js:68-79, 537-602` | A (+C) | WATCH | no | Every R4–R10 item in `todos/2026-10-06-session-peer-tuning.md` targets these constants. At measured volume on `main` the same detectors cannot even establish (capacity plan §0). That is two failure modes of one design, not a contradiction. "Learned" in name only: one mean and σ for every context. |
| 2 | Correlation: odd hours {00–05}, ±3 h, ≤1 earlier tick, 24 h lookback | `incident-correlation.js:47-71, 193-200` | A | AUTHOR | no | A pure guess about this machine's working hours, encoding one past incident. The hour-scale window blinds it to multi-day attacks. |
| 3 | Fixed resource reflexes | `alert-store.js:88-96, 149-184` | A | always evaluated; delivered only via opt-in intelligence or `alerts list` | no (`calibration.js:69`) | Measured 0.985 memory used on this host ⇒ permanent CRITICAL. 24 h metric memory rules out learning anyway. |
| 4 | Adaptation without arbitration (§1g) | `service-baseline.js:470-474, 830-853`; `process-lineage-baseline.js:278-317`; `persistence-baseline.js:226-249`; `session-baseline.js:416-430` | structural | WATCH | n/a | Attacker persistence becomes normal after one tick and its alert shows "recovered". |
| 5 | `session.churn` kill-then-resurrect rule | `session-baseline.js:456-644, :467` | A/C | WATCH | no | A one-incident signature. Recreating sessions after a reboot is indistinguishable (R6, R10). |
| 6 | R8 Tailscale exclusion | `peer-baseline.js:443-455` | A-shaped fix to B | WATCH | — | Removes a data source instead of adding a census or connected-state fact. The peer model cannot see tailnet behaviour at all. |
| 7 | `service.disappeared` one-step edge, established ≥3 | `service-baseline.js:62, 333-374` | A/C | WATCH | no | Treats every service as always on. Per-login launchd agents and timers fire at every logout, sleep or reboot. |
| 8 | Provenance launch-path list and fixed warnings | `tools/provenance.js:36-49, 134-237` | A | AUTHOR | no | Hand-written list of supervisors. `deleted_exe` is "high" after every upgrade, with no package context. |
| 9 | Identity baseline = operator snapshot | `provenance-store.js:54-70, 618-670` | A (UAC) | AUTHOR | no | Normal is declared. Every persistent new identity alerts until the next re-snapshot. |
| 10 | Credential path list, churn denylist, no atime | `tools/credential-access.js:13-41` | A | AUTHOR | no | Guesses which files churn; blind to reads. |
| 11 | Translator bucket edges; `login_hour_bucket` = tick hour | `fact-translators.js:657-683, 887-918` | C | all | no | A learner can only condition on boundaries someone guessed. |
| 12 | Constraint miner and promotion | `constraint-miner.js:23-24, 246`; `constraint-store.js:468-541`; `promotion-store.js:32` | C + UAC | AUTHOR/CLI | human, loosen-only | Cannot express "usually" or "given context". Two families only. |

Lower-ranked:
- `tools/findings.js` triage thresholds (A)
- calibration and tuning meta-priors (C)
- `RECOMMEND_MAP` (D)
- capacity-branch horizon values (C values on B gates)
- seen-set 30-day TTL (C)
- `main`'s 5 MB fact store (a B bound with catastrophic memory consequences; fixed on the branch)
- 24 h metric retention (a B bound with an A consequence)
- the `"warning"` severity caps (D)

---

## 2. Plans, designs and todos

### Where the docs correctly embody learning

- **Roadmap** `docs/plans/2026-07-09-self-learning-stratified-monitoring.md`:
  - §3.2 (`:74-80`): signature records carry frequency (`{key,count,first_seen,last_seen}`), and baselines are keyed by metric, dimension and an optional time bucket.
  - §8 Layer C, Slices 10–12 (`:181-183`). Slice 12 is "Hour-of-day × weekday/weekend buckets with hierarchical confidence fallback": the right design. **It was never built.** `todos/2026-07-09-self-learning-stratified-monitoring.md:91-93` is still unchecked, and `docs/plans/2026-07-14-compile-down-calibration.md:15` says "No `baseline-store.js`… Slice 10… never shipped".
- **`docs/design/autonomy-doctrine.md`**:
  - Clippy (`:27-38`): "the agent only toggles detectors a human pre-built and tunes a threshold".
  - The agent's non-delegable job (`:87-116`): refine / adapt / alarm arbitration. "Never adapts a model to unattested change" (`:103`); a package-manager event is the doctrine's own example of corroboration (`:105`).
- **`docs/plans/2026-09-03-proactive-behavioral-modeling.md`**:
  - Plane A: models built from composable primitives.
  - Review must-fix 1 (`:37`): operator labels plus seeded fixtures form the oracle, and "labeling ≠ UAC consent".
  - Must-fix 6 (`:42`): drift budget anchored to an attested baseline.
- **Slice 4c** (`docs/plans/2026-07-23-slice-4c-peer-baseline-robust.md` §2): the regime-keyed baseline ("chronic degradation establishes its own baseline within its own regime").
- **Capacity plan** §5 N1 (`:402`) gives honest memory accounting, and §17 (`:799`) adds the S3b first/last-seen set.
- **`docs/plans/2026-09-10-watch-by-default-slice-1.md` §11 #1:** the intent was "learn a normal count/pattern".
- **`docs/HANDOFF.md:55`:** protection contracts were rejected as "OTel + local PagerDuty, done worse", in favour of an agent that "discovers what's running and learns to monitor it". This is the same principle, stated a month earlier.
- **`todos/2026-10-06-session-peer-tuning.md`:** the reframe to "context as observed, learned data", keeping 31 days and keeping the gates. Correct.
- **Completeness hardening (2026-08-21) and recovery coverage (2026-09-20):** correct B work.

### Where they drifted toward an expert system, shorter memory, or missing context

1. **`docs/plans/2026-07-13-observed-incident-collectors.md` builds a signature for the last incident.**
   - Its Origin (`:18`) is one real incident. Slices 4, 4b and 6 encode exactly that incident: a mass session drop, churn, a peer burst, an odd-hour login near a kill. Slice 6 says outright that "v0 stays to the exact incident shape" (`:682`).
   - Slice 3 deferred "the statistical judgment" of odd hours to Slice 4 (`:7, :166`). Slice 4b then shipped "one global dimension_bucket, no per-source_type stratification, no hour-of-day weighting" (`:13`). Slice 6 shipped a fixed `{00..05}` set (`:674`).
   - `session-baseline.js` was declared "a fallback, not a permanent parallel engine… consume S10 instead if it lands first" (`:8`). S10 never landed, so the fallback became the engine.
2. **Layer C (S10–S12) was displaced by bespoke detectors.** In AGENTS.md (`:9`) and roadmap §1, "stratified" means the L0/L1/L2 layers, not context strata. The word never carried the operator's meaning into the code.
3. **Watch-by-default §11 #1 put untuned PROVISIONAL constants default-on for every install,** with a "calibration pass as the first fast-follow" (`session-baseline.js:68-75` labels them PROVISIONAL). The calibration (2026-10-05) came back as R4–R10: more thresholds and suppressions. R6's first decision (`7b533fc`) was an uptime-gap suppression rule; the operator reframed it the same day (`16d0ed9`).
4. **`fix/watch-fabrication` (merged as `ca94c04`).** A2 (freshness) and the v2 identities are correct B work. R8 (`c25cc4b`) and A3 (`a858410`) fixed problems by exclusion and by a hand-chosen bound.
5. **`docs/plans/2026-07-23-service-disappearance-alert.md`** chose a one-step edge and "established ≥3" through flap-proneness reasoning. No per-service presence model.
6. **`docs/plans/2026-08-21-agent-intrusion-detection-gaps.md`** uses a hand-curated credential list with a churn denylist (O6). No per-path cadence learning.
7. **`docs/plans/2026-07-10-layer-b-provenance.md` with roadmap §3.2:** "zero-learning known-bad… immediate fixed rules", and the identity baseline is an operator snapshot.
8. **`docs/plans/2026-07-14-compile-down-calibration.md`:** recall is null by design, session/peer/correlation cannot be mined, and retuning only loosens. The HANDOFF claim that "the self-learning loop is closed" (`:209, :235`) overstates. The loop is closed only for constraint thresholds, and only through a human.
9. **Constraint mining pipeline (2026-07-10):** exceptionless invariants, CLI only, a human nonce. The doctrine superseded per-item approval on 2026-09-03 ("remains in code until Slice 4"); the code is unchanged.
10. **Memory.**
    - The S6b default of 5 MB means about one day on real hosts; capacity plan §0 says WATCH "does nothing on real hosts today".
    - The plan's own §0 accepts about 5 days of novelty memory. S3b repairs that for only 3 families.
    - Rejecting R5 (shrink to 14 days) was correct.
    - Correlation's 24 h lookback and 3 h proximity are a separate memory cap nobody has addressed.
11. **`docs/architecture/2026-09-05-purpose-first-design.md` §3** ("start with useful deterministic judgments… statistical baselines come later") and §6 (learning = compiling cases into deterministic rules). It is not adopted doctrine, but it fed Path A.
    - AGENTS.md L1 ("Thresholds and static rules", `:58`) and `:157` ("compiling confirmed learning downward into deterministic rules") sanction the rule forest at the doc level.
    - Reword to: compile *learned models* into cheap evaluators.
12. **Doctrine deadlock.** Adaptation and promotion above notify-only are gated on off-host attestation, which does not exist (behavioral-modeling plan, direction decision 2026-09-03). So the principled learner is blocked, while the default tier adapts naively (§1g).
13. **The behavioral-model spike stalled after its pure half** (HANDOFF `:79`; `model-ir` and `model-ladder` unwired). Path B was parked behind Path A, then behind watch-by-default.
14. **The event-source spike was deferred** (`docs/plans/2026-07-14-event-source-spike.md`). It was scoped to privileged exec/file/network/login streams; unprivileged lifecycle context was never considered. Boot identity is planned only as an integrity primitive (`todos/2026-09-08-clamp-boot-identity-guard.md`, trusted-state §5.3), never as a feature for a learner.

---

## 3. Missing data and context (several items are already parsed, then discarded)

| Context a learner needs | Status | Evidence | Cheapest unprivileged source |
|---|---|---|---|
| Boot time / boot identity | not collected; uptime exists only as a 24 h metric | `daemon.js:307`, `history-store.js:4`; `boot_id` appears only in comments | macOS `sysctl kern.boottime`, `kern.bootsessionuuid`; Linux `/proc/sys/kernel/random/boot_id`, `/proc/stat btime` |
| Reboot/shutdown history | **fetched, then discarded** | `vpn-peer-status.js:124, :151` (the `last` rows) | already in hand |
| Sleep/wake transitions | not collected | grep | `pmset -g log`; journal `systemd-sleep` / logind |
| Daemon gaps | implicit in the structural checkpoint (`daemon.js:443-470`); no gap facts | — | derive from the checkpoint |
| Tailnet up/down | **parsed, then dropped**: `backend_state` (`tailscale-status.js:135-150`) becomes an `unable` envelope (`:164`), which the translator skips (`fact-translators.js:999`) | — | already parsed |
| VPN service state | stored only as peer presence | `vpn-peer-status.js:424` | already parsed |
| WireGuard handshake recency | kept as a bucket attribute; the peer is always "active" | `vpn-peer-status.js:286`, `fact-translators.js:898` | already parsed |
| Default route / interface class / DNS / SSID (hashed) | not collected | grep | `route`/`scutil --nwi`, `ip route` |
| Established inbound connections | collected, deliberately never persisted | `vpn-peer-status.js:354-356` | already parsed |
| Session origin | local `who` entries dropped; sessions are tmux/screen only; `attached` is stored but never used | `vpn-peer-status.js:409`; `tools/sessions.js:1-12` | `who` tty class, `tmux list-clients`, the lineage of the tmux server |
| Login time | not stored (only the tick hour) | `fact-translators.js:887-891` | time columns of `last`/`who` |
| User activity (idle, lock, console user) | none | — | `ioreg` HIDIdleTime, `loginctl` IdleHint |
| Software change (installs, upgrades) | none (grep for brew/apt/dpkg/softwareupdate finds nothing) | the doctrine's own corroboration example (`autonomy-doctrine.md:105`) | package-manager logs, `/var/log/install.log` |
| Time features (hour-of-week, weekday) | only the tick hour on peer facts, read by one fixed set | `incident-correlation.js:58` | derive from local time zone |
| Exec / short-lived processes | hourly snapshot, comm names only | `tools/processes.js:187-228`; event spike deferred | privileged sources later |
| Labels / outcomes | acknowledgements never consumed; no outcome records | grep; `calibration.js:64` | record acks and corrections as facts |
| Long metric memory | 24 h | `history-store.js:4` | hourly and daily rollups |
| Cross-UID completeness | the unprivileged census cannot see other users' sockets | HANDOFF 2026-10-05 | merge the root-helper branch |

---

## 4. Structural verdict

**Where it stands.** Descartes today is a **well-defended expert system with two pieces of learned state**: the peer regime key, and, on the branch, the seen-set.

| Axis | State | Evidence |
|---|---|---|
| Never-fabricate plumbing | strong | §1f |
| Observation space | narrow: hourly snapshots of about 7 domains | `daemon.js:66, :370-404` |
| Context | effectively absent; several contexts collected, then dropped | §3 |
| Models | hand-written functions with module constants; one global stratum; no model object with learned parameters | §1a–1c |
| Feedback | absent: no labels, recall `null` by design | `calibration.js:64` |
| Memory | about 1 day effective on `main`; about 5–8 days raw on the branch, 30 days in the seen-set for 3 families; metrics 24 h; correlation 3–24 h | §1d, §1e |
| Adaptation | naive (absorb or fold everything), the inverse of the doctrine | §1g |

**The asset.** The hardest part of learning from adversarial data already exists and can be reused: census-marked facts, a completeness ledger, per-family coverage, detector-reported evaluation and recovery freeze. Most of what is missing is additive.

### Highest-leverage changes (every never-fabricate gate stays)

1. **Context facts first: turn R6, R9 and R10 into data.**
   - Add census-marked fact families: `host.lifecycle` (boot id and time, the reboot/shutdown rows from `last`, sleep/wake, daemon gaps), `net.context` (tailnet and VPN state, route/interface class, hashed), `session.origin`, `user.activity`, `software.change`.
   - Most of this is a translator change on data already parsed (§3).
   - Reuse the census-marker pattern and the branch's `fact-families` registry. "Unknown context" is its own value, never a guess.
   - This also replaces R8: give Tailscale its own census and connected-state marker instead of excluding it.
2. **One context-conditioned baseline kernel replaces the per-detector constants.**
   - Generalize the regime key (`peer-baseline.js:537-548`) into a context vector: hour-of-week × lifecycle phase (post-boot, post-wake) × network state × origin.
   - Back off from specific to coarse to global, as roadmap Slice 12 designed.
   - Model counts per stratum (empirical quantiles or Poisson-Gamma) with transition terms, so "sessions are 0 after a reboot" is learned rather than suppressed.
   - Alert on tail probability against a per-model false-positive budget. Severity = surprise × corroboration across streams. The fold is robust: alarmed points are excluded.
   - Gates stay B: a stratum must be established before it is evaluated; otherwise fall back to a coarser stratum or freeze.
   - The same kernel, fed metric rollups, delivers S10 and retires the fixed memory and load reflexes.
3. **Labels and a feedback loop.**
   - Record ack, "mine", "expected" and "suspicious" as label facts. This needs readable correction hooks (watch-by-default §6 and §11 #3).
   - Add seeded red-team fixtures (behavioral-modeling must-fix 1).
   - Calibrate the false-positive rate per model and per stratum. Adjust automatically only within policy bounds, additive-only below attestation, with the human on the loop.
   - This replaces the null-recall situation and the constraint-only, loosen-only retuning.
4. **Long memory as compact learned state.**
   - Extend the seen-set pattern to sessions, peers, ports and lineage, adding counts, the strata each entity was seen in, and inter-arrival times or periodicity.
   - Keep raw facts within their budgets but keep summaries for a year or more.
   - Keep metric rollups instead of 24 h of raw points.
   - Use multi-day episode objects for correlation instead of the ±3 h / 24 h windows.
   - Anchor attested snapshots to the drift budgets.
5. **Arbitrated adaptation as the default.**
   - An observation that alarmed goes to **pending**: it is not folded into the baseline and not added to the seen-set as normal until a context fact (an install, a boot, user activity), a label, or a quiet period within a drift budget explains it (`autonomy-doctrine.md:99-116`, must-fix 6).
   - This is the security-critical item and can ship early.
   - Process rule: a calibration finding becomes a **missing-context/data work item**, never a new suppression or threshold. R8 is the lesson.

**Do not:** apply R4, R5, R7, R9 or R10 as rules; add more incident-shaped detectors or hour sets; or weaken any completeness, coverage, freshness or recovery-freeze gate to reduce noise.

A draft copy is saved at `/private/tmp/claude-502/-Users-thomas-Projects-lightless-labs-public-descartes/be295191-32e2-4267-93c6-9cf9026e593c/scratchpad/learning-principle-audit-draft.md`. It is in the scratchpad, not the repo, and this message is the corrected version. No repo files were modified.