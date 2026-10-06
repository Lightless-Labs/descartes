# Context-aware learned baselines

**Created:** 2026-10-06
**Status:** DRAFT — review pending (Opus 5.5 max + gpt-6-astra, against the core principle below)
**Origin:** `todos/2026-10-06-session-peer-tuning.md` (operator reframe, 2026-10-06). Realizes Slice 12 ("time-of-day / day-type bucketing") of `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` and generalizes it from time to all context.
**Depends on:** `feat/fact-store-capacity-2026-10` (per-family fact stores, `fact-families.js` registry, seen-sets) landing first.

---

## 0. Core principle (the test every section of this plan must pass)

Descartes is a system that **learns and adapts**. It needs **data**, **context awareness** and **the ability to learn**. It must not become an expert system: a growing set of hand-written rules and magic thresholds that encode a human's (or an AI assistant's) guesses about what is normal on this machine.

Concretely, for this plan:

1. **The plan adds data and the ability to use it. It does not add behaviour rules.** No "suppress X after reboot", no "ignore peers after wake", no "critical only if ≥ N". Those were the rejected R4–R10 items.
2. **The machine decides which context matters.** The plan supplies *candidate* context dimensions; the learner keeps a dimension only where this host's own history shows it explains behaviour. A dimension that does not help is dropped automatically.
3. **Long memory stays.** 31-day fact windows and the first/last-seen sets stay. Real attacks unfold over days.
4. **Safety invariants are not behaviour rules and stay:** never-fabricate gates (trust, freshness, coverage, integrity), resource bounds, privilege hardening, the earned-trust promotion ladder of the autonomy doctrine.
5. **Every number left in the design is classified** as one of: (S) safety invariant / resource bound, (P) weak bootstrap prior that data overrides (must be shown to be overridden), (O) operator attention policy (how much the operator wants to be disturbed; not a claim about the machine). Anything else is a defect.

## 1. Problem

Real-host calibration (2026-10-05) showed the session and peer detectors alerting on ordinary events: reboots (sessions 3 → 0, then tmux-resurrect churn), wake from sleep (VPN / tailnet not yet reconnected → peers "dropped"), tailnet devices coming and going. The cause is **missing context**, not wrong thresholds:

- Every statistical model is a single global fold (Welford mean/variance over all ticks, `welford-stats.js:36-89`), with no context dimension (`session-baseline.js:330-368`, `peer-baseline.js:393-460`).
- The context signals that matter are missing or thrown away:
  - **uptime**: collected every fast tick (`tools/system.js:65` → metric `system.uptime_seconds`, `daemon.js:307`), read by no model; no boot time, no reboot event.
  - **sleep / wake, daemon downtime**: not collected at all.
  - **Tailscale backend state** (Running / Stopped / NeedsLogin…): parsed (`tools/tailscale-status.js:76-89`) and then dropped (`fact-translators.js:998-1007` emits only per-peer facts). "Tailnet down" and "tailnet up, zero peers online" are indistinguishable in history.
  - **VPN service connected state**: only indirectly visible through per-peer presence; the census marker is collector health, not "VPN connected".
  - **Network interfaces, default routes, DNS**: collected (`tools/network.js:81-261`) and never persisted.
  - **Session origin**: tmux/screen sessions and ssh/VPN logins are disjoint universes; tty is matched but not captured (`tools/vpn-peer-status.js:87-97`); plain local terminal sessions are invisible.
  - **Time**: only `login_hour_bucket` on peer facts (`fact-translators.js:882-891`), consumed by one hand-coded rule (`CORRELATION_ODD_HOURS = {00..05}`, `incident-correlation.js:58`). No weekday anywhere.
- The existing context handling is hand-coded: the VPN/markerless fingerprint split and the Tailscale exclusion in `peer-baseline.js` (R8), and `CORRELATION_ODD_HOURS`.

## 2. Design overview

Three layers, each usable on its own:

| Layer | What | Behaviour change |
|---|---|---|
| **L1 Context facts** | Collect and persist host lifecycle, network context, session context as first-class facts and *transition events*. | None. Data only. Ships first so history starts accumulating. |
| **L2 Context vector** | A pure, reproducible function from facts to a per-tick context vector of closed-enum / bucketed dimensions. | None. Visible in `baseline inspect`. |
| **L3 Context-conditioned learners** | Session / peer / login-time models that learn normal *per context*, choose their own strata, learn event aftermaths, and run in **shadow** beside the current detectors until they earn promotion. | Shadow only, until promotion via evidence (§7). |

## 3. L1 — Context facts (data)

New fact families in the `fact-families.js` registry, each with its own budget (sized like S0 of the capacity plan: pinned worst-case bytes per tick × horizon), its own ledger, trust gate and seen-set where useful.

### 3.1 `host_lifecycle` family

| Fact | Source | Notes |
|---|---|---|
| `host.boot` | boot time derived from uptime (macOS `kern.boottime`; Linux `/proc/stat btime`) | One event per boot; a changed boot time = a reboot happened, with its time. Replaces "uptime < gap" inference with an observed fact. |
| `host.suspend_interval` | suspended duration between ticks: Linux `CLOCK_BOOTTIME − CLOCK_MONOTONIC` delta; macOS continuous-time vs absolute-time delta (`mach_continuous_time` − `mach_absolute_time`), or `kern.sleeptime` / `kern.waketime` | Observed sleep/wake with start, end and duration — no log parsing, no guessing from tick gaps. |
| `host.daemon_gap` | daemon's own previous-tick record vs now | Distinguishes "machine slept" from "daemon was down while the machine ran" (the latter is itself suspicious and is surfaced, never treated as normal). |
| `host.shutdown_cause` (later, optional) | macOS `pmset -g log` / Linux journal previous-boot last entries | Clean vs unexpected shutdown. Feeds the operator's "make reboot handling context-aware" note. Optional because it needs log access; degrade to `unknown`. |

### 3.2 `network_context` family

| Fact | Source |
|---|---|
| `net.tailnet_state` | Tailscale `BackendState` (closed enum) + self online + exit-node in use; `unable` / `not_installed` distinct from `Stopped`. |
| `net.vpn_service_state` | per VPN service connected / disconnected (already parsed in `vpn-peer-status.js:321-351`), hashed service identity. |
| `net.location` | fingerprint of (default-route interface kind, gateway hash, DNS resolver set hash, primary interface set). A *network location* identity, hashed at source. |
| `net.interface_set` | hashed interface-name set + kinds (wifi / ethernet / tunnel). |
| transition events | `context.transition` facts when any of the above changes between ticks (old → new, ts). |

### 3.3 `session_context` family

| Fact | Source |
|---|---|
| `session.login` | `who` / `last` rows with tty class (console / pts / ssh), origin class (local / remote-hash), login time bucket — capturing the tty column the regex already matches. |
| `session.multiplexer` (existing `session.presence`) | linked to its creating login where the process tree allows (creator process lineage via the existing provenance helper, hash-only). |
| local terminal sessions | currently invisible; added via the login records (pts without remote host). |

### 3.4 Rules for all L1 facts (safety, not behaviour)

- Closed enums, buckets and hashes only, following `login_hour_bucket` / `handshake_age_bucket`; through `sanitizeDiagnostics`.
- Degrade, never fabricate: each collector reports `ok / partial / unable / not_applicable`; an `unable` context is recorded as such, never as a value.
- Bounded per-tick entity counts and byte budgets; T8 invariant per family.
- No new privileged access. Log-based sources (shutdown cause) are optional and degrade to `unknown`.

## 4. L2 — Context vector

A pure function `contextAt(ts, facts) → ContextVector`, recomputable from history (so models can be re-fit and backtested). Candidate dimensions, all closed-enum or bucketed:

| Dimension | Derived from |
|---|---|
| `since_boot` | time since `host.boot`, log-scale buckets |
| `since_wake` | time since the end of the last `host.suspend_interval`, log-scale buckets |
| `tailnet` | `net.tailnet_state` |
| `vpn` | any / none / per-service-hash connected |
| `location` | `net.location` identity (top-K by frequency; rare → `other`; never-seen → `new`) |
| `hour` | local hour bucket |
| `day_type` | weekday / weekend (later: learned day clusters) |
| `session_origin_mix` | which origin classes have live sessions |

Missing or `unable` inputs produce the value `unknown` for that dimension, never a guess.

The bucket edges (log-scale time buckets, top-K) are **(P)/(S)**: they define resolution and bound cardinality; they make no claim about what is normal.

## 5. L3 — Context-conditioned learners

### 5.1 Estimator: hierarchical, partially pooled, self-selecting

For a stream (session count, churn events, peer count per source, login hour per peer):

- **Per-stratum estimates with partial pooling.** Each stratum's estimate shrinks toward its parent (fewer dimensions), and ultimately toward the global estimate, in proportion to how little data it has (empirical-Bayes shrinkage). A rare context falls back gracefully; a well-observed context stands on its own. This is S12's "specific → day-type → global" fallback, generalized and learned.
- **The learner chooses the strata.** The candidate dimensions of §4 are offered; a dimension is kept for a stream only if a rolling-origin backtest over the host's own history shows it improves out-of-sample predictive likelihood (beyond a complexity penalty). Different hosts will end up with different strata. The chosen structure is recorded, versioned and shown in `baseline inspect` ("session count on this host depends on: since_boot, hour").
- **Distributions, not sigma rules.** Counts are modelled as count distributions (e.g. negative-binomial / Poisson-gamma); churn as event rates; login time as a per-entity hour distribution. An observation is scored by its **predictive tail probability (surprise)** under its stratum's predictive distribution, not by `|z| ≥ 3`. This removes `DEFAULT_*_SIGMA` and the stddev floor: variance uncertainty is carried by the prior and shrinks as data arrives.
- **Learned event aftermaths.** For transition contexts (`since_boot`, `since_wake`, tailnet / VPN transitions) the stratum is "time since event", so the model learns the aftermath curve: after a reboot, sessions are 0 and climb back as tmux-resurrect runs; after a wake, peers reconnect within some learned time. A reboot becomes "a known event with its learned aftermath"; an aftermath that does not match what this host normally does is the anomaly.

### 5.2 Applied to the current streams

| Stream | Today | Under this plan |
|---|---|---|
| session count (drop) | global Welford, sigma 3 / 5, floor 0.5 | per-context count model; drop scored by surprise given `since_boot`, `hour`, … |
| session churn | fingerprint diff, fixed lookback | churn **rate** per context; tmux-resurrect after boot learned as normal aftermath; a lone churn is scored by how surprising it is *here, now* (answers R10 without a rule) |
| peer count | one count, VPN/markerless split, Tailscale excluded (R8) | **one stream per source** (ssh, vpn service, wireguard, tailnet-online), each per context; tailnet peers conditioned on `tailnet` state. Retires the R8 exclusion. |
| login hour (correlation) | `CORRELATION_ODD_HOURS = {00..05}` | per-entity and per-host login-hour distribution; "odd hour" = low learned probability for *this* host / peer. Retires the fixed set. |

### 5.3 Contamination and poisoning guards (the Skynet ditch)

Learning from data an attacker can shape is the main risk. Guards, all from the autonomy doctrine ("never adapt to unattested change"):

- **Don't learn from anomalies.** Observations scored as anomalous, or taken while a related alert is active and unacknowledged, are excluded from the fit (or held in quarantine until the alert is resolved as benign by the operator).
- **Context novelty is itself a signal.** A never-seen `location`, a first tailnet exit node, a first remote origin: the context dimension takes the value `new`, the learner claims nothing about normal there, and the novelty is surfaced as an event.
- **Slow-drift detection.** Each stratum compares its recent estimate with its long-memory estimate (31 days); a sustained shift is surfaced, not silently absorbed. This is why the long window stays.
- **Structure changes enter at shadow.** A newly selected stratum structure (e.g. "now depends on location") is a new model version; it starts in shadow and must earn promotion like any authored model.

### 5.4 Never-fabricate (unchanged contract)

- A learner reports `evaluatedAlertKeys` only for streams and strata it actually evaluated this tick, with a trusted, fresh, complete input and a trusted context vector.
- Context `unknown` or untrusted → evaluate at the parent stratum with lower confidence, or not at all if the parent is also untrusted; never claim a recovery from a stratum it could not resolve.
- Horizon gates (capacity plan S3) apply per model; the context families get their own horizons.
- Models are re-fit from history with the integrity / continuity / quarantine machinery; a lost or quarantined history re-arms (cold start), never "everything normal".

## 6. Delivery (separate, already decided)

**R3 notify once** (activation + severity escalation, then quiet until recovery) is accepted and independent of this plan. It ships as its own small slice in `alert-store.js` (`notificationDue`), before L3.

## 7. Evaluation and promotion (earned trust, measured honestly)

There is no ground truth (`recall_proxy` is null by design), so evidence is built deliberately:

- **Shadow side-by-side.** Each L3 model runs beside the current detector on the same ticks; both outcomes are logged.
- **Benign-event corpus.** Real lifecycle events on this host (reboots, wakes, tailnet flaps) give a labelled corpus of benign transitions: how many alerts did each model raise on them?
- **Replayed attack scenarios.** Synthetic injections into a *copy* of real history: mass session kill (the 2026-07-11 incident shape), session kill-and-replace, odd-hour unattributed login, slow drift over days, kill timed to just after a reboot (an attacker hiding in the aftermath). Detection rate and delay per model.
- **Operator acknowledgements** as labels where available.
- **Promotion** of an L3 model over the detector it replaces follows the earned-trust ladder (`docs/design/autonomy-doctrine.md`): evidence-driven, operator on the loop, and a daybreak gate. The old hand rules (`CORRELATION_ODD_HOURS`, R8 exclusion, sigma/floor constants) are retired only when their replacement is promoted.

## 8. Sequencing

| Step | Content | Gate |
|---|---|---|
| **C0** | Grounding: pin fact schemas, worst-case bytes per tick, family budgets/horizons; confirm macOS/Linux sources for boot / suspend; inventory every number to be classified S/P/O (feeds §0.5). | review |
| **C1** | R3 notify-once (delivery slice). | daybreak (alert-store) |
| **C2** | L1 context facts: `host_lifecycle`, `network_context`, `session_context` collectors + translators + families. **Data only; ship early so history accumulates.** | daybreak (collectors, sanitization, degrade-not-fabricate) |
| **C3** | L2 context vector + `baseline inspect` display. | review |
| **C4** | L3 estimator library (pure): hierarchical shrinkage, count / rate / hour-distribution models, surprise scoring, rolling-origin backtest + dimension selection. Offline harness over copied history. | review + property tests |
| **C5** | Shadow learners for session count, churn, peer-per-source, login hour; contamination / drift / context-novelty guards; side-by-side logging. | daybreak (coverage contract, poisoning) |
| **C6** | Evaluation harness (benign corpus + replayed scenarios) and report. | review |
| **C7** | Promotion of models that earned it; retirement of the hand rules they replace. | daybreak + operator on the loop |

C2 should start as soon as the capacity branch lands: the learners need weeks of context history, so collecting it early matters more than anything else in this plan.

## 9. Non-goals

- No new hand-written behaviour rules, thresholds or suppressions anywhere in this plan.
- No change to the 31-day memory.
- No LLM in the detection path.
- No privileged collection beyond what exists (the root helper remains optional).
- Not replacing set-based novelty (service / lineage / scheduled job) here; their context conditioning (e.g. "new service right after an OS update") is a follow-up once L1/L2 exist.

## 10. Open questions for the operator

1. **Tier.** Should L3 shadow models run under `watch.json` (default on, so every install collects evidence) or `learned.json` (opt-in)? Recommendation: L1 context facts under watch (data only); L3 shadow under watch as shadow-only (no alerts of its own until promoted).
2. **Shutdown-cause source.** Accept reading `pmset -g log` / journal (unprivileged, read-only), or keep reboot context to boot time only?
3. **Operator attention policy (O).** The surprise level at which a promoted model notifies is an attention budget, not a claim about the machine. Should it be expressed as "at most ~N notifications per week from statistical models", with the model translating that into a threshold from its own history?

## 11. Key code refs

- Global folds: `welford-stats.js:20,36-89`; `session-baseline.js:69-111,330-434,652-661`; `peer-baseline.js:46-93,393-460`.
- Hand-coded context: `peer-baseline.js:54-61` (fingerprint split), `:451-453` (R8 Tailscale exclusion); `incident-correlation.js:58,63,67,71`.
- Dropped context: `tools/tailscale-status.js:76-89` vs `fact-translators.js:998-1007`; `tools/network.js:81-261` vs `fact-translators.js:532-573`; `tools/vpn-peer-status.js:87-97,124-156,321-351`.
- Uptime dead end: `tools/system.js:65`, `daemon.js:307`.
- Extension points: `fact-families.js` (capacity branch), `novelty-seen-set.js`, `model-ir.js:262-455` (no context op yet), `alert-store.js:6,263-268`.
