# Slice 7 — Authority/Containment Plane — DESIGN-ONLY

**Status:** DRAFT — design-only, not an implementation plan. No code, no new tools, no new
`execFile` surface is prescribed to ship from this document.
**Reviewed:** 2026-07-23 (Stage 1 adversarial gate) — GO_WITH_CHANGES; all 3 must-fixes folded
(kill self-lockout gap, write-ahead/crash-consistent audit ordering, hash-at-source vs.
raw-identifier provenance tension). 6 PASS + 2 MINOR safety findings recorded, no further action
required on the MINORs beyond what §(a)'s "Inputs read" note and revoke's precondition text already
say.
**Created:** 2026-07-23
**Review MINORs folded:** 2026-07-23 — prior-art reconciliation with
`todos/2026-05-19-agent-delegation-identity-authority.md` (§ "Inputs read" below), and an
illustrative-not-exhaustive caveat on §(a) revoke's credential-class enumeration.
**Operator direction folded:** 2026-07-24 — see "## Operator direction (2026-07-24)" below for the
full operator response, and the updated §(a)/§(b)/§(c)/§(d) cross-references it drove. Summary of
what changed: §(b)'s authority-model tiering is now operator-confirmed rather than only
recommended; execution for kill/revoke/block is now explicitly routed through a **separate
capability-holding helper** (never the daemon/CLI directly) using single-use, time-limited consent,
leaning on existing OS privilege primitives rather than a new one; block gains an explicit
read-existing-state-first requirement; quarantine is now concretely defined and flagged as the
weakest verb, with a recommendation to fold it into {freeze + block} pending an open question back
to the operator; and a new, heavily governance-gated **federated immune system** direction is
captured as a future resolution to the fast-response/cooling-off tension, tied to `AGENTS.md`'s L3
Federated Knowledge Layer and Operational Lifecycle stage 7 ("Learn"). This document remains
DESIGN-ONLY — no code changed as part of folding this direction in.
**Slice 7 safety review (operator-direction update):** 2026-07-24 — GO_WITH_CHANGES; all 3
must-fixes folded (federated immune system fleet-global blast-radius controls — staged/canary
propagation, a fleet-wide circuit-breaker + signature recall/revocation, Sybil-resistance and
ratifier-compromise controls, added to the §(e) 7.8 (formerly 7.6, renumbered 2026-08-11)
governance checklist and §(d) item 9; the
federated reflex path's consent-model degradation — reflex execution has no human in the loop to
mint a per-execution consent nonce, so the helper/capability separation degrades to trusting the
daemon's own signature-recognition code, now named explicitly with a required-analysis item added
to the 7.8 (formerly 7.6) checklist; the single-use execution-consent nonce's own crash-consistency
and binding —
write-ahead consume before the mutating call, and cryptographic/logical binding to a specific
approved §(b) decision plus the freshly re-resolved target+verb, added to §(a) Cross-verb themes).
Safety findings folded alongside the must-fixes: self-lockout-at-fleet-scale added to the
federated-section governance checklist ("reversible-first" alone does not bound simultaneous
multi-host self-lockout); the quarantine-fold privileged-primitive-count overstatement between
§(a)'s recommendation and §(e) 7.7's (formerly 7.5) own text reconciled. Q2 (honest
autonomy-escalation labeling)
and Q4 (design-only, zero new `execFile`) both re-verified PASS; all three Stage-1 (2026-07-23)
must-fixes reconfirmed present and correctly reasoned. This document remains DESIGN-ONLY — no code
changed as part of folding this review in.
**Operator sign-off folded:** 2026-08-11 — see "## Operator sign-off (2026-08-11)" below for the
operator's full response to §(d)'s nine open scope decisions, **all now RESOLVED**. Headline
changes, threaded through §(a)–(e) and the Summary below: all four verbs (kill/revoke/block/
quarantine) confirmed in scope, and `quarantine` is **kept** as its own verb (not folded into
`{freeze + block}`) because, although the operator doesn't run containers personally, other users
of Descartes deployments do; §(b) now leads with Option 3 delivered via **local notification** as
the near-term mechanism, gains a no-central-service **SSH-key-relay transport** design option for
delivering an approval request to another of the operator's own devices, and separates **transport**
(how the request travels) from **authority** (a short-TTL, single-use, biscuit/macaroon-style
capability token minted on the operator's own device — never on the monitored machine — with a
fail-closed action→mechanism matrix as the default); §(c) is hardened to state plainly that
`AGENTS.md` cannot itself enforce anything and the authority plane must be a **deterministic code
gate**, never a model prompt/instruction — the model may only *propose*; §(e)'s phased build now
starts with recommend-only-via-local-notification (mutates nothing, specified precisely enough to
implement next), followed by remote-device notification, then the federated layer, then execution;
a new **deception/honey-tokens** slice is added below containment (mutates nothing, needs no
authority plane); a **Vault-Tec sandbox** validation harness is added — mutating verbs are exercised
only inside dedicated, otherwise-useless "Vault-Tec Vault"-themed VMs on the operator's other
hardware/CI (`big-cabbage`/`tart`), never the no-VM dev machine; a **per-host self-lockout opt-out**
toggle is added; a **hack-back/legal boundary** ("repel" means defending Descartes' own machines,
never reaching beyond that perimeter) is stated; and the federated immune system direction is spun
out into its own dedicated plan,
`docs/plans/2026-08-11-descartes-fleet-federated-topology.md` (a "Descartes all the way down"
fractal fleet vision), which this document now **references rather than absorbs**. This document
remains DESIGN-ONLY — no code changed as part of folding this sign-off in.
**Slice 7 sign-off safety review:** 2026-08-11 — GO_WITH_CHANGES; 1 must-fix folded (the fail-closed
action→mechanism matrix's "else Option 2a, else Option 3" floor contradicted §(c)'s
deterministic-gate guarantee, §(b)'s own key-custody guarantee, and Slice 7.5's own "derived from a
verified §(b) capability token" requirement by letting a mutating verb be authorized with no
off-machine capability token — the matrix and §(e)'s Slice 7.4→7.5 phasing are now corrected so
every mutating verb (`kill`/`block`/`revoke`/`quarantine`) requires an Option 2b-class capability
token as the non-overridable authority floor, denied outright rather than downgraded when no
token-bearing channel is configured). 4 safety findings folded: §(b)'s capability-token "minting"
language is clarified so device-side minting is read as binding to the human-approved target rather
than itself re-resolving a live one — the load-bearing TOCTOU-closing re-resolution remains the
execution-time, helper-side one §(a) already specifies; the Vault-Tec sandbox's precondition text is
corrected from "Slice 7.3 onward" to "Slice 7.5 onward" to match the actual first mutating slice; a
rooted-host residual is now stated explicitly in §(a) Cross-verb themes (a root-level host compromise
bypasses every mechanism in this document — the helper/off-machine-key design defends the
compromised-daemon/prompt-injected-model threat, not a rooted host); and Slice 7.1's deception
framing is tightened from "mutates nothing about the host's real state" / "zero new privilege" to
"adds only inert, additive bait — no destructive or self-lockout-capable mutation," with its own
explicit doors-and-corners pass now required, mirroring what Slice 7.2 already mandates for itself.
This document remains DESIGN-ONLY — no code changed as part of folding this review in.
**`throttle` verb folded:** 2026-08-11 — reversible graduated "buy-time" containment
(operator-suggested). A new fifth containment verb, `throttle` (covertly degrade a suspect
process's or connection's CPU/disk/network resources without it noticing, to buy time for the
§(b) Option 3 cooling-off window or a future federated response), is added throughout §(a)-(e)
below. It is the most reversible verb in this document — auto-reverting on a short timer,
non-destructive, and one-touch operator-revertible — but it is still a **mutating** verb and
therefore remains fully under §(b)'s fail-closed capability-token floor, exactly like
`kill`/`block`/`revoke`/`quarantine`; folding it in does **not** create any exception to that
floor. See §(a)'s new `### throttle` subsection, §(b)'s fail-closed-matrix and
fast-response-tension updates, §(c)'s policy-authorized-tier note, and §(e)'s slice breakdown for
the full treatment. This document remains DESIGN-ONLY — no code changed as part of folding this in.
**Supersedes:** nothing. This is the dedicated, separately-reviewed plan that
`docs/plans/2026-07-13-observed-incident-collectors.md`'s Slice 7 section (lines 858–871)
explicitly said would be required before any pickup — "a placeholder for a future,
separately-reviewed plan... do not begin implementation from this section."
**Mandate:** `docs/HANDOFF.md`'s "RESUME HERE" option #3 (2026-07-23): "Slice 7 —
authority/containment plane, DESIGN-ONLY... Sensitive — get explicit operator scope before even
the design." See the "Operator-scope note" immediately below for how this document treats that
requirement.
**Inputs read (read-only; none edited by this doc):**
`docs/plans/2026-07-13-observed-incident-collectors.md` (Slice 7 §858–871, Open Question 3
§908), `AGENTS.md` ("Policy / Authority Plane" §80–90), `tools/descartes-cli/src/promotion-store.js`
(627 lines, the template), `tools/descartes-cli/src/constraint-store.js` (single-writer
convention, `promoteReviewReadyToActive`), `tools/descartes-cli/src/index.js` (`learned` CLI
dispatch precedent, line 133), `tools/descartes-cli/src/daemon.js` (`learned.json` kill-switch
gating precedent, lines ~68–80/341/422), `docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`
(S3-priv `root_helper` adversarial review, used as the review-bar reference in §(e)). `todos/2026-05-19-agent-delegation-identity-authority.md` (an open, unassigned design-spike TODO,
not yet an implementation) — corrected 2026-07-23: this file does exist in this repo, contrary to
this document's earlier "not found / out of scope" framing, and bears directly on §(b)'s hardest
open question. That TODO scopes inter-**agent** delegation (a Descartes instance delegating work
to another agent/execution environment: explicit agent identity, scoped capability tokens rather
than ambient trust, and — most relevantly here — "the user can validate/approve cross-agent
delegation before mutating or sensitive actions") as a still-open question, not a settled answer.
It is prior art bearing on, but not a substitute for, this document's multi-party-confirmation
authority model (§(b)): it establishes that this codebase already recognizes delegated/multi-actor
authorization as a distinct open problem needing its own identity and capability-token design, which
is consistent with §(b)'s conclusion that a true second-party mechanism (Option 1) is aspirational
rather than buildable today. A future implementation should reconcile the two rather than design
authority primitives twice.

---

## Operator-scope note (read this before the rest of the document)

`docs/HANDOFF.md` requires explicit operator scope **before even the design**. This document was
produced under an orchestrator-issued task that itself supplied detailed scope: DESIGN-ONLY, no
code, the five required sections below, the verb set (kill/revoke/block/quarantine), the mandate
to template on `promotion-store.js`, and the mandate for a separate `authority/containment.json`
store. That dispatch constitutes a first layer of explicit scoping for *this drafting act*.

It does **not**, however, answer the deeper scope questions a real implementation would need
settled — whether the operator wants any containment *execution* capability at all, which verbs
apply to their actual environment, whether a second human operator exists, and how much
self-lockout risk is tolerable. Those are enumerated in full in **§(d) Open scope decisions** and
are explicitly flagged as requiring direct operator sign-off before any follow-on implementation
plan is opened. **This document is a design draft for operator review, not a green light to
build** — until it was: **updated 2026-08-11 — all nine §(d) items are now RESOLVED** by direct
operator sign-off (see "## Operator sign-off (2026-08-11)" below), and §(d) item 6 explicitly
directs **BUILD**, with a concrete phased sequence in §(e). This document itself remains
design-only — no code is added here, and it does not become an implementation plan by virtue of
being signed off — but the scope questions this note originally flagged as blocking are no longer
open, and a follow-on implementation plan for §(e) Slice 7.1 may now be opened on this basis.

---

## (a) Doors-and-corners prerequisite pass

For each verb: what platform capability/privilege/entitlement it needs, what can go wrong, and
what must exist before implementation is even attempted. This section is deliberately pessimistic
— containment is a **write** path; every precedent in this codebase (S3-priv's `root_helper`,
the WireGuard collector, the evidence-freeze action) has gone out of its way to stay read-only,
and this is the first design surface in the whole initiative that considers breaking that
pattern.

### kill (terminate a process/session)

- **Capabilities/privileges:** `kill(2)`/session teardown for a process the daemon's own UID owns
  needs nothing extra; for any other UID's process it needs root or an authorization-services
  grant. Killing a *named session* (tmux/screen, per Slice 1's session-census collector) means
  killing the session's controlling process, which requires access to a socket owned by the
  session's own user — cross-user kill therefore needs the same elevated-privilege shape S3-priv's
  `root_helper` needed for cross-UID **read**, except this would be a cross-UID **write**, a
  categorically different (and categorically more dangerous) grant.
- **What can go wrong:** PID reuse — S3-priv's own read path already documented PID-reuse races as
  an accepted residual risk for *reading*; for *killing*, a PID-reuse race means terminating the
  wrong live process, which is unrecoverable. Session-target ambiguity (the exact "multi-owner"
  problem the Codex-review Slice A finding fixed for read-side port facts) applied to a mutating
  verb means killing an unintended session. No undo exists — a killed process cannot be
  resurrected; rollback for this verb is fundamentally `none`, not merely difficult.
  **Self-lockout (reviewed 2026-07-23, folded from Stage 1 gate must-fix):** `kill` has its own,
  distinct self-lockout failure mode from block/revoke's "cut off remote access" case — the
  operator (or the approving actor's automation) kills its **own controlling session, parent
  shell, or `sshd`/terminal process** that is executing the approval itself, or an ancestor of it.
  Unlike block/revoke's lockout (which severs a *channel*), this is **irreversible** on top of
  self-inflicted: there is no reconnecting to resurrect a killed shell the way a removed firewall
  rule or VPN peer can be re-added. This is arguably the single worst compound failure mode in the
  whole document — irreversible *and* self-inflicted — yet it is the one verb the cross-verb
  self-lockout summary below previously excluded. Treat it as at least as serious as block/revoke's
  self-lockout risk, not a lesser case.
- **Preconditions before any implementation:** target re-resolution *at execution time*, not just
  at proposal/approval time (closing the TOCTOU gap between "human approved killing session X" and
  "the daemon actually issues the kill"); a hard "never kill by heuristic/fuzzy match" rule — the
  execution primitive must refuse to act on anything but an exact, freshly-reconfirmed identifier;
  a dry-run/simulate mode that reports what *would* be killed without doing it, exercised and
  reviewed before the real path is built; a **self-lockout guard**, mirroring revoke's and block's,
  that refuses to kill the approving actor's own session, its own login/controlling-terminal
  process, or any process in its own parent-process chain (walk the ancestry of the process issuing
  the kill request up to the session leader/`sshd`/login shell and refuse if the target intersects
  it) — this guard is a hard precondition for `kill`, not an optional hardening, precisely because
  `kill` combines self-lockout with zero rollback. **Execution routing (operator-directed
  2026-07-24):** `kill` must never be issued by the daemon/CLI process itself — it is issued only
  by the separate capability-holding helper described in the Cross-verb themes subsection below,
  gated on a single-use, time-limited consent nonce distinct from the §(b) approval nonce. See that
  subsection for the full model and the sudo/polkit-vs-bespoke-mechanism answer.

### revoke (invalidate a credential/session token)

- **Capabilities/privileges:** revoking an SSH session requires killing the session's `sshd`
  child (same privilege shape and risk as **kill**, above, plus the extra step of mapping a
  connection to the right process). Revoking a WireGuard peer requires a **write** to the
  interface (`wg set ... peer ... remove`), which needs the interface owner's privileges (root or
  a sudoers grant) — Slice 3's `collect_vpn_peer_status` collector *deliberately* used a read-only
  allowlist (`wg show interfaces`/`wg show <if> {peers,endpoints,latest-handshakes}`) and
  deliberately excluded any config-mutating `wg` subcommand for exactly this reason; a revoke verb
  would be the first thing in this codebase to cross that line.
- **What can go wrong:** revoking the wrong peer/session; **self-lockout** — revoking the
  credential or session the approving human is *currently using* to administer the host, cutting
  off their own access mid-incident (this is the single most concrete catastrophic failure mode
  discussed anywhere in this document); partial interface-state application if a multi-step `wg
  set` sequence fails halfway.
- **Preconditions:** an allowlisted, single-purpose, minimally-scoped write primitive (never a
  generic `wg set` accepting arbitrary arguments — mirror the read-side allowlist discipline
  exactly); a **self-lockout guard** that refuses to revoke the credential/session/peer currently
  in use by the approving actor's own connection; a designed-in reversal path (re-adding a peer)
  proven to work *before* the removal path ships. **Execution routing (operator-directed
  2026-07-24):** same helper-mediated, single-use/time-limited-consent execution model as `kill`
  (Cross-verb themes subsection below) — `revoke` is explicitly named alongside `kill` as executing
  only through the separate capability-holding helper, never directly by the daemon/CLI.
- **Enumeration scope note:** the SSH-session and WireGuard-peer cases above are illustrative
  examples, not the complete revoke surface. Other credential classes — OAuth tokens, API keys,
  Kerberos tickets, application session cookies — have their own distinct, and possibly higher,
  privilege surfaces (different revocation mechanisms, different blast radii, different
  self-lockout shapes) that are not analyzed here and must be enumerated concretely, per credential
  class, at implementation time (per §(d) item 2's "enumerate against the real deployment rather
  than building out the full abstract catalog speculatively" discipline). No scope expansion is
  intended by this note — it flags a gap in this document's enumeration, not a new verb or class to
  design now.

### block (firewall/deny a peer)

- **Capabilities/privileges:** macOS: `pfctl` anchor manipulation (root) and/or Application
  Firewall (`socketfilterfw`, a different mechanism with different semantics); Linux:
  nftables/iptables rule insertion needs `CAP_NET_ADMIN` or root.
- **What can go wrong:** this is the verb with the single highest self-lockout blast radius — a
  misapplied or overly broad rule can sever the operator's own SSH/remote-access channel to the
  host, making the mistake unrecoverable without physical/console access. Rule-ordering/anchor
  conflicts with a firewall configuration Descartes doesn't know about (the operator's existing
  rules could silently override, or be silently overridden by, a new Descartes-owned rule).
  Non-idempotent/partial rule application leaving the host in a worse state than before the
  action was attempted.
- **Preconditions:** an isolated, uniquely-named anchor/chain that Descartes exclusively owns and
  never touches the operator's pre-existing rules; a **hard-coded exception** that always
  preserves the current management/SSH connection regardless of what is being blocked; dry-run
  diffing against the live ruleset before any real application; a mandatory auto-expiry/auto-revert
  on every block rule (a forgotten permanent block is its own accumulating risk, mirroring why
  `promotion-store.js` uses a bounded expiry rather than an indefinite pending state). **Existing-state
  awareness (operator-directed 2026-07-24):** before any block action, Descartes must **read the
  current firewall state** (`pf`/`nft`/`iptables`, whichever the host runs) — it must **never
  blind-append** a rule without first observing what is already present. This read pass must
  **detect conflicts and duplicates** against Descartes' own prior rules and against the operator's
  existing configuration (e.g. a rule that already blocks the same target, or one that would
  contradict/shadow it) before deciding to act. On rollback/expiry, Descartes must remove **only the
  rules it itself added** — never a broader revert, never touching anything already present before
  Descartes acted, which is the concrete mechanism that makes the isolated-anchor-ownership
  requirement above actually safe in practice rather than merely aspirational. `block` is also
  shaped by, though not identical in every detail to, the helper-mediated, single-use-consent
  execution model described for `kill`/`revoke` in the Cross-verb themes subsection below — the
  same "helper holds the capability, daemon/CLI does not" and "lean on sudo/polkit rather than a
  new privilege path" reasoning applies to the anchor-manipulation call itself.

### quarantine (isolate a container/process)

**Definition (operator-directed 2026-07-24 — the operator asked what this verb even means; this
is now the answer):** quarantine means **contain without destroying, to preserve forensic state**
— as opposed to `kill`, which loses evidence the moment the process dies. Concretely this is one
or both of: **freeze** the process (`SIGSTOP`, a cgroup freezer, or `docker pause`) so it stops
executing but its memory/state remain inspectable, and/or **network-isolate** it (move it to an
isolated network namespace, or apply a deny-all rule scoped to its cgroup) so it can no longer
communicate while its on-disk and in-memory state stay intact for later analysis.

- **Capabilities/privileges:** container-runtime-dependent (Docker/Podman/containerd
  pause/network-disconnect/cgroup-freeze); access to the runtime's control socket
  (`docker.sock` membership is well-documented as *effectively root-equivalent* on the host, not a
  lesser privilege than root). For a non-containerized process, "quarantine" has no
  well-defined platform primitive on macOS/Linux short of `SIGSTOP` + network-namespace isolation,
  both of which also need elevated privilege.
- **What can go wrong:** treating `docker.sock` access as a "lighter" verb than kill/block is a
  false economy — a compromised or bugged daemon holding that socket has full host compromise
  capability, a materially worse blast radius than a narrowly-scoped kill or block primitive.
  `SIGSTOP`-based quarantine of a shared-dependency process can cascade-hang unrelated processes
  waiting on it.
- **Preconditions:** concretely determine what "quarantine" even means for the operator's actual
  environment before any privilege is requested at all (see §(d) item 2 — this is a scope question,
  not an engineering one); if a container-socket route is ever chosen, that credential must be
  held to at least the security bar `root_helper` earned (dedicated, minimally-scoped proxy —
  never the raw socket handed to the general daemon process).
- **Weakest-defined verb, flagged (operator-directed 2026-07-24):** even with the definition above,
  `quarantine` remains the least concretely specified verb in this document, because it is the only
  one whose primitives (freeze, network-isolate) are each already independently expressible as a
  narrower operation rather than a genuinely new one. **Recommendation:** fold `quarantine` into a
  **composition of {freeze + block}** — reuse `SIGSTOP`/cgroup-freezer as a "freeze" primitive
  alongside the `block` verb's network-isolation machinery above, rather than standing up
  `quarantine` as its own fifth verb with its own execution primitive and its own helper surface.
  **Reconciliation note (safety-review finding, folded 2026-07-24):** this fold reduces the **verb
  count** by one; it does not reduce the **privileged-primitive count** — §(e) Slice 7.7 (formerly
  7.5, renumbered 2026-08-11) already
  correctly notes that folding still introduces a new `SIGSTOP`/cgroup-freezer "freeze" primitive,
  which is itself a new privileged, cross-UID-capable mutating primitive needing its own helper
  routing and review, exactly as a standalone `quarantine` verb would have needed. Read "avoiding
  its own execution primitive and its own helper surface" above as applying to the **verb/API
  surface** (one fewer named verb, one fewer place operators choose from), not as a claim that no
  new privileged primitive is introduced — the count of privileged primitives (kill/revoke/block/
  freeze) is unchanged either way, and the security saving from folding is correspondingly smaller
  than the phrase alone implies. **Unless** the operator actually runs containers on the monitored
  host that they would want
  isolated via `docker pause`/`docker network disconnect`, in which case a container-runtime-aware
  quarantine primitive may be worth keeping distinct rather than decomposed, since the
  container-socket privilege shape doesn't map cleanly onto plain `SIGSTOP` + netns.
  **RESOLVED by operator sign-off (2026-08-11):** `quarantine` is **kept** as its own, distinct
  verb — not folded into `{freeze + block}`. The operator does not personally run containers on
  their own monitored host, but Descartes is not built for a single user; other operators of
  Descartes deployments do run containers, so dropping the container-runtime-aware primitive would
  be dropping real-world applicability, not just this operator's own case. The fold-vs-keep analysis
  above, and the reconciliation note on privileged-primitive count, remain correct as background
  reasoning and are retained for whichever future deployment genuinely has no container workload and
  wants to reconsider the fold — but the default going forward is **keep**. See §(d) items 2 and 8.

### throttle (covertly slow a suspect process/connection)

**Definition (operator-suggested addition, 2026-08-11):** `throttle` covertly degrades a
suspicious or unusual process's or connection's resource consumption — CPU, disk/filesystem I/O,
or network throughput/latency — **without the target noticing**, to buy time. Unlike every other
verb in this document, `throttle` is not itself an end state: its purpose is to hold a suspect in
a degraded-but-still-running state *while* the §(b) Option 3 cooling-off window plays out, or,
later, while a federated corroboration/response decision resolves — see the fast-response-tension
update in §(b) below. It is the **sibling of `block`**: where `block` DENIES a channel outright,
`throttle` DEGRADES it, and it inherits `block`'s doors-and-corners obligations for the network
mechanism specifically (below).

- **Capabilities/privileges (mechanism per resource; covert vs. loud stated honestly):**
  - **CPU:** Linux cgroup-v2 `cpu.max` (a hard CPU-time cap on the target's cgroup), or
    reassignment to `SCHED_IDLE`; macOS `taskpolicy -b` to push the target into the
    background/throttled QoS band. Both are **covert** — the target reads as a busy box getting
    fewer cycles, not as an externally-frozen process.
  - **Disk/filesystem:** Linux cgroup `io.max` or `ionice -c3` (idle I/O class); macOS
    `taskpolicy -b` also throttles I/O as part of the same background QoS band; optionally, an
    EndpointSecurity client adding bounded latency to `open`/`exec` authorization events for
    finer-grained FS throttling on macOS — this needs the ES entitlement, itself a
    **doors-and-corners item** (entitlement provisioning), and the added latency is hard-bounded by
    the ES authorization deadline, so it cannot stall a target indefinitely. **Covert-ish** —
    bounded added latency on file operations is a plausible symptom of a busy or slow disk, but a
    sufficiently instrumented target could in principle notice a suspicious pattern in exactly
    which operations are slowed.
  - **Network (highest value, most covert, most reversible):** Linux `tc`/`netem` (added latency,
    packet loss, and/or a bandwidth cap on a specific flow, classified via an `nft`/`iptables` mark
    scoped to the target); macOS `dnctl` (dummynet) + `pf`. Reads as a flaky or slow network path —
    directly slows exfiltration, C2 callbacks, and lateral movement, which is exactly the
    highest-value use case for buying time. **This is the sibling of `block`** named above, and it
    **inherits `block`'s existing-state-awareness rule** from that subsection and the Cross-verb
    themes execution-architecture bullet below: Descartes must read the existing `pf`/`nft`/`tc`
    state before adding a throttle rule, must never blind-append, and on auto-revert or
    operator-revert must roll back **only the rules/qdiscs/marks it itself added** — never a
    broader revert touching state it did not create.
  - **LOUD — avoid for the covert use case, named for completeness:** `SIGSTOP` (a fully frozen
    process is an obvious, discontinuous signal to any heartbeat/liveness check the target or its
    controller runs — this is `quarantine`'s freeze primitive, not `throttle`'s); ptrace-based
    syscall-delay (detectable via `TracerPid` in `/proc/<pid>/status` or timing-based anti-debug
    checks). Both are excluded from `throttle`'s own mechanism set precisely because they are loud,
    even though they are mechanically capable of slowing a target.
- **What can go wrong:**
  - **Imperfect covertness against an anti-analysis adversary.** The mechanisms above are covert
    against a naive or non-adversarial target, but a sufficiently sophisticated one can still
    notice — e.g. a mismatch between its own observed throughput and what the host's
    `uptime`/load-average or `/proc/stat` reports, or network-timing characteristics of
    `netem`/`dnctl` shaping rather than genuine congestion. **Full covertness is deception-grade**
    (it would require actively forging what the target can observe about its own environment, not
    merely degrading its resources) and is explicitly **not** what this verb provides — flagged
    here so it is never oversold as undetectable.
  - **False-positive collateral is now real, in a way most other verbs' failure modes are not.**
    Killing or blocking the wrong target is binary (wrong target harmed, right target unaffected);
    throttling a **legitimately busy, merely misclassified** process or connection degrades real
    work — a false positive here doesn't fail loudly, it silently makes something slower, which can
    go unnoticed and unremediated far longer than a failed kill/block would. This needs the same
    tight, fresh, non-fuzzy target re-resolution every other verb requires (Cross-verb themes)
    **and** the auto-revert net below as a structural backstop, not merely a monitoring/alerting
    backstop.
  - **Self-DoS (new guard, mirroring the existing self-lockout guard):** just as `kill`/`block`/
    `revoke` must never act on the approving actor's own session/connection/parent-process chain,
    `throttle` must never degrade the approval/critical path itself or any process/connection below
    a configured host-safety floor — throttling the daemon's own consent-nonce delivery channel,
    the approving device's notification transport, or a host-critical service (e.g. the SSH daemon
    the operator needs to reach the host to review or revert the throttle) would be a
    **self-inflicted denial of service** that defeats the entire point of buying time. This guard is
    a hard precondition for `throttle`, structurally identical in spirit to `kill`'s self-lockout
    guard, even though `throttle`'s irreversibility profile is the opposite of `kill`'s.
- **Reversibility (the strongest property of this verb, stated plainly):** `throttle` is
  **reversible, short-timer auto-reverting, and one-touch operator-revertible** — a throttle rule
  ships with a mandatory bounded expiry (mirroring `block`'s mandatory auto-expiry precondition)
  after which the cgroup/QoS/`tc`/`dnctl` state is automatically restored, **and** the operator can
  revert it immediately and manually at any point before that expiry (e.g. on recognizing a false
  positive). This makes `throttle` the **most reversible verb in this document** — see the
  Cross-verb themes irreversibility update below.
- **Preconditions before any implementation:** the same fresh, exact, non-fuzzy target
  re-resolution at execution time required of every other verb (Cross-verb themes, TOCTOU); a
  mandatory bounded auto-expiry/auto-revert, proven to actually restore prior state, not merely
  believed to; an immediate, one-touch manual revert path, proven to work before the throttle path
  ships; the self-DoS guard above, as a hard precondition, not optional hardening; for the network
  mechanism specifically, a read-existing-state-first pass identical in spirit to `block`'s, so a
  throttle rule never blind-appends onto unknown `pf`/`nft`/`tc` state. **Execution routing:** like
  every other mutating verb, `throttle` must never be issued by the daemon/CLI process itself — it
  executes only through the separate capability-holding helper described in the Cross-verb themes
  subsection below, under the same single-use, time-limited execution-consent nonce model.
  `throttle` introduces no exception to that routing, even though its reversibility profile is the
  best of any verb here — see §(b)'s fail-closed matrix update below for why it remains under the
  same authority floor as the other mutating verbs near-term, and §(c)'s policy-authorized tier
  note for the one place its reversibility may eventually matter.

### Cross-verb themes

- **Privilege escalation surface:** every verb needs a categorically new, write-capable privilege
  grant. None of S3-priv's existing `root_helper` capability grant (`cap_sys_ptrace,
  cap_dac_read_search`, read-only, seccomp-hardened) is reusable as-is — that grant was
  deliberately minimized for *reading* `/proc`; a containment helper would need a **wholly
  separate, independently-scoped, write-capable** privilege surface that does not exist today and
  is explicitly **not** designed by this document (only flagged as needing its own future
  doors-and-corners pass and review, per §(e)).
- **Execution architecture (operator-directed 2026-07-24; applies to `kill` and `revoke`, and
  shapes `block`):** any containment verb executes **only** through a **separate,
  capability-holding helper process**, mirroring the `root_helper` precedent's shape but as a
  distinct, write-capable grant (not a reuse of the read-only one, per the bullet above). The
  daemon/CLI itself **does not hold and cannot exercise** the containment capability directly — it
  can only construct a proposal and hand it to the helper. Each execution additionally requires
  explicit user consent that is **single-use** (a fresh nonce, consumed exactly once, never
  replayable) and **time-limited** (a short expiry after which the consent is void and must be
  re-minted) — this is a distinct, second nonce/expiry pair layered on top of, not a substitute
  for, the §(b) Option 3 approval-and-cooling-off nonce: the §(b) nonce authorizes the *decision*,
  this one authorizes the *single act of execution* the helper is about to perform. Are we
  reinventing sudo/SRP/a bespoke privilege tool? **No, by design intent:** the strong preference is
  to **lean on existing OS privilege and consent primitives** rather than invent a new
  privilege-escalation mechanism — concretely, `sudo`/`polkit` policy on Linux, and a privileged
  `launchd` helper reached over XPC with code-requirement (code-signing identity) checks on macOS,
  the same shape the platform already offers other privileged helpers. Descartes' own contribution
  sits **on top of** those primitives, not alongside or instead of them: the **policy** (which
  verb, which target, under which tier per §(c)), the **single-use consent ledger** (the
  nonce-per-execution mechanic above, distinct from any OS-level "remember this choice" caching),
  and the **audit** layer (§(c)'s write-ahead record). Where an existing OS primitive genuinely does
  not fit — e.g. neither `sudo`/`polkit` nor a signed XPC helper natively expresses "this specific
  consent nonce may authorize this specific mutating call exactly once and no more" — Descartes must
  add that single-use consent-ledger mechanic itself, since no OS primitive surveyed here provides
  it out of the box; this is the one piece of new mechanism this document considers justified, not
  a broader new privilege model.
- **Consent-ledger crash-consistency and binding (safety-review must-fix, folded 2026-07-24):** the
  single-use, time-limited execution-consent nonce introduced above needs the same discipline §(c)
  already mandates for the `containment.json` audit record, stated explicitly rather than left
  implicit, because it is a distinct artifact from that audit record and a future implementation
  must not conflate the two: (1) **write-ahead consume** — the consent nonce must be marked
  consumed/invalidated **synchronously before** the mutating call is issued, never after it returns,
  so that a crash between execution and consume cannot leave a still-valid, replayable nonce on
  daemon restart (this mirrors, but is separate from, §(c)'s write-ahead "execution in progress"
  record for the audit log — the audit record and the consent ledger must each independently satisfy
  write-ahead ordering, not share one write as if it covered both); and (2) **binding** — a consent
  nonce must be cryptographically or logically bound to one specific, already-approved §(b) decision
  record *and* to the freshly re-resolved target and verb at the moment of execution (per the TOCTOU
  re-resolution requirement below), so that a valid, unexpended nonce can never be replayed to
  execute a different verb, a different target, or execute at all without a matching approved
  decision. Without both properties the model has a theoretical replay-on-crash window and a
  misbinding window; a future implementation must close both before this execution model is built,
  not merely design the nonce as an opaque single-use token.
- **Self-lockout risk** is the dominant failure mode for block/revoke, **and, in its own
  irreversible-plus-self-inflicted form, for `kill` as well** — a self-lockout guard (refuse to
  act on the approving actor's own session/connection/parent-process chain) is a hard-stop
  precondition for **all three** of kill, block, and revoke, not a block/revoke-only concern
  (corrected 2026-07-23 per Stage 1 gate must-fix; see `kill`'s own subsection above).
  **Per-host self-lockout opt-out (RESOLVED by operator sign-off, 2026-08-11, §(d) item 4):** the
  self-lockout guard is necessary but the operator's answer to "is self-lockout ever tolerable" is
  host-dependent, not fleet-uniform — some hosts have physical/console fallback and can tolerate the
  residual risk, others are fully remote-administered with no fallback and cannot. Rather than pick
  one global answer, the containment capability itself gets a **per-host opt-out toggle**: on any
  host where self-lockout cannot be tolerated, the mutating containment capability (kill/revoke/
  block, and quarantine's network-isolation half) is **disabled outright** at the host-configuration
  level, independent of and in addition to the self-lockout guard's own runtime refusal — a second,
  static line of defense rather than relying on the runtime guard alone to always fire correctly.
- **Hack-back / legal boundary (operator sign-off, 2026-08-11):** every verb in this document acts
  on the monitored host's **own** processes, credentials, firewall, or containers — defending and,
  per the deception slice in §(e), deceiving on Descartes' **own** systems. Nothing in this document
  authorizes, and no future implementation may add, any action that reaches *beyond* the monitored
  host's own perimeter (e.g. probing, disrupting, or retaliating against a remote attacker's
  infrastructure). "Repel" in this codebase's vocabulary means defend-in-place, never hack-back —
  stated here explicitly because containment is the first surface in this codebase capable enough of
  mutating live infrastructure that the boundary needs saying out loud rather than assumed.
- **Rooted-host residual (safety-review finding, folded 2026-08-11):** every guarantee this document
  makes — the deterministic gate (§(c)), the capability-holding helper, capability-token
  verification, the write-ahead consent ledger, and the single-writer `containment.json` store — runs
  **on the monitored host itself**. A root-level compromise of that host bypasses all of them at once:
  a root attacker does not need Descartes' helper, does not need to forge a consent nonce, and does
  not need to steal or replay a capability token, because root can act directly, outside Descartes
  entirely. The helper/off-machine-key design defends against a **compromised daemon** or a
  **prompt-injected model** — an unprivileged process trying to self-authorize — it is not, and was
  never intended to be, a defense against a fully-rooted host.
  `docs/plans/2026-08-11-descartes-fleet-federated-topology.md` names this same limit honestly for
  the fleet case (the rooted-host-bypasses-the-fleet limit); this document states the equivalent
  single-host residual explicitly here so that "nothing on the monitored machine can self-authorize"
  (§(b)) is read as bounded by this threat model, not as an absolute guarantee against every possible
  host compromise.
- **Vault-Tec sandbox — mutating-verb validation harness (operator sign-off, 2026-08-11):** every
  mutating verb (kill/revoke/block/quarantine) must be exercised and reviewed inside the dedicated
  **Vault-Tec sandbox** described in §(e) before it is ever enabled against a real, monitored
  production host — see §(e)'s introductory note for the full model (dedicated sacrificial VMs,
  simulated suspicious behavior, honeypot side-benefit, and the no-local-VM constraint that puts
  these VMs on the operator's other hardware/CI rather than the dev machine).
- **Irreversibility** varies sharply by verb: kill has none; block/revoke are reversible if
  care is taken (reversal path proven up front); quarantine is reversible via
  pause/unpause **only** if the process's state survives the pause, which is not guaranteed.
  **`throttle` (added 2026-08-11, operator-suggested) is fully reversible and auto-reverting** —
  more reversible than block/revoke, which sever a channel outright and depend on a proven-up-front
  reversal path being exercised; `throttle` degrades rather than severs, ships with a mandatory
  bounded auto-expiry that restores prior state without any human action, and additionally supports
  an immediate one-touch manual revert. It is the most reversible verb in this document.
- **Race conditions (TOCTOU):** approval happens at one point in time; execution happens later.
  Every verb's execution primitive must re-verify target identity immediately before acting, never
  trust the identity captured at proposal/approval time alone.
- **Hash-at-source vs. raw-identifier provenance tension (reviewed 2026-07-23, folded from Stage 1
  gate must-fix, named but not resolved here):** the entire read-only monitoring layer (Slices 1/3)
  was deliberately designed so that raw session names, peer public keys, IPs, and PIDs are
  hashed/bucketed *at the point of collection* and never persist in raw form — this is a
  foundational privacy/provenance property of the monitoring plane, not an incidental detail. Every
  containment execution primitive in this document, by contrast, necessarily needs the **raw, live
  target identifier** — you cannot `kill` a hash, revoke a hashed peer key, or block a hashed IP.
  This document's "target re-resolution at execution time / never fuzzy-match" preconditions
  (§(a), above) gesture at needing a live target but never say the tension out loud: **the
  containment layer must re-derive the raw target from a live, independently-trusted source at
  execution time (e.g., a fresh, unhashed process/session/peer enumeration performed at the moment
  of execution), and must categorically NOT attempt to map a previously-stored hashed fact back to
  a raw identifier and act on that.** Doing the latter would both (a) be unsafe — a hash collision
  or stale mapping could resolve to the wrong live target, compounding the PID-reuse/session-target
  risks already listed above — and (b) silently reintroduce exactly the raw-identifier handling
  and raw-identifier persistence that the monitoring layers were deliberately designed to avoid,
  undermining that design decision through the back door of the containment plane. This document
  does not resolve how re-derivation is implemented (that is an implementation-time, not
  design-time, question, deferred to Slice 7.5+ (formerly 7.3+, renumbered 2026-08-11)) — it only
  requires that any future implementation
  state this constraint explicitly and never treat the hashed fact-history as an actionable
  target.

---

## (b) Authority model options for multi-party confirmation

This is the plan's own flagged hardest question (line 869/908 of the observed-incident plan): who
or what authorizes a containment action. Three options, with a recommendation.

### Option 1 — Second human operator (out-of-band, true two-person rule)

A containment action requires approval from a **different** operator identity than the one that
proposed it (e.g., two distinct configured operator identities, analogous to a real two-person
control).

- **Pros:** the strongest bar — approximates a genuine two-person rule; a single compromised
  account/session cannot unilaterally authorize containment.
- **Cons:** `promotion-store.js`'s own header comment states this codebase's authority model today
  is "single-user local CLI... not an attacker model." Descartes is explicitly single-host,
  and per `docs/HANDOFF.md`'s Open Question 1 in the observed-incident plan, single-operator by
  default. A mechanism that structurally requires a second human may be **unusable exactly when
  needed** (a live, single-operator incident), or pressure operators into building an insecure
  bypass to get around it — which would be worse than not having the mechanism. Requires new
  identity infrastructure (a second configured, independently-authenticated operator) that does
  not exist in this codebase today.
  **RESOLVED by operator sign-off (2026-08-11), §(d) item 3:** confirmed no second human operator
  exists or is planned; the operator has **many devices**, not a second person, so **multi-device is
  the path, not multi-human**. A future genuine multi-*operator* (n-of-x threshold) capability is not
  ruled out, but is explicitly deferred to be **built on top of** the Option 2b multi-device
  mechanism once it exists (a threshold over multiple operators' devices/tokens), rather than
  designed as its own, separate second-identity system now or built speculatively ahead of that
  need.

### Option 2 — Multi-device / out-of-band push approval

Approval must arrive over a channel distinct from the one that detected/proposed the incident
(e.g., a push notification to a second device, requiring the approver to act somewhere other than
the terminal that raised the alert). **Sharpened by operator sign-off (2026-08-11) into two
sub-options of different near-ness, per the operator's own framing — "no second human, but many
devices" — see "## Operator sign-off (2026-08-11)" below for the full response:**

**Option 2a — SSH-key relay between the operator's own machines, no central service (near/mid-term
design option, not yet built).** Deliver the approval request to *another of the operator's own
registered Descartes instances/devices* without standing up any central webservice — e.g. an
extremely limited, purpose-scoped SSH-key relay: the monitored instance pushes (or the second
instance polls for) a pending-decision record over an SSH channel already trusted between the
operator's own machines, scoped tightly enough that the relay itself grants no more than "deliver
this specific pending-decision record," never general remote access. The operator is explicit that
the exact mechanism is unresolved — this is captured as a **design option to work out**, not a
specified protocol. This still does not raise the authority bar past single-party (it is still the
same one operator deciding), but it does raise the bar over same-terminal approval in the same way
Option 2 always intended: an attacker who has compromised the monitored machine's local session does
not automatically also control the second device the approval now has to be actioned from.

**Option 2b — full multi-device push approval with a cryptographic capability token (later,
confirmed by operator sign-off 2026-08-11, needs a backend).** The original Option 2 as designed
below, now explicitly gated on standing up a backend for identity and push-notification delivery
(open-source is acceptable) plus a **cryptographically secure capability token** — candidate
primitives named by the operator: JWT, biscuits, or macaroons — chosen specifically so that
**nothing running on the (possibly-compromised) monitored machine can itself impersonate the
operator's authorization**. See "Transport vs. authority" and "Capability-token model" below for
why this property is the whole point of Option 2b and is not achievable by transport alone (Option
2a's SSH relay included). **Multi-operator (n-of-x threshold) is a later extension built *on top
of* this multi-device mechanism, per operator sign-off** — not a separate second-identity system;
see Option 1's update below.

- **Pros:** doesn't require a second *human* — raises the bar over a same-terminal approve, since
  an attacker who has compromised the local session doesn't automatically control the second
  channel too.
- **Cons:** this is genuinely **new external surface** — a second delivery channel, plausibly a
  new external service dependency, webhook, or API-key surface. That runs directly against this
  codebase's stated minimal-scope / no-new-execFile-or-privilege-surface ethos and would need its
  own dedicated security review before being designed in detail (not sketched further here, beyond
  the operator-directed elaboration above). It is also frequently *not* true multi-party in the
  adversarial sense — the "second channel" is often the same operator's own phone, i.e. multi-factor,
  not multi-party; the operator's own framing (2026-08-11) confirms this codebase's near-term
  reality is exactly that: multi-*device*, not multi-*party*.

### Option 3 — Time-delay / cooling-off window (no second party; explicitly weaker)

A containment proposal is recorded (nonce + expiry, exactly mirroring `promotion-store.js`'s
`mintPendingPromotion`/`decideConstraintPromotion` shape) and only becomes executable after a
mandatory minimum delay unless separately, deliberately re-confirmed. The delay is a "read this
again when calmer" safeguard and an audit/notification window, not a stand-in for a second party.
**RESOLVED by operator sign-off (2026-08-11):** the delivery mechanism for this mechanism's
pending-decision surface is a **local notification** on the monitored machine (e.g. a macOS
notification / platform-equivalent) — the human sees and acts on the pending decision where they
already are, not by polling a log file or CLI output. This is the concrete delivery mechanism for
both the recommend-only surface (§(e) Slice 7.1, the first buildable slice) and, once an execution
primitive exists, the approval-required decision surface (§(e) Slice 7.2's authority-store
scaffold).

- **Pros:** buildable **today** with zero new external infrastructure, purely on
  `promotion-store.js`'s already-shipped mechanics plus a delay field. Works for a genuinely
  single-operator deployment. Can be — and per the source plan's own caution, **must be** —
  honestly labeled as weaker than real multi-party confirmation, never dressed up as equivalent.
- **Cons:** does not provide real multi-party confirmation — a single compromised operator/session
  can still approve after the delay elapses. The delay is dead weight in exactly the scenario
  containment exists for (a fast-moving live incident), creating direct tension with the safety
  goal (see the emergency-bypass note below).

### Recommendation

A **tiered, honestly-labeled** approach, not a single mechanism. **Operator-confirmed 2026-07-24**
(see "## Operator direction (2026-07-24)" below for the full response) — the tiering itself is no
longer just this document's recommendation, it is the operator's explicit direction:

1. **Near-term, single mechanism actually being built: Option 3, delivered via local notification**
   — templated 1:1 on `promotion-store.js`'s nonce/expiry/deny-by-default/`audit_transitions`
   pattern, with a mandatory minimum delay, surfaced to the operator through a **local notification**
   on the monitored machine (operator sign-off, 2026-08-11 — see Option 3 above). Every surface that
   shows this to the operator (notification text, CLI output, audit record) must permanently and
   unambiguously label it "single-party, time-delayed — NOT multi-party confirmation." No language
   may imply a second party ever reviewed it. The operator has explicitly acknowledged this is weak
   against fast-moving threats (ransomware and similar) and accepts that weakness for now; see the
   "Fast-response tension → federated immune system" subsection of the Operator direction section
   below for the accepted future resolution.
1a. **Near/mid-term design option, not yet built: Option 2a, the SSH-key relay** — deliver the same
   Option 3 pending-decision record to another of the operator's own registered devices over a
   purpose-scoped SSH-key relay, without a central webservice (operator sign-off, 2026-08-11 — see
   Option 2a above). This is still single-party authority, moved to a second delivery surface — it
   raises the bar against a compromised monitored machine without requiring the backend Option 2b
   needs. Exact mechanism intentionally left open, to be worked out at design/implementation time.
2. **Option 1 (second human / two-person rule) — not for now.** Confirmed **out of scope near-term**
   by the operator, not merely deprioritized, and **superseded as the multi-party path** by
   multi-device (operator sign-off 2026-08-11: the operator has many devices, not a second human) —
   a future genuine multi-operator (n-of-x threshold) capability would be built *on top of*
   Option 2b's multi-device mechanism rather than as its own identity model. Do not build
   speculatively.
3. **Option 2b (full multi-device push, cryptographic capability token) — acceptable as a later
   improvement**, confirmed by the operator to require its own backend for identity and
   push-notification delivery, plus a cryptographically secure capability token (JWT / biscuits /
   macaroons — operator sign-off, 2026-08-11) before it is buildable at all. Still its own future
   workstream requiring a dedicated security review, and still not designed further here beyond the
   "Transport vs. authority" and "Capability-token model" subsections immediately below.

### Transport vs. authority (operator sign-off, 2026-08-11)

A distinction the options above blur together and must not: **transport** is *how the approval
request travels* (local notification, the Option 2a SSH relay, or Option 2b's push channel);
**authority** is *the proof that the human actually approved this specific verb on this specific
target* (the capability token). Conflating them is exactly how a compromised monitored machine could
end up minting its own "approval" — if the transport channel alone were trusted as authority, then
anything that can speak on that channel (including a compromised daemon) could forge consent.
Concretely:

- **Local notification (near-term):** transport and authority are effectively the same act today —
  the human interacting with the local notification *is* the approval, recorded by the Option 3
  nonce/expiry mechanism. This is acceptable **only** because the trust boundary is "the human is
  physically at the keyboard of the machine being protected," which is a materially weaker guarantee
  than what Option 2b is for, and must stay honestly labeled as such (per item 1 above).
- **Option 2a (SSH relay):** raises the transport bar (a second device) without yet raising the
  authority bar (still no cryptographic proof that the response actually originated from the
  operator's intent rather than, say, a compromised relay endpoint or a stolen SSH key). This is
  named as a known limitation of Option 2a, not silently glossed over.
- **Option 2b (push + capability token):** the design point where authority becomes genuinely
  independent of transport — see "Capability-token model" immediately below.

### Capability-token model and key custody (operator sign-off, 2026-08-11; orchestrator refinement)

For Option 2b to deliver on "nothing on the monitored machine can impersonate the operator's
authorization," the **signing key must never live on the monitored machine** — the monitored
instance is a relay and a verifier, never a minter, of authority:

- **Key custody:** the operator's approving **device** holds the private key. The monitored instance
  never sees, stores, or has access to it — it can only present a proposal (verb + target +
  rationale) over the transport channel and later verify a token that comes back.
- **Token minting:** on approval, the operator's device mints a **narrow, short-TTL, single-use**
  capability token bound to the specific decision the operator just approved — the exact verb and the
  exact target **as reported by the monitored instance in the proposal and eyeballed by the human in
  the approval prompt**. **Clarified (2026-08-11 sign-off safety review, safety finding):** the
  approving device cannot itself re-resolve the monitored host's live process/session/peer state — it
  has no channel to that state other than what the monitored instance already reported in the
  proposal — so device-side minting binds to the **human-approved** target, it does not itself
  re-verify that target is still live. The load-bearing re-resolution that closes the TOCTOU/replay
  window is the **execution-time, helper-side** one already required by §(a) Cross-verb themes ("a
  fresh, unhashed... enumeration performed at the moment of execution" / "freshly re-resolved target
  and verb at the moment of execution"): the helper re-resolves the live target immediately before
  acting and match-checks it against the token's binding, refusing to execute on any mismatch. Every
  other reference in this document to a token being bound to a "freshly re-resolved" target should be
  read as shorthand for this helper-side, execution-time check — not as a claim that the device-side
  mint itself re-resolves anything.
- **Why biscuits/macaroons fit:** both primitives support **offline attenuation only** — a holder can
  narrow (restrict) a token's scope without contacting the issuer again, but can never *widen* it.
  That property matches this design exactly: the monitored instance, the relay, and the helper
  process (§(a) Cross-verb themes) may each pass the token along or check its caveats, but none of
  them can mint a broader token than the operator's device actually issued. A plain JWT can serve the
  same near-term role (signed, short-TTL, single-use, verified against the device's public key) but
  does not offer the same offline-attenuation property if the token ever needs to be narrowed further
  downstream (e.g. by the capability-holding helper before the final mutating call) — biscuits/
  macaroons are the better long-term fit for exactly that reason, JWT is an acceptable interim choice
  if implementation urgency demands it.
- **The instance's role is relay-and-verify, never mint:** the monitored Descartes instance (and the
  capability-holding helper it hands the decision to, per §(a)) only ever **relays** the proposal out
  and **verifies-then-consumes** the token that comes back — write-ahead, per §(a)'s consent-ledger
  binding requirement, exactly as already mandated there. This is the same helper/capability
  separation §(a) already establishes for the execution-consent nonce, now explicitly extended to
  cover *where the token itself is minted*, not merely how it is consumed.

### Fail-closed action → mechanism matrix (operator sign-off, 2026-08-11)

The mapping from "which containment action" to "which authority mechanism" must be
**user-configurable**, because the right answer depends on the operator's own environment (per-host
self-lockout tolerance, §(a) Cross-verb themes; whether Option 2a/2b are even set up yet) — but it
must ship with **sensible, fail-closed defaults** so that an unconfigured or partially-configured
host never silently falls back to a weaker mechanism than intended:

| Action class | Default mechanism | Fail-closed rule |
|---|---|---|
| Unknown / unrecognized action | — | **Deny.** An action with no configured mechanism mapping is never permitted to fall through to a weaker default; it is refused outright. |
| Mechanism unavailable (e.g. Option 2b not yet configured) | — | **Deny**, not silent downgrade to a weaker configured mechanism (e.g. never silently fall back from Option 2b to Option 3/2a without the operator explicitly configuring that fallback — and, per the row below, no such fallback exists for mutating verbs regardless of configuration). |
| Recommend-only / deception (mutates nothing) | Local notification (Option 3), or the Option 2a relay once built | Lowest bar is acceptable — no mutation is possible regardless of who reads the notification, so no capability token is required. |
| **Mutating verb — `kill`, `block`, `revoke`, `quarantine` (network-isolation half), `throttle`** (**corrected 2026-08-11 sign-off safety review, must-fix; `throttle` added 2026-08-11, operator-suggested**) | **Option 2b only — an off-monitored-machine-minted capability token (§(b) "Capability-token model") is the authority floor for every mutating verb. No weaker fallback exists.** | **No token, no execution.** If no Option 2b-class, token-bearing channel is configured, the action is **DENIED outright** — it is never authorized via Option 3 (local notification) or Option 2a (SSH relay), because neither carries a cryptographic capability token: per "Transport vs. authority" above, Option 3's "transport and authority are effectively the same act" and Option 2a "does not raise the authority bar... no cryptographic proof" mean authority under either is on-machine and forgeable by a compromised daemon. This is deliberately **not** "the strongest available channel" — the previous "Option 2b if configured, else Option 2a, else Option 3" floor is retracted as unsafe. Option 3 and Option 2a may authorize **recommend-only/deception surfaces only**, never a mutating call, regardless of the verb's irreversibility or self-lockout risk. **`throttle` is included here because it mutates live cgroup/`pf`/`nft`/`tc`/`taskpolicy` state exactly as the other verbs mutate process/session/firewall/container state — its markedly better reversibility profile does NOT carve it an exception now.** Because `throttle` is reversible, non-destructive, and auto-reverting, a **future, separately-designed-and-reviewed** path may eventually grant it a lower authority tier (see §(c)'s policy-authorized tier note) — but until that future path exists and has cleared its own review, `throttle` remains fully under this same Option-2b-only floor, denied outright like every other mutating verb when no token-bearing channel is configured. |

This table is the **default** for non-mutating surfaces, and the operator may add stricter
requirements on top of it — but any override must be an explicit, auditable configuration act,
never an implicit consequence of a mechanism simply not being set up. **The mutating-verb row above
is not itself overridable to a weaker mechanism:** an operator cannot configure `kill`/`block`/
`revoke`/`quarantine` to execute via Option 3 or Option 2a alone, since doing so would reintroduce
the exact fail-closed contradiction this section's 2026-08-11 sign-off safety review corrected.

**Unresolved tension flagged, not resolved, by this recommendation:** a genuine fast-moving
incident may need a *faster* response than any cooling-off window allows, which is in direct
tension with the safety goal of slowing down an unauthorized/mistaken action. Whether — and how —
to allow an emergency bypass of the delay (and what would authorize skipping it) is left as
**Open scope decision 5** in §(d); this document deliberately does not pick a delay length or a
bypass mechanism. **Operator update 2026-07-24:** the operator has explicitly named this tension
(Option 3 is too slow for ransomware-class threats) and, rather than proposing a bypass of the
delay itself, has proposed a structurally different future direction that resolves the tension by
changing what "confirmation" means for pre-corroborated behaviors rather than shortening this
delay. See "Fast-response tension → federated immune system" in the Operator direction section
below. That direction is itself design-only, heavily governance-gated, and does not change the
Option 3 mechanism described above — it is a distinct future addition, not a replacement.

**`throttle` as the reversible holding action (added 2026-08-11, operator-suggested):** the
federated-immune-system direction above is a future, heavily governance-gated resolution to this
tension. `throttle` (§(a)'s new subsection) is a **nearer-term, partial** resolution available
today, and materially changes the shape of the tension rather than resolving it outright: instead
of choosing only between "wait out the full cooling-off window" and "bypass the window entirely,"
Descartes can **covertly throttle the suspect process/connection immediately** — buying time —
**while** the §(b) Option 3 approval-and-cooling-off decision plays out (or, later, while a
federated corroboration/response decision resolves), and **silently revert** if the pending
decision turns out to be a false alarm. This does not eliminate the tension — `throttle` only
degrades, it does not contain the way kill/block/revoke/quarantine do, so a sufficiently fast or
already-in-progress attack can still outrun a throttled response — but it makes the single-party,
time-delay authority model **materially safer** than it would be without it: the operator is not
helpless for the duration of the cooling-off window, they have a reversible, low-collateral action
available immediately, while the destructive/higher-certainty verbs remain gated behind the full
Option 3 delay (or an Option 2b token, per the fail-closed matrix below) exactly as before.

---

## (c) Composition with AGENTS.md's Policy/Authority Plane

`AGENTS.md` §"Policy / Authority Plane" (lines 80–90) defines five tiers — read-only,
recommend-only, approval-required, policy-authorized low-risk action, autonomous — and requires
every action to carry a full audit trail: proposed plan, approval source, command/tool call,
pre-state, result, post-state, rollback notes when possible.

**The authority plane is a deterministic code gate, never a model prompt/instruction (RESOLVED by
operator sign-off, 2026-08-11, §(d) item c).** `AGENTS.md` is context and instructions read by a
model — it **cannot enforce anything**, by construction: a document a model reads is, at best, a
strong bias on behavior, and a sufficiently confused, degraded, or adversarially-prompted model can
depart from anything stated in it. Enforcement requires a **deterministic validating process** —
code that runs independently of, and is not itself persuadable by, model output, and that refuses to
execute a mutating call unless a structurally valid, correctly-bound, unexpended capability token
(§(b)'s capability-token model) is presented. Concretely, this means: the model (the daemon's own
reasoning, or any agent operating through it) may only ever **propose** a containment action —
construct a candidate verb + target + rationale and hand it to the authority plane. It can never
itself execute one. The authority plane's gate — the nonce/expiry/deny-by-default mechanics in
`containment.json` (below), the capability-token verification, and the capability-holding helper
process (§(a) Cross-verb themes) that alone can issue the mutating call — is ordinary, deterministic
code, reviewed and tested like any other security-critical code path in this codebase, not a
behavior the model is merely asked nicely to respect. This principle applies uniformly across every
tier in the table below, and is the reason the federated reflex path's "consent-model degradation"
(named in the Operator direction section's governance checklist) is treated as a serious, unresolved
gap rather than an acceptable convenience — a reflex path with no human-minted token and no
deterministic gate checking one is, by this same principle, not yet a legitimate execution path.

**Tier mapping for containment:**

| Tier | Containment mapping |
|---|---|
| read-only | Already shipped: session-census, VPN/peer, provenance collectors (Slices 1/3/S3-S5). No change proposed here. |
| recommend-only | The **only** execution-adjacent tier this document considers safe to build in the near term: surface a proposed verb + target + rationale for a human to read and, if they choose, act on **manually and entirely outside Descartes**. Zero new `execFile`, zero new privilege. |
| approval-required | Where any real containment *execution*, if ever built, **must** live — the human-gated nonce/expiry/audit pattern from §(b) Option 3 (or 1/2 per the tiering above), with the approved decision then handed to the separate capability-holding helper (§(a) Cross-verb themes, operator-directed 2026-07-24) under its own single-use, time-limited consent nonce for the actual mutating call. No containment verb should skip this tier near-term. |
| policy-authorized | **Not recommended for any containment verb** in the foreseeable future, **with one named exception below.** `AGENTS.md` scopes this tier to "narrowly scoped, tested, reversible cases" — kill fails "reversible" outright; block/revoke fail "narrowly scoped" given self-lockout blast radius; quarantine's blast radius depends on a credential (`docker.sock`-class) that is itself not narrowly scoped. **`throttle` (added 2026-08-11, operator-suggested) is the one containment verb that could eventually qualify** for this tier — and, further out, conceivably the autonomous tier — because it is reversible, non-destructive, auto-reverting, and bounded (a fixed resource-degradation ceiling, a fixed expiry), a materially better fit for "narrowly scoped, tested, reversible" than any other verb here. This is named, not designed: `throttle` remains fully under §(b)'s Option-2b-only fail-closed floor near-term (see §(b)'s fail-closed matrix), and any move to policy-authorized requires its own, **separately-designed-and-reviewed** future path, not something assumed by naming it here. That future path — auto-throttle-on-suspicion, with the human-held capability token reserved for escalation to the destructive verbs (kill/block/revoke/quarantine) rather than for throttling itself — is what would actually resolve the §(b) fast-response tension structurally, rather than merely mitigating it the way the near-term "throttle as a reversible holding action" treatment does. It requires its own doors-and-corners pass, an S3-priv-or-stricter review (§(e)'s review bar), and all of the guardrails named in §(a)'s `throttle` subsection (the self-DoS guard, existing-state-awareness for the network mechanism, false-positive-collateral tightness) before it is anything more than a named future possibility. |
| autonomous | **Explicitly out of scope for the mechanisms in §(a)-(e) of this document.** Same reasoning as policy-authorized, stronger. **Exception, named not designed:** the federated immune system direction in the Operator direction section below proposes a distinct, heavily governance-gated future path to pre-consented reflex action on ratified/corroborated signatures with human notification rather than confirmation — that is a genuinely new tier-adjacent concept this table's five stock tiers don't cleanly capture, not a quiet reclassification of containment verbs into "autonomous" as `AGENTS.md` defines it today. It remains out of scope for any near-term build. |

**Write-ahead / crash-consistent audit ordering (reviewed 2026-07-23, folded from Stage 1 gate
must-fix):** the audit *fields* below are not sufficient on their own — the record's **write
order** relative to the irreversible act must be mandated explicitly, not left implicit. The
durable intent+approval record (nonce, target, verb, approval source) **must be persisted to
`authority/containment.json` before the execution primitive issues the actual mutating call**,
exactly the write-ahead discipline this codebase already had to learn the hard way: the
promotion-store's own "reconciled" orphan-status fix (`docs/HANDOFF.md` line 50) exists precisely
because a promotion could be recorded as decided without a guaranteed-consistent view of whether
the corresponding act actually completed, and the S13 "zero-leak write-ahead audit" follow-up
generalized that lesson. For containment this matters more than for promotion, because `kill` is
irreversible: if the daemon crashes or the process is killed *between* issuing the mutating call
and writing the post-state, the audit record must not silently read as "never attempted" or
silently read as "succeeded" — either false reading is unsafe. Concretely, any future execution
primitive must:
1. Write a durable "execution in progress" record (post-approval, pre-mutation) synchronously
   before the mutating syscall/subprocess is invoked.
2. Issue the mutating call.
3. Write the result/post-state record synchronously after the call returns (or after a bounded
   timeout/error is observed).
4. On daemon restart, **reconcile** any record left in "execution in progress" state — for `kill`
   specifically, re-check whether the target process/session is actually gone (never assume either
   outcome) and record an explicit `reconciled`/`unknown` status rather than leaving the record
   ambiguous; this is the same shape of reconciliation the promotion-store orphan-status fix already
   established for a lower-stakes case.
This ordering requirement must be templated into `containment.json`'s mechanics alongside the
nonce/expiry/`audit_transitions` fields inherited from `promotion-store.js` — "1:1 on
promotion-store.js" in the store-shape mandate below is not sufficient by itself, since
promotion-store's existing write-ahead behavior was itself retrofitted after the orphan-status bug,
not designed in from the start; the future implementation must carry that lesson forward
deliberately rather than rediscover it.

**Audit trail shape per verb** (proposed plan / approval source / command / pre-state / result /
post-state / rollback), mapped concretely rather than left abstract:

- **kill:** pre-state = a full process/session fact snapshot (reusing Slice 2's evidence-freeze
  mechanism verbatim, since it already exists and is read-only); result = execution
  outcome/exit status; post-state = confirmation the target is gone and no unintended sibling was
  affected; rollback = **honestly `none`** — this field must never be fabricated as "restart the
  process," which is not the same as undoing the kill.
- **revoke:** pre-state = the credential/peer's current config entry; post-state = confirmed
  removal; rollback = the concrete re-add command, proven to work before the removal path ships.
- **block:** pre-state = a diff against the current ruleset; post-state = confirmed rule
  installation; rollback = the concrete rule-removal command **plus** the mandatory auto-expiry as
  a second, independent failsafe (never rely on the manual rollback alone).
- **quarantine:** pre-state = running/network state; post-state = paused/isolated state; rollback
  = unpause/reconnect, contingent on the runtime actually preserving state across the pause
  (verify this per-runtime before relying on it). **Note (operator-directed 2026-07-24):** per
  §(a)'s quarantine subsection, if the fold-into-`{freeze + block}` recommendation is accepted this
  row collapses into `kill`-style freeze bookkeeping (pre/post-state = process run-state before and
  after `SIGSTOP`/cgroup-freeze, rollback = unfreeze) plus `block`'s row above for the network-isolation
  half, rather than needing its own distinct audit shape — this row is retained here only for the
  case where the operator's open question above resolves toward keeping quarantine as its own
  container-runtime-aware verb.

**Store shape (per the source plan's explicit mandate, line 867):** a **new, separate**
`authority/containment.json`, sibling to but never merged into `authority/promotions.json`
(`resolvePromotionStorePaths`'s exact pattern: `stateDir/authority/containment.json`), because
containment risk (killing/blocking on a live host) is categorically different from
artifact-promotion risk. Mechanics to template 1:1: 32-hex `crypto.randomBytes(16)` nonce, a
containment-specific expiry constant (analogous to `DEFAULT_PROMOTION_EXPIRY_MS`), deny-by-default
matching (`findValidPendingPromotion`'s exact shape), full `audit_transitions`, **the write-ahead /
crash-consistent ordering and restart-reconciliation requirement described immediately above** (not
merely the static field shape), and — critically — `constraint-store.js`'s **single-writer
discipline**: exactly one function in the entire codebase may ever flip a containment record toward
"executed," mirroring `promoteReviewReadyToActive` being the sole active-writer for constraints.

**Kill-switch:** any future containment authority-gate (even the inert §(e) Slice 7.3 (formerly 7.2,
renumbered 2026-08-11) scaffold)
must sit behind its **own**, dedicated, default-OFF switch — **not** `learned.json`'s existing
switch. `learned.json` gates passive monitoring; containment is a materially different risk class
and enabling monitoring must never implicitly enable any containment surface. This mirrors the
existing precedent (`daemon.js` lines ~68–80/341/422 gate the structural tick behind
`learned.json`, checked before any I/O) but requires a **separate** switch, checked independently.

**Precedent citation only, not wired here:** `index.js`'s `if (command === "learned")` dispatch
(line 133) is the only existing precedent for how a future `descartes authority ...` (or similar)
CLI verb would eventually be added — cited for shape, no case added by this document.

---

## (d) Open scope decisions — flagged for explicit operator sign-off before any implementation

None of the following are answered by this document. Each blocks a real implementation plan, not
merely its detail:

1. **Execution capability at all, or recommend-only forever? — RESOLVED by operator direction
   2026-07-24.** The operator has directed that real execution is wanted (not recommend-only
   forever), routed through the separate capability-holding helper with single-use, time-limited
   consent described in §(a)'s Cross-verb themes and reaffirmed in the Operator direction section
   below. **Sequencing confirmed by operator sign-off 2026-08-11 (§(d) item 6, BUILD):** §(e)'s
   phased build starts at Slice 7.1 (deception, mutates nothing) and Slice 7.2 (recommend-only via
   local notification, mutates nothing) before any execution primitive (Slice 7.5) — sequencing was
   never in question as to *whether* execution is ever wanted, only *when* in the build order it
   arrives, and that order is now settled.
2. **Which verbs are actually applicable to this operator's real environment? — RESOLVED by operator
   sign-off 2026-08-11.** All four verbs — `kill`, `revoke`, `block`, and `quarantine` — are
   confirmed in scope. The container question (item 8) is answered: the operator doesn't personally
   run containers, but Descartes has other users who do, so the full verb set is kept rather than
   narrowed to this operator's own deployment. See item 8 below for the quarantine-specific detail.
3. **Is a second human operator ever available? — RESOLVED by operator direction 2026-07-24,
   reaffirmed and sharpened by operator sign-off 2026-08-11.** No, not for now, and not framed as a
   gap to close — the operator has **many devices** instead, so the multi-party path this codebase
   pursues is **multi-device**, not multi-human. §(b) Option 1 (second human / two-person rule) is
   confirmed out of scope near-term, possible only in a later enterprise setting, with a future n-of-x
   multi-operator capability built *on top of* the multi-device mechanism rather than as its own
   identity system. §(b) Option 3 (time-delay, single-party, delivered via local notification) is
   confirmed as the near-term mechanism.
4. **Self-lockout tolerance. — RESOLVED by operator sign-off 2026-08-11.** Rather than one global
   answer, self-lockout tolerance is **host-dependent**: the containment capability (kill/revoke/
   block, and quarantine's network-isolation half) gets a **per-host opt-out toggle** — disabled
   outright, at the host-configuration level, on any host where self-lockout cannot be tolerated
   (fully remote-administered, no physical/console fallback), independent of and in addition to the
   runtime self-lockout guard already mandated in §(a). See §(a) Cross-verb themes.
5. **Emergency-bypass tension. — RESOLVED by operator sign-off 2026-08-11 (as a direction, not as a
   built mechanism).** The federated immune system direction is confirmed as the **intended answer**
   to this tension, not merely a possible future resolution — the operator has directed that Slice 7
   pursue it, now spun into its own dedicated plan,
   `docs/plans/2026-08-11-descartes-fleet-federated-topology.md` (§(e) Slice 7.8, item 9 below). It
   remains design-only and un-scheduled as a *build*; what's resolved here is that this, not a bypass
   of the §(b) Option 3 delay, is the accepted long-term direction.
6. **Build anything now, or park this document? — RESOLVED by operator sign-off 2026-08-11: BUILD.**
   The operator has directed a concrete phased sequence (§(e), fully updated below): recommend-only
   via local notification now (mutates nothing) → remote-device notification (via other registered
   Descartes instances over SSH, or a centralized backend + push) → the federated layer / comms /
   push backend → then "real teeth" (execution). This document is no longer parked pending further
   scope decisions — §(e)'s phased breakdown is the concrete next-actions list.
7. **Confirm this document's own scoping is sufficient. — RESOLVED by operator sign-off 2026-08-11:
   YES.** The operator has confirmed this document's scoping is sufficient to proceed; all nine items
   in this list are now resolved. This document should be treated as ready to drive the §(e) phased
   build, starting with Slice 7.1, rather than as an open draft awaiting further scope decisions.
8. **Quarantine fold-vs-keep — RESOLVED by operator sign-off 2026-08-11: KEEP.** The operator does
   not run containers on their own monitored host, but Descartes is not built for a single user —
   other operators of Descartes deployments do run containers, so `quarantine` is **kept** as its own
   verb with its own container-runtime-aware execution primitive (§(a)), rather than folded into
   `{freeze + block}`. The fold analysis in §(a) is retained as background reasoning for any future
   deployment that genuinely has no container workload and wants to reconsider.
9. **Federated immune system — RESOLVED by operator sign-off 2026-08-11, as a scoping decision, not
   as the full governance sign-off itself.** The operator has directed that the federated immune
   system direction be expanded into a "Descartes all the way down" fractal **fleet** vision and given
   its **own dedicated plan**, `docs/plans/2026-08-11-descartes-fleet-federated-topology.md`. Slice 7
   **references** that plan rather than absorbing its topology design (§(e) Slice 7.8). This resolves
   *where* the federated direction's design work happens, not the governance checklist itself — the
   full governance sign-off this item originally described (ratifying authority, corroboration
   threshold, fleet-level blast-radius controls, Sybil/ratifier-compromise controls, the reflex path's
   consent-model degradation, honest labeling, full audit) is carried forward as the gate the
   dedicated fleet-topology plan must clear before any part of the federated direction moves toward
   implementation — it is not lowered or waived by this resolution.

---

## (e) Phased, locally-testable-first slice breakdown for the eventual build

Presented as a design sketch for a **future** plan. **RESOLVED by operator sign-off (2026-08-11),
§(d) item 6: BUILD** — this phased breakdown is no longer only a design sketch awaiting a
build-or-park decision, it is the concrete next-actions sequence the operator has directed,
starting at Slice 7.1. The per-slice review-bar requirement below is unchanged by that resolution:
every slice from 7.2 onward must clear a dedicated `doors-and-corners` pass **and** an adversarial
review at least as strict as — arguably stricter than, since a root helper reads facts and a
containment action mutates live infrastructure and can kill real sessions — the S3-priv
`root_helper` review (`docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`: trust-boundary
analysis, minimal-capability-grant validation via an empirical/live-hardware check rather than
static reasoning alone, fail-closed/deny-by-default verification, race/TOCTOU analysis). A
mutating path deserves at least that bar, not less. **Overall phasing (operator sign-off,
2026-08-11):** recommend-only via local notification (mutates nothing) → remote-device notification
(via other registered Descartes instances over SSH, or a centralized backend + push) → the federated
layer / comms / push backend → then "real teeth" (execution) — the slice numbers below are ordered
to match.

**Vault-Tec sandbox — mutating-verb validation harness (operator sign-off, 2026-08-11).** Before any
mutating verb (Slice 7.5 onward — **corrected 2026-08-11 sign-off safety review**; Slices 7.3 and
7.4 are the authority-store scaffold and remote-device notification and are explicitly non-mutating,
so the first mutating slice is 7.5, matching the "Operator sign-off (2026-08-11)" section's own
"Run the mutating verbs (Slice 7.5 onward)" wording below) is ever enabled against a real, monitored
production host, it must
be built, exercised, and reviewed inside a dedicated, **otherwise-useless** validation VM — a
"Vault-Tec Vault" — where the operator simulates odd/suspicious behaviors the local Descartes
instance doesn't already know about and observes how the instance responds. This serves two purposes
at once: a safe dev/validation harness for containment (nothing of value is at risk if a mutating
verb misfires inside the Vault), and a natural **honeypot** (suspicious behavior aimed at the Vault
is itself signal worth capturing). **Naming convention:** each Vault instance is named after the
"Vault-Tec Vault" theme (e.g. `Vault 111`, `Vault 76`, ...), consistent across the fleet for easy
identification in logs/audit trails. **Constraint (per the existing "dev machine cannot run VMs"
finding — no `Virtualization.framework`):** Vaults cannot run on the primary dev machine; they run on
the operator's **other hardware** or **CI** (the `big-cabbage` host / `tart`-CI remotes already used
elsewhere in this codebase's build pipeline). This is a hard precondition for Slice 7.5 onward
(**corrected 2026-08-11 sign-off safety review** — the first mutating slice, not 7.3/7.4 which are
explicitly non-mutating), not an optional nicety — no mutating primitive is exercised against a real
host before it has been exercised against a Vault first.

- **Slice 7.0 — this document + operator resolution of §(d).** No code. Gate for everything below.
  **RESOLVED 2026-08-11: all nine §(d) items are now resolved** (items 1 and 3 by the 2026-07-24
  operator direction; items 2, 4, 5, 6, 7, 8, and 9 by the 2026-08-11 operator sign-off — see
  "## Operator sign-off (2026-08-11)" below). This slice's gate is cleared.
- **Slice 7.1 — deception / honey-tokens (NEW, operator sign-off 2026-08-11) — a distinct near-term
  slice BELOW containment, buildable independently and first:** the daemon gains the ability to
  plant and monitor **honey-tokens** — decoy credentials, decoy files, decoy listening services, or
  similar bait placed on the monitored host itself — and to alert when one is touched. This is
  explicitly **not** a containment verb: it needs **no authority plane** (nothing here is destructive
  or self-lockout-capable, so none of §(b)'s approval machinery applies). **Footprint, corrected
  2026-08-11 sign-off safety review (safety finding):** the earlier "mutates nothing about the host's
  real state" / "zero new privilege" framing was overbroad — planting bait is a real, additive
  footprint: new files (possibly in system locations), open listening sockets (possibly privileged
  `<1024` ports), and tamper-detection that may need elevated read access to observe another user's
  interaction with a decoy. Corrected framing: this slice **adds only inert, additive bait — no
  destructive or self-lockout-capable mutation** of the host's real state, and any privilege beyond
  what the read-only monitoring layer already has (e.g. to bind a privileged decoy port, or to read
  another user's access to a decoy file) must be scoped and justified per-decoy at implementation
  time, not assumed away. It is scoped to Descartes' own machine only, per the hack-back/legal
  boundary in §(a) Cross-verb themes — a honey-token is bait placed on Descartes' own systems, never
  an action directed at anything beyond that perimeter. Shippable ahead of, and independent from,
  every other slice below: it yields a clean, well-corroborated signal in its own right, and, as a
  side effect, a concrete "target" for later containment slices to test against. Locally testable
  end-to-end, zero new `execFile`. **Review, corrected 2026-08-11 sign-off safety review (safety
  finding):** this slice needs its **own explicit doors-and-corners pass**, scoped to the
  decoy-placement footprint above (file locations and permissions, listening-port privilege level,
  any elevated read needed for tamper-detection) — the SECURITY placement below containment (no
  authority plane, because nothing is destructive or self-lockout-capable) is correct and unchanged,
  but that placement previously omitted its own review requirement, unlike Slice 7.2 which already
  mandates one for itself.
- **Slice 7.2 — recommend-only surface, delivered via local notification** *(§(d) item 1 resolved —
  execution-adjacent work is wanted — but this slice is still the correct, lowest-risk starting point
  for containment specifically, and per operator sign-off 2026-08-11 is specified here precisely
  enough to implement next under the normal plan → TDD → doors-and-corners → review discipline)*:
  - **What it does:** the daemon/alert pipeline gains a new, purely additive signal that surfaces a
    proposed verb + target + rationale (e.g., `session.count_drop` → "consider
    investigating/killing session X") for a human to read and act on **manually and entirely outside
    Descartes** — Descartes never executes anything itself in this slice.
  - **Delivery (operator sign-off, 2026-08-11):** the recommendation is delivered as a **local
    notification** on the monitored machine (e.g. a macOS notification / platform-equivalent),
    consistent with §(b) Option 3's confirmed near-term delivery mechanism — not merely written to a
    log file or CLI output the operator has to think to check.
  - **Content:** verb, target (using the same freshly-resolved, non-hashed identifier discipline
    already required for execution primitives per §(a)'s hash-at-source-vs-raw-identifier
    provenance tension, even though this slice never acts on it), rationale/triggering signal, and an
    explicit, unmissable label that this is **recommend-only — Descartes will not act on this**,
    mirroring the honesty-labeling discipline §(b) already mandates for Option 3.
  - **Guarantees:** zero new `execFile`, zero new privilege, zero host mutation. Locally testable
    end-to-end.
  - **Review:** still needs its own doors-and-corners pass and review — a wrongly-targeted
    recommendation is itself a harm vector (misdirected operator trust), even with no execution
    capability behind it.
- **Slice 7.3 — authority-store scaffold, no execution primitive:** `containment.json` +
  nonce/expiry/deny-by-default mint+approve/reject CLI, templated 1:1 on `promotion-store.js`
  (§(c)), where "approve" records a decision and **executes nothing** — no execution primitive
  exists yet. Proves out the authority-gate mechanics, and the §(c) deterministic-code-gate
  principle, entirely in isolation from any privilege surface. Also the natural home for the §(b)
  capability-token verification logic (structurally validating a presented token even though nothing
  yet consumes one to execute). Locally testable, zero new `execFile`, zero new privilege.
- **Slice 7.4 — remote-device notification (operator sign-off, 2026-08-11; second phasing step):**
  extends Slice 7.2's local-notification surface off the monitored device, via **either** of the two
  §(b) Option 2 sub-options — Option 2a (a purpose-scoped SSH-key relay to another of the operator's
  own registered Descartes instances, no central service) or the beginnings of Option 2b (a
  centralized backend + push) — whichever the operator's real environment and the exact-mechanism
  design work (still open per §(b) Option 2a) makes buildable first. Still **mutates nothing** and
  needs no execution primitive; it is a transport extension of the recommend-only/approval-surface
  notification, not a new authority tier. Its own doors-and-corners pass is still required — a new
  cross-device transport (SSH relay or a push backend) is new external surface even though it
  authorizes no mutation by itself, per §(b)'s own caution about Option 2's security-review needs.
  **Note (corrected 2026-08-11 sign-off safety review, must-fix):** building this slice via Option 2a
  alone does **not** unlock Slice 7.5's execution primitive. Per §(b)'s fail-closed action→mechanism
  matrix, only an Option 2b-class capability-token channel authorizes a mutating call; a host with
  Option 2a (or Option 3) configured but not Option 2b remains **execution-DENIED** — Slice 7.4 is a
  notification-transport improvement, not an authority-tier upgrade.
- **Slice 7.5 — first real execution primitive, single most-reversible verb first** (**strongest
  candidate, added 2026-08-11, operator-suggested: `throttle`** — of a single suspect process's or
  connection's CPU/disk/network resources, per §(a)'s new `throttle` subsection — with `revoke` of
  a single VPN peer or `block` via an isolated firewall anchor as the prior candidates, whichever
  the operator's real environment supports per §(d) item 2): `throttle` is a **safer** first
  execution primitive than block/revoke precisely because it is non-destructive and auto-reverting
  rather than merely "reversible if care is taken" — a misfire degrades rather than severs, and
  self-corrects on its own bounded expiry even if the manual revert path is never exercised. This
  slice is otherwise unchanged by that choice: a scoped, allowlisted, single-purpose
  execution primitive, wired **only** behind Slice 7.3's authority gate, and, per the
  operator-directed execution architecture in §(a)'s Cross-verb themes, wired through the separate
  capability-holding helper (never invoked directly by the daemon/CLI) under a single-use,
  time-limited consent nonce that is itself derived from a verified §(b) capability token — leaning
  on `sudo`/`polkit` (Linux) or a privileged `launchd` helper + XPC + code-requirement checks (macOS)
  rather than a bespoke privilege mechanism — with a self-lockout guard (honoring the per-host
  opt-out from §(a)/§(d) item 4) — **or, if `throttle` is the verb chosen, the self-DoS guard from
  §(a)'s `throttle` subsection in its place** — a dry-run mode, an auto-revert/expiry, and full
  pre/post-state capture per §(c)'s audit shape. **Hard precondition: exercised in the Vault-Tec
  sandbox (above) before ever pointed at a real host** — no exception for `throttle` despite its
  reversibility. **Hard precondition (corrected 2026-08-11 sign-off safety
  review, must-fix): this primitive must refuse to execute — the deterministic gate (§(c)) denies by
  construction — on any host where only Option 3 and/or Option 2a are configured.** An Option
  2b-class, off-machine-minted capability token (§(b)) is the non-negotiable authority floor per the
  fail-closed matrix; Slice 7.4's Option 2a relay, even once built, does not by itself supply one.
  **This floor applies to `throttle` exactly as to every other mutating verb** (§(b)'s fail-closed
  matrix) — its superior reversibility does not exempt it from Slice 7.5's authority gate, even
  though that same reversibility is precisely why it is recommended as the first candidate: it
  bounds the consequences of a rare authority-gate or targeting failure far more tightly than
  `revoke`/`block` would. This is the first slice that introduces new
  `execFile`/privilege surface and is therefore the first slice that needs the full
  S3-priv-or-stricter review bar: trust-boundary analysis, minimal privilege grant (empirically
  validated, not just reasoned about, inside the Vault), fail-closed verification, TOCTOU/race
  analysis, a dedicated self-lockout test (or self-DoS test, if `throttle`), and a proven rollback
  test — now additionally including a
  dedicated review of the helper boundary itself (does the daemon/CLI genuinely hold zero capability,
  is the consent nonce genuinely single-use and unforgeable, is the capability token's signing key
  genuinely absent from the monitored machine per §(b)'s key-custody model).
- **Slice 7.6 — `kill`, if ever built at all:** given `kill`'s irreversibility (§(a)), this should
  be the **last** verb attempted, only after 7.5's authority+execution pattern has been live,
  audited, and uneventful for a meaningful period on a genuinely reversible verb first. Routed
  through the same helper + single-use-consent model as 7.5, per §(a), and, per the Vault-Tec
  requirement above, proven in the Vault first — `kill`'s zero-rollback property makes Vault
  rehearsal non-negotiable, not merely prudent.
- **Slice 7.7 — `quarantine`** (RESOLVED by operator sign-off 2026-08-11, §(d) items 2/8: **kept** as
  its own verb): a container-runtime-aware execution primitive (Docker/Podman/containerd
  pause/network-disconnect/cgroup-freeze), its own scoped credential (never a raw `docker.sock`-class
  handle on the general daemon process, per §(a)), routed through the same helper + single-use-consent
  model as 7.5/7.6, exercised in the Vault-Tec sandbox first, and its own dedicated review. The
  `{freeze + block}` composition analyzed in §(a) remains available as a fallback design for any
  future deployment that genuinely has no container workload, but is not the default path.
- **Slice 7.8 — federated immune system, design-only follow-on, not scheduled** *(governance
  checklist expanded by safety review 2026-07-24; scoped into its own dedicated plan by operator
  sign-off 2026-08-11; gated on §(d) item 9)*: **RESOLVED by operator sign-off 2026-08-11 as to
  where this work happens** — the correct next step, when the operator chooses to pursue it, is the
  already-created dedicated plan
  `docs/plans/2026-08-11-descartes-fleet-federated-topology.md`, which expands this direction into a
  "Descartes all the way down" fractal **fleet** topology vision. This document **references** that
  plan rather than absorbing its design — it is not an extension of Slices 7.1–7.7's work, and it is
  not implied to follow sequentially from 7.7. The full governance model that dedicated plan must
  work out before any code is contemplated is unchanged by the spin-out: ratifying authority,
  corroboration threshold, **both node-local and fleet-level blast-radius caps** (staged/canary
  propagation; a fleet-wide circuit-breaker and signature recall/revocation, not merely a per-node
  kill-switch; Sybil-resistance and ratifier-compromise controls — node-local caps alone do not
  bound the fleet-global catastrophic outcome this direction names, per the 2026-07-24 safety
  review), notification-vs-confirmation labeling, audit/post-hoc review, **and an explicit
  resolution of the reflex path's consent-model degradation** (what replaces the human-minted,
  per-execution consent nonce when the reflex path has no human in the loop, and why a compromised
  daemon cannot self-authorize by "recognizing" a signature). Per §(d) item 9, this remains gated on
  its own explicit operator sign-off on that full governance model before even the dedicated plan's
  design-only content moves toward implementation.

Every slice 7.3 and later (the authority-store scaffold onward) is additionally gated behind the
**dedicated, default-OFF containment kill-switch** from §(c) — never `learned.json`'s existing
switch — checked before any I/O, exactly mirroring the discipline `daemon.js` already applies to the
structural tick. Slices 7.1 (deception) and 7.2/7.4 (notification surfaces) mutate nothing and are
not gated behind this switch, consistent with them needing no authority plane per their own
descriptions above.

---

## Summary for the operator

The hardest problem — multi-party confirmation — has no clean answer today: this codebase's
single-operator reality makes a true second-human rule (§(b) Option 1) aspirational rather than
buildable now, a genuine second channel (§(b) Option 2) would be new external surface needing its
own review, and the only mechanism buildable today without new infrastructure (§(b) Option 3, a
time-delayed single-party approval templated on `promotion-store.js`) must be permanently and
honestly labeled as weaker than real multi-party confirmation. Every containment verb carries
irreversibility (`kill`) or self-lockout (`block`/`revoke`) risk that this codebase has not taken
on anywhere else.

**Updated 2026-07-24:** the operator has directed this document's §(b) tiering (Option 3 near-term,
Option 1 not for now/enterprise-later, Option 2 later-with-backend) and confirmed real execution is
wanted, routed only through a separate capability-holding helper under single-use, time-limited
consent, leaning on existing OS privilege primitives (`sudo`/`polkit`, macOS `launchd`+XPC) rather
than a new one. `block` now must read existing firewall state before acting; `quarantine` is now
defined ("contain without destroying, to preserve forensic state") and recommended folded into
`{freeze + block}` pending one open question back to the operator (do they run containers they'd
want isolated?). The operator has also named the resulting tension — this near-term model is
honestly too slow for fast-moving threats like ransomware — and proposed a future, heavily
governance-gated **federated immune system** direction as its resolution; that direction is
captured design-only in the new "Operator direction (2026-07-24)" section below and requires its
own separate operator sign-off (§(d) item 9) before it becomes anything more than a captured idea.
Nothing should be built from this document until the operator has answered §(d)'s nine open scope
decisions (seven original, two added 2026-07-24) — in particular items 2/8 (the container
question), 4 (self-lockout tolerance), and 6 (build-now-or-park).

**Safety review (2026-07-24), folded:** GO_WITH_CHANGES. The federated immune system direction's
governance checklist (§(e) Slice 7.8 — formerly 7.6, renumbered 2026-08-11 — §(d) item 9) now
explicitly requires fleet-level controls — staged/canary propagation, a fleet-wide circuit-breaker
and signature recall/revocation, and Sybil-resistance/ratifier-compromise controls — in addition to
the node-local caps already named, because node-local caps alone do not bound the fleet-global
catastrophic outcome that section itself names. The reflex path's consent-model degradation (no
human-minted, per-execution consent nonce when execution follows local signature recognition) is now
named explicitly, with a required analysis item added to the 7.8 (formerly 7.6) checklist. §(a)
Cross-verb themes now specifies the execution-consent nonce's own write-ahead-consume ordering and
its binding to a specific approved §(b) decision plus the freshly re-resolved target+verb, closing a
theoretical replay-on-crash and misbinding window. None of this changes what may be built now — it
sharpens the bar the not-yet-authorized federated direction (§(d) item 9) must clear, and adds detail
to the already-mandated §(a)/§(c) execution mechanics. This document remains DESIGN-ONLY.

**Updated 2026-08-11 — operator sign-off, all nine §(d) items now RESOLVED:** the operator has
signed off on the full remaining scope. All four verbs (kill/revoke/block/quarantine) are confirmed,
and **`quarantine` is kept** as its own verb rather than folded — the operator doesn't personally run
containers, but other Descartes deployments do. §(b)'s authority model now leads with Option 3
delivered via **local notification** as the near-term mechanism, adds a no-central-service
**SSH-key-relay** design option (Option 2a) for delivering approval requests to another of the
operator's own devices, and — per orchestrator refinement — formally separates **transport** (how a
request travels: local notification, SSH relay, or push) from **authority** (the proof of approval: a
short-TTL, single-use, biscuit/macaroon-style capability token whose signing key lives only on the
operator's own approving device, never on the monitored machine). A fail-closed action→mechanism
matrix is added: unknown actions and unavailable mechanisms deny by default, and irreversible
(`kill`) or self-lockout-capable (`block`/`revoke`/`quarantine`) verbs always demand the strongest
configured channel. §(c) is hardened to state plainly that `AGENTS.md` cannot itself enforce
anything — it is instructions a model reads, not a validating process — so the authority plane must
be a **deterministic code gate**; the model may only *propose* a containment action, never execute
one. The phased build in §(e) is renumbered and expanded around the operator's exact sequencing:
recommend-only via local notification (now Slice 7.2, the first buildable slice, specified precisely)
→ remote-device notification (new Slice 7.4) → the federated layer (Slice 7.8, spun into its own
dedicated plan) → execution (Slices 7.5–7.7). A new **deception/honey-tokens** slice (7.1) is added
below containment — mutates nothing, needs no authority plane, and is buildable first of all. A
**Vault-Tec sandbox** validation harness is added: every mutating verb must be exercised inside
dedicated, otherwise-useless "Vault-Tec Vault"-themed VMs (on the operator's other hardware/CI —
`big-cabbage`/`tart` — since the primary dev machine cannot run VMs) before ever touching a real
host, doubling as a honeypot. A **per-host self-lockout opt-out** toggle is added (§(a)/§(d) item 4):
hosts that cannot tolerate self-lockout disable the mutating containment capability outright, as a
second line of defense alongside the runtime self-lockout guard. A **hack-back/legal boundary** is
stated explicitly: every verb, and the new deception slice, act only on Descartes' own monitored
host — nothing in this document authorizes reaching beyond that perimeter. Finally, the federated
immune system direction is expanded into a **"Descartes all the way down" fractal fleet vision** and
spun out into its own dedicated plan, `docs/plans/2026-08-11-descartes-fleet-federated-topology.md`
— Slice 7 now **references** that plan rather than absorbing its topology design; the full governance
checklist captured in the "Operator direction (2026-07-24)" section below is carried forward as the
bar that dedicated plan must clear, unchanged and unlowered. This document remains DESIGN-ONLY — no
code changed as part of folding this sign-off in. See "## Operator sign-off (2026-08-11)" below for
the full, itemized response this summary condenses.

**Slice 7 sign-off safety review (2026-08-11), folded:** GO_WITH_CHANGES. The fail-closed
action→mechanism matrix's "else Option 2a, else Option 3" floor let a mutating verb be authorized
with no off-machine capability token, contradicting §(c)'s deterministic-gate guarantee, §(b)'s own
key-custody guarantee, and Slice 7.5's own "derived from a verified §(b) capability token"
requirement — the matrix now states plainly that every mutating verb requires an Option 2b-class
capability token as the authority floor, denied outright (never downgraded to Option 3 or Option
2a) when no token-bearing channel is configured, and §(e)'s Slice 7.4→7.5 phasing now states this
precondition explicitly so execution cannot be reached on an Option-2a-only host. Four safety
findings also folded: §(b)'s "Token minting" language is clarified so device-side minting is read as
binding to the human-approved target, not as itself re-resolving a live target (the load-bearing
re-resolution remains the execution-time, helper-side one §(a) already specifies); the Vault-Tec
sandbox's precondition text is corrected from "Slice 7.3 onward" to "Slice 7.5 onward" to match the
actual first mutating slice; a rooted-host residual is now stated explicitly in §(a) Cross-verb
themes (a root-level host compromise bypasses every mechanism in this document; the helper/
off-machine-key design defends the compromised-daemon/prompt-injected-model threat, not a rooted
host); and Slice 7.1's deception framing is tightened from "mutates nothing / zero new privilege" to
"adds only inert, additive bait — no destructive or self-lockout-capable mutation," with its own
explicit doors-and-corners pass now required. This document remains DESIGN-ONLY — no code changed
as part of folding this review in.

---

## Operator direction (2026-07-24)

This section records the operator's direct response to §(b)'s authority-model options and §(a)'s
per-verb execution questions, and captures one new future design direction the operator proposed.
It is folded inline throughout §(a)–(e) above (see the "operator-directed 2026-07-24" /
"operator-directed" callouts and the header's "Operator direction folded" line); this section is
the single authoritative statement of that direction, for reference, and does not introduce
anything not also reflected inline. **This section, like the rest of the document, is DESIGN-ONLY —
it directs what a future design should look like, it does not itself constitute or authorize any
code.**

### Authority model (§(b))

- **Option 1 (second human operator / two-person rule): not for now.** Confirmed out of scope for
  the near term. Possible in a later **enterprise** setting, where a real multi-operator identity
  model would exist to support it — not something to build speculatively ahead of that need.
- **Option 2 (multi-device / out-of-band push approval): acceptable as a later improvement.**
  Confirmed as a legitimate future direction, but explicitly gated on standing up **a backend for
  identity and push notifications** first — this is new external infrastructure this codebase does
  not have today, consistent with §(b)'s original caution that Option 2 needs its own dedicated
  security review before being designed in detail.
- **Option 3 (time-delay / cooling-off, single-party, explicitly weaker): the near-term mechanism.**
  Confirmed as the only mechanism actually being pursued right now — nothing more is feasible yet.
  The operator explicitly acknowledges this is **weak for fast-moving threats** (ransomware and
  similar classes of incident that outrun a cooling-off window), and accepts that weakness for now,
  to be addressed later via the federated direction below rather than by weakening Option 3's own
  honesty-labeling requirement.
- **The tiered, honestly-labeled approach as a whole: confirmed.** §(b)'s recommendation of treating
  these as tiers rather than picking one mechanism forever is itself operator-confirmed, not just
  this document's suggestion.

### Execution architecture (applies to kill + revoke, and shapes block)

Any containment verb executes **only** through a **separate capability-holding helper**, mirroring
the `root_helper` precedent's shape (S3-priv's read-only, seccomp-hardened grant) but as its own,
independently-scoped, write-capable grant — never a reuse of the read-only one. The helper **holds**
the capability; the daemon/CLI **does not and cannot** perform the action on its own. Each execution
additionally requires explicit user consent that is **single-use** and **time-limited** (a nonce
plus a short expiry) — distinct from, and layered on top of, the §(b) Option 3 approval nonce: one
nonce authorizes the *decision* (after the cooling-off window), the other authorizes the single act
of *execution* the helper is about to perform.

**Are we reinventing sudo / SRP / a dedicated privilege tool?** No, by explicit direction: the
strong preference is to **lean on existing OS privilege and consent primitives** — `sudo`/`polkit`
policy on Linux, and a privileged `launchd` helper reached over XPC with code-requirement
(code-signing identity) checks on macOS — rather than invent a new privilege-escalation mechanism.
Descartes contributes the **policy** (which verb, which target, which tier), the **single-use
consent-ledger** (the per-execution nonce mechanic above), and the **audit** layer (§(c)'s
write-ahead record) **on top of** those OS primitives, not a new privilege path alongside or instead
of them. The one place an existing primitive genuinely does not fit: neither `sudo`/`polkit` nor a
signed XPC helper natively expresses "this specific consent nonce authorizes this specific mutating
call exactly once, never again" — that single-use consent-ledger mechanic is the one piece of new
mechanism this direction adds, deliberately kept as narrow as possible.

### Per-verb direction

- **kill / revoke:** execute via the helper + single-use, time-limited consent model above. The
  write-ahead, crash-consistent audit ordering and the self-lockout guard already in §(a)/§(c) of
  this document stand as-is — this direction adds the execution-routing requirement on top of them,
  it does not relax either.
- **block:** Descartes must be **aware of existing firewall rules** — it must **read current state**
  (`pf`/`nft`/`iptables`, whichever the host runs) before acting, and must **never blind-append** a
  rule. It must detect conflicts and duplicates against both its own prior rules and the operator's
  pre-existing configuration. On rollback, it must roll back **only what it added**, never a
  broader revert.
- **quarantine:** the operator asked what this verb even means. Definition: **"contain without
  destroying, to preserve forensic state"** — freeze the process (`SIGSTOP` / cgroup freezer /
  `docker pause`) and/or network-isolate it (an isolated network namespace, or a deny-all rule
  scoped to its cgroup), as opposed to `kill`, which loses evidence. This is flagged as the
  **weakest-defined verb** in the document. Recommendation: fold it into a composition of
  **`{freeze + block}`** rather than standing it up as a fifth, independent verb with its own
  execution primitive — **unless** the operator actually runs containers on the monitored host that
  they would want isolated via a container-runtime-specific route (`docker pause`/network
  disconnect), in which case a distinct container-aware quarantine primitive may be worth keeping.
  This is recorded as an **open question for the operator** (also §(d) item 8), not resolved here.

### Fast-response tension → federated immune system (future direction, design-only, heavily governance-gated)

The operator named a real tension directly: Option 3's cooling-off window is honestly too slow for a
fast-moving threat (ransomware and similar). Rather than weakening Option 3's honesty-labeling or
adding an ad hoc emergency bypass, the operator proposed a structurally different future resolution:

- **The mechanism:** agents document behaviours and "signatures" and upload them to a **shared
  federated layer**. A signature that is either **ratified by some authority** or **independently
  corroborated by other agents** becomes a "rule" that **authorizes running its associated action as
  soon as the behaviour/signature is recognized locally** — with human **notification** (information
  after the fact), **not** human confirmation before the fact. This is a real, named escalation of
  autonomy relative to everything else in this document, and must always be labeled as such, never
  softened in language.
- **The trade-off the operator explicitly accepts:** "you lose a few nodes, but the vast majority
  won't be affected" — a herd-immunity framing, where fast local reflex action on a
  well-corroborated signature protects the fleet even though a rollout of a bad or malicious
  signature could still cost some individual nodes before it's caught.
- **Where this sits in Descartes' existing architecture:** this is the **terminus** of Descartes'
  already-documented Learn → compile-down → L3 Federated Knowledge arc (`AGENTS.md`'s L3 Federated
  Knowledge Layer, and Operational Lifecycle stage 7, "Learn — compile confirmed findings back into
  cheaper rules, signatures, tests, and tools"). That arc today is scoped to making **detection**
  cheaper (rules/signatures instead of repeated deliberation); this direction extends the same arc
  one step further, to **authorizing pre-consented reflex actions** on a signature once it's
  recognized, not merely cheaper detection of it. It is a natural extension of an arc this codebase
  already committed to, not a disconnected new idea — but it is a materially larger step than
  anything L3 currently does, and must be treated as such.
- **Governance is the entire safety burden here**, not a detail to fill in later. Required controls,
  enumerated (none of these are designed in detail by this document — they are the checklist any
  future design-only follow-on plan — now `docs/plans/2026-08-11-descartes-fleet-federated-topology.md`
  per operator sign-off 2026-08-11, referenced at §(e) Slice 7.8 (formerly 7.6) — must work through
  before this direction is anything more than a captured idea):
  - **Ratifying authority + corroboration threshold:** who or what authority can ratify a signature
    outright, and, separately, how many independently-corroborating agents/nodes are required before
    an unratified signature is trusted enough to become an action-authorizing rule.
  - **Per-node blast-radius caps (necessary, not sufficient — see "Fleet-level controls" below):**
    reversible-first actions only (never `kill`-class irreversible actions via this path without a
    materially higher bar than anything else in this document); scope strictly limited to exactly
    the recognized signature (no generalization at execution time); rate-limited; and a **per-node
    kill-switch** that can unilaterally halt this class of action on a single node regardless of
    federation state. **Safety-review note (2026-07-24):** these caps bound the *node-local* blast
    radius only. They do **not**, by themselves, bound the *fleet-global* catastrophic outcome this
    section names below ("infrastructure for a catastrophic automated global outcome") — a poisoned
    or maliciously-ratified signature that clears the corroboration threshold still propagates to
    every node that recognizes it, and each node firing its own capped, reversible, rate-limited
    local action is exactly how the fleet-wide event happens. The line between "you lose a few
    nodes" and "all nodes at once" is drawn entirely by how broadly a signature matches, not by
    anything in this per-node checklist — that scope-limiting property is therefore load-bearing and
    must be treated and reviewed as such, not as an incidental detail.
  - **Fleet-level controls (required, safety-review must-fix, added 2026-07-24 — without these,
    per-node caps alone do not bound the catastrophic risk this section itself names):**
    - **Staged/canary propagation:** a newly ratified-or-corroborated signature authorizes action on
      only a small, bounded fraction of nodes first, with a mandatory observation window before any
      propagation beyond that canary set — never an immediate fleet-wide rollout on first
      recognition.
    - **Fleet-wide circuit-breaker and signature recall/revocation:** a mechanism that can halt an
      in-flight rollout of a given signature **across the whole fleet**, not merely on one node — the
      per-node kill-switch above stops one node from acting again; it does nothing to stop every
      other node already mid-rollout on the same bad signature. Revocation must reach nodes that
      have already received the signature but not yet acted, and must be distinguishable from, and
      take priority over, the signature's own ratification/corroboration state.
    - **Sybil-resistance and ratifier-compromise controls:** "independently corroborated by other
      agents" and "ratified by some authority" are, as written, both assumed-honest and unsecured —
      neither corroborating-node authentication (so an attacker cannot manufacture the appearance of
      independent corroboration by standing up sock-puppet nodes/agents) nor ratifier
      key-management, cryptographic signature integrity, and ratification-revocation (so a
      compromised or coerced ratifying key cannot mint a trusted rule, and a bad ratification can
      itself be revoked) are designed here. Both must exist before this direction authorizes a
      single reflex action — the entire mechanism is only as trustworthy as the corroboration/
      ratification it executes off of.
  - **Consent-model degradation (safety-review must-fix, named 2026-07-24):** everywhere else in
    this document, execution requires a fresh, per-execution, human-minted consent nonce (§(a)
    Cross-verb themes) precisely so that a compromised or prompt-injected daemon cannot self-authorize
    a mutating action — the daemon proposes, it never holds or exercises the capability itself. The
    federated reflex path breaks this: it executes on **local signature recognition**, with
    notification rather than confirmation, meaning there is **no human in the loop to mint an
    execution-consent nonce at the moment of execution**. This document did not previously state what
    replaces that guarantee. Naming it plainly, consistent with how this document already names
    comparable tensions elsewhere (the hash-at-source-vs-raw-identifier tension and the self-lockout
    risk, both in §(a)): **on the reflex path, the helper/capability separation degrades to trusting
    the daemon's own signature-recognition code** — exactly the compromised-daemon threat model the
    helper boundary exists to contain on every other path this document describes. **Required
    analysis for §(e) Slice 7.8 (formerly 7.6), not answered here:** what unforgeable authority mints
    or stands in
    for the execution-consent nonce when no human is present, and what specifically prevents a
    compromised daemon from "recognizing" a signature it was never legitimately shown, in order to
    self-authorize action.
  - **Honest labeling:** every surface must say, unambiguously, that this is **notification, not
    confirmation** — a real escalation of autonomy beyond everything else in this document, never
    described as "still requiring approval" or similar softening language.
  - **Full audit + post-hoc human review:** every reflex action taken this way must be as fully
    audited (write-ahead, pre/post-state, per §(c)) as any human-approved containment action, plus a
    mandatory post-hoc human review pass — the absence of pre-action confirmation must be
    compensated by strengthened, not weakened, after-the-fact review.
  - **Self-lockout at fleet scale (safety-review finding, folded 2026-07-24):** "reversible-first
    actions only" is not by itself a sufficient guard against self-lockout on this path. §(a)
    establishes that block/revoke are reversible *in principle* (re-add the rule/peer) yet a
    self-lockout on a remotely-administered host can be practically unrecoverable if the host cannot
    be reached to reverse it — and at fleet scale, a bad block/revoke signature recognized broadly
    could self-lockout many hosts simultaneously, each individually "reversible" and each
    individually unreachable. The self-lockout guard that is a hard precondition for kill/block/
    revoke on the human-approved path (§(a)) must be carried onto this path explicitly, and the
    fleet-scale case (many simultaneous self-lockouts, not one) must be addressed by name —
    "reversible-first" alone does not cover it.
- **The risk, stated plainly, as the operator explicitly flagged it:** a federated, near-instantaneous
  action-on-recognition network is not only a defensive tool — it is **also the infrastructure for a
  catastrophic automated global outcome should Descartes become widely deployed**. A bad, poisoned,
  or maliciously-ratified signature propagating through the same mechanism that lets good signatures
  authorize fast reflex defense could authorize fast reflex harm at the same speed and the same
  scale. This is recorded here as an **accepted, eyes-open risk**, not a footnote or a caveat to be
  minimized — this direction demands the **strongest governance in the entire system**, must never
  ship without it, and the operator's own framing (herd immunity, "you lose a few nodes") should be
  read as an acceptance of bounded, individually-scoped local loss, not as license for the
  catastrophic global failure mode named directly above. Any future design-only follow-on plan for
  this direction must reproduce this risk statement prominently, not bury it.
- **Status:** captured here as a design direction only. Not scheduled, not designed in detail, and
  gated on its own explicit operator sign-off (§(d) item 9) before even a dedicated design-only
  follow-on plan (§(e) Slice 7.8, formerly 7.6 — now `docs/plans/2026-08-11-descartes-fleet-federated-topology.md` per operator sign-off 2026-08-11) is opened.

---

## Operator sign-off (2026-08-11)

This section records the operator's direct sign-off on the nine §(d) open scope decisions, plus a
set of orchestrator-refined mechanism details agreed with the operator this session. It is folded
inline throughout §(a)–(e) above (see the "operator sign-off 2026-08-11" / "RESOLVED by operator
sign-off" callouts and the header's "Operator sign-off folded" line and the Summary's "Updated
2026-08-11" paragraph); this section is the single authoritative statement of that sign-off, for
reference, and does not introduce anything not also reflected inline. **This section, like the rest
of the document, is DESIGN-ONLY — it directs what a future design should look like, it does not
itself constitute or authorize any code.**

### Verbs (§(a)) — ALL APPROVED

`kill`, `revoke`, `block`, and `quarantine` are all approved as in-scope containment verbs. No verb
is dropped. See "Which verbs" (§(d) item 2) and "Quarantine" (§(d) item 8) below for the reasoning —
in short, the operator's own environment doesn't need every verb (no personal container use), but
Descartes is not built for one deployment, and other users' environments do.

### Authority (§(b))

- **Near-term mechanism:** Option 3 (time-delay, single-party) remains the mechanism actually being
  built, now specified as delivered via **local notification** on the monitored machine.
- **Cross-device design option, near/mid-term:** deliver the approval request to **another of the
  operator's own machines** without a central webservice — e.g. an extremely limited, purpose-scoped
  **SSH-key relay** between the operator's own machines. The operator is explicit that the exact
  mechanism is unresolved; this is captured as a **design option to work out**, not a specified
  protocol (§(b) Option 2a).
- **Later:** multi-device / out-of-band push approval, with a **cryptographically secure
  capability** such that **nothing on the (possibly-compromised) monitored machine can impersonate
  the user's authorization** — candidate primitives **JWT / biscuits / macaroons**; needs a backend
  (open-source is acceptable) (§(b) Option 2b).
- **Multi-operator (n-of-x threshold):** later, and explicitly **built on top of multi-device**, not
  as its own second-identity system.
- **Action → mechanism mapping:** **user-configurable**, with **sensible (fail-closed) defaults** —
  see §(b)'s "Fail-closed action → mechanism matrix" subsection.

### AGENTS.md (§(c))

`AGENTS.md` **cannot enforce anything** — it is context/instructions only, read by a model.
Enforcement **requires a deterministic validating process**. Therefore: **the authority plane is a
deterministic code gate, never a model prompt/instruction.** The model may propose a containment
action; only the deterministic gate plus a valid capability token authorizes execution. See §(c)'s
new "authority plane is a deterministic code gate" paragraph.

### §(d) items — all RESOLVED

1. **Execution capability:** YES — the end-goal is real execution (already resolved 2026-07-24;
   reaffirmed here). Sequencing (what's built first) is settled by the §(e) phasing below.
2. **Which verbs:** the operator doesn't run containers personally, but other users of Descartes
   deployments do — **keep the full verb set**, do not drop `quarantine`.
3. **Second human operator:** none, but the operator has **many devices** — **multi-device**, not
   multi-human, is the path (already resolved 2026-07-24; reaffirmed and sharpened here with the
   n-of-x-on-top-of-multi-device framing).
4. **Self-lockout:** **disable the capability** on hosts where self-lockout can't be tolerated — a
   **per-host opt-out toggle**.
5. **Emergency bypass:** the **federated immune system** is the intended answer to this tension, now
   spun into its own dedicated plan (below).
6. **Build or park:** **BUILD.** Phasing: recommend-only via local notification NOW (mutates
   nothing) → remote-device notification (via other registered Descartes instances over SSH, or a
   centralized backend + push) → federated layer / comms / push backend → then "real teeth"
   (execution).
7. **Doc scoping sufficient for now:** YES.
8. **Quarantine:** **KEEP** — the operator is not the only user of Descartes.
9. **Federated immune system:** expanded into a **"Descartes all the way down" fractal FLEET
   vision** — gets its **own dedicated plan**,
   `docs/plans/2026-08-11-descartes-fleet-federated-topology.md`. Slice 7 **references** it, does not
   absorb it. The full governance checklist this item originally required (ratifying authority,
   corroboration threshold, fleet-level blast-radius controls, Sybil/ratifier-compromise controls,
   the reflex path's consent-model degradation, honest labeling, full audit — all enumerated in the
   "Fast-response tension → federated immune system" subsection of the 2026-07-24 Operator direction
   section above) is carried forward as the gate that dedicated plan must clear, unchanged and
   unlowered by the spin-out.

### (e) Phased breakdown — AGREED

The §(e) phased breakdown above, renumbered and expanded to match this sign-off, is agreed: Slice 7.1
(deception/honey-tokens) and Slice 7.2 (recommend-only via local notification) first, both mutating
nothing; Slice 7.3 (authority-store scaffold) and Slice 7.4 (remote-device notification) next, still
mutating nothing; Slice 7.5 (first execution primitive) onward is where real mutation begins, gated
on the Vault-Tec sandbox below; Slice 7.8 (federated) is referenced via its own dedicated plan, not
scheduled.

### Vault-Tec sandbox

Run the mutating verbs (Slice 7.5 onward) **only** inside dedicated, otherwise-useless VMs where the
operator simulates odd/suspicious behaviours the local instance doesn't already know about, and
monitors the result. This serves as both a safe **dev/validation harness** for containment and a
natural **honeypot**. **Naming theme:** each per-instance Vault is named after the "Vault-Tec Vault"
convention (e.g. `Vault 111`). **Constraint:** the dev machine cannot run VMs (no
`Virtualization.framework` — see the existing "Dev machine cannot run VMs" memory/finding), so Vaults
run on the operator's **other hardware** or **CI** (`big-cabbage` / `tart`-CI remotes). See §(e)'s
"Vault-Tec sandbox" subsection for the full model and its slice-by-slice application.

### Orchestrator refinements woven in this session

- **Transport vs. authority separation:** TRANSPORT (SSH-relay / push) is *how the request travels*;
  AUTHORITY (the capability token) is *proof the human approved this verb on this target*. Conflating
  the two is exactly how a compromised monitored machine could end up minting its own "approval." See
  §(b)'s "Transport vs. authority" subsection.
- **Key custody:** the signing key **must not live on the monitored machine**. The operator's
  **device** mints a narrow, short-TTL, single-use token bound to the specific approved decision plus
  the freshly re-resolved target+verb; the instance only relays and verifies-then-consumes
  (write-ahead) it. See §(b)'s "Capability-token model and key custody" subsection.
- **Why biscuits/macaroons fit:** they only **attenuate** (narrow) offline, never widen — exactly the
  property this design needs when a token passes through a relay and a capability-holding helper on
  its way to the mutating call.
- **The authority plane is a deterministic gate:** the model may **propose** a containment action;
  only the deterministic gate + a valid capability token **authorizes execution**. See §(c) above.
- **Fail-closed defaults for the action → mechanism matrix:** unknown action / unavailable mechanism
  → **DENY**; irreversible (`kill`) and self-lockout-capable (`block`/`revoke`/`quarantine`) verbs
  demand the strongest available channel; deception/recommend-only need only local. See §(b)'s
  "Fail-closed action → mechanism matrix" subsection.
- **Deception / honey-tokens is a shippable slice below containment:** mutates nothing, needs no
  authority plane, and yields a clean signal + a concrete target for later containment work to test
  against. Added as §(e) Slice 7.1, the first buildable slice of Slice 7 overall.
- **Legal boundary:** "repel" means defending Descartes' own systems, and deception on Descartes' own
  machine — **never** hack back beyond the monitored perimeter. Stated explicitly in §(a) Cross-verb
  themes.
