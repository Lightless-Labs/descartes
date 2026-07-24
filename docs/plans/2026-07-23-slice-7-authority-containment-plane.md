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
ratifier-compromise controls, added to the §(e) 7.6 governance checklist and §(d) item 9; the
federated reflex path's consent-model degradation — reflex execution has no human in the loop to
mint a per-execution consent nonce, so the helper/capability separation degrades to trusting the
daemon's own signature-recognition code, now named explicitly with a required-analysis item added
to the 7.6 checklist; the single-use execution-consent nonce's own crash-consistency and binding —
write-ahead consume before the mutating call, and cryptographic/logical binding to a specific
approved §(b) decision plus the freshly re-resolved target+verb, added to §(a) Cross-verb themes).
Safety findings folded alongside the must-fixes: self-lockout-at-fleet-scale added to the
federated-section governance checklist ("reversible-first" alone does not bound simultaneous
multi-host self-lockout); the quarantine-fold privileged-primitive-count overstatement between
§(a)'s recommendation and §(e) 7.5's own text reconciled. Q2 (honest autonomy-escalation labeling)
and Q4 (design-only, zero new `execFile`) both re-verified PASS; all three Stage-1 (2026-07-23)
must-fixes reconfirmed present and correctly reasoned. This document remains DESIGN-ONLY — no code
changed as part of folding this review in.
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
build.**

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
  count** by one; it does not reduce the **privileged-primitive count** — §(e) Slice 7.5 already
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
  container-socket privilege shape doesn't map cleanly onto plain `SIGSTOP` + netns. **Open question
  for the operator, not resolved by this document:** does the operator run containers on the
  monitored host that they would want isolated this way? The answer determines whether `quarantine`
  is folded away or kept as its own verb; see also §(d) item 2, which already flagged the container
  applicability question and is now sharpened by this fold-vs-keep framing.

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
- **Irreversibility** varies sharply by verb: kill has none; block/revoke are reversible if
  care is taken (reversal path proven up front); quarantine is reversible via
  pause/unpause **only** if the process's state survives the pause, which is not guaranteed.
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
  design-time, question, deferred to Slice 7.3+) — it only requires that any future implementation
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

### Option 2 — Multi-device / out-of-band push approval

Approval must arrive over a channel distinct from the one that detected/proposed the incident
(e.g., a push notification to a second device, requiring the approver to act somewhere other than
the terminal that raised the alert).

- **Pros:** doesn't require a second *human* — raises the bar over a same-terminal approve, since
  an attacker who has compromised the local session doesn't automatically control the second
  channel too.
- **Cons:** this is genuinely **new external surface** — a second delivery channel, plausibly a
  new external service dependency, webhook, or API-key surface. That runs directly against this
  codebase's stated minimal-scope / no-new-execFile-or-privilege-surface ethos and would need its
  own dedicated security review before being designed in detail (not sketched further here). It is
  also frequently *not* true multi-party in the adversarial sense — the "second channel" is often
  the same operator's own phone, i.e. multi-factor, not multi-party.

### Option 3 — Time-delay / cooling-off window (no second party; explicitly weaker)

A containment proposal is recorded (nonce + expiry, exactly mirroring `promotion-store.js`'s
`mintPendingPromotion`/`decideConstraintPromotion` shape) and only becomes executable after a
mandatory minimum delay unless separately, deliberately re-confirmed. The delay is a "read this
again when calmer" safeguard and an audit/notification window, not a stand-in for a second party.

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

1. **Near-term, single mechanism actually being built: Option 3** — templated 1:1 on
   `promotion-store.js`'s nonce/expiry/deny-by-default/`audit_transitions` pattern, with a
   mandatory minimum delay. Every surface that shows this to the operator (CLI output, audit
   record, any future notification) must permanently and unambiguously label it "single-party,
   time-delayed — NOT multi-party confirmation." No language may imply a second party ever
   reviewed it. The operator has explicitly acknowledged this is weak against fast-moving threats
   (ransomware and similar) and accepts that weakness for now; see the "Fast-response tension →
   federated immune system" subsection of the Operator direction section below for the accepted
   future resolution.
2. **Option 1 (second human / two-person rule) — not for now.** Confirmed **out of scope near-term**
   by the operator, not merely deprioritized; possible in a later **enterprise** setting with a
   real multi-operator identity model. Do not build speculatively.
3. **Option 2 (multi-device push) — acceptable as a later improvement**, confirmed by the operator
   to require its own backend for identity and push-notification delivery before it is buildable at
   all. Still its own future workstream requiring a dedicated security review, and still not
   designed further here.

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

---

## (c) Composition with AGENTS.md's Policy/Authority Plane

`AGENTS.md` §"Policy / Authority Plane" (lines 80–90) defines five tiers — read-only,
recommend-only, approval-required, policy-authorized low-risk action, autonomous — and requires
every action to carry a full audit trail: proposed plan, approval source, command/tool call,
pre-state, result, post-state, rollback notes when possible.

**Tier mapping for containment:**

| Tier | Containment mapping |
|---|---|
| read-only | Already shipped: session-census, VPN/peer, provenance collectors (Slices 1/3/S3-S5). No change proposed here. |
| recommend-only | The **only** execution-adjacent tier this document considers safe to build in the near term: surface a proposed verb + target + rationale for a human to read and, if they choose, act on **manually and entirely outside Descartes**. Zero new `execFile`, zero new privilege. |
| approval-required | Where any real containment *execution*, if ever built, **must** live — the human-gated nonce/expiry/audit pattern from §(b) Option 3 (or 1/2 per the tiering above), with the approved decision then handed to the separate capability-holding helper (§(a) Cross-verb themes, operator-directed 2026-07-24) under its own single-use, time-limited consent nonce for the actual mutating call. No containment verb should skip this tier near-term. |
| policy-authorized | **Not recommended for any containment verb** in the foreseeable future. `AGENTS.md` scopes this tier to "narrowly scoped, tested, reversible cases" — kill fails "reversible" outright; block/revoke fail "narrowly scoped" given self-lockout blast radius; quarantine's blast radius depends on a credential (`docker.sock`-class) that is itself not narrowly scoped. |
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

**Kill-switch:** any future containment authority-gate (even the inert §(e) Slice 7.2 scaffold)
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
   below. What remains open is *sequencing* (§(e)'s phased build still starts at 7.1
   recommend-only before any execution primitive), not *whether* execution is ever wanted.
2. **Which verbs are actually applicable to this operator's real environment? — Partially resolved.**
   `kill`, `revoke`, and `block` are confirmed in scope with the execution model above. `quarantine`
   remains genuinely open: §(a)'s quarantine subsection now recommends folding it into a
   composition of `{freeze + block}` unless the operator runs containers on the monitored host they
   would want isolated via a container-runtime-specific route — that container question is the one
   piece of item 2 still awaiting a direct operator answer.
3. **Is a second human operator ever available? — RESOLVED by operator direction 2026-07-24.** No,
   not for now. §(b) Option 1 (second human / two-person rule) is confirmed out of scope near-term,
   possible only in a later enterprise setting. §(b) Option 3 (time-delay, single-party, explicitly
   weaker) is confirmed as the near-term mechanism.
4. **Self-lockout tolerance.** For block/revoke/kill, is accidentally cutting off the operator's own
   remote access (or, for `kill`, destroying their own controlling session) an acceptable,
   recoverable risk (they have physical/console access) or a catastrophic one (fully
   remote-administered host, no fallback)? Still open — the operator direction folded into this
   document strengthens the *guards* (self-lockout guard, helper-mediated single-use consent) but
   does not itself state the operator's actual physical/console-access fallback situation.
5. **Emergency-bypass tension. — Reframed, not resolved, by operator direction 2026-07-24.** Rather
   than a bypass of the §(b) Option 3 delay itself, the operator has proposed a structurally
   different future resolution — the federated immune system direction in the Operator direction
   section below, where pre-corroborated signatures authorize reflex action with notification, not
   confirmation. That direction is design-only, heavily governance-gated, and not scheduled; whether
   and when to pursue it is itself a future operator sign-off decision, not answered here.
6. **Build anything now, or park this document?** Should any part of Slice 7 (even the inert
   recommend-only tier or the authority-store scaffold with no execution primitive, §(e) 7.1/7.2)
   move to an implementation plan in the near term, or does this document simply exist to be filed
   and revisited once the above are answered? Still open — the operator direction folded in here
   sharpens *what* would be built (the helper-mediated execution model, the quarantine fold
   recommendation) but does not itself green-light starting §(e) 7.1/7.2 now.
7. **Confirm this document's own scoping is sufficient.** The dispatch that produced this draft
   supplied section-level scope (the (a)–(e) structure, verb set, store-separation mandate) but did
   not answer items 1–6 above. The 2026-07-24 operator direction resolved items 1 and 3 and
   substantially sharpened items 2 and 5; items 4 and 6 remain open. Recommend treating this document
   as a second-pass draft, still requiring explicit operator answers to items 2 (container question
   only), 4, and 6 before any follow-on implementation plan is opened — not as a completed scoping
   conversation in itself.
8. **Quarantine fold-vs-keep — new, operator-directed 2026-07-24.** Does the operator run containers
   on the monitored host that they would want isolated via a container-runtime-specific route
   (`docker pause`/network-disconnect)? If no, `quarantine` folds into `{freeze + block}` per §(a)'s
   recommendation and is not built as its own verb. If yes, it stays a distinct verb with its own
   container-socket-scoped execution primitive and its own review. This is a sharpened,
   directly-answerable subset of item 2, called out separately because §(a) now has a concrete
   recommendation riding on the answer.
9. **Federated immune system — governance sign-off, new, operator-directed 2026-07-24; checklist
   expanded by safety review 2026-07-24.** The federated immune system direction (Operator direction
   section below) is captured as a future design direction only. Before any part of it moves toward
   even a design-only follow-on plan (let alone implementation), the operator must explicitly sign
   off on the full governance model that direction enumerates — **now including, per the 2026-07-24
   safety review's must-fixes**, fleet-level controls in addition to the node-local ones (staged/
   canary propagation; a fleet-wide circuit-breaker and signature recall/revocation that reaches
   nodes mid-rollout, not merely a per-node kill-switch; Sybil-resistance and ratifier-compromise
   controls, since corroboration and ratification are today assumed-honest and unsecured) and an
   explicit answer to the reflex path's consent-model degradation (what unforgeable authority
   substitutes for a human-minted, per-execution consent nonce when no human is in the loop, and why
   a compromised daemon cannot self-authorize by "recognizing" a signature) — alongside the
   originally-named ratifying authority, corroboration threshold, honest notification-vs-confirmation
   labeling, and full audit. This document does not itself constitute that sign-off, and the
   direction's own stated catastrophic-risk framing means this bar should be treated as at least as
   high as, not lower than, the rest of this document's sign-off requirements.

---

## (e) Phased, locally-testable-first slice breakdown for the eventual build

Presented as a design sketch for a **future** plan, not authorization to build any of it now.
Every slice from 7.2 onward must clear a dedicated `doors-and-corners` pass **and** an adversarial
review at least as strict as — arguably stricter than, since a root helper reads facts and a
containment action mutates live infrastructure and can kill real sessions — the S3-priv
`root_helper` review (`docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`: trust-boundary
analysis, minimal-capability-grant validation via an empirical/live-hardware check rather than
static reasoning alone, fail-closed/deny-by-default verification, race/TOCTOU analysis). A
mutating path deserves at least that bar, not less.

- **Slice 7.0 — this document + operator resolution of §(d).** No code. Gate for everything below.
  Partially cleared 2026-07-24: §(d) items 1 and 3 are resolved by the operator direction folded
  into this document; items 2 (container question), 4, and 6 remain open per §(d)'s updated text.
- **Slice 7.1 — recommend-only surface** *(§(d) item 1 now resolved — execution-adjacent work is
  wanted — but this slice is still the correct, lowest-risk starting point regardless)*: the
  daemon/alert pipeline gains a new, purely additive signal that surfaces a proposed
  verb + target + rationale (e.g., `session.count_drop` → "consider investigating/killing session
  X") for a human to read and act on manually. **Zero new `execFile`, zero new privilege, zero
  host mutation.** Locally testable end-to-end. Still needs its own doors-and-corners pass and
  review — a wrongly-targeted recommendation is itself a harm vector (misdirected operator trust),
  even with no execution capability behind it.
- **Slice 7.2 — authority-store scaffold, no execution primitive:** `containment.json` +
  nonce/expiry/deny-by-default mint+approve/reject CLI, templated 1:1 on `promotion-store.js`
  (§(c)), where "approve" records a decision and **executes nothing** — no execution primitive
  exists yet. Proves out the authority-gate mechanics entirely in isolation from any privilege
  surface. Locally testable, zero new `execFile`, zero new privilege.
- **Slice 7.3 — first real execution primitive, single most-reversible verb first** (likely
  `revoke` of a single VPN peer, or `block` via an isolated firewall anchor — whichever the
  operator's real environment supports per §(d) item 2): a scoped, allowlisted, single-purpose
  execution primitive, wired **only** behind Slice 7.2's authority gate, and, per the
  operator-directed execution architecture in §(a)'s Cross-verb themes, wired through the separate
  capability-holding helper (never invoked directly by the daemon/CLI) under a single-use,
  time-limited consent nonce — leaning on `sudo`/`polkit` (Linux) or a privileged `launchd`
  helper + XPC + code-requirement checks (macOS) rather than a bespoke privilege mechanism — with a
  self-lockout guard, a dry-run mode, an auto-revert/expiry, and full pre/post-state capture per
  §(c)'s audit shape. This is the first slice that introduces new `execFile`/privilege surface and
  is therefore the first slice that needs the full S3-priv-or-stricter review bar: trust-boundary
  analysis, minimal privilege grant (empirically validated, not just reasoned about), fail-closed
  verification, TOCTOU/race analysis, a dedicated self-lockout test, and a proven rollback test —
  now additionally including a dedicated review of the helper boundary itself (does the daemon/CLI
  genuinely hold zero capability, is the consent nonce genuinely single-use and unforgeable).
- **Slice 7.4 — `kill`, if ever built at all:** given `kill`'s irreversibility (§(a)), this should
  be the **last** verb attempted, only after 7.3's authority+execution pattern has been live,
  audited, and uneventful for a meaningful period on a genuinely reversible verb first. Routed
  through the same helper + single-use-consent model as 7.3, per §(a).
- **Slice 7.5 — `quarantine`, only if applicable** (§(d) items 2/8 — the container question):
  contingent on the operator's answer to whether they run containers on the monitored host. If not,
  this slice is replaced entirely by composing 7.3's `block` primitive with a new `freeze` primitive
  (`SIGSTOP`/cgroup-freezer) rather than standing up quarantine as its own verb, per §(a)'s
  fold-into-`{freeze + block}` recommendation. If yes, this slice proceeds as originally scoped:
  runtime-specific, its own scoped credential (never a raw `docker.sock`-class handle on the general
  daemon process, per §(a)), its own dedicated review.
- **Slice 7.6 — federated immune system, design-only follow-on, not scheduled** *(new,
  operator-directed 2026-07-24; governance checklist expanded by safety review 2026-07-24; gated on
  §(d) item 9)*: should the operator ever choose to pursue the federated immune system direction
  (Operator direction section below) beyond this document's capture of it, the correct next step is a
  **separate, dedicated, design-only plan** — not an extension of Slices 7.1–7.5's execution work —
  that works out the full governance model before any code is contemplated: ratifying authority,
  corroboration threshold, **both node-local and fleet-level blast-radius caps** (staged/canary
  propagation; a fleet-wide circuit-breaker and signature recall/revocation, not merely a per-node
  kill-switch; Sybil-resistance and ratifier-compromise controls — node-local caps alone do not
  bound the fleet-global catastrophic outcome this direction names, per the 2026-07-24 safety
  review), notification-vs-confirmation labeling, audit/post-hoc review, **and an explicit
  resolution of the reflex path's consent-model degradation** (what replaces the human-minted,
  per-execution consent nonce when the reflex path has no human in the loop, and why a compromised
  daemon cannot self-authorize by "recognizing" a signature). This slice is listed here only to keep
  it visible in the same phased breakdown as the rest of Slice 7; it is not implied to follow
  sequentially from 7.5, and per §(d) item 9 it requires its own explicit operator sign-off before
  even a design-only follow-on plan is opened.

Every slice 7.2 and later is additionally gated behind the **dedicated, default-OFF containment
kill-switch** from §(c) — never `learned.json`'s existing switch — checked before any I/O, exactly
mirroring the discipline `daemon.js` already applies to the structural tick.

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
governance checklist (§(e) Slice 7.6, §(d) item 9) now explicitly requires fleet-level controls —
staged/canary propagation, a fleet-wide circuit-breaker and signature recall/revocation, and
Sybil-resistance/ratifier-compromise controls — in addition to the node-local caps already named,
because node-local caps alone do not bound the fleet-global catastrophic outcome that section itself
names. The reflex path's consent-model degradation (no human-minted, per-execution consent nonce
when execution follows local signature recognition) is now named explicitly, with a required
analysis item added to the 7.6 checklist. §(a) Cross-verb themes now specifies the execution-consent
nonce's own write-ahead-consume ordering and its binding to a specific approved §(b) decision plus
the freshly re-resolved target+verb, closing a theoretical replay-on-crash and misbinding window.
None of this changes what may be built now — it sharpens the bar the not-yet-authorized federated
direction (§(d) item 9) must clear, and adds detail to the already-mandated §(a)/§(c) execution
mechanics. This document remains DESIGN-ONLY.

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
  future design-only follow-on plan, §(e) Slice 7.6, must work through before this direction is
  anything more than a captured idea):
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
    analysis for §(e) Slice 7.6, not answered here:** what unforgeable authority mints or stands in
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
  follow-on plan (§(e) Slice 7.6) is opened.
