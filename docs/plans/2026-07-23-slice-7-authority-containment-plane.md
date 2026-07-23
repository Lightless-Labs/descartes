# Slice 7 — Authority/Containment Plane — DESIGN-ONLY

**Status:** DRAFT — design-only, not an implementation plan. No code, no new tools, no new
`execFile` surface is prescribed to ship from this document.
**Reviewed:** 2026-07-23 (Stage 1 adversarial gate) — GO_WITH_CHANGES; all 3 must-fixes folded
(kill self-lockout gap, write-ahead/crash-consistent audit ordering, hash-at-source vs.
raw-identifier provenance tension). 6 PASS + 2 MINOR safety findings recorded, no further action
required on the MINORs beyond what §(a)'s "Inputs read" note and revoke's precondition text already
say.
**Created:** 2026-07-23
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
(S3-priv `root_helper` adversarial review, used as the review-bar reference in §(e)). No
`docs/plans/2026-05-19-agent-delegation-identity-authority.md` file exists in this repo despite
being referenced in `docs/HANDOFF.md` line 361/391 — treated as **not found / out of scope**;
if that spike exists elsewhere it should be reconciled with this document in a follow-up, not
assumed compatible.

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
  `kill` combines self-lockout with zero rollback.

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
  proven to work *before* the removal path ships.

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
  `promotion-store.js` uses a bounded expiry rather than an indefinite pending state).

### quarantine (isolate a container/process)

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

### Cross-verb themes

- **Privilege escalation surface:** every verb needs a categorically new, write-capable privilege
  grant. None of S3-priv's existing `root_helper` capability grant (`cap_sys_ptrace,
  cap_dac_read_search`, read-only, seccomp-hardened) is reusable as-is — that grant was
  deliberately minimized for *reading* `/proc`; a containment helper would need a **wholly
  separate, independently-scoped, write-capable** privilege surface that does not exist today and
  is explicitly **not** designed by this document (only flagged as needing its own future
  doors-and-corners pass and review, per §(e)).
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

A **tiered, honestly-labeled** approach, not a single mechanism:

1. **Default and only mechanism buildable without new external infrastructure: Option 3** —
   templated 1:1 on `promotion-store.js`'s nonce/expiry/deny-by-default/`audit_transitions`
   pattern, with a mandatory minimum delay. Every surface that shows this to the operator (CLI
   output, audit record, any future notification) must permanently and unambiguously label it
   "single-party, time-delayed — NOT multi-party confirmation." No language may imply a second
   party ever reviewed it.
2. **Option 1 (second human) as the aspirational default for any multi-operator deployment** —
   config-gateable, but not built until a real second-operator use case and identity model exist;
   do not build speculatively.
3. **Option 2 (multi-device push) treated as its own future workstream requiring a dedicated
   security review** given it is the only option that introduces genuinely new external surface —
   explicitly not designed further here.

**Unresolved tension flagged, not resolved, by this recommendation:** a genuine fast-moving
incident may need a *faster* response than any cooling-off window allows, which is in direct
tension with the safety goal of slowing down an unauthorized/mistaken action. Whether — and how —
to allow an emergency bypass of the delay (and what would authorize skipping it) is left as
**Open scope decision 5** in §(d); this document deliberately does not pick a delay length or a
bypass mechanism.

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
| approval-required | Where any real containment *execution*, if ever built, **must** live — the human-gated nonce/expiry/audit pattern from §(b) Option 3 (or 1/2 per the tiering above). No containment verb should skip this tier. |
| policy-authorized | **Not recommended for any containment verb** in the foreseeable future. `AGENTS.md` scopes this tier to "narrowly scoped, tested, reversible cases" — kill fails "reversible" outright; block/revoke fail "narrowly scoped" given self-lockout blast radius; quarantine's blast radius depends on a credential (`docker.sock`-class) that is itself not narrowly scoped. |
| autonomous | **Explicitly out of scope.** Same reasoning as policy-authorized, stronger. |

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
  (verify this per-runtime before relying on it).

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

1. **Execution capability at all, or recommend-only forever?** Does the operator want Descartes to
   ever *execute* a containment verb, or only ever *surface a recommendation* for a human to act on
   manually, outside Descartes entirely? This is the single biggest fork in the whole design —
   recommend-only never needs a privilege surface, a root-helper-equivalent, or an answer to the
   multi-party question at all, because a human types the real command themselves.
2. **Which verbs are actually applicable to this operator's real environment?** Is "quarantine"
   (container isolation) even relevant — does the operator run containers on the monitored host at
   all? Concretely enumerate against the real deployment rather than building out the full abstract
   kill/revoke/block/quarantine catalog speculatively.
3. **Is a second human operator ever available?** This directly decides whether §(b) Option 1 is
   buildable at all, or whether the design must commit to Option 3 (and its honesty-labeling
   requirement) as the only realistic mechanism, given the rest of this codebase (e.g.
   `promotion-store.js`'s own comment) assumes a single-operator deployment.
4. **Self-lockout tolerance.** For block/revoke, is accidentally cutting off the operator's own
   remote access an acceptable, recoverable risk (they have physical/console access) or a
   catastrophic one (fully remote-administered host, no fallback)? This changes the required
   safety bar for those two verbs specifically.
5. **Emergency-bypass tension.** Should the time-delay authority model (§(b) Option 3) ever have a
   fast-path override for a genuinely urgent incident, and if so, what authorizes skipping the
   delay? (Answering this re-introduces a scaled-down version of the multi-party question.)
6. **Build anything now, or park this document?** Should any part of Slice 7 (even the inert
   recommend-only tier or the authority-store scaffold with no execution primitive, §(e) 7.1/7.2)
   move to an implementation plan in the near term, or does this document simply exist to be filed
   and revisited once the above are answered?
7. **Confirm this document's own scoping is sufficient.** The dispatch that produced this draft
   supplied section-level scope (the (a)–(e) structure, verb set, store-separation mandate) but did
   not answer items 1–6 above. Recommend treating this document as a first-pass draft that still
   requires explicit operator answers to 1–6 before any follow-on implementation plan is opened —
   not as a completed scoping conversation in itself.

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
- **Slice 7.1 — recommend-only surface** *(only if §(d) item 1 selects execution-adjacent work at
  all)*: the daemon/alert pipeline gains a new, purely additive signal that surfaces a proposed
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
  execution primitive, wired **only** behind Slice 7.2's authority gate, with a self-lockout guard,
  a dry-run mode, an auto-revert/expiry, and full pre/post-state capture per §(c)'s audit shape.
  This is the first slice that introduces new `execFile`/privilege surface and is therefore the
  first slice that needs the full S3-priv-or-stricter review bar: trust-boundary analysis, minimal
  privilege grant (empirically validated, not just reasoned about), fail-closed verification,
  TOCTOU/race analysis, a dedicated self-lockout test, and a proven rollback test.
- **Slice 7.4 — `kill`, if ever built at all:** given `kill`'s irreversibility (§(a)), this should
  be the **last** verb attempted, only after 7.3's authority+execution pattern has been live,
  audited, and uneventful for a meaningful period on a genuinely reversible verb first.
- **Slice 7.5 — `quarantine`, only if applicable** (§(d) item 2): runtime-specific, its own scoped
  credential (never a raw `docker.sock`-class handle on the general daemon process, per §(a)), its
  own dedicated review.

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
on anywhere else. Nothing should be built from this document until the operator has answered
§(d)'s seven open scope decisions.
