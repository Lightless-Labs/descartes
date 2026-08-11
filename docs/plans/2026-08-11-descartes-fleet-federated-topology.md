# Descartes Fleet / Federated Topology — "Descartes all the way down" — DESIGN-ONLY

**Created:** 2026-08-11
**Purpose:** Investigate, decompose, and honestly bound the operator's fractal multi-instance
Descartes fleet — per-host, network-sentinel, ephemeral-VM, bastion/gateway/router, and laptop
instances (general and specialised, sometimes co-located, able to **watch each other**) — and
identify the **minimum valuable service** that unlocks the vision without hand-waving the hard
parts. This is a serious design investigation, **not** an implementation plan: NO CODE, no new
tools, no new `execFile` surface, no privilege grant is prescribed to ship from this document. It
is the dedicated plan the Slice 7 authority/containment doc (§(d) item 9, Slice 7.6) said the
"federated immune system" direction would require **before** anything beyond idea-capture, and it
references — never absorbs — that document.

**Status:** DRAFT — design-only, reviewed. Every buildable slice named in §(e) is gated behind
its own `doors-and-corners` pass **and** an adversarial review at least as strict as the S3-priv
`root_helper` bar (`docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`), and the reflex/federated
tiers additionally behind the expanded fleet-governance sign-off enumerated in the Slice 7 doc's
§(d) item 9. This document does not itself constitute that sign-off.

**Reviewed:** 2026-08-11 — GO_WITH_CHANGES. All five must-fixes resolved inline (Domain 6 /
Hard Problem H — software distribution/update integrity — added to §(b)/§(d); the co-location
overclaim corrected in §(a) and Hard Problem B; Slice F1 gated like every other slice in §(e) and
Hard Problem G; approval-device compromise named in Hard Problem C; the MVS's zero-execution-
primitive value claim substantiated by splitting Slice F2 into F2a notification-only / F2b token
minting in §(c) and §(e)). The six non-blocking safety findings from the same pass are folded as
named honest limits, not silently dropped: the false-accusation trust loop and the integrity-
attestation hand-wave (Hard Problem B), the rooted-host-bypasses-the-fleet limit and the clock-
manipulation corollary (Hard Problem C), the recall path's fail-open failure mode (Domain 5), and
Vault-Tec role-mixing / required trust-domain ring-fencing (§(a)). None of these change the
verdict; they sharpen what the document already tries to do — name hard problems honestly instead
of hand-waving them.

**Inputs read (read-only; none edited by this doc):**
`docs/plans/2026-07-23-slice-7-authority-containment-plane.md` (the authority/containment plane and
its 2026-07-24 operator direction + safety review — the near-term execution model this fleet
composes with), `AGENTS.md` ("Policy / Authority Plane" §80–90 and the L3 Federated Knowledge
Layer / Operational Lifecycle stage 7 "Learn"), `docs/HANDOFF.md` (fleet-relevant live state: the
read-only monitoring plane Slices 1–6, hash-at-source provenance, the `promotion-store.js`
authority-gate template, the `descartes-root-helper` privileged-helper precedent),
`todos/2026-05-19-agent-delegation-identity-authority.md` (prior art: this repo already recognises
inter-**agent** delegation identity + scoped capability tokens as an open problem — the fleet's
instance identity work must reconcile with it, not design authority primitives twice). Operator
vision + sign-off captured in auto-memory [[descartes-federated-immune-system-vision]].

**Operator mandate + sign-off folded (2026-08-11):** this document exists because the operator
signed off on the Slice 7 open-scope decisions and expanded the federated-immune-system idea into a
full "Descartes all the way down" fleet vision that "gets its own dedicated plan." All of the
operator's sign-off points are folded faithfully below (see the "Operator sign-off (2026-08-11)"
section) and cross-referenced inline via **(operator-directed 2026-08-11)** callouts.

---

## 0. Framing: what "Descartes all the way down" actually is

The operator's picture is a **fractal of Descartes instances**. Not one daemon per host in
isolation, but a *population*: one instance watching its own machine; a dedicated instance silently
surveilling an org's or user's Tailscale tailnet; instances living inside ephemeral, short-lived
VMs; instances on hosts, bastions, gateways, routers, and developers' laptops. Some general, some
specialised. Sometimes a focused specialist sits **right next to** a generalist on the same host.
Crucially, **instances can watch each other** — a host-watcher and a tailnet-watcher standing
side-by-side, each attesting to the other's health and honesty.

Three properties make this more than "run the daemon in more places":

1. **Heterogeneity is the point.** A tailnet-sentinel sees peer topology a host-instance cannot;
   an ephemeral-VM instance is *expendable* in a way a laptop is not; a bastion sees auth flows a
   leaf host never will. The value is in the **composition of vantage points**, not in replication.
2. **Mutual watching is a first-class mechanism, not a side effect.** Because the adversary this
   whole initiative is built against is an **AI-agent adversary capable of rooting a host**, the
   design must assume *any single instance can be turned*. Cross-instance attestation is how the
   fleet stays trustworthy when a member is not. (See §4 Hard Problem B — Byzantine tolerance.)
3. **The fleet is the intended answer to the fast-response tension.** Slice 7 named, but did not
   resolve, that a single-party cooling-off delay is too slow for a fast-moving incident
   (ransomware-class). The operator's resolution is *herd immunity*: a corroborated/ratified
   signature authorises **action-on-recognition with human notification, not confirmation** — "you
   lose a few nodes, but the vast majority won't be affected." That is a genuinely new authority
   tier and it carries a genuinely new catastrophic risk; it is **the last thing built**, behind
   the strongest governance in the system, and this document keeps it visible but firmly deferred.

**What this document deliberately does NOT do:** it does not pick wire formats, PKI vendors,
consensus algorithms, or transport libraries; it does not resolve the Slice 7 open scope decisions
(container/quarantine, self-lockout tolerance, build-or-park) that remain the operator's to answer;
and it does not authorise the reflex/federated action tier. It decomposes the space, names the
seams, finds the smallest valuable thing, and states the hard problems honestly.

---

## (a) Topology and instance archetypes

### Archetypes (by vantage point)

| Archetype | Watches | Distinguishing property | Notes |
|---|---|---|---|
| **Host instance** (the shipped Descartes) | Its own machine — processes, sessions, ports, provenance, identity | The baseline; everything else is a specialisation or a peer of it | This is what Slices 1–6 already are. The fleet is built *around* it, not by replacing it. |
| **Network sentinel** | An org/user's Tailscale tailnet (or WireGuard mesh) — peer presence, topology, odd-hour/unattributed logins | Sees **cross-host** relationships no single host sees; owns no host it watches | Extends Slice 3's `collect_vpn_peer_status` from "this host's view of peers" to "a dedicated observer of the whole mesh." Read-only first. |
| **Ephemeral-VM instance** | A short-lived VM (CI job, PR environment, disposable sandbox) | **Expendable** — its loss is cheap; ideal canary and ideal place to run dangerous verbs | Ties directly to the Vault-Tec sandbox below. Lifecycle is measured in minutes/hours; enrollment/teardown must be near-instant (Hard Problem A). |
| **Bastion / gateway / router instance** | The choke points — auth flows, ingress/egress, NAT, routing | Sees traffic and auth the leaf hosts never see; a high-value target itself | Highest-trust, highest-blast-radius placement. A compromised bastion-instance is among the worst cases — treat as a Byzantine-tolerance stress case, never as a trusted root. |
| **Laptop instance** | A developer's personal/work machine | Intermittently connected, roams networks, most likely to hold real user credentials | Self-lockout tolerance (Slice 7 §(d) item 4) is *most* acute here; also the natural home for the **operator's approval device** (§(c)). |

### General vs. specialised, and co-location

- **General** instances run the full observe → learn → alert loop (the shipped stratified nervous
  system). **Specialised** instances run a narrowed collector/model set for one vantage (e.g. a
  tailnet-only sentinel, or a "watch the other Descartes" attestation-only instance).
- **Co-location is explicitly supported** (operator-directed): a focused specialist may sit *right
  next to* a generalist on the same host — e.g. a host-watcher and a tailnet-watcher on the same
  machine, each attesting to the other. Co-located instances MUST NOT share a trust root or a key
  (that would collapse mutual watching into self-certification); they are peers that happen to be
  neighbours, not one process with two hats.
- **Honest limit on co-location (corrected 2026-08-11 review):** separate trust roots on the same
  host defend against *partial* compromise — one peer's process being exploited while the other
  remains honest (a bug, a narrow local exploit, one daemon crashing/misbehaving). This does **not**
  survive the adversary this document is built against at full strength: a root-level AI-agent
  compromise of the *host* owns both co-located peers' processes, memory, and keys at once, so
  separate trust roots do not yield two independent witnesses once root is lost. Same-host
  co-location should be read as a defense-in-depth / development convenience, not as evidence that
  mutual attestation "makes Byzantine tolerance concrete" on a single machine (see Hard Problem B,
  corrected in the same review) — **cross-host** watching is the mechanism that actually survives a
  root-level compromise, because it requires the adversary to separately root a second machine.

### Vault-Tec instances (the sacrificial-VM harness that runs the dangerous verbs)

**(operator-directed 2026-08-11.)** The mutating containment verbs (kill/revoke/block/quarantine)
run **only** inside dedicated, otherwise-useless VMs — "Vault-Tec Vaults" (per-instance naming
theme) — where the operator deliberately simulates odd/suspicious behaviours the local instance
does not yet know about, and watches how it responds. This serves three purposes at once:

1. A **safe dev/validation harness** for containment: the first place any execution primitive
   (Slice 7.3+) is exercised end-to-end, where a mistaken `kill` or a self-lockout costs nothing
   because the whole VM is disposable.
2. A **natural honeypot**: a Vault that exists only to be poked is, by construction, a place where
   *any* activity is suspicious — a clean high-signal environment for the deception/honey-token
   slice (§(c) / Hard Problems) and for maturing signatures before they touch a real host.
3. A **Byzantine-tolerance testbed**: the place to deliberately turn an instance malicious and
   verify the fleet's cross-watching actually catches it.

**Honest limit — role-mixing (named 2026-08-11 review, requires ring-fencing):** purposes 1–3 above
ask the same Vaults to be a dev/validation harness, a honeypot, *and* a deliberately-turned-
malicious BFT testbed, while also being enrolled fleet members. Purpose 3 in particular requires a
Vault to genuinely behave maliciously so cross-watching can be exercised against it — if that same
Vault's signatures/attestations were reachable by the real fleet, a deliberately-malicious test
signal could leak into production trust decisions (corroboration, ratification, or a false
"clean" attestation). **Required:** any Vault being exercised for purpose 3 MUST be enrolled in a
**separate federation namespace / trust domain** from every Vault or host participating in the real
fleet, so a deliberately-malicious test signature can never be corroborated, ratified, or otherwise
consumed outside the test harness. This is a prerequisite for Slice F6 (the Byzantine-tolerance
mesh), not an afterthought.

**Hard constraint (from auto-memory [[descartes-dev-machine-no-virtualization]]):** the dev machine
**cannot run VMs** — no Virtualization.framework (it is itself likely a VM). Vaults therefore run on
the operator's **other hardware / CI** — `big-cabbage` + the `tart-ci` remotes already used for the
notarization/CI pipeline. This is a real doors-and-corners prerequisite, not a detail: any Vault
slice must target that hardware from day one and can never assume local virtualization.

### Legal / ethical perimeter (stated, load-bearing)

**(operator-directed 2026-08-11.)** "Repel" means **defend your own systems** and run **deception
on your own machines** — nothing more. The fleet NEVER performs hack-back or any action beyond the
operator's own perimeter. A network-sentinel may *observe* a tailnet and *contain on hosts the
operator owns*; it may never reach out and act against a peer that is not the operator's. This
boundary is a hard invariant on every containment and deception slice, restated in each so it can
never be lost in a later refactor.

---

## (b) Domain and seam decomposition

Five domains, each with its trust boundary. The **seams** between them are where the design lives —
each seam is a place where a compromised component on one side must not be able to force the other.

### Domain 1 — Observation (per-instance, already shipped)

The existing read-only monitoring plane (Slices 1–6): collectors → hash-at-source facts → learned
models → the deterministic alert pipeline. Unchanged by this document. The fleet **consumes** its
output (signatures, incidents) and **feeds back** ratified signatures into its learned layer.

**Seam O↔F (Observation → Federation):** the *only* thing that crosses from a local instance to the
fleet is a **signature / incident fingerprint**, never raw logs. This is the AGENTS.md privacy
default (anonymized signatures, playbooks, fingerprints, outcome data; opt-in) made into a hard
seam. The hash-at-source discipline (Slice 1/3) is what makes this seam safe: what leaves the host
is already bucketed/hashed, so federation cannot become a raw-identifier exfiltration channel.
**Tension to carry (from Slice 7 §(a)):** containment needs the *raw* live target, but federation
must only ever see the *hashed* signature — the raw target is re-derived locally at execution time
and NEVER travels the federation seam.

### Domain 2 — Fleet Membership & Identity (the new crux)

Who is a legitimate instance; how a new instance is enrolled; how trust is bootstrapped and
revoked. This is **Hard Problem A** (§4) and the **MVP crux** — nothing else in the fleet is safe
until an instance's identity is unforgeable.

**Seam M↔everything:** every other domain depends on "is this message from a real, current fleet
member?" A single answer (fleet PKI + enrollment) serves membership, transport authentication, and
attestation. Designing it once, well, is the highest-leverage work in the whole plan.

### Domain 3 — Transport (how requests/signatures travel)

**(orchestrator refinement, operator-directed 2026-08-11: TRANSPORT is separate from AUTHORITY.)**
Transport is *how a message gets from A to B* — the SSH-key relay between the operator's own
machines, or a later push/backend channel. It is deliberately decoupled from authority: transport
proves *delivery*, never *approval*. A compromised transport can delay, drop, or reorder messages;
it must be structurally unable to **forge an approval** (that is the capability token's job, Domain
4). This separation is what lets the near-term SSH-relay and a later push backend be swapped without
touching the authority model.

**Seam T↔A (Transport → Authority):** the relay carries an approval *request* to the operator's
device and carries a signed capability token *back*. The relaying instance can read neither secret
nor mint either — it is a courier. (See §(c) MVS and Hard Problem C — key custody.)

### Domain 4 — Authority (proof the human approved THIS verb on THIS target)

**(orchestrator refinement + operator-directed 2026-08-11.)** The authority plane is a
**deterministic code gate** — never a model prompt or an `AGENTS.md` instruction. `AGENTS.md`
carries context and cannot *enforce* anything; enforcement requires a deterministic validating
process. The model may **propose** a containment action; only the deterministic gate **plus a valid
capability token** authorises execution. This is the fleet-scale restatement of the Slice 7 §(a)
"separate capability-holding helper" model.

**Key custody invariant (Hard Problem C):** the **signing key MUST NOT live on the monitored
machine.** The operator's **device** mints a **narrow, short-TTL, single-use** capability token
bound to (a) the specific approved decision, and (b) the **freshly re-resolved** target + verb at
execution time. The monitored instance only **relays** the request and **verifies-then-consumes**
(write-ahead) the returned token — it never holds minting authority. **Biscuits / macaroons** are
the candidate primitives precisely because they **only attenuate (narrow) offline, never widen**: a
compromised relay can make a token *more* restrictive but can never broaden its scope, forge a new
one, or replay a consumed one. (JWT is a weaker fit — it does not natively express offline
attenuation — but is named as a candidate for the simplest possible first relay.)

**Seam A↔E (Authority → Execution):** identical in shape to Slice 7 §(a)'s helper boundary — the
deterministic gate verifies the token, write-ahead-consumes the single-use nonce, then and only
then the capability-holding helper performs the mutating call. The fleet adds nothing to this seam
except that the token may now originate on a *different device* than the monitored host.

### Domain 5 — Governance (fleet-global blast-radius control)

Signature propagation policy, corroboration/ratification thresholds, the fleet circuit-breaker and
signature recall, Sybil-resistance, ratifier key management. This is where the "herd immunity"
reflex tier is bounded so it cannot become a "herd suicide" mechanism. It composes directly with —
and inherits — the expanded governance checklist the Slice 7 safety review already mandated (§(d)
item 9, Slice 7.6). This domain is **design-only in this document** and gated hardest of all.

**Seam G↔F (Governance → Federation):** governance decides *which* signatures may propagate, *how
fast* (staged/canary), and *how they are recalled*; federation is the mechanism it governs.

**Honest limit — recall has inverted failure semantics vs. approval (named 2026-08-11 review):**
Domain 4's fail-closed guarantee (a dropped/delayed transport message denies an approval, never
forges one) does **not** carry over to recall. For a circuit-breaker/signature-recall message, a
dropped or delayed delivery is fail-**open** — a node that never receives the recall keeps acting on
a bad signature. A future Domain-5 design must therefore name a fail-closed recall mechanism (e.g.
signatures carry a short auto-expiry and require active periodic renewal to stay valid, so silence
causes a signature to *lapse* rather than persist) rather than relying on recall messages
successfully reaching every node.

### Domain 6 — Software Distribution / Update Integrity (added 2026-08-11 review — the single
largest fleet-wide compromise vector)

**(review must-fix, resolved.)** None of Domains 1–5 protect against the channel that ships the
Descartes binary/config to every instance in the first place. Whoever controls the update channel
can rewrite the deterministic gate (Domain 4) and the capability-holding helper on **every host it
reaches, in one shot** — this bypasses all five drawn seams simultaneously, because a malicious
update doesn't need to defeat any seam's boundary; it ships as the code that *implements* the
boundary. This is the SolarWinds shape: a trusted distribution channel, once compromised,
compromises every downstream consumer at once, silently, without needing to breach Observation,
Membership, Transport, Authority, or Governance individually. It was absent from the original
five-domain decomposition and is the fleet's single largest compromise surface — larger than any
one instance being rooted, because it compromises the whole fleet at the moment of update, not one
host at a time.

**Seam D↔everything:** every other domain's guarantees implicitly assume "the code implementing
this seam is the code that was reviewed." Domain 6 is the seam that assumption depends on. If it is
compromised, that assumption is void fleet-wide in one step — a single point that can defeat
Domains 2–5 simultaneously, including rewriting the enrollment/PKI logic of Domain 2 itself.

**Not designed further here (future work, gates the whole fleet):** signed, reproducible builds
with a verifiable build provenance chain (hash-at-source discipline applied to *the binary itself*,
not just to observed facts); staged/canary rollout of updates with the same circuit-breaker/recall
shape Domain 5 needs for signatures; and — the hard part — some notion of update-signing key custody
that does not simply relocate the Domain-6 problem onto a single signing key with no ratifier-style
threshold protection (see Hard Problem E). No fleet slice past F1 should be read as "safe to
distribute widely" until this domain has its own dedicated design pass; see Hard Problem H.

### The one-paragraph seam summary

Observation emits **hashed signatures** (never raw data) → Federation propagates them under
**Governance** policy → Membership/Identity authenticates every participant → Transport carries
approval **requests** and **tokens** (but never forges approval) → Authority (a deterministic gate +
an off-host-minted, attenuation-only capability token) is the only thing that authorises Execution
(the capability-holding helper). Each arrow is a trust boundary designed so a compromise on one side
cannot force the other. **All of this assumes the code implementing the seams is genuine** — Domain
6 (Distribution/Update Integrity) is the seam that assumption rests on, and it is not yet solved.

---

## (c) The minimum valuable service (and what comes after)

**The smallest valuable thing is the multi-device / multi-user out-of-band approval-relay /
validation gateway.** Not the signature federation, not the reflex network, not execution — the
**relay that carries an approval request from a monitored machine to another of the operator's own
devices and carries a cryptographically sound approval back.** (operator-directed 2026-08-11:
Option 2's "deliver the approval request to ANOTHER of the operator's machines without a central
webservice" — e.g. an extremely limited, purpose-scoped SSH-key relay between the operator's own
machines — is exactly this.)

Why this is the MVS:

- It is the **highest-value seam** in the whole vision: it turns Slice 7's honestly-weak
  single-party time-delay (Option 3) into a genuine **multi-device** approval (Option 2) — an
  attacker who has rooted the monitored host still does not control the operator's phone/laptop.
- It **mutates nothing on its own** and needs **no reflex/federation/governance** machinery to be
  useful — so it can ship and prove value long before the dangerous tiers exist.
- It **forces the two hardest problems early, in their simplest form**: instance identity +
  enrollment (Hard Problem A — the two devices must know each other) and key custody (Hard Problem
  C — the minting key lives on the approval device, not the monitored host). Getting these right for
  *two of the operator's own machines* is the tractable beachhead for getting them right for a
  fleet.
- It composes cleanly with everything already shipped: the approval *decision* is still a
  `promotion-store.js`-shaped nonce/expiry/deny-by-default/`audit_transitions` record; the relay
  just changes *where the human sees it and where the token is minted.*

**Concretely, the MVS is two sub-slices under one gate — F2a then F2b (split 2026-08-11 review):**
the original single-slice framing bundled enrollment + mutual-auth + minting + verify-then-consume
together, which obscured *which part* actually carries value before any execution primitive exists.
Splitting names that value explicitly and lets the lower-stakes half ship and be reviewed before the
higher-stakes half opens Hard Problem C's minting/key-custody surface at all.

- **F2a — notification-only relay (the strictly smallest valuable slice; named first consumer).** A
  purpose-scoped, mutual-auth channel between two enrolled instances (the monitored host and the
  operator's approval device) over which the monitored host relays an approval **notification**
  (verb + hashed signature + freshly-resolved-target commitment) to the approval device — **no
  token is minted, nothing is authorised remotely.** Transport is the SSH-key relay (no central
  webservice). This has a concrete, named first consumer with **zero execution primitives wired**:
  it is a strictly-better delivery path for the recommend-only approvals that already exist today
  (the `promotion-store.js`-shaped promotion/tuning-change decisions, currently surfaced only via
  **local** notification per Slice 7 Option 3) — the operator sees and acts on the same local
  decision from a second device instead of only at the monitored host. Forces Hard Problem A
  (two-device identity/enrollment) in its smallest real form; does not touch Hard Problem C at all.
- **F2b — token minting (the authorisation path).** Adds the approval device **minting** and
  returning a narrow, short-TTL, single-use, attenuation-only capability token (biscuit/macaroon
  shape) that the deterministic gate on the monitored host verifies-then-consumes. This is what
  becomes the authorisation path the moment a real execution primitive (Slice 7.3, first realised
  in Slice F7) exists — it has **no independent consumer before that point**, which is exactly why
  it is a separately gated sub-slice rather than silently bundled into F2a. Forces Hard Problem C
  (off-host key custody, including the approval-device-compromise limit named there) in its
  smallest real form.

**Then, in order (each its own re-gated slice, §(e)):**

1. **MVS — the two-device approval relay, F2a notification-only then F2b token minting** (above).
2. **A third+ device / multi-device fan-out** — same primitives, N approval devices (still
   multi-*device*, not multi-*human*, per operator: the operator has many devices, not a second
   operator).
3. **Signature federation (read-only first)** — instances share **hashed** signatures/fingerprints
   into a shared layer under the O↔F seam; consumed only to *enrich local detection*, never yet to
   authorise action. This is the AGENTS.md L3 Federated Knowledge Layer, opt-in, privacy-default.
4. **Corroboration + ratification** — a signature gains standing when independently corroborated by
   ≥ threshold instances OR ratified by a designated authority. Still detection-only: it raises
   local *confidence*, not local *authority to act*.
5. **Multi-operator (n-of-x threshold)** — built *on top of* multi-device, only if/when a second
   human operator ever exists (enterprise-later per Slice 7 §(b) Option 1). Not near-term.
6. **The reflex tier (action-on-recognition with notification-not-confirmation)** — the herd-
   immunity terminus. Built **last**, behind the full Domain-5 governance model. Named, deferred,
   not designed here beyond its guardrails.

---

## (d) The hard problems, named honestly

These are not hand-waved. Each is a place the vision can fail catastrophically if it is faked.

### Hard Problem A — Instance identity + enrollment / trust bootstrap (fleet PKI) — THE MVP CRUX

Nothing in the fleet is safe until "is this a legitimate current instance?" has an unforgeable
answer. This is the **first** thing to solve and the hardest to retrofit.

- **The bootstrap paradox:** a brand-new instance (especially an ephemeral-VM one that lives for
  minutes) must be enrolled into the fleet's trust set *before* it has done anything to earn trust —
  and the very adversary we fear (an AI agent that roots hosts) would love to enroll a machine of
  its own. Enrollment must therefore be **operator-anchored**, not automatic: a new instance
  presents a key; a human-held (or hardware-held) root authority signs it into membership. There is
  no "trust on first contact" in an adversary model this strong.
- **Ephemeral churn:** VM/CI instances enroll and retire constantly. The PKI must issue short-lived
  member credentials and revoke them cheaply — long-lived certs on disposable hosts are a standing
  liability. This argues for short-TTL member certs + a fast revocation/recall path (which the
  Domain-5 fleet circuit-breaker also needs).
- **Reconcile with existing prior art:** `todos/2026-05-19-agent-delegation-identity-authority.md`
  already scopes explicit agent identity + scoped capability tokens (vs. ambient trust) as an open
  problem for inter-*agent* delegation. Fleet instance-identity and that agent-identity work MUST be
  designed together, not twice — the capability-token shape (biscuit/macaroon) is the same primitive
  both need.
- **Why the MVS de-risks it:** solving identity for exactly two of the operator's own machines
  (monitored host ↔ approval device) is the smallest real instance of this problem — a tractable
  beachhead that yields the primitives the full fleet PKI later generalises.

### Hard Problem B — Byzantine tolerance (assume ANY single instance can be turned)

The threat model is explicit and unusual: the adversary is **an AI-agent capable of rooting a
host**, which means it can compromise a Descartes instance *as thoroughly as it can compromise
anything else on that host.* The fleet therefore must **not** trust any single instance's word —
including its own report that it is healthy.

- **Mutual cross-instance watching / attestation** is the core resilience mechanism (operator's
  "host-watcher + tailnet-watcher next to each other"): instances attest to each other's presence,
  behaviour, and — as an explicit named limit, not yet solved — integrity. Presence/behaviour
  attestation (is the peer up, is it emitting the signals it should) is achievable with the
  primitives named in this document. Integrity attestation (is the peer's code and state actually
  what it claims) is **not**, absent a hardware root of trust: without one, a compromised instance
  can spoof normal telemetry and defeat behavioral attestation simply by replaying it. Cross-watching
  therefore reliably detects **silencing or absence**, and only weakly detects **lying while still
  present**. Hardware-anchored attestation (Secure Enclave/TPM-rooted measurement) is required future
  work before integrity attestation can be trusted — it is not already covered by "where possible."
  **Corrected 2026-08-11 review:** co-located peers (§(a)) with *separate* trust roots make the
  *mechanism* concrete (two independently-keyed processes attesting to each other) but do **not**
  survive the stated adversary at full strength — root on that host owns both peers' processes and
  keys simultaneously, so same-host separation defends only partial/process-level compromise.
  **Cross-host** watching, not same-host co-location, is what survives a root-level compromise.
- **A compromised instance must not be able to:** forge an approval (blocked by off-host key custody
  + attenuation-only tokens, Hard Problem C); widen a capability (blocked by biscuit/macaroon
  attenuation semantics); manufacture corroboration for a malicious signature (blocked by
  Sybil-resistance, Domain 5); or self-authorize a reflex action by "recognising" a signature it
  planted (this is the Slice 7 safety-review must-fix — the reflex path's consent-model degradation
  — carried forward verbatim as an unresolved bar the reflex tier must clear).
- **Honest limit — the false-accusation trust loop (named 2026-08-11 review, unaddressed):** the
  bullet above blocks a compromised instance from manufacturing corroboration *for* a malicious
  signature it planted, but nothing yet blocks a compromised instance from manufacturing
  **derogatory** attestation *against* a healthy peer — falsely reporting an honest neighbour as
  unhealthy, silenced, or malicious. This is weaponizable at the reflex tier (Slice F8) as
  fleet-assisted quarantine or kill of an *honest* host, and well before that as operator
  alarm-fatigue that trains the human to dismiss real alerts. Hard Problem E's Sybil-resistance work
  must extend to negative/derogatory attestations, not only positive corroboration — this is not
  designed here and must not be silently assumed solved by the positive-case machinery.
- **Honest limit:** cross-watching raises the cost of a single compromise but is not a proof of
  Byzantine *fault tolerance* in the formal sense. This document does not claim a consensus
  algorithm; it claims a **defense-in-depth watching mesh** and names formal BFT as future work if
  the fleet ever needs a hard guarantee rather than raised attacker cost.

### Hard Problem C — Key custody (signing key off the monitored machine)

Restated as the invariant it is: **the capability-signing key never lives on the monitored host.**

- The operator's **device** mints; the monitored instance **relays + verifies-then-consumes**. A
  fully-rooted monitored host therefore still cannot mint an approval — it can at most drop or delay
  the request (a denial, not a forgery), which fails *closed*.
- **Biscuit / macaroon** tokens are chosen because their offline caveats can only **narrow**: a
  relay can add "and only for target X in the next 30s," never remove a caveat, never widen scope,
  never mint fresh. This makes an honest courier and a malicious courier equally unable to escalate.
- **Write-ahead single-use consumption** (inherited verbatim from Slice 7 §(a) Cross-verb themes):
  the token/nonce is marked consumed **before** the mutating call, bound to one approved decision +
  the freshly re-resolved target+verb, so a crash cannot leave a replayable token and a valid token
  can never be replayed against a different target/verb.
- **Later hardening:** the mint step should move toward a **cryptographically secure capability**
  anchored in hardware where available (Secure Enclave / TPM / hardware key), and a backend
  (open-source acceptable) for multi-device/out-of-band push — so that **nothing on the possibly-
  compromised monitored machine can impersonate the user's authorization.** Candidate primitives:
  JWT (simplest), biscuits/macaroons (attenuation — preferred), backed by a hardware-held root.
- **Honest limit — approval-device compromise (named 2026-08-11 review, not yet mitigated):** §(a)
  places the operator's natural approval device on the **laptop** archetype — the same archetype
  this document itself calls out as intermittently connected, roaming networks, and most likely to
  hold real user credentials. Off-host key custody defends against a rooted *monitored* host
  stealing or forging a token; it does **not** defend against the **minting** device itself being
  compromised — malware co-resident with the signing key, UI spoofing of the approval prompt,
  consent-phishing (tapping "approve" on a request whose displayed target/verb has been
  misrepresented), or outright device theft. A compromised approval device can mint real,
  validly-scoped tokens for real attacker-chosen actions; nothing in the design above stops it.
  Mitigation direction (not designed here): bind minting to **user-presence/biometric confirmation
  of the specific decision** (not just device unlock), render the freshly-resolved target+verb on
  the approval UI itself so spoofing must also defeat the display path, and treat approval-device
  compromise as a **revocable event** via the fast enrollment/revocation path (Slice F3, Hard
  Problem A) rather than an unrecoverable one.
- **Honest limit — off-host custody does not protect the rooted host itself (named 2026-08-11
  review):** the local deterministic gate and token verification run **on** the possibly-rooted
  monitored host. A root-level attacker on that host needs no forged token to act locally — it acts
  directly, with or without the fleet. Off-host key custody's real guarantee is preventing
  **authority-laundering through the fleet** (a rooted host cannot leverage fleet trust to act
  against *other* hosts, or mint a credential that outlives the local compromise); it is not a
  guarantee that the rooted host itself is protected. This document should not be read as implying
  more local protection than the model supports.
- **Corollary — clock manipulation:** short-TTL tokens and write-ahead expiry are enforced against
  the monitored host's own clock, which a rooted host controls. TTL guarantees degrade together with
  the gate itself on a fully-rooted host — the same honest limit as above, restated for time rather
  than authority.

### Hard Problem D — Composition with the Slice 7 authority plane + its mandated governance

The fleet does not replace the Slice 7 plane; it **extends its perimeter** from one host to many.
Everything Slice 7 already mandated is inherited unchanged:

- The **deterministic code gate + separate capability-holding helper** (daemon/CLI cannot
  self-execute); leaning on OS primitives (sudo/polkit on Linux, privileged launchd+XPC with
  code-requirement checks on macOS) rather than a bespoke privilege mechanism.
- **User-configurable action→mechanism mapping with fail-closed defaults** (operator-directed): an
  unknown action or an unavailable mechanism → **DENY**; irreversible (`kill`) and self-lockout-
  capable (`block`/`revoke`) verbs demand the **strongest available channel** (multi-device/reflex-
  ratified, never local-only); deception/recommend-only need only the local channel. The full verb
  set is retained (kill/revoke/block/quarantine) — quarantine stays because other users run
  containers even though the operator does not (operator-directed).
- **Per-host opt-out toggle** for the whole containment capability where self-lockout cannot be
  tolerated (operator-directed §(d) item 4 resolution): a host may run observation + relay but be
  configured to hold **zero** execution capability.
- The **fleet-level governance** the Slice 7 safety review already required for the reflex tier —
  **staged/canary signature propagation, a fleet-wide circuit-breaker + signature recall/revocation
  that reaches nodes mid-rollout (not merely a per-node kill-switch), Sybil-resistance, and
  ratifier key-management** — is this document's Domain 5 and is carried forward as the non-
  negotiable gate on anything past detection-only federation.

### Hard Problem E — Sybil resistance + ratifier key management (the governance teeth)

Corroboration and ratification are today **assumed-honest and unsecured** (Slice 7 safety-review
finding). For the fleet:

- **Sybil resistance:** "≥ N independent instances corroborated this signature" is worthless if one
  attacker can spin up N instances. Corroboration weight must be anchored in the operator-anchored
  enrollment of Hard Problem A (a corroborating instance must be a *real, human-enrolled* member),
  not in raw instance count.
- **Ratifier key management:** if a designated authority can *ratify* a signature into
  action-authorizing standing, that ratifier key is the single most dangerous key in the system —
  its compromise turns the herd-immunity network into an automated global-action network for the
  attacker. It demands the strongest custody (hardware-held, ideally threshold/multi-party to
  ratify), and a recall path that can retract a ratified signature fleet-wide.

### Hard Problem F — "Conscript associative compute providers" (federation-participant model)

A later, governance-gated step: the fleet could recruit *external* participants (associative compute
providers) to contribute observation/corroboration/compute. This multiplies both the vantage-point
value **and** the Sybil / trust-boundary risk. It is named here as a **future, governance-gated**
direction only — it must not precede a solved Hard Problem A (enrollment) and Hard Problem E (Sybil
resistance), and it inherits the full Domain-5 governance bar. Do not design it further until the
operator explicitly green-lights that specific expansion; it is the point at which "defend your own
perimeter" (§(a) legal boundary) meets the most external surface and must be re-examined against
that invariant.

### Hard Problem G — Deception / honey-tokens (the shippable slice BELOW containment)

**(orchestrator refinement, operator-directed 2026-08-11.)** Deception is a **shippable slice that
sits below containment**: it mutates nothing on the real host, needs no authority plane, and stays
entirely within the operator's own perimeter (honey-tokens/honey-files on the operator's own
machines; Vault-Tec Vaults as natural honeypots). It is valuable on its own **and** it yields a
clean, high-confidence signal + a concrete target that later containment can act on. Because it is
low-risk and unblocks signal quality, it belongs **early** in §(e), ahead of any execution
primitive — a rare piece of the "teeth" story that can ship without the authority machinery.
**Corrected 2026-08-11 review:** "mutates nothing" overstates it — deception artifacts are real
writes (honey-files, honey-tokens) and the slice creates new alert/signal surface. The accurate
claim is **mutates no targets; writes only deception artifacts it creates itself** — and it clears
its own `doors-and-corners` pass like every other slice for exactly that reason (see §(e)).

### Hard Problem H — Software distribution / update integrity (added 2026-08-11 review)

See Domain 6 (§(b)) for the full statement. Restated here because every other Hard Problem in this
section implicitly assumes the code enforcing it is genuine: an attacker who controls the update
channel does not need to defeat Hard Problem A's enrollment, B's cross-watching, C's key custody, or
E's Sybil-resistance individually — it ships a build that already contains whatever bypass it wants,
to every enrolled instance at once. This is **not designed further in this document** (signed
reproducible builds, staged/canary update rollout, update-signing key custody are named as future
work in Domain 6) but it must be named as a Hard Problem in its own right, not folded silently into
"ship the code and hope the review caught everything": it is the largest fleet-wide compromise
vector in the whole decomposition, and no slice past F1 should be read as safe to distribute widely
until it has its own dedicated design pass.

---

## (e) Phased, locally-testable-first slice breakdown

Presented as a design sketch for **future** plans, not authorization to build any of it now. The
phasing mirrors the operator's stated order: **recommend-only via local notification NOW (mutates
nothing) → remote-device notification (via other registered Descartes instances over SSH, or a
centralized backend + push) → federated layer / comms / push backend → then "real teeth"
(execution).** Every slice — **including F1** — clears its **own** `doors-and-corners` pass **and** an
adversarial review at least as strict as the S3-priv `root_helper` bar; the reflex/federation tiers
additionally clear the expanded fleet-governance sign-off (Slice 7 §(d) item 9). **Corrected
2026-08-11 review:** F1 is not exempt — it plants artifacts on real hosts and creates new
alert/signal surface, so it needs the same doors-and-corners rigor as every other slice even though
it mutates no monitored targets and authorises no execution. Each slice is gated behind a
**dedicated, default-OFF switch**, never `learned.json`'s monitoring switch and never the Slice 7
containment switch — fleet participation is its own risk class.

- **Slice F0 — this document + operator resolution.** No code. Gate for everything below. Depends on
  the still-open Slice 7 scope decisions (container/quarantine, self-lockout tolerance,
  build-or-park), on operator sign-off for the fleet-governance model before any tier past
  detection-only federation, and — added 2026-08-11 review — on Hard Problem H (software
  distribution/update integrity) having its own dedicated design pass before any slice past F1 is
  read as safe to distribute widely.

- **Slice F1 — deception / honey-tokens (shippable, mutates no monitored targets, no authority
  plane).** Honey-tokens/honey-files on the operator's own machines (and Vault-Tec Vaults as
  honeypots) that emit a high-confidence local signal when touched. Own perimeter only (legal
  boundary invariant). Locally testable; zero execution capability; zero fleet dependency. Clears
  its **own** `doors-and-corners` pass like every other slice (corrected 2026-08-11 review — new
  artifact/alert surface even though it mutates no target). Ships value *and* produces a clean
  signal/target for later containment. (Hard Problem G.)

- **Slice F2a — notification-only relay (THE minimum valuable service; split from F2 per 2026-08-11
  review).** A purpose-scoped mutual-auth channel between the monitored host and the operator's
  approval device (SSH-key relay, no central webservice) that relays an approval **notification** —
  no token minted, nothing authorised remotely. Named concrete first consumer with zero execution
  primitives: remote-device delivery of the existing `promotion-store.js`-shaped recommend-only
  approvals (promotions/tuning changes), replacing local-only notification (Slice 7 Option 3) with a
  genuine second-device view of the same decision. Mutates nothing; touches no minting/key-custody
  surface. Forces Hard Problem A (two-device identity/enrollment) in its smallest real form.

- **Slice F2b — token minting (the authorisation path; split from F2 per 2026-08-11 review).** Adds
  the approval device **minting** and returning a narrow, short-TTL, single-use, attenuation-only
  capability token (biscuit/macaroon shape); the deterministic gate on the monitored host
  verifies-then-consumes it. Has **no independent consumer** before a real execution primitive
  exists (first realised at Slice F7) — gated as its own slice precisely because it opens Hard
  Problem C's minting/key-custody surface (including the approval-device-compromise limit named
  there) and is reviewed separately from F2a's lower-stakes notification relay. First slice needing
  the transport↔authority separation reviewed explicitly.

- **Slice F3 — multi-device fan-out.** Generalise F2a/F2b to N of the operator's own approval
  devices (still multi-device, not multi-human). Adds device-set enrollment/revocation — the first
  real exercise of fleet-PKI churn (Hard Problem A) beyond two nodes.

- **Slice F4 — signature federation, read-only.** Instances share **hashed** signatures/fingerprints
  into a shared layer (AGENTS.md L3, opt-in, privacy-default, O↔F seam). Consumed only to enrich
  local detection — **never** to authorise action. Introduces the transport for signatures but no
  new authority. Own doors-and-corners for the new external/shared surface.

- **Slice F5 — corroboration + ratification (detection-only standing).** A signature gains
  confidence when independently corroborated (≥ threshold, Sybil-resistant per Hard Problem E) or
  ratified (ratifier key management per Hard Problem E). Still raises local *confidence*, not local
  *authority to act*. First slice that needs Domain-5 governance primitives (thresholds,
  Sybil-resistance) even though it authorises nothing.

- **Slice F6 — cross-instance mutual watching / attestation (Byzantine-tolerance mesh).** Instances
  attest to each other's presence/behaviour, and — with the hardware-attestation limit named in
  Hard Problem B — integrity; co-located peers with separate trust roots (understood, per the
  2026-08-11 correction, as defending partial/process-level compromise, not a root-level guarantee —
  cross-host watching carries the Byzantine-tolerance claim); Vault-Tec Vaults, ring-fenced in their
  own trust domain (§(a)), used to deliberately turn an instance malicious and verify the mesh
  catches it. Detection/resilience only — no new mutation surface. (Hard Problem B.)

- **Slice F7 — first fleet-mediated execution, most-reversible verb, Vault-Tec-only.** The first
  slice that wires a real execution primitive to a *fleet-delivered* approval: the most reversible
  verb (a single VPN-peer `revoke` or an isolated-anchor `block`, per Slice 7 §(e) 7.3), executed
  **only inside a Vault-Tec Vault** on `big-cabbage`/`tart` (never the dev machine — no
  virtualization), behind the deterministic gate + off-host token + capability-holding helper + a
  self-lockout guard + dry-run + auto-revert. Full S3-priv-or-stricter review **plus** a dedicated
  review of the fleet approval path (does a rooted monitored host genuinely hold zero minting
  authority). This is the boundary where the fleet grows teeth; it grows them first where a mistake
  is free.

- **Slice F8 — the reflex tier (action-on-recognition, notification-not-confirmation) — LAST, and
  gated hardest.** The herd-immunity terminus: a corroborated/ratified signature authorises local
  reflex action with human **notification, not confirmation**. Requires the **entire** Domain-5
  governance model proven first — staged/canary propagation, fleet circuit-breaker + signature
  recall reaching nodes mid-rollout, Sybil-resistance, ratifier threshold key management, hard
  per-signature blast-radius caps, reversible-first, rate-limits, per-node kill-switch, full audit —
  **and** an explicit resolution of the reflex path's consent-model degradation (what unforgeable
  authority substitutes for the human-minted per-execution consent nonce when no human is in the
  loop, and why a compromised daemon cannot self-authorize by "recognizing" a signature). Eyes-open
  catastrophic-global-risk is accepted by the operator **only** with the strongest governance in the
  system; this document captures it, bounds it, and defers it. It is NOT implied to follow
  sequentially from F7 and requires its own explicit operator sign-off (Slice 7 §(d) item 9) before
  even a dedicated design-only follow-on plan is opened.

- **Slice F9 — conscript associative compute providers (external participants) — future, governance-
  gated.** Named only; must not precede solved Hard Problems A + E and must be re-examined against
  the "defend your own perimeter" legal boundary before any design work. (Hard Problem F.)

---

## Operator sign-off (2026-08-11) — folded

Single authoritative record of the operator's Slice 7 open-scope sign-off and the fleet expansion,
folded inline above via **(operator-directed 2026-08-11)** callouts. Design-only; directs future
design, authorises no code.

- **Verbs (§a):** kill, revoke, block, quarantine — ALL approved. Full set retained; quarantine
  kept because other users run containers even though the operator does not.
- **Authority (§b):** Option 3 (time-delay, single-party) is the near-term mechanism, delivered via
  **local notification**. Also design the option to deliver the approval request to **another of the
  operator's own machines without a central webservice** (purpose-scoped SSH-key relay — mechanism
  treated as a design option). Later: multi-device / out-of-band push with a cryptographically
  secure capability so nothing on the (possibly-compromised) monitored machine can impersonate the
  user's authorization (candidates JWT / biscuits / macaroons; needs a backend, open-source
  acceptable). Multi-operator (n-of-x) later, built on multi-device. **User-configurable
  action→mechanism mapping with sensible fail-closed defaults.**
- **AGENTS.md (§c):** AGENTS.md cannot enforce anything (context/instructions only). Enforcement
  requires a deterministic validating process ⇒ the authority plane is a **deterministic code
  gate**, never a model prompt/instruction.
- **(1) Execution:** yes — end-goal is real execution.
- **(2) Verbs:** keep the full set (do not drop quarantine).
- **(3) Second human:** none, but many devices ⇒ **multi-device** (not multi-human) is the path.
- **(4) Self-lockout:** **per-host opt-out toggle** — disable the capability on hosts where
  self-lockout cannot be tolerated.
- **(5) Emergency-bypass:** the federated immune system is the intended answer.
- **(6) Build or park:** **BUILD.** Phasing: recommend-only via local notification NOW (mutates
  nothing) → remote-device notification (via other registered Descartes instances over SSH, or a
  centralized backend + push) → federated layer / comms / push backend → then "real teeth"
  (execution).
- **(7) Doc scoping:** sufficient for now.
- **(8) Quarantine:** keep (operator not the only user).
- **(9) Federated immune system:** expanded into this "Descartes all the way down" fractal fleet
  vision — its own dedicated plan (this document); Slice 7 references it, does not absorb it.
- **(e) Phased breakdown:** agreed.
- **Vault-Tec sandbox:** run the mutating verbs ONLY inside dedicated, otherwise-useless VMs where
  the operator simulates odd/suspicious behaviours and monitors — a safe dev/validation harness for
  containment AND a natural honeypot; per-instance naming theme "Vault-Tec Vault." Constraint: the
  dev machine cannot run VMs (no Virtualization.framework) ⇒ Vaults run on the operator's other
  hardware / CI (`big-cabbage`/`tart`).
- **Orchestrator refinements folded:** separate TRANSPORT from AUTHORITY; signing key off the
  monitored machine (device mints a narrow/short-TTL/single-use token bound to the approved decision
  + freshly re-resolved target+verb; instance only relays + verifies-then-consumes, write-ahead);
  biscuits/macaroons because they only attenuate offline, never widen; the authority plane is a
  deterministic gate (model proposes, gate + token authorises); fail-closed action→mechanism
  defaults (unknown/unavailable → DENY; irreversible + self-lockout verbs demand the strongest
  channel; deception/recommend-only need only local); deception/honey-tokens is a shippable slice
  BELOW containment; legal boundary — "repel" = defend your OWN systems + deception on your OWN
  machines, NEVER hack-back beyond your perimeter.

---

## Summary for the operator

"Descartes all the way down" is a **fractal fleet of heterogeneous instances** — host,
network-sentinel, ephemeral-VM, bastion/gateway/router, laptop; general and specialised; co-located;
**watching each other** — whose value is the composition of vantage points and whose resilience is
mutual attestation under the honest assumption that **any single instance can be rooted by the same
AI-agent adversary the whole initiative fears.** The design decomposes into **six** domains
(Observation, Membership/Identity, Transport, Authority, Governance, and — added by the 2026-08-11
review — Distribution/Update Integrity, the seam every other domain's guarantees quietly depend on)
with the seams between them drawn so a compromise on one side cannot force the other.

The **minimum valuable service is the two-device approval relay, split into F2a notification-only
then F2b token minting** (split by the 2026-08-11 review so the value each half carries is explicit)
— the smallest thing that turns Slice 7's honestly-weak single-party time-delay into a genuine
multi-device approval. F2a alone mutates nothing and already has a named consumer (remote delivery
of today's recommend-only approvals); F2b adds the minting/key-custody surface once an execution
primitive exists. Together they force the two hardest problems (instance identity/enrollment and
off-host key custody) in their most tractable form. The **hard problems are named, not hand-waved,
and this review sharpened several of them**: fleet PKI/enrollment is the MVP crux; Byzantine
tolerance is met with a cross-watching mesh (raised attacker cost, honestly not formal BFT, and
honestly a cross-*host* claim — same-host co-location defends only partial compromise against a
root-level adversary); key custody keeps the signing key off the monitored machine with
attenuation-only biscuit/macaroon tokens, while honestly naming what it does *not* cover (a
compromised approval device, a rooted host acting locally without needing a forged token, and a
rooted host's own clock); Sybil-resistance must extend to false *derogatory* attestation, not only
manufactured corroboration; recall needs fail-closed semantics (auto-expiry), not reliance on
messages arriving; and the largest single fleet-wide compromise vector — the software update
channel that can rewrite every instance's gate at once — is now named as Domain 6 / Hard Problem H
rather than absent from the decomposition. The reflex "herd immunity" tier — the operator's
eyes-open, catastrophic-risk-accepted terminus — is bounded by the full Domain-5 governance model
the Slice 7 safety review already mandated and is built **last**, behind its own explicit sign-off.

Deception/honey-tokens ship early and cheaply (own perimeter only; mutates no monitored target, but
clears its own doors-and-corners pass like every other slice — it is not exempt); the dangerous
verbs run only in disposable **Vault-Tec Vaults** on the operator's non-dev hardware, ring-fenced
into their own trust domain when deliberately turned malicious for testing so a test signature can
never reach the real fleet. Nothing here is authorised to build: this is the serious investigation
the operator asked for, and every teeth-bearing slice remains behind its own doors-and-corners +
S3-priv-strict review, with the federated action tier behind the strongest governance in the
system.
