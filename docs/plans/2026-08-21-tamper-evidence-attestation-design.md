# Tamper-evidence + off-host / hardware attestation vs. a root-capable local adversary — DESIGN-ONLY

**Created:** 2026-08-21
**Reviewed:** 2026-08-21 (adversarial plan gate) — PASS_WITH_CHANGES, 5 must-fixes folded.
**Status:** DRAFT — design-only. NO code, no new tool, no new `execFile` surface, no privilege
grant, no new store is prescribed to *ship* from this document. It is a threat-model +
mechanism-survey + recommended-direction + candidate-first-slice design pass, structured to be
picked up later as one or more dedicated implementation plans, each behind its **own**
doors-and-corners pass and an adversarial review at least as strict as the S3-priv `root_helper`
bar (`docs/reviews/2026-07-11-codex-gpt5.6-sol-review.md`). This document is not that sign-off.

**Origin / mandate:** `todos/2026-08-11-tamper-evidence-attestation-design.md` (direction +
literature only; explicitly "NOT the design — when picked up it gets its own dedicated plan, a
doors-and-corners pass, and an adversarial review, the same discipline Slice 7 went through"). The
motivating case is the canary v0 collector's own honestly-stated limit
(`docs/HANDOFF.md`, 2026-08-12 canary-tamper-posture note): canary v0 ships tamper-**detection**
(a manifest that fails to read/parse fails the decommission gate OPEN, so corrupting/deleting
`canaries.json` keeps established canaries alerting instead of going silent) but "cannot defend
itself against root on its own host."

**Inputs read (read-only; none edited by this doc):**
`todos/2026-08-11-tamper-evidence-attestation-design.md` (direction + literature);
`docs/plans/2026-08-11-descartes-fleet-federated-topology.md` (the fleet decomposition this design
anchors in — Domains 1–6, Hard Problems A–H, Slices F0–F9, the off-host key-custody invariant, and
the rooted-host-bypasses-the-fleet honest limit);
`docs/plans/2026-07-23-slice-7-authority-containment-plane.md` (the authority plane, the
capability-holding-helper / off-host-minting model, the hash-at-source-vs-raw-target tension, and
the rooted-host residual §(a) Cross-verb themes);
`docs/plans/2026-08-11-deception-canary-collector-impl.md` +
`tools/descartes-cli/src/canary-manifest.js` / `canary-baseline.js` (the shipped tamper-detection
floor — `read_ok` distinguishes a genuinely-empty manifest from an unreadable one; the
degrade-not-fabricate discipline this design must not regress);
`AGENTS.md` (Safety Invariants §149–156, Policy/Authority Plane §80–90, L3 Federated Knowledge
Layer §74–78 privacy default, Evidence Envelope §103–122);
`docs/HANDOFF.md` (live state: read-only monitoring plane, hash-at-source provenance, the
`learned.json` kill-switch precedent, the `descartes-root-helper` privileged-helper precedent, the
no-local-VM constraint). Literature named by the todo and surveyed below: Bellare–Miner
forward-secure signatures; Crosby–Wallach history trees / Certificate-Transparency-style verifiable
logs; CONIKS / Key Transparency; TPM 2.0 quote/attestation; Apple Secure Enclave + App Attest.

**Relation to the fleet plan:** this document is the **tamper-evidence + attestation deep-dive**
that `docs/plans/2026-08-11-descartes-fleet-federated-topology.md` gestured at but deliberately
left as future work — its Hard Problem B names "hardware-anchored attestation (Secure Enclave/TPM-
rooted measurement) is **required future work** before integrity attestation can be trusted." This
plan is that future work, scoped honestly. It **references and composes with** the fleet plan and
the Slice 7 plane; it does not supersede or absorb either.

---

## Problem statement + why now

A host-local alarm cannot defend itself against root on its own host. Canary v0 is the concrete
motivating case, but the limit is general across the whole read-only monitoring plane (Slices 1–6,
the process-lineage detector, the fact stores): an adversary with root on the monitored host can

- delete or overwrite the alarm's state (`canaries.json`, the fact stores, `provenance.json`),
- stop the daemon or corrupt the alert-delivery pipeline (the exact class the 2026-08-12
  daemon-wide delivery-abort fix touched),
- forge a schema-valid-but-false store (the `fact-store-completeness` todo names this: retention
  silently cleans corrupt history, so a novelty detector can end up trusting a store a root
  attacker rewrote to look complete), and
- silence the entire process tree.

Canary v0's "tampering is itself suspicious → fail the gate OPEN" is real, shipped hardening and it
raises the attacker's cost: a *clumsy* tamper turns into escalated alerting rather than silence.
But it is still a **host-local control** — a sufficiently careful root attacker stops the daemon
*and* suppresses the alert transport *before* the detection fires, and the host goes dark with no
local trace anyone off-host can see.

**Why now.** Three shipped facts make this the right moment to design (not build) the next layer:
(1) the read-only monitoring plane is mature and now has real state worth protecting; (2) the
Slice 7 authority plane and the fleet plan have already established the two load-bearing primitives
this design reuses — **off-host key custody** (the signing key never lives on the monitored host)
and an **off-host trust anchor** (the fleet) — so tamper-evidence does not have to invent them; and
(3) the fleet plan explicitly deferred hardware-anchored attestation to a dedicated pass and this
is it. The honest goal is stated up front and never oversold: **tamper-EVIDENCE plus an off-host or
hardware root of trust, not tamper-PREVENTION.** You cannot win purely locally — root defeats any
purely local verifier, full stop. What remains defensible is the *silence itself*: a missed
heartbeat / dead-man's-switch check-in, raised off-host where local root cannot reach it.

---

## §1 Threat model — what is and is NOT defensible host-locally

**The adversary (inherited from the fleet plan, Hard Problem B and the Slice 7 rooted-host
residual):** an attacker — human or AI-agent — that has achieved **root on the monitored host**.
Root can act directly, outside Descartes entirely: it does not need Descartes' helper, does not need
to forge a consent nonce, does not need to steal a token. Any guarantee that runs *on* the
monitored host degrades together with the host under this adversary.

Three concentric boundaries, from weakest to strongest, define what each mechanism can actually buy:

1. **Purely host-local software (canary v0 today).** Buys: raised cost against a *clumsy* or
   *time-pressured* attacker; tamper becomes an alert instead of silence *if the attacker trips it
   before disabling the transport.* Does NOT buy: anything against a careful root attacker who
   disables detection and transport atomically. **This is the floor and it is already shipped.**

2. **A hardware root of trust on the same host (Secure Enclave / TPM).** Buys: a signing key that
   *cannot be exfiltrated* even by root (hardware-enforced non-exportability), so evidence signed
   *before* compromise cannot be *forged* after compromise for a *past* timestamp (this is what
   forward-secure signatures + a hardware key together give); and, where a genuine remote-
   attestation path exists (App Attest on macOS 27+, TPM quote on Linux), a statement about the
   host's measured state that a *remote verifier* can check. Does NOT buy: protection of the *live*
   host. Root still controls the clock, controls what is fed to the signing oracle *now*, and can
   simply *stop asking* the enclave to sign. A hardware key makes **past** evidence unforgeable and
   makes **absence** detectable; it does not make the **present** trustworthy. (See §3.2 for the
   critical distinction between a *non-exportable signing key* and *third-party attestation of
   provenance* — the Secure Enclave gives the former for free and the latter only via App Attest.)

3. **An off-host trust anchor (the fleet / a dead-man's-switch verifier).** Buys: the only thing
   that survives a fully-rooted host — **detection of silence**. A verifier that is NOT the
   compromised host expects a fresh, authenticated check-in on a cadence; a missing OR failed
   check-in is itself the alarm, raised where local root cannot reach it. Does NOT buy: any
   guarantee about *what the compromised host reports while still present*. Cross-watching reliably
   detects **silencing/absence** and only weakly detects **lying-while-present** (fleet plan Hard
   Problem B, carried forward verbatim) — because a compromised-but-present host can replay normal
   telemetry. Closing "lying-while-present" is exactly where boundary 2's hardware attestation is
   required, and exactly why it is future work.

**The load-bearing honest limits, stated once, referenced throughout:**

- **H-LOCAL — root defeats any purely local verifier.** No host-local mechanism in this document
  claims otherwise. Every host-local slice is a cost-raiser and an evidence-preserver, never a
  guarantee.
- **H-CLOCK — a rooted host owns its own clock.** Short-TTL tokens, forward-secure key-evolution
  cadence, and freshness windows are all enforced against a clock the adversary controls once
  rooted. Freshness is only meaningful when evaluated by the *off-host* verifier against *its* clock
  (fleet plan Hard Problem C clock-manipulation corollary).
- **H-PRESENT — absence is detectable; live-lying is not (without hardware integrity attestation).**
  The dead-man's-switch is strong against silence and weak against a present liar. This is the
  boundary hardware attestation exists to push, and it is honestly future work.
- **H-DEVICE — the verifier/anchor can itself be compromised.** Off-host trust relocates the
  problem, it does not delete it (fleet plan Hard Problem C approval-device-compromise limit; §6).
- **H-BOOTSTRAP — authenticating the public key is the unsolved crux.** Every mechanism here
  inherits the fleet PKI / enrollment bootstrap paradox (fleet Hard Problem A) rather than solving
  it independently. Key Transparency / CONIKS is the reference literature, not a shortcut around it.

Anything a slice below claims must map to exactly one boundary and must not borrow strength from a
boundary it does not actually reach. That mapping is the adversarial-review bar for this whole line
of work.

---

## §2 Doors-and-corners / PREREQUISITES

This repo has been bitten by skipped prerequisites; attestation is a minefield of them (App Attest
returning `isSupported == false` on Macs for years despite a macOS-labelled API is the canonical
trap). Each mechanism's real external dependencies are called out explicitly. **A slice may not be
opened until its row here is satisfied or explicitly descoped.**

### 2.0 T1 — local tamper-evident log (no hardware, no fleet): prerequisites

**Added 2026-08-21 (adversarial plan gate must-fix).** T1 is the slice §4/§5 recommend building
*now*, precisely because it needs no hardware and no fleet — but "no hardware" is not "no
prerequisites," and the rule stated above ("a slice may not be opened until its row here is
satisfied or explicitly descoped") applies to T1 exactly as it applies to T2–T5. T1's row:

- **(a) Concrete emission source(s) mirrored.** T1.1 mirrors the daemon's alert-emission path —
  concretely, the `evaluateAndPersistAlerts` call site in `daemon.js` (backed by `alert-store.js`'s
  `alerts.json` persistence), which `daemon.js` already treats as the daemon-tick-wide critical path
  (the 2026-08-12 canary tamper fix hardened this exact call so one collector's store failure can
  never abort the whole `extraCandidates` array / the whole tick — see the comment at
  `daemon.js:604-610`). T1.1 mirrors newly-created/updated alert records observed at this point; it
  does **not** mirror every internal store write in the codebase, and a future slice widening the
  mirrored source set (e.g. to `artifact-audit-store.js` evidence-freeze records) needs its own
  doors-and-corners note, not silent scope creep.
- **(b) Fail-isolation from the primary emission path.** The mirror-append must be strictly
  best-effort and out-of-band with respect to the alert path it mirrors — see §5 T1.1 for the full
  specification and the required test. This is a MUST-FIX, not a nice-to-have: a subsystem meant to
  raise an attacker's cost must not itself become a new way to suppress or delay the alert it is
  protecting.
- **(c) Bounded growth / retention-with-checkpoint semantics.** An append-only chain grows without
  bound; T1 must define, before implementation, what happens at a size/entry-count cap — see §5
  T1.1 and §8 item 6. Unspecified at-cap behavior is a disk-exhaustion vector when the switch is ON
  and a degrade-not-fabricate risk if a naive implementation silently drops entries under pressure.
- **(d) The switch is itself a host-local file a root attacker can flip.** `tamper-evidence.json`'s
  default-OFF kill switch is, like `learned.json`'s, a plain file on the monitored host — a root
  attacker can set it OFF (or delete it) exactly as easily as they can delete `alerts.json` itself.
  T1's switch-OFF state is therefore **indistinguishable from "tamper-evidence was never enabled"**
  to anyone inspecting the host after the fact; T1 alone gives no way to prove the switch was ever
  ON. Only T2's off-host anchor (a missing heartbeat is itself evidence that the switch was flipped,
  or the daemon was stopped, or both) starts to close this gap — that is a boundary-3 property
  (§1), not a T1 one. This is an honestly-scoped boundary-1 limit to carry forward, not a defect to
  fix inside T1.

### 2.1 Apple Secure Enclave — non-exportable signing key (macOS, Tier-1 platform)

- **Platform capability:** Apple Silicon (or T2) Mac. `SecKeyCreateRandomKey` with
  `kSecAttrTokenIDSecureEnclave` produces a **P-256 EC key whose private half never leaves the
  enclave** — hardware-enforced non-exportability, confirmed: "there is no API to export it… the
  private key is never exposed to the application, the operating system, or the CPU." Key ops are
  ECDSA-sign and ECDH-keyagreement only (no RSA, no arbitrary curve).
- **OS primitive / language boundary — the first door:** the Secure Enclave is reachable only
  through `Security.framework` (Swift/ObjC). **Node has no binding.** Touching the enclave requires
  a small, **code-signed native helper binary** (Swift or a Rust crate over the Security C API) that
  the Node CLI invokes over a **fixed-argv, read-only allowlist** — a new native artifact, not a
  library import. This mirrors the `descartes-root-helper` precedent's shape (separate signed
  helper, minimal surface) and inherits its build/sign/notarize pipeline obligations.
- **Entitlements / signing — the second door:** SE-key creation for a CLI/daemon needs the binary
  **code-signed with a Developer ID** and, for keychain-backed key persistence across processes,
  the `keychain-access-groups` entitlement (and a stable provisioning identity). The repo already
  signs+notarizes the notifier (build #67 green, per auto-memory) so the pipeline exists, but the SE
  helper is a **new signed artifact** that must be added to it — a doors-and-corners item, not an
  assumption.
- **What it does NOT give (critical):** a raw SE key is a **signing oracle bound to this device**;
  it is **not** third-party attestation that a given signature came from a genuine enclave. A remote
  verifier handed an SE public key + signature learns "some holder of this key signed this," not
  "genuine Apple hardware in an untampered state signed this." Provenance attestation is App Attest's
  job (§2.2), which is a separate, harder prerequisite.

### 2.2 Apple App Attest / DeviceCheck — remote provenance attestation (macOS: newly-arrived)

- **The historical trap (must be stated):** `DCAppAttestService` carried `macOS 11.0+` API labels
  for years, yet **`isSupported` returned `false` on every Mac** (including Catalyst and iOS-on-
  Apple-Silicon apps). Treating the API label as capability is exactly the doors-and-corners failure
  this skill exists to catch.
- **Current state (WWDC 2026 / macOS 27):** Apple is **expanding App Attest to macOS 27**, with
  macOS-specific policy — each generated key requires **full security mode + System Integrity
  Protection enabled**, and adds key-access-control validation and launch-validation extensions.
  This is genuinely new and genuinely relevant, but it lands a **hard floor**: it requires
  macOS 27+, SIP on, full security mode, an **app identity from a real Apple Developer team**,
  Apple's **attestation servers** in the loop, and a **server-side verifier holding the challenge**
  (App Attest is a challenge/response the *server* generates and checks — there is no offline path).
- **Prerequisites, enumerated:** Apple Developer team + app identity; macOS 27+ target; SIP + full
  security mode; an off-host verifier service that mints challenges and validates the Apple-signed
  attestation object (this is a **new external service surface**, and it is the fleet's off-host
  anchor by another name — do not build a second one). **Descartes is a CLI/daemon, not an App
  Store app**; whether a Developer-ID-signed CLI can obtain an App Attest key on macOS 27 (vs. only
  a sandboxed, App-Store-distributed app) is an **open verification item** that must be confirmed on
  real macOS 27 hardware before any slice depends on it. Until confirmed: **App Attest is treated as
  aspirational, not available.**

### 2.3 TPM 2.0 quote/attestation (Linux)

- **Platform capability:** a real TPM 2.0 (discrete or firmware/fTPM) exposed at `/dev/tpm0` and,
  preferred, the kernel resource manager `/dev/tpmrm0`.
- **OS primitives / stack:** the TSS stack (`tpm2-tss`) and `tpm2-tools` (`tpm2_createak`,
  `tpm2_quote`, `tpm2_pcrread`, `tpm2_readpublic`). A quote requires an **Attestation Key (AK)**
  and a verifier that holds the **AK public key** (and, for genuine provenance, the manufacturer
  **EK certificate** chain). Measured-boot PCR values require **UEFI measured boot + a TPM event
  log** to be meaningful; without measured boot the PCRs attest little.
- **Permissions:** access to `/dev/tpmrm0` is typically root or the `tss` group — a
  privilege/permission door. Any `tpm2_*` invocation is **new `execFile` surface** and must go
  behind a **fixed-argv allowlist** (read-only quote/pcrread/readpublic subcommands only; never a
  key-clearing, NV-write, or hierarchy-changing subcommand — structurally incapable of a mutating
  TPM op), mirroring the WireGuard/`wg show` read-only-allowlist discipline exactly.
- **The dev-machine + CI trap:** the dev machine **cannot run VMs** (no Virtualization.framework —
  auto-memory `descartes-dev-machine-no-virtualization`) and has no assured usable TPM; **many CI
  runners and VMs lack a vTPM**, so a quote path cannot be iterated locally and cannot be assumed
  present in CI. TPM validation needs a **real Linux target with a TPM, or a CI image with a vTPM
  explicitly provisioned** (`big-cabbage`/`tart`), confirmed by a capability probe first — the exact
  discipline `scripts/probe-linux-ci-capability.sh` established for S3-priv. **No TPM slice may be
  opened before that probe passes.**

### 2.4 Off-host anchor / fleet dead-man's-switch (cross-cutting)

- **Depends on the fleet MVP crux, not on new invention:** the heartbeat's authenticity and the
  verifier's identity are the fleet plan's **Hard Problem A (instance identity + enrollment /
  fleet PKI)** and **Hard Problem C (off-host key custody)**. This design **must not** stand up a
  parallel PKI; it consumes the fleet's. If the fleet PKI does not yet exist, the honest first
  slice is a **single-verifier, single-operator-anchored** heartbeat (two of the operator's own
  machines — the same tractable two-node beachhead the fleet MVS uses), explicitly NOT a fleet.
- **External service surface:** a verifier that is reachably off-host. The fleet plan's Slice F2a
  (notification-only SSH-key relay, no central webservice) is the near-term transport; a hosted or
  mutualised community verifier (todo's business-model note) is later and needs its own review.
- **Fail-closed recall/lapse semantics:** the fleet plan's Domain-5 honest limit applies — a
  missed message must cause a signature/credential to **lapse** (auto-expiry + active renewal), not
  persist. The dead-man's-switch is the *good* side of this: silence is the alarm, so its default is
  already fail-closed. Any positive-attestation payload it carries must inherit the auto-expiry
  discipline so a replayed stale attestation cannot masquerade as fresh.

### 2.5 Key distribution / Key Transparency (cross-cutting, unsolved)

- **No new primitive to build here — a crux to inherit.** "Authenticate the public key" is the
  fleet MVP blocker (Hard Problem A, the enrollment bootstrap paradox). CONIKS / Key Transparency
  is the **reference architecture to read**, not a component to ship in an early slice. Trust-on-
  enrollment / operator-anchored PKI is the near-term answer for the two-node case; KT/CONIKS is
  the literature for how this scales to a fleet without a single trusted directory. **Any slice
  that would require solving key distribution at fleet scale is out of scope for the first buildable
  rungs and is gated on the fleet PKI existing.**

---

## §3 Mechanism survey — what each mechanism actually buys

Each subsection states the mechanism, the boundary (§1) it reaches, what it genuinely buys, and its
honest ceiling. Nothing here is recommended in isolation; §4 composes them.

### 3.1 Host-local tamper-detection — the shipped floor (boundary 1)

Canary v0's model: tamper is *itself* the signal; an unreadable/corrupt manifest fails the
decommission gate OPEN (`read_ok:false` never suppresses established canaries, and is kept distinct
from a genuinely-empty `read_ok:true` manifest so an empty file cannot fabricate "no canaries").
**Buys:** clumsy-tamper → alert. **Ceiling (H-LOCAL):** a careful root attacker disables detection
and transport together. This is the floor every stronger layer builds on top of — it is not
replaced, and this design must not regress its degrade-not-fabricate discipline.

### 3.2 Hardware root of trust (boundary 2)

Two genuinely different things are routinely conflated; the design must keep them apart:

- **A non-exportable signing key (SE `kSecAttrTokenIDSecureEnclave`; TPM AK).** Buys: even root
  cannot *exfiltrate* the private key, so it cannot *move* the signing capability off the box or
  forge signatures *elsewhere*. Combined with forward-secure key-evolution (§3.3), evidence signed
  and sealed *before* compromise cannot be forged *after* compromise. **Ceiling:** root can still
  ask the live oracle to sign whatever it wants *now* (H-PRESENT), and can stop asking it to sign at
  all (which the dead-man's-switch, §3.5, turns into the alarm). Sealed storage (bind data so it is
  usable only under an untampered measured state) is the TPM analogue and would let a state file be
  unreadable after a measured-boot change — valuable, but measured-boot-dependent (§2.3) and
  bypassable by an attacker who compromises *after* boot without changing PCRs.
- **Third-party provenance attestation (App Attest; TPM quote against an EK-cert chain).** Buys: a
  *remote verifier* can check "genuine hardware in an attested state made this statement" — the only
  thing that starts to close H-PRESENT (lying-while-present). **Ceiling:** requires the full §2.2/
  §2.3 prerequisite stack (Developer team + Apple servers + verifier for App Attest; TPM + measured
  boot + EK cert + verifier for TPM), is newly-arrived-or-unconfirmed on macOS, and still cannot
  attest *userspace application* integrity beyond what the measured state covers. This is the
  hardest, highest-value, latest mechanism — correctly future work.

### 3.3 Forward-secure signatures — Bellare–Miner (boundary 2, composes with 1/3)

The rigorous version of "sign it, then evolve/discard the key." The signing key is evolved on a
schedule into a new key and the **old key material is destroyed**; a key compromised *now* cannot
forge signatures dated to a *past* epoch, because the past epoch's key no longer exists anywhere.
**Buys:** past evidence (tamper-log roots, attestation records) becomes unforgeable-in-retrospect
even after a full key compromise — directly the operator's own instinct in the todo. **Composes
with §3.2** (evolve the key *inside* the enclave / behind the AK so the current key is also
non-exportable) and **§3.4** (sign each log root with the current epoch key). **Ceiling / doors:**
key-evolution cadence is enforced against the host clock (H-CLOCK) — the *off-host* verifier must
be the one judging "which epoch should be current by now," or a rooted host can freeze its own
epoch. "Discard the old key" must interact carefully with Descartes' existing audit/provenance
stores (which are *retained*): the forward-secure key protects the **log-root signatures**, not the
retained plaintext history — conflating the two would either break audit retention or leave the
plaintext forgeable. Library survey (crate availability, evolution cadence) is an implementation-
time item flagged by the todo, not resolved here.

### 3.4 Merkle / hash-chain tamper-evident logs (boundary 1 locally; boundary 3 when anchored)

Crosby–Wallach history trees; Certificate-Transparency-style verifiable logs. Each new
alert/audit/attestation entry extends an append-only hash chain / Merkle tree; the current **root**
summarizes the entire history.

**Sharpened 2026-08-21 (adversarial plan gate must-fix — the original text over-claimed what an
unkeyed local chain detects).** Deletion or in-place editing of an entry cannot be PREVENTED locally
(root can rewrite the whole file) — but it is not reliably DETECTABLE locally either, against an
adversary willing to redo the arithmetic. The hash scheme is **golden-pinned in source, not
secret** (§5 T1.0): a root attacker can recompute a fully self-consistent shorter or rewritten chain
over whatever entries they choose to keep, and a local `verifyChain` run against that rewritten file
correctly returns `consistent:true` — the file *is* internally consistent under the public scheme.
**This is not a `verifyChain` defect; it is the honest ceiling of an unkeyed local hash chain**, and
it is exactly why the mechanism is *tamper-evident*, not *tamper-proof*. What T1 alone DOES make
detectable is a *clumsy* edit that fails to redo every downstream hash (a flipped byte, a hand-edited
entry, a partial/crashed write) — that is boundary 1 (H-LOCAL), and it is the whole of what T1
standalone buys. A *careful*, correctly-recomputed adversarial rewrite becomes detectable only the
moment the local root is checked against an off-host copy of a *previously-published* root
(**T2, §3.5, boundary 3**): a rewritten history produces a root that does not extend the last
published one, and no valid consistency proof exists between them — that off-host comparison, not
the local chain by itself, is what turns "silently edited history" into "provably inconsistent
history." **Buys (T1 standalone, boundary 1):** clumsy/non-adversarial corruption and careless
single-entry edits become detectable; a careful adversarial rewrite does not, by design, until
anchored. **Buys (once anchored, T2, boundary 3):** an adversarial rewrite becomes provably
inconsistent against the last published root. **Ceiling:** T1 never claims, alone, to catch a
deliberate rewrite — that claim belongs to T2. It remains the natural first buildable rung because
the *local* half (an append-only hash-chained log with a deterministic root) is host-local,
read-only, deterministic, and fully unit-testable **without** any attestation hardware or fleet — it
is the substrate the anchor (T2) and the forward-secure signature (T3) later protect, not itself the
mechanism that defeats an adversary. **This is the §5 candidate first slice.**

### 3.5 Off-host anchoring + fleet dead-man's-switch heartbeat (boundary 3 — the only rooted-host survivor)

The local instance emits, on a cadence, an **authenticated heartbeat** to an off-host verifier
carrying (a) the current tamper-log root (§3.4), (b) optionally a fresh attestation (§3.2 when
available), and (c) a monotonic sequence/epoch. The verifier — NOT the compromised host — checks
freshness, root-consistency against the last anchored root, and (later) the attestation. **A missing
OR failed check-in is itself the alarm, raised off-host.** **Buys:** the only guarantee that
survives a fully-rooted host — *silence is detectable* (H-PRESENT's absence half). A root attacker
who kills the daemon and suppresses local transport still cannot suppress the *expectation* at the
verifier. **Ceiling:** detects silencing/absence strongly, lying-while-present only as strongly as
the attestation payload allows (weak until §3.2 hardware attestation is real); freshness is judged
against the *verifier's* clock (defeating H-CLOCK for the absence signal specifically); the verifier
itself can be compromised (H-DEVICE) and its identity/authenticity is the fleet PKI crux (§2.4).
The heartbeat is emitted under the **opt-in federation privacy default** — it carries only
**hashed** signatures and roots, never raw identifiers (AGENTS.md §78; §6 below).

### 3.6 Key distribution / CONIKS — the crux, not a slice (H-BOOTSTRAP)

"Authenticate the public key" is the same blocker as the fleet MVP. Near-term: trust-on-enrollment,
operator-anchored, for two of the operator's own machines. At fleet scale: CONIKS / Key Transparency
is the reference architecture (a verifiable, append-only, auditable key directory — itself a §3.4
tamper-evident log applied to *keys*). **Buys:** a principled answer to "how do I know THIS is really
the right public key" without a single blindly-trusted directory. **Ceiling / scope:** unsolved
here by design; inherited from fleet Hard Problem A; no early slice may depend on solving it at
fleet scale.

---

## §4 Recommended direction

**Build tamper-EVIDENCE bottom-up, host-local-first, and let the off-host anchor be the thing that
gives the local evidence its teeth — while being permanently honest that the ceiling is
"detect, don't prevent" and that only the off-host layer survives a rooted host.**

Layering, weakest/cheapest/most-buildable first:

1. **Keep the shipped floor (§3.1).** Canary v0's tamper-detection stays; nothing here regresses it.
2. **Build a local tamper-evident log (§3.4), host-local and offline first.** An append-only,
   hash-chained/Merkle audit+alert log with a deterministic, verifiable root and a consistency-proof
   checker. Fully unit-testable with zero hardware and zero fleet. **This is the recommended first
   buildable slice (§5).** It is read-only w.r.t. every existing target, adds no `execFile` surface,
   and is the substrate every later layer protects.
3. **Anchor the log root off-host via a dead-man's-switch heartbeat (§3.5), two-node first.** Emit a
   hashed, authenticated, monotonic heartbeat to *one* operator-anchored verifier (another of the
   operator's own machines), reusing the fleet plan's Slice F2a SSH-key relay transport and its
   deny-by-default/nonce/expiry authority shape. Silence-is-the-alarm is fail-closed by
   construction. **Not a fleet** — the tractable two-node beachhead.
4. **Add a hardware-backed signing key (§3.2 non-exportable half) + forward-secure evolution
   (§3.3).** Sign log roots with a Secure-Enclave / TPM-AK key evolved on an off-host-judged cadence,
   so past roots are unforgeable-in-retrospect. Gated on §2.1/§2.3 prerequisites (signed SE helper;
   TPM+probe).
5. **Add genuine remote provenance attestation (§3.2 attestation half; §2.2/§2.3).** App Attest on
   macOS 27+ / TPM quote on Linux, verified off-host. The only thing that begins to close
   lying-while-present. Latest, hardest, most prerequisite-laden — correctly last.
6. **Generalise the verifier to the fleet + Key Transparency (§3.5/§3.6).** Only once fleet Hard
   Problems A/E exist; inherits the full fleet governance bar.

Rungs 1–2 are buildable now with no new hardware, no new external service, and no new privileged/
`execFile` surface. Rungs 3+ each need their §2 prerequisite row satisfied and their own
doors-and-corners + S3-priv-strict review before opening.

**Corrected 2026-08-21 (adversarial plan gate must-fix — the original text here over-attributed
rung-3/rung-4 properties to rungs 1–2; see §3.4 and §5 T1.0 for the full correction).** Rungs 1–2
(T1) deliver the *substrate*: a deterministic, host-local, offline-verifiable log that detects
*clumsy, non-adversarial* corruption (H-LOCAL, boundary 1 only). Rungs 1–2 do **not**, by
themselves, make an in-place tamper detectable against a *careful* adversary — that requires rung 3
/ T2's off-host-anchored root — and do **not** make past evidence unforgeable-in-retrospect — that
requires rung 4 / T3's forward-secure signature (§3.3). Hardware attestation (rungs 4–5), while
highest-value, is where the prerequisites are heaviest and the platform support is
newest/unconfirmed — but its properties must never be borrowed backward onto rungs 1–2, which is
exactly the failure §1's closing paragraph forbids ("must not borrow strength from a boundary it
does not actually reach").

---

## §5 Candidate first buildable slice — T1: local tamper-evident log (read-only, offline, no hardware)

Locally-testable-first and read-only-first. T1 builds **only** the §3.4 local half: an append-only
hash-chained log with a deterministic root and a consistency/inclusion-proof verifier. No hardware,
no fleet, no heartbeat, no new `execFile`, no mutation of any existing target or store. Everything
below is a *design sketch for a future dedicated plan*, not authorization to build.

**Dedicated default-OFF kill switch.** The whole tamper-evidence subsystem is gated behind its
**own** dedicated, default-OFF switch (e.g. `tamper-evidence.json` enable flag), **never**
`learned.json`'s monitoring switch and **never** the Slice 7 containment switch — tamper-evidence
is its own risk class, exactly as the fleet plan mandates a per-slice dedicated switch. With the
switch OFF, T1 is inert: it logs nothing and exposes only a no-op verify path.

### T1 slice sequence (each its own commit, TDD, read-only)

- **T1.0 — hash-chain core (pure, no I/O).** A pure module computing entry hashes and the chained
  root over an ordered list of entries; a `verifyChain(entries)` that returns
  `{consistent, first_bad_index, root}` and **degrades to `unknown` (never fabricates `consistent`)**
  on a malformed/garbled entry. Deterministic; golden-pinned hash scheme (domain-separated, distinct
  from the canary/provenance hash schemes per the identity-hashing invariant).
  - **Files:** `tools/descartes-cli/src/tamper-log-chain.js` (new).
  - **Tests:** `tools/descartes-cli/test/tamper-log-chain.test.js` — golden root vector; append
    extends root deterministically; a flipped byte anywhere yields `first_bad_index` at that entry;
    an empty log yields a defined empty-root (NOT an error, and NOT indistinguishable from a
    tampered one — mirror canary's `read_ok` genuinely-empty-vs-unreadable discipline); a
    truncated/garbled entry degrades to `unknown`, never `consistent`; a **documented
    recompute-limitation test** (must-fix, 2026-08-21 adversarial plan gate) — a wholesale rewrite of
    the entry list (drop/reorder/replace entries, then correctly recompute every downstream hash
    under the same public, golden-pinned scheme) MUST verify as `consistent:true`, asserted as the
    expected, honest behavior with an inline comment explaining why (§3.4): an unkeyed local chain
    cannot detect an adversary willing to redo the arithmetic; only an off-host-anchored prior root
    (T2) can. This test exists so the limitation is never mistaken for a defect and never silently
    regressed into an over-claim.
  - **Adversarial-verify focus:** can `verifyChain` be tricked into `consistent:true` by a *partial*
    or *inconsistent* edit — entries changed without correctly recomputing every downstream hash
    (the *clumsy*-edit case T1.0 must catch)? Note the boundary explicitly, corrected 2026-08-21: a
    *wholesale*, correctly-recomputed rewrite over the same public scheme WILL and SHOULD verify as
    `consistent:true` locally (§3.4) — that is not a defect, it is the honest ceiling of an unkeyed
    local chain, and T1.0's job is to catch the *careless* case, not the *careful* one. Is the
    empty-log root distinguishable from a suppressed-to-empty log? Is the hash scheme
    domain-separated so a canary/provenance hash can never be replayed as a log-entry hash? Does
    every degrade path emit `unknown`/skip, never a fabricated `consistent`?

- **T1.1 — append-only store with atomic write + read-side integrity, isolated from the primary
  alert path.** Persist the chain to a single-writer JSON store templated on `promotion-store.js`
  (write-ahead/atomic-rename), single-writer discipline enforced by an **in-process serialized async
  queue** (a promise-chain mutex — every append awaits the prior append's completion; not a
  filesystem advisory lock), with a reader that returns `{root, read_ok, entries}` —
  **`read_ok:false` on any unreadable/corrupt/schema-invalid store, exactly like
  `canary-manifest.js`**, and a defined genuinely-empty (`read_ok:true`, empty) vs. unreadable
  distinction. The reader **never** rewrites or "cleans" the store (contrast the
  `fact-store-completeness` retention trap the todo names) — a corrupt store is surfaced as corrupt,
  not silently repaired into a plausible one.

  **Fail-isolation from the primary emission path (MUST-FIX, 2026-08-21 adversarial plan gate).**
  The concrete source T1.1 mirrors is the daemon's alert-emission path — the
  `evaluateAndPersistAlerts` call site in `daemon.js` (§2.0(a)) — via **observer/subscriber wiring
  added in `daemon.js` after that call returns**, never an in-line edit inside `alert-store.js` or
  the delivery call itself. The mirror-append is **strictly best-effort and out-of-band**: wrapped
  so that any thrown error, rejected promise, or write failure is caught locally and surfaced only as
  a **tamper-log health warning** (a new, separate status field — never a field on the alert record
  itself); it **must never** propagate an exception into the primary alert path and must never
  impose a blocking wait that could delay alert persistence or delivery. This generalizes to the
  mirror the identical discipline the 2026-08-12 canary fix established for `extraCandidates`
  (`daemon.js:604-610` — one collector's store failure must not abort the whole tick): here, the
  tamper log's own failure must not abort or degrade the alert it exists to protect. A full disk, a
  corrupt tamper store, or an attacker who wedges the tamper-log write must **never** become a new
  way to suppress or delay the primary alert/audit delivery.

  **Bounded growth / rotation semantics (MUST-FIX, 2026-08-21 adversarial plan gate; also §8 item
  6).** An append-only chain grows without bound; T1.1 must define, before implementation, what
  happens at a size/entry-count cap. Rotation, if implemented, must **checkpoint-and-anchor a chain
  root before truncating** so continuity across the rotation boundary is provable (the pre-rotation
  root is retained and the post-rotation chain's first entry references it) — **never a silent
  drop**. At-cap behavior must **fail closed**: surfaced as a `warning`/`unknown` health state, never
  a silent discard that a naive `verifyChain` run would read as plain `consistent`. The concrete cap/
  cadence/trigger is left to §8 item 6 (an explicit open decision), but the *shape* of any answer is
  constrained to the above — degrade-not-fabricate applies to log-cap behavior exactly as it applies
  to every other read path in this document.

  - **Files:** `tools/descartes-cli/src/tamper-log-store.js` (new); the mirror-append hook is new
    observer code added in `daemon.js` (after the `evaluateAndPersistAlerts` call, §2.0(a)) — it is
    read-only w.r.t. every existing store/behavior (the alert emission already happens; T1.1
    additionally mirrors it into the log; it does not change what is emitted, computed, or
    delivered).
  - **Tests:** `tools/descartes-cli/test/tamper-log-store.test.js` — atomic write survives a
    simulated crash mid-write (no partial/half-valid root); corrupt store ⇒ `read_ok:false` and the
    verify path reports `unknown`, never `consistent`; genuinely-empty ⇒ `read_ok:true` empty root;
    concurrent-append single-writer discipline holds (queued, not interleaved); the reader never
    mutates the file (assert byte-identical after read); **a forced tamper-log append failure
    (injected error/rejected write) leaves the primary alert emission byte-for-byte unaffected and
    still delivered** (MUST-FIX test — asserts fail-isolation, not just documents it); an
    at-cap/rotation test asserting the post-rotation chain proves continuity against the retained
    pre-rotation root and that at-cap never silently drops entries.
  - **Adversarial-verify focus:** can a crash leave a store that reads as a *valid, shorter* history
    (silent truncation looking consistent)? Can a corrupt store be mistaken for empty? Does any code
    path clean/repair a corrupt store (which would erase evidence)? Is the writer truly single-writer
    (queued) under the daemon's concurrency? **Can a tamper-log append failure ever throw into,
    block, or otherwise affect the primary alert write/delivery path?** (MUST-FIX focus) **Can
    reaching the size cap produce a gap that `verifyChain` reports as `consistent`?** (MUST-FIX
    focus — the at-cap analogue of T1.0's recompute-limitation question.)

- **T1.2 — deterministic `verify` CLI (read-only, gated).** A `descartes tamper-log verify [--json]`
  subcommand that reads the store and reports `{root, consistent|unknown, entry_count, read_ok}` in
  the Evidence Envelope shape (`status: ok|warning|unknown`, `review_hint`). Gated behind the
  dedicated default-OFF switch.

  **OFF-state shape, resolved (should-fix, 2026-08-21 adversarial plan gate — the design previously
  offered two unresolved shapes).** When the switch is OFF, the CLI emits `status:"unable"`,
  `review_hint:"tamper_evidence_disabled"` (not `"missing_permission"`, which misdescribes a
  disabled feature switch as a permission gap) and performs **no store read at all** — this holds
  identically whether or not a `tamper-evidence.json` store already exists on disk from a prior ON
  period. OFF means the CLI does not look, full stop, so a switch flipped OFF cannot be used to
  selectively read an existing store while suppressing new writes.

  Emits **no raw identifiers** — roots and entry digests only.
  - **Files:** `tools/descartes-cli/src/index.js` (dispatch wiring only — one new subcommand branch,
    disjoint from other slices' edits); `tools/descartes-cli/src/tamper-log-cli.js` (new).
  - **Tests:** `tools/descartes-cli/test/tamper-log-cli.test.js` — OFF ⇒ inert/no-op; ON + valid
    store ⇒ `consistent` root; ON + tampered store ⇒ `warning` + `first_bad_index`; ON + corrupt ⇒
    `unknown`, never `consistent`; JSON output carries no raw identifier field.
  - **Adversarial-verify focus:** does the CLI ever emit a raw path/host/pid? Does OFF genuinely
    disable (no store reads, no writes)? Does the tampered-store path degrade to `unknown` rather
    than either fabricating `consistent` or crashing (which a root attacker could weaponize as a
    denial)?

**What T1 explicitly does NOT do (scope fence):** no hardware key, no attestation, no heartbeat, no
off-host emission, no `execFile`, no privilege, no mutation of any target/credential/firewall, no
new external service. T1 is the substrate; its off-host anchoring (T2, the §3.5 heartbeat) is a
*separate* future slice with its own doors-and-corners pass (it opens the federation/transport
surface and must satisfy §2.4). T1 alone only reaches **boundary 1** (detects clumsy in-place
edits) — it is honest that its evidence gains teeth only once T2 anchors the root off-host.

### Sketch of subsequent slices (design only; each its own future plan + review)

- **T2 — off-host heartbeat / dead-man's-switch (boundary 3).** Emit the T1 root as a hashed,
  authenticated, monotonic heartbeat to one operator-anchored verifier over the fleet Slice F2a
  SSH-key relay; verifier raises silence/failed-check-in as the alarm off-host. Prereqs: §2.4.
  New surface: opt-in federation transport. Own doors-and-corners + review. **Privacy note flagged
  for T2's own future review (should-fix, 2026-08-21 adversarial plan gate):** a dead-man's-switch
  heartbeat necessarily carries a *stable* (even if hashed) per-instance identity, so the verifier
  can bind "this check-in" to "this expected host" and detect its silence. A stable hashed
  identifier is still a **linkable** host identifier under the L3 privacy default (AGENTS.md §78),
  not a fully-anonymous one — T2's own design and review must treat this as an explicit privacy
  consideration, not assume "hashed, never raw" fully dissolves the linkability concern.
- **T3 — hardware-backed signing + forward-secure evolution (boundary 2).** Sign roots with an
  SE-helper / TPM-AK key evolved on an off-host-judged cadence. Prereqs: §2.1 (signed SE helper) or
  §2.3 (TPM + probe). New surface: signed native helper and/or `tpm2_*` fixed-argv read-only
  allowlist. Own doors-and-corners + review.
- **T4 — remote provenance attestation (boundary 2, closes some of H-PRESENT).** App Attest
  (macOS 27+) / TPM quote, verified off-host. Prereqs: §2.2/§2.3 fully satisfied and confirmed on
  real hardware. Latest/hardest.
- **T5 — fleet verifier + Key Transparency (boundary 3 at scale).** Only after fleet Hard
  Problems A/E; inherits full fleet governance.

---

## §6 Safety Analysis — invariant-by-invariant

Each NON-NEGOTIABLE invariant, mapped to how this design upholds it. The adversarial-review bar is
that no slice borrows strength from a boundary it does not reach (§1).

- **Read-only by default; no mutating action without an explicit policy/authority gate; no silent
  privilege escalation.** T1 is read-only w.r.t. every existing target and store — it *mirrors*
  existing audit/alert emissions into an append-only log; it changes no behavior, mutates no
  credential/process/firewall, and adds **no** `execFile` and **no** privilege. T2+ that touch
  off-host transport or hardware helpers each require their own doors-and-corners pass and inherit
  the Slice 7 / fleet authority gates (deny-by-default, off-host key custody). No tamper-evidence
  mechanism authorizes any containment/mutation — this whole line of work is *evidence*, sitting
  **below** the authority plane, exactly like deception/canary. **Critically (must-fix, 2026-08-21
  adversarial plan gate), the mirror itself must never become a mutating hazard against the thing it
  observes:** T1.1's fail-isolation discipline (§2.0(b), §5 T1.1 — the mirror-append is out-of-band,
  best-effort, and cannot throw into or block the primary alert path) is part of this invariant, not
  optional hardening. A tamper-evidence subsystem that could suppress or delay the alert it protects
  would itself be a silent-denial vector — exactly the class of failure the problem statement above
  exists to defend against.

- **NEVER fabricate a security signal; degrade-not-fabricate.** The governing rule of every slice.
  `verifyChain` and the store reader emit `unknown` (never a fabricated `consistent`) on any
  garbled/corrupt/truncated input; a genuinely-empty log is kept *distinct* from a suppressed-to-
  empty one (canary `read_ok` discipline reused verbatim); a corrupt store is surfaced as corrupt,
  **never silently repaired** (the `fact-store-completeness` trap is explicitly avoided). Tamper is
  itself the signal (canary posture generalised): a failed verify degrades toward *alerting*, never
  toward a fabricated "clean." The design must never emit "attested/untampered" when evidence is
  missing — absence of proof is reported as `unknown`, and off-host silence is reported as the
  alarm, never as "assume fine." **This discipline governs claims, not only outputs (must-fix,
  2026-08-21 adversarial plan gate):** §3.4/§4/§5 T1.0 were corrected to state explicitly that T1's
  local hash chain does not detect a careful, correctly-recomputed adversarial rewrite — only a
  clumsy one — because claiming otherwise would itself be a fabricated security signal, just one
  asserted in prose rather than a JSON field. The at-cap/rotation behavior (§5 T1.1, §8 item 6) is
  held to the identical bar: reaching a size cap must fail closed (`warning`/`unknown`), never
  silently discard entries in a way `verifyChain` would read as `consistent`.

- **Identity hashed/bucketed at source, distinct golden-pinned schemes per domain; never store/emit
  raw identifiers.** T1's hash scheme is domain-separated and golden-pinned, **distinct** from the
  canary and provenance schemes (§5 T1.0), so no cross-domain hash replay is possible. The heartbeat
  (T2) carries only **hashed** roots/signatures, never raw pids/ports/usernames/hostnames/IPs/
  pubkeys/paths — it rides the AGENTS.md §78 opt-in federation privacy default. The hash-at-source-
  vs-raw-target tension the Slice 7 plane names does **not** arise here: tamper-evidence never needs
  a *raw live target* (that tension is unique to containment execution); it operates entirely over
  already-hashed digests and roots. This is a strictly-safer position than the containment plane.

- **Fail-closed alert namespaces; whole subsystem behind a default-OFF kill switch; the only LLM
  path is the opt-in/rate-limited/audited/`enableTools:false` wakeup — add no new LLM path.** The
  entire tamper-evidence subsystem is gated behind its **own dedicated default-OFF switch**
  (`tamper-evidence.json`-style), never `learned.json`'s and never the containment switch. It is
  **deterministic end-to-end** — hash chaining, verification, heartbeat emission, and off-host
  silence-detection are all deterministic code with **no LLM in any path**. The dead-man's-switch is
  fail-closed by construction (silence ⇒ alarm). No slice introduces, routes into, or leaks toward
  the LLM wakeup path; a tamper finding is a deterministic alert like every other L0 signal.

- **No new `execFile` surface without a fixed-argv ALLOWLIST — no shell, no interpolation of
  untrusted values, structurally incapable of privilege-adjacent subcommands.** T1 adds **zero**
  `execFile`. The only `execFile` surfaces anywhere in this design are deferred to T3+/T4 and are
  bound now: the Secure-Enclave path is a **code-signed native helper over a fixed-argv read-only
  allowlist** (mirroring `descartes-root-helper`); the TPM path is a **fixed-argv allowlist of
  read-only `tpm2_*` subcommands only** (quote/pcrread/readpublic — never a key-clear, NV-write, or
  hierarchy-change; structurally incapable of a mutating TPM op), mirroring the `wg show` read-only-
  allowlist precedent. No shell, no string interpolation of untrusted values into argv, on any path.

**Residual limits carried honestly (not defects — the point of the honest framing):** H-LOCAL (root
defeats any local verifier — T1 alone is boundary-1 only, including against a careful,
correctly-recomputed chain rewrite over the public golden-pinned scheme, §3.4), H-CLOCK (rooted host owns its clock —
freshness only meaningful at the off-host verifier), H-PRESENT (absence detectable, live-lying not
until hardware attestation is real), H-DEVICE (the verifier can itself be compromised — the fleet
Hard Problem C approval-device-compromise limit applies to the anchor too), H-BOOTSTRAP (public-key
authentication is the inherited fleet crux, not solved here). Every one is stated in §1 and none is
papered over by a slice claim.

---

## §7 FILE MAP (for later parallel partitioning)

Partition a future parallel implementation phase by **disjoint files**. Within T1 the slices are
mostly file-disjoint and can be parallelised, with **one serialization constraint** noted.

| Slice | Creates | Edits (shared — serialize) | Parallel-safe? |
|-------|---------|-----------------------------|----------------|
| T1.0 hash-chain core | `tools/descartes-cli/src/tamper-log-chain.js` · `test/tamper-log-chain.test.js` | — | Yes (leaf; no deps) |
| T1.1 append-only store | `tools/descartes-cli/src/tamper-log-store.js` · `test/tamper-log-store.test.js` | **`tools/descartes-cli/src/daemon.js`** (one observer call site, after `evaluateAndPersistAlerts`) | After T1.0 lands; `daemon.js` edit must serialize (see note) |
| T1.2 verify CLI | `tools/descartes-cli/src/tamper-log-cli.js` · `test/tamper-log-cli.test.js` | **`tools/descartes-cli/src/index.js`** (one dispatch branch) | CLI file yes; **`index.js` edit must serialize** |
| T1 kill switch | `tamper-evidence.json` schema/loader (co-locate with existing switch loaders) | possibly the shared config loader | Serialize if it shares the config-loader file |

**Serialization constraints (shared substrate):**
- **`tools/descartes-cli/src/index.js`** is the CLI dispatch table — every slice that adds a
  subcommand edits it. This is the one guaranteed collision point; the T1.2 `index.js` edit must be
  serialized against any other slice touching dispatch (exactly the Wave-partitioning discipline the
  2026-07-23 session used). The *logic* lives in the disjoint `tamper-log-*.js` files, so the
  `index.js` edit is a one-line branch and merges trivially if done last.
- **The dedicated kill-switch loader**: if `tamper-evidence.json` is loaded via a shared config/
  switch-loader module (as `learned.json` is), that loader file is a second serialization point.
  Prefer a standalone loader file for tamper-evidence to keep it disjoint (its own risk class ⇒ its
  own switch ⇒ ideally its own loader).
- **The audit/alert emission point** T1.1 mirrors into the log: **resolved to `daemon.js`'s
  `evaluateAndPersistAlerts` call site** (§2.0(a), §5 T1.1) — T1.1 adds an observer call there,
  *after* the primary write returns, wrapped per the fail-isolation must-fix (§5 T1.1); it does not
  edit `alert-store.js` itself. `daemon.js` is a large, frequently-touched file, so this one-line
  observer call-site addition is a second serialization point alongside `index.js`; land it as the
  last edit in the T1.1 commit and diff-review it in isolation.

**Later slices (own plans; listed for partitioning foresight):** T2 (`tamper-heartbeat.js` +
transport wiring — collides with fleet Slice F2a relay files; coordinate), T3 (`crates/` SE helper
and/or `tamper-tpm-quote.js` + fixed-argv allowlist — new native artifact, new build/sign pipeline
edit), T4 (attestation verifier — off-host service, collides with the fleet verifier). Each is
file-disjoint from T1 except through `index.js` and the shared switch loader.

---

## §8 Open decisions for the operator

Design-only; these gate whether/when any slice past T1 is opened. None is answered here.

1. **Build T1 now, or park the whole line behind the fleet?** T1 (local tamper-evident log) is
   buildable today with no hardware, no fleet, no new privilege — it delivers boundary-1 evidence
   and is the substrate everything else protects. But its *teeth* (boundary 3) require T2's off-host
   anchor, which the fleet plan is already designing. Build T1 standalone now, or wait and build the
   log + anchor together as a fleet slice? (Recommendation leans *build T1 now*: it is cheap,
   inert-by-default, and de-risks the substrate — but it is honestly boundary-1-only until T2.)

2. **Off-host anchor: reuse the fleet, or a dedicated tamper-verifier?** §2.4 says reuse the fleet
   PKI/transport (Slice F2a relay) rather than stand up a parallel one. Confirm the tamper heartbeat
   is a *consumer* of the fleet MVS, not its own second identity/transport stack.

3. **Business/participant model for the anchor (todo's note).** A solo operator cannot self-host a
   meaningful cross-host fleet. Which off-host anchor: (a) a second machine the operator already
   owns (two-node beachhead, buildable now); (b) a **mutualised open-source community fleet**; (c) a
   **commercial hosted verifier** (product-of-one)? This scopes alongside whatever business model the
   fleet plan adopts and must be decided before T2's anchor is more than the operator's own second
   box.

4. **Hardware attestation target platform + timing.** App Attest on macOS is only *arriving* at
   macOS 27 (SIP + full-security-mode gated, Developer-team + Apple-servers + verifier required, and
   **unconfirmed for a CLI/daemon vs. an App Store app**). TPM on Linux needs a real TPM + measured
   boot + a CI vTPM the dev machine cannot provide. Which platform leads T3/T4, and is a real
   hardware target (`big-cabbage`/`tart` with a provisioned TPM, or a macOS 27 machine) available for
   the capability probe *before* the slice is opened? (Hard prerequisite gate — no slice opens
   without the probe passing, per the S3-priv discipline.)

5. **Forward-secure key-evolution cadence + audit-retention interaction (§3.3).** The forward-secure
   key protects *log-root signatures*, not the *retained plaintext* audit/provenance history. Confirm
   the intended cadence and confirm that "discard the old key" is scoped to signing keys only and
   never deletes retained evidence — the two must not be conflated.

6. **Retention/rotation policy for the tamper log itself (added 2026-08-21, adversarial plan gate
   should-fix — related to item 5's retention question but distinct: item 5 is about the *signing
   key*'s lifecycle, this is about the *log file*'s).** §5 T1.1 sketches the required *shape* of an
   answer (checkpoint-and-anchor a chain root before truncating; at-cap fails closed as
   `warning`/`unknown`, never a silent drop that `verifyChain` would read as `consistent`) but does
   not pick a concrete cap, cadence, or rotation trigger. Confirm before T1.1 is implemented: what
   triggers rotation (size? entry count? time?), and how a rotated-away segment stays available for
   audit (moved, not deleted, until its own retention window — mirroring the existing fact-store
   retention discipline) without ever breaking the provable-continuity chain across the rotation
   boundary.

7. **Governance bar for the anchor becoming a fleet (T5).** At what point does the off-host verifier
   stop being "the operator's own second machine" and become a fleet requiring the full fleet-plan
   Domain-5 governance (Sybil-resistance, ratifier keys, fail-closed recall)? This is the same
   eyes-open catastrophic-risk boundary the fleet plan defers to its own strongest sign-off; tamper-
   evidence must not cross it silently by "just adding more verifiers."
