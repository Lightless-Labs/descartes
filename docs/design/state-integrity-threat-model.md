# State-Integrity Threat Model — daybreak-blue independent analysis

**Date:** 2026-09-04
**Source:** `gpt-daybreak-blue-latest` (frontier defensive-cyber, via codex), asked *unbiased* — given the four concrete tamper cases + the local-first/single-user/no-server constraints, with our own "attestation/signing slice" prior deliberately withheld and an explicit invitation to challenge the framing.
**Status:** design input to weigh, not a decision. Supersedes the coarse "trusted-same-user-state = one attestation slice" framing from the 2026-09-04 daybreak sweep resolution.

> Provenance note: this is one strong model's independent analysis of a threat model, not ground truth. Verify claims (esp. platform-API specifics) before building. It aligns with, and sharpens, the [[descartes-autonomy-doctrine-no-uac-gate]] direction; it does **not** touch the autonomy doctrine itself.

---

## The reframe (this is the important part)

**"State-file integrity" is not one problem — it is six**, and most controls solve only one:

| Property | Question |
|---|---|
| Byte integrity | Were these bytes modified? |
| History continuity | Was anything deleted, reordered, forked, rolled back? |
| Semantic authenticity | Did a *trustworthy collector* observe this, or did malware submit plausible lies? |
| Liveness | Is the detector still running and reporting? |
| Authority authenticity | Did a *human* really authorize this rule / decommission? |
| Baseline poisoning | Even perfect immutable storage only proves Descartes *recorded* observations — not that an attacker didn't spend two weeks teaching the model that malicious behaviour is normal. |

**The single most important move is not cryptography or filesystem cleverness. It is moving the trusted writer, the security-critical collectors, and the state transitions OUT of the compromised UID.** A hash chain, a Keychain/TPM key, and immutable flags each *fail to create a trustworthy writer*; they only raise cost or preserve evidence.

## Our four "deferred" items are mostly ARCHITECTURAL BUGS, fixable now — no attestation required

daybreak's strongest point: three of our four deferrals should first be treated as *design bugs that remove the integrity dependency*, not as storage-hardening waiting on an attestation slice. Doing this "reduces the amount of state whose integrity must be defended":

- **Canary clean-delete (our "B"):** a historical trip must **never** be reinterpreted through *current* manifest membership. Record `canary.trip_observed` as an event bound to the **manifest version/digest that applied at observation time**; make canary retirement a later **append-only event**, not a retroactive deletion. → resolves B *architecturally* (neither "reverse the pinned gate" nor "wait for attestation").
- **Fact-store #3 (clock-rollback):** wall time must **never** establish continuity. Use a strictly-increasing local **sequence + boot identity + monotonic time**; a future or regressed wall timestamp means `unknown/degraded`, **never `intact`**. → resolves #3 architecturally.
- **Learned nonce (F1):** a nonce stored *beside* the decision is **replay protection, not authority**. If the attacker can write both sides (or invoke the same approval interface), it proves nothing about a human.
- **Baselines/tuning:** should be **disposable caches** derived from authoritative evidence; their loss/alteration should trigger cold-start/degraded, **not** change historical truth.

> This means the canary clean-delete and fact-store #3 "design sign-offs" we deferred to you may have a *third* answer beyond "reverse the pinned test" vs "defer to attestation": **redesign so historical positive evidence is an append-only event that current config can't rewrite.** Still your call, but the option set is better than we framed it.

## Solution space — what's real vs. theater (same-user adversary)

- **Theater against the owner UID:** `0600`/ownership/ACLs, macOS `uchg`/`uappnd` user flags, an unkeyed local hash chain "marketed as attacker-resistant", an HMAC key stored beside the ledger, a background Keychain/Secure-Enclave key used as an *unrestricted signing oracle*, `chmod`/`O_APPEND`/`flock`, wall-clock rollback protection. Keep the cheap ones for *hygiene*, never claim them as security.
- **The real non-root boundary — privilege separation:** a **separate service UID** (`_descartes`) or a **minimal privileged system service** owning the authoritative state + performing security-critical transitions, with **root-owned signed code/config**, state outside the user's XDG dirs, and a **closed, typed RPC** (`observe_canary`, `retire_canary`, `commit_fact_batch`, `promote_rule` — never `append_arbitrary_json`). Node stays the UX/query client; inputs from it are explicitly *untrusted* and cannot establish high-assurance state. Linux: DynamicUser + `StateDirectory=` + `ProtectSystem=strict` + `NoNewPrivileges`; macOS: LaunchDaemon via `SMAppService`. This is the **first mechanism that meaningfully defeats the non-root same-user file attacker.**
- **Crypto, correctly scoped:** unkeyed hash chain → corruption detection only (same-user recomputes it). A **service-only signing key** (the service constructs the record; typed narrow RPC; user cannot request arbitrary signatures) → meaningful against the login UID. Roots only become root-resistant **once they leave the host.** Forward-secure signatures / Merkle trees improve proof efficiency, not trust — don't build custom early.
- **Hardware (macOS Secure Enclave / Linux TPM):** an *unattended daemon key* is still a signing oracle and doesn't know whether a fact is true. Valuable for **interactive, user-presence approvals** (canary retirement, rule promotion, disabling monitoring) — *not* continuous logging. App Attest is **not available on the macOS CLI** (`isSupported` false on Mac) — do not plan around it. A signed/notarized/Hardened-Runtime Rust helper raises the bar (blocks injection classes) but is not a root guarantee.
- **The real root boundary — an external witness (no cloud required):** an independently-controlled witness (another Descartes install, an operator NAS/home server, a restricted SSH/syslog append target, optional hosted service, or WORM object storage) that **holds prior checkpoint roots** and receives **heartbeats with an expected deadline**, alarming on: missed deadline, decreasing/duplicate sequence, a root that doesn't extend the previous root, invalid signature, changed device identity, stale attestation. A heartbeat *without* a deadline detects nothing. **Against full root, no purely-local software control gives a continuing guarantee** — the witness (holding prior commitments + missed-check-in alarms) is the minimum meaningful control; hardware attestation *strengthens what the witness receives*, it does not replace it.

## Meaningful guarantee by adversary

| Adversary | Meaningful minimum | Remains impossible |
|---|---|---|
| Same login UID, no escalation, service intact | Separate service UID / minimal system daemon; service-owned state; root-owned code; collection + transitions inside the service | Can't prove facts supplied by an untrusted Node client; local "approval" isn't automatically human-authentic |
| Same UID + ptrace/inject the user daemon | + different UID, non-dumpable/hardened service, closed RPC, rate limits, no attacker-chosen signing input | Any secret/policy living only in the compromised user process is lost |
| Administrative root, boot chain intact | Locally: HW non-exportable key / TPM counter preserves *limited post-recovery* evidence. **Operationally: an off-host witness is required.** | Root can stop the agent, feed false observations, suppress local notifications |
| Kernel/boot-chain compromise or physical owner | Independent off-host observer holding prior state | The host cannot truthfully attest arbitrary runtime observations about itself; no local file mechanism survives |

(macOS SIP / Linux Secure-Boot+lockdown+IMA narrow what "root" *means*, but Descartes state lives on the writable data volume — not thereby protected.)

## Build order daybreak recommends

1. **Remove mutable-current-state dependencies** (the architectural-bug fixes above) — *before* any cryptography. Closes several attacks without pretending storage is trusted.
2. **Optional "protected local mode":** the small Rust integrity/collector system service + closed typed RPC. Label the no-admin mode honestly: `integrity_level: unprotected_same_uid`.
3. **Segmented authenticated ledger** inside the service: strict sequence, prev-record hash, version refs, signed segment checkpoints, service-only key (SE-backed on macOS / software→TPM on Linux later). Don't claim root-resistance until roots leave the host.
4. **Optional witness protocol** (interchangeable: another install / NAS / SSH append / hosted / WORM). Send commitments + status by default, not raw logs; include a heartbeat deadline; report `witness_status: stale` / `root_resistant_integrity: unavailable`. **First meaningful root-level control.**
5. **Interactive hardware-backed authority** (Touch ID / Secure Enclave / FIDO2 second-device) for canary retirement, rule promotion, disabling integrity monitoring, resetting continuity.
6. **Hardware attestation LAST**, only after witnessing works (TPM quote + measured boot where supported; SE key protection on macOS with no platform-attestation claim; external verifier supplies freshness).

**Explicitly do NOT build:** an unkeyed hash chain sold as attacker-resistant; an HMAC key in the state dir; a background SE/Keychain signing oracle; a nonce-beside-rules "human auth"; reliance on chmod/`O_APPEND`/flock/`uchg`; wall-clock rollback protection; eBPF/Endpoint-Security to guard Descartes' own dir *before* privilege separation exists; TPM NV writes per fact; an App Attest dependency; blockchain/fleet consensus (one witness is enough); a large root Node daemon (keep privileged code small + Rust); any "root-proof" claim.

## Bottom line (daybreak, verbatim in substance)

> Descartes cannot meaningfully defend security-critical state from a deliberate same-user attacker while that state, its integrity metadata, its authorization records, and the code interpreting them all remain writable by that same OS user. A hash chain / Keychain / TPM key / immutable flag does not fix that.
>
> - **Non-root same-user:** the minimum meaningful control is a **separate OS principal** controlling the authoritative state and the security-critical transitions.
> - **Root:** no purely-local software control gives a continuing guarantee; the minimum is an **independently-controlled witness** holding prior commitments that treats missed check-ins as evidence. Attestation strengthens what the witness receives; it doesn't replace it.
>
> The current "same-user integrity is out of scope" position is acceptable **only for an explicitly-labeled zero-install/best-effort mode** — **not** a defensible default for detectors whose positive evidence and active policy can be silently rewritten by the exact attacker they purport to detect.

## How this changes our roadmap framing

- Our sweep-resolution note called the four deferrals "one trusted-state boundary → one attestation slice." daybreak says: **attestation is step 6, not step 1.** The ladder is *architecture fixes → privilege separation → authenticated ledger → witness → interactive HW approval → attestation.*
- **Steps 1 is cheap and autonomous-ish** (it's design/refactor of our own detectors — the canary-trip-as-event and monotonic-continuity changes), and it dissolves most of the four deferrals without waiting on any infrastructure.
- The honest-labeling point (`integrity_level: unprotected_same_uid`) is a small, high-integrity change we can make regardless.
