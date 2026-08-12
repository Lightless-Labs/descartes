---
title: Tamper-evidence + attestation hardening against a root-capable local adversary (anchored in the fleet)
created: 2026-08-11
status: pending
priority: medium
area: security
kind: todo
owner: unassigned
related:
  - docs/plans/2026-08-11-descartes-fleet-federated-topology.md
  - docs/plans/2026-08-11-deception-canary-collector-impl.md
  - docs/plans/2026-07-23-slice-7-authority-containment-plane.md
  - todos/2026-08-11-deception-canary-collector.md
---

# TODO: Tamper-evidence + attestation hardening (root-capable local adversary)

**Origin:** operator design discussion, 2026-08-11, prompted by the canary collector's own limits.
**This todo is direction + literature only — NOT the design.** When picked up it gets its own
dedicated plan, a doors-and-corners pass, and an adversarial review, the same discipline Slice 7
went through before any code.

## Problem

A host-local alarm — the canary tripwire is the concrete motivating case — cannot defend itself
against root on its OWN host. An attacker with root can delete the canary, overwrite
`canaries.json` with a valid-but-empty manifest, or corrupt the baseline store. Canary v0 (see
`docs/plans/2026-08-11-deception-canary-collector-impl.md` and
`tools/descartes-cli/src/canary-manifest.js`/`canary-baseline.js`) mitigates this today by
**detecting** tamper rather than preventing it: a manifest that fails to read/parse fails the
decommission gate OPEN instead of silently suppressing established canaries, so corrupting or
deleting the manifest turns into continued/escalated alerting rather than silence — "tampering is
suspicious in itself." That is real, shipped hardening, but it is still fundamentally a host-local
control: it does not survive an adversary who can also stop the daemon, corrupt the alert pipeline
itself, or otherwise silence the whole process tree. True tamper-EVIDENCE plus off-host
verification is the deeper hardening this todo scopes for a future dedicated design pass.

## Two roots of trust that aren't the compromised host (combine them)

1. **Hardware.** TPM 2.0 (Linux) and Apple Secure Enclave (Apple Silicon — Descartes' Tier-1
   platform): measured state, sealed storage (data usable only under an untampered platform
   state), remote attestation. Investigate what's actually available/usable from each platform
   (TPM quote APIs on Linux; Secure Enclave / DeviceCheck / attestation primitives on macOS) and
   what a realistic sealed-storage story looks like for Descartes' state files.
2. **Off-host — the fleet.** The fleet (`docs/plans/2026-08-11-descartes-fleet-federated-topology.md`)
   holds authenticated public keys plus signature copies; the local instance performs an
   authenticated heartbeat / dead-man's-switch carrying a fresh attestation. A missing OR failed
   check-in is itself the alarm, raised off-host where local root can't reach it.

## Tamper-evidence primitives to evaluate

- **Forward-secure signatures** (Bellare–Miner) — the rigorous version of "sign it, then
  evolve/discard the key" so a key compromised NOW can't be used to forge signatures dated in the
  past. Maps directly to the operator's own instinct here.
- **Merkle / hash-chain tamper-evident logs** — Crosby–Wallach history trees; Certificate-
  Transparency-style verifiable logs. Deletion of a log entry can't be PREVENTED locally, but it
  becomes DETECTABLE as a gap once the log (or its root) is checked against an off-host copy.

## Key distribution — the crux

"Authenticate the public key" is the hard part (operator named this directly). It is the same
crux already named as the fleet MVP blocker: trust-on-enrollment, operator-anchored PKI
(`docs/plans/2026-08-11-descartes-fleet-federated-topology.md`'s enrollment-bootstrap-paradox
section). Any tamper-evidence scheme here inherits that bootstrap problem rather than solving it
independently — Key Transparency / CONIKS is the reference literature to read for how a
production system handles the analogous "how do you know THIS is really the right public key"
problem at scale.

## Honest framing

Not foolproof. You cannot win purely locally — root defeats any purely local verifier, full stop.
The point of this whole line of work is tamper-EVIDENCE plus an off-host or hardware root of
trust, not tamper-PREVENTION. Even a fully silenced host still leaves a signal: the silence
itself, i.e. a missed heartbeat/dead-man's-switch check-in at the fleet layer.

## Business-model / participant-model note

A solo operator or small user with only a handful of devices cannot self-host a meaningful fleet
for cross-host corroboration. Two paths to get that off-host trust anchor anyway:

- A **mutualised, open-source community fleet** (participants watch for each other).
- A **commercial hosted fleet** (a possible product-of-one).

This is the participant-model side of the earlier "conscript associative compute providers" idea
(see auto-memory `descartes-federated-immune-system-vision`) and should be scoped alongside
whatever business model the fleet plan eventually adopts.

## What a future design pass should investigate

- TPM 2.0 quote/attestation APIs (Linux) and Secure Enclave attestation primitives (Apple Silicon)
  — concretely, what Descartes could seal/attest today vs. what needs new plumbing.
  - Applicability boundary to flag explicitly: the dev machine cannot run VMs (no
    Virtualization.framework — see auto-memory `descartes-dev-machine-no-virtualization`), so any
    TPM/attestation validation needs a real or CI-hosted target, not local VM-based iteration.
- Bellare–Miner forward-secure signature schemes: available libraries/crates, key-evolution
  cadence, and how "discard the old key" interacts with Descartes' existing audit/provenance
  stores.
- Merkle/hash-chain tamper-evident log designs (Crosby–Wallach history trees; CT-style logs) for
  Descartes' own alert/audit trail, and how a local log root gets checked against an off-host
  (fleet) copy.
- Key Transparency / CONIKS as the reference architecture for "authenticate the public key" at
  fleet scale, and how it composes with the fleet PKI/enrollment anchor already named as the
  fleet MVP crux.
- Authenticated heartbeat / dead-man's-switch design: cadence, what a fresh attestation payload
  needs to contain, and how a missing-or-failed check-in gets raised as an alert AT THE FLEET
  LAYER (never locally, since local is exactly what's untrusted).
- Scope boundary: this is design-only, heavily governance-gated like Slice 7's federated-immune-
  system direction — no implementation before its own dedicated plan + doors-and-corners +
  adversarial review.
