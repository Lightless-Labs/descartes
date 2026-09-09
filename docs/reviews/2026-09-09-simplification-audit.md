# Simplification audit (gpt-6-astra)

**Date:** 2026-09-09
**Reviewer:** `gpt-6-astra` (via codex, read-only, high effort), grounded against the working tree.
**Status:** advisory — recommendations to verify before acting, **not adopted**. Nothing here is a
security finding; the trust machinery was found to earn its complexity.
**Constraint given:** a "simplification" that collapses an honest-uncertainty distinction, removes a
fail-closed guard, or weakens a security/provenance check is a regression, not a simplification —
those were to be flagged off-limits, not proposed.

> Headline: the best opportunities are **duplicated mechanics, unused scaffolding, and accumulated
> implementation history** — not the defensive core. Claims below are Astra's caller-tracing; verify
> each (esp. the "only test callers" / "unreachable from CLI" ones) before removing anything.

## Ranked opportunities

1. **Unused peer-signature-store machinery** (`peer-signature-store.js:149`). `applyPeerIdentityObservation`,
   `reconcilePeerSignatures`, normalization, store I/O have **only test callers**; production uses
   `computePeerIdentitySignature` (`fact-translators.js`) + the presence-window constant
   (`incident-correlation.js`). Keep the hash contract + constant; remove/relocate the unconnected
   store lifecycle. Low risk after checking external imports. **Preserve the exact hash domain,
   delimiter, field ordering, golden fixtures** — changing those resets identity.
2. **Dev-history comments → current contracts** (`index.js:138`, `daemon.js:142`, …). "Slice X was
   additive"/reviewer-name commentary; some now **inaccurate** (the learned-dispatch "currently just
   mine" comment despite the branches below it; `fact-store.js:207` contrasts atomic retention with a
   direct history-store write, though history retention now uses atomic rename too). Editorial pass —
   present-invariant beside each branch, historical rationale linked once. Cosmetic, very low risk;
   **keep** explanations of genuinely surprising defenses.
3. **13 exact copies of `readJsonFile`** (`constraint-store.js:149` + 12 others: promotion, tuning
   authority, provenance, baseline stores). Same read/parse with a `{parsed, missing, corrupt}`
   contract. Consolidate to **one** small reader; leave schema/quarantine/defaults/authorization in
   each caller. Low risk. **Do NOT** generalize into a universal store abstraction — fact-ledger and
   strict budget-audit reads have materially different contracts.
4. **3 copies of census grouping + first-appearance detection** (`process-lineage-baseline.js:223`,
   `persistence-baseline.js:193`, `service-baseline.js:264`). Share the two pure operations (group by
   explicit fact names; first-appearance by explicit thresholds), keep thin domain wrappers.
   **Moderate risk** — preserve contradictory-marker handling, markerless/unknown distinctions,
   ordering, freshness, minimum-history.
5. **2 implementations of deterministic notification delivery** (`alert-intelligence.js:550` &
   `:871`). Session-family + metric-fallback each re-implement dependency loading, sequential
   delivery, per-alert isolation, `fired`/`failed` accounting. Keep both entry points + gates; call
   one internal helper. Low–moderate risk — preserve namespace opt-out, corrupt/unavailable-config
   suppression, per-alert failure isolation (see `test/alert-intelligence.test.js:1800`).
6. **Parallel detector-wiring lists in the daemon** (`daemon.js:838`). 12 producer vars, then a second
   list repeating identities/args/labels/fallbacks. One ordered list of named closures + a loop
   through `safeCandidates`. Moderate risk — preserve execution order, per-detector failure
   boundaries, the `evaluateAlerts:false` no-I/O contract, the separate containment phase. (No plugin
   registry / class hierarchy.)

## Load-bearing complexity to KEEP (explicitly not simplify)

- **Fact integrity/completeness** (`fact-store-integrity.js:268`, `fact-store-completeness.js:44`) — as
  explicit as the domain requires; pending/committed writes, digest verification, loss accounting, and
  intact/degraded/unknown are distinct evidence claims.
- **Different baseline policies** (`peer-baseline.js:407` spike-vs-drop; `canary-baseline.js:703`/`:759`
  trip-vs-vanished) — a universal pipeline would erase real distinctions (a capped count supports a
  spike lower-bound but not a drop).
- **Private harness + triage guards** (`pi-harness.js:461`) — resource isolation, evidence registry,
  forced tool-disabling for alerts, triage retry/fallback are purposeful; no compelling structural win.

## Systemic themes

- **Share mechanics without sharing authority.** Copied parsing/transport is not required by separate
  hash domains / schemas / approval stores; and similar-looking recovery branches are not
  interchangeable trust policies.
- **"Additive-only" development left permanent scaffolding.** Do occasional consolidation passes after
  milestones — remove historical comments + repeated wiring while keeping the tested boundaries.
- **Separate experimental code from the live surface.** `model-ir.js` and `model-ladder.js` are
  (per Astra's import tracing) unreachable from the CLI entry point — test-only, headers identify an
  offline spike. Supports relocating them outside the shipped runtime tree — **not** declaring their
  defensive checks unnecessary.
