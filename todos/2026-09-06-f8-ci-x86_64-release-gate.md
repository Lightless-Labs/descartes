# F8: CI x86_64 test execution + exact-commit release gate

**Created:** 2026-09-06 (Astra audit finding F8)
**Status:** deferred — operator CI-stability review FIRST, then implement
**Area:** CI / release pipeline (not application code)
**Tracking:** `todos/2026-09-04-codex-project-audit-follow-up.md` (F8 disposition)

## Context

Astra's F8: Rust that is Linux/x86_64-only is currently guarded on this dev machine by cross-target
`cargo check --tests` (the dev machine has no Virtualization.framework — see
[[descartes-dev-machine-no-virtualization]]), with actual *execution* relying on CI. Two gaps:

1. **CI must actually EXECUTE the x86_64 test suite** (not just cross-check it), so Linux-only paths
   are exercised, not merely type-checked.
2. **The release gate must bind to an EXACT commit** — the artifact that ships is the artifact that
   passed, no drift between the green run and the released binary.

## Why operator review comes first

The macOS notarization pipeline has a **history of VM-pairing flakiness** (see
[[descartes-macos-notarization-status]] and the tart-ci / big-cabbage host notes). Adding an
x86_64 execution lane + an exact-commit gate touches the same CI substrate. Standing up a new
execution lane on a flaky substrate can turn a real green into intermittent red and erode trust in
the gate. So: **the operator reviews CI stability and sequencing before this is implemented** —
decide whether to harden the existing lane first, or stand the new lane up in parallel/non-blocking
until it is proven stable, then make it a required gate.

## Plan (after operator sign-off on approach)

1. Operator: CI-stability review — is the substrate ready for another required lane?
2. Add an x86_64 test-execution job (Linux) that runs the full suite.
3. Bind the release artifact to the exact commit that passed (exact-commit gate).
4. Make it a required check only once it is demonstrably stable (avoid a flaky required gate).

## Acceptance

- Linux/x86_64-only paths are executed in CI, not just cross-checked.
- The released binary is provably the exact commit that passed CI.
- The new lane does not reintroduce VM-pairing flakiness as a blocking gate.
