---
title: macOS Notifier Helper Delivery
created: 2026-07-08
status: pending
priority: high
area: notifications
kind: todo
owner: unassigned
related:
  - docs/plans/2026-07-08-macos-helper-delivery.md
  - docs/plans/2026-05-30-native-macos-notifications.md
  - todos/2026-05-30-native-macos-notifications.md
---

# TODO: macOS Notifier Helper Delivery

## Summary

Deliver the notarized `DescartesNotifier.app` release asset to end users. Milestone 1:
`descartes alerts notifications setup --channel native` downloads the version-matched
asset from the GitHub Release, verifies sha256 + staple + Gatekeeper, installs to a
stable per-user path, and persists the helper path in config. Milestone 2: add a
`descartes` formula to the existing `Lightless-Labs/homebrew-tap` (currently `middens`
only — Descartes is NOT on Homebrew today). See the plan for design bounds.

## Acceptance criteria

- [ ] `setup --channel native` on macOS installs the helper for the CLI's own version
      with checksum + staple + Gatekeeper verification, failing closed with an audit
      record on any error.
- [ ] Stable install path preserves bundle identity across CLI reinstalls; idempotent
      re-runs; atomic replacement on version change.
- [ ] Tests cover URL derivation, checksum verification, install/replace via injected
      fetcher, config persistence, and failure modes (no network, missing asset,
      checksum mismatch).
- [ ] Real-host validation: first-run Notification Center permission prompt attribution
      and persistence with the downloaded helper.
- [ ] Homebrew milestone decision recorded (ship Node-era formula now vs wait for Rust
      binaries), with tap-bump automation and token scoping noted if shipped.
