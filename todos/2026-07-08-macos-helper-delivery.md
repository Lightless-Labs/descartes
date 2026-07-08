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

Deliver the notarized `DescartesNotifier.app` release asset to end users via Homebrew
(operator decision 2026-07-08; the in-CLI download flow is deferred). Milestone 1: a
`descartes` formula in the existing `Lightless-Labs/homebrew-tap` installs the Node CLI
plus the helper resource inside the npm package tree at the path the CLI's
bundled-helper resolution already probes — no CLI code changes. Milestone 2: the
release job bumps the formula on each tag. See the plan for design bounds.

## Acceptance criteria

- [ ] `brew install lightless-labs/tap/descartes` on macOS yields a working
      `descartes` CLI and a stapled, Gatekeeper-accepted helper that
      `descartes alerts notifications setup --channel native` resolves without flags.
- [ ] Formula `test` block passes; helper bundle survives brew staging with signature
      and staple intact (`stapler validate`, `spctl --assess`).
- [ ] README documents brew as the macOS install path, including the migration caveat
      for prior `npm -g` installs sharing the Homebrew prefix.
- [ ] Real-host validation: first-run Notification Center permission prompt attribution
      and persistence with the brew-installed helper.
- [ ] Milestone 2 tap-bump automation implemented with a separately-scoped token, or
      explicitly deferred with manual bump steps documented in the release flow.
