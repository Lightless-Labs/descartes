---
title: macOS Notifier Helper Delivery
created: 2026-07-08
status: in_progress
priority: high
area: notifications
kind: todo
owner: unassigned
related:
  - docs/plans/2026-07-08-macos-helper-delivery.md
  - docs/plans/2026-05-30-native-macos-notifications.md
  - todos/2026-05-30-native-macos-notifications.md
  - todos/2026-07-08-macos-release-validation.md
---

# TODO: macOS Notifier Helper Delivery

## Summary

Deliver the notarized `DescartesNotifier.app` release asset to end users via Homebrew
(operator decision 2026-07-08; the in-CLI download flow is deferred). The local delivery
pieces are in place: the `descartes` formula in `Lightless-Labs/homebrew-tap` installs
the Node CLI plus the helper resource inside the npm package tree at the path the CLI's
bundled-helper resolution already probes, and the release job includes tap-bump
automation. The next-tag tap token can be checked ahead of time with
`scripts/check-homebrew-tap-token.sh`. This is not fully release-validated yet: the
remaining work is external validation on a real Mac and the next tagged release; see
`todos/2026-07-08-macos-release-validation.md` for executable steps.

## Acceptance criteria

- [x] Homebrew formula exists and locally verified install yields a working `descartes`
      CLI plus a stapled, Gatekeeper-accepted helper that
      `descartes alerts notifications setup --channel native` resolves without flags.
- [x] README documents brew as the macOS install path, including the migration caveat
      for prior `npm -g` installs sharing the Homebrew prefix.
- [x] Milestone 2 tap-bump automation implemented with fixture tests and documented
      fallback/manual bump behavior; it reuses `GITHUB_TOKEN` by default, with optional
      `HOMEBREW_TAP_GITHUB_TOKEN` for a narrower token. `scripts/check-homebrew-tap-token.sh`
      provides a read-only preflight for the token before the next tag.
- [ ] Real-host validation: first-run Notification Center permission prompt attribution
      and persistence with the brew-installed helper.
- [ ] First-tag validation: tap-bump automation runs successfully in CI on the next
      version tag and `brew upgrade descartes` pulls the new CLI + helper.
