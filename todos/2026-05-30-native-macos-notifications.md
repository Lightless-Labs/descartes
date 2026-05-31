---
title: Native macOS Notifications
created: 2026-05-30
status: in_progress
priority: high
area: monitoring
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-30-native-macos-notifications.md
  - docs/plans/2026-05-28-monitoring-alerting.md
---

# TODO: Native macOS Notifications

## Summary

Add an explicit native macOS notification path so Descartes is not limited to the current `osascript` fallback. Users must not have to build the helper. The product path is a release-built helper delivered only through macOS-specific packaging or an explicit macOS setup/download flow; the configured helper path is only a development/advanced override until packaging/signing/notarization and real-host behavior are validated. Do not put a macOS `.app` payload in Linux/cross-platform installs.

## Scope

- Add `macos-native` notification channel plus a CLI-friendly `native` alias.
- Resolve a bundled native helper automatically when present.
- Persist an optional native helper path in Descartes notification config for development/advanced overrides only.
- Execute the helper using fixed arguments only.
- Pass only bounded notification text and alert metadata.
- Add a Swift `UserNotifications` helper prototype source file.
- Use bundle identifier `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier` for the native notifier bundle.
- Keep the notarized `.app` out of the cross-platform npm package; use macOS-specific release/Homebrew/setup delivery.
- Keep local delivery audit for delivered/error/unavailable outcomes.

## Acceptance Criteria

- [x] Create dedicated plan and todo.
- [x] Add notification config support for native helper path.
- [x] Add CLI setup UX for native helper path as a development/advanced override.
- [x] Add native adapter fixed-command execution and fail-closed audit behavior.
- [x] Add Swift helper source prototype.
- [x] Add tests for native setup, missing helper, and fixed command invocation.
- [x] Document real-host validation gap and do not make native default yet.

## Follow-up

- [x] Add maintainer-only scripts to compile an app bundle, sign/notarize/staple/verify it, and keep generated artifacts out of git/package output.
- [x] Exclude native macOS helper sources/artifacts from the cross-platform npm package metadata so Linux installs do not carry the `.app`.
- [ ] Wire real release credentials/CI or maintainer release process for signing/notarization.
- [ ] Verify the release artifact passes Gatekeeper/notarization checks on a clean macOS host.
- [ ] Validate first-run macOS permission prompt attribution on real hosts.
- [ ] Validate Notification Center display name/icon and denied-permission behavior.
- [ ] Validate daemon-context delivery behavior before making native delivery the default macOS desktop path.
