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

Add an explicit native macOS notification path so Descartes is not limited to the current `osascript` fallback. The first slice should be safe and incremental: support a configured helper path and checked-in Swift helper source, but do not make native notifications the default until packaging/signing and real-host behavior are validated.

## Scope

- Add `macos-native` notification channel plus a CLI-friendly `native` alias.
- Persist an optional native helper path in Descartes notification config.
- Execute the helper using fixed arguments only.
- Pass only bounded notification text and alert metadata.
- Add a Swift `UserNotifications` helper prototype source file.
- Keep local delivery audit for delivered/error/unavailable outcomes.

## Acceptance Criteria

- [x] Create dedicated plan and todo.
- [x] Add notification config support for native helper path.
- [x] Add CLI setup UX for native helper path.
- [x] Add native adapter fixed-command execution and fail-closed audit behavior.
- [x] Add Swift helper source prototype.
- [x] Add tests for native setup, missing helper, and fixed command invocation.
- [x] Document real-host validation gap and do not make native default yet.

## Follow-up

- [ ] Compile/sign/package the helper in a reproducible release flow.
- [ ] Validate first-run macOS permission prompt attribution on real hosts.
- [ ] Validate Notification Center display name/icon and denied-permission behavior.
- [ ] Validate daemon-context delivery behavior before making native delivery the default macOS desktop path.
