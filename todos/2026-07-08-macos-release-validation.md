---
title: macOS Notifier Release — Real-Host & First-Tag Validation
created: 2026-07-08
status: pending
priority: high
area: notifications
kind: todo
owner: unassigned
related:
  - macos-notifier-release-validation-brief.md
  - docs/plans/2026-07-08-macos-helper-delivery.md
  - docs/plans/2026-05-30-native-macos-notifications.md
  - todos/2026-07-08-macos-helper-delivery.md
  - todos/2026-07-07-rcodesign-investigation.md
---

# TODO: macOS Notifier Release — Real-Host & First-Tag Validation

## Summary

The macOS notifier release pipeline is implemented and CI-validated through GitHub
Release publication (Buildkite #67 signed/notarized/stapled; #73 auto-published the
release). Two validations remain that require a real environment, plus one optional
spike. Full executable steps: `macos-notifier-release-validation-brief.md`.

## Acceptance criteria

- [ ] **Real-host helper (Part A):** on a Mac with no prior grant, `brew install
      lightless-labs/tap/descartes` then `descartes alerts notifications setup
      --channel native --json` resolves the bundled helper with no flags
      (`resolution.macos_native_helper_available: true`, source `bundled`, path inside
      the brew keg); the first-run Notification Center prompt appears attributed to
      *DescartesNotifier* (not Terminal); the notification displays; the grant persists
      across restart; the denied path fails closed with an audit record and the
      osascript fallback still works. Results recorded under `docs/reviews/`.
- [ ] **First-tag chain (Part B):** on the next `vX.Y.Z` tag, the Buildkite release job
      runs build → sign → notarize (Accepted) → staple → Buildkite artifacts → GitHub
      Release → **tap formula bump** (a `descartes: update to X.Y.Z` commit in
      `Lightless-Labs/homebrew-tap` with url version + both sha256 updated); and
      `brew upgrade descartes` pulls the new version + helper. This is the first CI run
      of the tap auto-bump.
- [ ] **Token confirmation:** the tap bump succeeded reusing `GITHUB_TOKEN` (no separate
      secret); if it warned/skipped on token access, resolved by widening that token or
      setting `HOMEBREW_TAP_GITHUB_TOKEN` in Doppler.
- [ ] (Optional) **rcodesign spike** progressed or explicitly deferred — see
      `todos/2026-07-07-rcodesign-investigation.md`.

## Notes

- Permission grants are identity-keyed; `tccutil reset Notifications
  com.bande-a-bonnot.lightless-labs.descartes.macos.notifier` to re-test first-run.
- Milestone 1 of the helper-delivery plan (in-CLI download flow) is deferred by operator
  decision in favor of Homebrew; not part of this validation.
