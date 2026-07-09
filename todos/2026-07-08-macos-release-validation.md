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
  - docs/reviews/macos-notifier-real-host-validation-template.md
  - docs/reviews/macos-notifier-first-tag-tap-bump-validation-template.md
  - docs/reviews/2026-07-09-macos-release-validation-blocker-audit.md
  - todos/2026-07-08-macos-helper-delivery.md
  - todos/2026-07-07-rcodesign-investigation.md
---

# TODO: macOS Notifier Release — Real-Host & First-Tag Validation

## Summary

The macOS notifier release pipeline is implemented and CI-validated through GitHub
Release publication (Buildkite #67 signed/notarized/stapled; #73 auto-published the
release). Local Homebrew install/linkage/helper packaging validation passed after tap
commit `75e886f`; see `docs/reviews/2026-07-09-homebrew-notifier-install-validation.md`.
Remaining release-readiness work is external: first-run TCC/Notification Center behavior
on a real Mac, daemon-context native delivery, first live next-tag tap-bump validation,
and token confirmation around that tag. Full executable steps:
`macos-notifier-release-validation-brief.md`; the
guided real-host helper runner is `scripts/validate-macos-notifier-helper.sh` (it
isolates Descartes XDG config/state/cache and prompts before resetting TCC or sending a
test notification unless `--yes` is passed). The tap token can now be preflighted before
cutting the next tag with `scripts/check-homebrew-tap-token.sh`; the check is read-only
and proves formula read access plus GitHub-reported push/write permission for
`Lightless-Labs/homebrew-tap`. For Part A, copy
`docs/reviews/macos-notifier-real-host-validation-template.md` into a dated review file
so every first-run, daemon-context, denied-path, fallback, and audit-record observation
is captured before closing the acceptance criterion. For Part B and token confirmation,
copy `docs/reviews/macos-notifier-first-tag-tap-bump-validation-template.md` into a
dated review file so the preflight, Buildkite release, GitHub Release, tap commit,
formula URL/sha updates, and Homebrew upgrade evidence are captured before closing those
criteria.

Local stop-condition audit: `docs/reviews/2026-07-09-macos-release-validation-blocker-audit.md`
records that the remaining acceptance criteria require external real-host, credential,
or next-tag evidence. If the app repo and tap repo are clean, the latest tag remains
`v0.0.47`, and no credential-bearing environment or suitable real-host evidence is
available, do not reclassify this todo as complete; wait for those external inputs.

## Acceptance criteria

- [ ] **Real-host helper (Part A):** on a Mac with no prior grant, `brew install
      lightless-labs/tap/descartes`, confirm `descartes` resolves to the brewed 0.0.47+
      CLI rather than an older npm-global shim, then `descartes alerts notifications setup
      --channel native --json` resolves the bundled helper with no flags
      (`resolution.macos_native_helper_available: true`, source `bundled`, path inside
      the brew keg), or the guided runner verifies the same plus signature/staple/Gatekeeper
      checks; the first-run Notification Center prompt appears attributed to
      *DescartesNotifier* (not Terminal); the notification displays; the grant persists
      across restart; daemon-context native delivery displays and records a local audit
      result (or the review clearly states any narrower harness used); the denied path
      fails closed with an audit record and the osascript fallback still works. Results
      recorded under `docs/reviews/`.
- [ ] **First-tag chain (Part B):** on the next `vX.Y.Z` tag, the Buildkite release job
      runs build → sign → notarize (Accepted) → staple → Buildkite artifacts → GitHub
      Release → **tap formula bump** (a `descartes: update to X.Y.Z` commit in
      `Lightless-Labs/homebrew-tap` with url version + both sha256 updated); and
      `brew upgrade descartes` pulls the new version + helper. This is the first CI run
      of the tap auto-bump.
- [ ] **Token confirmation:** before tagging, `scripts/check-homebrew-tap-token.sh`
      reports that the effective token can read `Formula/descartes.rb` and has
      push/write permission on `Lightless-Labs/homebrew-tap`; then the tap bump succeeds
      reusing `GITHUB_TOKEN` (no separate secret). If preflight or CI warns/skips on
      token access, resolve by widening that token or setting `HOMEBREW_TAP_GITHUB_TOKEN`
      in Doppler.
- [x] (Optional) **rcodesign spike** progressed or explicitly deferred — see
      `todos/2026-07-07-rcodesign-investigation.md` and
      `docs/research/2026-07-09-rcodesign-macos-notifier-release-research.md`.

## Notes

- Permission grants are identity-keyed; `tccutil reset Notifications
  com.bande-a-bonnot.lightless-labs.descartes.macos.notifier` to re-test first-run.
- Milestone 1 of the helper-delivery plan (in-CLI download flow) is deferred by operator
  decision in favor of Homebrew; not part of this validation.
