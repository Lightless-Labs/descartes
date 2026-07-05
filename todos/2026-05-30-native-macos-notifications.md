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

Add an explicit native macOS notification path so Descartes is not limited to the current `osascript` fallback. Users must not have to build the helper. The product path is a release-built helper delivered only through macOS-specific packaging or an explicit macOS setup/download flow; the configured helper path is only a development/advanced override until packaging/signing/notarization and real-host behavior are validated. Do not put a macOS `.app` payload in Linux/cross-platform installs. Release automation should assume a tag-triggered Buildkite pipeline rather than GitHub Actions; GitHub Releases may still be used as the artifact publication surface.

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
- [x] Add a tag-triggered Buildkite release pipeline/script for signing/notarization inside Tart using ephemeral guest-local keychain material.
- [x] Replace the incorrect direct signing-secret passthrough approach with a scoped Doppler-token bootstrap pattern:
  - `github.com/Lightless-Labs/tart-ci#v0.2.2` accepts `doppler_token_secret`;
  - Buildkite secret `DOPPLER_DESCARTES_PRD_NOTARISATION` is exposed to the Tart guest as `DOPPLER_TOKEN`;
  - guest release script fetches only required release keys from Doppler project `lightless-labs-descartes`, config `prd_notarisation`: `MACOS_DEVELOPER_ID_CERT_P12_BASE64`, `MACOS_DEVELOPER_ID_CERT_PASSWORD`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, and `APPLE_NOTARY_KEY_P8_BASE64`;
  - guest fetches Doppler secrets via Python stdlib / Doppler REST, not the Doppler CLI, so the base macOS image does not need `doppler` installed;
  - guest unsets the Doppler token before running signing/notarization;
  - decoded cert/notary key files remain guest-local and are deleted by cleanup.
- [ ] Run the tag-triggered Buildkite release and verify the release artifact passes Gatekeeper/notarization checks on a clean macOS host.
  - [x] Apply the GitHub Actions-style ephemeral keychain pattern from IronsideXXVI/Hacker-News to `scripts/release-macos-notifier-buildkite.sh`: create/unlock, import p12, set partition list, add to search list, do not set as default keychain.
  - [x] Stop passing `CODESIGN_KEYCHAIN` to `scripts/notarize-macos-notifier.sh` so `codesign` searches the full keychain list.
  - [x] Import the Apple Developer ID intermediate certificate (matched by leaf issuer CN) from system root stores into the ephemeral keychain.
  - [x] Add stapling retry to `scripts/notarize-macos-notifier.sh`.
  - [ ] Validate the fix with a real tag-triggered Buildkite run using the actual Apple Developer ID p12.
- [ ] Validate first-run macOS permission prompt attribution on real hosts.
- [ ] Validate Notification Center display name/icon and denied-permission behavior.
- [ ] Validate daemon-context delivery behavior before making native delivery the default macOS desktop path.
