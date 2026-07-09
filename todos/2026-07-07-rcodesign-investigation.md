---
title: Investigate rcodesign for keychain-free macOS signing/notarization
created: 2026-07-07
status: in_progress
priority: medium
area: release
kind: todo
owner: unassigned
related:
  - docs/plans/2026-05-30-native-macos-notifications.md
  - todos/2026-05-30-native-macos-notifications.md
  - docs/research/2026-07-09-rcodesign-macos-notifier-release-research.md
---

# TODO: Investigate rcodesign for keychain-free macOS signing/notarization

## Summary

The Buildkite macOS notifier release currently signs with `codesign` through an ephemeral
macOS keychain and notarizes with `xcrun notarytool`. That path works only when the full
certificate chain (leaf + Apple Developer ID intermediate) is present in the keychain
search list, and it took days of debugging keychain semantics (`security find-certificate -a`
exit-code false positives, missing G2 intermediate on fresh CI images, partition lists,
search-list ordering) to make it viable. `rcodesign` from the
[apple-codesign](https://github.com/indygreg/apple-platform-rs) project removes that entire
failure class:

**Research update 2026-07-09:** Foundry-style research is recorded at
`docs/research/2026-07-09-rcodesign-macos-notifier-release-research.md`. Recommendation:
do **not** replace the working Apple-toolchain release path yet. Keep rcodesign as an
optional spike/fallback until it is proven with the real Descartes Developer ID p12 and
App Store Connect API key, using the same Doppler-derived credential path as CI. The
Swift app build still requires macOS today (`swiftc` + UserNotifications), so the first
practical win would be keychain-free signing/notarization inside the existing Tart job,
not eliminating the macOS VM end-to-end.

- Signs directly from the `.p12` (`rcodesign sign --p12-file ... --p12-password-file ...`)
  with no keychain, trust store, partition list, or search list involvement.
- Submits to the Apple notary API with an App Store Connect API key
  (`rcodesign notary-submit --api-key-file ...`) and can staple (`rcodesign staple`).
- Runs headless anywhere, including Linux — a release job would no longer require a
  macOS VM at all if the Swift build is separated from signing/notarization.
- Rust implementation aligns with the monorepo direction (Rust core, Bazel).

## Scope

- Spike: sign the real `DescartesNotifier.app` locally with `rcodesign` using the release
  p12 and compare `codesign -dvvv` / `codesign --verify --deep --strict` output against the
  Apple-toolchain-signed artifact (hardened runtime flags, secure timestamp, entitlements).
- Verify notarization acceptance and stapling parity (`rcodesign notary-submit`,
  `rcodesign staple`, then `spctl --assess --type execute`).
- Decide whether to replace the keychain path in
  `scripts/release-macos-notifier-buildkite.sh` / `scripts/notarize-macos-notifier.sh`
  or keep rcodesign as a documented fallback.
- If adopted: pin the rcodesign version, decide install mechanism in the Tart guest
  (prebuilt binary download with checksum vs cargo install), and update the release scripts
  and tests.

## Acceptance criteria

- [ ] Local rcodesign-signed app passes `codesign --verify --deep --strict` and Gatekeeper
      assessment after notarization/stapling.
- [ ] Signature attributes (hardened runtime, timestamp, identifier, team ID) match the
      Apple-toolchain baseline.
- [x] Written recommendation (adopt/reject/fallback) recorded in
      `docs/research/2026-07-09-rcodesign-macos-notifier-release-research.md` and this
      todo: defer adoption; keep as optional fallback until real-cert signing,
      notarization, stapling, and Gatekeeper parity are proven. CI implication: macOS VM
      is still required for the Swift build; rcodesign would first remove keychain
      fragility, not the Tart job.

## Notes

- Not urgent: the keychain path was fixed on 2026-07-07 (Developer ID G2 intermediate is
  now imported from Apple PKI into the ephemeral keychain). This todo is about removing
  the failure class, not unblocking the release.
- The notary API key secrets already live in Doppler (`APPLE_NOTARY_KEY_ID`,
  `APPLE_NOTARY_ISSUER_ID`, `APPLE_NOTARY_KEY_P8_BASE64`) and are transport-compatible
  with rcodesign's `--api-key-file` JSON format (requires a small transform).
