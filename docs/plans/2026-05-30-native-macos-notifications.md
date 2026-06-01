# Native macOS Notifications

**Created:** 2026-05-30
**Status:** In Progress
**Updated:** 2026-05-30 — initial native channel/config/adapter and Swift helper prototype implemented; real-host packaging/signing validation remains.
**Updated:** 2026-05-30 — added maintainer-only `.app` bundle build/notarization scripts and excluded native macOS payloads from cross-platform npm packaging.
**Updated:** 2026-05-30 — added initial tag-triggered Buildkite release pipeline/script for macOS notifier signing, notarization, stapling, checksum, and artifact upload; real Buildkite secrets and first release run remain pending.
**Addendum:** 2026-05-30 — users must not build the helper. Native delivery should use a bundled, release-built helper; `--helper` is only a development/advanced override.
**Addendum:** 2026-05-30 — release packaging must include macOS Developer ID signing and notarization, not signing alone, so downloaded helpers pass Gatekeeper and behave predictably for end users.
**Addendum:** 2026-05-30 — native notifier bundle identifier is `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`.
**Addendum:** 2026-05-30 — do not pollute Linux/cross-platform installs with a macOS `.app`; the notarized helper should be delivered only through macOS-specific packaging or an explicit macOS setup/download flow.
**Addendum:** 2026-05-30 — release automation should assume a tag-triggered Buildkite pipeline rather than GitHub Actions; GitHub Releases may still be used as the artifact publication surface.

## Purpose

Move beyond the current macOS `osascript` notification adapter toward a bundled native macOS notification helper that can eventually provide clearer branding, a stable bundle identity, and more predictable Notification Center permission behavior. End users should not have to compile Swift or install Xcode.

The current `osascript` path is acceptable as a conservative fallback, but permission attribution may attach to Terminal, the user's shell, or `osascript`. A native helper should make that platform caveat explicit and progressively replace the fallback where a packaged/signed helper is available.

## Safety Boundaries

- Notification delivery remains disabled by default.
- Native delivery must be explicitly selected/configured by the user until the macOS-specific signed/notarized helper is validated enough to become the macOS default.
- The helper receives only bounded notification payloads: title, body, severity, alert id, and rule id.
- No raw logs, process dumps, history dumps, credentials, or arbitrary evidence blobs are passed to the helper.
- No remediation/action authority.
- No arbitrary shell execution; the Node adapter may execute only an installed macOS helper path, a macOS-specific packaged helper path, or an explicit development override, with fixed arguments.
- Cross-platform/Linux packages must not include a macOS `.app` payload.
- Missing helper, permission denial, Gatekeeper/notarization failures, or platform errors must fail closed and produce local delivery audit records.

## Initial Implementation Slice

- Add a `macos-native` notification channel and CLI alias such as `--channel native`.
- Resolve a packaged helper automatically when present.
- Store an optional explicit helper path in Descartes notification config for development/advanced overrides only.
- Add fixed-argument Node adapter execution for the helper.
- Add local audit for missing-helper/unavailable/delivered/error outcomes.
- Add a checked-in Swift helper source prototype using `UserNotifications`.
- Keep `macos-desktop`/`osascript` as fallback until packaging/signing is solved.

## Future Packaging Work

- Decide packaging shape: signed and notarized helper app bundle, signed and notarized command-line helper, or LaunchServices-registered notification app.
- Use bundle identifier `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier` and determine display name/icon behavior for Notification Center.
- Add repeatable build/release packaging without hidden local build steps; this is for maintainers/Buildkite, not users.
  - Current maintainer scripts: `scripts/build-macos-notifier.sh` creates `.build/macos-notifier/DescartesNotifier.app`; `scripts/notarize-macos-notifier.sh` signs, submits with `notarytool`, staples, and verifies.
  - Intended automation shape: pushing a version tag triggers a Buildkite macOS job that imports signing material into an ephemeral keychain, builds, signs, notarizes, staples, verifies, computes checksums, and publishes a macOS-specific release artifact.
  - Current automation files: `.buildkite/pipeline.yml` and `scripts/release-macos-notifier-buildkite.sh`.
  - Required Buildkite secret/env names: `CODESIGN_IDENTITY`, `MACOS_DEVELOPER_ID_CERT_P12_BASE64`, `MACOS_DEVELOPER_ID_CERT_PASSWORD`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, and `APPLE_NOTARY_KEY_P8_BASE64`. `GITHUB_TOKEN` is optional for GitHub Release upload when `gh` is installed.
- Keep the signed/notarized `.app` out of the cross-platform npm payload; deliver it via macOS-specific release asset, future Homebrew formula/cask packaging, or an explicit macOS-only setup/download/install flow.
- Add Developer ID signing, hardened runtime where applicable, `notarytool` submission, notarization polling, and stapling/verification to the maintainer release flow.
- Validate on real macOS hosts:
  - first-run permission prompt attribution;
  - Notification Center display name/icon;
  - behavior when notifications are denied;
  - behavior from daemon context vs interactive CLI context.

## Acceptance Criteria

- [x] Dedicated plan/todo exists before implementation.
- [x] `descartes alerts notifications setup --channel native --helper <path>` persists native helper config as a development/advanced override.
- [x] Native channel delivery uses a fixed executable path and fixed argument list.
- [x] Missing helper or non-macOS host fails closed with local audit, not daemon failure/spam.
- [x] Swift helper source prototype exists and accepts bounded fixed arguments.
- [x] Tests cover config normalization, CLI setup, missing-helper audit, and fixed native command invocation.
- [x] Maintainer-only scripts exist to build an app bundle, sign/notarize/staple/verify it, and keep generated artifacts under ignored build output.
- [x] Cross-platform npm package metadata excludes `tools/descartes-cli/native` so Linux installs do not carry a macOS `.app` payload.
- [x] Initial tag-triggered Buildkite release pipeline/script exists and uses an ephemeral runner-local keychain password generated at runtime.
- [ ] Buildkite release secrets are seeded and the tag-triggered release flow signs/notarizes/verifies a real artifact before publication.
- [ ] Real-host macOS validation is documented before making native delivery the default macOS desktop channel.
