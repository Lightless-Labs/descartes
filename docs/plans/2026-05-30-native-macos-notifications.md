# Native macOS Notifications

**Created:** 2026-05-30
**Status:** In Progress
**Updated:** 2026-05-30 — initial native channel/config/adapter and Swift helper prototype implemented; real-host packaging/signing validation remains.
**Updated:** 2026-05-30 — added maintainer-only `.app` bundle build/notarization scripts and excluded native macOS payloads from cross-platform npm packaging.
**Updated:** 2026-05-30 — added initial tag-triggered Buildkite release pipeline/script for macOS notifier signing, notarization, stapling, checksum, and artifact upload; real Buildkite secrets and first release run remain pending.
**Updated:** 2026-05-30 — Buildkite release script now auto-detects the Developer ID Application codesign identity from the imported `.p12`; `CODESIGN_IDENTITY` is optional override-only.
**Addendum:** 2026-05-30 — release signing/notarization must remain isolated inside Tart. Use the Lightless-Labs `tart-ci` fork with explicit required env passthrough instead of running signing directly on the Buildkite host.
**Addendum:** 2026-05-30 — users must not build the helper. Native delivery should use a bundled, release-built helper; `--helper` is only a development/advanced override.
**Addendum:** 2026-05-30 — release packaging must include macOS Developer ID signing and notarization, not signing alone, so downloaded helpers pass Gatekeeper and behave predictably for end users.
**Addendum:** 2026-05-30 — native notifier bundle identifier is `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`.
**Addendum:** 2026-05-30 — do not pollute Linux/cross-platform installs with a macOS `.app`; the notarized helper should be delivered only through macOS-specific packaging or an explicit macOS setup/download flow.
**Addendum:** 2026-05-30 — release automation should assume a tag-triggered Buildkite pipeline rather than GitHub Actions; GitHub Releases may still be used as the artifact publication surface.
**Addendum:** 2026-07-05 — applied the working GitHub Actions notarization keychain pattern from IronsideXXVI/Hacker-News to the Buildkite release scripts. `scripts/release-macos-notifier-buildkite.sh` now creates the ephemeral keychain, imports the p12, sets the partition list, and adds the keychain to the search list without making it the default. `codesign` is no longer restricted to the ephemeral keychain, so it can evaluate certificate validity against the system/login trust anchors. The script also imports the Apple Developer ID intermediate certificate (matched by the leaf cert's issuer CN) from system root stores into the ephemeral keychain, and `scripts/notarize-macos-notifier.sh` now retries stapling on propagation delays. The next step is a real tag-triggered Buildkite run with the actual Developer ID p12 to validate the fix.

**Addendum:** 2026-07-05 — macOS release signing is blocked on reproducing a valid Developer ID Application identity in a CI-style disposable keychain. The p12 imports, the private key is present and paired, and `verify-cert -p codeSign` can validate the certificate, but `security find-identity -v -p codesigning "$KEYCHAIN"` reports `0 valid identities found` and `codesign --keychain "$KEYCHAIN"` fails with `no identity found` when signing the real `DescartesNotifier.app`. Importing Apple Developer ID G1/G2 intermediates into the disposable keychain or login keychain did not make the disposable-keychain test pass locally; trust-setting changes require interactive/admin authorization. Do not update CI scripts or retag for this signing hypothesis until a local disposable-keychain run produces a valid identity and successful real-app codesign, or the release strategy is changed to use a pre-provisioned trusted keychain/Tart image.

**Addendum:** 2026-07-07 — the 2026-07-05 hard-stop conclusion above is retracted: those experiments were poisoned by a `security find-certificate -a` exit-code false positive (it exits 0 on zero matches), so the intermediates believed to be present were never actually in the keychains under test. Root cause of the CI signing failures: the Developer ID Certification Authority (OU=G2) intermediate that issued the leaf exists nowhere on fresh CI macOS images (system stores ship only roots plus the legacy G1 CA; Xcode is what installs intermediates on developer machines), and the p12 contains only the leaf. Fixed in `scripts/release-macos-notifier-buildkite.sh` by downloading `DeveloperIDG2CA.cer` from Apple PKI, subject-verifying it against the leaf issuer, and importing it into the ephemeral keychain; all Apple Root CA trust-settings code was removed (the chain terminates at the classic "Apple Root CA", trusted on every genuine macOS image). See `docs/HANDOFF.md` (2026-07-07) for full details and `todos/2026-07-07-rcodesign-investigation.md` for the keychain-free alternative.

**Addendum:** 2026-07-07 — platform requirements for the notification feature itself, so future work does not over-provision: local notifications via `UNUserNotificationCenter` require **no entitlement, no provisioning profile, and no Xcode/xcodebuild** on macOS. The runtime requirements are exactly what the current pipeline produces: a real `.app` bundle with an Info.plist and stable bundle identifier (`swiftc` + hand-written plist suffices — the framework fails without a resolvable bundle), plus a stable code-signing identity, because Notification Center keys permission grants and the Settings entry to the signed bundle identity (unsigned/ad-hoc helpers get flaky or absent permission attribution). The escalation point that would force entitlements + an embedded Developer ID provisioning profile (and make Xcode tooling worthwhile) is **remote push via APNs** (`com.apple.developer.aps-environment`) or App Store distribution (sandbox) — not local notifications. A Notification Center icon needs only a plain `.icns` referenced by `CFBundleIconFile` (`iconutil` ships with macOS); asset catalogs would require Xcode's `actool` and are not needed. Validation caveats: permission grants reset whenever the signed identity or bundle ID changes, and the Node adapter execs the helper binary directly inside the `.app` (bundle resolution from the binary path generally works, but first-run prompt attribution and grant persistence with the notarized artifact launched the CLI's way is the real-host validation to perform once a stapled release exists).

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
  - Intended automation shape: pushing a version tag triggers a Buildkite macOS release job inside an ephemeral Tart guest using `github.com/Lightless-Labs/tart-ci#v0.2.0` required `env` passthrough. The job imports signing material into an ephemeral keychain, builds, signs, notarizes, staples, verifies, computes checksums, and publishes a macOS-specific release artifact.
  - Current automation files: `.buildkite/pipeline.yml` and `scripts/release-macos-notifier-buildkite.sh`.
  - Required Buildkite secret/env names: `MACOS_DEVELOPER_ID_CERT_P12_BASE64`, `MACOS_DEVELOPER_ID_CERT_PASSWORD`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, and `APPLE_NOTARY_KEY_P8_BASE64`. `CODESIGN_IDENTITY` is optional override-only; the script auto-detects the first Developer ID Application identity imported from the `.p12`. `GITHUB_TOKEN` is optional for GitHub Release upload when `gh` is installed.
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
