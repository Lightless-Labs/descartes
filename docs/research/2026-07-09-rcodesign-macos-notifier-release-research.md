---
date: 2026-07-09
topic: rcodesign macOS notifier release spike
---

# Research: rcodesign macOS Notifier Release Spike

## Codebase Context

- Descartes is currently a Node.js CLI with macOS notifier build/release automation under `scripts/` and Buildkite/Tart CI in `.buildkite/pipeline.yml`.
- The native notification helper is built from Swift source at `tools/descartes-cli/native/macos/DescartesNotifier.swift` into `.build/macos-notifier/DescartesNotifier.app` by `scripts/build-macos-notifier.sh`.
- The shipping release path for `v0.0.47` uses Apple's tools inside a macOS Tart guest:
  - `scripts/release-macos-notifier-buildkite.sh` fetches secrets from Doppler, creates an ephemeral keychain, imports the Developer ID p12, installs the Apple Developer ID intermediate, builds the helper, signs/notarizes/staples/verifies, publishes release assets, and attempts the Homebrew tap bump.
  - `scripts/notarize-macos-notifier.sh` performs the Apple-toolchain signing/notarization/stapling sub-flow using `codesign`, `xcrun notarytool`, `xcrun stapler`, `spctl`, and `ditto`.
- CI is pinned to `github.com/Lightless-Labs/tart-ci#v0.2.4` and the Cirrus Sequoia image digest in `.buildkite/pipeline.yml`.
- Release readiness is still blocked on real-host Notification Center/TCC validation and the first live tap-bump run; rcodesign is optional and should not destabilize the working keychain path until proven.

## Existing Work

- `todos/2026-07-07-rcodesign-investigation.md` tracks the optional spike. Its motivation is to remove the keychain/intermediate/trustd failure class from signing and notarization.
- `docs/solutions/build-errors/macos-codesign-ci-missing-developer-id-intermediate-2026-07-07.md` documents the fixed Apple-toolchain failure: fresh CI images lacked the Developer ID G2 intermediate, `security find-certificate -a` gave false-positive presence checks, and the intermediate had to be installed into `/Library/Keychains/System.keychain` for `codesign`/`trustd` to build the chain.
- `docs/plans/2026-05-30-native-macos-notifications.md` records that local macOS notifications need no entitlements/provisioning profile, but do need a real `.app` bundle with stable bundle ID and Developer ID signing/notarization for predictable Notification Center attribution.

## Relevant Code

### Current Apple-toolchain release path

- `.buildkite/pipeline.yml`
  - Release step runs only for `vX.Y.Z` tags.
  - Runs inside a macOS Tart guest through `Lightless-Labs/tart-ci#v0.2.4`.
  - Exposes `DOPPLER_DESCARTES_PRD_NOTARISATION` as `DOPPLER_TOKEN`; only `BUILDKITE_TAG` is passed explicitly as env.
  - Copies final `.build/macos-notifier/release/*` artifacts back to the host for Buildkite artifacts.
- `scripts/release-macos-notifier-buildkite.sh`
  - Fetches `MACOS_DEVELOPER_ID_CERT_P12_BASE64`, `MACOS_DEVELOPER_ID_CERT_PASSWORD`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`, `APPLE_NOTARY_KEY_P8_BASE64`, optional `GITHUB_TOKEN`, and optional `HOMEBREW_TAP_GITHUB_TOKEN` from Doppler.
  - Decodes the p12 and notary key to guest-local temp files.
  - Creates/unlocks an ephemeral keychain, imports the p12, imports Developer ID G1/G2 intermediate, installs that intermediate into System.keychain, detects the Developer ID Application identity, then invokes the build/notarize scripts.
- `scripts/notarize-macos-notifier.sh`
  - Requires macOS, `CODESIGN_IDENTITY`, `codesign`, `xcrun`, `spctl`, and `ditto`.
  - Signs with `codesign --force --timestamp --options runtime --sign` and optional `CODESIGN_KEYCHAIN`.
  - Submits `DescartesNotifier.app.zip` with `xcrun notarytool` using API-key, keychain-profile, or Apple ID credentials.
  - Staples with retry and verifies with `xcrun stapler validate` and `spctl --assess --type execute`.

### rcodesign insertion points if adopted

- Replace the keychain-sensitive signing setup in `scripts/release-macos-notifier-buildkite.sh`:
  - no `security create-keychain`, `security import`, partition list, search-list edit, Developer ID intermediate download/import, or System.keychain mutation;
  - decode the p12 and write its password to guest-local files;
  - call `rcodesign sign --p12-file <p12> --p12-password-file <password-file> --code-signature-flags runtime --for-notarization <DescartesNotifier.app>`.
- Replace or bypass most of `scripts/notarize-macos-notifier.sh` for the release flow:
  - write App Store Connect API key JSON from `APPLE_NOTARY_ISSUER_ID`, `APPLE_NOTARY_KEY_ID`, and decoded `APPLE_NOTARY_KEY_P8_BASE64` (prefer `rcodesign encode-app-store-connect-api-key` over hand-rolled JSON);
  - call `rcodesign notary-submit --api-key-file <json> --wait ...` and then `rcodesign staple ...` if not using `--staple`;
  - keep Apple verification commands (`codesign --verify --deep --strict`, `xcrun stapler validate`, `spctl --assess --type execute`) as independent parity checks.
- Keep `scripts/build-macos-notifier.sh` on macOS for now because the Swift build uses `swiftc` plus macOS `Foundation`/`UserNotifications`; rcodesign can remove keychain dependence, but it does not make the Swift build cross-platform by itself.

## External References

- Apple Codesign documentation: `https://gregoryszorc.com/docs/apple-codesign/main/apple_codesign_getting_started.html`
  - Prebuilt binaries are published in GitHub Releases for `indygreg/apple-platform-rs`.
  - `cargo install apple-codesign` installs `rcodesign` when Rust/Cargo is available.
  - App Store Connect API keys can be encoded with `rcodesign encode-app-store-connect-api-key -o <json> <issuer-id> <key-id> <private-key-file>`.
- Signing docs: `https://gregoryszorc.com/docs/apple-codesign/main/apple_codesign_rcodesign_signing.html`
  - `rcodesign sign --p12-file developer-id.p12 --p12-password-file <file> --code-signature-flags runtime <path>` signs Mach-O executables and app bundles.
  - rcodesign recursively signs nested entities by default, unlike Apple's `codesign`.
- Notarization docs: `https://gregoryszorc.com/docs/apple-codesign/main/apple_codesign_rcodesign_notarizing.html`
  - `rcodesign notary-submit --api-key-file <json> --wait <asset>` waits for notarization.
  - `rcodesign notary-submit --api-key-file <json> --wait --staple <asset>` can staple after success.
  - `rcodesign staple <path>` can staple an already-notarized asset.
  - `--for-notarization` on `rcodesign sign` validates/adjusts settings for notarization compatibility.
  - Hardened runtime requires `--code-signature-flags runtime`; for complex bundles, scoped flags may be necessary for additional binaries.

## Test Landscape

- `tools/descartes-cli/test/package-metadata.test.js` currently asserts the Apple-toolchain/keychain release path:
  - keychain password generation and `security create-keychain`;
  - `security find-identity` identity detection;
  - Developer ID G2 intermediate download and System.keychain install;
  - absence of `add-trusted-cert`;
  - Doppler project/config, `DOPPLER_TOKEN` cleanup, GitHub Release upload, Homebrew tap bump, and `tart-ci#v0.2.4`.
- If rcodesign is adopted, update the test to assert:
  - `rcodesign sign` / `rcodesign notary-submit` / `rcodesign staple` or explicit Apple verification after rcodesign;
  - no ephemeral keychain, partition list, `security import`, Developer ID intermediate download/import, or System.keychain mutation in the rcodesign path;
  - preservation of Doppler scoping, artifact paths, GitHub Release upload, Homebrew tap bump, and `DOPPLER_TOKEN` cleanup.
- If rcodesign remains only a spike/fallback script, tests should assert the production release script still uses the proven Apple-toolchain path and any spike script is maintainer-only, ignored for packaging, and not called by Buildkite release jobs.

## Credential / Profile Consistency Notes

- The Buildkite release script and standalone `scripts/notarize-macos-notifier.sh` do not consume credentials in the same way:
  - Buildkite uses a scoped Doppler token and fetches API-key credentials into guest-local files.
  - The standalone script accepts `APPLE_NOTARY_KEY_PATH` + id/issuer, a keychain profile, or Apple ID/app-specific password.
- An rcodesign implementation must avoid a local/CI mismatch where a local spike passes using a profile or Apple ID path that CI never uses. Prefer exercising the same Doppler-derived p12 and App Store Connect API-key path that Buildkite uses.
- Keep all decoded cert/key files guest-local or scratch-local, mode `0600`, and removed by cleanup. Do not print secret values.

## Recommendation

Do **not** replace the working Apple-toolchain release path yet. Keep rcodesign as an optional spike/fallback until the following are proven with the real Descartes signing material:

1. `rcodesign` is installed from a pinned, reproducible source (prebuilt binary with checksum or a pinned Cargo version).
2. A `DescartesNotifier.app` signed by rcodesign passes `codesign --verify --deep --strict` and has hardened runtime, timestamp, identifier, and Team ID parity with the Apple-toolchain baseline.
3. `rcodesign notary-submit --wait` returns Accepted using the same App Store Connect API-key credentials that Buildkite uses.
4. Stapling succeeds and `xcrun stapler validate` plus `spctl --assess --type execute` pass on the signed/stapled app.
5. The produced zip can still be consumed by the existing GitHub Release and Homebrew formula flow.

The current keychain path is now CI-proven and shipping; rcodesign's value is reducing fragility, not unblocking the release.

## Open Questions

- Which rcodesign install mechanism should be pinned for CI if adopted: `apple-codesign` crate version via Cargo, or a prebuilt `apple-platform-rs` release artifact with checked sha256?
- Should a spike submit the `.app`, the `.zip`, or both? Existing Apple-toolchain flow submits the zip and staples the app; rcodesign supports `notary-submit --staple`, but the exact asset/staple target should be verified empirically.
- Does `--for-notarization` plus `--code-signature-flags runtime` produce the same signature attributes as the current `codesign --timestamp --options runtime` invocation for this simple single-binary app?
- Can rcodesign signing happen outside the macOS VM later? The Swift build still requires macOS today, so the immediate practical win is keychain-free signing inside the existing Tart job, not eliminating Tart entirely.
