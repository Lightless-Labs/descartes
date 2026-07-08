# macOS Notifier Helper Delivery

**Created:** 2026-07-08
**Status:** Proposed

## Purpose

Close the gap between the notarized helper release artifact and the user-facing
`macos-native` notification channel. As of `v0.0.47`, every release tag publishes a
Developer ID-signed, notarized, stapled `DescartesNotifier.app.zip` (+ `.sha256`) as a
GitHub Release asset, but nothing delivers that helper to end users: the CLI's
"bundled-helper resolution" has nothing to resolve (the npm payload intentionally
excludes macOS binaries), and `--helper <path>` is a development-only override.

## Current facts (verified 2026-07-08)

- CLI delivery is `npm install -g github:Lightless-Labs/descartes`; the git tag is the
  delivery vehicle for all JS code. npm registry publishing is explicitly a non-goal.
- The release pipeline ties the tag to `package.json` version, so a CLI build can derive
  the exact release asset URL for its own version.
- Helper asset: `https://github.com/Lightless-Labs/descartes/releases/download/v<version>/DescartesNotifier.app.zip`
  plus a `.sha256` sibling. Stapled, so Gatekeeper accepts it offline.
- **Descartes is NOT currently on Homebrew.** `Lightless-Labs/homebrew-tap` exists but
  carries only `middens` (per-platform GitHub-Release binary tarballs, version + sha256
  pinned, `odie` on unsupported platforms). No descartes formula or cask exists anywhere.
- Homebrew and GitHub Release binaries are the roadmap's preferred long-term channels,
  aligned with the future Rust core (see `docs/plans/2026-05-18-003-*` distribution notes).
- Notification permission grants are keyed to the signed bundle identity and install
  path stability matters (see 2026-07-07 addenda in
  `docs/plans/2026-05-30-native-macos-notifications.md`).

## Milestone 1 — in-CLI setup/download flow (universal)

Make `descartes alerts notifications setup --channel native` (without `--helper`) deliver
the helper on macOS regardless of how the CLI was installed:

1. Derive the asset URL from the CLI's own `package.json` version (fixed URL template,
   HTTPS only, no user-supplied URLs).
2. Download zip + `.sha256`; require checksum match before any extraction.
3. Extract with `ditto -x -k`; install to a stable per-user path
   (`~/Library/Application Support/descartes/DescartesNotifier.app`) so the bundle
   identity — and therefore the user's notification permission grant — survives CLI
   reinstalls/upgrades.
4. Verify post-install: `xcrun stapler validate` and `spctl --assess --type execute`;
   fail closed (keep `osascript` fallback, write a delivery-audit record) on any failure.
5. Persist the helper path in notification config; send the standard test notification.
6. Idempotent re-runs: if the installed helper version matches, no-op; if it differs,
   replace atomically (extract to temp dir, swap) and note that a changed signing
   identity resets the permission grant.

Failure modes to handle explicitly: no network, release/asset missing for this version
(e.g., installed from `main` between tags), checksum mismatch (delete download, fail
closed), non-macOS invocation (unchanged fail-closed behavior).

Tests: URL derivation from version, checksum verification, install/replace flow with an
injected fetcher (no real network in tests), config persistence, audit records. Real-host
validation checklist: first-run permission prompt attribution and persistence with the
downloaded helper (this is also the outstanding item from the native-notifications plan).

## Milestone 2 — Homebrew delivery via the existing tap

Add `descartes` to `Lightless-Labs/homebrew-tap` as the macOS convenience channel:

- Node era (now): a formula with `depends_on "node"`, `url` = release tag tarball, npm
  install into libexec; on macOS, the notarized helper zip as a version+sha256-pinned
  `resource` installed alongside, with the CLI's bundled-helper resolution taught to
  check the brew install location before falling back to Milestone 1's download path.
- Rust era (later): the formula converges on the middens shape — per-platform binary
  tarballs from GitHub Releases (macOS binaries signed/notarized by the same pipeline)
  plus the helper resource on macOS. Defer heavy formula investment until then if
  Milestone 1 proves sufficient interim delivery.
- Release automation follow-up: bump the tap formula from the release job (needs a token
  scoped to `homebrew-tap`, separate from the descartes-repo `GITHUB_TOKEN` in Doppler —
  do not widen the existing token's scope).

Milestone 1 ships first: it is small, channel-agnostic, and remains the fallback even
for Homebrew installs.

## Non-goals

- npm registry publishing.
- Shipping the `.app` inside the cross-platform npm payload.
- Mac App Store distribution (would require sandbox entitlements; see the
  local-notifications platform-requirements addendum).

## Open questions

- Exact-version pinning vs allowing newest-compatible asset when the CLI version has no
  release (installed from an untagged `main`): recommend exact-version with a clear
  error and `--helper` escape hatch.
- Formula vs cask for the helper: recommend formula `resource` (the helper is not a
  user-facing app; it should not land in `/Applications`).
