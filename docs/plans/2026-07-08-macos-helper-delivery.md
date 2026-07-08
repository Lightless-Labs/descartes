# macOS Notifier Helper Delivery

**Created:** 2026-07-08
**Status:** In Progress
**Updated:** 2026-07-08 — direction decision (operator): Homebrew is the primary macOS delivery channel. The tap formula installs the CLI and the notarized helper together; the in-CLI setup/download flow is deferred, not implemented.
**Updated:** 2026-07-08 — Milestone 1 implemented and verified: `Formula/descartes.rb` pushed to `Lightless-Labs/homebrew-tap` (`e655211`). Local install verified end-to-end: CLI `--version` from the keg, helper stapled + Gatekeeper-accepted after ditto extraction (generic resource staging descends into the single top-level `.app` and breaks — the formula uses `resource.fetch` + `ditto -x -k`), and `resolveBundledMacosHelperPath()` resolves the helper from the installed tree with no configuration. The npm-shadow link caveat was confirmed live (brew leaves an existing npm-owned `descartes` symlink untouched and installs unlinked). Remaining: Milestone 2 (release-job tap bump) and real-host permission-prompt validation.

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

## Milestone 1 — Homebrew tap formula: CLI + helper together (primary)

Add `Formula/descartes.rb` to `Lightless-Labs/homebrew-tap`:

- `url` = release tag source tarball (sha256-pinned); `depends_on "node"`; install via
  `std_npm_args` into `libexec`; symlink `bin/descartes`.
- The notarized `DescartesNotifier.app.zip` release asset as a version+sha256-pinned
  `resource`, installed (macOS only) inside the npm package tree at
  `libexec/lib/node_modules/@lightless-labs/descartes/tools/descartes-cli/native/macos/DescartesNotifier.app`
  — the exact relative path `resolveBundledMacosHelperPath` in
  `tools/descartes-cli/src/notification-delivery.js` already probes, so the CLI needs
  **no code changes**: `descartes alerts notifications setup --channel native` resolves
  the helper out of the box.
- Note `npm pack`'s `files` filter keeps `tools/descartes-cli/native` sources out of the
  npm payload as before; only the brew resource places the built helper there.
- Verification per install: `stapler validate` + `spctl --assess` on the installed
  bundle; formula `test` block asserts `descartes --version`.
- Known migration caveat: users who previously ran `npm install -g` with Homebrew's
  node have an npm-owned `/opt/homebrew/bin/descartes` symlink; `brew link` will refuse
  until `npm uninstall -g @lightless-labs/descartes` (document in README/caveats).
- Rust era (later): the formula converges on the middens shape — per-platform binary
  tarballs from GitHub Releases (macOS binaries signed/notarized by the same pipeline)
  plus the helper resource on macOS.

## Milestone 2 — release automation bumps the tap

On each tag release, update `Formula/descartes.rb` (url version + both sha256 values)
in `Lightless-Labs/homebrew-tap` from the release job. Needs a token scoped to
`homebrew-tap` (separate from the descartes-repo `GITHUB_TOKEN` in Doppler — do not
widen the existing token's scope). Until implemented, the formula is bumped manually
per release.

## Deferred — in-CLI setup/download flow

The previously drafted Milestone 1 (CLI downloads the version-matched release asset,
verifies sha256 + staple + Gatekeeper, installs to a stable per-user path) is deferred
by operator decision in favor of Homebrew delivery. Revisit only if a meaningful
population of macOS users stays on npm installs; those users retain the documented
`--helper` override and can install the helper from the GitHub Release manually.

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
