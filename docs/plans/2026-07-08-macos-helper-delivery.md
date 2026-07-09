# macOS Notifier Helper Delivery

**Created:** 2026-07-08
**Status:** In Progress — local delivery implementation has landed; release readiness remains blocked on external validation (real-host TCC behavior and the next tagged release's tap-bump run).
**Updated:** 2026-07-08 — direction decision (operator): Homebrew is the primary macOS delivery channel. The tap formula installs the CLI and the notarized helper together; the in-CLI setup/download flow is deferred, not implemented.
**Updated:** 2026-07-08 — Milestone 1 implemented and verified: `Formula/descartes.rb` pushed to `Lightless-Labs/homebrew-tap` (`e655211`). Local install verified end-to-end: CLI `--version` from the keg, helper stapled + Gatekeeper-accepted after ditto extraction (generic resource staging descends into the single top-level `.app` and breaks — the formula uses `resource.fetch` + `ditto -x -k`), and `resolveBundledMacosHelperPath()` resolves the helper from the installed tree with no configuration. The npm-shadow link caveat was confirmed live (brew leaves an existing npm-owned `descartes` symlink untouched and installs unlinked).
**Updated:** 2026-07-08 — Milestone 2 implemented and unit-tested: the release script now bumps `Lightless-Labs/homebrew-tap` through the GitHub Contents API after successful GitHub Release publication, reusing `GITHUB_TOKEN` by default with optional `HOMEBREW_TAP_GITHUB_TOKEN`. Remaining validation: first real-host Notification Center permission flow and first real tag run of the tap-bump step.

## Purpose

Close the gap between the notarized helper release artifact and the user-facing
`macos-native` notification channel. As of `v0.0.47`, release tags publish a
Developer ID-signed, notarized, stapled `DescartesNotifier.app.zip` (+ `.sha256`) as a
GitHub Release asset, and the macOS Homebrew formula delivers that helper to the
bundled-helper path the CLI already probes. npm installs still do not include macOS
binaries; those users retain the development/advanced `--helper <path>` override unless
an in-CLI download flow is revisited later.

## Current facts (verified 2026-07-08)

- macOS CLI delivery is now primarily `brew install lightless-labs/tap/descartes`, which
  installs both the Node CLI and the native helper. Cross-platform npm/GitHub install
  remains available as `npm install -g github:Lightless-Labs/descartes`, without the
  helper. npm registry publishing is explicitly a non-goal.
- The release pipeline ties the tag to `package.json` version, so a CLI build can derive
  the exact release asset URL for its own version.
- Helper asset: `https://github.com/Lightless-Labs/descartes/releases/download/v<version>/DescartesNotifier.app.zip`
  plus a `.sha256` sibling. Stapled, so Gatekeeper accepts it offline.
- **Descartes is now on Homebrew for macOS.** `Lightless-Labs/homebrew-tap` contains
  `Formula/descartes.rb`; the formula installs the CLI from the tagged source tarball and
  installs the notarized helper release asset as a macOS-only resource at the path the CLI
  probes. This is the primary macOS delivery channel.
- Homebrew and GitHub Release binaries remain the roadmap's preferred long-term channels,
  aligned with the future Rust core (see `docs/plans/2026-05-18-003-*` distribution notes).
- Notification permission grants are keyed to the signed bundle identity and install
  path stability matters (see 2026-07-07 addenda in
  `docs/plans/2026-05-30-native-macos-notifications.md`).

## Milestone 1 — Homebrew tap formula: CLI + helper together (primary)

Implemented by adding `Formula/descartes.rb` to `Lightless-Labs/homebrew-tap`:

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

**Implemented 2026-07-08** in `scripts/release-macos-notifier-buildkite.sh`
(`bump_homebrew_tap_formula`): after the GitHub Release publishes (hard-gated on
`GITHUB_RELEASE_PUBLISHED=1` so the formula can never point at assets that don't
exist), the script downloads the tag's source tarball to checksum it, reuses the
stapled zip's checksum, and rewrites `Formula/descartes.rb` via the GitHub Contents
API (no git/gh in the guest): version in both pinned URLs plus pairwise sha256
replacement (each URL line's following sha256 line, so tarball/helper checksums cannot
swap), with a shape guard that refuses to PUT on unexpected formula structure.
Transient failures (GitHub 5xx/429/rate-limited-403, network/timeout) are retried with
exponential backoff — the Contents API calls in python, the tarball download via
`curl --retry --retry-all-errors` — and a 409 edit conflict re-reads and retries once.
Only after retries are exhausted does the step fall through to strictly best-effort: it
warns loudly with manual-bump instructions and never fails the release job (the
artifacts and GitHub Release are already out, and a job failure would also skip the
pipeline's artifact rsync-back). The bump reuses `GITHUB_TOKEN` by default (no second
secret); `HOMEBREW_TAP_GITHUB_TOKEN` is only an optional narrower-token override. It is
skipped when no token is available, and when the release published to a repo other than
the formula's canonical `Lightless-Labs/descartes` (its pinned URLs could never match).
Manual bump remains the fallback (url version + tarball sha256 + helper zip sha256).
Covered by `tools/descartes-cli/test/tap-bump.test.js`: the exact embedded python runs
against a formula fixture with a mocked Contents API (bump / no-op / shape-guard /
transient-retry-then-success / give-up-after-exhaustion). **Operator action to
activate:** none beyond ensuring the `GITHUB_TOKEN` already in Doppler
(`lightless-labs-descartes` / `prd_notarisation`) can write `Lightless-Labs/homebrew-tap`
— the tap bump reuses it rather than requiring a second secret. CI validation happens on
the next tag release.

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
