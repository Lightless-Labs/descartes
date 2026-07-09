# Homebrew Notifier Install Validation — 2026-07-09

## Scope

Partial real-host validation of the macOS Homebrew delivery path on this local macOS host. This run validates install/linkage/helper packaging, not the first-run Notification Center/TCC prompt.

## Environment

- Host OS: macOS (`uname -s` → `Darwin`)
- Formula: `lightless-labs/tap/descartes` v0.0.47
- Installed CLI path validated explicitly: `/opt/homebrew/bin/descartes`
- Homebrew tap fix: `Lightless-Labs/homebrew-tap` commit `75e886f` (`descartes: remove unused clipboard addons`)

## Findings

1. The machine initially had an older npm-global Descartes shim at `/opt/homebrew/bin/descartes` resolving to v0.0.25. This reproduced the documented npm-shadow migration caveat.
2. `brew install lightless-labs/tap/descartes` built v0.0.47 and installed the helper, but before the tap fix Homebrew failed its install/linkage step while trying to rewrite a vendored optional native clipboard add-on from Descartes' internal Pi dependency tree (`@mariozechner/clipboard-darwin-arm64`).
3. The tap formula now removes the unused `@mariozechner` optional clipboard packages after `npm install`, before Homebrew linkage repair. This avoids the Mach-O install-name rewrite/headerpad failure and removes non-native optional clipboard binaries from the keg.
4. The released v0.0.47 CLI predates the newer `resolution` JSON fields. `scripts/validate-macos-notifier-helper.sh --skip-test` now falls back to deriving the bundled helper path from the Homebrew-installed CLI path, so it can validate v0.0.47 while future releases still use explicit JSON resolution. The script refuses `DESCARTES_MACOS_NOTIFICATION_HELPER` to prevent a dev/env helper override from masquerading as bundled-helper validation.

## Commands / Results

- Removed the old npm-global shim:
  - `npm uninstall -g @lightless-labs/descartes`
  - `/opt/homebrew/bin/descartes` was removed before relinking the formula.
- Formula validation in the tap repo:
  - `HOMEBREW_NO_AUTO_UPDATE=1 brew audit --strict --online lightless-labs/tap/descartes` → exit 0
  - `HOMEBREW_NO_AUTO_UPDATE=1 brew reinstall --build-from-source lightless-labs/tap/descartes` → success
  - `HOMEBREW_NO_AUTO_UPDATE=1 brew linkage --test descartes` → exit 0
  - `HOMEBREW_NO_AUTO_UPDATE=1 brew test lightless-labs/tap/descartes` → success
- CLI identity:
  - `/opt/homebrew/bin/descartes --version` → `0.0.47`
  - `/opt/homebrew/bin/descartes` resolves to `/opt/homebrew/Cellar/descartes/0.0.47/.../tools/descartes-cli/src/index.js`
- Optional clipboard package cleanup:
  - `find /opt/homebrew/Cellar/descartes/0.0.47/.../node_modules -path '*@mariozechner*'` → no output
- Helper validation:
  - `DESCARTES_BIN=/opt/homebrew/bin/descartes scripts/validate-macos-notifier-helper.sh --skip-test </dev/null` → success
  - `codesign --verify --deep --strict --verbose=2 DescartesNotifier.app` → valid on disk / satisfies designated requirement
  - `xcrun stapler validate DescartesNotifier.app` → validate action worked
  - `spctl --assess --type execute --verbose=4 DescartesNotifier.app` → accepted, `source=Notarized Developer ID`

## Not validated in this run

- First-run Notification Center permission prompt attribution.
- Notification display, second-run persistence, and new-shell persistence.
- Denied-permission fail-closed behavior and audit record.
- Daemon-context native notification delivery.
- Next-tag Buildkite tap-bump run.

Those remain tracked in `todos/2026-07-08-macos-release-validation.md` and `macos-notifier-release-validation-brief.md`.
