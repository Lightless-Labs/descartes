# macOS Notifier Release — Validation Brief

**Created:** 2026-07-08
**For:** an agent/operator on a real macOS host (Part A) and watching the next tag release (Part B).
**Status:** pending — the release *pipeline* is implemented and CI-validated through GitHub Release publication (Buildkite #73); the items below are the remaining real-world validations that cannot be exercised from the build machine or without a fresh version tag.

Context: `v0.0.47` is signed, notarized, stapled, published to GitHub Releases, and installable via `brew install lightless-labs/tap/descartes` (CLI + bundled notarized helper). See `docs/plans/2026-07-08-macos-helper-delivery.md` and the 2026-07-07/08 entries in `docs/HANDOFF.md` for how it was built.

---

## Part A — Real-host native notification helper validation

**Why it needs a real host:** notification permission grants are keyed to the signed bundle identity and are stored per-user by TCC; they cannot be exercised in the headless CI VM. Best run on a Mac that has **never** granted this helper permission (or after resetting — see below), so the first-run prompt is observable.

Bundle identifier: `com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`.

Steps:

1. Install: `brew install lightless-labs/tap/descartes`. If a prior `npm -g` install owns `/opt/homebrew/bin/descartes`, run `npm uninstall -g @lightless-labs/descartes` first (documented caveat).
2. Confirm the CLI resolves the bundled helper with no `--helper` flag:
   `descartes alerts notifications setup --channel native` — it should find the helper inside the brew keg, not report "not packaged or configured".
3. Trigger a test notification (`descartes alerts notifications test` or the setup flow's built-in test) and confirm:
   - the **first-run Notification Center permission prompt appears**, attributed to *DescartesNotifier* (branded), NOT Terminal/osascript;
   - after granting, the notification actually displays with the expected title/body/severity;
   - a second test does not re-prompt (grant persists).
4. Confirm the grant **persists across a CLI restart** and a new shell session.
5. Denied-permission path: deny (or `tccutil reset Notifications $BUNDLE_ID` then deny) and confirm delivery **fails closed** with a local delivery-audit record, and that the `osascript`/`macos-desktop` fallback channel still works.
6. Reset helper (to re-test cleanly): `tccutil reset Notifications com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`.

Gotcha: a Mac that previously ran an unsigned/dev build with the same bundle id may hold a stale TCC grant; reset before testing to see true first-run behavior.

Record results under `docs/reviews/` (follow the existing macOS/Linux validation review docs), and check the acceptance boxes in `todos/2026-07-08-macos-helper-delivery.md`.

---

## Part B — First-tag validation of the release → GitHub Release → tap-bump chain

**Why it needs the next tag:** the GitHub Release auto-publish was CI-validated in build #73, but the **Homebrew tap auto-bump has never run in CI** — it only fires on a real `vX.Y.Z` tag with `GITHUB_RELEASE_PUBLISHED=1` and a token that can write `Lightless-Labs/homebrew-tap`.

On the next version bump (edit `package.json` version, commit, `git tag vX.Y.Z`, push tag — `export SSH_AUTH_SOCK=~/.ssh/agent.sock` first), watch the Buildkite `release-macos-notifier` job and confirm the full sequence:

1. build → codesign (identity valid) → notarize **Accepted** → staple → `spctl` "Notarized Developer ID";
2. Buildkite artifacts uploaded (`DescartesNotifier.app.zip` + `.sha256`);
3. GitHub Release for the tag created/updated with both assets;
4. **tap bump**: a `descartes: update to X.Y.Z` commit appears in `Lightless-Labs/homebrew-tap` with `Formula/descartes.rb` url version + BOTH sha256 values updated (tarball + helper zip), and the log line `bumped Lightless-Labs/homebrew-tap/Formula/descartes.rb to X.Y.Z: <sha>`.
5. End-user check: `brew update && brew upgrade descartes` (or a fresh install) pulls the new version and its helper; `descartes --version` matches the tag.

Token note: the tap bump reuses `GITHUB_TOKEN` (no separate secret). Confirm that token can write `homebrew-tap`; if the log shows `no GitHub token available` or an HTTP 403 warning + `bump manually:` instructions, the token lacks tap write access — either widen it or set a narrower `HOMEBREW_TAP_GITHUB_TOKEN` in Doppler (`lightless-labs-descartes` / `prd_notarisation`).

Fallback: if the bump warns/skips (e.g. transient failure after retries), follow the script's printed manual-bump instructions — url version + tarball sha256 + helper zip sha256 in `Formula/descartes.rb`.

Retag caveat (learned this cycle): deleting a tag orphans its published GitHub Release into a *draft* invisible to `gh release list`; check `gh api repos/Lightless-Labs/descartes/releases` for drafts after any retag loop.

---

## Part C — rcodesign spike (optional, separate)

Tracked in `todos/2026-07-07-rcodesign-investigation.md`: evaluate `rcodesign` (apple-codesign) to sign/notarize with no keychain at all, which would remove the whole keychain-intermediate failure class and could let signing move off the macOS VM entirely. Not blocking; do only if the keychain path proves fragile again or when the Rust core lands per-platform binaries.
