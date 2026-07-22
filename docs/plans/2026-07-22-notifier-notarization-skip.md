# Skip notifier rebuild+notarize when its source is unchanged (content-hash reuse)

**Created:** 2026-07-22
**Reviewed:** 2026-07-22 (adversarial design review, Sonnet — verdict NEEDS REWORK; 4 must-fixes + 8 should-fixes/nits folded below)
**Status:** REVIEWED — ready to implement
**Motivation:** Every release tag rebuilds → signs → **notarizes** → staples `DescartesNotifier.app`
unconditionally (`release-macos-notifier-buildkite.sh:518-529`), even for a pure-JS release where the
notifier binary is byte-equivalent. That burns a multi-minute Apple notarization round-trip + a
submission per release for no benefit (confirmed on `v0.0.49`, a JS-only change). The redundancy
exists only because the Homebrew formula pins the helper zip URL to the same tag as the CLI.

## Goal

On a release, if the notifier **source** is unchanged since the most recent prior release that carries
a reuse attestation, REUSE that prior release's already-notarized+stapled `DescartesNotifier.app.zip`
(download → verify identity+integrity+notarization → re-upload as this version's asset) instead of
rebuilding+notarizing. Saves the notarize round-trip on the (common) releases where the notifier
didn't change. **Every uncertainty resolves to BUILD, never reuse.**

## Grounding (verified 2026-07-22 against the pipeline)

- Build/notarize/staple/zip/sha256: `release-macos-notifier-buildkite.sh:518-529`. Skip branch slots
  in before 518 and short-circuits 518-529, populating `$ZIP_PATH`+`$SHA_PATH` from a prior asset.
- `notarize-macos-notifier.sh` does sign → `notarytool submit --wait` → `stapler staple` →
  `stapler validate` → **`spctl --assess --type execute --verbose=4`** (`:90`) → re-zip.
- **Version is baked into the built `.app`** (`build-macos-notifier.sh:40-43` `sed` of
  `__DESCARTES_VERSION__`/`__DESCARTES_BUILD__` from `package.json`). A reused zip carries the OLD
  version strings — see §4.
- **No git in the Tart guest** (`.buildkite/pipeline.yml:238` `--exclude .git`; `release-…sh:547`
  documents the fallback). Detection uses a content hash vs a prior release's attestation asset.
- GitHub API: only GET-release-by-tag exists (`:588`) + a retryable `call()` (`:687-728`) + a `curl`
  public-download idiom (`:661`). "List releases" and "download a release ASSET" are NEW (§ Feasibility).
- **`github_release_repository()` (repo-slug, with the git-less fallback) is defined at `:539` and the
  `call()` retry helper inside `bump_homebrew_tap_formula` at `:687` — BOTH after line 518.** (must-fix #4)
- Tap-bump helper sha256 = local `shasum -a 256 "$ZIP_PATH"` (`:658`) — works unchanged whether
  `$ZIP_PATH` was built or reused.
- **Core build path is fail-HARD** (`set -euo pipefail`, `exit 2`); only the tap-bump is best-effort.
- Test harness (`tap-bump.test.js`): extract an embedded python heredoc by regex+marker, run vs a
  stubbed `urllib.request.urlopen`; OR a script with a `DESCARTES_GITHUB_API_URL` override → local
  `http.createServer`. PATH-stubbing external bins (`stapler`/`spctl`) is the same technique.

## Design

### 1. The notifier source digest (`SOURCE_DIGEST`)

A stable sha256 over the files that determine the built artifact's BEHAVIOR — EXCLUDING the version
substitution (cosmetic; from the template at build):
- every file under `tools/descartes-cli/native/macos/` (the `.swift`, the Info.plist **template**
  with `__DESCARTES_VERSION__` placeholders intact, plus any future `.icns`/resource — none today),
  sorted by path;
- `scripts/build-macos-notifier.sh` + `scripts/notarize-macos-notifier.sh` (signing/build/notarize
  flags live here — a change must force a rebuild).

Computed as `sha256( sorted "<sha256>␠␠<relpath>" lines )` — collision-resistant, order-stable, pure
bash+`shasum`, computable in the guest.

**Deliberately EXCLUDED, with the escape hatch that covers them (should-fix #5/#6):** the code-signing
IDENTITY (cert rotation), the `swiftc`/SDK toolchain, and `release-macos-notifier-buildkite.sh`'s own
build/notarize INVOCATION wiring (`:518-529`). Rationale: reusing an already-valid
notarized+stapled artifact is safe across toolchain changes, and hashing the volatile release script
would force rebuilds on unrelated edits (tap-bump, this very feature). The gap these leave — a
deliberate identity rotation or an invocation-wiring change that should force a fresh build — is
closed by an explicit override: **`DESCARTES_NOTIFIER_FORCE_REBUILD=1` short-circuits the skip
decision straight to BUILD.** See § Runbook.

### 2. The reuse attestation asset (binds a digest to a SPECIFIC zip) — must-fix #3

Each release uploads a small `notifier-reuse.json` asset:
```
{"source_digest":"<64hex>","zip_sha256":"<64hex of THIS release's DescartesNotifier.app.zip>","source_version":"<version of the build this zip originated from>"}
```
`zip_sha256` cryptographically ties the attestation to one exact artifact, so a mismatched/tampered
marker (a digest published next to the wrong zip) can never be trusted by construction — the reuse
gate re-verifies the downloaded zip against `zip_sha256`. On reuse, the JSON we upload for THIS
release carries the CURRENT `source_digest`, the reused zip's `zip_sha256` (unchanged bytes), and the
ORIGINAL `source_version` (so the chain and the version-lag stay honest).

### 3. Skip decision (fail-safe toward BUILD; fail-FAST)

Runs before `:518`; emits `reuse <zip-download-url>` or `build`. **`DESCARTES_NOTIFIER_FORCE_REBUILD=1`
→ `build` immediately.** Otherwise:
1. `GITHUB_TOKEN` + repo slug resolvable (already required downstream)? No → `build`.
2. LIST releases (one page, newest-first), filter `draft:false && prerelease:false && tag =~
   ^v\d+\.\d+\.\d+$ && tag != current && semver(tag) < semver(current)` (should-fix #7 — don't trust
   raw API order); pick the highest such semver that has BOTH `DescartesNotifier.app.zip` and
   `notifier-reuse.json`. None → `build`.
3. Fetch its `notifier-reuse.json`; parse. Unparsable/truncated/missing field → `build` (should-fix
   #8). `source_digest` != current `SOURCE_DIGEST` → `build`.
4. Download that release's `DescartesNotifier.app.zip`. Verify — ANY failure → `build`:
   a. `shasum -a 256 <downloaded>` == the attestation's `zip_sha256` (binds marker↔zip);
   b. `unzip` it; **`CFBundleIdentifier == com.bande-a-bonnot.lightless-labs.descartes.macos.notifier`
      AND `CFBundleExecutable == DescartesNotifier`** (must-fix #2 — prove it's actually our app, not
      a different notarized bundle uploaded under the name);
   c. `codesign --verify --deep --strict` + Team Identifier == the release's signing team (anti-
      substitution: only our Developer ID can produce this);
   d. `stapler validate` + **`spctl --assess --type execute --verbose=4`** (must-fix #1 — `execute`,
      matching `notarize-macos-notifier.sh:90`; the app is `open`-launched, not a `.pkg` install).
5. All pass → place downloaded zip at `$ZIP_PATH`, `$SHA_PATH = shasum(reused zip)`, set
   `NOTIFIER_REUSED=1`, log `reused notifier from <prior tag> (source unchanged; embedded version
   <source_version> lags CLI <version> — see plan §4)`.
6. Guard the build block: `if [[ "${NOTIFIER_REUSED:-0}" != "1" ]]; then <build; notarize; shasum>; fi`.
   Everything downstream (GitHub Release upload, tap-bump) is UNCHANGED — it operates on
   `$ZIP_PATH`/`$SHA_PATH` regardless of origin.

**Fail-FAST, no retry (should-fix #10):** since every failure falls to the safe BUILD path, the
list/fetch/download use a single attempt with a short timeout — retrying just delays an already-safe
fallback. The whole decision is wrapped so any error → `build`.

### 4. Trade-off (explicit, accepted): embedded version lag

A reused `.app` keeps the `CFBundleShortVersionString`/`CFBundleVersion` of the last release where the
notifier source actually changed — it does NOT match the CLI version. **Cosmetic and safe** (verified
repo-wide): permission is keyed to `CFBundleIdentifier`; Gatekeeper/notarization to the signature +
stapled ticket; helper resolution + `descartes alerts notifications status` to PATH — none read the
version. Re-stamping the plist would change the bundle → invalidate signature+notarization → force a
re-notarize, defeating the point; so we deliberately do NOT re-stamp. **One-time external check
(nit):** confirm the Homebrew tap's `Formula/descartes.rb` `test do` block does not assert the
notifier's plist version (it lives in the separate `Lightless-Labs/homebrew-tap` repo).

### 5. Asset upload order (should-fix #9)

The per-release upload loop (`:564-611`) uploads `notifier-reuse.json` **LAST**, only after
`DescartesNotifier.app.zip` + `.sha256` succeed — so a mid-loop crash never leaves a
digest-present/zip-absent state that a future run's step 2 would treat as a reuse candidate.

## Feasibility (must-fix #4 + should-fixes)

- The skip decision runs before `:518`, but `github_release_repository()` (`:539`) and the retry
  helper (`:687`) are defined LATER. → Define the new functions (repo-slug resolution reused/moved
  up, plus `notifier_reuse_decision`, digest, verify) NEAR THE TOP, before the main flow reaches
  `:518`. This is duplication of the bash-heredoc idiom, not literal reuse — stated so explicitly.
- Available at that point (guest): `python3`, `curl`, `unzip`, `shasum`, `codesign`, `stapler`,
  `spctl`, `plutil`/`defaults` (for reading Info.plist) — all standard on the macOS guest. `GITHUB_TOKEN`
  is resolved (Doppler hydration at `:173`) before the release upload; move that resolution (or a
  read-only check) ahead of the skip branch, or simply have the skip decision resolve/require it
  itself and `build` if absent.
- Listing releases needs only read scope the release token already has; one page (per_page≈30) is
  ample. The skip runs BEFORE this tag's GitHub Release is created — correct (it targets PRIOR
  releases only).

## Runbook (should-fix #5)

- **Force a fresh build/notarize** (identity rotation, toolchain bump you want baked in, invocation-
  wiring change, or any doubt): set `DESCARTES_NOTIFIER_FORCE_REBUILD=1` on the release (pipeline env
  or the tag build) → the skip decision returns `build` immediately.
- **Developer ID cert rotation / emergency re-sign:** a routine ~5-yr renewal or a compromise
  response is NOT caught by the source digest (identity is excluded). Do the next release with
  `DESCARTES_NOTIFIER_FORCE_REBUILD=1` to re-notarize under the new identity; subsequent releases then
  reuse the new-identity artifact normally.

## Bootstrap

The first release with this feature finds no prior `notifier-reuse.json` → builds (correct) and
uploads the attestation. From the second post-feature release onward, reuse activates when the source
is unchanged. No back-fill; `v0.0.49` simply lacks the marker and the next release builds once to seed.

## Test strategy (host-runnable; the Apple/guest path stays CI-only)

- **Digest determinism** (host): run the digest fn over a fixture dir → stable, order-independent;
  changing the Info.plist's version *value* does not change it (template hashed), changing the
  `.swift` does.
- **Skip-decision logic** (extract embedded python + stub `urlopen`, mirroring `tap-bump.test.js`):
  (a) force-rebuild env → build; (b) no prior release → build; (c) prior lacks the attestation → build;
  (d) unparsable attestation → build; (e) digest mismatch → build; (f) draft/prerelease/newer/non-semver
  candidates ignored; (g) digest match + valid attestation → `reuse <url>`. Assert it NEVER emits
  reuse without a positive digest match.
- **Integrity/identity gate + verify FALLBACK control flow** (host, via PATH-stubbed fake
  `stapler`/`spctl`/`codesign`/`unzip`, per should-fix #11): a downloaded zip whose sha ≠ attestation
  `zip_sha256` → build; a wrong `CFBundleIdentifier` → build; a nonzero `stapler`/`spctl` exit → build
  (NOT a `set -euo pipefail` crash). These prove the safety-critical fallbacks without a real
  notarized artifact.
- The real notarize-skip + genuine `stapler`/`spctl` on a genuine artifact runs only under the macOS
  Buildkite release job; validated across the next TWO release tags (seed, then observe a reuse).

## Residual trust assumptions (explicit)

- Reuse trusts that a prior release's `notifier-reuse.json` + `DescartesNotifier.app.zip` were produced
  by this pipeline. The gate mitigates tampering four ways (marker↔zip sha binding, bundle-id/exe
  match, codesign team-id, stapler+spctl), so a substitute would have to be a DescartesNotifier bundle
  genuinely signed by our Developer ID and notarized under our account — i.e. an attacker with our
  signing identity, which is out of this pipeline's threat model regardless. Anything short of that →
  the gate fails → build.

## Non-goals

- Decoupling notifier version from CLI version (separate version stream) — the lag trade-off (§4)
  covers the cosmetic gap without complicating the formula/guard.
- Cross-repo / dedicated cache release — the per-release attestation reuses the existing mechanism.
- Changing what users receive: a reused notifier is byte-identical to a prior notarized build.

## Sequencing

TDD the host-testable pieces (digest fn; skip-decision python; integrity/identity gate + verify
fallbacks via PATH stubs) → wire the skip branch + `notifier-reuse.json` (upload last) + the
early-defined helpers into the release script → adversarial review → full suite + `shellcheck` +
`node --check` → commit. First real validation spans the next two release tags (seed, then reuse).
