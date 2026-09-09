# Shared macOS CI image migration

Status: independently source-reviewed; native image bake1 and fresh-plugin clone2 passed. Consumer CI270 passed on published main4a5aed4.
Reviewed: 2026-09-09 by gpt-5.6-sol; 8 focused helper cases passed independently, including actual Bash/zsh invocation.
Owner direction September 9: all compatible macOS builds use one shared image with baked toolchains, retaining disposable job clones. No additional agents.

Canonical image contract lives in Lightless-Labs/lightless-labs at `foundry/docs/plans/2026-09-09-shared-macos-build-toolchains.md` (local `/tmp/shared-macos-image-20260909/`). The candidate is `ci-macos-rust-bazel-ios-20260909-v1`, derived from the existing shared base and retaining Xcode 26.3 while adding Rust 1.88.0, Bazel 8.2.1 and Node v22.21.1. Actual bake and fresh-clone smoke must pass before Descartes publishes this migration.

## Atomic implementation boundary

Update only both macOS image references in `.buildkite/pipeline.yml`, retaining their queue, concurrency group, plugin, conditions, secret wiring, commands and artifacts. The Linux steps must remain byte-identical. Replace only the macOS Node download/install functions with a sourced helper `scripts/use-ci-node.sh` that validates Darwin/arm64, a valid user HOME, and executable `$HOME/.local/node-v22.21.1-darwin-arm64/bin/node` returning exactly `v22.21.1`, then prepends that bin directory to PATH. It must clearly reject missing/wrong baked tools without downloading or modifying the image. Source the helper before copying/changing the checkout directory in both macOS jobs. Preserve the release flow unchanged otherwise.

Luna owns `.buildkite/pipeline.yml`, `scripts/use-ci-node.sh`, and `scripts/test_use_ci_node.py` only. Root owns this plan, handoff, final review, Git and Buildkite operations. Test first with temporary fake Node/platform executables; cover valid cache, missing cache, wrong version and wrong platform, with no network, real installations, native compilation or account access. Parse YAML and bash syntax; compare the Linux prefix unchanged. Sol independently reviews the final diff and reruns focused tests. Do not run the application, agent, or release tooling.

Actual acceptance: fresh clone proves baked Node and normal noninteractive tool PATH; one Descartes macOS CI build must execute successfully using the shared image. No signing/notarization release is required or inferred by this infrastructure migration. Existing product validation gates remain unchanged.

Native evidence: [bake1](https://buildkite.com/la-bande-a-bonnot/shared-macos-image/builds/1) at `07d530050ded01a8b41dbbaf552f256b3e770057`; [fresh clone2](https://buildkite.com/la-bande-a-bonnot/shared-macos-image/builds/2) at `0597acf8257aa828c76203b2535c9bedf59b2b2f`. Full shared toolchain/compiler smoke passed; plugin log records exact clone stop/delete. Root helper checks also passed8/8. No Descartes app CI or release is inferred.

Completed: 2026-09-09 for this Descartes migration. [CI270](https://buildkite.com/la-bande-a-bonnot/descartes/builds/270) executed the shared-image macOS job with Nodev22.21.1 and1942 tests passing/0 failing/34 skips; both Linux jobs passed. Exact job-clone stop/delete observed. Tag-only notifier release did not run. No app product behavior was changed.
