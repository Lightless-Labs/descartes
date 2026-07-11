---
title: "macOS Buildkite jobs red for ~20h: two concurrent Tart macOS guests starve each other and die mid-job"
date: 2026-07-11
category: ci
module: buildkite-pipeline
problem_type: ci_infrastructure
component: tooling
symptoms:
  - "macOS Apple Silicon CI job fails with heterogeneous errors while the Linux job stays green"
  - "SSH 'Read from remote host: Connection reset by peer' / 'client_loop: send disconnect: Broken pipe', exit 255 mid-command"
  - "npm error ENOENT: no such file or directory, open '/Users/admin/descartes-checkout/package.json' (guest checkout empty or vanished)"
  - "npm itself crashes with errno -2 inside @npmcli/config during npm ci"
  - "tart-ci command hook exits 7 (network connect failure during Node.js download)"
  - "macOS job durations jump from ~34 min (solo) to ~77-92 min (paired) before dying"
---

## Problem

Every `main` build from #108 (2026-07-10 21:40 UTC) through #120 (2026-07-11) failed in the
`:mac: macOS Apple Silicon` job while `:linux: Linux ARM64` passed every time (552 tests,
550 pass + 2 darwin-only skips — identical to local). The failures looked like test/code
regressions correlated with the Layer-B S4 push, but none ever reached a real test failure:
each was a different infrastructure death (SSH reset-by-peer, empty rsync'd checkout,
npm ENOENT mid-run, curl connect failure), i.e. the guest VM's filesystem/network/liveness
degrading under load.

## Root cause

The `big-cabbage/tart-ci` concurrency group allowed 2 concurrent jobs, so with ≥2 queued
builds the two builds' macOS VMs always ran **paired** on one host. Two concurrent macOS
Tart guests starve each other on big-cabbage: solo macOS jobs take ~34 min (#104: 2053s);
paired jobs take ~77-92 min (4600-5500s) and one or both die (VM/sshd killed, shared
`/Volumes/My Shared Files/checkout` automount unstable, guest network failing). The state
was **self-sustaining**: every push queued another build, paired macOS jobs took 2x+ longer,
so the queue never drained and macOS jobs kept pairing. #107 vs #108 is the cleanest
evidence: started 37s apart, ended within 8s of each other at ~77 min — one passed, one died.

Diagnosed entirely via the Buildkite REST API (read-only token): list builds → per-job
`state`/`started_at`/`finished_at` → `raw_log_url` for the failing jobs.

## Fix

`.buildkite/pipeline.yml`: split the concurrency groups so at most ONE macOS guest runs at
a time, shared between the CI and release jobs (a tag build can still overlap a main build,
which is why they must share a group):

- `:mac:` CI job + `:apple:` release job → `concurrency_group: "big-cabbage/tart-ci-macos"`,
  `concurrency: 1`
- `:linux:` job → `concurrency_group: "big-cabbage/tart-ci-linux"`, `concurrency: 2`
  (Linux guests are ~20s per job and do not count toward the macOS two-guest license limit)

**Deploy-order caveat:** renaming a concurrency group must not happen while old-group jobs
are running/queued — jobs in the new group ignore the old group's slots, so a push mid-queue
briefly allows old-pair + new jobs to run simultaneously (3-4 VMs), making everything worse.
Wait for the old-group queue to drain first.

## Prevention / follow-ups

- Consider enabling **"Cancel Intermediate Builds"** in the Buildkite pipeline settings
  (needs UI/admin; the API token used was read-only) so rapid push cadence can't pile up
  stale queued builds behind a 34-min macOS job.
- If a macOS job ever dies solo again, the next diagnostic step is on-host (big-cabbage):
  the tart-ci run log path is printed in the job log
  (`/var/folders/.../T/tart-ci/<vm-id>/tart-run.log`).
- Don't trust "CI red since commit X" as evidence that commit X broke it: check WHICH job
  failed and whether it reached the test runner at all before bisecting code.
