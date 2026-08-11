# Collector candidate: `apple/container` (native Apple-Silicon containers)

**Created:** 2026-08-11
**Status:** Candidate / not scheduled — a small, well-scoped L0 collector addition.
**Origin:** Slack — Livio Gamassia, on seeing Descartes shared: *"j'espère que y'a 0 docker si tu veux rester apple à fond"* → https://github.com/apple/container

## Why

Descartes' container collector (`tools/descartes-cli/src/tools/containers.js`) already inventories **docker / podman / colima / lima / podman-machine**, read-only. Apple's native containerization (`apple/container`, open-sourced WWDC 2025) is the on-brand gap: on Apple Silicon it's the runtime an Apple-first operator will actually use, and today Descartes would only see those workloads (if at all) via a Docker shim, not natively.

Note the framing for Livio's worry: Descartes **does not depend on Docker** — the container collectors only *detect and enumerate* whatever runtime is present. So "0 docker" is already true; adding `apple/container` just makes native Apple containers a **first-class, natively-seen** surface rather than an invisible one.

## Scope (mirror the existing runtime blocks — do NOT invent new machinery)

Add an `apple-container` runtime alongside the docker/podman/colima blocks in `tools/descartes-cli/src/tools/containers.js`, following the same shape:
- **Detect** the `container` CLI binary (macOS only; gate on platform + presence, degrade-not-fabricate when absent — never error).
- **Enumerate** read-only: running containers + images + system/runtime status via `container`'s list/inspect commands. Bounded output, redacted/bounded command lines, same evidence-envelope shape as the other runtimes.
- **VM correlation:** each `apple/container` workload runs in its **own lightweight VM** (unlike Docker Desktop's single shared VM) — so this likely wants a per-container `vm_correlation` like the colima block already does, and it also touches the **VM collector** (`tools/descartes-cli/src/tools/vms.js`).
- Register/name consistently with the sibling runtimes; TDD with fixtures (no live daemon needed — parse fixed CLI-output fixtures, per the existing collector tests).

## Open items to verify at implementation time (don't assume)

- Exact `container` subcommands + output shape for a machine-readable inventory (e.g. `container ls`, `container images`, `container system status` — confirm names + whether there's a `--format json` / stable parseable output). Facts from memory (Swift `Containerization` framework, per-container lightweight VM, macOS 15+/Tahoe) should be re-checked against apple/container docs.
- Whether it exposes stats (CPU/mem) comparable to `attachStats` in containers.js.
- Update `docs/reference/collectors.md` (the "container basics" line) + `README.md`'s collector list when landed.

## Effort

Small — one runtime block + tests, mirroring a shipped pattern. No new privilege/execFile *class* (another read-only CLI, same as docker/podman), so no doors-and-corners escalation beyond a fixed-argv allowlist for the `container` subcommands.
