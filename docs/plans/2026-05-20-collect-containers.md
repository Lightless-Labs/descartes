# Descartes Container Collector Plan

**Created:** 2026-05-20  
**Status:** Completed  
**Completed:** 2026-05-20 — implemented `collect_containers`, parser tests, guarded triage exposure, docs updates, and v0.0.20 metadata bump.

## Goal

Add a bounded read-only `collect_containers` tool for local container/runtime triage. It should help answer whether Docker, Podman, Colima, or Lima-backed container environments exist, are reachable, and have running/stopped containers consuming resources.

## Scope

- Docker: fixed `docker version`, `docker ps --all`, and `docker stats --no-stream` probes.
- Podman: fixed `podman version`, `podman ps --all`, and best-effort `podman stats --no-stream` probes.
- Colima: fixed status/list probes as container-host context, not container inventory.
- Lima: fixed `limactl list --json` probe as container-host context, not full VM inventory.
- Normalize runtime availability, container list, resource snapshots, host instances, unsupported/missing commands, and probe metadata into one evidence envelope.

## Safety

- Read-only fixed command argv arrays only.
- No start/stop/create/delete/prune/exec/log-copy operations.
- Strict container/host bounds.
- Missing commands, stopped daemons, and permission-limited sockets must not fail the whole collector.
- Container names/images/commands/ports are sensitive diagnostic artifacts.

## Acceptance Criteria

- Parser tests cover Docker ps/stats, Podman ps/stats, Colima status/list, Lima list, missing/permission command classification, numeric parsing, and bounds.
- `collect_containers` is exposed in the guarded triage tool surface.
- The triage prompt tells the model to use `collect_containers` for Docker/Podman/Colima/Lima/container questions.
- README/handoff/todo document the collector and package metadata is bumped.
- `npm test` passes.
