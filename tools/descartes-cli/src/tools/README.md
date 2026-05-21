# Descartes evidence collectors

This directory contains Descartes' local read-only evidence collectors. They are the factual boundary for model-led triage: the model may decide which collector tool to call, but system facts must come from these deterministic collectors and their structured evidence envelopes.

For the operator-facing catalog, see `../../../../docs/reference/collectors.md`.

## Directory map

| File | Purpose |
|---|---|
| `envelope.js` | Shared evidence envelope helpers. |
| `system.js` | OS, host, CPU/load, memory, swap. |
| `processes.js` | Top processes, bounded/redacted command lines, PID inspection, parent trees. |
| `disks.js` | Filesystem space/inode usage and pressure relevance classification. |
| `network.js` | Interfaces, default routes, DNS resolver/reachability, listening sockets. |
| `services.js` | launchd/systemd service state. |
| `logs.js` | Bounded recent warning/error/security-oriented log excerpts. |
| `containers.js` | Docker, Podman, Colima, Lima, and Podman machine container/runtime/host inventory. |
| `vms.js` | Local VM runtime inventory, container-host correlation metadata, and VM-like process hints. |
| `scheduled-jobs.js` | cron, systemd timers, and launchd scheduled job definitions. |
| `time-sync.js` | Local clock/NTP state and optional bounded NTP offset checks. |
| `certificates.js` | Bounded local certificate validity inventory for common stores/paths. |
| `sampling.js` | Bounded temporal sampling and Descartes-owned sampling artifacts. |
| `findings.js` | Deterministic findings derived from evidence envelopes. |
| `collect.js` | Compact first-pass triage bundle: system, processes, disks, findings. |

Tool exposure lives in `../pi-harness.js`. The exact allowed guarded tool surface lives in `../tool-policy.js` and must be updated whenever a model-visible tool is added or removed.

## Evidence envelope contract

Collectors should return an envelope shaped like:

```json
{
  "id": "time-sync",
  "status": "ok",
  "layer": "L0",
  "source": "time_sync",
  "result": {},
  "confidence": 0.85,
  "review_hint": "none",
  "trace": {
    "tool": "collect_time_sync",
    "target": "check_offset=false",
    "latency_ms": 12,
    "ts": "2026-05-21T00:00:00.000Z"
  }
}
```

Use `evidenceEnvelope()` and `timedEnvelope()` from `envelope.js` unless there is a strong reason not to.

## Collector rules

- Read-only by default; no mutating host action.
- No arbitrary shell strings. Use fixed commands and argument arrays through `execFile`.
- Bound output size, item counts, timeouts, sample duration, and file reads before parsing untrusted/local scheduler content.
- Represent missing tools, unsupported platforms, permissions, and daemon/socket failures as structured `unknown`/`unable` evidence rather than throwing or panicking.
- Capture command argv, read-only intent, stderr/error boundaries, and per-probe status when shelling out.
- Redact obvious secrets from process args, log excerpts, scheduled commands, and process-backed hints.
- Treat local evidence as sensitive diagnostic artifacts even when redacted.
- Do not read or write Pi-owned paths. Descartes-owned artifact paths must go through the path helpers and guardrails.
- Do not add a new collector to `collect_triage_evidence` by default; that bundle intentionally remains the compact resource-pressure first pass.

## Network behavior

Most collectors should not contact the network. If a collector can contact the network, make it explicit in parameters and documentation.

Current network-capable behavior:

- `collect_network_basics` may perform a DNS lookup for reachability unless disabled by `check_dns_reachability: false`.
- `collect_time_sync` only performs an external NTP offset probe when `check_offset: true` is requested, and validates the server value so it cannot become an `sntp` option.
- `collect_certificates` does not contact the network; it reads bounded local certificate files/stores and intentionally does not read private keys.

## Adding a collector

1. Create `tools/descartes-cli/src/tools/<name>.js`.
2. Export a `collect<Name>Evidence()` function that returns one evidence envelope.
3. Add parser/normalizer helpers as named exports when useful for tests.
4. Add tests under `tools/descartes-cli/test/<name>.test.js` before or alongside implementation.
5. Expose the tool in `../pi-harness.js` with a narrow TypeBox parameter schema.
6. Add the tool name to `../tool-policy.js` and update `tool-policy.test.js`.
7. Update `README.md`, `docs/reference/collectors.md`, `docs/HANDOFF.md`, and the relevant todo/plan notes.
8. Bump package metadata if this is a user-visible package slice.
9. Run the smallest relevant tests, then `npm test` before finishing.

## Tests

Prefer parser fixtures and normalizer tests over host-specific assertions. Direct host smoke checks are useful, but tests should not require a particular OS service manager, container runtime, VM runtime, network state, or credentials.
