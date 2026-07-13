# Descartes Incident Freeze Reference

**Updated:** 2026-07-13

`descartes incident freeze` is the observed-incident collectors milestone's Slice 2 (see
`docs/plans/2026-07-13-observed-incident-collectors.md`). It is documented separately from
`docs/reference/collectors.md` because it is not a collector — it is an **action** that persists a
Descartes-owned forensic snapshot by orchestrating the already-registered collector set.

## Safety: read-only against the monitored host

**`descartes incident freeze` mutates nothing on the monitored host.** It persists new
Descartes-owned state (a JSON evidence bundle plus an audit log line under
`stateDir/evidence/`), but it does this by calling **only** the already-registered,
already-reviewed read-only evidence-tool set from `pi-harness.js`'s `createEvidenceTools()` — the
exact same tools `descartes triage` already uses. It introduces **zero new `execFile`/`spawn`
surface**: every command it runs is a command one of the existing collectors already runs, and
this is enforced by a standing regression test (`test/evidence-freeze.test.js`), not left as an
unchecked promise.

This is the concrete boundary between "detect/monitor/log/inform" (this action, and every other
slice in the milestone) and "contain" (kill/revoke/block/quarantine a live process, credential,
peer, or container) — that entire class of mutating verb is explicitly **not implemented anywhere
in this repository**; it is scoped, design-only, in the plan's Slice 7 and requires its own
dedicated plan, safety review, and multi-party authority mechanism before a single line ships.

## What gets captured

A freeze snapshots every already-registered broad, zero-argument `collect_*` evidence tool (system
overview, processes, disks, network basics, services, recent logs, containers, VMs, scheduled
jobs, time sync, certificates, session census) in parallel. Targeted, single-entity tools
(`inspect_process`, `inspect_parent_tree`, `inspect_runtime_provenance`, `sample_dimension`,
`read_sampling_artifact`) and the derived/aggregate `collect_triage_evidence` and `derive_findings`
tools are deliberately not called — they either need a specific pid/port/container/dimension target
a "snapshot everything now" action has no meaningful way to supply, or they re-derive data already
captured individually.

If one evidence source is unavailable or errors, the bundle is still written with that source
marked `degraded` — a snapshot with 9 of 10 sources beats no snapshot at all. A freeze never fails
outright just because one collector degraded.

## Bundle format and integrity

Each freeze writes one file to `stateDir/evidence/<timestamp>-<nonce>-<reason-hash>.json`
(directory mode `0o700`, file mode `0o600`), written atomically (temp file, then a hard-link
publish step that fails loudly — `EEXIST` — rather than silently overwriting an existing bundle on
an actual filename collision; the random nonce is what makes an actual collision astronomically
unlikely in the first place). The bundle carries a `sha256` integrity digest computed over its own
contents; recomputing that digest over a read-back bundle and comparing it against the stored value
detects any tampering (a single flipped byte anywhere in the file changes the recomputed digest).

Every invocation also appends one line to `stateDir/evidence/freeze-audit.jsonl` recording who/what
triggered the freeze, the timestamp, and each evidence source's succeeded/degraded status.

## Reason handling

`--reason <text>` is a free-text operator note. It is sanitized and bounded (charset-restricted,
length-capped) before it ever reaches the persisted manifest, and it is **hashed**, not embedded
raw, in the filename — a path-traversal-shaped or shell-injection-shaped reason cannot affect the
filename or escape into a path.

## Explicit exemptions (by design, not oversights)

- **Not gated by `configDir/learned.json`.** This is an on-demand action like `descartes triage`,
  not an inference artifact — it has no draft/shadow/review-ready lifecycle, because it captures
  facts rather than asserting a conclusion.
- **No automatic trigger in v0.** `descartes incident freeze` is operator-invoked only. There is no
  daemon-initiated auto-freeze on alert — wiring one would start to brush the authority/containment
  plane and is deliberately deferred.
- **Never enters an LLM prompt.** The bundle is a pure operator-facing forensic artifact. Unlike
  alert `diagnostics`/`compactAlert` (the only thing ever handed to the S13 LLM adjudication path),
  no evidence-freeze bundle is ever passed to `createSession`/`session.prompt`/`compactAlert`.
- **Never auto-deleted.** Evidence bundles are not subject to `fact-store.js`'s 30-day/5MB
  retention cap — they live under their own `stateDir/evidence/` directory, structurally outside
  that store's reach, because evidence is potentially legal-hold material. Retention policy for
  evidence bundles is an open question (see the plan's §7) — no auto-deletion of any kind is
  implemented.
- **No privilege escalation.** Same-UID as whatever collectors it calls already are.

## CLI

```bash
descartes incident freeze [--reason <text>] [--json]
```

See `docs/reference/collectors.md` for the underlying evidence-tool catalog this action reuses.
