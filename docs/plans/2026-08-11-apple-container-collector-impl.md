# `apple/container` collector — implementation plan

**Created:** 2026-08-11
**Purpose:** add a native, read-only `apple-container` runtime block to the existing container
collector, mirroring the shipped docker/podman/colima/lima/podman_machine blocks exactly, plus a
narrow per-container VM-correlation seam in the VM collector — no new collection machinery, no
alert, no daemon/fact-store wiring.
**Todo:** `todos/2026-08-11-apple-container-collector.md`
**Reviewed:** 2026-08-11 (Fable + gpt-5.6-sol) — Fable GO_WITH_CHANGES, sol UNAVAILABLE (no
second-model review obtained). Fable's must-fix (ps-probe reuse seam in
`correlateContainerHostResources` early-returning before the apple-container correlation path
could ever reuse it) resolved in-plan with an exact scan-gate/return-shape refactor — see
"`correlateContainerHostResources` scan-gate refactor" under New code and test 6a under Test plan.
**Scope discipline:** this plan is Phase 1 only (collector + fixture-driven tests). Phase 2
(wiring a `container.*`-namespaced disappearance alert) is explicitly deferred — see
"COLLISION-WITH-SHARED-ALERT-PIPELINE" below.

## Research findings (verified against `apple/container` docs, 2026-08-11)

Read `docs/command-reference.md` from `apple/container` (GitHub, `main` branch) directly — do not
trust the todo's WWDC-2025-era assumptions uncritically; two corrections came out of this:

1. **Subcommand namespace is `container image ...` (singular), not `container images`.** Relevant
   verified subcommands + flags:
   - `container list [--all] [--format json|table|yaml|toml] [--quiet]` — container inventory.
     `--all`/`-a` includes non-running containers (mirrors `docker ps --all`).
   - `container inspect <ids>...` — JSON detail, no `--format` flag (always JSON).
   - `container stats [--format json] [--no-stream] [<ids>...]` — CPU%, memory, net I/O, block
     I/O, process count. `--no-stream` gives one snapshot (mirrors `docker stats --no-stream`).
   - `container image list [--format json|table|yaml|toml] [--quiet] [--verbose]` — local image
     inventory.
   - `container system status [--format json|table|yaml|toml]` — health-checks the
     `container-apiserver` background service and returns basic system info (this is the
     install/available probe; structurally like `colima status --json`, not like
     `docker version`).
   - `container system version [--format json|table|yaml|toml]` — CLI + (if reachable) server
     version, two-row table when the API server responds (mirrors `docker version`/`podman
     version`'s split client/server shape).
   - **No field-level JSON schema is published** for any of the above — the doc only documents
     `--format json` exists. Exact key names (`id` vs `ID`, `image` vs `Image`, etc.) are
     genuinely unknown until captured. Per the todo's own instruction and the project's
     degrade-not-fabricate invariant, the parser must be written against a **captured real fixture
     of `container list --all --format json` / `container image list --format json` / `container
     system status --format json` output** (from a teammate's Apple Silicon Tahoe machine, or from
     `apple/container`'s Swift model source as a fallback), not guessed key casing. Until that
     fixture exists, write the parsers defensively with the same `firstDefined(...)`-style
     multi-key-candidate fallback `vms.js` already uses for other ambiguous CLI JSON (e.g.
     `parseTartListJson`), rather than assuming a single casing.

2. **The "own lightweight VM per container" framing needs a correction before it can drive a
   design.** As of the 1.0 CLI (`apple/container` 1.0.0, mid-2026), there are **two distinct,
   unrelated VM-shaped surfaces**:
   - The per-`container run`/`container create` Containerization-framework VM that backs each
     regular container. This is **not independently enumerable** — there is no `container vm
     list` or similar; it's an internal implementation detail of `container-apiserver`. The
     closest observable trace of it is host-side: a per-container hypervisor/init helper process
     visible in `ps` (exact binary/command-line signature **unconfirmed** — this dev machine
     cannot run VMs per existing memory note, and the doc doesn't name the process; a real Tahoe
     capture or a read of `apple/container`'s `Sources/` is required before writing the `ps`
     matcher).
   - `container machine create/run/list/inspect/...` — a **new, separate, opt-in** "boot a full
     guest-OS VM from an image" feature added in 1.0. It has its own listable/inspectable
     entities, but it is **not what a regular `container run` container runs in** — treating
     `container machine list` output as "the container's host VM" (i.e. mirroring it into
     `container_hosts` the way `colima list`/`podman machine list` are today) would misattribute
     an unrelated feature and violate degrade-not-fabricate.

   **Design consequence:** do not add an `apple-container` entry to `container_hosts` (there is no
   analog to "one named, listable shared VM" here). Instead, express the 1:1 container↔VM
   relationship as a per-**container** `vm_correlation` stub (cheap, always derivable from the
   container's own id — see below) plus an *optional* `process_correlation`/`resource_snapshot`
   sourced from the existing `ps`-scan mechanism, gated on confirming the real process signature.
   If that signature cannot be confirmed before landing, ship without
   `process_correlation`/`resource_snapshot` (degrade, don't fabricate) and file the signature
   confirmation as a tightly-scoped follow-up — do not block the collector on it.

## Non-finding: containers.js/vms.js are NOT wired into the daemon/fact/alert pipeline today

Checked directly (`ast-grep`/`grep` over `src/daemon.js`, `src/fact-translators.js`,
`src/pi-harness.js`): `collectContainerEvidence`/`collectVmEvidence` are **only** invoked from
`pi-harness.js`'s `collect_containers`/`collect_vms` model-visible tools (on-demand triage) and the
CLI. Neither `runDaemonIteration`'s fast tick nor its structural tick (`collectStructuralEvidence`,
`factPointsFromServiceEvidence`-style translators, `extraCandidates`) touches either file. This
means Phase 1 genuinely has **zero collision surface** with `daemon.js`, `fact-translators.js`,
`alert-intelligence.js`, `calibration.js`, `notification-delivery.js`, or `learned.json` defaults —
confirmed, not assumed. It also means this phase produces **no fact, no marker, and no alert**: it
is a pure read-only evidence-collector extension, exactly mirroring the fact that none of
docker/podman/colima/lima/podman_machine alert either.

## New code — exact location, exact shape

No new files. Both edits are additive blocks in the two named sibling files, following their
existing per-runtime function-group convention (parse fn(s) → `collectX(request)` → wired into the
top-level `Promise.all`).

### `tools/descartes-cli/src/tools/containers.js`

- `DEFAULT_IMAGE_LIMIT = 60` constant (new, alongside `DEFAULT_CONTAINER_LIMIT`/`DEFAULT_HOST_LIMIT`).
- `normalizeContainerRequest`: add `image_limit: clampNumber(options.imageLimit ?? options.image_limit, DEFAULT_IMAGE_LIMIT, 1, 200)`.
- `parseAppleContainerListJson(stdout, { limit, includeStopped })` — mirrors
  `parsePodmanPsJson`'s shape (per-container list, not a host list): `{runtime:
  "apple_container", id, name, image, command, command_redaction, state, status, ports,
  source_runtime: "apple_container", confidence: 1, vm_correlation}`. `vm_correlation` is always
  `{ runtime: "apple_container", name: <id>, confidence: 1 }` when an id is present — cheap,
  always-derivable, and honestly represents "this container has its own VM" without claiming any
  additional VM-specific fact not otherwise observed (see research finding #2).
  Command redaction reuses `redactContainerCommand` (already generic). State normalization reuses
  `normalizeContainerState` (already generic; verify at implementation whether `container`'s state
  strings need a new branch, e.g. `"stopped"` vs `"exited"` — normalize defensively either way).
- `parseAppleContainerImageListJson(stdout, { limit })` — new, no existing sibling to mirror 1:1
  (docker/podman blocks in this file don't collect images today; this is a genuinely new
  dimension the todo asks for). Shape: `{runtime: "apple_container", repository, tag, digest,
  size_bytes, source_runtime: "apple_container", confidence: 1}`.
- `parseAppleContainerStatsJson(stdout)` — mirrors `parsePodmanStatsJson`'s `Map` shape (keyed by
  id/name) for `attachStats` reuse (already generic, no changes needed to `attachStats` itself).
- `parseAppleContainerSystemStatusJson(stdout)` — mirrors `parseColimaStatusJson`'s single-object
  availability read (health-check shape, not a version probe).
- `parseAppleContainerVersionJson(stdout)` — mirrors `parseDockerVersion`/`parsePodmanVersion`.
- `collectAppleContainer(request)` — mirrors `collectDocker`'s parallel-probe shape: `[statusProbe,
  versionProbe, listProbe, imageListProbe]` via `Promise.all`, then a conditional `statsProbe`
  gated on `request.collect_stats && containers.some(running)` exactly like `collectDocker`.
  `runtimeFromProbe("apple_container", statusProbe, version)` — **status probe is primary**
  (mirrors `collectColima`, not `collectDocker`), since `container system status` is the
  documented health/availability check, not a version command.
- `collectContainerEvidence`: add `collectAppleContainer(request)` to the top-level `Promise.all`
  array; flat-map `result.images ?? []` into a new `rawContainerImages` bounded by
  `request.image_limit`, exposed as a new top-level `container_images` array (parallel to
  `containers`/`container_hosts`, empty for every runtime except `apple_container` today —
  intentionally not merged into `containers`, which is containers-only across runtimes).
  `summarize()` gains `image_count: images.length`. Envelope `target` string gains
  `,images=${request.image_limit}`. `privacy.note` gains "image repository/tag" to the sensitive-fields list.
- New, small, dedicated `correlateAppleContainerProcessHints(containers, processHints)` —
  deliberately a **separate function**, not a generalization of the existing
  `correlateContainerHostProcessHints`/`containerHostProcessMatchScore` (which score against
  `hosts`, a different entity shape/semantics from `containers`). That pure function and its
  existing tests are untouched by this plan (see the softened blast-radius note below — the scan
  gate it depends on *is* touched). Only reached when `request.collect_stats` is true and at least
  one `apple_container` container exists; consumes `apple_container`-runtime hints from
  `parseVmProcesses` (see vms.js edit below) via the same `ps -axo ...` scan
  `correlateContainerHostResources` already runs, per the scan-gate refactor immediately below (do
  not add a second `ps` invocation). Attaches `process_correlation`/`resource_snapshot` matched by
  container id/name, same shape as the existing host correlation's output fields.
- **`correlateContainerHostResources` scan-gate refactor — must-fix from Fable review
  (2026-08-11):** the shipped function
  (`tools/descartes-cli/src/tools/containers.js:450-461`) early-returns *before* running `ps`
  whenever `hosts.length === 0`, and its return shape is `{hosts, probes, correlation}` — the
  computed `processHints` are never handed back to the caller. In the most common
  `apple_container`-only scenario (apple-container containers present, zero colima/lima/podman-
  machine hosts), `hosts.length === 0`, so the unmodified function would never invoke `ps` at all
  and `process_correlation` could never attach for apple-container containers. Exact fix:
  - Change the signature to accept a third, optional options argument:
    `correlateContainerHostResources(hosts, request, { hasAppleContainerCandidates = false } = {})`.
    `collectContainerEvidence` computes `hasAppleContainerCandidates` once it has the
    `apple_container` container list (`appleContainerContainers.length > 0`) and passes it at the
    single existing call site (`containers.js:590`); this is the only call site today, so no other
    caller needs updating.
  - Change the early-return guard from `if (hosts.length === 0)` to
    `if (hosts.length === 0 && !(request.collect_stats && hasAppleContainerCandidates)) return
    { hosts, probes: [], correlation: { correlated_host_process_count: 0,
    uncorrelated_host_process_hint_count: 0 }, processHints: [] };` — i.e. still short-circuits
    when there is nothing to correlate against on *either* side, but now also runs when there are
    apple-container containers to correlate even though `hosts` is empty.
  - When the gate passes (either reason), run the single `ps` probe and compute `processHints`
    exactly as today (no change to the probe args or the `parseVmProcesses` call).
  - Add `processHints` as a fourth field on the normal return value:
    `{hosts: correlation.hosts, probes: [...], correlation, processHints}` — so
    `collectContainerEvidence` can hand the same array straight into
    `correlateAppleContainerProcessHints(appleContainerContainers, processHints)` without a second
    `ps` invocation or a second `parseVmProcesses` parse.
  - Net effect: **exactly one `ps` invocation per `collectContainerEvidence` call**, still skipped
    when there is truly nothing to correlate (no hosts, no apple-container stats request, or
    `request.collect_stats` false), and the parsed `processHints` are now available to both the
    existing host-correlation path and the new container-correlation path from that single probe.
  - **Blast-radius correction (softens the original claim):** the pure
    `correlateContainerHostProcessHints`/`containerHostProcessMatchScore` functions and their
    existing tests are untouched — confirmed, `correlateContainerHostResources` is not itself
    covered by any existing unit test (`test/containers.test.js` only tests the pure
    `correlateContainerHostProcessHints`), so this is a behavior-preserving-for-existing-callers
    signature/return-shape widening, not a zero-diff change. The existing
    colima/lima/podman_machine path (`hosts.length > 0`) takes the same branch as before and
    receives the same `{hosts, probes, correlation}` fields unchanged, plus the new
    `processHints` field it can ignore.
- Wire the new correlation step into `collectContainerEvidence` right after the widened
  `correlateContainerHostResources` call, passing its returned `processHints` straight into
  `correlateAppleContainerProcessHints(appleContainerContainers, processHints)` (**no new
  execFile/shell surface** — same fixed `ps -axo ...` / `ps -eo ...` argv already in the allowlist,
  invoked at most once per collection either way).

### `tools/descartes-cli/src/tools/vms.js`

- `processRuntime(command, args)`: add one new `haystack.includes(...)` branch returning
  `"apple_container"`. **Exact substring is VERIFY-AT-IMPLEMENTATION** (candidates to check
  against a real Tahoe `ps -axo pid,ppid,pcpu,pmem,rss,comm,args` capture with an active `container
  run` container: a `vminitd`/`container-runtime-linux`-style helper, or a
  `com.apple.container.*`/Containerization-framework path segment — mirror how the existing
  `apple_virtualization` branch matches `virtualizationservice`/
  `com.apple.virtualization.virtualmachine`/`/virtualization.framework/`). If no reliable
  signature can be confirmed, **skip this branch entirely** rather than guessing — `containers.js`
  degrades to the tautological `vm_correlation` stub with no `process_correlation`, which is still
  an honest, useful result.
- `parseVmProcesses` needs no changes — it already calls `processRuntime` generically and will
  pick up the new branch automatically once added.
- Export nothing new from `vms.js` for this — `containers.js`'s new
  `correlateAppleContainerProcessHints` consumes `parseVmProcesses`' output the same way
  `correlateContainerHostResources` already does (already imported: `import { parseVmProcesses }
  from "./vms.js"`).
- Explicitly **do not** touch `compatibleProcessRuntime`, `vmProcessMatchScore`,
  `correlateVmProcessHints`, or add an `apple_container` entry to `parseTartListJson`-style VM
  inventory. Per research finding #2, apple-container containers are not "VMs" in `vms.js`'s own
  inventory sense (they're not listed by any `vms.js`-native tool the way Tart/Colima/Lima VMs
  are) — they only ever appear as `containers.js` container entries. Adding them to `vms.js`'s own
  `collectVmEvidence()` output would double-count/misclassify a container as a VM inventory item.

## Fact / marker consumed or produced

**None.** Confirmed above: `containers.js`/`vms.js` are not wired into `fact-store.js` or
`fact-translators.js` today, and this plan does not add that wiring (see collision note below).
The only new "fact" is inside the evidence envelope's own `result` shape
(`container_images`, per-container `vm_correlation`/`process_correlation`) — visible to
`pi-harness.js`'s model-visible tool and CLI callers, not persisted to any store.

## Alert(s) + severity

**None in this phase.** Mirrors every existing block in `containers.js` (docker, podman, colima,
lima, podman_machine) — none of them alert either; they are pure evidence collectors. See
"COLLISION-WITH-SHARED-ALERT-PIPELINE" for the deferred Phase 2 sketch.

## Exact wiring edits, named by file

| File | Change | Needed for Phase 1? |
|---|---|---|
| `tools/descartes-cli/src/tools/containers.js` | New parse fns, `collectAppleContainer`, `correlateAppleContainerProcessHints`, `correlateContainerHostResources` scan-gate/return-shape refactor (must-fix), `Promise.all` entry, `container_images` field, `summarize()`/`normalizeContainerRequest`/envelope `target`/`privacy.note` updates | **Yes** |
| `tools/descartes-cli/src/tools/vms.js` | New `processRuntime` branch only | **Yes** |
| `tools/descartes-cli/src/pi-harness.js` | Cosmetic: mention "Apple container" in the `collect_containers` tool `description` string and preferred-flow guidance item 7 (both plain prose, no schema/logic change) | Optional, low-risk, do if time allows |
| `docs/reference/collectors.md` | `collect_containers` row: add `image_limit?: 1..200` to the parameters column; "Sources" bullet list gains an "Apple container (`apple/container`)" line; "Behavior" prose gains the `container_images`/per-container `vm_correlation` sentence | **Yes** (todo explicitly asks for this) |
| `README.md` | Line ~98 "container basics" bullet: add "Apple container" to the runtime list | **Yes** (todo explicitly asks for this) |
| `src/daemon.js` | none | **No — do not touch** |
| `src/fact-translators.js` | none | **No — do not touch** |
| `src/alert-intelligence.js` (`KNOWN_ALERT_NAMESPACES`/`classifyAlertNamespace`) | none | **No — do not touch** |
| `src/calibration.js` | none (generic per-rule_id proxy; would auto-cover a future alert with zero changes) | **No — do not touch** |
| `src/notification-delivery.js` | none (generic delivery path) | **No — do not touch** |
| `configDir/learned.json` defaults | none | **No — do not touch** |

## Test plan (fixture-driven, mirror the named siblings — no live daemon/VM needed)

`test/containers.test.js` (mirror the existing `parseDockerPsJsonLines`/`parsePodmanPsJson`/
`parseColimaListJson`/`correlateContainerHostProcessHints` tests already in this file):

1. `normalizeContainerRequest` — assert the new `image_limit` clamp (999 → 200, 0 → 1), same style
   as the existing "clamps limits and preserves booleans" test.
2. `parseAppleContainerListJson` — one fixture with a running + a stopped container, asserting:
   normalized `state`, redacted `command` + `command_redaction`, `source_runtime:
   "apple_container"`, and the always-present `vm_correlation` stub. A second assertion for
   `includeStopped: false` filtering (mirrors the Docker test's second `assert.equal(...length,
   1)` line).
3. `parseAppleContainerImageListJson` — fixture with 2+ images, asserting bounded `size_bytes`
   parsing (reuse `parseByteQuantity` if the field is a human string, or plain number pass-through
   if numeric — confirm against the captured fixture) and `limit` truncation.
4. `parseAppleContainerStatsJson` — fixture asserting the returned `Map` is keyed by both id and
   name (mirrors the existing Docker/Podman stats tests), and that `attachStats` (already generic,
   no test change needed there) correctly attaches a `resource_snapshot` to a matching
   `parseAppleContainerListJson` entry in a small integration-style unit test.
5. `parseAppleContainerSystemStatusJson` — fixtures for the "daemon up" and empty/`unable` shapes,
   feeding into the already-generic `classifyCommandFailure`/`runtimeFromProbe` (no new test needed
   for those — existing `classifyCommandFailure` test's "distinguishes missing, daemon, permission,
   and unknown failures" coverage already exercises the shared classifier against any `command`
   failure shape, including a synthesized `container` one).
6. `correlateAppleContainerProcessHints` — new test mirroring "correlateContainerHostProcessHints
   attaches process resource snapshots to matching hosts", but against `containers` entries and an
   `apple_container`-runtime process hint fixture (using whatever signature substring lands from
   the vms.js verification step). Include a no-match case asserting the container's
   `vm_correlation` stub survives untouched (degrade, not fabricate) when no process hint matches.
6a. `correlateContainerHostResources` scan-gate — new tests covering the must-fix refactor above,
   since this function has no existing direct test today (only the pure
   `correlateContainerHostProcessHints` is currently covered): (a) `hosts: []`,
   `hasAppleContainerCandidates: false` → asserts `ps` is never invoked (mock/stub
   `runFixedCommand` or assert via a probe-count/`probes: []` check) and `processHints: []` is
   returned, preserving today's short-circuit behavior for runtimes with no apple-container
   containers; (b) `hosts: []`, `request.collect_stats: true`, `hasAppleContainerCandidates: true`
   → asserts `ps` **is** invoked and a non-empty `processHints` array comes back even though
   `hosts` stays empty; (c) `hosts: [<one host>]`, `hasAppleContainerCandidates: false` → asserts
   the pre-existing colima/lima/podman_machine path is unchanged (same `{hosts, probes,
   correlation}` fields populated as before, `processHints` present but not required by that
   caller).

`test/vms.test.js` (mirror the existing `parseVmProcesses`-adjacent coverage — check current tests
for the `qemu-system`/`vmware-vmx`/`utm`/`apple_virtualization` branches of `processRuntime` and add
a parallel case):

7. `parseVmProcesses` — one new `ps`-line fixture matching the confirmed `apple_container`
   signature, asserting `runtime: "apple_container"` and `confidence: 0.4` (same as every other
   process-hint branch). If the signature could not be confirmed before landing, this test (and
   the `processRuntime` branch itself) is dropped from the diff — do not ship a guessed regex.

No `collectContainerEvidence`/`collectAppleContainer`-level test with mocked `execFile` — this
matches the existing convention in `test/containers.test.js` (zero `execFile` mocking anywhere in
that file today; all coverage is at the pure-parser/pure-correlation level). Run `cd
tools/descartes-cli && npm test` (`node --test`) before considering the slice done.

## Safety invariants preserved

- **Read-only:** every new `container ...` invocation is a read/inspect/list/stats/status/version
  subcommand — no `run`/`create`/`start`/`stop`/`delete`/`kill`/`exec`/`prune`/`copy`/`build`
  subcommand is ever constructed. `command: { argv, read_only: true }` on every `runFixedCommand`
  call (already generic, inherited for free).
- **Bounded:** `container_limit`/`host_limit`/new `image_limit` all clamp 1..200/1..100 via the
  existing `clampNumber`; `maxBuffer` set on every `execFileAsync` call, mirroring siblings.
- **Evidence-envelope-shaped:** no new envelope shape — `collectAppleContainer`'s result folds into
  the same `evidenceEnvelope({ id: "containers", ... })` the other five runtimes already share.
- **Degrade-not-fabricate:** missing `container` binary → `classifyCommandFailure` → `"missing"` →
  `runtime.installed: false, available: false` (identical path to every other runtime, zero new
  logic). No `container_hosts`/VM-inventory entry is fabricated from the unrelated `container
  machine` feature (research finding #2). `vm_correlation` never claims more than "this container
  has its own VM by construction"; `process_correlation` is only ever attached on a genuine `ps`
  match, never inferred.
- **No new execFile/shell/privilege surface beyond a fixed-argv allowlist:** all six new `container
  ...` invocations (`system status`, `system version`, `list --all`, `image list`, `stats
  --no-stream`, plus the reused `ps` scan) are fixed argv arrays built the same way every existing
  `runFixedCommand(command, args)` call is — no string interpolation into a shell, no
  user-controlled argv beyond the already-bounded `--limit`-style request options (which don't feed
  the CLI invocation itself — the `container` CLI has no such flag; bounding happens client-side
  after parsing, matching every sibling block).
- **Hash/bucket identity at source:** N/A this phase — no fact-store write, no entity_key,
  nothing to hash. (Would apply to Phase 2's fact-translator, not here.)
- **macOS-only, degrade-not-error elsewhere:** no manual `process.platform` gate is added — mirrors
  every existing block in this file (VBoxManage/prlctl/vmrun/tart/etc. all rely purely on
  ENOENT-based absence detection rather than a platform branch); on Linux, `container` is
  absent → `"missing"`, never an error.
- **TDD, fixture-driven, no VM execution required:** every new function is a pure parser or a pure
  correlation function, testable with static fixtures — consistent with "this dev machine cannot
  run VMs."
- **Fail-closed alert namespace:** not applicable this phase (no alert emitted) — preserved
  trivially since the invariant only binds once an alert exists.

## COLLISION-WITH-SHARED-ALERT-PIPELINE (Phase-2 sequencing note)

Phase 1 (this plan) touches **zero** shared alert-pipeline files, confirmed above. A **future**
Phase 2 — wiring a `container.disappeared`-style deterministic alert (mirroring
`service.disappeared`'s set-diff-over-census design in `service-baseline.js`) — would require:

- A `container.census`-style marker + `container.presence`-style fact in a new
  `factPointsFromContainerEvidence` translator in **`src/fact-translators.js`**.
- A new `container-baseline.js` module (or a generalization of `service-baseline.js`) computing
  set-diff candidates.
- A new `extraCandidates` entry in **`src/daemon.js`**'s `evaluateAndPersistAlerts` call — the same
  growing, sequentially-numbered-comment array every prior alerting slice
  (session/peer/correlation/service) has appended to. This file is the single hottest collision
  point in the whole codebase for any concurrently-landing alert-emitting collector work.
- Likely **no** change to `src/alert-intelligence.js`'s `classifyAlertNamespace` (a
  `container.`-prefixed rule_id would fall through to the fail-closed `unknown_namespace` default
  exactly like `service.disappeared` does today, unless a future operator decision explicitly
  opts a `container` namespace into LLM adjudication) and **no** change to `calibration.js`/
  `notification-delivery.js` (both are generic over rule_id already).
- Also needs the same per-VM host-list question resolved for `vms.js` proper (should apple-container
  containers ever surface as `vms.js`-native inventory, given research finding #2's "not
  independently enumerable" conclusion) before a disappearance alert could distinguish "container
  stopped normally" from "container's VM died out from under it."

**Sequencing implication:** if/when this Phase 2 is scheduled, it must NOT run concurrently with
any other in-flight collector-alerting slice (e.g. the sibling `todos/2026-08-11-tailscale-
collector.md`, if that one also grows an alert) — both would append to the same
`extraCandidates` array and the same `fact-translators.js` file in the same window, guaranteeing a
merge conflict at best and a silently-dropped `extraCandidates` entry at worst if resolved
carelessly. Phase 1 (this plan) has no such constraint and can land independently and immediately.
