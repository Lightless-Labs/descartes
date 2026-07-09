# Witr-Inspired Provenance and Notification Approval Gates

**Created:** 2026-07-09
**Status:** Draft plan
**Tracking todo:** `todos/2026-07-09-witr-provenance-and-approval-notifications.md`
**Research:** 2026-07-09 — inspected `https://github.com/pranshuparmar/witr` via a read-only scout pass plus direct checkout of README, `go.mod`, `LICENSE`, `internal/app/app.go`, `internal/pipeline/analyze.go`, `internal/proc/net_linux.go`, `internal/target/port_linux.go`, `internal/target/port_darwin.go`, `internal/source/detect.go`, `internal/source/systemd_linux.go`, `internal/source/launchd_darwin.go`, `internal/output/json.go`, and `pkg/model/*`.

## Purpose

Use Witr's "why is this running?" design as a reference for Descartes' deterministic process/service/network provenance tools, and sketch how Descartes notifications could become one approval surface for risky or irreversible actions without making notifications themselves the authority source.

## Witr findings

Witr is a Go CLI/TUI whose core question is: **why is this running?** It resolves a target process/port/container into process ancestry, service/source classification, container/runtime context, sockets, and warnings.

Observed structure:

- `cmd/witr/main.go` and `internal/app/app.go`: Cobra CLI entrypoint and flag handling. The source confirms `--pid`, `--port`, `--file`, `--container`, and `--json` flags, so an optional binary integration could realistically call `witr --json --pid <pid>` or `witr --json --port <port>`.
- `internal/pipeline/analyze.go`: orchestration (`AnalyzePID`) that resolves ancestry, detects source, enriches the target process, gathers optional verbose context, and returns a typed `model.Result`.
- `internal/proc/*`: platform-specific process, socket, boot-time, container, and extended-info collectors.
- `internal/proc/net_linux.go`: Linux socket table parsing from `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`; inode-to-process mapping by scanning `/proc/<pid>/fd`; short TTL socket cache.
- `internal/source/*`: source classification chain for containers, SSH, shell, systemd, launchd, BSD rc, supervisors, cron, Windows services, init, plus warning generation.
- `pkg/model/*`: typed process/source/socket/result models. These are importable Go packages, but the pipeline, target resolution, source detection, and output rendering are under Go `internal/`, so they cannot be imported directly by another Go module.
- `internal/tui/*`: Bubble Tea TUI for interactive process/port/container/lock exploration.
- License: Apache-2.0.
- Runtime/deps: Go 1.25 module; notable deps include Cobra, Bubble Tea/Lipgloss, go-systemd, godbus/dbus, and `x/sys`.

Important non-finding: Witr does **not** appear to solve Wi-Fi/router state. It does socket/listener/process/container provenance, not wireless association, gateway health, DNS reachability, or router diagnostics.

## Borrow vs depend

### Prefer borrowing patterns first

Directly depending on Witr as a library is not a realistic path: most useful implementation packages are under Go `internal/`, so another module cannot import them directly. The realistic dependency choices are (a) shell out to a `witr` binary and consume `--json`, (b) fork/vendor selected code with Apache-2.0 attribution, or (c) borrow the architecture and reimplement in Descartes' Rust/Bazel-friendly core. Apache-2.0 makes borrowing concepts safe, but copying code into Rust/Node would still need attribution hygiene.

Borrow these patterns:

1. **Target-first provenance:** support `pid`, `port`, `container`, and eventually `file/lock` entrypoints that all produce a common provenance result.
2. **Source classification chain:** turn raw parent trees into operator-facing causes: systemd unit, launchd job, cron/timer, shell, SSH session, supervisor, container runtime, unknown.
3. **Warnings as deterministic signatures:** public bind, root/dangerous capabilities, suspicious working directory, deleted executable, zombie/stopped, excessive restarts, no known supervisor.
4. **Socket table caching:** short TTL cache while walking many processes; avoid reparsing expensive state for every PID.
5. **Structured result before prose:** typed process/source/socket/result model wrapped in Descartes evidence envelopes.
6. **Graceful degradation:** missing privileges or platform-specific APIs produce partial evidence plus review hints, not invented conclusions.

### Optional dependency path

Consider an optional external integration only after Descartes has its own minimal provenance schema:

- Detect `witr` on PATH and run `witr --json --pid <pid>` or `witr --json --port <port>` as a supplemental evidence source. These flags are present in `internal/app/app.go`; JSON rendering is implemented by `internal/output/json.go` over `model.Result`.
- Capture `witr --version`, command arguments, exit code, latency, and bounded stdout/stderr in the Descartes trace.
- Treat exit code `0` as clean success and exit code `1` as "warnings present but potentially useful JSON"; only discard the result if JSON parsing fails or the exit code maps to not-found/permission/invalid/internal failure.
- Bound execution with a short timeout and maximum output size. Parse the JSON tolerantly because Witr currently marshals `model.Result` directly without a schema/version wrapper.
- Treat the output as third-party observed data with tool/version recorded.
- Do not require Witr for core Descartes installs, Homebrew formula, or npm/Linux usage until there is a clear benefit and stable JSON contract.
- Avoid a Go-library dependency unless Witr exposes non-`internal` packages for the pipeline/targets/sources in the future.

## Proposed Descartes milestones

### Milestone 1 — provenance schema and existing-tool alignment

Define a Descartes evidence envelope result for process provenance:

- target: `{kind: "pid" | "port" | "container" | "service", value}`
- resolved process: PID, PPID, executable, bounded command, user, start time, cwd, deleted-exe flag when available
- ancestry: bounded parent chain with source labels
- source: `{type, name, unit/job/container/session id, confidence, details}`
- sockets: protocol/address/port/state/public-bind flag
- warnings: deterministic strings with rule ids
- missing permissions / unavailable platform facts

Map this against current collectors (`inspect_process`, `inspect_parent_tree`, `collect_network_basics`, `collect_services`, `collect_containers`, `collect_vms`) before adding new commands.

### Milestone 2 — listener-to-process provenance

Add or deepen a deterministic L0 tool for `port -> process -> source`:

- Linux: parse `/proc/net/*`, map socket inode to `/proc/<pid>/fd`, then enrich via existing process/service/container collectors.
- macOS: use bounded `lsof`/`netstat`/`proc_pidinfo` strategy depending on what is already available in the current Node slice; keep fixed commands and bounded output.
- Return `unknown` rather than shelling out broadly or requiring root.
- Tests use fixtures for socket parsing and process ancestry classification.

### Milestone 3 — source classifier

Implement a small, deterministic classifier over parent chains and existing service/container evidence:

- launchd/systemd/init/shell/SSH/cron/supervisor/container/unknown.
- Include confidence and `review_hint` for ambiguous parent chains.
- Keep model reasoning out of the source-of-truth path; LLMs may narrate or ask for more evidence.

### Milestone 4 — user-facing "why" command or triage tool

Expose provenance either as:

- a guarded model tool first (`inspect_runtime_provenance`), then
- a direct CLI command later, e.g. `descartes why --pid <pid>` and `descartes why --port <port> --json`.

CLI output should be concise and cite evidence; JSON should be stable enough for tests and future UI.

### Milestone 5 — Wi-Fi/router state as a separate track

Do not conflate Witr-inspired process provenance with network access diagnostics. For Wi-Fi/router questions, design separate L0 collectors:

- macOS: `networksetup`, `scutil --dns`, `route -n get default`, `ifconfig`, captive portal/reachability checks where safe.
- Linux: `ip addr`, `ip route`, resolver config, optional `nmcli`/`iw` when present.
- Common: default gateway, DNS resolver status, interface link state, local IP, packet loss/connectivity probes only when explicitly relevant and bounded.

## Notification approval gates

Notifications are a promising approval surface, but they must be only one **UI for an authority record**, not the authority source itself.

### Approval model

For any mutating, destructive, irreversible, or LLM-judged-risky action:

1. Create a persisted approval request with a unique id, nonce, risk class, requested action, bounded human summary, evidence refs, proposed command/tool call, preconditions, expiry, rollback note, and originating agent/model.
2. Notify the user that approval is pending.
3. Executor proceeds only after reading a matching persisted `approved` decision from Descartes state.
4. Default on timeout, notification failure, ambiguous response, or denied permission is **deny**.
5. Every transition is append-only audited: proposed → notified → approved/denied/expired → executed/skipped → post-state.

### macOS notification action caveat

The current native helper is an exec-and-exit delivery helper. Action buttons or inline replies via `UNNotificationAction`/`UNTextInputNotificationAction` may require a persistent app/helper delegate, stable category registration, launch handling, or a URL/open fallback. Focus modes, notification settings, lock state, and permission state can also delay or hide notifications.

Therefore:

- Do **not** assume delivered notification means seen or actionable.
- Do **not** use notification action buttons as the only approval path for destructive/irreversible actions.
- First implementation should include a CLI fallback such as `descartes approvals respond <id> --nonce <nonce> --approve|--deny` and notification text that points to it.
- Later macOS native action support should be a spike with a real-host harness before any high-risk approval depends on it.

### Approval milestones

1. **Approval store and CLI:** `descartes approvals list/show/respond`, local append-only audit, expiry, deny-by-default.
2. **Policy gate integration:** all future mutating action executors require an approval id for approval-required risk classes.
3. **Notification prompt:** send bounded approval notification with request id, risk label, and fallback CLI command; no raw logs/secrets.
4. **Native macOS action spike:** prototype action buttons in the signed helper; validate response delivery from Notification Center, lock/focus states, denied permissions, and daemon context. Button callbacks may only write a persisted approval decision after id/nonce validation; executors must still read the authority store.
5. **Risk tiering:** allow notification action approval only for reversible/low-to-medium risk after validation; require explicit CLI/TUI confirmation for destructive or irreversible operations.

## Tests and validation

- Unit tests for provenance classifiers with fixture parent chains.
- Fixture tests for Linux socket parsing and public-bind detection.
- Platform smoke tests for macOS/Linux listener provenance with permission-denied paths.
- Approval store tests: id/nonce matching, expiry, deny default, append-only audit, no execution without approval.
- Notification approval tests: delivery failure does not approve; duplicate/stale response rejected; denied permissions preserve pending/expired state.
- Real macOS action-button spike before relying on notification responses.

## Recommendation

Borrow Witr's architecture and signatures now; do not take a hard Witr runtime dependency yet. In parallel, treat notification approvals as an authority-plane feature with notifications as a convenience surface and CLI/TUI as the reliable fallback.
