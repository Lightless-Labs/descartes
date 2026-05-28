# Descartes Handoff

**Last updated:** 2026-05-28

## Current Status

Current session update: added history truncation diagnostics and bumped package metadata to v0.0.40. `readMetricPoints`/`buildHistorySummary` now expose `matched_point_count`, `point_limit`, and `truncated`, human history summaries mention when only the newest bounded points are shown, and triage JSON diagnostics include the same fields in `history_summary`. This addresses the field observation where auto-history hit the 10,000 point query cap. Field validation on a work Apple Silicon laptop showed v0.0.39 auto-history worked (`history_mode: auto`, `history_used: true`, fresh sample, model used `history-summary` alongside live tools). Created the next product step as `docs/plans/2026-05-28-monitoring-alerting.md` and `todos/2026-05-28-monitoring-alerting.md`: move into deterministic monitoring/alerting with alert state, dedupe/cooldown, acknowledgements, and notification adapters (macOS Notification Center/osascript, Linux desktop notify-send/D-Bus, headless syslog/journald/email/webhook after opt-in, and CLI `alerts list/watch`).

Current session update: made history-aware triage automatic by default and bumped package metadata to v0.0.39. `descartes triage` now auto-includes a bounded `history-summary` evidence envelope when the local daemon has fresh points, daemon status is `ok`, and the newest sample is within `max(5m, 3x daemon interval)`. `--no-history` opts out, while `--use-history` is retained as force mode for stale/empty history. JSON diagnostics now include `history_mode`, `history_used`, `history_skip_reason`, freshness/max-age, a daemon status summary, and sanitized history summary. README/help/tests/todo/plan were updated.

Current session update: investigated the macOS launchd start failure reported after v0.0.37. Local testing showed launchd can return only `Bootstrap failed: 5: Input/output error` when bootstrapping an already-loaded user agent, and immediate restart after `bootout` can see a transient loaded-but-not-running `SIGTERMed` state. Implemented v0.0.38 launchd hardening: parse `launchctl print` state, treat `state = running` as idempotent before/after generic bootstrap errors, clear stale non-running launchd state with `bootout`, wait for unload, then bootstrap. Added tests for launchd state parsing, generic bootstrap I/O idempotency, and stale-state clearing. Local real launchd validation passed install/start/start/status/history/stop/immediate-start, then cleanup stopped/uninstalled the service. Field retry later succeeded on both personal and work Apple Silicon laptops; work-laptop logs showed repeated ok samples and empty stderr. `npm test` passes 146 Node test cases for this slice.

Current session update: implemented compact default `descartes history summary` output and bumped package metadata to v0.0.37. Human summaries now show point count/window, last sample age, daemon cadence from the profile, daemon state, and key load/memory/swap/disk/process highlights; the previous full metric table is available behind `--verbose`, while `--json` remains machine-readable. README/help/tests/todo/plan were updated. `npm test` now passes 142 Node test cases, and an isolated-XDG daemon one-shot plus compact/verbose history summary smoke succeeded locally.

Current session update: picked up the daemon/history handoff and completed the repeated foreground-loop scheduling test gap without real-time sleeps. Added exported `runForegroundDaemonLoop` injection seams around iteration/sleep/output/stop checks, wired `runDaemon` through it, and marked the daemon/history todo scheduling criterion complete. `npm test` now passes 138 Node test cases.

Current session update: implemented and pushed `descartes triage --use-history [--history-window <duration>]` after field report showed the public CLI rejected the documented next-step flag. The flag builds a bounded `history-summary` evidence envelope from the local XDG history store, includes compact metric rollups in the triage prompt, and exposes `diagnostics.history_used`, `history_window`, and a sanitized `history_summary` in JSON output. README/help/tests were updated. Follow-up field report showed the initial 1h default was too short for an overall system-health question, so the default `--use-history` window is now `24h`; users can narrow with `--history-window`. Package metadata was bumped to v0.0.36 for that slice and `main` was pushed through commit `0ad3526`. Current retention reality: high-resolution JSONL metric history is kept for 24h or until the store reaches 5 MiB, whichever trims first; planned longer rollups are not implemented yet. This is the first history-aware triage slice; richer history-specific prompting, configurable retention, and longer rollups remain follow-up work.

Current session update: recorded real macOS daemon lifecycle field validation at `docs/reviews/2026-05-24-macos-daemon-validation.md`. `descartes daemon install` and `descartes daemon start` worked on a real macOS laptop, launchd reported running, and `descartes history summary` showed daemon metrics accumulating from 52 to 260 to 312 points on the expected one-minute cadence with daemon status `ok`. Remaining real-host validation: status after start, idempotent install/start reruns, stop, uninstall, log inspection, and Linux systemd-user lifecycle. UX finding from that validation was that default `history summary` was too verbose and needed last-sample age/cadence; this is now addressed in v0.0.37 with compact default output and `--verbose` for the full table. Created `linux-daemon-lifecycle-validation-brief.md` for Linux systemd-user validation of daemon install/start/status/history/stop/uninstall behavior; updated daemon and Linux CI todos to link it and record macOS validation status.

Current session update: added a dedicated future use-case library at `docs/use-cases/`, modeled structurally after Pocket Companion's use-case examples. The first Descartes example is `docs/use-cases/examples/2026-05-24-ransomware-like-mass-file-encryption.md`, documenting a hypothetical ransomware-like mass file encryption detector: required low-latency filesystem telemetry, process identity/lineage, per-process mutation baselines, entropy/content-shape sampling, security rules, privacy boundaries, and approval-gated response policy. This is a product/architecture specimen, not an implementation commitment.

Current session update: started the recommended daemon/history substrate and bumped package metadata to v0.0.34. Added `descartes daemon run --foreground [--once] [--interval <duration>]` as a read-only foreground development loop over the conservative system/process/disk collector profile; it writes compact metric points to `metrics.jsonl` and daemon status to `daemon-status.json` under Descartes-owned XDG state history paths. Added retention/max-byte enforcement, corrupt-record skipping, metric rollups, `descartes history summary [--json] [--window <duration>]`, README/help updates, and tests for metric extraction, storage writes, summaries, retention, corrupt records, and daemon status. After user pushback, added real idempotent `descartes daemon install`, `start`, `status`, `stop`, and `uninstall` commands for user-level launchd/systemd services; install returns `installed`, reruns return `unchanged`, drift is detected/updated, start treats already-loaded as ok, stop treats not-loaded as ok, status queries runtime state where possible, and uninstall stops before removing the service file. README now has a dedicated Local history daemon section documenting lifecycle commands, `--json`, idempotent statuses, service-file paths, start/stop mechanisms, and no-background-LLM safety boundaries. Daemon lifecycle commands now render concise human-readable output by default and keep machine-readable data behind `--json`; install/start/status JSON no longer includes generated service file contents. This does not call an LLM in the background and only mutates through explicit daemon lifecycle commands. Follow-ups: repeated loop scheduling tests, real-host launchd/systemd lifecycle validation, richer collectors/rollups, and `triage --use-history`.

Descartes has an initial first-slice CLI scaffold. The LLM-driven investigation loop has been validated on real macOS subscription-auth runs with Anthropic and ChatGPT/Codex. A release-readiness pass is effectively complete for macOS: packaging, local/GitHub install, XDG no-auth failure, API-key login storage, README/help drift, metadata drift, login UX, model-led tool use, and current-package human/JSON triage have been tightened/validated. Linux ARM64 best-effort validation now passes for public v0.0.11 install/help/version, ChatGPT/Codex `--no-open` login, model-led guarded triage, and system/process/disk evidence collection. Public v0.0.30 direct collector/package validation passed on Ubuntu 24.04 ARM64, Debian 13 ARM64, Fedora 42 ARM64, and Debian 13 x86_64. Remaining validation gap is v0.0.31+ rerun after review-finding fixes plus optional credentialed model-led Linux validation.

Current session update: prepared dedicated infrastructure-agent validation briefs for Linux ARM64 and Linux x86_64 at `linux-arm64-validation-brief.md` and `linux-x86_64-validation-brief.md`. Both briefs target v0.0.31+, use Node.js 22.19.0+, avoid privileged/mutating actions, install into a temporary npm prefix, check installed collector docs, validate isolated-XDG no-auth failure, run clone `npm test`/pack dry-run, run sanitized direct collector smokes across the current tool surface, capture read-only platform capability snapshots, and define optional credentialed model-led triage summaries without raw report upload. `todos/2026-05-19-linux-ci-validation.md` links these briefs and frames x86_64 as the Tier-1 gap-closing run.

Current session update: ran two parallel read-only Pi reviews with `openai-codex/gpt-5.5` and `--thinking xhigh`; reports are saved under `docs/reviews/`. The technical review found no blockers but raised high-priority issues: container commands are bounded but not redacted; empty assistant/no-tool fallback can still skip deterministic precollection; Linux validation briefs still capture raw-sensitive external snapshots. Medium items include credentialed validation snippets not XDG-isolated, Linux memory pressure using `os.freemem()` instead of `/proc/meminfo MemAvailable`, and likely weak macOS inode parsing. The alignment review says the v0 read-only LLM-backed local triage slice is well aligned, but L0 collector breadth is outpacing L1/product consolidation; Linux x86_64 remains the main release validation gap; Rust/Bazel substrate remains documentary; and evidence-reference validation/policy-plan-audit schemas should be introduced before action work.

Current session update: addressed the high-priority technical review findings and nearby validation-brief credential isolation. Package metadata is bumped to v0.0.31. `collect_containers` now redacts/bounds Docker and Podman command fields with `command_redaction` metadata. The evidence guard now falls back to deterministic precollection when a model returns no assistant text and no evidence, and fallback wording no longer claims evidence was collected if the fallback evidence set is empty. Linux ARM64/x86_64 validation briefs now replace raw external snapshots with counts/states only and run optional credentialed triage under isolated `$work/xdg-auth` XDG paths. Remaining review follow-ups include Linux `MemAvailable`, macOS inode fixture/parsing hardening, L1 consolidation, evidence-reference validation, and Rust/Bazel substrate.

Current session update: reviewed the latest Linux validation results and curated a durable summary at `docs/reviews/2026-05-23-linux-validation-summary.md`. The run validated public v0.0.30 at commit `eccea433` on Ubuntu 24.04 ARM64, Debian 13 ARM64, Fedora 42 ARM64, and Debian 13 x86_64 with Node v22.21.1/npm 10.9.4. Public install/help/version, installed collector docs, isolated-XDG no-auth failure, `npm test`, pack dry-run, and direct collector smokes all passed; no collector threw or emitted malformed JSON. Credentialed triage was skipped. The only major caveat is version drift: the run happened before local v0.0.31 review-finding fixes were pushed. Current `main` has now been pushed to GitHub through `1f95686`, so the next Linux rerun should observe v0.0.31+.

Current session update: v0.0.31 Linux rerun is explicitly deferred because the temporary x86 host was deleted and the operator is done for the night. Do not block the next work on this rerun. Treat public v0.0.30 Linux direct-collector validation as sufficient to move on, with a later short v0.0.31+ rerun remaining as follow-up when infrastructure is available.

Current session update: clarified the next architectural step: do not hand-author deterministic findings/signatures for every process/failure mode. The missing layer is an agent-authored sensor/toolkit substrate: a fact bridge from collector envelopes into Prolog/Datalog-like relations, a safe Casbin-style logic/policy evaluation engine, constrained statistical model artifacts, fixture/evaluation corpora, and promotion gates so background LLM agents can build their own deterministic tools, sensors, monitoring, triggers, and alarms. Created `docs/plans/2026-05-23-agent-authored-sensor-toolkit.md` as the proposed next plan.

Current session update: expanded the sensor-toolkit plan to include local historical data/metric persistence. Background agents need a metric catalog and store over time, not just current facts: sampled or event-driven collection, sampling intervals, retention/rollups, dimensions/cardinality caps, min/max/mean/count/rate/p95/last aggregations, missing-data semantics, provenance, and sensitivity labels. The proposed milestones now include a local history and metric store before the agent workbench/statistical model prototype.

Current session update: agreed that the daemon/background agent and local history store should come before the agent-authored sensor toolkit implementation. Created `docs/plans/2026-05-23-daemon-history-store.md` and `todos/2026-05-23-daemon-history-store.md` as the recommended next implementation work. Scope: explicit daemon install/start/status/stop/uninstall UX eventually, foreground daemon loop first, conservative read-only collector profile, Descartes-owned XDG history store, bounded metric points/rollups, retention/rotation/max-size enforcement, `descartes history summary`, and later `triage --use-history`. No background LLM calls in the first daemon milestone.

Current session update: documented the next layer after daemon/history: agent-authored derived collectors as pure transformations over stored facts/metrics. Created `docs/plans/2026-05-23-derived-collector-transformation-engine.md` and `todos/2026-05-23-derived-collector-transformation-engine.md`. These artifacts are declarative map/filter/group/reduce/window algorithms over Descartes-owned data with strict sandboxing: no arbitrary JS/Rust/Python/shell, no process execution, no network, no arbitrary file reads, no host mutation, bounded windows/cardinality/runtime, and provenance/diagnostics on all outputs. They feed later Prolog/Datalog/Casbin-like rules and statistical models. Example end-state capability added: CLI/model can set up a derived collector to track a specific executable/binary/process identity across all process instances over time, computing instance count, total/per-instance CPU/RSS, restart/churn rate, redacted command-shape changes, lineage patterns, and container/VM correlation where available.

Current session update: ran a read-only Pi review with Codex 5.5 xhigh over the daemon/history, derived transformation, and sensor toolkit plans; report saved at `docs/reviews/2026-05-23-composable-capability-plans-codex-5.5-xhigh.md`. Verdict: plans are directionally aligned and composable, with correct order daemon/history -> pure transformations -> rule/model/sensor workbench. Main required plan hardening: move a minimal fact/metric/entity catalog and bounded query API earlier into daemon/history, make safety/resource bounds uniform across all plans, explicitly block sensor-toolkit implementation on daemon/history + transformation foundations, separate Datalog/logic, statistical models, and Casbin/policy planes, and keep executable tracking as a worked composability test rather than a bespoke watcher product.

Current session update: Linux validation report showed the first Ubuntu attempt used unsupported Node v18.19.1/npm 9.2.0 and failed global install with `EACCES` on `/usr/local/lib/node_modules`; it did not reach Descartes runtime. A second run with `$HOME/.local` prefix installed public v0.0.8, completed ChatGPT/Codex `--no-open` login, and produced non-fallback model-led triage on Linux arm64 with guarded `collect_triage_evidence` and `actions_taken: []`; process collection failed because Linux procps rejected BSD-style `ps -axo ... -m`. v0.0.10 switched Linux process collection to `ps -eo ...` and sorts top CPU/memory in-process. v0.0.11 fixed npm-bin symlink entrypoint detection. Third Linux ARM64 validation with public v0.0.11 passed: install, symlinked `--version`/`--help`, ChatGPT/Codex `--no-open` login, non-fallback model-led triage, guarded `collect_triage_evidence`, and ok `collect_system`/`collect_processes`/`collect_disks` envelopes. That validation exposed raw process command lines before the current redaction/bounding work. v0.0.12 moves the embedded harness dependency from deprecated `@mariozechner/*` packages to `@earendil-works/pi-coding-agent` 0.75.3 and raises the runtime requirement to Node.js 22.19.0+. Fresh local tarball install no longer emits the `@mariozechner/*` deprecation warnings; one upstream `node-domexception` deprecation warning remains through `@google/genai`/Google auth transitive dependencies in Pi AI.

Current session update: normal `triage` is model-led and does not precollect evidence before the LLM turn. The model must request local facts through the guarded Descartes read-only tool surface. It now exposes `collect_system`, `collect_processes`, `collect_disks`, `collect_network_basics`, `collect_services`, `collect_recent_logs`, `collect_containers`, `collect_vms`, `collect_scheduled_jobs`, `collect_time_sync`, `collect_certificates`, `inspect_process`, `inspect_parent_tree`, `sample_dimension`, `read_sampling_artifact`, `collect_triage_evidence`, and `derive_findings`; a runtime guard rejects Pi coding/shell tools if they appear active. `--no-investigate` is available as a temporary degraded no-tool synthesis escape hatch and still uses deterministic precollection. JSON output includes selected model metadata, thinking level, active tools, tool calls/results/errors, assistant stop reason, LLM error, fallback state, evidence, findings, traces, and `actions_taken: []`. Fallback construction is testable and explicitly marked degraded mode.

Field validation update: a real macOS disk triage using Anthropic Sonnet succeeded end-to-end: `investigation_enabled: true`, active tools were exactly the guarded Descartes tool set, the model called `collect_disks`, and it returned a useful non-fallback diagnosis for large macOS "System Data" caused primarily by Xcode CoreSimulator runtime image mounts. This completes `todos/2026-05-19-llm-driven-investigation-tools.md`. The follow-up disk classification work is also complete: `/dev`, `map ... /home`, Linux/macOS pseudo filesystems, and macOS CoreSimulator/Cryptex developer runtime image mounts are classified as not pressure-relevant; runtime images now produce one aggregate notice instead of per-mount critical findings. Package metadata is bumped to v0.0.14.

Process identity/lineage update: `todos/2026-05-19-process-identity-lineage-tools.md` is complete. `collect_processes` now emits redacted/bounded command lines with redaction metadata, and the guarded triage surface includes `inspect_process` plus `inspect_parent_tree` for PID-level identity/provenance using fixed read-only `ps` snapshots and Linux `/proc` metadata where available. Package metadata is bumped to v0.0.13 for this slice. Linux x86_64 validation remains open for CI/true x86_64 coverage, but Linux ARM64 VM validation passed with v0.0.11. Roadmap note added: temporary VM/container cleanup and repeated-work playbook suggestions are framed as glimpses/capability biases enabled by intent preservation, lifecycle signals, structured memory, temporal confidence/decay, evidence-grounded recommendations, and policy-gated actions rather than as hardcoded workflows.

No-evidence guard update: `todos/2026-05-19-no-evidence-no-diagnosis-guard.md` is complete and package metadata is bumped to v0.0.15. Normal model-led triage now refuses to silently accept assistant text with no collected evidence: it retries once with an explicit instruction to call `collect_triage_evidence` or targeted Descartes tools, then falls back to deterministic precollection and marks degraded fallback diagnostics if evidence is still absent. JSON diagnostics include `evidence_guard.enabled`, `outcome`, `retry_count`, and `fallback_reason`.

Temporal sampling update: `todos/2026-05-19-temporal-sampling-investigation-tools.md` is complete and package metadata is bumped to v0.0.16. Guarded triage now exposes `sample_dimension` for `cpu_processes`, `memory_processes`, and `load_memory_swap` with clamped duration/interval/top_n/sample counts, aggregate summaries, stability notes, and optional Descartes-owned cache artifacts. `read_sampling_artifact` only reads bounded excerpts from sampling artifact IDs under Descartes cache; it is not a general file reader.

Network basics update: package metadata is bumped to v0.0.17. Guarded triage now exposes `collect_network_basics` for read-only network interface facts, default route discovery, DNS resolver/reachability checks, and bounded listening socket inventory. The collector uses fixed command arrays (`ip route show default`, `route -n get default`, `ss -H -ltnu`, `lsof -nP -iTCP -sTCP:LISTEN`) plus OS/Node APIs; MAC addresses are intentionally omitted from interface output. README was shortened and reorganized so Quick start comes before the longer product-direction section.

Service manager update: package metadata is bumped to v0.0.18. Guarded triage now exposes `collect_services` for read-only launchd/systemd service state. macOS uses fixed `launchctl list` parsing and summarizes running/not-running jobs plus nonzero last-exit statuses. Linux uses fixed `systemctl list-units --type=service --all --no-pager --no-legend` parsing and summarizes running, failed, restarting, exited, and inactive services.

Recent logs update: package metadata is bumped to v0.0.19. Guarded triage now exposes `collect_recent_logs` for bounded warning/error excerpts plus fail2ban/firewall-oriented signals. Linux uses fixed `journalctl` commands for recent warnings, fail2ban, firewall units, kernel firewall messages, plus fixed `tail` probes for `/var/log/fail2ban.log` and `/var/log/ufw.log`. macOS uses fixed `log show --style ndjson` predicates for recent errors/faults and firewall/security-oriented messages. Log messages are bounded and obvious secrets are redacted, but excerpts remain sensitive diagnostic artifacts.

Container basics update: package metadata is bumped to v0.0.20. Guarded triage now exposes `collect_containers` for bounded read-only Docker, Podman, Colima, and Lima evidence. Docker/Podman probes collect version, container inventory, and best-effort no-stream stats; Colima/Lima probes collect container-host context. Missing commands, stopped daemons, and permission-limited sockets are represented per-runtime instead of failing the whole envelope. No container mutating commands are exposed.

VM basics update: package metadata was bumped to v0.0.21 after a field report showed `descartes triage "do I have any containers or VMs running?"` correctly used container/process evidence but could not see that Tart was installed. Guarded triage exposed `collect_vms` for bounded read-only Tart, Lima, Multipass, VirtualBox, and libvirt/virsh evidence. Tart uses fixed `tart --version` and `tart list --format json`, so installed-but-empty Tart should be reported as an available VM runtime with zero VMs instead of being omitted.

VM parity update: package metadata is bumped to v0.0.22. `collect_vms` now also probes Parallels (`prlctl list --all --json`), VMware (`vmrun list`), UTM app fixed paths, Podman machine, Incus/LXD VM instances, Proxmox `qm`, Xen `xl`, and direct VM-like processes (`qemu-system-*`, `vmware-vmx`, UTM) via bounded/redacted `ps` snapshots. Duplicate runtime evidence is merged so a process-backed runtime can override a missing CLI/app probe.

Scheduled jobs update: package metadata is bumped to v0.0.23. Guarded triage now exposes `collect_scheduled_jobs` for bounded read-only cron, Linux systemd timer, and macOS launchd scheduled plist evidence. It uses fixed commands (`crontab -l`, `systemctl list-timers`, `systemctl --user list-timers`, `plutil`) plus bounded reads of fixed cron/launchd directories; scheduled command lines are redacted for obvious secrets but remain sensitive diagnostic artifacts. This implementation also fixed a missing comma in the `collect_vms` tool definition that made `pi-harness.js` fail syntax checking.

Time sync update: package metadata is bumped to v0.0.24. Guarded triage now exposes `collect_time_sync` for bounded read-only local clock/NTP state. Linux uses fixed `timedatectl show/status`, optional `chronyc tracking` and `ntpq -pn`; macOS uses fixed `launchctl print system/com.apple.timed` plus best-effort `systemsetup` reads that may report missing admin permission. Optional `check_offset` can run fixed read-only `sntp -t 2 <server>` and records that the probe may contact an NTP server; it never uses `sntp -s`/`-S` or adjusts the clock.

Collector documentation update: added `docs/reference/collectors.md` as the operator/reference catalog for all model-visible evidence tools, parameters, platforms, sources, network behavior, and privacy notes. Added `tools/descartes-cli/src/tools/README.md` as the source-adjacent developer guide for collector structure, safety rules, and adding new collectors.

Review hardening update: package metadata is bumped to v0.0.25 after a read-only Pi/Codex review. `collect_time_sync` now validates NTP server values before invoking `sntp`, rejects option/path/whitespace values such as `-s`/`-S`, and no longer turns unknown sync state into confirmed `synchronized: false`. `collect_scheduled_jobs` now checks cron paths are regular files, caps large cron file reads before parsing, tracks discovered vs returned job counts, and selects returned jobs fairly across scheduler sources so cron entries cannot hide all systemd timers/launchd jobs.

Certificate basics update: package metadata was bumped to v0.0.26. Guarded triage now exposes `collect_certificates` for bounded read-only local certificate validity evidence from common Linux/macOS stores and service-certificate paths. The collector parses local certificate PEM/DER data with Node's X509 support, uses fixed macOS `security find-certificate` probes for system keychains, bounds file counts/sizes, prioritizes expired/soon-expiring certificates in returned results, and intentionally skips private-key files.

Linux ARM64 validation brief update: `todos/2026-05-19-linux-ci-validation.md` now records the ignored `materials/descartes-linux-arm64-validation.zip` archive. That archive validated v0.0.22-era install/help/version/npm-test/container/VM smokes on Ubuntu 24.04, Debian 13, and Fedora 42 ARM64 with Node 22.21.1/npm 10.9.4. It also confirms external scheduler/time commands were available, but scheduled-job/time-sync direct collector smokes failed with expected `ERR_MODULE_NOT_FOUND` because v0.0.22 predated those files. Model-led triage was skipped due no VM credentials.

VM resource correlation update: package metadata was bumped to v0.0.27 and `docs/plans/2026-05-21-vm-container-resource-correlation.md` was created. `collect_vms` now correlates direct QEMU/VMware/UTM process hints into matching runtime VM inventory entries by compatible runtime/name/path signals, attaches process `resource_snapshot` plus `process_correlation`, and avoids double-counting matched process-backed hints.

Container-host/VM correlation update: package metadata was bumped to v0.0.28. `collect_vms` now includes Colima VM inventory, `collect_containers` now includes Podman machine host context, and Colima/Lima/Podman machine entries on both sides carry explicit runtime/name correlation metadata plus summary counts (`container_host_correlatable_vm_count` and `vm_correlatable_host_count`).

Container-host resource attachment update: package metadata is bumped to v0.0.29. `collect_containers` now performs a fixed read-only `ps` scan when container-host entries are present and attaches bounded `resource_snapshot` plus `process_correlation` to Colima/Lima/Podman machine hosts when QEMU process names/paths deterministically match. `collect_vms` process matching now recognizes `.lima/<name>`, `.colima/_lima/<name>`, and `podman-machine-*` process paths/names and can correlate QEMU hints into Colima/Lima/Podman machine VM entries.

Apple Virtualization attribution update: package metadata is bumped to v0.0.30. `collect_vms` now recognizes `VirtualizationService`, `com.apple.Virtualization.VirtualMachine`, and `Virtualization.framework` process hints as `apple_virtualization`, extracts names from `--name`/`--vm-name`/`--machine` plus common `.lima/<name>`, `.colima/_lima/<name>`, and `podman-machine-*` paths, and correlates matching process resource snapshots into Tart/Colima/Lima/Podman-machine inventory. `collect_containers` also accepts Apple Virtualization process hints for deterministic Colima/Lima/Podman-machine host resource attachment. Remaining work is real-host validation, especially whether any VZ helper processes lack stable path/name hints and need a conservative ambiguity-bounded rule.

Conceptual update: Descartes no longer has a separate L-1 Interface / Privacy Gate layer. Privacy and provider-boundary behavior remain product/safety constraints, but architecture layers now start at L0 deterministic system tools.

Field report update: GitHub-installed triage on a real work laptop returned an empty diagnosis after login. `tools/descartes-cli/src/triage.js` now reads final assistant text from `session.messages` after `session.prompt()` instead of relying only on streaming `text_delta` events, and emits a deterministic fallback report if the model still returns no final text.

Second field report update: v0.0.1 still produced fallback with empty `evidence`, `findings`, and `tool_traces`, meaning the LLM session did not call any Descartes evidence tools. v0.0.2 precollects the first-slice read-only evidence bundle before invoking the model, injects that evidence into the prompt, and includes precollected evidence/traces in JSON output even when the model makes no tool calls.

Third field report update: v0.0.2 had evidence but still no LLM text. v0.0.3 changes synthesis to a no-tool LLM turn over a compact evidence summary, avoiding custom tool schemas and oversized raw evidence in the provider request. JSON fallback now includes `llm_error` when the assistant message records one.

Fourth field report update: v0.0.3 selected `openai-codex/gpt-5.1`, which ChatGPT subscription Codex rejected. v0.0.4 added explicit model selection and defaulted ChatGPT/Codex subscription auth to `openai-codex/gpt-5.5` with high reasoning when available. v0.0.5 replaces hardcoded Codex preferences with semantic-version "highest GPT model" selection per preferred subscription provider. v0.0.6 also avoids Anthropic registry-order Haiku defaults by selecting the highest available Anthropic Sonnet. v0.0.7 fixes Anthropic date parsing so release dates like `20250514` are not treated as version components ahead of `claude-sonnet-4-6`. v0.0.8 includes the login UX cleanup and temporary tool-forcing triage behavior. `--model` and `--thinking` are passed through to the harness.

Release-readiness update: README now starts with concrete "What it does", "Where it's going", and "How to get started" blocks, and frames the long-term goal as real-time operations/defense behavior detection with policy-bounded interruption of novel harmful behavior such as ransomware-like or trojan-like activity. CLI help now documents `--model`/`--thinking`; `--version` reads package metadata instead of a hardcoded string; root package contents exclude tests; root/nested package engine metadata is aligned; and `tools/descartes-cli/test/package-metadata.test.js` covers metadata/help/version drift.

Login UX fix: subscription OAuth login no longer starts an immediate manual paste `readline` prompt during normal browser-based login, because the Pi OAuth helper races that prompt against the localhost callback and leaves the terminal waiting for Enter after browser success. Normal `descartes login` now opens the browser and waits for callback; manual paste is available via `descartes login --no-open`. User re-test confirmed the flow is much better.

Current-package ChatGPT/Codex validation: GitHub-installed `descartes triage "my machine is slow"` returned a useful non-fallback human diagnosis citing system/process/disk evidence and ended with `No actions were taken.` Initial GitHub-installed JSON triage returned `fallback_used: false`, selected `openai-codex/gpt-5.5` with high thinking, active tools exactly `collect_system`, `collect_processes`, `collect_disks`, `collect_triage_evidence`, `derive_findings`, three ok precollected evidence envelopes, findings/tool traces, and `actions_taken: []`. The model made no additional tool calls because compact precollected evidence was sufficient; prior Anthropic validation covered explicit tool-call behavior. The JSON model output cited compact summary keys (`top_cpu`, `top_memory`) as evidence refs, so prompt instructions were tightened to require envelope IDs only.

Evidence collection policy decision: keep normal `triage` model-led rather than restoring unconditional precollection. The model must request local facts through the guarded Descartes tool surface; `collect_triage_evidence` remains the compact resource-pressure first-pass bundle (system/process/disk), not an ever-growing all-collectors bundle. New collectors should stay as targeted tools so the model chooses them intentionally. `--no-investigate` remains the degraded no-tool synthesis escape hatch and still precollects deterministic evidence. v0.0.8 GitHub-installed validation confirmed this works: JSON triage had `fallback_used: false`, selected `openai-codex/gpt-5.5`, active tools exactly matched the guarded Descartes tool set, the model called `collect_triage_evidence`, evidence refs were envelope IDs, and `actions_taken: []`. Future hardening: add a "no evidence, no diagnosis" guard that retries or degrades if normal investigation returns without tool calls/evidence.

Packaging/distribution policy update: the current npm package is only a pragmatic GitHub-install wrapper for the embedded Node/Pi harness. Do not prioritize npm registry publishing; npm is not a strategic distribution goal. Long-term direction remains moving durable core functionality away from JavaScript/TypeScript toward Rust/Bazel-friendly components.

Existing files:

- `README.md` — updated to describe the LLM-backed local triage first slice, Pi/XDG boundaries, future intent-based policy-gated operations use cases, and the collector reference link.
- `AGENTS.md` — operating instructions for coding agents.
- `.gitignore` — excludes local reference material, logs, Rust build output, Node package output, and OS noise.
- `package.json` — root npm package so end users can install with `npm install -g github:Lightless-Labs/descartes` without cloning.
- `tools/descartes-cli/` — initial npm-style Descartes CLI scaffold.
  - `src/paths.js` resolves Descartes-owned XDG paths and rejects Pi-owned paths.
  - `src/tools/` contains read-only evidence collectors for system overview, top processes with redacted/bounded args, process identity/lineage inspection, bounded temporal sampling/artifacts, network basics, service manager basics, bounded recent logs, container basics with VM correlation metadata, VM basics/resource correlation, scheduled job basics, time sync basics, certificate basics, disks, deterministic findings, and a combined triage bundle.
  - `src/pi-harness.js` wraps Pi SDK session creation with Descartes-owned auth/model paths, no default resource discovery, no built-in coding tools, and only explicit Descartes evidence tools.
  - `src/login.js` implements a first terminal OAuth/API-key login path storing under Descartes config.
  - `src/triage.js` implements human and JSON triage prompts around the private harness.
  - `test/` covers XDG path resolution, Pi-path guardrails, deterministic finding thresholds, parser fixtures, tool policy, sampling, and fallback/guard diagnostics.
- `docs/ROADMAP.md` — roadmap for capability discovery, process/behavior understanding, temporal sampling, planning, inter-agent delegation/identity, policy-gated action, and learning. Includes the guiding future use case: “I need a quick Linux environment with npm,” where Descartes discovers Docker/Colima/Podman/Tart/Lima/UTM/Multipass/Buildkite/authenticated delegated-agent options, recommends a plan, asks approval, executes or delegates within scoped authority, verifies, and cleans up.
- `docs/reference/collectors.md` — reference catalog for model-visible evidence tools, envelope IDs, parameters, sources, platform coverage, network behavior, and privacy notes.
- `docs/reviews/2026-05-22-technical-implementation-codex-5.5-xhigh.md` — read-only Pi/Codex technical implementation review report.
- `docs/reviews/2026-05-22-functional-alignment-codex-5.5-xhigh.md` — read-only Pi/Codex product/project-direction alignment review report.
- `docs/reviews/2026-05-23-linux-validation-summary.md` — curated summary of the latest Linux ARM64/x86_64 validation run.
- `docs/reviews/2026-05-23-composable-capability-plans-codex-5.5-xhigh.md` — read-only Pi/Codex review of the daemon/history, derived transformation, and sensor toolkit plans through the composable-capability lens.
- `linux-arm64-validation-brief.md` — standalone infrastructure-agent brief for best-effort Linux ARM64 v0.0.31+ validation.
- `linux-x86_64-validation-brief.md` — standalone infrastructure-agent brief for Tier-1 Linux x86_64 v0.0.31+ validation.
- `linux-daemon-lifecycle-validation-brief.md` — standalone infrastructure-agent brief for Linux systemd-user daemon lifecycle validation (`install/start/status/history/stop/uninstall`) against v0.0.40+.
- `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` — **current implementation plan**, now in progress.
- `docs/plans/2026-05-21-vm-container-resource-correlation.md` — in-progress follow-on plan for VM/container resource correlation; first VM process-hint correlation slice is implemented.
- `docs/plans/2026-05-23-daemon-history-store.md` — active substrate plan for installing/running a local background daemon and bounded local history/metric store; mostly complete for the Node.js prototype.
- `docs/plans/2026-05-28-monitoring-alerting.md` — **recommended next plan** for deterministic local monitoring/alerting over daemon history with alert state and optional notification adapters.
- `docs/plans/2026-05-23-derived-collector-transformation-engine.md` — follow-on plan for agent-authored pure map/reduce/window derived collectors over stored data without arbitrary code/host execution.
- `docs/plans/2026-05-23-agent-authored-sensor-toolkit.md` — proposed follow-on plan for a fact/rule/statistical-model workbench that lets background LLM agents author deterministic sensors/tools instead of humans hand-writing every signature.
- `todos/` — frontmatter-indexed work items for quick triage/sorting:
  - `2026-05-19-first-external-slice-validation.md` — mostly complete first-slice release validation; remaining Linux x86_64/full credentialed validation is deferred and should not block monitoring/alerting work.
  - `2026-05-19-llm-driven-investigation-tools.md` — completed; safe LLM tool-driven local investigation restored and validated with Anthropic on macOS.
  - `2026-05-19-process-identity-lineage-tools.md` — completed; redacted/bounded process args, `inspect_process`, and `inspect_parent_tree` are implemented and exposed through the guarded triage tool surface.
  - `2026-05-19-expand-local-investigation-tools.md` — completed; process identity/lineage, temporal sampling, network basics, service manager basics, recent logs, container basics, VM basics, scheduled job basics, time sync basics, and certificate basics are implemented and exposed through guarded triage.
  - `2026-05-19-vm-inventory-collector.md` — completed first VM inventory slice and parity expansion for Tart, Lima, Multipass, VirtualBox, libvirt/virsh, Parallels, VMware, UTM, Podman machine, Incus/LXD VM mode, Proxmox, Xen, and direct VM-like process hints.
  - `2026-05-19-temporal-sampling-investigation-tools.md` — completed; bounded LLM-requested sampling over time with aggregates and Descartes-owned artifacts.
  - `2026-05-19-macos-disk-evidence-classification.md` — completed; classifies pseudo/runtime filesystems, fixes macOS map row parsing, and reduces disk finding noise.
  - `2026-05-19-linux-ci-validation.md` — v0.0.31+ Linux rerun is deferred; public v0.0.30 direct collector/package validation passed on Linux ARM64 and x86_64.
  - `2026-05-23-daemon-history-store.md` — active task, mostly complete for the Node.js prototype: foreground loop, JSONL history, idempotent daemon lifecycle commands, compact history summaries, auto history-aware triage, truncation diagnostics, and macOS personal/work-laptop validation exist. Linux systemd-user validation and longer rollups/configurable retention remain follow-up.
  - `2026-05-28-monitoring-alerting.md` — **recommended next task**: deterministic local monitoring/alerting over daemon history with alert state, dedupe/cooldown, CLI `alerts` commands, and notification adapter design.
  - `2026-05-23-derived-collector-transformation-engine.md` — follow-on: let agents author pure bounded map/reduce/window transformations over daemon history as derived collectors/sensors.
  - `2026-05-23-agent-authored-sensor-toolkit.md` — follow-on: build the fact/rule/metric-history/statistical-model substrate that lets background LLM agents author deterministic sensors/tools.
  - `2026-05-19-agent-delegation-identity-authority.md` — future design spike for inter-agent communication/delegation with identity, auth, scoped authority, policy, user validation, and audit.
  - `2026-05-19-no-evidence-no-diagnosis-guard.md` — completed; normal model-led triage retries once if assistant text arrives with no evidence, then deterministic-precollection fallback marks degraded diagnostics.
  - `2026-05-19-web-search-retrieval-tools.md` — closer-future explicit web/search retrieval tools and optional proxy.
  - `2026-05-19-federated-process-knowledge-db.md` — future shared/federated process behavior knowledge database.
- `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md` — deferred broader product direction.
- `docs/plans/2026-05-18-002-descartes-bootstrap-kernel-and-workbench-plan.md` — superseded; do not implement this first.

## Start Here In A New Session

1. Read `README.md`, `AGENTS.md`, and this handoff.
2. Treat `docs/plans/2026-05-28-monitoring-alerting.md` and `todos/2026-05-28-monitoring-alerting.md` as the active next implementation source of truth, while `docs/plans/2026-05-23-daemon-history-store.md` remains the daemon/history substrate baseline and `docs/plans/2026-05-18-003-first-external-slice-local-triage.md` remains the current first-slice product baseline.
3. Do **not** jump directly to broad agent-authored signatures or background LLM calls. The daemon/history substrate now exists for the Node.js prototype; the next task is deterministic monitoring/alerting over that substrate.
4. Do not restore unconditional precollection as the normal triage path. Normal `triage` should remain model-led tool investigation; `--no-investigate` is the degraded precollection path.
5. Recommended next task: pick up `docs/plans/2026-05-28-monitoring-alerting.md` / `todos/2026-05-28-monitoring-alerting.md`. Start with a local alert store schema, deterministic rule evaluator, and CLI-only `alerts list/watch/ack` before desktop/headless notification delivery.

## Current First Slice

Ship an installable command:

```bash
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

This must be an **LLM-backed local triage flow**. The LLM interprets the user's natural-language complaint and decides which Descartes read-only evidence tools to call. Deterministic code gathers/structures evidence and computes optional findings for grounding; it does not pretend to understand arbitrary user intent by keyword matching.

The product value is not a stats dump. It is an evidence-cited operational diagnosis with confidence, safe next checks, and explicit no-action/audit language.

## Non-Negotiable Boundaries

### LLM and Auth

- Natural-language `triage` requires an LLM-backed agent harness.
- Normal users often have subscriptions, not API keys. `descartes login` should be the primary user path.
- API keys may be an advanced/headless fallback, not the main UX.
- LLM/provider network calls are expected for explicit `descartes triage ...` requests.
- Telemetry, background upload, and federation are not part of v0.

### Pi / Agent Harness

- Do not reinvent agent harness machinery if Pi SDK/RPC can provide model/provider/tool/session behavior.
- Descartes may use Pi internally as a private embedded harness.
- Users must **not** need to preinstall or configure Pi.
- Descartes must **never** read, import, reuse, modify, migrate, or inspect the user's personal Pi setup.
- No interaction with `~/.pi`, `~/.pi/agent`, project `.pi`, Pi sessions, Pi settings, Pi auth, Pi extensions, Pi skills, Pi prompts, Pi themes, or Pi model config.
- If Pi SDK/RPC is used, configure it with Descartes-owned paths, explicit resources, and Descartes read-only tools only.

### Local Evidence / Privacy

- Descartes runs for the machine owner or authorized local user.
- Local output may include operationally useful identifiers: hostname, usernames where relevant, process names, command lines, mount points, paths, service names, and later logs.
- The privacy boundary is not hiding the local machine from its owner. The boundary is not transmitting sensitive local evidence except to the selected LLM provider for the explicit triage request.
- Saved reports/session state are sensitive diagnostic artifacts.

### Safety

- Local evidence collection is read-only.
- No mutating host action in v0.
- No arbitrary shell/coding tools exposed to the triage agent by default.
- The LLM may ask for evidence through Descartes tools; it may not execute arbitrary commands or claim facts not present in evidence.

## Descartes-Owned Paths

Use XDG Base Directory conventions for Descartes-owned state on Unix-like systems:

| Purpose | Env var | Default |
|---|---|---|
| Config/auth | `XDG_CONFIG_HOME` | `$HOME/.config/descartes` |
| Data | `XDG_DATA_HOME` | `$HOME/.local/share/descartes` |
| State | `XDG_STATE_HOME` | `$HOME/.local/state/descartes` |
| Cache | `XDG_CACHE_HOME` | `$HOME/.cache/descartes` |
| Runtime | `XDG_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/descartes` when set |

Do not default to `~/.descartes`. Do not use any Pi-owned path.

## Distribution Assumptions

Primary public home:

```text
https://github.com/lightless-labs/descartes
```

The first install mechanism is an implementation decision, but it must include/private-vendor the agent harness. A Cargo-only CLI is not sufficient if it cannot provide the LLM-backed private harness and subscription login flow.

Current distribution is a pragmatic GitHub npm install wrapper around the embedded Node/Pi harness:

```bash
npm install -g github:Lightless-Labs/descartes
```

Do not prioritize npm registry publishing. Long-term distribution should move toward GitHub Release packages/binaries, Homebrew, or native Rust/Bazel-friendly artifacts when the durable core moves out of the temporary JavaScript harness layer.

## Platform Scope

Tier 1 for first slice:

- macOS Apple Silicon
- Linux x86_64

Tier 2 / best effort:

- macOS Intel
- Linux ARM64

Not supported initially:

- Windows
- BSD
- Android/Termux
- remote hosts
- container-only introspection

## Implementation Direction

Likely architecture for the first slice:

```text
descartes CLI/package
  -> Descartes-owned XDG config/auth/state/cache paths
  -> private Pi SDK/RPC or equivalent harness
  -> explicit Descartes system prompt/resources
  -> Descartes read-only evidence tools
  -> Rust-first or native local collector components where useful
  -> LLM-authored, evidence-cited diagnosis
```

Possible repository shape from the current plan:

```text
Cargo.toml
crates/
  descartes-core/
  descartes-collector/

tools/descartes-cli/
  package.json
  src/
    index.ts
    paths.ts
    login.ts
    triage.ts
    pi-harness.ts
    tools/
      collect-system.ts
      collect-processes.ts
      collect-disks.ts
```

This shape is not mandatory. The mandatory part is the user-visible behavior and the path/Pi/safety boundaries.

## Suggested Next Action

Recommended next task: pick up `docs/plans/2026-05-28-monitoring-alerting.md` / `todos/2026-05-28-monitoring-alerting.md`. Build deterministic local alerts over daemon history first: alert store schema, rule evaluator, dedupe/cooldown, CLI list/watch/ack, then optional notification adapters.

The v0.0.31+ Linux rerun and real-host VM/container correlation validation remain useful but deferred; do not block the daemon/history work on them.

## Tests / Checks To Prioritize

- XDG path resolution honors environment variables and defaults.
- No Descartes path code references `~/.pi`, `.pi`, or Pi user config locations.
- Private harness starts with explicit Descartes resources/tools only.
- Evidence tools serialize structured evidence envelopes.
- Local evidence collection is read-only.
- Human renderer includes diagnosis, evidence citations, next checks, and "No actions were taken."
- JSON output includes evidence/tool traces and diagnosis.

## Broader Product Direction Later

After the first external slice exists, the broader L2 builder/auditor direction remains relevant: Descartes should learn by compiling experience down into durable probes, rules, signatures, fixtures, and tests. That is covered in the deferred plan `docs/plans/2026-05-18-001-descartes-pi-integration-and-runtime-plan.md`.

Do not implement that broader artifact lifecycle before the first LLM-backed local triage slice.

## Repository Notes

- This directory is now a git repository; `git status --short` works.
- Current checked command: `npm test` passes 153 Node test cases after the history truncation diagnostics slice.
- Current checked command: `git diff --check` passes after the compact history summary slice.
- Current checked command: extracted `collector-smoke.mjs` snippets from both Linux validation briefs pass `node --check`.
- Current checked command: two parallel Pi print-mode reviews completed with `PI_SKIP_VERSION_CHECK=1 PI_TELEMETRY=0 pi --no-session --tools read,grep,find,ls --model openai-codex/gpt-5.5 --thinking xhigh -p ...` and wrote reports under `docs/reviews/`.
- Current checked command: direct local `collectProcessEvidence({ limit: 3 })` returns ok on macOS with `ps -axo ...`.
- Current checked command: `npm run pack:dry-run` includes README, `docs/reference/collectors.md`, plus runtime `tools/descartes-cli/src` files (including `daemon.js`, `history-store.js`, `history.js`, `tools/network.js`, `tools/services.js`, `tools/logs.js`, `tools/containers.js`, `tools/vms.js`, `tools/scheduled-jobs.js`, `tools/time-sync.js`, `tools/certificates.js`, and the source-adjacent tools README) and excludes tests/local artifacts for v0.0.40.
- Current checked command: `git push origin main` succeeded after v0.0.31 review-finding fixes; public GitHub `main` should now expose package version 0.0.31 for the next Linux validation rerun.
- Current checked command: local tarball install via `npm pack --pack-destination "$tmp"` + `npm install -g --prefix "$tmp/prefix" "$pkg"` works; installed `descartes --help` and `descartes --version` work.
- Current checked command: `npm install -g --prefix "$tmp" github:Lightless-Labs/descartes` installs from the public GitHub repo without cloning; installed `descartes --help` and `descartes --version` work.
- Current checked command: installed `descartes triage "my machine is slow" --json` reaches the expected "No configured model credentials" error with isolated XDG paths when no login exists and creates only `$XDG_CONFIG_HOME/descartes/auth.json`.
- Current checked command: installed `descartes login test-provider --api-key` with isolated XDG writes credentials to `$XDG_CONFIG_HOME/descartes/auth.json`.
- Current checked command: `npm test` and local tarball API-key login still pass after the login UX fix; user re-tested normal OAuth browser login and confirmed the extra-Enter issue is resolved.
- Current checked command: `node tools/descartes-cli/src/index.js --help` works without importing Pi dependencies and documents `--model`, `--thinking`, and `--no-investigate`.
- Current checked command: direct `collectAllEvidence()` invocation returns three ok evidence envelopes on the local macOS host.
- Current checked command: direct `collectProcessEvidence`, `inspectProcessEvidence`, and `inspectParentTreeEvidence` invocations return ok envelopes on the local macOS host with bounded process args.
- Current checked command: direct `collectDiskEvidence()` invocation returns classified filesystem envelopes on local macOS; `/dev`, `map auto_home`, CoreSimulator runtime mounts, and MetalToolchain Cryptex mounts are not pressure-relevant, and derived disk findings no longer include them as critical pressure.
- Current checked command: direct `sampleDimensionEvidence({ dimension: "load_memory_swap", duration_seconds: 1, interval_seconds: 1 })` returns an ok `sample-load_memory_swap` envelope with two samples and aggregate stats.
- Current checked command: direct `collectNetworkEvidence({ checkDnsReachability: false, socketLimit: 5 })` returns an ok `network-basics` envelope on local macOS with interface, route, and listening socket sub-results.
- Current checked command: direct `collectServiceEvidence({ serviceLimit: 5 })` returns a `services` launchd envelope on local macOS with bounded service output and nonzero-exit summaries.
- Current checked command: direct `collectRecentLogsEvidence({ windowMinutes: 1, eventLimit: 3, includeSecurity: true })` returns an ok `recent-logs` envelope on local macOS with bounded unified-log excerpts; partial `log show` output is accepted as bounded input when macOS emits more than the collector buffer.
- Current checked command: direct `collectContainerEvidence({ containerLimit: 3, hostLimit: 5, collectStats: false })` returns a `containers` envelope on local macOS with per-runtime missing/daemon-unavailable state when Docker/Podman/Colima/Lima/Podman machine CLIs are unavailable, plus `vm_correlatable_host_count`, `correlated_host_process_count`, and `uncorrelated_host_process_hint_count` in the summary.
- Current checked command: direct `collectVmEvidence({ vmLimit: 8 })` returns an ok `vms` envelope on local macOS with 14 deduplicated runtime entries and process-scan correlation summary counts; current local host has two uncorrelated process-backed VM hints and no Colima/Lima/Podman-machine VZ host to validate attribution end-to-end.
- Current checked command: direct `collectScheduledJobsEvidence({ jobLimit: 5 })` returns an ok `scheduled-jobs` envelope on local macOS with bounded cron/launchd probes.
- Current checked command: direct `collectTimeSyncEvidence()` returns an ok `time-sync` envelope on local macOS with `launchctl_timed` ok and `systemsetup` probes represented as unable/missing admin permission.
- Current checked command: direct `collectCertificateEvidence({ certificateLimit: 3 })` returns an ok `certificates` envelope on local macOS with bounded source summaries and no private-key reads.
- Current checked command: isolated-XDG `node tools/descartes-cli/src/index.js daemon run --foreground --once` writes 49 metric points on the local macOS host, and compact plus `--verbose` `descartes history summary --window 5m` render successfully.
- Current checked command: isolated HOME/XDG `descartes daemon install` on macOS returns `installed`, a second install returns `unchanged`, and `descartes daemon status` returns `installed` without touching the real user LaunchAgents directory.
- Current field validation: real macOS `descartes daemon install` and `descartes daemon start` succeeded; `descartes history summary` showed point counts increasing 52 -> 260 -> 312 with daemon status `ok`. See `docs/reviews/2026-05-24-macos-daemon-validation.md`.
- Current implementation: `descartes triage --use-history` now parses and injects a bounded `history-summary` evidence envelope; JSON diagnostics include `history_used`, `history_window`, and sanitized history metric names/counts. Default history window is 24h.
- Current implementation: daemon history retention is 24h high-resolution JSONL capped at 5 MiB. There are no longer 7d rollups yet despite the plan direction.
- Current field validation: v0.0.8 GitHub-installed JSON triage with ChatGPT/Codex called `collect_triage_evidence`, returned `fallback_used: false`, cited envelope IDs, and left `actions_taken: []`.
- Remaining validation gap: v0.0.31+ Linux rerun and optional credentialed model-led Linux validation. Linux arm64 validation with `$HOME/.local` prefix passes on public v0.0.11 for install, symlinked `descartes --version`/`--help`, ChatGPT/Codex `--no-open` login, model-led guarded triage, `fallback_used: false`, `collect_triage_evidence`, `actions_taken: []`, and ok system/process/disk envelopes. Public v0.0.30 direct collector/package validation passes on Ubuntu 24.04 ARM64, Debian 13 ARM64, Fedora 42 ARM64, and Debian 13 x86_64 with Node 22.21.1/npm 10.9.4; see `docs/reviews/2026-05-23-linux-validation-summary.md`. v0.0.31 review-finding fixes were pushed after that validation, so rerun should confirm public package version 0.0.31+ and container command redaction/fallback guard behavior on Linux. The Linux todo uses a writable `--prefix`; future Buildkite validation should use scoped CI secrets rather than personal credentials where possible.
- Completed implementation: process args redaction/bounding plus `inspect_process` / `inspect_parent_tree`, disk filesystem classification/noise reduction, no-evidence/no-diagnosis guard, temporal sampling, network basics, service manager basics, bounded recent logs, container basics, VM basics/parity, scheduled job basics, time sync basics, certificate basics, initial VM process-resource correlation, container-host/VM correlation metadata, QEMU-backed container-host process-resource attachment, and Apple Virtualization/VZ process attribution by deterministic path/name hints. Recommended next work is the daemon/history store, which becomes the substrate for the later agent-authored sensor toolkit.
- `materials/` exists locally but is ignored and should not be referenced in committed project docs.
- `nohup.out` exists locally and is ignored.
- `lynx` is installed and can be used for web docs via `lynx -dump`.

## Update Discipline

Update this file:

- before context compaction
- before handing off to another agent
- after completing a milestone
- after changing the plan direction
- after discovering important constraints or gotchas
