# Descartes

Descartes is a local-first operations triage CLI. It collects read-only evidence from the current machine, asks an LLM-backed private agent session to interpret that evidence, and prints an evidence-cited diagnosis with safe next checks.

Today it can answer questions like:

```bash
descartes triage "my machine is slow"
```

No host actions are taken.

## Quick start

On macOS, install with Homebrew — this delivers the CLI together with the signed,
notarized native notification helper:

```bash
brew install lightless-labs/tap/descartes
```

If you previously installed via `npm install -g` using Homebrew's Node.js, remove that
install first so `brew link` can claim the `descartes` command:

```bash
npm uninstall -g @lightless-labs/descartes
```

Cross-platform install via npm requires Node.js 22.19.0+ and a writable npm global
prefix. This path does not include the macOS native notification helper; the
`osascript` fallback channel still works, and `--helper` remains a manual override.

```bash
npm install -g github:Lightless-Labs/descartes
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
# If fresh daemon history exists, triage includes a bounded history summary automatically:
descartes triage "How's my system doing?"

# Optional local history prototype, no background LLM calls:
descartes daemon install       # idempotently writes a user launchd/systemd service file
descartes daemon start         # idempotently loads/starts the user service
descartes daemon status
descartes daemon stop
descartes daemon run --foreground --once
descartes history summary          # compact local metric summary
descartes alerts list              # deterministic local alerts, no LLM
```

HTTPS tarball form:

```bash
npm install -g https://github.com/Lightless-Labs/descartes/tarball/main
```

If your system npm prefix is root-owned, install into a user prefix instead:

```bash
npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes
export PATH="$HOME/.local/bin:$PATH"
```

On Linux distributions with older Node.js packages, install Node.js 22.19.0+ through your normal version manager before installing Descartes.

## Where it's going

Descartes is intended to become a stratified machine operations and defense agent: deterministic local tools and rules first, real-time behavior detection, adaptive diagnosis for ambiguity and tradeoffs, LLM-assisted planning when useful, and eventually policy-gated actions with audit trails.

The long-term goal is to recognize operational failures and harmful behavior as they emerge — for example ransomware-like file activity or trojan-like persistence/network behavior — and interrupt them only within explicit policy boundaries.

It should also support intent-based operations. For example, if a user says “I need a quick Linux environment with npm,” Descartes should discover whether Docker, Colima, Podman, Tart, Lima, UTM, Multipass, Buildkite, another local option, or an authenticated remote/CI agent is available; recommend a plan; ask for scoped approval; execute or delegate only within that approval; verify the result; and clean up.

The durable core is expected to move toward Rust. The current external slice is a Node.js/JavaScript CLI so it can ship quickly with the embedded Pi SDK agent harness and subscription login flow.

See `docs/ROADMAP.md` for the broader capability roadmap.

## What `triage` does today

Normal triage is model-led:

1. The user asks a local machine question.
2. The private Descartes agent decides which read-only Descartes evidence tools to call.
3. Deterministic collectors return structured evidence envelopes.
4. The model writes an evidence-cited diagnosis using only those envelopes.
5. Descartes prints the report and records `actions_taken: []`.

Current collectors include:

- system identity, uptime, CPU/load, memory, and swap
- disks, mounts, inode pressure, and filesystem classification
- top processes with redacted/bounded command lines
- process identity and parent-tree inspection
- bounded temporal sampling for CPU, memory, load, and swap
- network basics: interfaces, default route, DNS resolver/reachability, and listening sockets
- service manager basics: launchd jobs on macOS and systemd services on Linux
- bounded recent logs: warnings/errors plus fail2ban/firewall-oriented signals where available
- container basics: Docker, Podman, Colima, Lima, and Podman machine host/runtime/container inventory where available
- VM basics: Tart, Colima, Lima, Multipass, VirtualBox, libvirt/virsh, Parallels, VMware, UTM, Podman machine, Incus/LXD VMs, Proxmox, Xen, and direct VM-like process hints where available
- scheduled job basics: cron, systemd timers on Linux, and launchd scheduled jobs on macOS
- time sync basics: local clock/NTP state and optional bounded offset checks
- certificate basics: bounded local certificate validity checks for common stores/paths

See `docs/reference/collectors.md` for the full collector/tool reference.

`--no-investigate` is a degraded escape hatch. It disables LLM-requested evidence tools and uses deterministic precollection for no-tool synthesis.

If the local history daemon has collected fresh metrics, triage automatically includes a bounded history summary as another evidence envelope in the prompt. The default history window is `24h`; use `--history-window` to narrow or widen it within retained data. Use `--no-history` to opt out, or `--use-history` to force including a history summary even when it is stale or empty:

```bash
descartes triage "How's my system doing?"
descartes triage --history-window 6h "Did anything change recently?" --json
descartes triage --no-history "Ignore local history for this question"
```

## Local history daemon

Descartes can keep a bounded local metric history so later CLI commands can answer “what changed recently?” without invoking an LLM.

```bash
# Install/update the user-level service file. Safe to rerun.
descartes daemon install

# Load/start the user service. Safe to rerun if already running.
descartes daemon start

# Report service-file state plus best-effort runtime state.
descartes daemon status

# Stop/unload the user service. Safe to rerun if already stopped.
descartes daemon stop

# Stop if needed, then remove the service file. Safe to rerun.
descartes daemon uninstall

# Add --json to any lifecycle command for machine-readable output.
descartes daemon status --json
```

For development or one-shot collection, you can run the loop in the foreground:

```bash
descartes daemon run --foreground --once
descartes daemon run --foreground --interval 60s
```

Current daemon collection is deliberately conservative: system overview, top processes, and disk usage. It writes compact metric points, daemon status, and deterministic alert state under Descartes-owned XDG state paths, then enforces retention/max-size bounds. It does **not** make background LLM calls unless alert intelligence is explicitly enabled, upload telemetry, expose shell tools, or take remediation actions.

Service management is user-level only:

| Platform | Service file | Start/stop mechanism |
|---|---|---|
| macOS | `$HOME/Library/LaunchAgents/com.lightless-labs.descartes.daemon.plist` | `launchctl bootstrap` / `launchctl bootout` for `gui/$UID` |
| Linux | `$XDG_CONFIG_HOME/systemd/user/descartes.service` or `$HOME/.config/systemd/user/descartes.service` | `systemctl --user enable --now` / `disable --now` |

Daemon lifecycle commands print concise human-readable output by default. Add `--json` for machine-readable output; generated service-file contents are not printed.

The daemon commands are intended to be idempotent:

- `install`: `installed`, `updated`, or `unchanged`
- `start`: `started` or `already_running`
- `status`: `installed`, `not_installed`, or `drifted`, plus runtime fields where available
- `stop`: `stopped` or `not_running`
- `uninstall`: `removed` or `not_installed`

Summarize local history without an LLM:

```bash
descartes history summary                 # compact operator summary
descartes history summary --verbose       # full human metric table
descartes history summary --json --window 1h
```

Inspect deterministic local alerts without an LLM:

```bash
descartes alerts list
descartes alerts list --json --all
descartes alerts watch --interval 30s
descartes alerts ack alert_...
```

Initial alert rules cover missing/stale daemon samples, sustained high memory pressure, sustained high load relative to CPU count, and disk pressure. Alert state is stored locally under Descartes-owned XDG state paths.

Alert intelligence is explicit opt-in. When enabled, deterministic alert transitions may wake an LLM with bounded alert/history summaries so the model can decide whether/how to notify and write bounded notification text. It has no remediation/action tools:

```bash
descartes alerts intelligence status
descartes alerts intelligence enable --max-per-hour 3
descartes alerts intelligence disable
```

Desktop/headless notification delivery is separately explicit opt-in. Delivery adapters receive only the LLM's bounded notification decision text, not raw alert/evidence dumps:

```bash
descartes alerts notifications status
descartes alerts notifications setup --channel desktop   # macOS osascript or Linux notify-send when available
descartes alerts notifications test                      # may trigger the platform permission prompt
descartes alerts notifications setup --channel syslog    # headless/local log entry option
# Experimental native macOS path; Homebrew installs the signed/notarized helper.
# Setup fails closed if no executable helper is resolved; --json includes the helper resolution.
descartes alerts notifications setup --channel native --json
# --helper remains a development/advanced override for non-Homebrew installs:
descartes alerts notifications setup --channel native --helper /path/to/DescartesNotifier
descartes alerts notifications disable
```

Platform caveat: a pure CLI may have desktop notification permission attributed to Terminal/osascript on macOS; Linux desktop notifications require a graphical session notification service. Experimental native macOS delivery uses a macOS-specific signed/notarized release-built helper when available (for example through Homebrew), without shipping a `.app` payload in Linux/cross-platform installs, but still needs real-host TCC/Notification Center validation before becoming the default.

This daemon lifecycle is new and still needs broader real-host validation across launchd/systemd variants.

## Login and model selection

`descartes login` opens a browser for subscription OAuth when possible. If the browser callback cannot complete, use:

```bash
descartes login --no-open
```

For subscription logins, Descartes picks a strong default rather than the provider registry's first model: highest available `openai-codex` GPT model by semantic version, or highest available Anthropic Sonnet. You can override model selection:

```bash
descartes triage "my machine is slow" --model openai-codex/gpt-5.5 --thinking high
```

## JSON output

Use `--json` for replay/debugging:

```bash
descartes triage "my machine is slow" --json
```

JSON output includes the diagnosis, evidence envelopes, deterministic findings, diagnostics, tool traces, selected model metadata, active tool names, fallback state, and:

```json
"actions_taken": []
```

## Safety and privacy boundaries

Current v0 boundaries:

- local evidence collection is read-only
- triage takes no host actions
- daemon lifecycle commands mutate only explicit Descartes user-level service files/service state
- alert commands mutate only Descartes-owned alert acknowledgement/state files
- notification delivery is disabled by default and requires explicit setup/test opt-in
- no arbitrary shell/coding tools are exposed to the triage agent
- no telemetry, background upload, or federation
- alert-intelligence background LLM wakeups are disabled by default and require explicit opt-in
- explicit `triage` requests may send collected evidence to the selected LLM provider
- saved reports/session state are sensitive diagnostic artifacts

Descartes may use Pi internally as a private harness, but it does not require, read, import, or modify the user's personal Pi setup (`~/.pi`, project `.pi`, sessions, settings, auth, skills, prompts, themes, or model config).

## Supported platforms

- Tier 1: macOS Apple Silicon, Linux x86_64
- Best effort: macOS Intel, Linux ARM64
- Not supported initially: Windows, BSD, Android/Termux, remote hosts, and container-only introspection

MVP limitations: user-level daemon lifecycle is new and still needs real-host validation, no remote hosts, limited VM/container/service-manager/log coverage, no redacted export mode yet, and no remediation actions beyond explicit daemon lifecycle commands.

## Descartes-owned paths

Descartes follows XDG Base Directory conventions:

| Purpose | Default |
|---|---|
| Config/auth | `$XDG_CONFIG_HOME/descartes` or `$HOME/.config/descartes` |
| Data | `$XDG_DATA_HOME/descartes` or `$HOME/.local/share/descartes` |
| State/session artifacts | `$XDG_STATE_HOME/descartes` or `$HOME/.local/state/descartes` |
| Cache | `$XDG_CACHE_HOME/descartes` or `$HOME/.cache/descartes` |
| Runtime | `$XDG_RUNTIME_DIR/descartes` when `XDG_RUNTIME_DIR` is set |

Descartes must not use any Pi-owned path.

## Evidence envelopes

Tools return structured evidence, not prose blobs. A typical envelope looks like:

```json
{
  "id": "system-overview",
  "status": "ok",
  "layer": "L0",
  "source": "os",
  "result": {},
  "confidence": 1,
  "review_hint": "none",
  "trace": {
    "tool": "collect_system",
    "target": null,
    "latency_ms": 18,
    "ts": "2026-05-18T00:00:00Z"
  }
}
```

This makes diagnosis, replay, testing, auditing, and future signature extraction easier.

## Architecture direction

Descartes is designed as layered machinery, not a single free-roaming autonomous shell:

| Layer | Purpose |
|---|---|
| L0 Deterministic System Tools | Gather factual evidence from local tools and platform APIs. |
| L1 Monitoring / Rules / Signatures | Detect thresholds, repeated failures, drift, and known issue patterns. |
| L2 Deliberative Agents | Escalated diagnosis, incident correlation, recommendations, and planning. |
| L3 Federated Knowledge | Optional future sharing of anonymized signatures and outcomes. |
| Policy / Authority Plane | Permissioning, approvals, action plans, and audit logs. |

The model may route questions, request evidence, synthesize explanations, audit gaps, and suggest improvements. It is not the source of truth. The source of truth is local structured evidence.

## Repository status

The installable first slice lives under `tools/descartes-cli/`. It includes idempotent user-level daemon install/start/status/stop/uninstall commands, a foreground `descartes daemon run --foreground` development loop that stores bounded metric history under Descartes-owned XDG state paths, `descartes history summary` for deterministic local summaries, deterministic alerts via `descartes alerts list/watch/ack`, opt-in alert intelligence, and opt-in notification setup/test commands.

Rust remains the intended direction for durable collectors, stores, policy/audit machinery, and future native CLIs. When Rust crates are introduced, they should stay Bazel-friendly: explicit manifests, reproducible tests, no hidden generation steps, and a clean crate graph.

The wider Lightless Labs monorepo prefers Bazel.
