# Descartes

Descartes is an AI-native, local-first operations agent: a maintenance agent, sysadmin
assistant, and system-operations gateway for a machine. It observes a host through
read-only tools, asks an LLM-backed private agent session to interpret that evidence, and
prints an evidence-cited diagnosis with safe next checks. No host actions are taken unless
a future mutating command is explicitly invoked and policy-authorized.

```bash
descartes triage "my machine is slow"
```

The name comes from Philip Kerr's *The Second Angel*: Descartes is the computer running the
literal Blood Bank on the Moon. This project borrows the idea of a machine entrusted with
keeping critical infrastructure alive, but starts humbly: observe first, notify clearly, act
only when explicitly allowed.

Descartes is not "an LLM watching a server." It is meant to become a stratified machine
nervous system — cheap deterministic reflexes, statistical baselines, known-issue
signatures, and deliberative agent layers for escalation — all sitting on top of local
structured evidence rather than model guesswork. See `AGENTS.md` for the full project
identity, architecture, and conventions this repo follows.

## Status

This is v0: a read-only triage CLI, a local-first deterministic alerting daemon, and an
opt-in (default-off) self-learning subsystem that mines constraints and provenance
baselines from a machine's own history. The durable core is expected to move toward Rust
over time; the current external slice is a Node.js CLI so it can ship quickly with the
embedded agent harness and subscription login flow. See `docs/ROADMAP.md` for the broader
capability roadmap and `docs/HANDOFF.md` for exactly what is implemented right now.

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

On Linux distributions with older Node.js packages, install Node.js 22.19.0+ through your
normal version manager before installing Descartes.

## Architecture

Descartes is designed as layered machinery, not a single free-roaming autonomous shell.
Lifecycle stages (below) are conceptually separate from these implementation layers — a
stage may involve several layers, and a layer may support several stages.

| Layer | Purpose |
|---|---|
| L0 Deterministic System Tools | Gather factual evidence from local tools and platform APIs (OS/CPU/memory/disks, processes, services, logs, network, containers/VMs, scheduled jobs, certificates, sessions, peers). |
| L1 Monitoring / Rules / Signatures | Detect thresholds, repeated failures, drift, and known-issue patterns without invoking an LLM. |
| L2 Deliberative Agents | Escalated diagnosis, incident correlation, recommendations, and planning for novelty/ambiguity. |
| L3 Federated Knowledge | Optional future sharing of anonymized signatures and outcomes across a fleet. |
| Policy / Authority Plane | Permissioning, approvals, action plans, and audit logs for anything that changes the system. |

The model may route questions, request evidence, synthesize explanations, audit gaps, and
suggest improvements. It is not the source of truth — the source of truth is local
structured evidence, returned as typed envelopes rather than prose:

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

## Operational lifecycle

```
Observe → Notify → Diagnose → Recommend → Plan → Act → Learn
```

1. **Observe** — collect facts, logs, metrics, events, and machine state.
2. **Notify** — surface meaningful changes, risks, failures, and anomalies.
3. **Diagnose** — explain likely causes from grounded evidence.
4. **Recommend** — suggest remediations, tradeoffs, and next checks.
5. **Plan** — build auditable, reviewable action plans.
6. **Act** — execute only through explicit policy and authority gates.
7. **Learn** — compile confirmed findings back into cheaper rules, signatures, tests, and
   tools.

## What `triage` does today

Normal triage is model-led:

1. The user asks a local machine question.
2. The private Descartes agent decides which read-only Descartes evidence tools to call.
3. Deterministic collectors return structured evidence envelopes.
4. The model writes an evidence-cited diagnosis using only those envelopes.
5. Descartes prints the report and records `actions_taken: []`.

Current collectors span system identity/uptime/CPU/memory/swap; disks/mounts/filesystem
classification; top processes and process/parent-tree inspection; bounded temporal
sampling; network basics (interfaces, routes, DNS, listening sockets); service manager
basics (launchd/systemd); bounded recent logs; container basics (Docker, Podman, Colima,
Lima, Apple `container`); VM basics (Tart, Multipass, VirtualBox, libvirt, Parallels,
VMware, UTM, and more); scheduled jobs; time sync; certificates; tmux/screen session
census; and VPN/peer status (WireGuard, macOS VPN services, Tailscale). See
`docs/reference/collectors.md` for the full collector/tool reference.

`--no-investigate` is a degraded escape hatch: it disables LLM-requested evidence tools and
uses deterministic precollection for no-tool synthesis.

If the local history daemon has collected fresh metrics, triage automatically includes a
bounded history summary as another evidence envelope. The default window is `24h`:

```bash
descartes triage "How's my system doing?"
descartes triage --history-window 6h "Did anything change recently?" --json
descartes triage --no-history "Ignore local history for this question"
```

## Local history daemon and deterministic alerts

Descartes can keep a bounded local metric history so later CLI commands can answer "what
changed recently?" without invoking an LLM, and can raise deterministic alerts from that
history with no model involved:

```bash
descartes daemon install    # idempotently writes a user launchd/systemd service file
descartes daemon start      # idempotently loads/starts the user service
descartes daemon status
descartes daemon stop
descartes daemon uninstall
descartes daemon run --foreground --once      # development / one-shot collection

descartes history summary                     # compact local metric summary, no LLM
descartes alerts list                          # deterministic local alerts, no LLM
descartes alerts watch --interval 30s
descartes alerts ack alert_...
```

Daemon collection is deliberately conservative (system overview, top processes, disk
usage) and writes only under Descartes-owned XDG state paths, honoring retention/max-size
bounds. It does **not** make background LLM calls unless alert intelligence is explicitly
enabled, upload telemetry, expose shell tools, or take remediation actions. Service
management is user-level only (`launchctl` on macOS, `systemctl --user` on Linux); this
lifecycle is comparatively new and still benefits from broader real-host validation across
launchd/systemd variants.

Alert rules cover missing/stale daemon samples, sustained high memory pressure, sustained
high load relative to CPU count, and disk pressure. Alert intelligence — an explicit
opt-in that lets a deterministic alert transition wake a rate-limited, audited LLM session
(no remediation tools) to decide whether/how to notify — and notification delivery
(desktop, syslog, or an experimental native macOS channel) are both separately opt-in:

```bash
descartes alerts intelligence enable --max-per-hour 3
descartes alerts notifications setup --channel desktop
```

## Self-learning subsystem (opt-in, default off)

Behind a single `learned.json` kill switch (default disabled), Descartes can observe its
own accumulated fact history, mine candidate constraints and provenance/identity
baselines, shadow-soak them against real traffic, and only promote a candidate to live
monitoring after an explicit, single-use, audited human approval:

```bash
descartes learned mine       # deterministic candidate mining from accumulated facts
descartes learned soak       # shadow-soak evaluation, never alerts on its own
descartes learned review     # list promotions awaiting human approval
descartes learned approve <constraint-id> --nonce <nonce>
descartes learned status
descartes provenance snapshot          # process/identity baseline snapshot
descartes provenance baseline show
```

Learned artifacts move through one lifecycle — `draft → shadow → review-ready → active →
retired` — and, once active, feed the same deterministic alert pipeline as the fixed
rules; no promotion happens without a human decision. Design and current build status live
in `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` and `docs/HANDOFF.md`.

## Login and model selection

`descartes login` opens a browser for subscription OAuth when possible. If the browser
callback cannot complete, use `descartes login --no-open`.

For subscription logins, Descartes picks a strong default rather than the provider
registry's first model: highest available `openai-codex` GPT model by semantic version, or
highest available Anthropic Sonnet. You can override model selection:

```bash
descartes triage "my machine is slow" --model openai-codex/gpt-5.5 --thinking high
```

## JSON output

Use `--json` on most commands for replay/debugging. For `triage`, JSON output includes the
diagnosis, evidence envelopes, deterministic findings, diagnostics, tool traces, selected
model metadata, active tool names, fallback state, and:

```json
"actions_taken": []
```

## Safety and privacy invariants

- Read-only by default; local evidence collection takes no host actions.
- No mutating action without explicit policy authorization — today the only mutating
  surfaces are Descartes' own user-level daemon lifecycle and its alert
  acknowledgement/state files; there is no general remediation/action tool yet.
- No raw telemetry, background upload, or federation without explicit opt-in.
- Alert-intelligence background LLM wakeups are disabled by default, rate-limited, and
  audited when enabled; that path has no remediation/shell tools (`enableTools:false`).
- Notification delivery is disabled by default and requires explicit setup/test opt-in.
- Identity-bearing values (pids, ports, users, hosts, IPs, paths) are hashed or bucketed at
  the source before they enter any store, with distinct golden-pinned schemes per domain.
- Missing or garbled evidence degrades to `unknown`/skip — Descartes never fabricates a
  security or health signal.
- `descartes incident freeze` persists a Descartes-owned forensic evidence bundle by
  calling only already-registered read-only evidence tools; it mutates nothing on the
  monitored host, is operator-invoked only, and the bundle is never sent to an LLM — see
  `docs/reference/incident-freeze.md`.
- Descartes may use Pi internally as a private agent harness, but it does not require,
  read, import, or modify the user's personal Pi setup (`~/.pi`, project `.pi`, sessions,
  settings, auth, skills, prompts, themes, or model config), and never writes to a
  Pi-owned path.

See `AGENTS.md` for the complete, authoritative safety-invariant list.

## Supported platforms

- Tier 1: macOS Apple Silicon, Linux x86_64
- Best effort: macOS Intel, Linux ARM64
- Not supported initially: Windows, BSD, Android/Termux, remote hosts, and container-only
  introspection

## Descartes-owned paths

Descartes follows XDG Base Directory conventions and must not use any Pi-owned path:

| Purpose | Default |
|---|---|
| Config/auth | `$XDG_CONFIG_HOME/descartes` or `$HOME/.config/descartes` |
| Data | `$XDG_DATA_HOME/descartes` or `$HOME/.local/share/descartes` |
| State/session artifacts | `$XDG_STATE_HOME/descartes` or `$HOME/.local/state/descartes` |
| Cache | `$XDG_CACHE_HOME/descartes` or `$HOME/.cache/descartes` |
| Runtime | `$XDG_RUNTIME_DIR/descartes` when `XDG_RUNTIME_DIR` is set |

## Repository layout

- `tools/descartes-cli/` — the installable Node.js CLI: triage, the local history daemon,
  deterministic alerts/notifications, the self-learning subsystem, and all L0 collectors
  (`tools/descartes-cli/src/tools/`).
- `crates/` — Rust workspace. Today this holds `descartes-root-helper`, a zero-shell,
  fixed-argv `/proc` resolver for an opt-in elevated-read path on Linux; it is a starting
  point, not the full durable core described in `AGENTS.md`.
- `docs/plans/` — dedicated implementation plans for each slice of work, reviewed and
  updated as they progress.
- `docs/reference/` — collector and command reference docs (`collectors.md`,
  `incident-freeze.md`).
- `docs/research/`, `docs/reviews/`, `docs/solutions/`, `docs/use-cases/` — research notes,
  real-host validation reports, durable learnings, and example scenarios.
- `docs/ROADMAP.md` — the longer-term capability roadmap and non-negotiables.
- `docs/HANDOFF.md` — the live continuity/handoff document; start here for current state.
- `todos/` — pending, tracked work items.

## Building and testing

The Node.js CLI is the primary tested surface today:

```bash
npm install
npm test          # node --test tools/descartes-cli/test/*.test.js
npm run smoke:cli  # descartes --help
```

The Rust workspace under `crates/` builds and tests independently of the Node CLI:

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

Some Rust behavior (the elevated `/proc` resolution paths) is Linux-only and is gated
accordingly in CI; `cargo check` still exercises those code paths for compile-time
correctness on any host.

The wider Lightless Labs monorepo prefers Bazel. This repo currently builds with npm and
Cargo directly, but is kept Bazel-friendly: explicit manifests, no hidden generation steps,
reproducible tests, and a clean crate graph.

## Further reading

- `AGENTS.md` — agent instructions: project identity, architecture, lifecycle, safety
  invariants, and conventions. Read this first.
- `docs/HANDOFF.md` — the current continuity/handoff document; the authoritative pointer
  to live state and the next action.
- `docs/plans/` — per-slice implementation plans.
- `docs/ROADMAP.md` — the broader capability roadmap.
