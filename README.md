# Descartes

Descartes is a local-first operations agent for one machine. It works as a maintenance
agent, a system-administration assistant, and a gateway to system operations. It looks at
the host with read-only tools. Then a private LLM agent reads the evidence. Descartes
prints a diagnosis that shows the evidence and gives safe next checks.

Descartes makes no change to the host. A change needs a special command. That command does
not exist yet. When it exists, a person must start it, and the policy must approve it.

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

## Index

- [Capabilities at a glance](#capabilities-at-a-glance)
- [Status](#status)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Operational lifecycle](#operational-lifecycle)
- [What `triage` does today](#what-triage-does-today)
- [Local history daemon and deterministic alerts](#local-history-daemon-and-deterministic-alerts)
- [Self-learning and defensive detection](#self-learning-and-defensive-detection-opt-in-default-off) — [detectors](#defensive-detectors) · [current limits](#current-limits)
- [Login and model selection](#login-and-model-selection)
- [JSON output](#json-output)
- [Safety and privacy invariants](#safety-and-privacy-invariants)
- [Supported platforms](#supported-platforms)
- [Descartes-owned paths](#descartes-owned-paths)
- [Repository layout](#repository-layout)
- [Building and testing](#building-and-testing)
- [Further reading](#further-reading)

## Capabilities at a glance

| Capability | What it does | Status |
|---|---|---|
| **Triage** | Answers a question about the host. The model leads. The diagnosis uses only read-only evidence envelopes (`actions_taken: []`). | Live |
| **Local history and alerts** | Keeps a bounded local metric history. Raises alerts on memory, load, disk, and daemon staleness. Uses no LLM. | Live |
| **Self-learning monitoring** | Mines candidate rules and baselines from the host history. A person must approve each one before it becomes active. | Off by default |
| **Defensive detection** | Runs novelty detectors, deception canaries, and intrusion signals. See the [detector list](#defensive-detectors). | Off by default |
| **Containment recommendations** | Recommends containment through a local notification. It only recommends. It makes no change. | Off by default |
| **Evidence freeze** | Makes a read-only forensic evidence bundle. An operator starts it (`descartes incident freeze`). | Live |
| **Remediation and host actions** | No general action tool exists yet. Descartes changes only its own daemon service and its alert-state files. | Not yet |

The self-learning and defensive detection functions are **off by default**. They go quiet
when in doubt. They do not make a false alarm. See the [current limits](#current-limits).

## Status

This is version 0. It has these parts:

- a read-only triage CLI;
- a local-first alerting daemon with deterministic rules;
- a self-learning subsystem (off by default).

The self-learning subsystem mines rules and baselines from the machine history. It also
runs defensive detectors: novelty baselines, deception canaries, and intrusion signals.
These detectors go quiet when in doubt. They do not make a false alarm.

The durable core will move to Rust over time. The current CLI uses Node.js, because this
lets the tool ship quickly. The CLI includes the agent harness and the subscription login.

For the plan, see `docs/ROADMAP.md`. For the current state, see `docs/HANDOFF.md`.

## Quick start

On macOS, use Homebrew to install Descartes. Homebrew installs the CLI and the signed,
notarized notification helper:

```bash
brew install lightless-labs/tap/descartes
```

An old `npm install -g` with Homebrew's Node.js can block `brew link`. Remove that old
install first. Then `brew link` can claim the `descartes` command:

```bash
npm uninstall -g @lightless-labs/descartes
```

For other systems, install with npm. This needs Node.js 22.19.0 or higher and a writable
npm global prefix. This install does not include the macOS notification helper. The
`osascript` channel still works. The `--helper` option stays available as a manual override.

```bash
npm install -g github:Lightless-Labs/descartes
descartes login
descartes triage "my machine is slow"
descartes triage "my machine is slow" --json
```

To install from an HTTPS tarball, use this command:

```bash
npm install -g https://github.com/Lightless-Labs/descartes/tarball/main
```

For a root-owned system npm prefix, install into a user prefix instead:

```bash
npm install -g --prefix "$HOME/.local" github:Lightless-Labs/descartes
export PATH="$HOME/.local/bin:$PATH"
```

Some Linux distributions have an old Node.js package. On these systems, install Node.js
22.19.0 or higher first with your usual version manager. Then install Descartes.

## Architecture

Descartes has layers. It is not one free autonomous shell. The lifecycle stages (below) are
not the same as these layers. One stage can use several layers. One layer can support
several stages.

| Layer | Purpose |
|---|---|
| L0 Deterministic System Tools | Get facts from local tools and platform APIs: OS, CPU, memory, disks, processes, services, logs, network, containers, VMs, scheduled jobs, certificates, sessions, and peers. |
| L1 Monitoring, Rules, Signatures | Find threshold breaches, repeated failures, drift, and known-issue patterns. Use no LLM. |
| L2 Deliberative Agents | Do escalated diagnosis, incident correlation, recommendations, and plans for new or unclear conditions. |
| L3 Federated Knowledge | Share anonymized signatures and outcomes across a fleet. This is optional and for the future. |
| Policy and Authority Plane | Control permissions, approvals, action plans, and audit logs for every change to the system. |

The model can route questions, ask for evidence, write explanations, audit gaps, and
suggest improvements. The model is not the source of truth. The source of truth is the local
structured evidence. Descartes returns this evidence as typed envelopes, not as prose:

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

1. **Observe** — Collect facts, logs, metrics, events, and machine state.
2. **Notify** — Show important changes, risks, failures, and anomalies.
3. **Diagnose** — Explain the probable causes from the evidence.
4. **Recommend** — Suggest fixes, tradeoffs, and next checks.
5. **Plan** — Build action plans that a person can audit and review.
6. **Act** — Do actions only through the policy and authority gates.
7. **Learn** — Turn confirmed findings into cheaper rules, signatures, tests, and tools.

## What `triage` does today

In normal triage, the model leads. The steps are:

1. The user asks a question about the machine.
2. The private Descartes agent selects the read-only evidence tools to call.
3. The deterministic collectors return structured evidence envelopes.
4. The model writes a diagnosis. It uses only those envelopes and shows the evidence.
5. Descartes prints the report. It records `actions_taken: []`.

The collectors cover many areas:

- system identity, uptime, CPU, memory, and swap;
- disks, mounts, and filesystem type;
- top processes and the process parent tree;
- bounded time sampling;
- network basics: interfaces, routes, DNS, and listening sockets;
- service managers: launchd and systemd;
- recent logs (bounded);
- containers: Docker, Podman, Colima, Lima, and Apple `container`;
- VMs: Tart, Multipass, VirtualBox, libvirt, Parallels, VMware, UTM, and more;
- scheduled jobs;
- time sync;
- certificates;
- tmux and screen sessions;
- VPN and peer status: WireGuard, macOS VPN services, and Tailscale.

For the full list, see `docs/reference/collectors.md`.

`--no-investigate` is a fallback mode. It turns off the LLM-requested evidence tools. It
uses precollected facts to write the answer without tools.

When the local history daemon has fresh metrics, triage adds a bounded history summary.
This summary is one more evidence envelope. The default window is `24h`:

```bash
descartes triage "How's my system doing?"
descartes triage --history-window 6h "Did anything change recently?" --json
descartes triage --no-history "Ignore local history for this question"
```

## Local history daemon and deterministic alerts

Descartes can keep a bounded local metric history. Later CLI commands use this history to
answer "what changed recently?". They use no LLM. Descartes can also raise deterministic
alerts from this history. These alerts use no model.

```bash
descartes daemon install    # write a user launchd/systemd service file (safe to repeat)
descartes daemon start      # load and start the user service (safe to repeat)
descartes daemon status
descartes daemon stop
descartes daemon uninstall
descartes daemon run --foreground --once      # one collection, for development

descartes history summary                     # short local metric summary, no LLM
descartes alerts list                         # deterministic local alerts, no LLM
descartes alerts watch --interval 30s
descartes alerts ack alert_...
```

The daemon collects only a few facts: the system overview, the top processes, and the disk
usage. It writes only under Descartes-owned XDG state paths. It obeys the retention and
size limits.

The daemon does not do these things:

- make background LLM calls (unless you enable alert intelligence);
- upload telemetry;
- give shell tools;
- do remediation actions.

The daemon runs at user level only: `launchctl` on macOS, `systemctl --user` on Linux.
This part is new. It needs more tests on real hosts and different launchd and systemd
versions.

The alert rules cover four conditions:

- a missing or stale daemon sample;
- sustained high memory pressure;
- sustained high load for the CPU count;
- disk pressure.

Alert intelligence is a separate option, off by default. When you enable it, an alert
change can wake an LLM session. This session is rate-limited and audited. It has no
remediation tools. It decides whether and how to notify.

Notification delivery is also a separate option, off by default. The channels are desktop,
syslog, or an experimental native macOS channel:

```bash
descartes alerts intelligence enable --max-per-hour 3
descartes alerts notifications setup --channel desktop
```

## Self-learning and defensive detection (opt-in, default off)

One kill switch controls this subsystem: `learned.json`. It is off by default. When on,
Descartes can do these things:

- read its own fact history;
- mine candidate rules and provenance and identity baselines;
- run the defensive detectors.

Descartes promotes a mined candidate to live monitoring only after a human approval. The
approval is explicit, single-use, and audited.

```bash
descartes learned enable                # turn the subsystem on (off by default)
descartes learned mine                  # mine candidates from the facts
descartes learned soak                  # shadow test; never alerts on its own
descartes learned review                # list candidates that wait for approval
descartes learned approve <constraint-id> --nonce <nonce>
descartes learned status                # subsystem state and fact-store completeness
descartes provenance snapshot           # process/identity baseline snapshot
descartes provenance baseline show
descartes containment recommend status  # recommend-only containment surface (separate option, off by default)
```

Each mined artifact moves through one lifecycle: `draft → shadow → review-ready → active →
retired`. An active artifact feeds the same alert pipeline as the fixed rules. No promotion
happens without a human decision.

### Defensive detectors

These detectors run inside the daemon tick. They are deterministic and use no LLM, except
where noted. They read only the host's own facts. They hash identity values at the source.

Each novelty detector is completeness-gated. When its fact history is incomplete, damaged,
or changed, the detector emits nothing. This state is "cold-start". The detector does not
make a false "first time" alert.

The positive-evidence detectors are different. Credential access and canary trips fire on a
direct observation. They are not gated. Descartes never discards a real event.

| Detector | Detects | Basis |
|---|---|---|
| Session baseline | A mass session drop or churn (`session.count_drop`, `session.churn`). | tmux and screen session census |
| Peer baseline | A burst or a drop of VPN or tailnet peer logins (`peer.count_spike`, `peer.count_drop`). | WireGuard, Tailscale, and VPN peer census |
| Service baseline | A known service that disappears, or a new service that appears (`service.disappeared`, `service.appeared`). | launchd and systemd census |
| Scheduled-job baseline | A new cron or scheduled job — a common persistence foothold (`scheduled_job.appeared`). | cron, systemd-timer, and launchd census |
| Process lineage | A new exec-chain edge — an unusual child process (`process.lineage_edge`). | process parent and child census |
| Credential access | A read or a rewrite of a watched credential file (`credential.access`). This is positive evidence, not gated. | two `lstat` snapshots (mtime and inode); `lstat` only; never reads the contents |
| Deception canaries | A touch of a honey-token file, or a change to the canary manifest or store (`canary.tripped`, `canary.tampered`). | filesystem tripwire |
| Incident correlation | A mass session drop together with an odd-hour, unknown peer login. | cross-stream join (optional, separately-gated LLM adjudication) |
| Provenance and identity | A process or a listening socket whose provenance or identity signature moves away from its baseline. | process ancestry and hashed identity signatures |

The **fact-store completeness** substrate supports these detectors. It makes the "never
fabricate" rule hold. A durable, tamper-aware integrity ledger records whether the fact
history is complete. So a detector can separate two cases: "I have never seen this" and "I
cannot trust my history". In the second case, the detector stays quiet. The state `intact`
needs positive proof. `descartes learned status` shows the current completeness state.

The **recommend-only containment surface** turns a strong signal into a recommendation, for
example "throttle, block, or quarantine X". It sends the recommendation through the
local-notification path. It always adds the label `RECOMMEND-ONLY`. This surface cannot act.
It has no execution primitive, no capability token, and no way to change the host. Its
option does not turn on unless `descartes learned enable` is already on.

### Current limits

These are the limits of the defensive layer today:

- **Off by default.** This layer protects nothing until you enable it with
  `descartes learned enable` and run the daemon. For alerts, you must also turn on
  notifications.
- **Cold-start and setup time.** A detector stays quiet until it has enough clean history
  for a baseline. A new install reports nothing. A detector that recovers from a real
  history loss also reports nothing. Recovery after a real loss takes up to the
  fact-retention window. This delay is deliberate and safe.
- **Host-edge scope.** Descartes watches the local host. It does not watch the cloud plane
  or the cluster plane.
- **Polling, not real-time.** Detection runs on the daemon cycle. A fast action between two
  cycles can escape. A real-time event path exists in the design, but it is not built.
- **On-host tamper has a bound.** The completeness ledger stops accidental loss and
  non-root, out-of-band changes. But a root attacker who rewrites both the facts and the
  ledger together defeats the on-host check. An off-host attestation and a fleet
  dead-man's-switch are future design work. A canary detects tampering, but it cannot
  protect itself against local root.
- **Recommend-only.** Containment proposes an action. It never does the action. There is no
  general remediation tool yet.
- **One instance only.** Two daemon instances on the same state directory can race the fact
  store. This is a known, deferred item.

The design and the current build status are in
`docs/plans/2026-07-09-self-learning-stratified-monitoring.md`,
`docs/plans/2026-08-21-fact-store-completeness-hardening.md`, and `docs/HANDOFF.md`.

## Login and model selection

`descartes login` opens a browser for subscription OAuth, when possible. When the browser
callback cannot finish, use `descartes login --no-open`.

For a subscription login, Descartes picks a strong default model. It does not pick the first
model in the registry. It picks the highest `openai-codex` GPT model by version, or the
highest Anthropic Sonnet model. You can override the model:

```bash
descartes triage "my machine is slow" --model openai-codex/gpt-5.5 --thinking high
```

## JSON output

Use `--json` on most commands for replay and debugging. For `triage`, the JSON output
includes these items:

- the diagnosis;
- the evidence envelopes;
- the deterministic findings;
- the diagnostics;
- the tool traces;
- the selected model metadata;
- the active tool names;
- the fallback state;
- and this field:

```json
"actions_taken": []
```

## Safety and privacy invariants

- Descartes is read-only by default. Local evidence collection makes no host change.
- No action changes the host without an explicit policy approval. Today Descartes changes
  only two things: its own user-level daemon service, and its alert-state files. There is no
  general remediation tool yet.
- Descartes does no raw telemetry, no background upload, and no federation, unless you turn
  it on.
- Alert-intelligence LLM wakeups are off by default. When on, they are rate-limited and
  audited. That path has no remediation or shell tools (`enableTools:false`).
- Notification delivery is off by default. It needs an explicit setup and test step.
- Descartes hashes or buckets every identity value at the source: PIDs, ports, users, hosts,
  IPs, and paths. This happens before the value enters any store. Each domain uses its own
  fixed scheme.
- Missing or damaged evidence becomes `unknown` or a skip. Descartes never invents a
  security signal or a health signal.
- `descartes incident freeze` saves a Descartes-owned forensic evidence bundle. It calls
  only the registered read-only evidence tools. It changes nothing on the host. Only an
  operator can start it. Descartes never sends the bundle to an LLM. See
  `docs/reference/incident-freeze.md`.
- Descartes can use Pi inside itself as a private agent harness. But Descartes does not read,
  import, or change the user's own Pi setup. This includes `~/.pi`, a project `.pi`,
  sessions, settings, auth, skills, prompts, themes, and model config. Descartes never
  writes to a Pi-owned path.

For the complete safety-invariant list, see `AGENTS.md`.

## Supported platforms

- Tier 1 (supported): macOS Apple Silicon and Linux x86_64.
- Best effort: macOS Intel and Linux ARM64.
- Not supported now: Windows, BSD, Android and Termux, remote hosts, and container-only
  introspection.

## Descartes-owned paths

Descartes uses the XDG Base Directory conventions. It must not use a Pi-owned path:

| Purpose | Default |
|---|---|
| Config and auth | `$XDG_CONFIG_HOME/descartes` or `$HOME/.config/descartes` |
| Data | `$XDG_DATA_HOME/descartes` or `$HOME/.local/share/descartes` |
| State and session artifacts | `$XDG_STATE_HOME/descartes` or `$HOME/.local/state/descartes` |
| Cache | `$XDG_CACHE_HOME/descartes` or `$HOME/.cache/descartes` |
| Runtime | `$XDG_RUNTIME_DIR/descartes` when `XDG_RUNTIME_DIR` is set |

## Repository layout

- `tools/descartes-cli/` — the Node.js CLI. It holds triage, the history daemon, the alerts
  and notifications, the self-learning subsystem, and all L0 collectors
  (`tools/descartes-cli/src/tools/`).
- `crates/` — the Rust workspace. Today it holds `descartes-root-helper`. This is a `/proc`
  resolver with no shell and a fixed argv. It supports an optional elevated-read path on
  Linux. It is a start, not the full durable core in `AGENTS.md`.
- `docs/plans/` — one implementation plan per slice of work. The team reviews and updates
  each plan.
- `docs/reference/` — collector and command reference docs (`collectors.md`,
  `incident-freeze.md`).
- `docs/research/`, `docs/reviews/`, `docs/solutions/`, `docs/use-cases/` — research notes,
  real-host validation reports, durable learnings, and example scenarios.
- `docs/ROADMAP.md` — the longer-term capability roadmap and non-negotiables.
- `docs/HANDOFF.md` — the live handoff document. Start here for the current state.
- `todos/` — pending, tracked work items.

## Building and testing

The Node.js CLI is the main tested surface today:

```bash
npm install
npm test          # node --test tools/descartes-cli/test/*.test.js
npm run smoke:cli  # descartes --help
```

The Rust workspace in `crates/` builds and tests on its own, apart from the Node CLI:

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

Some Rust code (the elevated `/proc` paths) runs on Linux only. CI gates it for Linux. But
`cargo check` still compiles those paths on any host.

The larger Lightless Labs monorepo prefers Bazel. This repo builds with npm and Cargo
directly for now. But it stays Bazel-friendly: clear manifests, no hidden generation steps,
reproducible tests, and a clean crate graph.

## Further reading

- `AGENTS.md` — the agent instructions: project identity, architecture, lifecycle, safety
  invariants, and conventions. Read this first.
- `docs/HANDOFF.md` — the current handoff document. It points to the live state and the next
  action.
- `docs/plans/` — per-slice implementation plans.
- `docs/ROADMAP.md` — the broader capability roadmap.

### Lineage (fiction)

Two novels sit behind the project's sensibility:

- *The Second Angel*, Philip Kerr — the source of the name. Descartes is the computer
  running the literal Blood Bank on the Moon: a machine entrusted with keeping critical
  infrastructure alive. That is the whole posture, made humble — observe first, act only
  when allowed.
- *Absolution Gap*, Alastair Reynolds — for the layered approach. Survival there is a matter
  of stratified, defense-in-depth reflexes and escalation rather than one all-seeing
  intelligence, which is exactly how Descartes' L0–L3 layering is meant to work.
