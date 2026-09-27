---
date: 2026-09-26
topic: Sandboxing and microVM boundaries after CVE-2025-13032
status: complete
---

# Research: Sandboxing and microVM Boundaries after CVE-2025-13032

## Executive Finding

Descartes should not put the whole product in a VM, and should not make a microVM its primary
authority boundary. A host-operations agent needs host visibility and, eventually, narrowly scoped
host mutation. Giving a guest enough mounts, sockets, credentials, and RPCs to do those jobs would
recreate a large, security-critical integration surface while making collection less truthful.

The near-term move is privilege separation around a typed capability broker:

1. Keep the model unable to call a shell or a privileged helper directly.
2. Run collectors and future executors behind small, typed interfaces whose effects are classified
   semantically rather than by names such as `read_only`.
3. Snapshot and canonicalize each request once, bind it to a stable target identity, then use that
   exact captured value through validation and execution.
4. Isolate the L2/model session from state, credentials, and host execution with an unprivileged
   process boundary before considering a VM.
5. Add a capability-limited WASM runtime when Descartes starts accepting agent-authored or
   third-party parsers, rules, and transforms.
6. Consider an ephemeral microVM only when a concrete feature must run arbitrary native code,
   install packages, or inspect a suspicious artifact dynamically.

The microVM can be a useful *execution cell*. It is not an authorization mechanism, a trustworthy
source of host facts, or evidence that an action is safe on the real host.

## Codebase Context

Descartes currently has three relevant trust surfaces:

- The Node CLI/daemon owns local orchestration, state, monitoring, and the model harness.
- The model sees a closed set of named evidence tools from `tool-policy.js`; `pi-harness.js` maps
  those names to bounded collector implementations. There is no general shell tool.
- The Linux `descartes-root-helper` is a separate Rust binary with an exact three-command argv
  grammar. It engages `NO_NEW_PRIVS` and a seccomp allowlist before parsing argv, performs a narrow
  `/proc` resolution, drops capabilities, and only then writes output.

This is already closer to a capability system than to a general agent shell. The strongest current
pattern is in `proc_linux.rs`: it opens one `/proc/<pid>` directory descriptor and performs the
subsequent identity reads relative to it. A process exit therefore fails closed instead of allowing
PID reuse to splice two identities together. That is the correct response to the same broad class
of check/use race seen in the Avast driver.

The repository's design documents also already point in the right direction:

- `docs/architecture/2026-09-05-purpose-first-design.md` says the model requests observations
  through a broker, hostile evidence cannot grant authority, and privileged operations use a
  separate narrow executor.
- `docs/design/autonomy-doctrine.md` keeps executable code out of the detector hot path and leaves a
  future fuel-bounded expression runtime as an explicit exception.
- `docs/design/state-integrity-threat-model.md` identifies a separate service UID, service-owned
  state, root-owned code/config, and a closed typed RPC as the first meaningful boundary against a
  same-login-UID attacker.
- `docs/plans/2026-07-23-slice-7-authority-containment-plane.md` requires execution-time identity
  re-resolution and a capability-holding helper that the model and daemon cannot invoke as general
  authority.

## What the Avast Incident Actually Teaches

The useful lesson is not merely that sandboxes can be escaped.

### 1. A sandbox may add privileged attack surface

Avast installed a complex kernel driver with user-reachable IOCTL handlers. The vulnerable handler
was gated to sandboxed processes, so entering the sandbox exposed a kernel attack surface that the
ordinary process could not reach. Isolation therefore changed capability routing; it did not just
remove capabilities.

Descartes should avoid custom kernel components and custom hypervisors. Prefer existing kernel and
OS isolation primitives, and keep every Descartes-specific privileged interface much smaller than
the code it protects.

### 2. Transport permissions do not describe semantic effects

The researchers could register a new process in the sandbox through an IOCTL available with
read-only device access. The access mode and the operation's real effect disagreed.

Descartes currently records commands with fields such as `read_only: true` and exposes tools whose
names begin with `collect` or `inspect`. Those are useful assertions, but they must not become the
authorization oracle. A capability manifest should instead declare and enforce at least:

- effect class: observe, store, notify, prepare, authorize, execute;
- resource and target scope;
- host privilege required;
- filesystem and network access;
- data sensitivity and model-disclosure policy;
- resource budget and expected duration;
- whether the request can modify policy, enrollment, routing, or authority.

An operation that changes sandbox membership, installs a rule, changes a gate, or grants a tool is
a mutation even if its transport is a GET request, a read-only file descriptor, or a command named
`inspect`.

### 3. Capture once; validate and use the captured object

The core double-fetch repeatedly read a user-controlled length. Allocation used one value and copy
used another. The patch copied the user data into trusted memory and reused the validated length.

Apply this discipline to:

- model tool arguments;
- per-tick configuration;
- action proposals and approvals;
- executable/helper identity;
- process, socket, container, and service identity;
- policy and capability-token caveats;
- evidence used to authorize a later action.

The current deep-frozen per-tick configuration work and the root helper's pinned `/proc` directory
are good examples. Future execution should bind authorization to a canonical request digest plus
boot identity, process start identity, and the relevant executable or workload identity, then
revalidate immediately before the action.

### 4. A subject must not be able to enroll itself into a stronger trust domain

The attacker used a weaker interface to make its own process eligible for the privileged sandbox
path. Future plugins, agent-authored code, model sessions, and sandboxed workers must never be able
to edit their capability manifest, register additional host bridges, select a stronger execution
backend, or make their own outputs authoritative.

### 5. Similar variants need independent coverage

SAFA found several related bugs caused by repeated parsing and length calculations. Treating one
as representative did not remove the others. Descartes should audit each boundary path, including
`pid`, `port`, and `container` resolution; daemon and interactive collection; Linux and macOS;
success, missing permission, timeout, malformed output, and partial-result behavior.

### 6. Shared channels become the weakest link

The HN discussion correctly centers the practical problem with per-app VMs: useful software needs
data exchange. Clipboard services, password managers, shared directories, sockets, network
proxies, and forwarded agents are capability bridges. They determine the real boundary.

For Descartes, the analogous bridges are evidence input, model output, state access, provider
credentials, host filesystem mounts, the privileged helper protocol, notification channels, and
future action RPC. Each bridge needs a narrow schema, size and time limits, explicit direction, and
independent authorization.

## Trust-Domain Recommendation

| Domain | Boundary | Reason |
|---|---|---|
| L0 deterministic collectors | Separate unprivileged process or tightly constrained in-process code initially; migrate high-risk parsers to a collector worker | Needs host visibility, but should not receive model credentials, mutable policy, or authority |
| L1 rules and known signatures | Pure/declarative code in the daemon; WASM only for reviewed extension code | Deterministic hot path should stay cheap, replayable, and free of ambient I/O |
| L2 model session | Separate unprivileged process with typed broker RPC; model-provider access through a narrow parent/proxy | Logs and tool output are hostile text; compromise must not expose state, credentials, or execution |
| Local state and security transitions | Dedicated service UID / protected Rust service when protected mode is built | Same-UID sandboxing cannot protect files and authorization records from that UID |
| Read-only privileged observation | Existing narrow Rust helper model | Exact argv, minimal environment, syscall allowlist, bounded output, capability drop |
| Future host mutation | Separate per-verb or tightly grouped executor plus deterministic policy gate | A sandbox cannot substitute for authorization, identity binding, preconditions, receipts, and rollback |
| Agent-authored parsers/rules | Capability-limited WASM component | Good fit for pure transforms over supplied snapshots with fuel, memory, deadline, and output bounds |
| Arbitrary native code / artifact detonation | Disposable microVM | A separate kernel materially reduces risk when WASM cannot express the workload |

## A Dedicated Sandbox for Descartes

### Whole-product VM: low value and misleading

A VM sees its guest's kernel, process table, services, mounts, and network namespace. Descartes is
supposed to observe the host. Supplying that visibility through bind mounts, management sockets, a
host agent, forwarded credentials, or a broad RPC turns the host-side bridge into the real trusted
component. Future actions have the same problem: a command executed in the guest does not repair
the host, so a host executor remains necessary.

The result would add another kernel, image lifecycle, VMM, guest agent, update channel, and protocol
without removing the authority plane. It would also make “what machine did this fact describe?”
harder to answer.

### Process sandbox around the model: useful near term

The model session can be isolated from:

- Descartes state directories;
- provider and notification credentials;
- the user's home directory;
- arbitrary child processes;
- Unix sockets and SSH agents;
- unrestricted network egress.

It should receive evidence projections and issue typed observation requests over one local broker
channel. The broker, not the model session, should own host collection and enforce data policy.
Provider API access can be mediated by the parent so the child does not need ambient credentials.

This protects against a defect or compromise in the agent runtime and contains prompt-injection
effects. It does not make model reasoning trustworthy; evidence citation and deterministic policy
remain necessary.

### Collector sandbox: selective value

Collectors need enough host access to do their job, so one universal profile will either be too
weak or break collection. The useful form is a small set of profiles by capability family:

- procfs/process inventory;
- service manager queries;
- bounded log readers;
- network inventory;
- container/VM runtime clients.

Each worker should receive no state-store write access and no model credentials. Network should be
off unless the capability explicitly needs it. Collector failure must produce `unknown` or
`unable`, never a fabricated healthy result or recovery.

On Linux, namespaces, `NO_NEW_PRIVS`, seccomp, Landlock, and cgroups can compose here. A tool such
as bubblewrap is only a policy-construction mechanism; its own documentation correctly says the
arguments determine whether it forms a security boundary. macOS needs a separate platform design
rather than an imitation of the Linux profile.

## WASM Before a MicroVM for Extensibility

The autonomy doctrine says agent-authored models remain declarative in the hot path. Preserve that.
If a reviewed escape hatch becomes necessary, WASM is the next step because it can expose only
typed host functions and supplied evidence snapshots. Do not preopen the home directory, Descartes
state, network, or arbitrary clocks. Apply fuel, epoch/deadline interruption, memory limits, output
limits, module digests, and a versioned host ABI.

Good WASM workloads:

- parse a bounded log or command-output blob;
- transform an evidence envelope;
- evaluate a candidate rule over a supplied fact window;
- extract a signature from a scrubbed artifact;
- replay a proposed detector against stored fixtures.

Poor WASM workloads:

- enumerate the real host directly;
- invoke arbitrary system tools;
- perform privileged collection;
- mutate policy or active state;
- execute remediation.

Wasmtime's security guidance describes WASI filesystem access as capability-based, but the runtime
and its host functions still belong in the trusted computing base. Terminal/control-sequence output
also remains untrusted.

## When a MicroVM Has Real Value

Use a microVM when a feature genuinely needs a guest kernel or arbitrary native execution:

- dynamic analysis of a suspicious binary or package;
- installation and execution of an untrusted package tree;
- running model-generated native code after an explicit operator request;
- a compatibility test that needs a real Linux userland;
- rehearsing the mechanics of a mutating operation against a disposable replica;
- fuzzing native parsers or external tools with hostile input.

Keep these constraints non-negotiable:

- ephemeral disk and fresh guest identity by default;
- no writable host mounts;
- no host SSH agent, cloud credentials, Docker socket, or Descartes state;
- network disabled by default and destination-scoped when enabled;
- fixed CPU, memory, process, time, and output budgets;
- a small, versioned vsock/RPC protocol;
- VMM jailed as a separate unprivileged host process;
- guest output treated as hostile evidence;
- teardown and orphan reconciliation;
- no claim that a guest rehearsal proves a real-host action safe.

A malware-detonation feature would be a separate, opt-in product mode with its own threat model. It
should not share the long-lived Descartes daemon, state, credentials, or notification identity.

## Embeddable VM Options

### smolVM / libkrun

smolVM is relevant because it offers a cross-platform microVM workflow and an embedded Node API.
Its documented defaults include network-off ephemeral execution, and it uses `libkrun` underneath.
It is suitable for a time-boxed adapter spike, not yet for a foundational dependency decision.

The critical integration fact comes from libkrun itself: the guest and VMM are considered one
security context, because the VMM proxies host resources. Its documentation says `virtio-fs` does
not by itself prevent access to other host paths and requires host mount isolation. A Descartes
integration would therefore have to sandbox the VMM process in addition to configuring the guest.

Before adoption, verify:

- the exact pinned libkrun and guest-kernel provenance and update path;
- VMM process separation from the Node/Rust parent;
- Linux namespace/seccomp/Landlock behavior and macOS host restrictions;
- absence of host mounts, agent forwarding, credential inheritance, and default egress;
- signed/reproducible release artifacts and an incident-response/update story;
- crash/orphan cleanup and resource accounting;
- API stability and real-host performance on the supported Linux and macOS matrix.

### Firecracker, Kata, and Apple Containerization

Firecracker has a deliberately small device model and a documented jailer, but it is a Linux/KVM
building block and its production guidance still requires a dedicated UID, namespaces, cgroups,
and trusted paths. Kata is a heavier container-runtime integration that adds a VM boundary and is
mainly relevant if Descartes later targets Kubernetes-native execution.

Apple's Containerization library runs each Linux container in a lightweight VM through
Virtualization.framework, but currently targets Apple silicon and recent macOS releases. It is a
useful platform reference, not a cross-platform answer for Descartes.

The right abstraction is a small internal `ExecutionCell` contract implemented first by a local
process sandbox, later by WASM, and only then by an optional microVM adapter. The contract should
describe inputs, outputs, mounts, network, resources, lifetime, and attested backend properties. It
must not expose a generic VM control API to the model.

## Current Implementation Findings

### Strong patterns to keep

- Exact model-visible tool allowlist with a standing test for missing and unexpected names.
- No general shell tool in triage.
- Bounded schemas for model parameters and bounded subprocess time/output.
- Fixed argv rather than shell strings.
- The root helper's exact command grammar, minimal environment, `NO_NEW_PRIVS`, seccomp allowlist,
  capability drop before output, and all-or-nothing response.
- Echo-back verification of helper output before merging it.
- Pinned `/proc/<pid>` descriptors to close PID-reuse races.
- Honest partial/unknown degradation instead of treating missing visibility as health.
- Current plan to re-resolve targets at execution time.

### Follow-up findings

1. **Critical: the seccomp policy does not confine the full capability blast radius.** The helper
   carries `CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH` and the seccomp allowlist permits unrestricted
   `openat`, `read`, `write`, and `lseek`. Denying `ptrace`, `process_vm_*`, `pidfd_getfd`, and
   `open_by_handle_at` is valuable, but arbitrary code execution inside the helper could still use
   the allowed syscalls and capabilities as a broad file-read oracle, including sensitive
   `/proc/<pid>` files. `lseek` also matters to `/proc/<pid>/mem`. The helper is small Rust with a
   tiny input grammar, so this is residual blast radius rather than evidence of an exploit. The
   comments claiming that everything sharing those capabilities' threat model is unreachable are
   nevertheless too strong. Re-derive the confinement against the real capability grant, add
   negative tests for `/etc/shadow`, `/proc/<victim>/environ`, and `/proc/<victim>/mem`, and choose
   a real filesystem/process-resource confinement or a narrower mechanism. Checking `openat` flags
   and removing unnecessary `lseek` would help but would not by itself remove the read capability.
2. **High: elevated port resolution performs a semantic double-fetch.** The unprivileged Node path
   observes TCP and UDP sockets, selects `matches[0]`, and keeps protocol/address/UID/inode facts.
   It then asks the helper to resolve only a numeric port. The helper independently rereads only
   TCP/TCP6 and returns the first owner it encounters. Echo-back verifies the port and the caller
   cross-checks UID, but it does not bind protocol, address, socket inode, or observation
   generation. Socket handoff, same-port binds, `SO_REUSEPORT`, and TCP/UDP collisions can therefore
   misattribute the original observation while returning confidence `1`. Bind the full socket
   identity or make the helper perform one atomic observation and return ambiguity for multiple
   owners.
3. **High: the documented two opt-ins are consent/configuration gates, not two independent attacker
   boundaries.** A same-UID process can edit `provenance.json`; a process in the dedicated helper
   group can invoke the helper directly. The group/file capability is the OS admission boundary.
   The config switch remains useful product consent, but protected mode needs a separate service
   identity and authenticated typed RPC before it can be called an independent security gate.
4. **High: the tool allowlist binds names, not semantic capabilities or implementation identity.**
   `command: { read_only: true }` and tool names should be generated from a canonical descriptor
   containing implementation/version, effects, privilege, network, sensitivity, and limits. One
   concrete drift already exists: `inspect_runtime_provenance` tells the model it is “Unprivileged
   only,” while its real executor passes `paths` and can use the configured elevated helper.
5. **High: the Node helper trust check is check-then-exec.** `verifyTrustBoundary()` calls `stat()`
   on the helper and ancestors, then `execFile()` resolves the pathname later for both probe and
   invoke. `stat()` also follows a final symlink. Installation verification requires a root-owned,
   non-symlinked chain, which materially lowers the practical risk, but the runtime property is not
   atomic. Before this is relied on as a high-assurance boundary, preserve that root-owned chain and
   use a descriptor/pinned service design (`openat2`/no-symlink resolution plus execution of the
   captured object, or a long-lived root-owned socket-activated helper) instead of path
   re-resolution.
6. **Medium: PID response scope verification does not bind the resolved PID.** For a PID request,
   `parseAndVerifyHelperResponse()` checks `requested.pid` against the request but only checks that
   `resolved.pid` is a positive integer. A buggy or compromised helper could echo the requested PID
   and return another one. The live elevated path currently serves port resolution, but this must be
   closed before PID elevation or a generalized broker uses the contract.
7. **Medium: mechanism normalization can broaden an enabled configuration.** The audit label remains
   `cap_sys_ptrace` although the real grant is the two-capability union. An invalid mechanism string
   with `enabled:true` normalizes to `auto`, which can select a real helper instead of failing to
   `none`. Use a truthful versioned mechanism ID and make invalid enabled configurations inert.
8. **Medium: helper exit code `3` has two meanings.** The production helper uses it for a truncated
   port scan and the hardening module uses it for confinement failure. Node labels every exit `3`
   as `fd_scan_truncated`. Access still fails closed, but diagnosis is corrupted exactly when the
   security boundary fails to initialize.
9. **Medium: the session evidence registry binds derivation to a reusable label, not an immutable
   observation.** `registerEvidence()` stores envelopes in a `Map` by envelope `id`, while many
   collectors use stable IDs such as `system-overview`, `top-processes`, or `recent-logs`. Calling
   the same collector again overwrites the earlier entry. A later `derive_findings` call that cites
   the old textual ID therefore consumes the newest envelope, not necessarily the observation the
   model intended to reference. Store immutable observations by `(tool_call_id, evidence_id)` or a
   content-addressed observation ID, reject collisions, and carry that identity into citations and
   derivation.
10. **Medium: helper output loses the pinned process identity after return.** Pinning the procfs
    directory closes intra-helper PID reuse, but the returned PID/UID/path/command contains no boot
    ID or process start time. It is suitable for immediate display, not later authorization.
11. **Most ordinary collector subprocesses inherit ambient environment and resolve short command
    names via `PATH`.** The privileged helper uses a minimal environment; ordinary collectors do
    not. This is acceptable only under the documented same-UID trust assumption. A protected mode
    should use a centralized runner, minimal environment, and platform-pinned executable
    resolution.
12. **Host command output is hostile input.** Parsers and model-visible projections need uniform
    control-character handling, size bounds, sensitivity labeling, and prompt-injection tests.
13. **Same-UID state remains honestly unprotected.** A process sandbox under the login UID does not
    change that. Protected monitoring needs the separate-service design already captured in the
    state-integrity threat model.

## Test Landscape

The Node CLI has 82 test files and the Rust root helper has three integration-test files, in
addition to module tests. Relevant existing tests cover the model tool allowlist, helper response
scope, environment stripping, trust-path permissions, seccomp enforcement, PID resolution, state
canonicalization, partial-result behavior, and no-fabricated-recovery invariants.

Five boundary tests should be required before a new sandbox or execution backend is considered
usable:

1. **Real-grant helper breakout suite.** While the helper holds its actual capability union, attempt
   `ptrace`, `process_vm_*`, `/proc/<victim>/mem`, `/proc/<victim>/environ`, `/etc/shadow`,
   `open_by_handle_at`, network creation, and `execve`. Every operation outside the intended
   procfs contract must be kernel-denied while the exact supported reads still work.
2. **Socket and target identity race suite.** Rebind or hand off one port across TCP/UDP, addresses,
   `SO_REUSEPORT` owners, same/different UIDs, and process lifetimes between broker observation and
   helper resolution. Also recycle a PID and replace a container or service name. Descartes must
   return the original fully bound identity or `ambiguous/unknown`, never a wrong target at
   confidence `1`.
3. **Admission and semantic-capability suite.** From unrelated same-UID and same-group processes,
   attempt direct helper invocation, config changes, invalid mechanism fallback, RPC replay,
   capability/backend/mount changes, and substitution behind an approved tool name. Product
   consent and protected-mode authorization must behave as separately documented; unknown or
   misleading requests fail closed and leave an audit record.
4. **Hostile worker and evidence suite.** Attempt to read home/state/provider secrets, use Unix
   sockets or the SSH agent, reach the network, invoke an unregistered binary, and emit prompt
   instructions, ANSI/control sequences, oversized output, malformed encodings, forged evidence
   IDs, or repeated-ID overwrites. No capability changes and no secret crosses the boundary.
5. **Resource and failure-containment suite.** Exercise fork/process bombs, memory and CPU
   exhaustion, infinite output, hangs, guest panic, VMM crash, and parent crash. The worker dies,
   Descartes remains responsive, state stays consistent, and coverage becomes unknown rather than
   fabricated healthy/recovered.

MicroVM-specific additions should verify that the VMM remains jailed after guest compromise, a
guest cannot escape a declared host share, egress policy is enforced at the host, snapshots cannot
carry stale authority or credentials, and orphaned VMs are found and destroyed.

## Recommended Sequence and Decision Gates

### Phase 1: capability broker and process separation

- Define one capability/effect registry used by the model tool list, broker, evidence trace, data
  policy, and future authority plane.
- Canonicalize each request once; reject unknown structure; bind it to an immutable request ID.
- Centralize subprocess execution with minimal environment, explicit executable resolution,
  deadlines, output caps, and per-platform manifests.
- Move the model session behind an unprivileged process boundary with one typed broker channel.
- Rework or explicitly narrow the root helper's capability/confinement claim; close the duplicated
  exit code, mechanism-label/fail-closed config, PID-response binding, port-identity transaction,
  and path check/use gaps before expanding that helper.

Gate: prompt-injected or compromised L2 code cannot access state, credentials, a shell, or the
privileged helper, and all requested observations are reconstructible from the audit record.

### Phase 2: protected local mode

- Build the previously designed service-UID / small Rust service boundary for authoritative state
  and security-critical transitions.
- Keep the existing zero-install mode and label it `unprotected_same_uid`.

Gate: a malicious login-UID process cannot rewrite authoritative state or ask the service to sign
or commit arbitrary facts through the typed RPC.

### Phase 3: WASM extension cell

- Add only when a real parser/rule use case exceeds the declarative model IR.
- Start with offline fixture replay, then shadow evaluation; do not grant live host enumeration.

Gate: deterministic resource bounds, no ambient capabilities, content-addressed modules, replayable
results, and measurable benefit over the declarative implementation.

### Phase 4: microVM spike

- Start only for one native-code workload that WASM cannot support.
- Compare a cross-platform libkrun/smolVM adapter with platform-native alternatives.
- Treat the VMM jail and every host bridge as part of the security deliverable.

Gate: the feature's security benefit exceeds its new VMM, guest-kernel, image, update, and bridge
attack surface on the supported platform matrix.

## Non-goals

- Building a custom kernel driver, hypervisor, VMM, or general shell.
- Putting every application on the host in a Descartes-managed VM.
- Treating a container, WASM runtime, or VM as authorization.
- Passing broad host mounts, Docker sockets, SSH agents, or credentials into a worker.
- Claiming that a clean sandbox run proves a real-host action is safe.
- Claiming a sandbox makes evidence trustworthy after root/kernel compromise.
- Turning Descartes into an antivirus or general malware-analysis product in the core path.

## Relevant Files

- `README.md`
- `AGENTS.md`
- `docs/HANDOFF.md`
- `docs/architecture/2026-09-05-purpose-first-design.md`
- `docs/design/autonomy-doctrine.md`
- `docs/design/state-integrity-threat-model.md`
- `docs/plans/2026-07-11-s3-priv-elevated-read-path.md`
- `docs/plans/2026-07-23-slice-7-authority-containment-plane.md`
- `tools/descartes-cli/src/tool-policy.js`
- `tools/descartes-cli/src/pi-harness.js`
- `tools/descartes-cli/src/tools/provenance-elevated.js`
- `tools/descartes-cli/src/tools/provenance.js`
- `crates/descartes-root-helper/src/main.rs`
- `crates/descartes-root-helper/src/hardening.rs`
- `crates/descartes-root-helper/src/proc_linux.rs`
- `crates/descartes-root-helper/src/procfs.rs`

## External References

- [SAFA Part 1: entering the Avast sandbox and reaching the vulnerable
  IOCTL](https://www.safateam.com/intelligence-hub/research/technical-articles/cve-2025-13032-entering-and-breaking-the-avast-antivirus-sandbox-part-1)
- [SAFA Part 2: double-fetch to kernel read/write and SYSTEM token
  theft](https://www.safateam.com/intelligence-hub/research/technical-articles/cve-2025-13032-entering-and-breaking-the-avast-antivirus-sandbox-part-2)
- [HN discussion](https://news.ycombinator.com/item?id=49841115) and the [official HN API
  documentation](https://github.com/HackerNews/API)
- [smolVM README](https://github.com/smol-machines/smolvm/blob/main/README.md) and [embedded SDK
  status](https://github.com/smol-machines/smolvm/blob/main/sdks/README.md)
- [libkrun security model](https://github.com/libkrun/libkrun)
- [Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
  and [production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Kata Containers virtualization architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/virtualization.md)
- [Apple Containerization design](https://github.com/apple/containerization/blob/main/README.md)
- [Wasmtime security guidance](https://docs.wasmtime.dev/security.html)
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [bubblewrap security model](https://github.com/containers/bubblewrap)

## Review Provenance

An independent repo-grounded `gpt-daybreak-blue-latest` review at `xhigh` examined the same
question after the initial research draft. Its direction converged on component isolation now,
declarative models before executable extensions, WASM only for a concrete extension need, and
microVMs only for hostile native code. Its implementation findings were checked against the local
source before being incorporated above. The capability/syscall residual, socket-identity
double-fetch, consent-vs-admission distinction, tool-description drift, PID response mismatch,
mechanism fallback, exit-code collision, and reusable evidence-ID issue were all confirmed in the
current working tree.

## Open Questions

1. Is the first desired sandbox use case isolation of the current model session, execution of
   agent-authored extensions, or future artifact detonation? These require different boundaries.
2. Should protected local mode precede model-process isolation, given that same-UID state is the
   stronger current adversary boundary?
3. Can the Node agent/provider stack be split so provider credentials remain in a narrow parent or
   proxy without making cancellation, streaming, and tool-call auditing fragile?
4. Which collector families can run under useful Linux seccomp/Landlock profiles without hiding
   facts that Descartes promises to observe?
5. What macOS process-sandbox mechanism is supportable without private/deprecated APIs and while
   preserving notarization and distribution?
6. What single native-code workload would justify a microVM spike and provide a measurable go/no-go
   result?
