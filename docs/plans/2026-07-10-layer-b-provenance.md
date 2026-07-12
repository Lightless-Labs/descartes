# Layer B — Provenance / Signature Reflex Layer (Slices S3–S5, + S3-priv)

**Created:** 2026-07-10
**Deepens:** `docs/plans/2026-07-09-self-learning-stratified-monitoring.md` §6 (Witr-Provenance Integration Stance), §8 Slices 3–5
**Origin:** Produced by a Sonnet design+review workflow (ground-pass over two collector/provenance areas → cross-checked against live source → drafted → reviewed by two independent lenses: feasibility/seam-verification and security/doors-and-corners → this pass applies every must-fix from both).
**Reviewed:** 2026-07-10 (via two-lens design review — feasibility/seam-verification + security-privilege/doors-and-corners) — all `mustFix` items from both lenses resolved below; disposition summarized in §0.
**Status:** Refined — ready for S3 pickup. S3-priv is design-complete but implementation-gated (see §0 and §6f).
**Operator decision recorded (2026-07-10):** ship an **opt-in elevated read path** for cross-UID provenance. Explicit opt-in, deny-by-default, **never self-escalating**, degrades to the unprivileged path whenever not installed/authorized. Planned as its own slice, **S3-priv**, sequenced strictly after the unprivileged base collector (S3).
**Reconciles with:** `docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md` (see §7) — that plan owns Layer B provenance/approval **milestone numbering**; this plan sequences and TDD-shapes the same work as roadmap slices S3–S5/S3-priv, superseding none of its milestone content.

---

## 0. Disposition of review findings

Both review lenses returned `mustFix` lists. Every item is resolved in this refined plan; none are declined. Summary:

**Feasibility lens (4 must-fix):**
1. uid→username resolution mechanism was unspecified — **resolved**, §2 now names a fixed-argv `id -un <uid>` call with a fixture test.
2. S4's "no duplicate execFile calls" claim was not achievable given S3's single-target orchestration shape — **resolved**, §2 now specifies a decomposed pure-function export surface, and §4 explicitly budgets the new per-socket I/O that codesign/exe-existence checks introduce rather than claiming it's free.
3. S4's collector-default question was answered inconsistently in two places (body said `false`, open questions re-asked it) — **resolved**, §4 now states one answer (`true`, matching sibling collectors, still safe behind the outer `learned.json` kill switch) and the open question is removed.
4. "codesign -dv reported path drift" is not a real mechanism — **resolved**, §2 now specifies an `fs.stat`/`ENOENT`-while-still-open-per-`lsof` check, matching the real Linux `(deleted)`-suffix signal.

Also folded in as moderate/minor feasibility notes: `spctl --assess` is descoped from S4's fixed-rule warning set for v1 (noisy on unbundled CLI daemons, kept low-confidence/heuristic only, §2/§4); public-bind address-literal matching is pinned against real `ss`/`lsof` fixtures including the bare `*` form (§2 TDD item).

**Security/doors-and-corners lens (7 must-fix), all folded into a redesigned §6:**
1. OS-level audience-scoping added: Linux helper is never world-executable (root:descartes-provenance group, mode 0750); macOS XPC listener enforces a code-signing-requirement (`csreq`) check on the connecting client. §6(d).
2. The §6(b)/§6(c) contradiction (full daemon running as root) is removed. **No mechanism in this plan ever runs the long-running Node daemon as root.** Elevated privilege is confined to the same tiny, fixed-purpose, no-shell helper binary in every mechanism, including the Linux fallback (renamed `root_helper`, on-demand-invoked, never the daemon process) and macOS (helper calls `libproc.h` directly, never shells to `lsof`/`codesign`). §6(c).
3. CAP_SYS_PTRACE's true blast radius (arbitrary ptrace, not just proc-read) is documented, and kernel-enforced hardening (capability drop after open, seccomp-bpf syscall allowlist, `PR_SET_NO_NEW_PRIVS`) is now a requirement on the helper, not just code review. §6(b).
4. Config/`helper_path` ownership+permission verification is now required before any elevated mode trusts it — closes the local-privilege-escalation path. §6(d), TDD item.
5. `mechanism: "auto"` is now scoped to only auto-probe within comparable-blast-radius mechanisms; `root_helper` requires an explicit named opt-in, never an auto fallback target. §3, §6(d).
6. TDD coverage added for untrusted helper responses: bounded/schema-validated stdout, and echo-back scope verification that the response matches the exact pid/port requested before merging any field. §3 TDD items 8–9.
7. An explicit go/no-go checkpoint now gates S3-priv's macOS half on post-S3 real-fixture verification, not sequencing alone. §6(f).

Not declined, but flagged as a scope note (feasibility minor #5): "packaged post-install script" is named as a future install path; only the manual-command install path is implementable today given no packaging pipeline exists in this repo. Documented explicitly in §6(a).

---

## 1. Grounding — what already exists, cited

Verified directly against source at HEAD (not inferred):

- **Envelope contract** (`tools/descartes-cli/src/tools/envelope.js`): `evidenceEnvelope({id, status, source, result, confidence, reviewHint, tool, target})` returns `{id, status, layer:"L0", source, result, confidence, review_hint, trace:{tool, target, latency_ms, ts}}`. `timedEnvelope(fn, envelope)` is the **only** sanctioned wrapper — on any thrown error it fails closed to `status:"unable"`, `confidence:0`, `review_hint:"missing_permission"` and still stamps `latency_ms`. Every provenance record MUST be built through this.
- **`review_hint` enum in live use, exactly:** `"none" | "ambiguous" | "missing_permission"`. No other values exist in `tools/*.js` today. This plan does **not** invent new values in S3–S5 (see §5, decision restated not reopened).
- **Tool-registration seam, exact and atomic** (`tools/descartes-cli/src/tool-policy.js`): `TRIAGE_TOOL_NAMES` is a frozen, 17-entry literal array; `assertSafeTriageToolNames(activeToolNames)` does **exact set-equality** (not subset) and throws `"Unsafe Descartes triage tool surface"` on any unexpected, missing, or forbidden name. `tools/descartes-cli/src/pi-harness.js`'s `createEvidenceTools(paths)` returns the matching `defineTool(...)` array; `createPrivateSession()` calls `assertSafeTriageToolNames(session.getActiveToolNames())` immediately after construction whenever `enableTools` is true. **No existing test cross-checks `pi-harness.js`'s tool names against `tool-policy.js`'s array directly** — only `test/tool-policy.test.js`'s `assert.deepEqual(TRIAGE_TOOL_NAMES, [...])` literal exists. This is a real gap S3 closes.
- **Redaction seam** (`tools/descartes-cli/src/tools/processes.js`): `redactAndBoundProcessArgs(args, {maxLength=240, maxTokenLength=96})` is the **one** cross-file-reused sanitizer (imported verbatim by `containers.js`). Any command/args field provenance.js surfaces MUST import this, not reimplement it.
- **macOS baseline is already ahead of Linux**: `network.js`'s `collectListeningSockets()` on macOS runs unprivileged `lsof -nP -iTCP -sTCP:LISTEN` and `parseMacLsofListeningSockets` already extracts `{protocol, state:"LISTEN", command, pid, local_address, local_port}` for **every** listener regardless of owning UID. On Linux, the same collector runs `ss -H -ltnu` with **no `-p` flag** — zero PID resolution attempted today. The Linux port→PID gap is the substantive greenfield work in S3, not a symmetric two-platform build.
- **Linux unprivileged ceiling, precisely**: `/proc/net/{tcp,tcp6,udp,udp6}` is world-readable and includes a numeric owning-UID column with no privilege required — a real, `confidence:1` partial fact (socket exists, who owns it by UID) is available even when PID resolution fails. PID resolution additionally requires walking `/proc/<pid>/fd/*` and matching `socket:[<inode>]` targets, which is blocked by the kernel for other-UID processes regardless of group membership (procfs entries are owned by the target process's own uid/gid, not an arbitrary reader group) unless the caller is same-UID, root, or holds `CAP_SYS_PTRACE` (subject to Yama `ptrace_scope`). **This rules out "setgid-to-a-reader-group" as a general mechanism** — see §6. **[CORRECTED — see the 2026-07-12 addendum after §6(b): the "holds `CAP_SYS_PTRACE`" clause is kernel-wrong for the `/proc/<pid>/fd` *directory* specifically, which is DAC-gated, not ptrace-gated; `CAP_SYS_PTRACE` alone does not, in fact, unblock the walk this bullet describes. "Root" here also only passes because plain, unrestricted root holds the DAC capabilities too, not because of any ptrace exemption — a bounding-set-restricted root does not get the same pass, which is itself a bug this addendum's finding surfaced (S3-priv Slice 5's systemd `root_helper` fallback).]**
- **Daemon-loop precedent for additive alert sources, already live (S-live-1)**: `daemon.js`'s `runDaemonIteration` calls `evaluateAndPersistAlerts(descartesPaths, {..., extraCandidates: await computeActiveConstraintCandidates(descartesPaths, options)})` (L406–413). `computeActiveConstraintCandidates` (L298–312) is gated by `loadLearnedConfig(descartesPaths).enabled` (cheap short-circuit to `[]` first), then reads active constraints, then evaluates against fact-history, returning already-`sanitizeDiagnostics`-routed candidates. `collectStructuralEvidence(structuralProfile, collectors)` (L192–203) runs `services`/`network`/`scheduled-jobs` as **independently-toggleable** sub-collectors gated by `structuralProfile.collectors.<name>.enabled`, on a slower cadence, with partial-tick results discarded (never partially persisted) on deadline. `defaultDaemonProfile()` sets **all three siblings' `enabled` default to `true`** — confirmed directly in `daemon.js` (this corrects the earlier draft's claim that a `false` default matches "every other learned-artifact gate"; the real deny-by-default gate in this area is the separate outer `learned.json` `{enabled:false}` flag, which already gates the entire structural tick before any sub-collector runs).
- **`extraCandidates` merge is a single array, not additive per-source**: today only `computeActiveConstraintCandidates` feeds it. S4 changes L412 to `extraCandidates: [...await computeActiveConstraintCandidates(...), ...await computeProvenanceWarningCandidates(...)]` — both must land in the same concatenation before the one `applyAlertCandidates` call, per `applyAlertCandidates`'s recovery semantics (any active alert id absent from the current candidate array is marked `recovered`).
- **XDG paths** (`tools/descartes-cli/src/paths.js`): `resolveDescartesPaths()` returns bare `stateDir`/`configDir` (no `descartes/descartes` double-nest). New state joins directly: `stateDir/learned/signatures.json`; config joins `configDir/provenance.json` (new, S3-priv), mirroring `configDir/learned.json`'s `enabled:false`-default pattern.
- **CLI dispatch pattern** (`tools/descartes-cli/src/index.js` L103–139): each top-level command dynamically imports a dedicated module and delegates to a `run<Thing>(paths, args)` export. S5's `descartes provenance snapshot`/`baseline show` follows this exactly, via a **new** `provenance-store.js` (CLI/state surface) kept separate from `tools/provenance.js` (the L0 collector) — mirroring the `constraint-eval.js`/`constraint-miner.js`/`constraint-store.js` split.
- **Test layout**: flat `tools/descartes-cli/test/*.test.js`, one file per module. No `pi-harness.test.js` exists yet — a gap this plan closes (S3 TDD list).
- **Witr plan's Milestone 4** (`docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md` L90–97) names the eventual model tool `inspect_runtime_provenance` and a later CLI `descartes why --pid <pid>` / `--port <port> --json`. This plan adopts `inspect_runtime_provenance` as the **canonical tool name** for S3 (see §7 reconciliation) rather than inventing `collect_provenance`.
- **`getpwuid`/username resolution precedent: none.** A grep for `username`/`getpwuid`/`/etc/passwd`/`dscl`/`getent` across `src/` returns zero hits. `linuxProcessMetadata()` marks `user: "unavailable"` today. S3 must define this mechanism explicitly (§2) rather than leave the schema field unimplemented.

---

## 2. Slice S3 — Unprivileged provenance collector (`inspect_runtime_provenance`)

### Goal

One new on-demand L0 collector, `tools/descartes-cli/src/tools/provenance.js`, doing **target-first** resolution (`pid` | `port` | `container` → one provenance record), a deterministic **source-classification chain**, and **warnings-as-facts** (not yet alerts — S4 turns matching warnings into alert candidates). Unprivileged only. Registered into the model-visible triage surface via the enforced atomic two-file edit.

### Exported function surface (resolves feasibility must-fix #2)

`provenance.js` exports **two layers**, not one monolithic orchestration function, so S4 can reuse classification/warning logic without re-doing target-first I/O:

- **Orchestration (I/O-performing):** `resolveProvenance({pid|port|container})` — the target-first entry point used by the model tool. Performs the platform-specific resolution calls (§ below), builds `ancestry`, and returns one envelope-wrapped record.
- **Pure, exported, no I/O (reusable by S4):**
  - `classifySourceFromAncestry(ancestryChain)` — the deterministic classification chain (§ below), taking an already-resolved ancestry array and returning `{type, name, confidence, review_hint, details}`.
  - `detectWarnings(resolvedRecord, sockets)` — pattern matching over an already-resolved record + socket list, returning `warnings[]`. **This function itself does no I/O**, but two of its inputs (`deleted_exe` status, and — deferred, see below — `spctl` assessment) are themselves the product of per-process I/O performed by the caller. S4 is explicitly told which inputs are "free" (already computed once per structural tick's ancestry walk) versus "new I/O" (§4).

### Data shape

```
{
  target: { kind: "pid" | "port" | "container", value },
  resolved: {
    status: "ok" | "partial" | "unknown",
    pid, ppid,
    executable_path, executable_path_unavailable: bool,
    deleted_exe: true | false | "unknown",
    command, args_redaction,            // via redactAndBoundProcessArgs (processes.js), reused verbatim
    user: { uid, username, username_unavailable: bool },
    start_time, start_time_unavailable: bool,
    codesign: { status: "ok"|"unable"|"unsupported", identity, signed, notarized, unavailable_reason },  // macOS only
  },
  ancestry: [ { pid, ppid, command_snippet, args_redaction }, ... ],   // bounded depth, reuses buildParentTreeResult shape
  source: {
    type: "launchd" | "systemd" | "cron" | "shell" | "ssh" | "supervisor" | "container" | "init" | "unknown",
    name, confidence, review_hint, details,
  },
  sockets: [ { protocol, local_address, local_port, state, public_bind: bool } ],
  warnings: [ { rule_id, message, severity, confidence } ],   // facts only here; S4 turns these into alert candidates
  privilege: { mechanism: "unprivileged", elevated_available: bool, elevated_used: false },  // S3-priv extends this
}
```

Envelope: `id: "provenance-<kind>-<value>"` (e.g. `provenance-pid-4821`, `provenance-port-5432`), `source: "provenance"`, `tool: "inspect_runtime_provenance"`, `target: "kind=<kind>,value=<value>"` (matching `network.js`'s `target` string convention).

**Confidence/review_hint policy (no new enum values):** `confidence` is per-envelope aggregate: `1` when `resolved.status==="ok"` and `source.type!=="unknown"`; `0.4` when `resolved.status==="partial"` (extends `inspectProcessEvidence`'s `1 : 0.4` split, not reused verbatim since 0.4 was process.js-specific); `0` when cross-UID/unresolvable. `review_hint` stays inside `{none, ambiguous, missing_permission}`.

### Resolution mechanics per platform

- **pid target:** reuse the existing `linuxProcessMetadata(pid)`-style per-field try/catch pattern (`processes.js`) for `executable_path`/`uid`.
  - **`deleted_exe` detection (corrects feasibility must-fix #4 — "codesign -dv reported path drift" is not a real capability):**
    - Linux: readlink `/proc/<pid>/exe`; a target string containing the literal `(deleted)` suffix is the kernel's own signal — `deleted_exe:true`, `confidence:1` on this sub-field, no heuristic needed.
    - macOS: no equivalent kernel-provided suffix. Get the exe path from `lsof`'s reported path for the still-open FD; `fs.stat()`/`fs.access()` that literal path. If it `ENOENT`s **while `lsof` still lists the process as holding an open executable-text FD to it**, that mismatch (path gone, FD still open, process still running) is the actual "deleted but running" signal — mirrors the Linux suffix mechanically instead of inventing a codesign-path-diff that doesn't exist. Flagged `deleted_exe:true` at reduced confidence (`0.7`) since it's inferred, not kernel-asserted; `deleted_exe:"unknown"` if either half of the check itself fails.
  - **`user.username` resolution (resolves feasibility must-fix #1 — previously an unimplemented schema field):** fixed-argv `execFile("id", ["-un", String(uid)], {timeout, maxBuffer})` — portable across macOS and Linux (`id -un` is POSIX-present on both; no `getent`/`dscl` platform branching needed for the common case). On non-zero exit, timeout, or unexpected stdout shape (not a single bare username token), `username_unavailable:true`, `username:undefined` — never a guessed name. `uid` itself remains a plain numeric fact regardless (already available from `/proc` or `ps`, no extra call).
  - **`codesign`/`spctl` (macOS only):** `codesign -dv <path>` (fixed-argv, read-only signature/identity check) is a primary signal. `spctl --assess -t execute <path>` is **retained in the schema but excluded from S4's fixed alert-rule inputs for v1** (see §4) — it is tuned for Gatekeeper's quarantine/execute policy and is known to false-positive on legitimate, non-bundled, never-quarantined CLI/daemon binaries (Homebrew-installed postgres/nginx/java, etc.), exactly the class of long-running server process this collector cares about most. It is surfaced in `resolved.codesign` at low confidence / `review_hint:"ambiguous"` for operator inspection via the tool call, but S4 does not wire it into a fixed rule until validated against real daemon fixtures (open item, not blocking S3/S4 v1).
- **port target:**
  - macOS: fixed-argv `lsof -nP -iTCP:<port> -sTCP:LISTEN` (bounded to the one port), parse with a `parseMacLsofListeningSockets`-shaped regex → pid, then delegate to pid-target resolution.
  - Linux (greenfield): parse `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` for the matching local port (hex-encoded), extract the socket inode and the world-readable owning-UID column (`confidence:1` fact even if PID resolution later fails), then walk `/proc/<pid>/fd/*` for **own-UID processes only**, `readlink`ing for `socket:[<inode>]`. Other-UID sockets return the owning UID as a confident fact and `resolved.status:"partial"`/`pid:undefined`/`review_hint:"missing_permission"` — never a guessed PID.
- **container target:** fixed-argv `docker inspect -f '{{.State.Pid}}' <id>` / `podman inspect ...` (mirrors `containers.js`'s per-runtime independent-degrade pattern) to get the container's top PID, then delegate to pid-target resolution, tagging `source.type:"container"` and `source.details.runtime`.
- **Source classification chain** (deterministic, no learning; lives in `classifySourceFromAncestry`): walk `ancestry`; ppid==1 + pid-1 comm (`launchd` on macOS / `systemd` on Linux) → `launchd`/`systemd`; ancestor comm in a fixed known-binary list (`cron`,`crond`,`atd`) → `cron`; ancestor comm `sshd` → `ssh`; immediate parent comm in a fixed shell list (`bash`,`zsh`,`sh`,`fish`) → `shell`; ancestor comm in a fixed supervisor list (`supervisord`,`runit`,`s6-svscan`,`pm2`,`forever`) → `supervisor`; ancestor comm in (`containerd-shim`,`dockerd`,`runc`,`podman`) → `container`; `ppid===0 || pid===1` → `init`; else → `unknown` (`confidence:0`, `review_hint:"ambiguous"`).
- **Warnings (facts, not alerts yet; lives in `detectWarnings`):** `public_bind_no_supervisor` (socket bound to a public-bind address literal AND `source.type` not in a recognized-supervisor set — **address-literal set pinned against real fixtures, not assumed**: `0.0.0.0`, `[::]`, and the bare `*` form some `ss`/kernel/flag combinations emit for an all-zero IPv4 bind, per real fixture capture on both platforms before the rule ships), `deleted_exe_running`, `unexpected_parent` (source type `unknown` with a non-trivial ancestry depth).

### Registration (atomic two-file edit, enforced)

1. `tools/descartes-cli/src/tool-policy.js`: append `"inspect_runtime_provenance"` to `TRIAGE_TOOL_NAMES` (after `"inspect_parent_tree"`, before `"sample_dimension"`).
2. `tools/descartes-cli/src/pi-harness.js`: add a matching `defineTool({name:"inspect_runtime_provenance", ..., parameters: Type.Object({ pid: Type.Optional(Type.Number({minimum:1})), port: Type.Optional(Type.Number({minimum:1, maximum:65535})), container: Type.Optional(Type.String()) }), executionMode:"parallel", execute: async (_id, params) => jsonToolResult(await resolveProvenance({...})) })` entry; validate exactly one of `pid`/`port`/`container` is set (reject/`status:"unknown"` otherwise, never guess which target was meant).
3. Extend `triageSystemPrompt()`'s numbered "Preferred flow" — step 3 currently says "call `inspect_process` and/or `inspect_parent_tree` ... before making claims about provenance"; extend it to also mention `inspect_runtime_provenance` for port/container-shaped "why is this running / who owns this port" complaints.
4. `docs/reference/collectors.md`: new row in the "Model-visible tools" table + a `### inspect_runtime_provenance` prose subsection (Sources / Behavior / Privacy).

### TDD test list (`tools/descartes-cli/test/provenance.test.js`, new)

1. Pure parser fixtures: Linux `/proc/net/tcp` line → `{local_port, uid, inode}`; a synthetic `/proc/<pid>/fd` inode map → resolved pid (own-UID case).
2. Cross-UID Linux case: fixture where the fd-walk would `EACCES` → asserts `resolved.status:"partial"`, `pid:undefined`, owning UID still present, `confidence:0` on the pid sub-field, envelope `review_hint:"missing_permission"` — **never a fabricated pid**.
3. macOS `lsof -iTCP:<port>` fixture parsing → pid + command.
4. Source classification fixtures, table-driven, one per branch (`launchd`, `systemd`, `cron`, `shell`, `ssh`, `supervisor`, `container`, `init`, `unknown`) exercised directly against the **pure** `classifySourceFromAncestry` export (no I/O mocking needed).
5. Warning fixtures against the **pure** `detectWarnings` export: deleted-exe running, public bind with no supervisor (including the bare `*` address-literal case), unexpected parent — each asserts the exact `rule_id`; assert zero interaction with `alert-store.js` (S3 has zero import of it).
6. `deleted_exe` mechanism fixtures per-platform: Linux `(deleted)`-suffix readlink fixture; macOS `lsof`-still-open + `fs.stat` `ENOENT` fixture, asserting the reduced (`0.7`) confidence.
7. `username` resolution fixtures: successful `id -un` parse; non-zero exit / timeout / malformed stdout → `username_unavailable:true`, no guessed value.
8. Redaction reuse: assert any `command`/`args` field in the result equals `redactAndBoundProcessArgs`'s output shape exactly (spy/import check, not reimplementation).
9. `timedEnvelope` fail-closed: force a thrown error mid-collection (e.g. malformed `/proc/net/tcp`) → assert `status:"unable"`, `confidence:0`, `review_hint:"missing_permission"`, `latency_ms` still stamped.
10. Ambiguous-target guard: both `pid` and `port` supplied, or none supplied → deterministic rejection, not silent pick.
11. `test/tool-policy.test.js`: update the literal `TRIAGE_TOOL_NAMES` array (18 entries) in the same commit.
12. **New** `test/pi-harness.test.js`: imports `createEvidenceTools` from `pi-harness.js` and `TRIAGE_TOOL_NAMES` from `tool-policy.js`; asserts `createEvidenceTools(paths).map(t => t.name).sort()` deep-equals `[...TRIAGE_TOOL_NAMES].sort()` — the "session-construction test," no live model credentials required.
13. `docs/reference/collectors.md` diff reviewed as part of the same PR (checklist item, not a test).

### Acceptance criteria

- All of the above tests pass; `npm test` stays green (393+ passing).
- `inspect_runtime_provenance` resolves same-UID pid/port/container targets on macOS Apple Silicon and Linux x86_64 with real fixtures (not just synthetic parsing tests) for at least one clean case per platform.
- Cross-UID Linux and any macOS resolution failure degrade to `unable`/`confidence:0`/`missing_permission` — grep-verified: zero code path returns a non-`unknown`/non-degraded pid/executable/source without having actually resolved it.
- No `shell:true` anywhere in the new file; every `execFile` call has a literal argv array, a `timeout`, and a `maxBuffer`.
- Session construction (`createPrivateSession`) still succeeds after registration — verified by `pi-harness.test.js`.
- `docs/reference/collectors.md` updated per its own checklist.

### Safety notes

- Read-only: no mutation anywhere (no `kill`, no `docker stop`, no file writes outside the collector's own bounded output).
- Fixed-argv only; no interpolated shell strings, no `container`/`port` value ever concatenated into a shell command string.
- `codesign`/`spctl`/`id` calls are read-only assessment commands, never mutating.

---

## 3. Slice S3-priv — Opt-in elevated read path

See §6 (Doors-and-Corners) for the full privilege analysis. Summary below; §6 is authoritative and has been substantially redesigned from the earlier draft to close every security must-fix.

### Goal

Extend cross-UID port→process resolution (the Linux gap, and the narrower — pending §6(f) verification — macOS gap) via an **explicitly operator-installed**, deny-by-default, never-self-escalating elevated read mechanism, with elevated privilege **confined to a tiny fixed-purpose helper** — never the daemon process itself — and OS-level audience-scoping so the capability isn't ambiently available to every other local process once installed. Ships strictly after S3.

### Data shape

Extends S3's `privilege` field: `{ mechanism: "unprivileged" | "elevated:cap_sys_ptrace" | "elevated:root_helper" | "elevated:helper_xpc", elevated_available: bool, elevated_used: bool, elevated_config_enabled: bool }`. When `elevated_used:true`, the fact fields resolved via the elevated path are otherwise **identical in shape** to the unprivileged case — attribution lives only in `privilege`, not a parallel schema.

New config: `configDir/provenance.json` — `{ elevated: { enabled: false, mechanism: "auto" | "cap_sys_ptrace" | "root_helper" | "helper_xpc" | "none", helper_path: <optional override> } }`, loaded via `loadProvenanceConfig(descartesPaths)` mirroring `loadLearnedConfig`'s `enabled:false`-default pattern.

**`mechanism: "auto"` is scoped, not open-ended (resolves security must-fix #5):** `auto` only probes among mechanisms of **comparable blast radius** to a scoped read-only helper — `cap_sys_ptrace` on Linux, `helper_xpc` on macOS. It **never** auto-selects `root_helper`; that mechanism requires the operator to name it explicitly in config, because it represents a materially larger privilege footprint (root, even if confined to the tiny helper process) than the capability-scoped alternative. The resolved mechanism is surfaced prominently at daemon startup (log line) and in every provenance envelope's `privilege.mechanism` field.

### Seam/approach validated against the maps

- The daemon/collector **only probes** whether the elevated mechanism is present and config-enabled (`execFile` the helper with a harmless `--version`/probe subcommand, catch `ENOENT`/`EPERM`, cache the probe result per process lifetime); it **never** invokes `setcap`, `sudo`, or an admin-prompt API at runtime. Privilege is granted once, out-of-band, at install time — this is the literal enforcement of "never self-escalating," verified structurally (grep for `sudo`/`setcap`/`osascript.*administrator` returning zero hits in the diff, part of the PR checklist), not just by convention.
- Helper is a **tiny, fixed-purpose, no-shell binary** with a fixed-argv contract (`--resolve-port <n>` / `--resolve-pid <n>`, JSON stdout, bounded), recommended in Rust per the company stack preference. **The same helper binary is used in every elevated mechanism, including `root_helper`** (see §6(c)) — there is no design in this plan where the long-running Node daemon itself acquires elevated privilege.
- Both the OS-level grant (helper present + capability/root/XPC authorized) **and** the Descartes config opt-in (`configDir/provenance.json` `elevated.enabled:true`) must independently be true before the elevated path is used; either being false/absent degrades silently to the S3 unprivileged path with `review_hint:"missing_permission"` — never an error, never a crash.
- **Config/helper_path trust boundary (resolves security must-fix #4):** before honoring any `helper_path` override (or the default helper path) in an elevated mode, the daemon verifies the resolved config file, its parent directory, and the helper binary itself are owned by the principal running the elevated daemon (or root, for `root_helper` mode) and are not group/world-writable — mirroring the SSH `authorized_keys`/host-key permission-check discipline. A failed check degrades to unprivileged and logs a operator-visible warning; it never executes an unverified path.

### TDD test list

1. Probe logic: helper absent (`ENOENT`) → `elevated_available:false`, falls through to unprivileged path, no throw.
2. Config disabled (`elevated.enabled:false`) but helper present → still falls through to unprivileged path (config wins over availability — opt-in is a two-key AND, test both keys independently).
3. Config enabled + helper present + probe succeeds → `elevated_used:true`, result shape identical to unprivileged case plus `privilege.mechanism` populated.
4. Fixed-argv assertion: spy on `execFile` call to the helper, assert argv is a literal bounded array, never a template string.
5. Helper probe timeout → degrades to unprivileged, does not hang the collector.
6. Regression: with `elevated.enabled:false` (the shipped default), S3's existing test suite output is byte-identical.
7. Doors-and-corners fixture (Linux): a probe asserting the actual `ptrace_scope` value on the real CI/dev host before assuming `CAP_SYS_PTRACE` will work there — a diagnostic, not a hard-fail, since this varies per host.
8. **New — untrusted-response handling (resolves security must-fix #6):** helper returns malformed JSON, or JSON exceeding a bounded `maxBuffer` → degrades to `unable`/`confidence:0`/`missing_permission`, never a partial-parse merge.
9. **New — response-scope verification (resolves security must-fix #6):** helper returns a well-formed record for a **different** pid/port than the one requested (simulated race/bug/compromise) → the mismatch is detected before merge (echo-back check: response must include and match the requested target) and the call degrades to `unable`, the mismatched fact is never merged into the provenance record.
10. **New — config/helper_path trust boundary (resolves security must-fix #4):** `helper_path` pointing at a group/world-writable file, or a config file in a group/world-writable directory, is rejected — degrades to unprivileged, does not execute the path, logs a warning.
11. **New — mechanism scoping (resolves security must-fix #5):** `mechanism:"auto"` with only `root_helper` available (capability-scoped mechanisms absent) does **not** silently use `root_helper` — stays on the unprivileged path unless `root_helper` is named explicitly.

### Acceptance criteria

- Default install (no config, no helper): behavior is **byte-identical** to pre-S3-priv S3.
- No code path in the daemon or `provenance.js` ever shells to `sudo`, calls `setcap`, or invokes an OS admin-prompt API.
- No code path in this plan runs the long-running Node daemon process itself with elevated privilege — elevated privilege is confined to the tiny helper binary in every mechanism.
- Elevated attribution is visible in every envelope that used it (`privilege.mechanism` populated, never silently blended into unprivileged-looking output).
- Helper binary has no shell interpretation anywhere, a fixed minimal argv surface, is not world-executable/world-connectable at the OS level (§6(d)), and drops unneeded capabilities / applies a seccomp allowlist after opening its needed resources (§6(b)) — audited as such in the PR description. (Capability-drop/seccomp unit tests live in the helper binary's own test suite, not the Node `npm test` suite — noted explicitly so this isn't silently skipped.)
- Install-time privilege grant is documented (README/HANDOFF) as an explicit manual step (packaged post-install is a documented future option, not assumed available — see §6(a)).
- macOS elevated-helper implementation does not begin until the §6(f) go/no-go checkpoint has run.

### Safety notes

This is the highest-risk slice in Layer B. Treat as its own reviewed unit; invoke `doors-and-corners` again at actual implementation time (not just at this planning pass), and again specifically before the macOS helper per §6(f).

---

## 4. Slice S4 — Immediate provenance-warning fixed rules (zero learning)

### Goal

Turn S3's `warnings[]` facts (deleted-exe running, public bind with no recognized supervisor) into sanitized alert candidates through the **already-live** `extraCandidates` merge (S-live-1), on the **existing structural daemon cadence** — no new daemon coupling, no learning, no LLM.

### Seam/approach validated against the maps

`collectStructuralEvidence(structuralProfile, collectors)` (`daemon.js` L192–203) already runs `services`/`network`/`scheduled-jobs` as independently-toggleable sub-collectors on a slower cadence, with partial-tick results discarded on deadline. Add a **fourth** structural sub-collector, `provenance: collectors.provenance ?? collectProvenanceWarningsEvidence`, gated the same way (`structuralProfile.collectors.provenance.enabled`).

**Default resolved, not left open (resolves feasibility must-fix #3):** default `structuralProfile.collectors.provenance.enabled` to **`true`**, matching its literal siblings (`services`, `network`, `scheduled-jobs` all default `true` in `defaultDaemonProfile()`). This is still safe and byte-identical to today's behavior for any operator who hasn't opted into learned features at all, because the **outer** `learned.json` `{enabled:false}` kill switch already gates the entire structural tick before any sub-collector — including this one — runs. The earlier draft's claim that per-sub-collector `false` "matches the deny-by-default ethos of every other learned-artifact gate" was checked against `defaultDaemonProfile()` and found incorrect; the real deny-by-default gate in this area is the outer flag, not the per-collector one. No open question remains on this point.

**What is actually reused vs. new I/O (resolves feasibility must-fix #2 — the earlier "no duplicate execFile calls" claim was not fully achievable):**
- **Free reuse:** `classifySourceFromAncestry` is pure and reusable per-socket against ancestry data already resolved once per structural tick's process walk — no duplicate `execFile` calls for source classification.
- **New I/O, explicitly budgeted, not free:** the Linux `(deleted)`-suffix check is a cheap `readlink` per candidate process (negligible cost, fine to run per listener). The macOS `fs.stat`-after-`lsof` deleted-exe check and any `codesign` call **are** new per-process I/O in the structural tick, not reuse of anything S3 already computed for that tick. To bound this cost, S4 runs the macOS deleted-exe/codesign checks **only for sockets that are already public-bind warning candidates** (i.e., after the cheap address-literal + supervisor-classification filter has already narrowed the set), not for every listener on every tick. This is stated explicitly here so the "no duplicate calls" framing in the earlier draft is corrected rather than silently carried forward.
- `spctl --assess` is **excluded from S4's fixed rule inputs for v1** per §2's noise concern; only `codesign -dv` identity/validity feeds any fixed rule, and only at the bounded, narrowed set described above.

**Addendum (2026-07-10, as shipped):** S4 as implemented needs **neither** `codesign` **nor** `spctl` for its two `rule_id`s — the deleted-exe check is `readlink`/`fs.stat`-only (via S3's `resolveExecutableInfo`) and the public-bind check is address-literal + source-classification only. So the shipped structural sub-collector calls strictly *less* per-tick I/O than this section budgets for; `codesign` remains available in S3 for on-demand triage but is not on any S4 fixed-rule path. Additionally, the emitted executable path is **sha256-hashed (16 hex) before it ever reaches a warning entry, fact point, or candidate** — no raw path is persisted or surfaced.

Add `computeProvenanceWarningCandidates(descartesPaths, options)`, structurally mirroring `computeActiveConstraintCandidates` (same `loadLearnedConfig(...).enabled` short-circuit-to-`[]` first). Wire into `runDaemonIteration`'s existing `extraCandidates` array: `extraCandidates: [...await computeActiveConstraintCandidates(descartesPaths, options), ...await computeProvenanceWarningCandidates(descartesPaths, options)]` — **both sources land in the same concatenation in the same commit**.

Candidates route through the existing `sanitizeDiagnostics()` gate — no raw paths/usernames/command lines in `diagnostics`, only numeric/closed-enum/fixed-length-hash fields.

`rule_id`s: `provenance.process.deleted_exe_running`, `provenance.socket.public_bind_no_supervisor`.

### Explicit scope decision

This slice reuses the **existing** structural-tick cadence and gating; it does **not** introduce a new sampling cadence or scheduling primitive. If the structural tick's interval proves too coarse for provenance warnings specifically, that is deferred to the roadmap's own Slice 6a (multi-cadence scheduling) rather than solved ad hoc here.

### TDD test list

1. `computeProvenanceWarningCandidates` unit tests: outer `learned.json` disabled → `[]`, no I/O attempted (spy-verified, mirrors constraint-eval's own short-circuit test).
2. Fixture-driven: given a structural `network` evidence envelope with one deleted-exe-owning listener → exactly one `provenance.process.deleted_exe_running` candidate, correctly shaped diagnostics.
3. `sanitizeDiagnostics()` rejection test: a hand-crafted candidate with a raw path in `diagnostics` fails the build (extends the existing `diagnostics-sanitizer.test.js` pattern).
4. **Regression, mandatory per roadmap precedent:** fixed-rule alert behavior (existing resource-pressure rules) stays byte-identical before/after this merge-point change.
5. **Simultaneous-active test:** a constraint alert, a provenance-warning alert, and a plain fixed-rule alert can all be active in the same tick without any one recovering another (extends S2's own cross-recovery regression test to a third source).
6. Structural-tick timeout: partial provenance results are discarded, not partially persisted, matching the existing `STRUCTURAL_TICK_TIMED_OUT` discard discipline.
7. Bounded-I/O test: assert the macOS `fs.stat`/`codesign` deleted-exe check runs **only** for sockets already narrowed to public-bind-warning candidates in a fixture with N listeners and 1 candidate — not N `execFile`/`stat` calls.
8. Sibling-default consistency test: `defaultDaemonProfile()`'s `provenance.enabled` is `true`, matching `services`/`network`/`scheduled-jobs`; outer `learned.json enabled:false` still yields byte-identical daemon output to pre-S4 (covers the resolved default decision above).

### Acceptance criteria

- Both `rule_id` families fire correctly against real/fixture data, are sanitized, and appear in `descartes alerts list` with no code changes to `alerts.js`/`notification-delivery.js`.
- No daemon-loop coupling beyond the existing structural-tick seam.
- Per-tick provenance-warning I/O is bounded (narrowed-candidate-only, not every listener) — verified by test 7 above.
- Feature is gated end-to-end by the outer `learned.json enabled:false` default; enabling learned features at all is the single explicit action that turns this on, matching its siblings exactly.

### Safety notes

Deterministic only — no LLM involvement anywhere in this slice. Any given warning fires the same candidate every time given the same facts (pure function, testable without a model).

**Recovery/staleness note (as shipped):** `public_bind_no_supervisor` facts refresh (explicit `active` true/false) for every checked socket each structural tick, so they self-heal on the next tick. `deleted_exe_running` facts are only re-emitted for the *narrowed* candidate set that tick (per the bounded-I/O directive), so if a pid silently leaves the narrowed set while still flagged, its last `active:"true"` fact goes stale rather than explicitly clearing — bounded by `DEFAULT_PROVENANCE_FACT_WINDOW_MS` (3h) read window, after which the candidate stops being produced and `applyAlertCandidates` recovers the alert. Worst case is a stale-but-self-clearing alert lingering ≤3h past the real condition ending; never permanently stuck.

---

## 5. Slice S5 — Identity baseline + deterministic deviation warnings

### Goal

An `identity_signature` per process/port identity, hashing inputs **pinned with fixtures before any behavior is written**, a `provisional → known_good` state machine with a grace window (no day-1 alert storm), and three new deterministic candidate types, UID-scoped per S3/S3-priv.

### Data shape

`stateDir/learned/signatures.json`:

```
{
  version: 1,
  signatures: {
    "<identity_signature_hash>": {
      kind: "signature", family: "identity",
      state: "provisional" | "known_good" | "retired",
      first_seen, last_seen,
      stable_sample_count, stable_iteration_count,
      inputs_hash: { executable_path_hash, identity_hash /* codesign identity or exe content hash */, source_classification, owning_user_hash },
      target_examples: [ { kind, value } ],   // bounded list, for operator introspection only
    }
  }
}
```

`identity_signature = sha256(executable_path, exe_hash|codesign_identity, source_classification, owning_user)`, truncated to a fixed length (consistent with `sanitizeDiagnostics`'s fixed-length-hash rule). Raw fields (`executable_path`, `owning_user`) are stored **hashed** in `signatures.json` too — not just at emission — since this is the one provenance store a future operator CLI (`descartes provenance baseline show`) could read, and its hashing/redaction discipline should not depend on which surface reads it.

New CLI, `tools/descartes-cli/src/provenance-store.js`, dispatched from `index.js` exactly like `alerts`/`learned`:

- `descartes provenance snapshot` — bootstrap: seed `known_good` directly from currently-observed identities (an explicit, operator-invoked action, analogous to the constraint layer's shadow-soak bootstrap — never automatic).
- `descartes provenance baseline show [--identity <hash>]`.

New candidates (routed through the same S4 seam, added to the same `extraCandidates` concatenation): `provenance.process.unknown_identity`, `provenance.process.identity_drift`, `provenance.port.new_public_bind` — all UID-scoped (only emitted for identities the daemon's own UID could resolve, or that S3-priv resolved and clearly attributed).

**`diagnostics.review_hint` for these candidates is deliberately left unset** (or `"none"`) — the roadmap's forward-looking `"novel_pattern"` L2-narrowing value is explicitly out of scope for Layer B (no L2 wiring happens in S3–S5), and inventing a value prematurely would create an unused enum member. Decision restated here, not reopened.

### Seam/approach validated against the maps

Grace window: `provisional → known_good` requires `stable_sample_count ≥ 3` **and** observations spanning `stable_iteration_count ≥ 2` distinct structural ticks (not just repeated observations within one tick) — mirrors the constraint layer's own multi-sample-across-iterations promotion discipline. No `unknown_identity`/`identity_drift`/`new_public_bind` candidate fires for any identity still `provisional`, and none fire at all until `descartes provenance snapshot` has been run at least once (day-1 no-storm guarantee, explicit and testable).

### TDD test list (fixtures-first, hashing inputs pinned before hashing code is written)

1. **Golden fixture test, written first, before `identity_signature` is implemented:** a fixed input tuple → an exact expected hash string, checked into the test file.
2. Hash stability: same inputs across two calls → identical hash; one differing input (e.g. `owning_user`) → different hash.
3. `provisional → known_good` promotion: exactly `stable_sample_count-1` samples across `stable_iteration_count` ticks → still `provisional`; one more sample → `known_good`. Table-driven boundary test.
4. Day-1 no-storm: fresh `signatures.json` (no prior snapshot) + a batch of currently-running processes → zero `unknown_identity` candidates fire, regardless of how many distinct identities are present.
5. `unknown_identity` fires only after at least one `descartes provenance snapshot` has established a `known_good` baseline and a **new**, never-seen identity appears.
6. `identity_drift` fires when a previously `known_good` identity's hash changes for the same target (e.g. executable replaced) — fixture asserts the exact fired `rule_id` and its sanitized diagnostics shape.
7. `new_public_bind` UID-scoping: fires only for own-UID (or S3-priv-attributed) sockets; other-UID unresolvable sockets never fire this candidate (asserts silence, not a degraded-confidence version of the candidate).
8. `provenance-store.js` CLI tests: `snapshot` populates `known_good` entries idempotently (running it twice doesn't duplicate/reset state); `baseline show` output is bounded and redacted for human consumption.
9. Atomic-write + corrupt-file tolerance for `signatures.json`, mirroring `history-store.js`'s existing pattern (tmp+rename, `0o600`).
10. `sanitizeDiagnostics()` rejection test extended to these three new `rule_id`s.

### Acceptance criteria

- Hashing inputs and the golden fixture are agreed and merged **before** any promotion-state-machine code lands (enforced by commit order, not just review).
- Day-1 no-storm test passes on a fresh state directory.
- `descartes provenance snapshot`/`baseline show` work end-to-end against real fixture data on both tier-1 platforms.
- No new `review_hint` enum values introduced.

### Safety notes

Deterministic set/pattern matching only — this slice adds zero statistical inference (that's Layer C, out of scope). `identity_drift` on a legitimate software update is an expected, bounded false-positive class; documented as such (operator can `descartes provenance snapshot` again to re-baseline), not treated as a defect to eliminate in this slice.

**Addendum (2026-07-10, as shipped — identity_drift fidelity gap, fail-safe):** `identity_hash` (the codesign/content-hash component) is **absent in this build** — computing it would be unbounded per-process I/O (a `codesign -dv` or full binary hash per observed process each reconciliation), exactly what S4's own addendum excluded from fixed-rule paths. So the `identity_signature` is derived from `executable_path + source_classification + owning_user` only. Consequence: `identity_drift` detects a target whose **launcher (source_classification) or owner changed**, but does **NOT** detect an in-place binary **swap** at the same path/launcher/owner (the signature is unchanged) — a **false-negative only** gap (never a false alarm, crash, or fabricated fact). Drift also is not instantaneous: for the natural (non-snapshot) case the replacement identity must itself cross the grace window before drift fires. Interim mitigation: S4's `deleted_exe_running` rule already catches the common "FD still open to a deleted inode" swap. **Tracked fast-follow (S5-follow-1):** wire `identity_hash` via a bounded `codesign`/content check on the narrowed candidate set (S4-style), pinned against real fixtures.

---

## 6. Doors-and-corners — the elevated read path (S3-priv), redesigned

### (a) Install-time privilege source

The elevated capability is granted **once, out-of-band, at install time**. **Currently implementable today: a documented manual operator command only** (`setcap cap_sys_ptrace=ep <path-to-helper>` on Linux, or installing a signed helper on macOS). A package/Homebrew post-install script running as root is named as a **future** option, not treated as available infrastructure — a repo-wide search found no packaging pipeline, Homebrew formula, or postinstall script anywhere in this codebase today (resolves feasibility minor #5 / scope-guardian minor); it would require its own prerequisite packaging-infrastructure slice before it could be relied on.

**The Descartes daemon process itself, at any point in its runtime lifecycle, never invokes `sudo`, `setcap`, `osascript` with administrator privileges, or any other escalation call.** It only ever *probes* — attempts a bounded, fixed-argv call to the helper, catches `ENOENT`/`EPERM`, and degrades. This is checked in the TDD list (§3) by asserting no such call exists anywhere in the diff, not just by convention.

### (b) Minimal attack surface, including the true blast radius (redesigned per security must-fix #3)

The elevated capability, once granted (a file capability or root privilege), applies to the **entire process for its whole lifetime** once exec'd — so it must never be granted to the Node interpreter or the daemon's full dependency tree. It must be a **tiny, fixed-purpose, no-shell, fixed-argument binary** (recommend Rust, per the company stack preference) whose only job is "map one port or pid to an owning pid/uid/executable path," with a literal bounded argv contract (`--resolve-port <n>` / `--resolve-pid <n>`), JSON stdout, and nothing else — no config file parsing, no network access, no dynamic argument construction.

**`CAP_SYS_PTRACE`'s advertised command surface is not its actual blast radius.** The capability permits `PTRACE_ATTACH` and arbitrary memory read/write of any `ptrace_scope`-permitted process, not merely `/proc` metadata reads — the read-only behavior of this helper exists only because its own code chooses not to call `PTRACE_POKEDATA`/`PTRACE_CONT`/etc., not because the OS enforces read-only. A compromised or buggy holder of the capability (memory-safety bug, supply-chain compromise, crafted `--resolve-*` input) has a full-ptrace blast radius, not a scoped-read one. **Required, not optional, hardening on the helper:**
- Drop all capabilities except the minimum immediately after opening the needed `/proc` paths for the current call (capability scoping window, not held for process lifetime).
- `PR_SET_NO_NEW_PRIVS` set on the helper process.
- A seccomp-bpf syscall allowlist restricting the helper to `open`/`openat`/`readlink`/`read`/`close`/`exit` on `/proc/*` — no `ptrace()` syscall with `PEEKDATA`/`POKEDATA`/`CONT` operations ever invoked, enforced at the kernel level, not just by code review.
- `getcap`-visible (Linux) or codesigned-and-notarized (macOS), auditable in a PR diff of a few hundred lines at most.
- These hardening properties are implemented and tested **inside the helper binary's own test/build pipeline** (a separate Rust crate, not the Node `npm test` suite) — flagged explicitly here so it is a first-class acceptance item for the helper's own implementation slice, not silently assumed covered by the Node-side TDD list.

**Addendum (2026-07-12) — this section (and §1's bullet above) is where the error originated: `CAP_SYS_PTRACE` alone does not, in fact, grant the cross-UID `/proc/<pid>/fd` access §1 and this section both assumed.** A real privileged aarch64 CI run of S3-priv Slice 6 (`scripts/ci-elevated-provenance.sh`, real `setcap`, a real 2nd UID) proved this directly: granting exactly `cap_sys_ptrace=ep` and attempting the cross-UID **port** resolution this section's own helper exists to perform *failed* — while the identical resolution run as literal root succeeded, isolating the gap to the capability grant, not the resolution code.

**Kernel mechanism (confirmed against source, not re-guessed):** `/proc/<pid>/fd` is a **directory**. Its permission hook, `proc_fd_permission`, is DAC/same-thread-group gated — it allows access if the caller is in the target's thread group, OR if the ordinary DAC `generic_permission()` check passes (which checks `CAP_DAC_READ_SEARCH` before falling through to owner/group/other bits). It does **not** call `ptrace_may_access()` at all. So *enumerating* another UID's fd table (the `openat`+`getdents64` this helper's `find_owning_pid` does) needs `CAP_DAC_READ_SEARCH`, not `CAP_SYS_PTRACE`. `CAP_SYS_PTRACE` covers a different, narrower thing: the `readlinkat` of each fd **target** once found, and of `/proc/<pid>/exe` — both of which a `ptrace_may_access(PTRACE_MODE_READ)`-gated check does accept a `CAP_SYS_PTRACE` holder for. §1's "unless the caller is same-UID, root, or holds `CAP_SYS_PTRACE`" therefore conflates two different kernel gates behind one sentence; "root" in that sentence passes for a third reason entirely — plain, unrestricted root simply holds `CAP_DAC_READ_SEARCH` (and everything else) in its default capability set, not because of any ptrace-specific exemption for the directory check.

**Minimal sufficient grant, empirically confirmed (same CI run, escalating grants tested against a non-privileged helper copy):** the union `cap_sys_ptrace,cap_dac_read_search=ep`. `cap_sys_ptrace` alone: fails. `cap_dac_read_search` alone: fails (the pid's own identity read still needs the `exe`/fd-target readlink covered by `cap_sys_ptrace`). The union: succeeds. `cap_dac_override` was also tested (as a broader alternative to `cap_dac_read_search`) and **confirmed unnecessary** — `cap_dac_read_search`'s narrower, read-only bypass is sufficient.

**Consequence for §6(c)'s named `root_helper` fallback, below:** that mechanism's `CapabilityBoundingSet=CAP_SYS_PTRACE` (single-cap) has the identical bug. A process's *effective* capability set is bounded by its capability bounding set even when the process runs as literal root — `CAP_DAC_READ_SEARCH` is not in that bounding set, so it can never be gained, and the same `/proc/<pid>/fd`-enumeration failure this addendum found would reproduce under that fallback exactly as it did under the primary file-capability mechanism. Plain (non-bounding-set-restricted) root "just works" only because it isn't restricted at all — which is precisely what `CapabilityBoundingSet` exists to narrow. **Fixed** (S3-priv Slice 6, this repo's implementation): the bounding set is now `CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`, and `verify-install.sh` checks it as a sorted capability-name SET (order-independent), not an exact-string match against the old single-cap value.

**No change to the seccomp allowlist or to the "read-only by code, not by OS enforcement" framing above** — both remain accurate. The newly-succeeding syscalls under the corrected grant (`openat`/`getdents64`/`readlinkat` against another UID's `/proc/<pid>/fd`) were already allowlisted; the capability grant only changes their kernel-level return value from EACCES to success. The mechanism config-name `"cap_sys_ptrace"` (§3's `mechanism` enum) is kept as-is — only the underlying OS-level grant set changed, not Descartes's own config/envelope vocabulary. Full writeup: `docs/plans/2026-07-11-s3-priv-elevated-read-path.md`'s 2026-07-12 addendum.

### (c) Cross-platform mechanism — redesigned to remove the §6(b) contradiction (resolves security must-fix #2)

The earlier draft proposed a `root_daemon` fallback (the whole Node daemon, or a shelling-to-`lsof` LaunchDaemon, running as root) — this directly contradicted (b)'s "never the daemon's full dependency tree" principle and reintroduced a shell surface. **Removed. Replaced with `root_helper`: the same tiny, fixed-purpose, no-shell binary from (b), invoked on-demand as root, never the long-running daemon.**

- **Linux — primary mechanism, `CAP_SYS_PTRACE` as a file capability (`setcap cap_sys_ptrace=ep`)** on the helper binary, hardened per (b). Not "setgid to a reader group" (procfs entries are owned by the target process's own uid/gid, not an arbitrary group — plain group membership does not bypass the kernel's ptrace/proc permission check on stock kernels; this was a genuine discrepancy in the initial framing, corrected here). Subject to the Yama LSM `ptrace_scope` setting (0=classic, 1=restricted-but-capability-holders-still-work, 2=admin-only, 3=disabled even for capable processes) — S3-priv's TDD list includes a diagnostic (not hard-fail) probe of the real host's `ptrace_scope` value.
- **Linux — named fallback, `root_helper`:** when file capabilities are stripped (common: `tar` without `--xattrs`, some container-layer copies, some package managers), the **same helper binary** is invoked on-demand as root — via a narrowly-scoped, socket-activated systemd unit (`User=root`, `CapabilityBoundingSet=CAP_SYS_PTRACE` only, `NoNewPrivileges=yes`, `ProtectSystem=strict`) or an equivalently narrow sudoers/polkit rule limited to that exact binary path with no arguments substitution. **The Node daemon is never the process granted root; it only invokes the helper, which runs, answers, and exits.** Must be **explicitly named** in config (`mechanism:"root_helper"`), never reached via `auto` (§3).
- **macOS — no `CAP_SYS_PTRACE` analog exists.** Cross-UID process introspection is gated by XNU at the kernel level; other-UID access is blocked unless the caller is root. Options, redesigned to drop the shell-out:
  1. A small compiled helper calling `libproc.h`'s `proc_pidinfo`/`proc_pidfdinfo` **directly**, running as root via a `LaunchDaemon` — **no shelling out to `lsof`/`codesign`**, consistent with the no-shell requirement in (b). This is the `root_helper`-equivalent on macOS.
  2. The Apple-recommended **privileged helper tool** pattern (`SMAppService`, macOS 13+): a separate signed root-daemon component, authorized **once** via Authorization Services with an OS-native admin-credential prompt at install time, invoked over XPC thereafter. Cleanest fit for "explicit opt-in, install-time-granted, never self-escalating," but greenfield in this codebase (no `SMJobBless`/`SMAppService`/XPC precedent exists — confirmed by grep) and gated on the §6(f) checkpoint below before implementation begins.
- **Scoping finding, restated:** macOS's cross-UID gap may be **narrower** than assumed — unprivileged `lsof` already resolves pid+command for listeners regardless of owning UID (confirmed in `network.js`'s existing macOS path). The real macOS elevated-path need is likely concentrated in `codesign`/`spctl` checks on other-UID executables, SIP-protected/root daemons, and container-runtime helper processes. §6(f) makes this an explicit, blocking checkpoint rather than a background note.

### (d) Opt-in gating, no self-escalation, OS-level audience-scoping (redesigned per security must-fixes #1, #4, #5)

Two independent AND-gated conditions, both required: (1) the OS-level grant is present (helper binary exists, capability/root/XPC-authorization verified by probe) — installer-controlled, not daemon-controlled; (2) `configDir/provenance.json`'s `elevated.enabled` is explicitly `true` — operator-controlled, defaults `false`. Either being false/absent degrades silently and immediately to the S3 unprivileged path.

**This Descartes-level opt-in does not, by itself, restrict who else on the machine can invoke the elevated capability once installed — that is a separate, independently-required OS-level guarantee (must-fix #1):**
- **Linux:** the helper binary is installed **not world-executable** — owned `root:descartes-provenance` (a dedicated group, not a general "admin" group), mode `0750`. Only members of that dedicated group (in practice, the account the Descartes daemon runs as) can execute it at all; other local users/processes cannot invoke it merely because it exists with a capability bit set.
- **macOS (`helper_xpc`):** the XPC listener **must** enforce a code-signing-requirement (`csreq`/`SecCodeCheckValidity` against the connecting client's code signature), accepting connections only from the exact signed Descartes daemon binary — not "any local process that can open the XPC service." This is a hard requirement on the XPC helper's own implementation, not an assumption.
- Both of these are independent from, and in addition to, Descartes's own config-flag opt-in; the PR for the helper (in either language/mechanism) must demonstrate both — Descartes's opt-in scopes *whether Descartes uses* the capability, OS-level permissions scope *who can reach* the capability at all.

**Config/`helper_path` trust boundary (must-fix #4):** before honoring any `helper_path` override or the default helper path in an elevated mode, verify the resolved config file, its parent directory, and the helper binary are owned by the principal running the elevated daemon (or root, for `root_helper`) and are not group/world-writable. A failed check degrades to unprivileged, logs an operator-visible warning, and never executes an unverified path. (TDD item, §3.)

**`mechanism:"auto"` scoping (must-fix #5):** restated from §3 — `auto` only probes comparable-blast-radius mechanisms (`cap_sys_ptrace`, `helper_xpc`); `root_helper` is never an auto target, requiring an explicit named operator choice.

No runtime code path in `provenance.js` or `daemon.js` ever attempts to grant, escalate, or request privilege — verified structurally (grep for `sudo`/`setcap`/`osascript.*administrator` returning zero hits in the diff) as well as by the TDD list's explicit assertions.

### (e) Graceful fallback, including untrusted-input handling on the way in (redesigned per security must-fix #6)

Every elevated-path failure mode (helper missing, probe timeout, `EPERM`, config disabled, unsupported platform, **or a malformed/oversized/mis-scoped helper response**) degrades to exactly the same `status:"unable"`/`confidence:0`/`review_hint:"missing_permission"` shape S3 already produces unprivileged — there is no third, different-shaped "elevated attempted but failed" error surface.

**The helper's stdout is untrusted input from a less-audited external process, not a trusted internal call (must-fix #6):** it is bounded by `maxBuffer`, schema-validated before use, and — critically — the response is checked to be **scoped to the exact pid/port requested** (echo-back verification) before any field is merged into the provenance record. A response describing a different pid/port than requested (race, bug, or compromise) is treated as a degrade-to-`unable` case, not merged. This closes the "quieter, more dangerous" failure mode the review flagged: a confidently-wrong fact silently entering an alert candidate is worse than an admitted "unable," and both are now guarded identically.

The only observable difference between "elevated not configured" and "elevated configured but failed this call" is an internal trace detail (`privilege.elevated_available` vs `privilege.elevated_used`), never a difference in the degrade-not-fabricate guarantee.

### (f) Go/no-go checkpoint gating the macOS half of S3-priv (new — resolves security must-fix #7)

S3-priv's macOS elevated-helper implementation (either the `libproc`-direct `root_helper` or the full `SMAppService`/XPC path) **does not begin on sequencing alone** ("after S3 ships"). It is gated on an explicit checkpoint, run after S3 ships and before any macOS helper code is written:

1. **Real-fixture verification spike:** using S3's already-shipped unprivileged collector, capture real cases of (a) `codesign -dv`/`spctl` behavior on another UID's executable, (b) a SIP-protected or root-owned `launchd` job's listening port, (c) a container-runtime helper process's port. Determine concretely what fraction of realistic "why is this running / who owns this port" queries S3's unprivileged macOS path already answers versus what remains genuinely blocked by cross-UID kernel restrictions.
2. **Decision recorded in this plan** (append to §9) based on that spike: proceed with the full `SMAppService`/XPC helper, descope to `root_helper`-only (`libproc`-direct, no XPC), or defer the macOS half of S3-priv entirely if the residual gap proves narrow.
3. **A fresh `doors-and-corners` pass specifically for whichever macOS mechanism is chosen**, at implementation time — not reuse of this planning-time pass — per that skill's own trigger list (new entitlement/capability/signing work).

Linux `S3-priv` is not gated by this checkpoint (its cross-UID gap is already confirmed real and mechanically well-understood per §1's grounding) and may proceed once S3 ships.

---

## 7. Reconciliation vs the witr plan

`docs/plans/2026-07-09-witr-provenance-and-approval-notifications.md` **owns Layer B provenance/approval milestone numbering** (its own Milestones 1–5 for provenance, and a separate Approval Milestones 1–5). This plan does not renumber or duplicate that document; it maps onto it as follows:

| Witr plan | This plan (roadmap S3–S5/S3-priv) | Disposition |
|---|---|---|
| Milestone 1 — provenance schema and existing-tool alignment | §2 data shape, mapped against `inspect_process`/`inspect_parent_tree`/`collect_network_basics`/`collect_services`/`collect_containers`/`collect_vms` per its own instruction | **Reused.** This plan's `resolved`/`ancestry`/`source`/`sockets`/`warnings` schema is a direct implementation of Milestone 1's sketch, not a rival schema. |
| Milestone 2 — listener-to-process provenance | §2 port-target resolution (Linux `/proc/net`+fd-walk, macOS `lsof`) | **Reused/implemented.** Same design (fixtures for socket parsing + ancestry classification), TDD-shaped here. |
| Milestone 3 — source classifier | §2 source-classification chain | **Reused/implemented.** Same taxonomy (launchd/systemd/init/shell/SSH/cron/supervisor/container/unknown), confidence + `review_hint`. |
| Milestone 4 — user-facing "why" tool | §2 registration | **Reused, tool name adopted verbatim:** `inspect_runtime_provenance`, as a guarded model tool first, matching Milestone 4's stated sequencing (`descartes why` CLI is explicitly deferred, not part of this plan). |
| Milestone 5 — Wi-Fi/router state | — | **Out of scope**, correctly, per the witr plan's own instruction not to conflate it with process provenance. Not touched here. |
| Approval Milestones 1–5 | — | **Not this plan's concern.** S3–S5/S3-priv are the provenance/signature reflex layer; no risky-action approval store, no notification-approval design, no overlap with `authority/promotions.json` (constraint promotion) or any future witr risky-action store. The roadmap's own §6 states this explicitly ("We do not merge now.") and this plan does not revisit that decision. |
| "Optional dependency path" (shell to a `witr --json` binary) | — | **Deferred**, consistent with roadmap S16 — mentioned nowhere in the implementation of S3–S5; a future bounded cross-check, not a dependency of this plan. |

No duplication: this plan is the **TDD-shaped implementation plan** for the roadmap's own S3–S5/S3-priv text (`docs/plans/2026-07-09-self-learning-stratified-monitoring.md` §8, and §6's UID-scoping-limitation paragraph). This plan is that decision, made and recorded per the operator's 2026-07-10 instruction.

---

## 8. Safety summary (hard boundaries, restated per-slice)

- **Read-only host:** every new file/collector in S3–S5/S3-priv only reads (`/proc`, `lsof`, `codesign`, `id`, `docker inspect`, `libproc`) — no writes to any host path outside Descartes-owned `stateDir`/`configDir`.
- **No silent privilege escalation:** enforced structurally in S3-priv (§6d) — grep-checkable, not just documented. No mechanism runs the long-running daemon itself with elevated privilege (§6c).
- **Degrade-not-fabricate:** every unresolved fact (cross-UID pid, unavailable executable path, unclassified source, unverifiable username, malformed/mis-scoped helper response) returns `unable`/`unknown`/`confidence:0`/`missing_permission` — never a guessed value. Tested explicitly in every slice's TDD list, including untrusted-input handling on the elevated path (§6e).
- **Descartes-owned XDG paths only:** `stateDir/learned/signatures.json`, `configDir/provenance.json` — both bare-joined, no double-nest, both pass `assertNoPiOwnedPath`.
- **Never touch the user Pi setup:** no new file in this plan writes outside `resolveDescartesPaths()`'s returned paths.
- **Deterministic collector+rules, no LLM:** S3, S4, S5 are all pure/deterministic; zero model calls anywhere in this plan's code paths.
- **Evidence-envelope result shape:** every record goes through `evidenceEnvelope`/`timedEnvelope` unmodified.
- **Bounded + sanitized before alert/notification/LLM:** S4/S5 candidates route through the existing `sanitizeDiagnostics()` gate; command/args fields route through `redactAndBoundProcessArgs`; the elevated helper's own output is additionally schema-validated and scope-verified before merge (§6e).
- **TDD, atomic commits, small slices:** each slice is independently shippable and independently testable; S5's hashing fixture is explicitly sequenced before its dependent code; S3-priv's macOS half is explicitly gated on a real-fixture checkpoint (§6f) rather than proceeding on sequencing alone.
- **Tier-1 platforms only:** macOS Apple Silicon + Linux x86_64; no Windows/ARM-Linux commitment in this plan.
- **Minimal attack surface, kernel-enforced, not just convention:** the elevated helper drops capabilities after use and runs under a seccomp allowlist + `NO_NEW_PRIVS` (§6b); it is not world-executable/world-connectable at the OS level (§6d); any config path it trusts is permission-verified before use (§6d).

---

## 9. Open questions

1. **`identity_signature` hashing inputs — MUST be pinned with fixtures before any S5 code lands** (§5, item 1). Candidate input tuple: `(executable_path, exe_hash | codesign_identity, source_classification, owning_user)`. Too coarse → collisions across genuinely different processes sharing a path; too fine (e.g. including a volatile field like start_time) → never stabilizes to `known_good`. Proposed but provisional until the golden-fixture test is written and reviewed.
2. ~~S4's structural-collector default~~ — **resolved in §4**: defaults `true`, matching siblings, still gated by the outer `learned.json` kill switch. No longer open.
3. **macOS S3-priv scope** — now a **blocking checkpoint**, not an open question: see §6(f). The decision (proceed with `SMAppService`/XPC, descope to `root_helper`-only, or defer) will be recorded as an addendum to this plan once the real-fixture spike runs.
4. **Helper implementation language for S3-priv** — this plan recommends Rust (company stack preference); confirm before implementation whether a compiled Rust binary is acceptable build/packaging overhead for a first cut, or whether S3-priv should start with the Linux `root_helper` mode (same tiny binary, on-demand root invocation, no new capability-grant mechanism) before the `CAP_SYS_PTRACE` file-capability path.
5. **`ptrace_scope` on real target hosts** — no existing verification in this repo/CI of the actual Yama hardening level Descartes' Linux targets run; S3-priv's diagnostic probe (§3 TDD item 7) surfaces this but doesn't resolve it — worth an explicit pre-implementation spike.
6. **Whether `descartes provenance snapshot`/`baseline show` need a `--json` flag from day one** for future UI/scripting consumption, matching the witr plan's stated intent for `descartes why ... --json` (Milestone 4) even though that CLI itself is out of scope here.
7. **`spctl --assess` as a future signal** — currently excluded from S4's fixed rules (§2/§4) due to expected false-positive noise on unbundled CLI daemons; revisit only after validating against a real corpus of legitimate macOS daemon binaries, not before.

---

## Recommended pickup order

**S3 first.** It is the only slice with zero dependencies on anything not already live, ships real triage value immediately (the model gains a genuine "why is this running / who owns this port" tool today, unprivileged though it is), and its exported pure helpers (`classifySourceFromAncestry`, `detectWarnings`, Linux port→pid resolution) are load-bearing prerequisites for S4 (reused directly in the structural tick, with the new-I/O boundary now explicit — §4), S5 (reused for identity hashing inputs), and S3-priv (the elevated helper's output must slot into the exact same `resolved`/`source`/`warnings` shape S3 defines, and is subject to the same schema-validation/scope-verification discipline before merge). S3-priv, S4, and S5 all block on S3's schema being real and tested, not sketched. S3-priv's macOS half additionally blocks on the §6(f) checkpoint after S3 ships.
