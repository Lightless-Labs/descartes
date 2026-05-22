Overall verdict: Directionally sound, with strong read-only/tool-surface scaffolding. I found no confirmed mutating collector or exposed Pi shell/coding tool in source. However, I would not treat the current slice/validation briefs as release-ready until the High privacy/correctness issues below are fixed. I did not run commands/tests; this is read-only inspection only.

## Findings

### Blocker
- None confirmed from read-only inspection.

### High

1. **Container commands are bounded but not redacted**
   - Files: `tools/descartes-cli/src/tools/containers.js:147,187`; test codifies leak at `tools/descartes-cli/test/containers.test.js:42,51`.
   - Evidence: Docker/Podman `Command` fields are passed through `boundedString(...)`; the test expects `postgres -c password=secret`.
   - Impact: container commands can contain tokens/passwords and are sent to the LLM during explicit triage.
   - Fix: reuse `redactAndBoundProcessArgs()` for Docker/Podman container commands and return `command_redaction` metadata; update tests to expect redaction.

2. **No-evidence guard misses empty-assistant/no-tool path**
   - Files: `tools/descartes-cli/src/triage-guard.js:14-30`, `tools/descartes-cli/src/triage.js:160-184`, `tools/descartes-cli/src/triage-fallback.js:4`.
   - Evidence: retry/fallback require `assistantText.trim()`. If the model returns no text and no tools, fallback is generated without deterministic precollection, and fallback text says “Descartes collected evidence” even when evidence is empty.
   - Impact: known “empty diagnosis / empty evidence” class can still recur.
   - Fix: if investigation is enabled and evidence is empty after the session, precollect deterministic fallback evidence regardless of assistant text; add mocked `runTriage` tests for empty assistant/no tool calls.

3. **Linux validation briefs can capture raw sensitive data despite their own privacy rules**
   - Files: `linux-x86_64-validation-brief.md:15-16,239-247`; `linux-arm64-validation-brief.md:15-16,230-235`.
   - Evidence: x86 brief captures raw `journalctl`, `podman ps --all`, `docker ps --all`, and `ps ... args`; ARM brief captures timer/VM inventory into `external-capabilities.txt`.
   - Impact: command lines, logs, container names/images, VM names can leak into validation artifacts.
   - Fix: replace with sanitized summaries (`--format` with limited fields where possible, no `args`, no raw journal lines), or explicitly mark these files local-only and not reportable.

### Medium

4. **Credentialed validation snippets are not XDG-isolated**
   - Files: `linux-x86_64-validation-brief.md:265-282`; `linux-arm64-validation-brief.md:240-257`.
   - Evidence: optional `descartes login --no-open` / `descartes triage` snippets omit the isolated `HOME`/`XDG_*` env used earlier.
   - Impact: may read/write a validator’s real Descartes config/auth instead of disposable validation state.
   - Fix: wrap optional credentialed steps in a dedicated `$work/xdg-auth` environment.

5. **Linux memory pressure can be misleading**
   - Files: `tools/descartes-cli/src/tools/system.js:54-72`, `tools/descartes-cli/src/tools/findings.js:19-24`.
   - Evidence: memory used fraction is `totalmem - os.freemem`; Linux operational pressure should usually use `/proc/meminfo` `MemAvailable`.
   - Impact: cache-heavy Linux hosts may be reported as memory-pressure cases.
   - Fix: on Linux, compute available/used from `MemAvailable`; add fixture tests.

6. **macOS inode parsing likely misreads real `df -iP` output**
   - Files: `tools/descartes-cli/src/tools/disks.js:36-44,75-77`; weak fixture at `tools/descartes-cli/test/disks.test.js:45-48`.
   - Evidence: parser uses the first `%` column generically; macOS `df -i` commonly has both space capacity and inode `%iused`.
   - Impact: inode evidence can be wrong on macOS.
   - Fix: parse inode output separately and add a real macOS `df -iP` fixture.

### Low

7. **Collector reference drift**
   - Files: `docs/reference/collectors.md:3,33`; code at `tools/descartes-cli/src/tools/processes.js:374`.
   - Evidence: docs say `inspect_parent_tree` emits `parent-tree-<pid>` but code emits `process-parent-tree-<pid>`; updated date is stale relative to v0.0.30 content.
   - Fix: align docs with code.

8. **API-key login prompt echoes secrets**
   - File: `tools/descartes-cli/src/login.js:58-61`.
   - Impact: advanced API-key fallback can expose keys in terminal/recordings.
   - Fix: hidden input or documented env/file-based non-echo path. I could not verify auth file permissions from source.

## Positive confirmations

- XDG path resolution is Descartes-owned and rejects `.pi` path segments (`paths.js:22-38`).
- Pi harness is strongly constrained: extensions/skills/prompts/themes/context disabled, in-memory sessions, explicit custom tool names, exact active-tool assertion (`pi-harness.js:366-403`, `tool-policy.js:1-44`).
- Collectors generally use fixed `execFile` argv arrays with timeouts/bounds.
- Good test breadth exists for parsers, package metadata, tool policy, redaction in process/log/scheduler paths, sampling artifact path guards, time-sync server validation.
- Package metadata is aligned at v0.0.30 with Node `>=22.19.0` and published files include `docs/reference` plus runtime source.

## Suggested next checks/tests

- Add container command redaction tests for Docker and Podman.
- Add mocked end-to-end triage tests for: empty assistant/no tools, assistant text/no evidence retry, fallback precollection, enforced top-level `actions_taken: []`.
- Rework Linux validation briefs to sanitize external snapshots and isolate credentialed XDG state.
- Add Linux `/proc/meminfo` `MemAvailable` fixture tests and real macOS `df -iP` fixture tests.
- Run adjusted Linux x86_64 and ARM64 validation on real hosts/VMs after fixes.
