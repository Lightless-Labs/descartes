## Review basis

Read-only inspection only. I did not run tests, install packages, execute collectors, or validate live LLM/provider behavior. I reviewed the requested docs, todos, package metadata, validation briefs, and `tools/descartes-cli` source shape.

## Overall alignment verdict

Descartes is **well aligned for a v0 explicit, read-only, LLM-backed local triage slice**, especially around L0 evidence collection, guarded tool access, Pi/XDG separation, and “no host actions.”

It is **not yet a stratified machine nervous system** beyond the first slice. The repo is currently heavily weighted toward broad L0 JavaScript collectors plus model-led synthesis. L1 rules/signatures, notification, plan objects, policy/authority machinery, learning/promotion loops, Rust/Bazel substrate, and durable schema enforcement remain mostly aspirational.

Recent VM/container/correlation and validation-brief work **advances the roadmap** if treated as capability-discovery/L0 groundwork. More collector expansion before Linux x86_64 validation and L1 extraction would start to become drift.

## Strong alignment points

- **Product identity is clearly stated** in `README.md`, `AGENTS.md`, and `docs/ROADMAP.md`: local-first triage now, stratified operations/defense agent later.
- **Evidence-first loop is implemented in shape**:
  - `tools/descartes-cli/src/pi-harness.js` exposes only Descartes evidence tools.
  - `tools/descartes-cli/src/tool-policy.js` rejects unexpected/Pi coding tools.
  - `tools/descartes-cli/src/triage.js` includes diagnostics, evidence flattening, fallback state, and `actions_taken: []`.
  - `tools/descartes-cli/src/triage-guard.js` prevents normal no-evidence diagnosis from silently succeeding.
- **L0 collector coverage is broad and relevant**: system, processes, disks, network, services, logs, containers, VMs, scheduled jobs, time sync, certificates, sampling.
- **Read-only boundary is mostly respected**: collectors use fixed `execFile` argv arrays or bounded file reads; no shell/coding/mutation tools are exposed.
- **VM/container correlation is directionally right** for the roadmap’s intent-based provisioning/resource-attribution story.
- **Validation briefs are well aligned**: read-only, sanitized, platform-focused, and targeted at the real remaining Tier-1 Linux x86_64 gap.
- **Node/Pi pragmatism is documented honestly** in README/HANDOFF/package metadata.

## Misalignments / architectural debt by severity

### High

1. **L0 breadth is outpacing L1/product consolidation.**
   Many collectors exist, but deterministic findings remain mostly resource-pressure oriented in `tools/descartes-cli/src/tools/findings.js`. There is little L1 rule/signature/playbook behavior for services, logs, time sync, certs, scheduled jobs, containers, or VMs.

2. **Tier-1 Linux x86_64 remains unverified.**
   Docs repeatedly identify this as the main release gap. I could verify the briefs exist, not that they were run.

3. **Rust/Bazel direction is still only documentary.**
   `find` showed only npm metadata, no `Cargo.toml`, `MODULE.bazel`, or Bazel/Rust scaffold. The longer collector work lives in JavaScript, increasing migration cost.

### Medium

4. **“No model-invented facts” is prompted/guarded, not fully enforced.**
   The no-evidence guard is good, but I did not see a validator that rejects JSON `evidence_refs` not in collected envelopes or checks human prose citations/factual claims.

5. **Policy/authority plane is only represented by absence.**
   `actions_taken: []` and no action tools are correct for v0, but there is no plan/approval/audit schema yet. That is fine now, but should exist before any action-tool design.

6. **Privacy/redaction is uneven.**
   Process/log/scheduled-job paths have explicit redaction. Container commands appear bounded but not obviously redacted in `containers.js`; logs/certs/network/container/VM evidence remain sensitive by design. This is documented, but no redacted export/privacy profile exists.

7. **VM/container correlation needs real-host validation and ambiguity handling.**
   Current matching is deterministic by name/path/runtime hints, but best-match heuristics can misattribute when names collide or helper processes lack stable hints.

### Low / documentation debt

8. **Roadmap/handoff/status wording has drift.**
   - `docs/ROADMAP.md` still lists no-evidence guard as remaining/recently deferred despite completed todo/handoff entries.
   - First-slice plan remains “In progress” while many parts are effectively complete except Linux x86_64.
   - Handoff is overloaded with chronological “current session update” history.
   - `docs/reference/collectors.md` header says updated 2026-05-21 while it describes 2026-05-22-era work.
   - `collect_triage_evidence` is documented as compact, but `pi-harness.js` labels it “Collect all triage evidence,” which could confuse future maintainers/models.

## Recommended course corrections / next milestones

1. **Freeze new collector expansion until v0.0.30+ Linux x86_64 validation is complete.**
2. **Create an L1 extraction milestone:** deterministic findings/rules for service failure, certificate expiry, unsynced time, recurring jobs, recent auth/firewall errors, and VM/container resource attribution.
3. **Add evidence-reference validation** for JSON output and diagnostics for invalid/missing citations.
4. **Start the Rust/Bazel-friendly substrate now:** at minimum a Rust `descartes-core` evidence schema crate plus JSON-schema/conformance tests used by the Node wrapper.
5. **Keep Pi/Node as harness glue, not the durable collector home.**
6. **Add a policy/plan/audit schema before action work**, even while all actions remain disabled.
7. **Complete real-host VM/container correlation validation**, especially Colima/Lima/Podman-machine QEMU/VZ/Apple Virtualization cases.
8. **Clarify docs:** current lifecycle coverage is Observe + Diagnose/Recommend on explicit request; Notify/Plan/Act/Learn are future.

## Could not verify

- Live npm install, package contents, or `npm test`.
- Actual provider/tool-calling behavior.
- Actual absence of Pi path access inside the external Pi dependency.
- No telemetry behavior of transitive dependencies/providers.
- Linux x86_64 runtime behavior.
