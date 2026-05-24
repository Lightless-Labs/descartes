---
title: "Ransomware-like mass file encryption in progress"
status: example
priority: p1
product_area: security
summary: "Detect when a process appears to be rapidly encrypting or replacing broad sets of user/system files, explain the evidence, and gate any intervention behind explicit policy."
required_capabilities:
  - daemon_history
  - low_latency_filesystem_activity_stream
  - process_identity_and_lineage
  - per_process_file_mutation_baselines
  - entropy_or_content_shape_sampling
  - security_signature_rules
  - policy_gated_alerting_and_response
required_data_sources:
  - process_table_snapshots
  - process_parent_tree_snapshots
  - executable_path_hash_and_signature_metadata
  - filesystem_write_rename_delete_events
  - bounded_file_content_shape_samples
  - local_history_metric_store
  - backup_snapshot_state
required_surfaces:
  - urgent_local_notification
  - cli_security_status
  - evidence_explanation_sheet
  - approval_required_response_prompt
  - audit_log_entry
optional_improvements:
  capabilities:
    - kernel_or_endpoint_security_event_source
    - eBPF_or_fanotify_file_event_source_on_linux
    - EndpointSecurity_file_event_source_on_macos
    - application_reputation_and_package_provenance
    - backup_snapshot_creation_or_verification
    - network_egress_correlation
    - sandbox_or_quarantine_workflow
  data_sources:
    - code_signing_and_notarization_state
    - package_manager_ownership
    - known_good_backup_tool_allowlist
    - known_ransomware_extension_or_note_signatures
    - privacy_preserving_federated_behavioral_priors
  surfaces:
    - menu_bar_or_tray_alert
    - timeline_view
    - one_click_collect_evidence_bundle
    - rollback_or_restore_plan_preview
privacy:
  raw_data_boundary: "Raw file paths, process arguments, content samples, hostnames, usernames, and local history stay on the device by default. Explicit triage may send bounded, redacted summaries to the selected LLM provider."
  content_sampling: "Only bounded local byte-window samples or derived entropy/content-shape metrics should be stored; full file contents should not be copied into history."
  user_controls:
    - explain_why
    - show_affected_paths_summary
    - suppress_or_allowlist_process
    - disable_filesystem_security_detector
    - delete_security_history
policy:
  interruption_threshold: "Interrupt only when a process shows high-confidence mass mutation behavior across sensitive file sets, or lower-confidence behavior touches especially critical directories."
  action_authority: "Notify/recommend by default. Killing, suspending, quarantining, network blocking, snapshot creation, or rollback requires explicit approval unless the user has configured a narrow autonomous policy."
  non_goals:
    - generic_high_cpu_alerts
    - scanning_or_uploading_user_file_contents
    - killing_backup_sync_or_developer_tools_without_strong_evidence
related_docs:
  - docs/plans/2026-05-23-daemon-history-store.md
  - docs/plans/2026-05-23-derived-collector-transformation-engine.md
  - docs/plans/2026-05-23-agent-authored-sensor-toolkit.md
---

# Ransomware-like mass file encryption in progress

## User story

The user is working normally when an unfamiliar process begins touching thousands of files under home directories and project folders. It reads existing files, writes new high-entropy replacements, renames many of them with a new extension, deletes originals, and drops similarly named note files into multiple directories.

Descartes notices the behavior quickly, attributes it to a process identity and parent tree, explains the evidence, and asks for approval before any disruptive response.

Example alert:

> Descartes sees `unknown-sync-helper` modifying files unusually fast: 3,842 writes/renames across Documents, Pictures, and Projects in the last 90 seconds. Many replacements have high-entropy content and a new `.locked` suffix, and the process was launched from `~/Downloads` by a shell. This resembles mass-encryption behavior. No action has been taken. Review evidence or approve stopping the process.

## Why this is Descartes-shaped

A generic assistant can explain ransomware after the fact. Descartes should be able to connect **local real-time evidence** to an operationally useful diagnosis:

- which process is doing the mutations
- where it came from and what parent launched it
- which file sets are affected
- whether the behavior is abnormal for this host
- whether the executable is signed, known, packaged, or newly introduced
- which response options are safe, reversible, and authorized

The model is not the source of truth. Deterministic event streams, local history, process identity, and bounded content-shape metrics produce the evidence. Deliberative reasoning can summarize uncertainty, recommend next checks, and draft an approval-gated response plan.

## Required evidence artifacts

```text
FileMutationEvent
  ts
  pid
  executable_identity
  operation: create | write | truncate | rename | delete | chmod
  path_bucket_or_redacted_path
  directory_scope
  extension_before
  extension_after
  size_before
  size_after
  entropy_before_bucket
  entropy_after_bucket
  source: endpoint_security | fanotify | audit | ebpf | fsevents | fallback
  sensitivity

ProcessIdentity
  pid
  ppid
  executable_path
  executable_hash
  code_signature_or_package_owner
  launch_time
  user
  parent_tree
  command_shape_redacted
  first_seen_on_host

MutationBurst
  process_identity
  window
  files_touched_count
  directories_touched_count
  write_rate
  rename_rate
  delete_rate
  extension_churn
  entropy_shift_summary
  affected_sensitive_scopes
  baseline_comparison
  confidence

SecurityFinding
  type: ransomware_like_mass_encryption
  severity
  evidence_refs
  likely_process
  affected_scope_summary
  false_positive_notes
  recommended_next_checks
  response_options
```

## Detection sketch

A first useful detector would combine several lower-confidence signals rather than rely on one magic signature:

1. **Mutation rate:** a single process writes/renames/deletes many user files in a short window.
2. **Breadth:** affected files span multiple directories or sensitive scopes, not just one cache/build directory.
3. **Content-shape change:** sampled replacements shift toward high entropy or uniform encrypted-looking bytes.
4. **Rename/extension pattern:** many files acquire the same new extension or naming convention.
5. **Original removal:** writes are followed by deletes/truncates of previous versions.
6. **Ransom-note pattern:** similarly named text/html files appear in many directories.
7. **Suspicious provenance:** executable is unsigned, newly downloaded, launched from a temp/download path, or has an unusual parent tree.
8. **Baseline mismatch:** this process has not historically performed broad file mutations on this host.

Known-good exceptions must be explicit and evidence-grounded: backup tools, sync clients, photo libraries, package managers, compilers, database maintenance, archive/extract tools, and legitimate disk encryption workflows can all perform high-volume I/O.

## Required local substrate

Current Descartes history is not enough. This use case requires:

- low-latency filesystem mutation telemetry attributed to process IDs
- process identity snapshots frequent enough to survive short-lived helpers
- a bounded per-process metric store for write/rename/delete rates
- local-only content-shape/entropy sampling with strict size and sensitivity bounds
- entity correlation between file events, process identity, parent tree, package/signature state, and historical baselines
- a rules/signature layer that can alert without an LLM
- an approval/audit plane for any response that changes the host

## Privacy and explainability

The alert must be explainable without exposing unnecessary raw data:

- "this process touched N files across these broad scopes"
- "these operations were unusual compared with local history"
- "content-shape samples shifted toward high entropy"
- "the process lineage is X → Y → suspicious executable"

The user should be able to inspect representative redacted paths, affected directory summaries, process identity, and the exact rule signals. They should also be able to correct false positives:

- "this is my backup tool"
- "allow this signed app to touch this directory"
- "disable ransomware-like alerts for this path"
- "delete the stored security history"

## Policy and response gates

Initial shipping posture should be notify/recommend only:

```text
read-only alert
  -> explain evidence
  -> recommend immediate checks
  -> offer approval-required response plan
```

Possible approval-required responses:

- suspend or kill the process
- block network access for the process or executable
- quarantine the executable
- create or verify a local snapshot/backup if safe and available
- preserve forensic evidence bundle locally
- guide the user through restore/rollback options

Autonomous action should be reserved for a later, explicit, narrowly scoped policy such as:

> If an unsigned process launched from Downloads modifies more than 500 documents in two minutes with high entropy replacements and ransom-note creation, suspend it and notify me.

Even then, every action needs an audit trail: evidence, policy match, command/tool call, pre-state, result, post-state, and rollback notes.
