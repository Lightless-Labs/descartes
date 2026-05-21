export const TRIAGE_TOOL_NAMES = Object.freeze([
  "collect_system",
  "collect_processes",
  "collect_disks",
  "collect_network_basics",
  "collect_services",
  "collect_recent_logs",
  "collect_containers",
  "collect_vms",
  "collect_scheduled_jobs",
  "collect_time_sync",
  "inspect_process",
  "inspect_parent_tree",
  "sample_dimension",
  "read_sampling_artifact",
  "collect_triage_evidence",
  "derive_findings",
]);

export const FORBIDDEN_TRIAGE_TOOL_NAMES = Object.freeze([
  "bash",
  "read",
  "write",
  "edit",
  "grep",
  "find",
  "ls",
]);

export function assertSafeTriageToolNames(activeToolNames) {
  const active = [...activeToolNames].sort();
  const allowed = [...TRIAGE_TOOL_NAMES].sort();
  const unexpected = active.filter((name) => !TRIAGE_TOOL_NAMES.includes(name));
  const missing = allowed.filter((name) => !active.includes(name));
  const forbidden = active.filter((name) => FORBIDDEN_TRIAGE_TOOL_NAMES.includes(name));

  if (unexpected.length > 0 || missing.length > 0 || forbidden.length > 0) {
    const details = [
      unexpected.length > 0 ? `unexpected tools: ${unexpected.join(", ")}` : undefined,
      missing.length > 0 ? `missing tools: ${missing.join(", ")}` : undefined,
      forbidden.length > 0 ? `forbidden tools: ${forbidden.join(", ")}` : undefined,
    ].filter(Boolean).join("; ");
    throw new Error(`Unsafe Descartes triage tool surface (${details}).`);
  }
}
