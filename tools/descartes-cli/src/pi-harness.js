import { Type } from "typebox";
import {
  AuthStorage,
  createAgentSession,
  DefaultResourceLoader,
  defineTool,
  ModelRegistry,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { collectCertificateEvidence } from "./tools/certificates.js";
import { collectContainerEvidence } from "./tools/containers.js";
import { collectDiskEvidence } from "./tools/disks.js";
import { collectRecentLogsEvidence } from "./tools/logs.js";
import { collectNetworkEvidence } from "./tools/network.js";
import { collectProcessEvidence, inspectParentTreeEvidence, inspectProcessEvidence } from "./tools/processes.js";
import { collectScheduledJobsEvidence } from "./tools/scheduled-jobs.js";
import { collectServiceEvidence } from "./tools/services.js";
import { collectSystemEvidence } from "./tools/system.js";
import { collectTimeSyncEvidence } from "./tools/time-sync.js";
import { collectVmEvidence } from "./tools/vms.js";
import { collectAllEvidence } from "./tools/collect.js";
import { deriveFindings } from "./tools/findings.js";
import { readSamplingArtifactEvidence, sampleDimensionEvidence } from "./tools/sampling.js";
import { selectTriageModel } from "./model-selection.js";
import { assertSafeTriageToolNames, TRIAGE_TOOL_NAMES } from "./tool-policy.js";

function jsonToolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    details: value,
  };
}

export function createEvidenceTools(paths) {
  return [
    defineTool({
      name: "collect_system",
      label: "Collect system overview",
      description: "Collect read-only OS, CPU/load, memory, swap, uptime, and host identity evidence.",
      parameters: Type.Object({}),
      executionMode: "parallel",
      execute: async () => jsonToolResult(await collectSystemEvidence()),
    }),
    defineTool({
      name: "collect_processes",
      label: "Collect top processes",
      description: "Collect read-only top CPU and memory process evidence using the process table.",
      parameters: Type.Object({ limit: Type.Optional(Type.Number({ minimum: 1, maximum: 25 })) }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectProcessEvidence({ limit: params.limit ?? 10 })),
    }),
    defineTool({
      name: "collect_disks",
      label: "Collect disk usage",
      description: "Collect read-only filesystem space and inode usage evidence.",
      parameters: Type.Object({}),
      executionMode: "parallel",
      execute: async () => jsonToolResult(await collectDiskEvidence()),
    }),
    defineTool({
      name: "collect_network_basics",
      label: "Collect network basics",
      description: "Collect read-only network interface, default route, DNS resolver/reachability, and listening socket evidence using fixed local probes.",
      parameters: Type.Object({
        check_dns_reachability: Type.Optional(Type.Boolean()),
        socket_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectNetworkEvidence({
        checkDnsReachability: params.check_dns_reachability ?? true,
        socketLimit: params.socket_limit ?? 50,
      })),
    }),
    defineTool({
      name: "collect_services",
      label: "Collect service manager state",
      description: "Collect read-only service manager evidence: systemd services on Linux or launchd jobs on macOS, with failed/restarting/nonzero-exit summaries.",
      parameters: Type.Object({ service_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })) }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectServiceEvidence({ serviceLimit: params.service_limit ?? 80 })),
    }),
    defineTool({
      name: "collect_recent_logs",
      label: "Collect recent logs",
      description: "Collect bounded read-only recent warning/error logs plus fail2ban/firewall-oriented signals where available. Log excerpts are sensitive diagnostic artifacts.",
      parameters: Type.Object({
        window_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 360 })),
        event_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })),
        include_security: Type.Optional(Type.Boolean()),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectRecentLogsEvidence({
        windowMinutes: params.window_minutes ?? 30,
        eventLimit: params.event_limit ?? 80,
        includeSecurity: params.include_security ?? true,
      })),
    }),
    defineTool({
      name: "collect_containers",
      label: "Collect container inventory",
      description: "Collect bounded read-only Docker, Podman, Colima, and Lima container/runtime evidence using fixed local probes. No container actions are taken.",
      parameters: Type.Object({
        container_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })),
        host_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 100 })),
        include_stopped: Type.Optional(Type.Boolean()),
        collect_stats: Type.Optional(Type.Boolean()),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectContainerEvidence({
        containerLimit: params.container_limit ?? 80,
        hostLimit: params.host_limit ?? 40,
        includeStopped: params.include_stopped ?? true,
        collectStats: params.collect_stats ?? true,
      })),
    }),
    defineTool({
      name: "collect_vms",
      label: "Collect VM inventory",
      description: "Collect bounded read-only VM runtime and inventory evidence for Tart, Lima, Multipass, VirtualBox, libvirt/virsh, Parallels, VMware, UTM, Podman machine, Incus/LXD VMs, Proxmox, Xen, and direct VM-like processes where available. No VM actions are taken.",
      parameters: Type.Object({ vm_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })) }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectVmEvidence({ vmLimit: params.vm_limit ?? 80 })),
    }),
    defineTool({
      name: "collect_scheduled_jobs",
      label: "Collect scheduled jobs",
      description: "Collect bounded read-only cron, systemd timer, and launchd scheduled job evidence using fixed local probes. No scheduled jobs are modified.",
      parameters: Type.Object({
        job_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 200 })),
        include_system: Type.Optional(Type.Boolean()),
        include_user: Type.Optional(Type.Boolean()),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectScheduledJobsEvidence({
        jobLimit: params.job_limit ?? 80,
        includeSystem: params.include_system ?? true,
        includeUser: params.include_user ?? true,
      })),
    }),
    defineTool({
      name: "collect_time_sync",
      label: "Collect time sync state",
      description: "Collect bounded read-only clock/time synchronization evidence using local system time tools. Optional offset checks may contact a requested/default NTP server but never adjust the clock.",
      parameters: Type.Object({
        check_offset: Type.Optional(Type.Boolean()),
        server: Type.Optional(Type.String()),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectTimeSyncEvidence({
        checkOffset: params.check_offset ?? false,
        server: params.server,
      })),
    }),
    defineTool({
      name: "collect_certificates",
      label: "Collect certificate inventory",
      description: "Collect bounded read-only local certificate validity evidence from common system/keychain/service certificate stores. Private keys are not read.",
      parameters: Type.Object({
        warning_days: Type.Optional(Type.Number({ minimum: 1, maximum: 3650 })),
        certificate_limit: Type.Optional(Type.Number({ minimum: 1, maximum: 500 })),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await collectCertificateEvidence({
        warningDays: params.warning_days ?? 30,
        certificateLimit: params.certificate_limit ?? 80,
      })),
    }),
    defineTool({
      name: "inspect_process",
      label: "Inspect process identity",
      description: "Inspect one process by PID using read-only process table facts, redacted command lines, parent summary, and child summaries.",
      parameters: Type.Object({ pid: Type.Number({ minimum: 1 }) }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await inspectProcessEvidence({ pid: params.pid })),
    }),
    defineTool({
      name: "inspect_parent_tree",
      label: "Inspect process parent tree",
      description: "Inspect a bounded read-only ancestry chain for a process by PID using redacted command line snippets.",
      parameters: Type.Object({
        pid: Type.Number({ minimum: 1 }),
        max_depth: Type.Optional(Type.Number({ minimum: 1, maximum: 64 })),
      }),
      executionMode: "parallel",
      execute: async (_id, params) => jsonToolResult(await inspectParentTreeEvidence({ pid: params.pid, maxDepth: params.max_depth ?? 16 })),
    }),
    defineTool({
      name: "sample_dimension",
      label: "Sample a dimension over time",
      description: "Collect bounded read-only temporal samples for process CPU, process memory, or load/memory/swap and return aggregates.",
      parameters: Type.Object({
        dimension: Type.Union([Type.Literal("cpu_processes"), Type.Literal("memory_processes"), Type.Literal("load_memory_swap")]),
        duration_seconds: Type.Optional(Type.Number({ minimum: 1, maximum: 60 })),
        interval_seconds: Type.Optional(Type.Number({ minimum: 1, maximum: 60 })),
        top_n: Type.Optional(Type.Number({ minimum: 1, maximum: 20 })),
        aggregation: Type.Optional(Type.Union([Type.Literal("summary"), Type.Literal("timeseries"), Type.Literal("summary_and_timeseries_ref")])),
      }),
      execute: async (_id, params) => jsonToolResult(await sampleDimensionEvidence(params, paths)),
    }),
    defineTool({
      name: "read_sampling_artifact",
      label: "Read Descartes sampling artifact",
      description: "Read a bounded excerpt from a Descartes-owned sampling artifact returned by sample_dimension. This is not a general file reader.",
      parameters: Type.Object({
        artifact_id: Type.String(),
        max_samples: Type.Optional(Type.Number({ minimum: 1, maximum: 25 })),
      }),
      execute: async (_id, params) => jsonToolResult(await readSamplingArtifactEvidence(params, paths)),
    }),
    defineTool({
      name: "collect_triage_evidence",
      label: "Collect all triage evidence",
      description: "Collect the full first-slice read-only resource-pressure evidence bundle and deterministic findings.",
      parameters: Type.Object({}),
      executionMode: "parallel",
      execute: async () => jsonToolResult(await collectAllEvidence()),
    }),
    defineTool({
      name: "derive_findings",
      label: "Derive deterministic findings",
      description: "Given evidence envelopes, compute deterministic resource-pressure findings for grounding.",
      parameters: Type.Object({ evidence: Type.Array(Type.Any()) }),
      execute: async (_id, params) => jsonToolResult({ findings: deriveFindings(params.evidence) }),
    }),
  ];
}

export function alertSystemPrompt() {
  return `You are Descartes alert intelligence, a local-first monitoring adjudicator.

Your job is to review bounded deterministic alert summaries and decide whether/how to notify the user.

Hard rules:
- Use only alert/history facts provided in the prompt.
- Do not execute tools or request host actions.
- Do not claim facts that are not present in alert/history summaries.
- Do not recommend or imply remediation was taken.
- Return only the structured notification decision requested by the prompt.`;
}

export function triageSystemPrompt() {
  return `You are Descartes, a local-first operations triage agent.

Your job is to answer the user's local machine complaint with an evidence-cited diagnosis.

Hard rules:
- Use only Descartes evidence tools for local facts.
- Do not execute arbitrary shell commands.
- Do not claim system facts that are not present in returned evidence.
- Local evidence collection is read-only.
- No host actions are authorized or taken in v0.
- Be explicit about uncertainty and missing evidence.
- Include evidence IDs in citations.

Preferred flow:
1. Select the narrowest Descartes evidence tools that match the complaint.
2. For broad slowness/resource-pressure triage, call collect_triage_evidence first.
3. If a process looks important, call inspect_process and/or inspect_parent_tree for process identity and lineage before making claims about provenance.
4. If the complaint involves connectivity, DNS, listening ports, or network reachability, call collect_network_basics rather than guessing.
5. If the complaint involves a daemon, service, startup item, or repeated restart/failure, call collect_services rather than guessing.
6. If the complaint involves crashes, reboots, authentication failures, fail2ban, firewall blocks, denied traffic, or recent error context, call collect_recent_logs with tight bounds rather than guessing. Treat log excerpts as sensitive.
7. If the complaint involves Docker, Podman, Colima, Lima, containers, images, container ports, or container resource use, call collect_containers rather than guessing. Do not suggest start/stop/delete/prune actions as already taken.
8. If the complaint involves VMs, Tart, UTM, Parallels, VMware, Lima VMs, Multipass, VirtualBox, libvirt, virsh, KVM, QEMU, Podman machine, Incus/LXD VMs, Proxmox, Xen, hypervisors, or a general “containers or VMs” inventory, call collect_vms as well as collect_containers when relevant rather than inferring only from processes.
9. If the complaint involves cron, launchd scheduled jobs, systemd timers, periodic tasks, startup timers, or unexplained recurring/sporadic workload, call collect_scheduled_jobs rather than guessing.
10. If the complaint involves clock skew, time synchronization, NTP, TLS/certificate time validity, Kerberos/auth time errors, or suspicious timestamp drift, call collect_time_sync rather than guessing. Set check_offset only when an external NTP offset check is directly relevant.
11. If the complaint involves certificate expiry, TLS validity, local trust stores, Let's Encrypt, nginx/apache/httpd certificates, or keychain/system certificate state, call collect_certificates rather than guessing. Treat certificate subjects, issuers, paths, and fingerprints as sensitive.
12. If a snapshot is ambiguous or the user asks about patterns over time, call sample_dimension with a short bounded duration before diagnosing sustained/flapping behavior.
13. Produce a concise operator-facing report: most likely cause, confidence, evidence, safe next checks, avoid for now, and the exact sentence "No actions were taken."`;
}

function truncate(value, max = 180) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function compactEvidenceForPrompt(evidenceBundle) {
  if (!evidenceBundle) return undefined;
  const evidence = Object.fromEntries((evidenceBundle.evidence ?? []).map((item) => [item.id, item.result]));
  const system = evidence["system-overview"];
  const processes = evidence["top-processes"];
  const disks = evidence["disk-usage"];
  const history = evidence["history-summary"];

  const pressuredFilesystems = Array.isArray(disks?.filesystems)
    ? disks.filesystems
        .filter((fs) => typeof fs.used_fraction === "number" && fs.used_fraction >= 0.9 && fs.pressure_relevant !== false)
        .slice(0, 8)
        .map((fs) => ({ mount_point: fs.mount_point, used_fraction: fs.used_fraction, available_bytes: fs.available_bytes }))
    : [];

  return {
    system: system ? {
      hostname: system.hostname,
      platform: system.platform,
      arch: system.arch,
      cpu_count: system.cpu_count,
      load_average: system.load_average,
      memory: system.memory,
      swap: system.swap,
    } : undefined,
    top_cpu: (processes?.top_cpu ?? []).slice(0, 8).map((process) => ({
      pid: process.pid,
      command: process.command,
      cpu_percent: process.cpu_percent,
      memory_percent: process.memory_percent,
      args: truncate(process.args),
    })),
    top_memory: (processes?.top_memory ?? []).slice(0, 5).map((process) => ({
      pid: process.pid,
      command: process.command,
      cpu_percent: process.cpu_percent,
      memory_percent: process.memory_percent,
      rss_bytes: process.rss_bytes,
      args: truncate(process.args),
    })),
    pressured_filesystems: pressuredFilesystems,
    history: history ? {
      window_ms: history.window_ms,
      since: history.since,
      until: history.until,
      point_count: history.point_count,
      corrupt_count: history.corrupt_count,
      metrics: (history.metrics ?? []).slice(0, 32).map((metric) => ({
        metric_name: metric.metric_name,
        unit: metric.unit,
        count: metric.count,
        min: metric.min,
        max: metric.max,
        mean: metric.mean,
        last: metric.last,
        p95: metric.p95,
        dimensions_seen: metric.dimensions_seen,
      })),
    } : undefined,
    findings: (evidenceBundle.findings ?? []).slice(0, 16),
    actions_taken: [],
  };
}

function evidenceContext(evidenceBundle, { toolsEnabled = false } = {}) {
  if (!evidenceBundle) return "";
  const evidenceIds = (evidenceBundle.evidence ?? []).map((item) => item.id);
  const toolInstruction = toolsEnabled
    ? "You may call Descartes read-only evidence tools if the compact summary is insufficient or you need to refresh/scope evidence. Do not call tools just to restate the same facts."
    : "No tools are available in this synthesis turn; local collection has already happened.";
  return `

Initial read-only Descartes evidence summary, already collected for this explicit triage request:
${JSON.stringify(compactEvidenceForPrompt(evidenceBundle), null, 2)}

Evidence citation rule: cite only these evidence envelope IDs: ${evidenceIds.join(", ")}. Do not cite derived summary keys such as top_cpu, top_memory, pressured_filesystems, or findings as evidence_refs.

Use the evidence above and any additional Descartes tool results. Do not claim facts outside this evidence. ${toolInstruction}`;
}

export function jsonTriagePrompt(userPrompt, evidenceBundle, options = {}) {
  return `Triage this local machine complaint: ${JSON.stringify(userPrompt)}${evidenceContext(evidenceBundle, options)}

Return only valid JSON with this shape:
{
  "summary": string,
  "confidence": "low" | "medium" | "high",
  "explanation": string,
  "evidence_refs": string[], // only evidence envelope IDs, e.g. "system-overview", "top-processes", "disk-usage"
  "next_checks": string[],
  "avoid": string[],
  "actions_taken": []
}`;
}

export function humanTriagePrompt(userPrompt, evidenceBundle, options = {}) {
  return `Triage this local machine complaint: ${JSON.stringify(userPrompt)}${evidenceContext(evidenceBundle, options)}

Print a concise report with these headings:
Descartes triage: <complaint>
Most likely cause
Confidence
Evidence
Safe next checks
Avoid for now

End with: No actions were taken.`;
}

async function createPrivateSession(paths, options = {}) {
  const authStorage = AuthStorage.create(paths.authFile);
  const modelRegistry = ModelRegistry.create(authStorage, paths.modelsFile);
  const settingsManager = SettingsManager.inMemory({
    compaction: { enabled: false },
    retry: { enabled: true, maxRetries: 2 },
  });

  const resourceLoader = new DefaultResourceLoader({
    cwd: options.cwd ?? process.cwd(),
    agentDir: paths.configDir,
    settingsManager,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPromptOverride: () => options.systemPrompt ?? triageSystemPrompt(),
    agentsFilesOverride: () => ({ agentsFiles: [] }),
    skillsOverride: () => ({ skills: [], diagnostics: [] }),
    promptsOverride: () => ({ prompts: [], diagnostics: [] }),
    themesOverride: () => ({ themes: [], diagnostics: [] }),
  });
  await resourceLoader.reload();

  const available = modelRegistry.getAvailable();
  const { model, thinkingLevel } = selectTriageModel(available, options);
  if (!model) {
    throw new Error("No configured model credentials found. Run `descartes login` or configure an API key in Descartes' XDG config path.");
  }

  const enableTools = options.enableTools ?? false;

  const result = await createAgentSession({
    cwd: options.cwd ?? process.cwd(),
    agentDir: paths.configDir,
    authStorage,
    modelRegistry,
    settingsManager,
    resourceLoader,
    sessionManager: SessionManager.inMemory(),
    model,
    thinkingLevel,
    noTools: enableTools ? undefined : "all",
    tools: enableTools ? TRIAGE_TOOL_NAMES : undefined,
    customTools: enableTools ? createEvidenceTools(paths) : [],
  });

  const activeToolNames = result.session.getActiveToolNames();
  if (enableTools) assertSafeTriageToolNames(activeToolNames);

  return {
    ...result,
    selectedModel: model,
    selectedThinkingLevel: thinkingLevel,
    activeToolNames,
  };
}

export async function createPrivateTriageSession(paths, options = {}) {
  return createPrivateSession(paths, { ...options, systemPrompt: triageSystemPrompt() });
}

export async function createPrivateAlertSession(paths, options = {}) {
  return createPrivateSession(paths, { ...options, systemPrompt: alertSystemPrompt(), enableTools: false });
}
