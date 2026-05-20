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
import { collectDiskEvidence } from "./tools/disks.js";
import { collectProcessEvidence, inspectParentTreeEvidence, inspectProcessEvidence } from "./tools/processes.js";
import { collectSystemEvidence } from "./tools/system.js";
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
1. Call collect_triage_evidence first for broad resource-pressure triage.
2. If needed, call specific collectors to refresh or inspect a subset.
3. If a process looks important, call inspect_process and/or inspect_parent_tree for process identity and lineage before making claims about provenance.
4. If a snapshot is ambiguous or the user asks about patterns over time, call sample_dimension with a short bounded duration before diagnosing sustained/flapping behavior.
5. Produce a concise operator-facing report: most likely cause, confidence, evidence, safe next checks, avoid for now, and the exact sentence "No actions were taken."`;
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

export async function createPrivateTriageSession(paths, options = {}) {
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
    systemPromptOverride: () => triageSystemPrompt(),
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
