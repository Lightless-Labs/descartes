import { Type } from "typebox";
import {
  AuthStorage,
  createAgentSession,
  DefaultResourceLoader,
  defineTool,
  ModelRegistry,
  SessionManager,
  SettingsManager,
} from "@mariozechner/pi-coding-agent";
import { collectDiskEvidence } from "./tools/disks.js";
import { collectProcessEvidence } from "./tools/processes.js";
import { collectSystemEvidence } from "./tools/system.js";
import { collectAllEvidence } from "./tools/collect.js";
import { deriveFindings } from "./tools/findings.js";

export const TRIAGE_TOOL_NAMES = ["collect_system", "collect_processes", "collect_disks", "collect_triage_evidence", "derive_findings"];

function jsonToolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    details: value,
  };
}

export function createEvidenceTools() {
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
3. Produce a concise operator-facing report: most likely cause, confidence, evidence, safe next checks, avoid for now, and the exact sentence "No actions were taken."`;
}

function evidenceContext(evidenceBundle) {
  if (!evidenceBundle) return "";
  return `

Initial read-only Descartes evidence bundle, already collected for this explicit triage request:
${JSON.stringify(evidenceBundle, null, 2)}

Use the evidence above even if you do not call any tools. You may call tools only if you need refreshed or additional first-slice evidence.`;
}

export function jsonTriagePrompt(userPrompt, evidenceBundle) {
  return `Triage this local machine complaint: ${JSON.stringify(userPrompt)}${evidenceContext(evidenceBundle)}

Return only valid JSON with this shape:
{
  "summary": string,
  "confidence": "low" | "medium" | "high",
  "explanation": string,
  "evidence_refs": string[],
  "next_checks": string[],
  "avoid": string[],
  "actions_taken": []
}`;
}

export function humanTriagePrompt(userPrompt, evidenceBundle) {
  return `Triage this local machine complaint: ${JSON.stringify(userPrompt)}${evidenceContext(evidenceBundle)}

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
  const model = options.model ?? available[0];
  if (!model) {
    throw new Error("No configured model credentials found. Run `descartes login` or configure an API key in Descartes' XDG config path.");
  }

  return createAgentSession({
    cwd: options.cwd ?? process.cwd(),
    agentDir: paths.configDir,
    authStorage,
    modelRegistry,
    settingsManager,
    resourceLoader,
    sessionManager: SessionManager.inMemory(),
    model,
    thinkingLevel: options.thinkingLevel ?? "off",
    tools: TRIAGE_TOOL_NAMES,
    customTools: createEvidenceTools(),
  });
}
