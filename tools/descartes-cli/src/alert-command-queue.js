import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { acknowledgeAlert } from "./alert-store.js";
import { acquireDaemonSingleton } from "./daemon-singleton.js";

export function resolveAlertCommandQueuePath(descartesPaths) {
  return path.join(descartesPaths.stateDir, "alerts", "commands.jsonl");
}

async function appendCommand(descartesPaths, command) {
  const file = resolveAlertCommandQueuePath(descartesPaths);
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await fs.appendFile(file, `${JSON.stringify({ ...command, command_id: crypto.randomUUID(), queued_at: new Date().toISOString() })}\n`, { mode: 0o600 });
}

function acquireFor(paths, options) {
  return options.singleton?.acquire ? options.singleton.acquire(paths, options) : acquireDaemonSingleton(paths, { timeoutMs: 0 });
}

export async function queueOrApplyAlertCommand(descartesPaths, command, options = {}) {
  try {
    const owner = await acquireFor(descartesPaths, options);
    try {
      if (command.type !== "ack") throw new Error(`Unsupported alert command: ${command.type}`);
      const alert = await acknowledgeAlert(descartesPaths, command.alert_id, { now: options.now });
      return { queued: false, alert };
    } finally {
      await owner.release?.();
    }
  } catch (error) {
    if (error?.code !== "DAEMON_SINGLETON_BUSY") throw error;
    await appendCommand(descartesPaths, command);
    return { queued: true, command };
  }
}

export async function applyQueuedAlertCommands(descartesPaths, options = {}) {
  const file = resolveAlertCommandQueuePath(descartesPaths);
  const processing = `${file}.${process.pid}.${crypto.randomUUID()}.processing`;
  try {
    await fs.rename(file, processing);
  } catch (error) {
    if (error?.code === "ENOENT") return { applied: [], retained: [] };
    throw error;
  }

  const retained = [];
  const applied = [];
  const contents = await fs.readFile(processing, "utf8");
  for (const line of contents.split("\n")) {
    if (!line.trim()) continue;
    let command;
    try {
      command = JSON.parse(line);
    } catch {
      continue;
    }
    try {
      if (command.type !== "ack") throw new Error(`Unsupported alert command: ${command.type}`);
      await acknowledgeAlert(descartesPaths, command.alert_id, { now: options.now ?? command.queued_at });
      applied.push(command.alert_id);
    } catch (error) {
      if (/^Alert not found:/.test(error?.message ?? "")) retained.push(command);
      else throw error;
    }
  }
  await fs.unlink(processing);
  if (retained.length > 0) {
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    await fs.appendFile(file, `${retained.map((command) => JSON.stringify(command)).join("\n")}\n`, { mode: 0o600 });
  }
  return { applied, retained };
}
