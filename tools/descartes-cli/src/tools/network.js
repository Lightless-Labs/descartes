import dns from "node:dns/promises";
import os from "node:os";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);
const DNS_LOOKUP_TARGET = "example.com";

function truncate(value, max = 4096) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function runFixedCommand(command, args, options = {}) {
  const argv = [command, ...args];
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: options.timeout ?? 2500,
      maxBuffer: options.maxBuffer ?? 1024 * 512,
    });
    return {
      status: "ok",
      stdout,
      stderr: truncate(stderr, 2048),
      command: { argv, read_only: true },
    };
  } catch (error) {
    return {
      status: "unable",
      error: error instanceof Error ? error.message : String(error),
      stdout: truncate(error?.stdout ?? "", 2048),
      stderr: truncate(error?.stderr ?? "", 2048),
      command: { argv, read_only: true },
    };
  }
}

function uniqueBy(items, keyFn) {
  const seen = new Set();
  const result = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

export function normalizeInterfaces(interfaces = os.networkInterfaces()) {
  return Object.entries(interfaces).flatMap(([name, addresses]) => (addresses ?? []).map((address) => ({
    name,
    family: address.family,
    address: address.address,
    cidr: address.cidr,
    internal: address.internal,
    scopeid: address.scopeid,
  }))).sort((left, right) => `${left.name}:${left.family}:${left.address}`.localeCompare(`${right.name}:${right.family}:${right.address}`));
}

export function parseLinuxDefaultRoutes(stdout) {
  return stdout.split("\n").map((line) => line.trim()).filter(Boolean).filter((line) => line.startsWith("default")).map((line) => {
    const parts = line.split(/\s+/);
    const valueAfter = (token) => {
      const index = parts.indexOf(token);
      return index >= 0 ? parts[index + 1] : undefined;
    };
    const metric = valueAfter("metric");
    return {
      destination: "default",
      gateway: valueAfter("via"),
      interface: valueAfter("dev"),
      source: valueAfter("src"),
      protocol: valueAfter("proto"),
      metric: metric === undefined ? undefined : Number(metric),
      raw: line,
    };
  });
}

export function parseMacDefaultRoute(stdout) {
  const fields = {};
  for (const line of stdout.split("\n")) {
    const match = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
    if (match) fields[match[1].trim()] = match[2].trim();
  }
  if (!fields.gateway && !fields.interface) return [];
  return [{
    destination: fields.destination || fields["route to"] || "default",
    gateway: fields.gateway,
    interface: fields.interface,
    flags: fields.flags,
  }];
}

export function parseResolvConf(contents) {
  const resolvers = [];
  for (const line of contents.split("\n")) {
    const match = line.trim().match(/^nameserver\s+(\S+)/);
    if (match) resolvers.push({ address: match[1], source: "/etc/resolv.conf" });
  }
  return uniqueBy(resolvers, (item) => item.address).slice(0, 8);
}

export function parseScutilDns(stdout) {
  const resolvers = [];
  for (const line of stdout.split("\n")) {
    const match = line.match(/nameserver\[[0-9]+\]\s*:\s*(\S+)/);
    if (match) resolvers.push({ address: match[1], source: "scutil --dns" });
  }
  return uniqueBy(resolvers, (item) => item.address).slice(0, 8);
}

function parseAddressPort(endpoint) {
  const clean = String(endpoint ?? "").replace(/^\[/, "").replace(/\]$/, "");
  if (!clean) return { address: undefined, port: undefined };

  const bracketed = String(endpoint).match(/^\[([^\]]+)\]:(\*|\d+)$/);
  if (bracketed) return { address: bracketed[1], port: bracketed[2] === "*" ? undefined : Number(bracketed[2]) };

  const lastColon = clean.lastIndexOf(":");
  if (lastColon === -1) return { address: clean, port: undefined };
  const address = clean.slice(0, lastColon) || "*";
  const portText = clean.slice(lastColon + 1);
  return { address, port: portText === "*" ? undefined : Number(portText) };
}

export function parseLinuxListeningSockets(stdout, { limit = 50 } = {}) {
  return stdout.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const parts = line.split(/\s+/);
    if (parts.length < 5) return undefined;
    const local = parseAddressPort(parts[4]);
    return {
      protocol: parts[0],
      state: parts[1],
      local_address: local.address,
      local_port: local.port,
      raw: line,
    };
  }).filter(Boolean).slice(0, limit);
}

export function parseMacLsofListeningSockets(stdout, { limit = 50 } = {}) {
  return stdout.split("\n").slice(1).map((line) => line.trim()).filter(Boolean).map((line) => {
    const match = line.match(/^(\S+)\s+(\d+)\s+\S+.*\s+(TCP)\s+(.+?)\s+\(LISTEN\)$/);
    if (!match) return undefined;
    const local = parseAddressPort(match[4]);
    return {
      protocol: match[3].toLowerCase(),
      state: "LISTEN",
      command: match[1],
      pid: Number(match[2]),
      local_address: local.address,
      local_port: local.port,
    };
  }).filter(Boolean).slice(0, limit);
}

async function collectDefaultRoutes() {
  if (process.platform === "linux") {
    const command = await runFixedCommand("ip", ["route", "show", "default"]);
    return {
      status: command.status,
      routes: command.status === "ok" ? parseLinuxDefaultRoutes(command.stdout) : [],
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("route", ["-n", "get", "default"]);
    return {
      status: command.status,
      routes: command.status === "ok" ? parseMacDefaultRoute(command.stdout) : [],
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }
  return { status: "unsupported", routes: [], error: `unsupported platform: ${process.platform}` };
}

async function collectDnsResolvers() {
  if (process.platform === "linux") {
    try {
      return { status: "ok", resolvers: parseResolvConf(await fs.readFile("/etc/resolv.conf", "utf8")), sources: ["/etc/resolv.conf"] };
    } catch (error) {
      return { status: "unable", resolvers: [], sources: ["/etc/resolv.conf"], error: error instanceof Error ? error.message : String(error) };
    }
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("scutil", ["--dns"], { timeout: 2500, maxBuffer: 1024 * 512 });
    return {
      status: command.status,
      resolvers: command.status === "ok" ? parseScutilDns(command.stdout) : [],
      sources: ["scutil --dns"],
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }
  return { status: "unsupported", resolvers: [], sources: [], error: `unsupported platform: ${process.platform}` };
}

async function lookupWithTimeout(target, timeoutMs = 2500) {
  let timeout;
  try {
    const addresses = await Promise.race([
      dns.lookup(target, { all: true }),
      new Promise((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`DNS lookup timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
    return {
      status: "ok",
      target,
      addresses: addresses.map((item) => ({ address: item.address, family: item.family })).slice(0, 8),
      network_probe: true,
    };
  } catch (error) {
    return {
      status: "unable",
      target,
      error: error instanceof Error ? error.message : String(error),
      network_probe: true,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function collectListeningSockets(limit) {
  if (process.platform === "linux") {
    const command = await runFixedCommand("ss", ["-H", "-ltnu"], { timeout: 2500, maxBuffer: 1024 * 512 });
    return {
      status: command.status,
      sockets: command.status === "ok" ? parseLinuxListeningSockets(command.stdout, { limit }) : [],
      command: command.command,
      error: command.error,
      stderr: command.stderr,
      truncated: command.status === "ok" && parseLinuxListeningSockets(command.stdout, { limit: Number.MAX_SAFE_INTEGER }).length > limit,
    };
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], { timeout: 3500, maxBuffer: 1024 * 512 });
    return {
      status: command.status,
      sockets: command.status === "ok" ? parseMacLsofListeningSockets(command.stdout, { limit }) : [],
      command: command.command,
      error: command.error,
      stderr: command.stderr,
      truncated: command.status === "ok" && parseMacLsofListeningSockets(command.stdout, { limit: Number.MAX_SAFE_INTEGER }).length > limit,
    };
  }
  return { status: "unsupported", sockets: [], error: `unsupported platform: ${process.platform}`, truncated: false };
}

export async function collectNetworkEvidence({ checkDnsReachability = true, socketLimit = 50 } = {}) {
  const boundedSocketLimit = Math.min(Math.max(Number(socketLimit) || 50, 1), 200);
  return timedEnvelope(async () => {
    const [defaultRoutes, dnsResolvers, listeningSockets, dnsReachability] = await Promise.all([
      collectDefaultRoutes(),
      collectDnsResolvers(),
      collectListeningSockets(boundedSocketLimit),
      checkDnsReachability ? lookupWithTimeout(DNS_LOOKUP_TARGET) : Promise.resolve({ status: "skipped", target: DNS_LOOKUP_TARGET, network_probe: false }),
    ]);

    return {
      platform: process.platform,
      interfaces: normalizeInterfaces(),
      default_routes: defaultRoutes,
      dns: {
        ...dnsResolvers,
        reachability: dnsReachability,
      },
      listening_sockets: listeningSockets,
    };
  }, (result) => evidenceEnvelope({
    id: "network-basics",
    status: result?.dns?.reachability?.status === "unable" ? "warning" : "ok",
    source: "network",
    result,
    reviewHint: result?.dns?.reachability?.status === "unable" ? "ambiguous" : "none",
    tool: "collect_network_basics",
    target: `dns=${checkDnsReachability ? DNS_LOOKUP_TARGET : "skipped"},socket_limit=${boundedSocketLimit}`,
  }));
}
