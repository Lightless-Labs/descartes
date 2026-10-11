import dns from "node:dns/promises";
import os from "node:os";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { throwIfCollectorAborted } from "./collector-abort.js";

const execFileAsync = promisify(execFile);
const DNS_LOOKUP_TARGET = "example.com";

function attachCensusMetadata(value, metadata) {
  for (const [key, entry] of Object.entries(metadata)) Object.defineProperty(value, key, { value: entry, enumerable: false });
  return value;
}

function truncate(value, max = 4096) {
  if (typeof value !== "string") return value;
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

async function runFixedCommand(command, args, options = {}) {
  throwIfCollectorAborted(options.signal);
  const result = await runResolvedExecFile(command, args, {
    ...options,
    timeout: options.timeout ?? 2500,
    maxBuffer: options.maxBuffer ?? 1024 * 512,
    execFileAsync,
  });
  return {
    ...result,
    status: result.status === "ok" ? "ok" : (result.availability ?? "unable"),
    stdout: truncate(result.stdout ?? "", 2048),
    stderr: truncate(result.stderr ?? "", 2048),
  };
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

export function normalizeSocketProtocol(protocol) {
  if (typeof protocol !== "string") return undefined;
  const value = protocol.toLowerCase();
  if (value === "tcp4") return "tcp";
  if (value === "udp4") return "udp";
  return value;
}

// Keep the transport family when the source exposes it explicitly (Linux /proc/net/tcp6 or
// lsof's IPv6 TYPE column), and infer it from the canonical bracketed address when that is all a
// source provides (for example, an `ss` row). IPv4 keeps the legacy `tcp`/`udp` spelling so
// persisted provenance target keys remain stable.
export function normalizeSocketProtocolForFamily(protocol, familyOrAddress) {
  const normalized = normalizeSocketProtocol(protocol);
  if (normalized === undefined) return undefined;
  const base = normalized.replace(/6$/, "");
  if (base !== "tcp" && base !== "udp") return normalized;
  const hint = typeof familyOrAddress === "string" ? familyOrAddress.toLowerCase() : "";
  const ipv6 = normalized.endsWith("6")
    || hint === "ipv6"
    || hint === "6"
    || hint.includes("inet6")
    || hint.startsWith("[")
    || hint === "::";
  return `${base}${ipv6 ? "6" : ""}`;
}

export function normalizeSocketAddress(address) {
  if (typeof address !== "string") return undefined;
  return address === "::" ? "[::]" : address;
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
  if (typeof stdout !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const routes = [];
  let malformed_count = 0;
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (!line.startsWith("default")) { malformed_count += 1; continue; }
    const parts = line.split(/\s+/);
    const valueAfter = (token) => {
      const index = parts.indexOf(token);
      return index >= 0 ? parts[index + 1] : undefined;
    };
    const metric = valueAfter("metric");
    if (parts.some((part, index) => index > 0 && ["via", "dev", "src", "proto", "metric"].includes(part) && parts[index + 1] === undefined)) {
      malformed_count += 1;
      continue;
    }
    const metricValue = metric === undefined ? undefined : /^\d+$/.test(metric) ? Number(metric) : undefined;
    if (metric !== undefined && metricValue === undefined) { malformed_count += 1; continue; }
    routes.push({
      destination: "default",
      gateway: valueAfter("via"),
      interface: valueAfter("dev"),
      source: valueAfter("src"),
      protocol: valueAfter("proto"),
      metric: metricValue,
      raw: line,
    });
  }
  return attachCensusMetadata(routes, { malformed_count });
}

export function parseMacDefaultRoute(stdout) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const fields = {};
  let malformed_count = 0;
  for (const line of stdout.split("\n")) {
    if (line.trim() && !/^\s*[^:]+:\s*.*$/.test(line)) { malformed_count += 1; continue; }
    const match = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
    if (match) fields[match[1].trim()] = match[2].trim();
  }
  if (!fields.gateway && !fields.interface) return attachCensusMetadata([], { malformed_count });
  return attachCensusMetadata([{
    destination: fields.destination || fields["route to"] || "default",
    gateway: fields.gateway,
    interface: fields.interface,
    flags: fields.flags,
  }], { malformed_count });
}

export function parseResolvConf(contents) {
  if (typeof contents !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const resolvers = [];
  let malformed_count = 0;
  for (const line of contents.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || /^(?:search|domain|options)\b/.test(trimmed)) continue;
    const match = line.trim().match(/^nameserver\s+(\S+)/);
    if (match) resolvers.push({ address: match[1], source: "/etc/resolv.conf" });
    else malformed_count += 1;
  }
  return attachCensusMetadata(uniqueBy(resolvers, (item) => item.address).slice(0, 8), { malformed_count, truncated: resolvers.length > 8 });
}

export function parseScutilDns(stdout) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const resolvers = [];
  let malformed_count = 0;
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === "DNS configuration" || /^resolver #[0-9]+$/i.test(trimmed)
      || /^(?:search domain\[[0-9]+\]|domain|if_index|flags|options|order|reach)\s*:/i.test(trimmed)) continue;
    const match = line.match(/nameserver\[[0-9]+\]\s*:\s*(\S+)/);
    if (match) resolvers.push({ address: match[1], source: "scutil --dns" });
    else malformed_count += 1;
  }
  return attachCensusMetadata(uniqueBy(resolvers, (item) => item.address).slice(0, 8), { malformed_count, truncated: resolvers.length > 8 });
}

function parseAddressPort(endpoint) {
  if (typeof endpoint !== "string") return { address: undefined, port: undefined };
  const clean = endpoint.replace(/^\[/, "").replace(/\]$/, "");
  if (!clean) return { address: undefined, port: undefined };
  if (clean === "::") return { address: "[::]", port: undefined };

  const bracketed = endpoint.match(/^\[([^\]]+)\]:(\*|\d+)$/);
  if (bracketed) return { address: normalizeSocketAddress(bracketed[1]), port: bracketed[2] === "*" ? undefined : Number(bracketed[2]) };

  const lastColon = clean.lastIndexOf(":");
  if (lastColon === -1) return { address: clean, port: undefined };
  const address = normalizeSocketAddress(clean.slice(0, lastColon) || "*");
  const portText = clean.slice(lastColon + 1);
  return { address, port: portText === "*" ? undefined : Number(portText) };
}

export function parseLinuxListeningSockets(stdout, { limit = 50 } = {}) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { rejected_count: 1, truncated: false });
  let rejected_count = 0;
  const entries = stdout.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const parts = line.split(/\s+/);
    if (parts.length < 5) { rejected_count += 1; return undefined; }
    const local = parseAddressPort(parts[4]);
    if (!local.address || normalizeSocketProtocol(parts[0]) === undefined || (local.port !== undefined && !Number.isSafeInteger(local.port))) { rejected_count += 1; return undefined; }
    return {
      protocol: normalizeSocketProtocolForFamily(parts[0], local.address),
      state: parts[1],
      local_address: local.address,
      local_port: local.port,
      raw: line,
    };
  }).filter(Boolean);
  return attachCensusMetadata(entries.slice(0, limit), { rejected_count, truncated: entries.length > limit });
}

export function parseMacLsofListeningSocketsDetailed(stdout, { limit = 50 } = {}) {
  if (typeof stdout !== "string") return { entries: [], rejected: 1, truncated: false };
  const entries = [];
  let rejected = 0;
  for (const line of stdout.split("\n").slice(1).map((item) => item.trim()).filter(Boolean)) {
    const match = line.match(/^(\S+)\s+(\d+)\s+\S+.*\s+(TCP|UDP)\s+(.+?)(?:\s+\(LISTEN\))?$/);
    const family = line.match(/\s(IPv[46])\s/)?.[1];
    const protocol = normalizeSocketProtocol(match?.[3]);
    const isTcp = protocol === "tcp";
    if (!match || (isTcp && !/\(LISTEN\)$/.test(line))) {
      rejected += 1;
      continue;
    }
    const local = parseAddressPort(match[4]);
    if (!local.address) {
      rejected += 1;
      continue;
    }
    // macOS emits UDP wildcard bookkeeping rows such as `*: *`/`*:*` for an
    // unconnected, portless socket. They are valid census rows but carry no
    // bind target, so ignore them without degrading the census.
    if (local.port === undefined) {
      if (protocol === "udp" && local.address === "*") continue;
      rejected += 1;
      continue;
    }
    const familyProtocol = normalizeSocketProtocolForFamily(protocol, family ?? local.address);
    entries.push({
      protocol: familyProtocol,
      state: isTcp ? "LISTEN" : "UNCONN",
      command: match[1],
      pid: Number(match[2]),
      local_address: local.address,
      local_port: local.port,
    });
  }
  return { entries: entries.slice(0, limit), rejected, truncated: entries.length > limit };
}

export function parseMacLsofListeningSockets(stdout, { limit = 50 } = {}) {
  return parseMacLsofListeningSocketsDetailed(stdout, { limit }).entries;
}

async function collectDefaultRoutes(options = {}) {
  if (process.platform === "linux") {
    const command = await runFixedCommand("ip", ["route", "show", "default"], options);
    const routes = command.status === "ok" ? parseLinuxDefaultRoutes(command.stdout) : [];
    return {
      status: command.status === "ok" && routes.malformed_count === 0 ? "ok" : command.status === "ok" ? "partial" : command.status,
      routes,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("route", ["-n", "get", "default"], options);
    const routes = command.status === "ok" ? parseMacDefaultRoute(command.stdout) : [];
    return {
      status: command.status === "ok" && routes.malformed_count === 0 ? "ok" : command.status === "ok" ? "partial" : command.status,
      routes,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
    };
  }
  return { status: "unsupported", routes: [], error: `unsupported platform: ${process.platform}` };
}

async function collectDnsResolvers(options = {}) {
  if (process.platform === "linux") {
    try {
      const resolvers = parseResolvConf(await fs.readFile("/etc/resolv.conf", "utf8"));
      return { status: resolvers.malformed_count === 0 && !resolvers.truncated ? "ok" : "partial", resolvers, sources: ["/etc/resolv.conf"] };
    } catch (error) {
      return { status: "unable", resolvers: [], sources: ["/etc/resolv.conf"], error: error instanceof Error ? error.message : String(error) };
    }
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("scutil", ["--dns"], { ...options, timeout: 2500, maxBuffer: 1024 * 512 });
    const resolvers = command.status === "ok" ? parseScutilDns(command.stdout) : [];
    return {
      status: command.status === "ok" && resolvers.malformed_count === 0 && !resolvers.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
      resolvers,
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

async function collectListeningSockets(limit, options = {}) {
  if (process.platform === "linux") {
    const command = await runFixedCommand("ss", ["-H", "-ltnu"], { ...options, timeout: 2500, maxBuffer: 1024 * 512 });
    const sockets = command.status === "ok" ? parseLinuxListeningSockets(command.stdout, { limit }) : [];
    return {
      status: command.status === "ok" && sockets.rejected_count === 0 && !sockets.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
      sockets,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
      truncated: command.status === "ok" && sockets.truncated,
    };
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], { ...options, timeout: 3500, maxBuffer: 1024 * 512 });
    const detailed = command.status === "ok" ? parseMacLsofListeningSocketsDetailed(command.stdout, { limit }) : { entries: [], rejected: 0, truncated: false };
    return {
      status: command.status === "ok" && detailed.rejected === 0 && !detailed.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
      sockets: detailed.entries,
      command: command.command,
      error: command.error,
      stderr: command.stderr,
      truncated: command.status === "ok" && detailed.truncated,
    };
  }
  return { status: "unsupported", sockets: [], error: `unsupported platform: ${process.platform}`, truncated: false };
}

export async function collectNetworkEvidence({ checkDnsReachability = true, socketLimit = 50, ...options } = {}) {
  const requestedSocketLimit = typeof socketLimit === "number" && Number.isSafeInteger(socketLimit) ? socketLimit : 50;
  const boundedSocketLimit = Math.min(Math.max(requestedSocketLimit, 1), 200);
  return timedEnvelope(async () => {
    const [defaultRoutes, dnsResolvers, listeningSockets, dnsReachability] = await Promise.all([
      collectDefaultRoutes(options),
      collectDnsResolvers(options),
      collectListeningSockets(boundedSocketLimit, options),
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
