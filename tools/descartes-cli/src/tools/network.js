import dns from "node:dns/promises";
import { isIP } from "node:net";
import os from "node:os";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";
import { finalizeCensus } from "./census-validate.js";
import { throwIfCollectorAborted } from "./collector-abort.js";
import { parseLinuxIpRouteLine } from "./linux-iproute-grammar.js";

const execFileAsync = promisify(execFile);
const DNS_LOOKUP_TARGET = "example.com";
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

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
    const parsed = parseLinuxIpRouteLine(line);
    if (!parsed?.interfaceName) { malformed_count += 1; continue; }
    routes.push({
      destination: "default",
      gateway: parsed.gateway,
      interface: parsed.interfaceName,
      source: parsed.source,
      protocol: parsed.protocol,
      metric: parsed.metric,
      raw: line,
    });
  }
  const census = finalizeCensus({
    records: routes,
    identity: (route) => JSON.stringify([route.destination, route.gateway, route.interface, route.source, route.protocol, route.metric]),
    malformed: malformed_count,
  });
  return attachCensusMetadata(census.records, {
    malformed_count,
    duplicate_count: census.duplicate_count,
    truncated: census.truncated,
  });
}

export function parseMacDefaultRoute(stdout) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const fields = {};
  let malformed_count = 0;
  let duplicate_count = 0;
  for (const line of stdout.split("\n")) {
    if (line.trim() && !/^\s*[^:]+:\s*.*$/.test(line)) { malformed_count += 1; continue; }
    const match = line.match(/^\s*([^:]+):\s*(.*?)\s*$/);
    if (match) {
      const key = match[1].trim();
      if (Object.prototype.hasOwnProperty.call(fields, key)) { duplicate_count += 1; continue; }
      fields[key] = match[2].trim();
    }
  }
  if (!fields.gateway && !fields.interface) return attachCensusMetadata([], { malformed_count, duplicate_count });
  const routes = [{
    destination: fields.destination || fields["route to"] || "default",
    gateway: fields.gateway,
    interface: fields.interface,
    flags: fields.flags,
  }];
  const census = finalizeCensus({ records: routes, identity: (route) => JSON.stringify(route), malformed: malformed_count + duplicate_count });
  return attachCensusMetadata(census.records, { malformed_count, duplicate_count: duplicate_count + census.duplicate_count, truncated: census.truncated });
}

export function parseResolvConf(contents) {
  if (typeof contents !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const resolvers = [];
  let malformed_count = 0;
  for (const line of contents.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || /^(?:search|domain|options)\b/.test(trimmed)) continue;
    if (/^nameserver\b/.test(trimmed)) {
      const match = trimmed.match(/^nameserver\s+(\S+)(?:\s+#.*)?$/);
      if (!match || isIP(match[1]) === 0) { malformed_count += 1; continue; }
      resolvers.push({ address: match[1], source: "/etc/resolv.conf" });
      continue;
    }
    malformed_count += 1;
  }
  const census = finalizeCensus({ records: resolvers, identity: (item) => item.address, cap: 8, malformed: malformed_count });
  return attachCensusMetadata(census.records, {
    malformed_count,
    duplicate_count: census.duplicate_count,
    truncated: census.truncated,
  });
}

export function parseScutilDns(stdout) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { malformed_count: 1 });
  const resolvers = [];
  let malformed_count = 0;
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === "DNS configuration" || /^resolver #[0-9]+$/i.test(trimmed)
      || /^(?:search domain\[[0-9]+\]|domain|if_index|flags|options|order|reach)\s*:/i.test(trimmed)) continue;
    if (/nameserver\[/i.test(line)) {
      const match = line.match(/^\s*nameserver\[[0-9]+\]\s*:\s*(\S+)\s*$/i);
      if (!match || isIP(match[1]) === 0) { malformed_count += 1; continue; }
      resolvers.push({ address: match[1], source: "scutil --dns" });
      continue;
    }
    malformed_count += 1;
  }
  const census = finalizeCensus({ records: resolvers, identity: (item) => item.address, cap: 8, malformed: malformed_count });
  return attachCensusMetadata(census.records, {
    malformed_count,
    duplicate_count: census.duplicate_count,
    truncated: census.truncated,
  });
}

function parseAddressPort(endpoint) {
  if (typeof endpoint !== "string") return { address: undefined, port: undefined };
  const bracketed = endpoint.match(/^\[([^\]]+)\]:(\*|\d+)$/);
  if (bracketed && isIP(bracketed[1]) === 6) return { address: normalizeSocketAddress(bracketed[1]), port: parseSocketPort(bracketed[2]) };
  const unbracketed = endpoint.match(/^(\*|\d+(?:\.\d+){3}):(\*|\d+)$/);
  if (!unbracketed || (unbracketed[1] !== "*" && isIP(unbracketed[1]) !== 4)) return { address: undefined, port: undefined };
  return { address: unbracketed[1], port: parseSocketPort(unbracketed[2]) };
}

function parseSocketPort(value) {
  if (value === "*") return undefined;
  const port = Number(value);
  return Number.isSafeInteger(port) && port >= 0 && port <= 65535 ? port : Number.NaN;
}

export function parseLinuxListeningSockets(stdout, { limit = 50 } = {}) {
  if (typeof stdout !== "string") return attachCensusMetadata([], { rejected_count: 1, truncated: false });
  let rejected_count = 0;
  const entries = stdout.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const parts = line.split(/\s+/);
    if (parts.length !== 6) { rejected_count += 1; return undefined; }
    const local = parseAddressPort(parts[4]);
    const peer = parseAddressPort(parts[5]);
    const protocol = normalizeSocketProtocol(parts[0]);
    if (!/^(?:tcp|tcp6|udp|udp6)$/.test(parts[0]) || !/^(?:LISTEN|UNCONN)$/.test(parts[1])
      || !/^\d+$/.test(parts[2]) || !/^\d+$/.test(parts[3]) || !local.address || !peer.address
      || (local.port !== undefined && !Number.isSafeInteger(local.port)) || (peer.port !== undefined && !Number.isSafeInteger(peer.port))) {
      rejected_count += 1;
      return undefined;
    }
    return {
      protocol: normalizeSocketProtocolForFamily(protocol, local.address),
      state: parts[1],
      local_address: local.address,
      local_port: local.port,
      raw: line,
    };
  }).filter(Boolean);
  const census = finalizeCensus({
    records: entries,
    identity: (entry) => JSON.stringify([entry.protocol, entry.state, entry.local_address, entry.local_port]),
    cap: limit,
    malformed: rejected_count,
  });
  return attachCensusMetadata(census.records, {
    rejected_count,
    duplicate_count: census.duplicate_count,
    truncated: census.truncated,
  });
}

export function parseMacLsofListeningSocketsDetailed(stdout, { limit = 50 } = {}) {
  if (typeof stdout !== "string") return { entries: [], rejected: 1, truncated: false };
  const firstLine = stdout.split("\n").find((line) => line.trim());
  if (firstLine && !/^COMMAND\s+PID\s+USER\s+FD\s+TYPE\s+DEVICE\s+SIZE\/OFF\s+NODE\s+NAME$/.test(firstLine.trim())) {
    return { entries: [], rejected: 1, duplicate_count: 0, truncated: false };
  }
  const entries = [];
  let rejected = 0;
  for (const line of stdout.split("\n").slice(1).map((item) => item.trim()).filter(Boolean)) {
    const match = line.match(/^(\S+)\s+(\d+)\s+(\S+)\s+(\d+[A-Za-z]+)\s+(IPv[46])\s+(\S+)\s+(\S+)\s+(TCP|UDP)\s+(\S+)(?:\s+\((LISTEN|UNCONN)\))?$/);
    const family = match?.[5];
    const protocol = normalizeSocketProtocol(match?.[8]);
    const isTcp = protocol === "tcp";
    if (!match || (isTcp && match[10] !== "LISTEN")) {
      rejected += 1;
      continue;
    }
    const local = parseAddressPort(match[9]);
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
  const census = finalizeCensus({
    records: entries,
    identity: (entry) => JSON.stringify([entry.protocol, entry.state, entry.command, entry.pid, entry.local_address, entry.local_port]),
    cap: limit,
    malformed: rejected,
  });
  const boundedEntries = attachCensusMetadata(census.records, { duplicate_count: census.duplicate_count });
  return { entries: boundedEntries, rejected, duplicate_count: census.duplicate_count, truncated: census.truncated };
}

export function parseMacLsofListeningSockets(stdout, { limit = 50 } = {}) {
  return parseMacLsofListeningSocketsDetailed(stdout, { limit }).entries;
}

async function collectDefaultRoutes(options = {}) {
  if (process.platform === "linux") {
    const command = await runFixedCommand("ip", ["route", "show", "default"], options);
    const routes = command.status === "ok" ? parseLinuxDefaultRoutes(command.stdout) : [];
    return {
      status: command.status === "ok" && routes.malformed_count === 0 && routes.duplicate_count === 0 ? "ok" : command.status === "ok" ? "partial" : command.status,
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
      status: command.status === "ok" && routes.malformed_count === 0 && routes.duplicate_count === 0 ? "ok" : command.status === "ok" ? "partial" : command.status,
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
      return { status: resolvers.malformed_count === 0 && resolvers.duplicate_count === 0 && !resolvers.truncated ? "ok" : "partial", resolvers, sources: ["/etc/resolv.conf"] };
    } catch (error) {
      return { status: "unable", resolvers: [], sources: ["/etc/resolv.conf"], error: error instanceof Error ? error.message : String(error) };
    }
  }
  if (process.platform === "darwin") {
    const command = await runFixedCommand("scutil", ["--dns"], { ...options, timeout: 2500, maxBuffer: 1024 * 512 });
    const resolvers = command.status === "ok" ? parseScutilDns(command.stdout) : [];
    return {
      status: command.status === "ok" && resolvers.malformed_count === 0 && resolvers.duplicate_count === 0 && !resolvers.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
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
      status: command.status === "ok" && sockets.rejected_count === 0 && sockets.duplicate_count === 0 && !sockets.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
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
      status: command.status === "ok" && detailed.rejected === 0 && detailed.duplicate_count === 0 && !detailed.truncated ? "ok" : command.status === "ok" ? "partial" : command.status,
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
