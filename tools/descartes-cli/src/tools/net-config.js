// Context plan C0.5 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, §4.2; Opus M5,
// Astra 14): the network-configuration fingerprint collector, renamed from "location" because it is
// an observed configuration, not a place.
//
// READ ONLY, fixed argv, no shell, every binary through the binary resolver. The only values that
// reach an argv slot from output (an interface name, a gateway IPv4 address) are validated against
// strict patterns first.
//
// Components, each with its own state (ok / absent / unable / not_applicable / not_found_on_known_paths
// / untrusted_binary / missing_permission):
//   - the PHYSICAL default-route interface's kind (a tunnel default route -- utun, wg, tun, ppp,
//     tailscale... -- is skipped; if only tunnels carry a default route the kind is `tunnel` and the
//     physical components are not_applicable: the physical interface is never guessed);
//   - the gateway's link-layer address (macOS `arp -n <gw>`, Linux `ip neigh show <gw> dev <if>`);
//     `absent` only when the default route has no gateway; an unresolved entry is `unable`;
//   - the IPv6 router-advertised global prefixes on that interface (macOS `ndp -p`, Linux `ip -6
//     addr` lines positively marked with `proto ra` and `dynamic`/`mngtmpaddr`);
//   - the DHCP-provided domain (macOS `ipconfig getoption <if> domain_name`; Linux from the
//     explicit `DHCP4.OPTION.domain_name` NetworkManager lease field, else unable);
//   - the resolvers scoped to that interface only (macOS `scutil --dns` if_index scoping; Linux
//     `resolvectl dns <if>`), never MagicDNS (100.100.100.100) or a tunnel's resolvers.
// Raw values stay in memory; context-translators.js HMACs them with the per-install key.

import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isBinaryNotFound, isBinaryUntrusted, runResolvedExecFile } from "./binary-resolver.js";
import { evidenceEnvelope, timedEnvelope } from "./envelope.js";

const execFileAsync = promisify(execFile);

const IFACE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;
const IPV4_RE = /^(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$/;
const MAC_RE = /^[0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5}$/;
const DOMAIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})$/;
const TUNNEL_IFACE_RE = /^(utun|ipsec|ppp|tun|tap|wg|gif|stf|tailscale|zt|vpn|nordlynx|proton)/;
const MAGIC_DNS = new Set(["100.100.100.100", "fd7a:115c:a1e0::53"]);

async function defaultRunFixedExecFile(command, args, options = {}) {
  return runResolvedExecFile(command, args, {
    ...options,
    timeout: options.timeout ?? 3000,
    maxBuffer: options.maxBuffer ?? 512 * 1024,
    execFileAsync,
  });
}

function probeOptions(options) {
  const { runFixedExecFile: _drop, ...resolverOptions } = options;
  return resolverOptions;
}

function failureState(probe) {
  if (isBinaryNotFound(probe)) return "not_found_on_known_paths";
  if (isBinaryUntrusted(probe)) return "untrusted_binary";
  const text = `${probe?.stderr ?? ""}`.toLowerCase();
  if (probe?.code === "EACCES" || probe?.code === "EPERM" || /permission denied|operation not permitted/.test(text)) return "missing_permission";
  return "unable";
}

const NOT_APPLICABLE = Object.freeze({ state: "not_applicable" });

export function isTunnelInterface(iface) {
  return TUNNEL_IFACE_RE.test(String(iface ?? ""));
}

/** `netstat -rn -f inet` -> [{ gateway, iface }] for every default route, in table order. */
export function parseNetstatDefaultRoutes(stdout) {
  const routes = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const tokens = rawLine.trim().split(/\s+/);
    if (tokens[0] !== "default" || tokens.length < 4) continue;
    const iface = tokens[3];
    if (!IFACE_RE.test(iface)) continue;
    routes.push({ gateway: IPV4_RE.test(tokens[1]) ? tokens[1] : undefined, iface });
  }
  return routes;
}

/** `ip route show default` -> [{ gateway, iface }]. */
export function parseIpRouteDefault(stdout) {
  const routes = [];
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith("default")) continue;
    const dev = /\bdev\s+(\S+)/.exec(line)?.[1];
    const via = /\bvia\s+(\S+)/.exec(line)?.[1];
    if (!dev || !IFACE_RE.test(dev)) continue;
    routes.push({ gateway: via && IPV4_RE.test(via) ? via : undefined, iface: dev });
  }
  return routes;
}

/** The first default route on a non-tunnel interface; `tunnel_only` when every default is a tunnel. */
export function choosePhysicalDefault(routes) {
  if (!routes.length) return { state: "absent", kind: "none" };
  const physical = routes.find((route) => !isTunnelInterface(route.iface));
  if (!physical) return { state: "ok", kind: "tunnel", tunnel_only: true };
  return { state: "ok", iface: physical.iface, gateway: physical.gateway };
}

/** `ifconfig -v <if>`: "type: Wi-Fi|Ethernet|Cellular|..." and global inet6 addresses. */
export function parseIfconfigVerbose(stdout) {
  const text = String(stdout ?? "");
  const type = /^\s*type:\s*(.+?)\s*$/m.exec(text)?.[1];
  const kind = !type ? "unknown"
    : /wi-?fi|802\.11|airport/i.test(type) ? "wifi"
      : /^ethernet$/i.test(type) ? "ethernet"
        : /cellular|wwan/i.test(type) ? "cellular"
          : /bridge/i.test(type) ? "bridge"
            : /loopback/i.test(type) ? "loopback"
              : "other";
  return { kind, prefixes: [] };
}

function expandIpv6(address) {
  const [head, tail] = address.toLowerCase().split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail !== undefined && tail !== "" ? tail.split(":") : [];
  if (address.includes("::")) {
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return undefined;
    return [...headParts, ...Array(missing).fill("0"), ...tailParts];
  }
  return headParts.length === 8 ? headParts : undefined;
}

function canonicalIpv6Prefix(address, prefixLength) {
  const parts = expandIpv6(String(address ?? ""));
  if (!parts || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return undefined;
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 128) return undefined;
  const masked = parts.map((part, index) => {
    const bits = Math.max(0, Math.min(16, prefixLength - index * 16));
    const mask = bits === 0 ? 0 : (0xffff << (16 - bits)) & 0xffff;
    return parseInt(part, 16) & mask;
  });
  const words = masked.map((word) => word.toString(16));
  let bestStart = -1;
  let bestLength = 1;
  for (let start = 0; start < words.length;) {
    if (words[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < words.length && words[end] === "0") end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const rendered = bestStart >= 0
    ? `${words.slice(0, bestStart).join(":")}::${words.slice(bestStart + bestLength).join(":")}`
    : words.join(":");
  return `${rendered || "::"}/${prefixLength}`;
}

function isGlobalIpv6(address) {
  const parts = expandIpv6(String(address ?? ""));
  if (!parts || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return false;
  return (parseInt(parts[0], 16) & 0xe000) === 0x2000;
}

/** The observed /64 of a GLOBAL unicast IPv6 address, retained for compatibility callers. */
export function globalPrefix64(address) {
  return isGlobalIpv6(address) ? canonicalIpv6Prefix(address, 64) : undefined;
}

/**
 * `ip -6 addr show dev <if> scope global` -> observed RA prefixes. Static/global addresses are
 * deliberately unable rather than converted to a guessed /64.
 */
export function parseLinuxRouterAdvertisementPrefixes(stdout) {
  const prefixes = new Set();
  let sawGlobalAddress = false;
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const match = /\binet6\s+([^\s/]+)\/(\d+)\s+(.+)$/.exec(rawLine.trim());
    if (!match) continue;
    const [, address, lengthText, flags] = match;
    const prefixLength = Number(lengthText);
    if (!isGlobalIpv6(address) || !Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 128) continue;
    sawGlobalAddress = true;
    if (/\bproto\s+ra\b/.test(flags) && /\b(?:dynamic|mngtmpaddr)\b/.test(flags)) {
      const prefix = canonicalIpv6Prefix(address, prefixLength);
      if (prefix) prefixes.add(prefix);
    }
  }
  if (prefixes.size > 0) return { state: "ok", prefixes: [...prefixes].sort() };
  return { state: sawGlobalAddress ? "unable" : "absent", prefixes: [] };
}

/** `ndp -p` -> sorted unique global prefixes for the selected interface, preserving /len. */
export function parseNdpRouterAdvertisementPrefixes(stdout, iface) {
  const prefixes = new Set();
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const match = /^\s*([^\s/]+)\/(\d+)\s+if=([^\s]+)/.exec(rawLine);
    if (!match || match[3] !== iface) continue;
    const address = match[1];
    const prefixLength = Number(match[2]);
    if (!isGlobalIpv6(address)) continue;
    const prefix = canonicalIpv6Prefix(address, prefixLength);
    if (prefix) prefixes.add(prefix);
  }
  return [...prefixes].sort();
}

/** `ip -6 addr show dev <if> scope global` compatibility wrapper. */
export function parseIpAddrInet6(stdout) {
  return parseLinuxRouterAdvertisementPrefixes(stdout).prefixes;
}

/** `arp -n <gw>` / `ip neigh show <gw> dev <if>` -> the lowercased MAC, or undefined (incomplete). */
export function parseNeighborMac(stdout) {
  const text = String(stdout ?? "");
  const match = /\bat\s+([0-9A-Fa-f:]{11,17})\b/.exec(text) ?? /\blladdr\s+([0-9A-Fa-f:]{11,17})\b/.exec(text);
  return match && MAC_RE.test(match[1]) ? match[1].toLowerCase().split(":").map((p) => p.padStart(2, "0")).join(":") : undefined;
}

/** `scutil --dns` -> nameservers of the resolvers scoped to `iface` (if_index : N (iface)), MagicDNS excluded. */
export function parseScutilDnsForInterface(stdout, iface) {
  const servers = new Set();
  for (const block of String(stdout ?? "").split(/\n(?=resolver #)/)) {
    const scope = /if_index\s*:\s*[0-9]+\s*\(([^)]+)\)/.exec(block)?.[1];
    if (scope !== iface) continue;
    for (const match of block.matchAll(/nameserver\[[0-9]+\]\s*:\s*(\S+)/g)) {
      if (!MAGIC_DNS.has(match[1])) servers.add(match[1]);
    }
  }
  return [...servers].sort();
}

/** `resolvectl dns <if>` -> "Link 2 (eth0): 1.1.1.1 9.9.9.9" -> sorted servers, MagicDNS excluded. */
export function parseResolvectlDns(stdout) {
  const servers = new Set();
  for (const rawLine of String(stdout ?? "").split("\n")) {
    const colon = rawLine.indexOf("):");
    if (colon < 0) continue;
    for (const token of rawLine.slice(colon + 2).trim().split(/\s+/)) {
      const server = token.replace(/%.*$/, "").replace(/#.*$/, "");
      if (server && !MAGIC_DNS.has(server)) servers.add(server);
    }
  }
  return [...servers].sort();
}

function listComponent(values, state = "ok") {
  return values.length > 0 ? { state, value: values.join(",") } : { state: "absent" };
}

function parseNmcliDomains(stdout, { lease = false } = {}) {
  const values = [];
  for (const rawLine of String(stdout ?? "").split(/[\n|]/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const value = lease ? /^domain_name\s*=\s*(.*)$/i.exec(line)?.[1] : line;
    if (value === undefined) continue;
    for (const domain of value.split(/[,\s]+/).map((item) => item.trim().toLowerCase()).filter(Boolean)) {
      if (DOMAIN_RE.test(domain)) values.push(domain);
    }
  }
  return [...new Set(values)].sort();
}

async function readDarwin(runExec, options) {
  const routesProbe = await runExec("netstat", ["-rn", "-f", "inet"], probeOptions(options));
  if (routesProbe.status !== "ok") return { route: { state: failureState(routesProbe), kind: "unknown" } };
  const chosen = choosePhysicalDefault(parseNetstatDefaultRoutes(routesProbe.stdout));
  if (chosen.state !== "ok" || chosen.tunnel_only) return { route: chosen };
  const { iface, gateway } = chosen;
  const ifconfigProbe = await runExec("ifconfig", ["-v", iface], probeOptions(options));
  const ifconfig = ifconfigProbe.status === "ok" ? parseIfconfigVerbose(ifconfigProbe.stdout) : undefined;
  const route = { state: "ok", kind: ifconfig?.kind ?? "unknown", iface };

  let gatewayMac;
  if (!gateway) gatewayMac = { state: "absent" };
  else {
    const arp = await runExec("arp", ["-n", gateway], probeOptions(options));
    const mac = arp.status === "ok" ? parseNeighborMac(arp.stdout) : undefined;
    // C0 review M6(a): the gateway exists, so a missing or incomplete neighbour entry (a cache miss
    // right after wake) is an unread value, never "absent".
    gatewayMac = arp.status !== "ok" ? { state: failureState(arp) } : mac ? { state: "ok", value: mac } : { state: "unable" };
  }
  const ndpProbe = await runExec("ndp", ["-p"], probeOptions(options));
  const raPrefix = ndpProbe.status === "ok"
    ? listComponent(parseNdpRouterAdvertisementPrefixes(ndpProbe.stdout, iface))
    : { state: failureState(ndpProbe) };

  const domainProbe = await runExec("ipconfig", ["getoption", iface, "domain_name"], probeOptions(options));
  let dhcpDomain;
  const domain = String(domainProbe.stdout ?? "").trim();
  if (domainProbe.status === "ok") dhcpDomain = DOMAIN_RE.test(domain) ? { state: "ok", value: domain.toLowerCase() } : domain ? { state: "unable" } : { state: "absent" };
  // `ipconfig getoption` exits 1 with no output when the lease carries no such option.
  else if (domainProbe.code === 1 && !domain && !isBinaryNotFound(domainProbe) && !isBinaryUntrusted(domainProbe)) dhcpDomain = { state: "absent" };
  else dhcpDomain = { state: failureState(domainProbe) };

  const dnsProbe = await runExec("scutil", ["--dns"], probeOptions(options));
  const resolvers = dnsProbe.status === "ok" ? listComponent(parseScutilDnsForInterface(dnsProbe.stdout, iface)) : { state: failureState(dnsProbe) };
  return {
    route,
    components: {
      gateway_mac: gatewayMac,
      ra_prefix: raPrefix,
      dhcp_domain: dhcpDomain,
      configured_search_domain: { state: "not_applicable" },
      resolvers,
    },
  };
}

async function linuxKind(iface, readFile, stat) {
  const base = `/sys/class/net/${iface}`;
  try {
    await stat(`${base}/wireless`);
    return "wifi";
  } catch { /* not wireless */ }
  try {
    await stat(`${base}/bridge`);
    return "bridge";
  } catch { /* not a bridge */ }
  try {
    const type = Number(String(await readFile(`${base}/type`, "utf8")).trim());
    if (type === 1) return "ethernet";
    if (type === 772) return "loopback";
    if (type === 65534) return "tunnel";
    if (Number.isInteger(type)) return "other";
  } catch { /* unreadable */ }
  return "unknown";
}

async function readLinux(runExec, options) {
  const readFile = options.readFile ?? fs.readFile;
  const stat = options.stat ?? fs.stat;
  const routesProbe = await runExec("ip", ["route", "show", "default"], probeOptions(options));
  if (routesProbe.status !== "ok") return { route: { state: failureState(routesProbe), kind: "unknown" } };
  const chosen = choosePhysicalDefault(parseIpRouteDefault(routesProbe.stdout));
  if (chosen.state !== "ok" || chosen.tunnel_only) return { route: chosen };
  const { iface, gateway } = chosen;
  const route = { state: "ok", kind: await linuxKind(iface, readFile, stat), iface };

  let gatewayMac;
  if (!gateway) gatewayMac = { state: "absent" };
  else {
    const neigh = await runExec("ip", ["neigh", "show", gateway, "dev", iface], probeOptions(options));
    const mac = neigh.status === "ok" ? parseNeighborMac(neigh.stdout) : undefined;
    // C0 review M6(a): empty output, INCOMPLETE or FAILED for an existing gateway is unread, not absent.
    gatewayMac = neigh.status !== "ok" ? { state: failureState(neigh) } : mac ? { state: "ok", value: mac } : { state: "unable" };
  }
  const addr = await runExec("ip", ["-6", "addr", "show", "dev", iface, "scope", "global"], probeOptions(options));
  const raPrefixes = addr.status === "ok" ? parseLinuxRouterAdvertisementPrefixes(addr.stdout) : undefined;
  const raPrefix = addr.status !== "ok" ? { state: failureState(addr) } : raPrefixes.state === "ok" ? listComponent(raPrefixes.prefixes) : { state: raPrefixes.state };

  const configuredProbe = await runExec("nmcli", ["-g", "IP4.DOMAIN", "device", "show", iface], probeOptions(options));
  const configuredSearchDomain = configuredProbe.status === "ok"
    ? listComponent(parseNmcliDomains(configuredProbe.stdout))
    : { state: failureState(configuredProbe) };
  // IP4.DOMAIN is NetworkManager's effective configuration, not lease provenance. Read the
  // DHCP option namespace separately; an IP4.DOMAIN value must never be copied into dhcp_domain.
  const dhcpProbe = await runExec("nmcli", ["-g", "DHCP4.OPTION", "device", "show", iface], probeOptions(options));
  const dhcpDomain = dhcpProbe.status === "ok"
    ? listComponent(parseNmcliDomains(dhcpProbe.stdout, { lease: true }))
    : { state: failureState(dhcpProbe) };
  const dns = await runExec("resolvectl", ["dns", iface], probeOptions(options));
  const resolvers = dns.status === "ok" ? listComponent(parseResolvectlDns(dns.stdout)) : { state: failureState(dns) };
  return {
    route,
    components: {
      gateway_mac: gatewayMac,
      ra_prefix: raPrefix,
      dhcp_domain: dhcpDomain,
      configured_search_domain: configuredSearchDomain,
      resolvers,
    },
  };
}

export async function readNetConfig(options = {}) {
  const platform = options.platform ?? process.platform;
  const runExec = options.runFixedExecFile ?? defaultRunFixedExecFile;
  let read;
  if (platform === "darwin") read = await readDarwin(runExec, options);
  else if (platform === "linux") read = await readLinux(runExec, options);
  else read = { route: { state: "not_applicable", kind: "unknown" } };
  const components = read.components ?? {
    gateway_mac: NOT_APPLICABLE,
    ra_prefix: NOT_APPLICABLE,
    dhcp_domain: NOT_APPLICABLE,
    configured_search_domain: NOT_APPLICABLE,
    resolvers: NOT_APPLICABLE,
  };
  const states = [read.route.state, ...Object.values(components).map((c) => c.state)];
  const status = read.route.state === "not_applicable" ? "not_applicable"
    : !["ok", "absent"].includes(read.route.state) ? read.route.state
      : states.every((state) => ["ok", "absent", "not_applicable"].includes(state)) ? "ok" : "partial";
  return { platform, status, route: { state: read.route.state, kind: read.route.kind ?? "unknown" }, components };
}

export async function collectNetConfigEvidence(options = {}) {
  return timedEnvelope(async () => readNetConfig(options), (result) => evidenceEnvelope({
    id: "net-config",
    status: result.status === "ok" ? "ok" : result.status === "partial" ? "warning" : "unable",
    source: "net_config",
    result,
    confidence: result.status === "ok" ? 1 : result.status === "partial" ? 0.5 : 0,
    reviewHint: result.status === "untrusted_binary" ? "untrusted_binary" : "none",
    tool: "collect_net_config",
    target: "default_route",
  }));
}
