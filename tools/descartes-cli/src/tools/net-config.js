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
//   - the IPv6 router-advertised global /64 prefixes on that interface;
//   - the DHCP-provided domain (macOS `ipconfig getoption <if> domain_name`; Linux via nmcli when
//     installed, else not_found_on_known_paths);
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
  const prefixes = new Set();
  for (const match of text.matchAll(/^\s*inet6\s+([0-9a-fA-F:]+)(?:%\S+)?\s+prefixlen\s+([0-9]+)/gm)) {
    const prefix = globalPrefix64(match[1]);
    if (prefix) prefixes.add(prefix);
  }
  return { kind, prefixes: [...prefixes].sort() };
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

/** The /64 of a GLOBAL unicast IPv6 address (2000::/3), else undefined (link-local, ULA, loopback). */
export function globalPrefix64(address) {
  const parts = expandIpv6(String(address ?? ""));
  if (!parts || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return undefined;
  const first = parseInt(parts[0], 16);
  if ((first & 0xe000) !== 0x2000) return undefined;
  return `${parts.slice(0, 4).map((part) => parseInt(part, 16).toString(16)).join(":")}::/64`;
}

/** `ip -6 addr show dev <if> scope global` -> sorted unique global /64 prefixes. */
export function parseIpAddrInet6(stdout) {
  const prefixes = new Set();
  for (const match of String(stdout ?? "").matchAll(/inet6\s+([0-9a-fA-F:]+)\/[0-9]+/g)) {
    const prefix = globalPrefix64(match[1]);
    if (prefix) prefixes.add(prefix);
  }
  return [...prefixes].sort();
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
  const raPrefix = ifconfig ? listComponent(ifconfig.prefixes) : { state: failureState(ifconfigProbe) };

  const domainProbe = await runExec("ipconfig", ["getoption", iface, "domain_name"], probeOptions(options));
  let dhcpDomain;
  const domain = String(domainProbe.stdout ?? "").trim();
  if (domainProbe.status === "ok") dhcpDomain = DOMAIN_RE.test(domain) ? { state: "ok", value: domain.toLowerCase() } : domain ? { state: "unable" } : { state: "absent" };
  // `ipconfig getoption` exits 1 with no output when the lease carries no such option.
  else if (domainProbe.code === 1 && !domain && !isBinaryNotFound(domainProbe) && !isBinaryUntrusted(domainProbe)) dhcpDomain = { state: "absent" };
  else dhcpDomain = { state: failureState(domainProbe) };

  const dnsProbe = await runExec("scutil", ["--dns"], probeOptions(options));
  const resolvers = dnsProbe.status === "ok" ? listComponent(parseScutilDnsForInterface(dnsProbe.stdout, iface)) : { state: failureState(dnsProbe) };
  return { route, components: { gateway_mac: gatewayMac, ra_prefix: raPrefix, dhcp_domain: dhcpDomain, resolvers } };
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
  const raPrefix = addr.status === "ok" ? listComponent(parseIpAddrInet6(addr.stdout)) : { state: failureState(addr) };

  const nmcli = await runExec("nmcli", ["-g", "IP4.DOMAIN", "device", "show", iface], probeOptions(options));
  let dhcpDomain;
  if (nmcli.status !== "ok") dhcpDomain = { state: failureState(nmcli) };
  else {
    const domains = String(nmcli.stdout ?? "").split(/[\n|]/).map((d) => d.trim().toLowerCase()).filter(Boolean);
    dhcpDomain = domains.every((d) => DOMAIN_RE.test(d)) ? listComponent([...new Set(domains)].sort()) : { state: "unable" };
  }
  const dns = await runExec("resolvectl", ["dns", iface], probeOptions(options));
  const resolvers = dns.status === "ok" ? listComponent(parseResolvectlDns(dns.stdout)) : { state: failureState(dns) };
  return { route, components: { gateway_mac: gatewayMac, ra_prefix: raPrefix, dhcp_domain: dhcpDomain, resolvers } };
}

export async function readNetConfig(options = {}) {
  const platform = options.platform ?? process.platform;
  const runExec = options.runFixedExecFile ?? defaultRunFixedExecFile;
  let read;
  if (platform === "darwin") read = await readDarwin(runExec, options);
  else if (platform === "linux") read = await readLinux(runExec, options);
  else read = { route: { state: "not_applicable", kind: "unknown" } };
  const components = read.components ?? {
    gateway_mac: NOT_APPLICABLE, ra_prefix: NOT_APPLICABLE, dhcp_domain: NOT_APPLICABLE, resolvers: NOT_APPLICABLE,
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
