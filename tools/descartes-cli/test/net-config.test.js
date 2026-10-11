import assert from "node:assert/strict";
import test from "node:test";
import {
  choosePhysicalDefault,
  collectNetConfigEvidence,
  globalPrefix64,
  isTunnelInterface,
  parseIfconfigVerbose,
  parseIpAddrInet6,
  parseIpRouteDefault,
  parseNeighborMac,
  parseNetstatDefaultRoutes,
  parseResolvectlDns,
  parseScutilDnsForInterface,
  readNetConfig,
} from "../src/tools/net-config.js";
import { CONTEXT_KEY_BYTES, contextHmac } from "../src/context-key.js";
import { validateContextFact } from "../src/context-schemas.js";
import { factPointsFromNetConfigEvidence } from "../src/context-translators.js";

// Real outputs captured on the Darwin 25.2 dev VM (2026-10-11): an Ethernet en0 and a Tailscale utun4
// that also carries a default route and MagicDNS.
const NETSTAT_REAL = [
  "Routing tables",
  "",
  "Internet:",
  "Destination        Gateway            Flags               Netif Expire",
  "default            192.168.64.1       UGScg                 en0       ",
  "default            link#12            UCSIg               utun4       ",
  "127                127.0.0.1          UCS                   lo0       ",
].join("\n");
const IFCONFIG_REAL = [
  "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500",
  "\toptions=400<CHANNEL_IO>",
  "\tether b2:c8:d7:7c:51:4b",
  "\tinet6 fe80::cd1:461b:11ed:fb1b%en0 prefixlen 64 secured scopeid 0x6 ",
  "\tinet6 2001:db8:abcd:12:1c2:3ff:fe4:5 prefixlen 64 autoconf secured ",
  "\tinet6 2001:db8:abcd:12:aaaa::1 prefixlen 64 autoconf temporary ",
  "\tinet 192.168.64.6 netmask 0xffffff00 broadcast 192.168.64.255",
  "\ttype: Ethernet",
  "\tlink quality: 100 (good)",
].join("\n");
const SCUTIL_DNS_REAL = [
  "DNS configuration",
  "",
  "resolver #1",
  "  search domain[0] : tail1856e.ts.net",
  "  nameserver[0] : 100.100.100.100",
  "  if_index : 12 (utun4)",
  "",
  "resolver #2",
  "  nameserver[0] : 192.168.64.1",
  "  if_index : 6 (en0)",
  "  flags    : Request A records",
  "",
  "resolver #3",
  "  domain   : local",
  "  options  : mdns",
].join("\n");
const ARP_REAL = "? (192.168.64.1) at 1e:f6:4c:23:af:64 on en0 ifscope [ethernet]\n";

function scripted(map, calls = []) {
  return async (command, args = []) => {
    const key = [command, ...args].join(" ");
    calls.push(key);
    if (!(key in map)) return { status: "not_found_on_known_paths", availability: "not_found_on_known_paths", stdout: "" };
    return map[key];
  };
}
const ok = (stdout) => ({ status: "ok", stdout, stderr: "" });

test("C0.5 parsers (real darwin output): physical default route skips the tunnel; kind, global /64s, gateway MAC, en0-scoped resolvers without MagicDNS", () => {
  const routes = parseNetstatDefaultRoutes(NETSTAT_REAL);
  assert.deepEqual(routes, [{ gateway: "192.168.64.1", iface: "en0" }, { gateway: undefined, iface: "utun4" }]);
  assert.deepEqual(choosePhysicalDefault(routes), { state: "ok", iface: "en0", gateway: "192.168.64.1" });
  assert.deepEqual(choosePhysicalDefault([{ iface: "utun4" }]), { state: "ok", kind: "tunnel", tunnel_only: true });
  assert.deepEqual(choosePhysicalDefault([]), { state: "absent", kind: "none" });
  assert.deepEqual(parseIfconfigVerbose(IFCONFIG_REAL), { kind: "ethernet", prefixes: ["2001:db8:abcd:12::/64"] });
  assert.equal(parseIfconfigVerbose("\ttype: Wi-Fi\n").kind, "wifi");
  assert.equal(parseIfconfigVerbose("nothing").kind, "unknown");
  assert.equal(parseNeighborMac(ARP_REAL), "1e:f6:4c:23:af:64");
  assert.equal(parseNeighborMac("? (192.168.64.1) at (incomplete) on en0 ifscope [ethernet]"), undefined);
  assert.equal(parseNeighborMac("192.168.1.1 dev eth0 lladdr a:b:c:d:e:f REACHABLE"), "0a:0b:0c:0d:0e:0f");
  assert.deepEqual(parseScutilDnsForInterface(SCUTIL_DNS_REAL, "en0"), ["192.168.64.1"]);
  assert.deepEqual(parseScutilDnsForInterface(SCUTIL_DNS_REAL, "utun4"), [], "MagicDNS is never a resolver component");
  assert.ok(isTunnelInterface("utun4") && isTunnelInterface("wg0") && isTunnelInterface("tailscale0") && !isTunnelInterface("en0"));
});

test("C0.5 parsers (linux formats)", () => {
  assert.deepEqual(parseIpRouteDefault("default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600\ndefault dev wg0 scope link\n"), [
    { gateway: "192.168.1.1", iface: "wlp2s0" }, { gateway: undefined, iface: "wg0" },
  ]);
  assert.deepEqual(parseIpAddrInet6("    inet6 2a01:e0a:1:2:3:4:5:6/64 scope global dynamic mngtmpaddr\n    inet6 fd00::1/64 scope global\n"), ["2a01:e0a:1:2::/64"]);
  assert.deepEqual(parseResolvectlDns("Link 3 (wlp2s0): 192.168.1.1 fe80::1%3 100.100.100.100\n"), ["192.168.1.1", "fe80::1"]);
  assert.equal(globalPrefix64("fe80::1"), undefined);
  assert.equal(globalPrefix64("fd7a:115c:a1e0::1"), undefined, "ULA is not a router-advertised global prefix");
  assert.equal(globalPrefix64("not-an-address"), undefined);
});

test("C0.5 darwin collector: fixed argv per component, through the resolver; the tunnel default route is never the physical interface", async () => {
  const calls = [];
  const result = await readNetConfig({
    platform: "darwin",
    runFixedExecFile: scripted({
      "netstat -rn -f inet": ok(NETSTAT_REAL),
      "ifconfig -v en0": ok(IFCONFIG_REAL),
      "arp -n 192.168.64.1": ok(ARP_REAL),
      "ipconfig getoption en0 domain_name": { status: "error", code: 1, stdout: "", stderr: "" },
      "scutil --dns": ok(SCUTIL_DNS_REAL),
    }, calls),
  });
  assert.deepEqual(calls, ["netstat -rn -f inet", "ifconfig -v en0", "arp -n 192.168.64.1", "ipconfig getoption en0 domain_name", "scutil --dns"]);
  assert.equal(result.status, "ok");
  assert.deepEqual(result.route, { state: "ok", kind: "ethernet" });
  assert.deepEqual(result.components, {
    gateway_mac: { state: "ok", value: "1e:f6:4c:23:af:64" },
    ra_prefix: { state: "ok", value: "2001:db8:abcd:12::/64" },
    dhcp_domain: { state: "absent" },
    resolvers: { state: "ok", value: "192.168.64.1" },
  });
});

test("C0.5: a tunnel-only default route records kind tunnel and leaves the physical components not_applicable (never guessed)", async () => {
  const result = await readNetConfig({ platform: "darwin", runFixedExecFile: scripted({ "netstat -rn -f inet": ok("default link#12 UCSIg utun4\n") }) });
  assert.deepEqual(result.route, { state: "ok", kind: "tunnel" });
  for (const component of Object.values(result.components)) assert.equal(component.state, "not_applicable");
});

test("C0.5 linux collector: ip route / ip neigh / ip -6 addr / nmcli / resolvectl; kind from /sys; a missing nmcli is not_found, not absent", async () => {
  const result = await readNetConfig({
    platform: "linux",
    stat: async (p) => { if (p === "/sys/class/net/wlp2s0/wireless") return {}; throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); },
    readFile: async () => "1\n",
    runFixedExecFile: scripted({
      "ip route show default": ok("default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600\n"),
      "ip neigh show 192.168.1.1 dev wlp2s0": ok("192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"),
      "ip -6 addr show dev wlp2s0 scope global": ok(""),
      "resolvectl dns wlp2s0": ok("Link 3 (wlp2s0): 192.168.1.1\n"),
    }),
  });
  assert.deepEqual(result.route, { state: "ok", kind: "wifi" });
  assert.deepEqual(result.components.gateway_mac, { state: "ok", value: "aa:bb:cc:dd:ee:ff" });
  assert.deepEqual(result.components.ra_prefix, { state: "absent" });
  assert.deepEqual(result.components.dhcp_domain, { state: "not_found_on_known_paths" });
  assert.equal(result.status, "partial");
});

test("C0.5: a failing route read is the collector's state, never a fabricated 'no network'", async () => {
  const result = await readNetConfig({ platform: "darwin", runFixedExecFile: scripted({ "netstat -rn -f inet": { status: "untrusted_binary", availability: "untrusted_binary", stdout: "" } }) });
  assert.equal(result.status, "untrusted_binary");
  assert.equal(result.route.state, "untrusted_binary");
  const envelope = await collectNetConfigEvidence({ platform: "sunos" });
  assert.equal(envelope.id, "net-config");
  assert.equal(envelope.result.status, "not_applicable");
});

const KEY = Buffer.alloc(CONTEXT_KEY_BYTES, 3);
const TS = "2026-10-11T12:00:00.000Z";

function fingerprintOf(result, key = KEY) {
  const [point] = factPointsFromNetConfigEvidence([{ id: "net-config", status: "ok", result, observation: { start_ms: 1, end_ms: 2 } }], { ts: TS, hmacKey: key });
  assert.deepEqual(validateContextFact(point.fact_name, point.attributes), { ok: true }, JSON.stringify(point.attributes));
  return point;
}

const HOME_NET = {
  platform: "darwin",
  status: "ok",
  route: { state: "ok", kind: "wifi" },
  components: {
    gateway_mac: { state: "ok", value: "1e:f6:4c:23:af:64" },
    ra_prefix: { state: "ok", value: "2001:db8:abcd:12::/64" },
    dhcp_domain: { state: "ok", value: "home.example" },
    resolvers: { state: "ok", value: "192.168.64.1" },
  },
};

test("C0.5 translator: per-component availability and HMACs; the aggregate is a keyed, irreversible fingerprint", () => {
  const point = fingerprintOf(HOME_NET);
  assert.equal(point.fact_name, "net.config_fingerprint");
  assert.equal(point.attributes.components_ok, "5");
  assert.equal(point.attributes.gateway_mac_hmac, contextHmac(KEY, "net_gateway_mac", "1e:f6:4c:23:af:64"));
  assert.match(point.attributes.fingerprint_hmac, /^[0-9a-f]{16}$/);
  for (const raw of ["1e:f6:4c", "2001:db8", "home.example", "192.168.64.1"]) assert.ok(!JSON.stringify(point).includes(raw), raw);
  assert.equal(fingerprintOf(HOME_NET).attributes.fingerprint_hmac, point.attributes.fingerprint_hmac, "deterministic per install");
  assert.notEqual(fingerprintOf(HOME_NET, Buffer.alloc(CONTEXT_KEY_BYTES, 4)).attributes.fingerprint_hmac, point.attributes.fingerprint_hmac, "per-install key");
  const otherGateway = fingerprintOf({ ...HOME_NET, components: { ...HOME_NET.components, gateway_mac: { state: "ok", value: "00:11:22:33:44:55" } } });
  assert.notEqual(otherGateway.attributes.fingerprint_hmac, point.attributes.fingerprint_hmac, "a different gateway is a different configuration");
});

test("C0.5 translator: an absent component is 'none' and still fingerprints; a FAILED component makes the aggregate unknown; no key makes everything unknown", () => {
  const noRa = fingerprintOf({ ...HOME_NET, components: { ...HOME_NET.components, ra_prefix: { state: "absent" } } });
  assert.equal(noRa.attributes.ra_prefix_hmac, "none");
  assert.match(noRa.attributes.fingerprint_hmac, /^[0-9a-f]{16}$/);
  const arpFailed = fingerprintOf({ ...HOME_NET, components: { ...HOME_NET.components, gateway_mac: { state: "unable" } } });
  assert.equal(arpFailed.attributes.gateway_mac_hmac, "unknown");
  assert.equal(arpFailed.attributes.fingerprint_hmac, "unknown", "a failure is never folded into a configuration identity");
  const keyless = fingerprintOf(HOME_NET, null);
  assert.equal(keyless.attributes.fingerprint_hmac, "unknown");
  assert.equal(keyless.attributes.gateway_mac_hmac, "unknown");
});

test("real darwin host: the collector runs unprivileged and yields only closed, schema-valid states", { skip: process.platform !== "darwin" }, async () => {
  const result = await readNetConfig({ platform: "darwin" });
  // Any closed state is acceptable here (a CI image may resolve a binary as untrusted); the point is
  // that a real read never produces an out-of-schema value.
  assert.ok(["ok", "partial", "unable", "not_found_on_known_paths", "untrusted_binary", "missing_permission"].includes(result.status), JSON.stringify(result.route));
  fingerprintOf(result);
});
