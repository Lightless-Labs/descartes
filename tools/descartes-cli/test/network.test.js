import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeInterfaces,
  parseLinuxDefaultRoutes,
  parseLinuxListeningSockets,
  parseMacDefaultRoute,
  parseMacLsofListeningSocketsDetailed,
  parseMacLsofListeningSockets,
  parseResolvConf,
  parseScutilDns,
} from "../src/tools/network.js";

test("normalizeInterfaces returns bounded interface facts without MAC addresses", () => {
  const interfaces = normalizeInterfaces({
    lo: [{ family: "IPv4", address: "127.0.0.1", cidr: "127.0.0.1/8", internal: true, mac: "00:00:00:00:00:00" }],
    en0: [{ family: "IPv6", address: "fe80::1", cidr: "fe80::1/64", internal: false, scopeid: 4, mac: "aa:bb:cc:dd:ee:ff" }],
  });

  assert.deepEqual(interfaces, [
    { name: "en0", family: "IPv6", address: "fe80::1", cidr: "fe80::1/64", internal: false, scopeid: 4 },
    { name: "lo", family: "IPv4", address: "127.0.0.1", cidr: "127.0.0.1/8", internal: true, scopeid: undefined },
  ]);
  assert.equal(Object.hasOwn(interfaces[0], "mac"), false);
});

test("parseLinuxDefaultRoutes parses default route facts", () => {
  const routes = parseLinuxDefaultRoutes(`default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.42 metric 100\n10.0.0.0/24 dev wg0 proto kernel\n`);

  assert.deepEqual(routes, [{
    destination: "default",
    gateway: "192.168.1.1",
    interface: "eth0",
    source: "192.168.1.42",
    protocol: "dhcp",
    metric: 100,
    raw: "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.42 metric 100",
  }]);
});

test("parseLinuxDefaultRoutes accepts iproute2 route flags after key/value attributes", () => {
  const routes = parseLinuxDefaultRoutes(
    "default via 192.168.1.1 dev eth0 proto dhcp metric 100 dead onlink pervasive offload trap notify linkdown unresolved rt_offload rt_trap rt_offload_failed\n",
  );
  assert.equal(routes.length, 1);
  assert.equal(routes.malformed_count, 0);
});

test("parseMacDefaultRoute parses route -n get default output", () => {
  const routes = parseMacDefaultRoute(`   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,GLOBAL>\n`);

  assert.deepEqual(routes, [{
    destination: "default",
    gateway: "192.168.1.1",
    interface: "en0",
    flags: "<UP,GATEWAY,DONE,STATIC,GLOBAL>",
  }]);
});

test("DNS resolver parsers preserve duplicate rows and expose census metadata", () => {
  assert.deepEqual(parseResolvConf(`# comment\nnameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n`), [
    { address: "1.1.1.1", source: "/etc/resolv.conf" },
    { address: "1.1.1.1", source: "/etc/resolv.conf" },
    { address: "2606:4700:4700::1111", source: "/etc/resolv.conf" },
  ]);
  assert.equal(parseResolvConf("nameserver 1.1.1.1\nnameserver 1.1.1.1\n").duplicate_count, 1);

  assert.deepEqual(parseScutilDns(`resolver #1\n  nameserver[0] : 192.168.1.1\nresolver #2\n  nameserver[0] : 9.9.9.9\n  nameserver[1] : 9.9.9.9\n`), [
    { address: "192.168.1.1", source: "scutil --dns" },
    { address: "9.9.9.9", source: "scutil --dns" },
    { address: "9.9.9.9", source: "scutil --dns" },
  ]);
  assert.equal(parseScutilDns("resolver #1\nnameserver[0] : 9.9.9.9\nnameserver[1] : 9.9.9.9\n").duplicate_count, 1);
});

test("network populations preserve duplicate routes and sockets for census validation", () => {
  const routes = parseLinuxDefaultRoutes("default via 192.168.1.1 dev eth0 metric 100\ndefault via 192.168.1.1 dev eth0 metric 100\n");
  assert.equal(routes.length, 2);
  assert.equal(routes.duplicate_count, 1);

  const sockets = parseLinuxListeningSockets("tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n");
  assert.equal(sockets.length, 2);
  assert.equal(sockets.duplicate_count, 1);
});

test("network line parsers reject prefix-shaped suffixes and invalid values", () => {
  const routeJunk = parseLinuxDefaultRoutes("default via 192.168.1.1 dev eth0 metric 100 MALFORMED\n");
  assert.equal(routeJunk.length, 0);
  assert.equal(routeJunk.malformed_count, 1);
  const routeValueJunk = parseLinuxDefaultRoutes("default via NOT_AN_IP dev eth0 metric 100\n");
  assert.equal(routeValueJunk.length, 0);
  assert.equal(routeValueJunk.malformed_count, 1);

  const resolvJunk = parseResolvConf("nameserver 1.1.1.1 MALFORMED\n");
  assert.equal(resolvJunk.length, 0);
  assert.equal(resolvJunk.malformed_count, 1);
  const resolvValueJunk = parseResolvConf("nameserver NOT_AN_IP\n");
  assert.equal(resolvValueJunk.length, 0);
  assert.equal(resolvValueJunk.malformed_count, 1);

  const scutilJunk = parseScutilDns("resolver #1\nnameserver[0] : 1.1.1.1 MALFORMED\n");
  assert.equal(scutilJunk.length, 0);
  assert.equal(scutilJunk.malformed_count, 1);
  const scutilValueJunk = parseScutilDns("resolver #1\nnameserver[0] : NOT_AN_IP\n");
  assert.equal(scutilValueJunk.length, 0);
  assert.equal(scutilValueJunk.malformed_count, 1);

  const socketJunk = parseLinuxListeningSockets("tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:* MALFORMED\n");
  assert.equal(socketJunk.length, 0);
  assert.equal(socketJunk.rejected_count, 1);
  const socketValueJunk = parseLinuxListeningSockets("tcp LISTEN NOT_A_QUEUE 128 127.0.0.1:22 0.0.0.0:*\n");
  assert.equal(socketValueJunk.length, 0);
  assert.equal(socketValueJunk.rejected_count, 1);

  const macSocketJunk = parseMacLsofListeningSocketsDetailed(
    "COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nnode 1234 me 23u IPv4 0xabc 0t0 TCP 127.0.0.1:3000 (LISTEN) MALFORMED\n",
  );
  assert.equal(macSocketJunk.entries.length, 0);
  assert.equal(macSocketJunk.rejected, 1);
});

test("parseLinuxListeningSockets parses ss listener rows with address families", () => {
  const sockets = parseLinuxListeningSockets(`tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\n`, { limit: 3 });

  assert.deepEqual(sockets, [
    { protocol: "tcp", state: "LISTEN", local_address: "127.0.0.1", local_port: 5432, raw: "tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*" },
    { protocol: "udp", state: "UNCONN", local_address: "0.0.0.0", local_port: 5353, raw: "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*" },
    { protocol: "tcp6", state: "LISTEN", local_address: "[::]", local_port: 22, raw: "tcp LISTEN 0 128 [::]:22 [::]:*" },
  ]);
});

test("parseMacLsofListeningSockets parses bounded lsof listener rows", () => {
  const sockets = parseMacLsofListeningSockets(`COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nnode     1234 me     23u  IPv4 0xabc              0t0  TCP 127.0.0.1:3000 (LISTEN)\nControl  431 me     10u  IPv6 0xdef              0t0  TCP *:5000 (LISTEN)\n`, { limit: 10 });

  assert.deepEqual(sockets, [
    { protocol: "tcp", state: "LISTEN", command: "node", pid: 1234, local_address: "127.0.0.1", local_port: 3000 },
    { protocol: "tcp6", state: "LISTEN", command: "Control", pid: 431, local_address: "*", local_port: 5000 },
  ]);
});

test("parseMacLsofListeningSockets canonicalizes an IPv6 wildcard and skips valid portless UDP wildcard rows", () => {
  const sockets = parseMacLsofListeningSockets(`COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node     1234 me     23u  IPv6 0xabc              0t0  TCP [::]:3000 (LISTEN)
mdns     4321 me     24u  IPv6 0xdef              0t0  UDP *:*
`, { limit: 10 });

  assert.deepEqual(sockets, [
    { protocol: "tcp6", state: "LISTEN", command: "node", pid: 1234, local_address: "[::]", local_port: 3000 },
  ]);
});
