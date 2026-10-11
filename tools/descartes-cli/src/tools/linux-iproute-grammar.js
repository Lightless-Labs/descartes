import { isIP } from "node:net";

const ROUTE_FLAGS = new Set([
  "dead", "onlink", "pervasive", "offload", "trap", "notify", "linkdown", "unresolved",
  "rt_offload", "rt_trap", "rt_offload_failed",
]);

const ROUTE_KEYS = new Set([
  "via", "dev", "proto", "scope", "src", "metric", "mtu", "advmss", "pref", "table", "realm", "realms",
  "from", "nhid", "as", "tos", "mark", "uid", "expires", "error", "users", "used", "age", "ipid", "ts", "tsage",
  "window", "rtt", "rttvar", "ssthresh", "cwnd", "reordering", "hoplimit", "initcwnd", "rto_min", "initrwnd",
  "quickack", "congctl", "fastopen_no_cookie", "iif", "ttl-propogate", "cache",
]);

const ROUTE_NUMERIC_KEYS = new Set([
  "metric", "mtu", "advmss", "nhid", "uid", "error", "users", "used", "window", "ssthresh",
  "cwnd", "reordering", "hoplimit", "initcwnd", "initrwnd",
]);

const ROUTE_TIME_KEYS = new Set(["rtt", "rttvar", "rto_min", "expires", "age", "tsage"]);
const ROUTE_WORD_RE = /^[A-Za-z][A-Za-z0-9_.-]*$/;
const ROUTE_IFACE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;
const ROUTE_HEX_RE = /^0x[0-9A-Fa-f]+$/;

function unsigned(value, max = 0xffffffff) {
  if (!/^\d+$/.test(value)) return false;
  const number = Number(value);
  return Number.isSafeInteger(number) && number <= max;
}

function address(value, prefix = false) {
  if (typeof value !== "string") return false;
  const [host, length] = value.split("/");
  if (!prefix && length !== undefined) return false;
  if (isIP(host) === 0) return false;
  if (length === undefined) return true;
  return unsigned(length, isIP(host) === 4 ? 32 : 128);
}

function routeValueValid(key, value) {
  if (!value || ROUTE_KEYS.has(value) || ROUTE_FLAGS.has(value)) return false;
  if (key === "via") return address(value);
  if (key === "dev" || key === "iif") return ROUTE_IFACE_RE.test(value);
  if (key === "src" || key === "from") return address(value, true);
  if (key === "proto") return unsigned(value, 255) || ROUTE_WORD_RE.test(value);
  if (key === "scope") return unsigned(value, 255) || ROUTE_WORD_RE.test(value);
  if (key === "table") return unsigned(value, 0xffffffff) || ROUTE_WORD_RE.test(value);
  if (key === "pref") return /^(?:low|medium|high)$/.test(value) || unsigned(value, 255);
  if (key === "tos") return unsigned(value, 255) || ROUTE_HEX_RE.test(value) || ROUTE_WORD_RE.test(value);
  if (key === "realm" || key === "realms") return /^(?:0x[0-9A-Fa-f]+|[A-Za-z0-9_.-]+)(?:\/(?:0x[0-9A-Fa-f]+|[A-Za-z0-9_.-]+))?$/.test(value);
  if (ROUTE_NUMERIC_KEYS.has(key)) return unsigned(value);
  if (ROUTE_TIME_KEYS.has(key)) return /^\d+(?:\.\d+)?(?:s|ms|sec|usec)$/.test(value)
    || (key === "expires" && /^-\d+sec$/.test(value))
    || unsigned(value);
  if (key === "mark" || key === "ipid" || key === "ts") return unsigned(value) || ROUTE_HEX_RE.test(value);
  if (key === "quickack" || key === "fastopen_no_cookie") return /^(?:0|1)$/.test(value);
  if (key === "congctl") return ROUTE_WORD_RE.test(value);
  if (key === "ttl-propogate") return /^(?:enabled|disabled)$/.test(value);
  if (key === "nhid") return unsigned(value);
  return false;
}

/** Parse one `ip route show default` line using tokens emitted by iproute2's print_route(). */
export function parseLinuxIpRouteLine(line) {
  if (typeof line !== "string") return undefined;
  const parts = line.trim().split(/\s+/);
  if (!parts.length || parts[0] !== "default") return undefined;

  const seen = new Set();
  const result = { gateway: undefined, interfaceName: undefined, source: undefined, protocol: undefined, metric: undefined };
  for (let index = 1; index < parts.length;) {
    const token = parts[index];
    if (ROUTE_FLAGS.has(token)) {
      if (seen.has(token)) return undefined;
      seen.add(token);
      index += 1;
      continue;
    }
    if (token === "features") {
      if (seen.has(token)) return undefined;
      seen.add(token);
      let featureCount = 0;
      while (["ecn", "tcp_usec_ts"].includes(parts[index + 1])) {
        featureCount += 1;
        index += 1;
      }
      if (!featureCount && !ROUTE_HEX_RE.test(parts[index + 1] ?? "")) return undefined;
      index += featureCount ? 1 : 2;
      continue;
    }
    if (!ROUTE_KEYS.has(token) || seen.has(token)) return undefined;
    seen.add(token);
    if (token === "cache") {
      const cache = parts[index + 1];
      if (cache !== undefined && !/^<[^<>]+>$/.test(cache)) return undefined;
      index += cache === undefined ? 1 : 2;
      continue;
    }
    if (token === "as") {
      if (parts[index + 1] === "to") index += 1;
      if (!address(parts[index + 1], true)) return undefined;
      index += 2;
      continue;
    }
    if (token === "via" && ["inet", "inet6", "mpls", "bridge", "link"].includes(parts[index + 1])) index += 1;
    const value = parts[index + 1];
    if (!routeValueValid(token, value)) return undefined;
    if (token === "via") result.gateway = value;
    if (token === "dev") result.interfaceName = value;
    if (token === "src") result.source = value;
    if (token === "proto") result.protocol = value;
    if (token === "metric") result.metric = Number(value);
    index += 2;
  }
  return result;
}
