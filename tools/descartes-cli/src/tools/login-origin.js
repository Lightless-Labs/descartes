// Context plan C0.4 (docs/plans/2026-10-06-context-aware-learned-baselines.md §3, Opus M3, Astra 12):
// login-origin classification, shared by the login-sessions context collector and the incumbent
// peer collector (vpn-peer-status.js), so `(:0)`, `(:pts/3:S.0)` and `(tmux(123).%0)` stop being
// read as remote hosts.
//
// Pure, closed, explicit patterns only. These are FORMAT facts about what utmp/wtmp writers put in
// the host field (an X display, a screen/tmux attachment tag, mosh's server tag), not claims about
// what is normal on a host: nothing here scores, suppresses or explains anything.

// Explicit local-host patterns for the who/last host field.
const X_DISPLAY_RE = /^:[0-9]+(?:\.[0-9]+)?$/; // a bare X display: ":0", ":1.0"
const SCREEN_TAG_RE = /^:?pts\/[0-9]+:S\.[0-9]+$/; // GNU screen: ":pts/3:S.0"
const TMUX_TAG_RE = /^tmux\([0-9]+\)\.%[0-9]+$/; // tmux: "tmux(1234).%0"
const MOSH_TAG_RE = /^mosh \[[0-9]+\]$/; // mosh-server: "mosh [1234]" (the remote host is not recorded)

const WEEKDAYS = new Set(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]);
const MONTHS = new Set(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]);

/** True when `token` + `next` start a `last` date column ("Fri Sep"), i.e. the host column is empty. */
export function isLastDateStart(token, next) {
  return WEEKDAYS.has(token) && MONTHS.has(next);
}

export function ttyClassOf(tty) {
  const value = typeof tty === "string" ? tty.trim() : "";
  if (!value) return "none";
  if (value === "console") return "console";
  if (/^ttys[0-9]+$/.test(value)) return "ttys";
  if (/^pts\/[0-9]+$/.test(value)) return "pts";
  if (/^tty[0-9A-Za-z]*$/.test(value)) return "tty";
  if (/^:[0-9]+(?:\.[0-9]+)?$/.test(value)) return "display";
  return "unknown";
}

/**
 * Classifies one utmp/wtmp row from its tty and its host field (the who parenthetical or the last
 * host column; undefined/empty when the row has none). Returns { origin_class, remote_host } where
 * remote_host is the raw host for a remote login (to be HMAC'd by the caller) and undefined
 * otherwise. Origin classes: console, local_tty, local_display, remote, remote_mosh, unknown.
 */
export function classifyLoginOrigin({ tty, host } = {}) {
  const ttyClass = ttyClassOf(tty);
  const value = typeof host === "string" ? host.trim() : "";
  if (!value || value === "-") {
    if (ttyClass === "console") return { origin_class: "console", remote_host: undefined };
    if (ttyClass === "display") return { origin_class: "local_display", remote_host: undefined };
    if (ttyClass === "ttys" || ttyClass === "pts" || ttyClass === "tty") return { origin_class: "local_tty", remote_host: undefined };
    return { origin_class: "unknown", remote_host: undefined };
  }
  if (value === "console") return { origin_class: "console", remote_host: undefined };
  // A bare X display (":0", ":1.0") is local. "host:10.0" (ssh X11 forwarding, or a remote X
  // display) carries a real host and stays remote.
  if (X_DISPLAY_RE.test(value)) return { origin_class: "local_display", remote_host: undefined };
  if (SCREEN_TAG_RE.test(value) || TMUX_TAG_RE.test(value)) return { origin_class: "local_tty", remote_host: undefined };
  if (MOSH_TAG_RE.test(value)) return { origin_class: "remote_mosh", remote_host: undefined };
  return { origin_class: "remote", remote_host: value };
}

/** True when a who/last host field is a LOCAL attachment (never a peer). mosh is not local. */
export function isLocalLoginHost(host, tty) {
  const { origin_class: origin } = classifyLoginOrigin({ host, tty });
  return origin === "console" || origin === "local_tty" || origin === "local_display";
}
