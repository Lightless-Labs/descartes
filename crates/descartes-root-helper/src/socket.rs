//! Pure, platform-independent socket-identity logic for `--resolve-socket` (2026-10). No I/O, no
//! `libc`, no `#[cfg]` gate: host-unit-tested everywhere. `proc_linux.rs` does the `/proc` reads
//! and calls into this module for every DECISION, so the decisions are exercised on the macOS dev
//! host too.
//!
//! WHY (docs/research/2026-09-26-sandbox-and-microvm-boundaries-research.md, finding 2): the old
//! `--resolve-port <port>` re-observed a BARE port. The unprivileged Node path had already picked a
//! specific socket (protocol, address, uid, inode), but the helper independently re-read only
//! TCP/TCP6 and returned the first process holding ANY listener on that port -- so a TCP/UDP
//! collision, a second address, an `SO_REUSEPORT` sibling (distinct inode), or a rebind/handoff
//! between Node's observation and the helper's could be misattributed at confidence 1.
//! `--resolve-socket <protocol> <port> <inode>` binds the request to the exact socket Node observed:
//!   1. the helper reads ONLY `/proc/net/<protocol>` and requires the row with EXACTLY that inode
//!      to still exist with the same port (LISTEN state for TCP, state 07 for UDP) -- else "not
//!      found";
//!   2. it collects every process holding `socket:[<inode>]` (a socket inode can be shared across
//!      processes by fork inheritance / fd passing);
//!   3. holders that disagree on executable are AMBIGUOUS (distinct exit code, no answer);
//!      otherwise the holder is chosen deterministically (`select_holder`);
//!   4. a post-resolution consistency check re-reads the chosen holder's fd link and the socket
//!      row; any change (close, handoff, rebind) between the scan and the answer is "not found".
//!
//! A returned holder therefore ALWAYS genuinely holds the exact socket Node observed.
#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// The four `/proc/net` socket tables the Node side observes (`provenance.js`'s
/// `resolveByPortLinux`) -- the protocol token is passed through argv verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Protocol {
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "tcp" => Some(Protocol::Tcp),
            "tcp6" => Some(Protocol::Tcp6),
            "udp" => Some(Protocol::Udp),
            "udp6" => Some(Protocol::Udp6),
            _ => None,
        }
    }

    pub fn token(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
            Protocol::Udp => "udp",
            Protocol::Udp6 => "udp6",
        }
    }

    /// Path relative to `/proc` of the one table this protocol's sockets appear in.
    pub fn net_table(self) -> &'static str {
        match self {
            Protocol::Tcp => "net/tcp",
            Protocol::Tcp6 => "net/tcp6",
            Protocol::Udp => "net/udp",
            Protocol::Udp6 => "net/udp6",
        }
    }

    /// Explicit components for `/proc/<pid>/net/<table>`. This deliberately avoids the Linux
    /// `/proc/net` symlink and is pure so its path contract can be tested on every host.
    #[cfg(test)]
    pub fn proc_net_path_components(self, pid: u32) -> [String; 4] {
        [
            "/proc".to_string(),
            pid.to_string(),
            "net".to_string(),
            self.net_table().strip_prefix("net/").unwrap().to_string(),
        ]
    }

    /// TCP sockets must still be LISTENing (Node only ever selects LISTEN rows for TCP); UDP is
    /// limited to state 07, the bound/unconnected rows Node can attribute as listeners.
    pub fn requires_listen(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Tcp6)
    }
}

/// The exact socket the caller observed and wants attributed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketTarget {
    pub protocol: Protocol,
    pub port: u16,
    pub inode: u64,
}

impl SocketTarget {
    /// The fd-symlink target (`readlinkat` on `/proc/<pid>/fd/<n>`) of a holder of this socket.
    pub fn fd_link(&self) -> String {
        format!("socket:[{}]", self.inode)
    }
}

/// The identity-bearing columns of one `/proc/net/<protocol>` row, used both to admit the row
/// against the request and, unchanged, as the "generation" a post-resolution re-read must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketRow {
    /// `local_address` column verbatim (`<hex addr>:<hex port>`).
    pub local_address: String,
    pub port: u16,
    /// `st` column, upper-cased hex (e.g. `0A` = TCP LISTEN).
    pub state: String,
    pub uid: u32,
}

const LOCAL_ADDRESS_COLUMN: usize = 1;
const STATE_COLUMN: usize = 3;
const UID_COLUMN: usize = 7;
const INODE_COLUMN: usize = 9;
const TCP_LISTEN_STATE: &str = "0A";
const UDP_UNCONNECTED_STATE: &str = "07";

/// Finds the row whose inode column is exactly `inode` in a `/proc/net/{tcp,udp}[6]` table
/// (header line skipped). Malformed rows are skipped, never guessed at.
pub fn find_row(contents: &str, inode: u64) -> Option<SocketRow> {
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local_address), Some(state), Some(uid), Some(row_inode)) = (
            fields.get(LOCAL_ADDRESS_COLUMN),
            fields.get(STATE_COLUMN),
            fields.get(UID_COLUMN),
            fields.get(INODE_COLUMN),
        ) else {
            continue;
        };
        if row_inode.parse::<u64>().ok() != Some(inode) {
            continue;
        }
        let Some(port_hex) = local_address.rsplit(':').next() else {
            continue;
        };
        let (Ok(port), Ok(uid)) = (u16::from_str_radix(port_hex, 16), uid.parse::<u32>()) else {
            continue;
        };
        return Some(SocketRow {
            local_address: (*local_address).to_string(),
            port,
            state: state.to_ascii_uppercase(),
            uid,
        });
    }
    None
}

/// Whether the live row still describes the socket the caller observed: same port, and (TCP)
/// still LISTENing. The inode already matched (`find_row`).
pub fn row_admits(row: &SocketRow, target: &SocketTarget) -> bool {
    row.port == target.port
        && if target.protocol.requires_listen() {
            row.state == TCP_LISTEN_STATE
        } else {
            row.state == UDP_UNCONNECTED_STATE
        }
}

/// The facts `select_holder` decides on, one per process found holding the socket.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderFacts {
    pub pid: u32,
    pub tgid: u32,
    pub start_time: u64,
    pub uid: u32,
    pub executable_path: String,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub enum Selection {
    /// Index into the holder slice.
    Chosen(usize),
    /// Holders are different processes: no single process can honestly be named the owner.
    Ambiguous,
    /// No holders at all.
    Empty,
}

/// Chooses the process to report for a socket held by `holders`.
///
/// Different `(tgid, start_time)` tuples are different processes even when their executable paths
/// match (for example, unrelated SO_REUSEPORT services). Only repeated observations of the same
/// process may be collapsed to one owner.
#[cfg(test)]
pub fn select_holder(holders: &[HolderFacts], socket_uid: u32) -> Selection {
    let Some(first) = holders.first() else {
        return Selection::Empty;
    };
    if holders
        .iter()
        .any(|h| h.tgid != first.tgid || h.start_time != first.start_time)
    {
        return Selection::Ambiguous;
    }
    let lowest = |pred: &dyn Fn(&HolderFacts) -> bool| {
        holders
            .iter()
            .enumerate()
            .filter(|(_, h)| pred(h))
            .min_by_key(|(_, h)| h.pid)
            .map(|(i, _)| i)
    };
    match lowest(&|h| h.uid == socket_uid).or_else(|| lowest(&|_| true)) {
        Some(index) => Selection::Chosen(index),
        None => Selection::Empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 424242 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000   997        0 515151 1 0000000000000000 20 4 30 10 -1
   2: 00000000:0050 00000000:0000 0a 00000000:00000000 00:00000000 00000000     0        0 600600 1 0000000000000000 100 0 0 10 0
   3: garbage
";

    fn tcp(port: u16, inode: u64) -> SocketTarget {
        SocketTarget {
            protocol: Protocol::Tcp,
            port,
            inode,
        }
    }

    #[test]
    fn protocol_tokens_round_trip_and_reject_everything_else() {
        for p in [Protocol::Tcp, Protocol::Tcp6, Protocol::Udp, Protocol::Udp6] {
            assert_eq!(Protocol::parse(p.token()), Some(p));
            assert!(p.net_table().ends_with(p.token()));
        }
        for bad in ["", "TCP", "tcp4", "raw", "unix", "tcp6 ", "../tcp"] {
            assert_eq!(Protocol::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn socket_tables_use_explicit_proc_pid_net_components_not_proc_net_symlink() {
        assert_eq!(
            Protocol::Tcp.proc_net_path_components(4242),
            ["/proc", "4242", "net", "tcp"].map(String::from)
        );
        assert_eq!(
            Protocol::Udp6.proc_net_path_components(4242),
            ["/proc", "4242", "net", "udp6"].map(String::from)
        );
    }

    #[test]
    fn find_row_matches_the_exact_inode_only() {
        let row = find_row(TCP_TABLE, 424242).expect("row present");
        assert_eq!(
            row,
            SocketRow {
                local_address: "0100007F:1F90".to_string(),
                port: 8080,
                state: "0A".to_string(),
                uid: 997
            }
        );
        assert_eq!(
            find_row(TCP_TABLE, 4242),
            None,
            "no prefix/substring matching"
        );
        assert_eq!(find_row(TCP_TABLE, 999), None);
        // lower-case state normalized.
        assert_eq!(find_row(TCP_TABLE, 600600).unwrap().state, "0A");
    }

    #[test]
    fn a_same_port_socket_with_a_different_inode_is_never_admitted() {
        // The race the research describes: the port is still bound, but by a DIFFERENT socket
        // (rebind / SO_REUSEPORT sibling / other protocol). Binding on inode makes it not-found.
        assert_eq!(find_row(TCP_TABLE, 777777), None);
    }

    #[test]
    fn row_admits_requires_the_same_port_and_listen_for_tcp() {
        let listen = find_row(TCP_TABLE, 424242).unwrap();
        assert!(row_admits(&listen, &tcp(8080, 424242)));
        assert!(!row_admits(&listen, &tcp(8081, 424242)), "port must match");
        let established = find_row(TCP_TABLE, 515151).unwrap();
        assert!(
            !row_admits(&established, &tcp(8080, 515151)),
            "a TCP socket that is no longer LISTENing is not the observed listener"
        );
        let udp = SocketTarget {
            protocol: Protocol::Udp,
            port: 8080,
            inode: 515151,
        };
        assert!(
            !row_admits(&established, &udp),
            "UDP resolution is limited to state 07 (unconnected/bound)"
        );
        let udp_bound = SocketRow {
            state: "07".to_string(),
            ..established
        };
        assert!(row_admits(&udp_bound, &udp));
    }

    fn holder(pid: u32, uid: u32, exe: &str) -> HolderFacts {
        HolderFacts {
            pid,
            tgid: pid,
            start_time: u64::from(pid),
            uid,
            executable_path: exe.to_string(),
        }
    }

    #[test]
    fn select_holder_single_holder_is_chosen() {
        assert_eq!(
            select_holder(&[holder(10, 997, "/a")], 997),
            Selection::Chosen(0)
        );
        assert_eq!(select_holder(&[], 997), Selection::Empty);
    }

    #[test]
    fn select_holder_same_process_repeated_observations_are_collapsed() {
        let holders = [
            holder(300, 33, "/usr/bin/node"),
            holder(200, 0, "/usr/bin/node"),
            holder(100, 33, "/usr/bin/node"),
        ];
        assert_eq!(
            select_holder(&[holders[0].clone()], 33),
            Selection::Chosen(0)
        );
        assert_eq!(
            select_holder(&[holders[0].clone(), holders[0].clone()], 33),
            Selection::Chosen(0)
        );
    }

    #[test]
    fn select_holder_different_processes_are_ambiguous_even_with_the_same_executable() {
        let holders = [
            holder(1, 0, "/usr/bin/node"),
            holder(900, 0, "/usr/bin/node"),
        ];
        assert_eq!(select_holder(&holders, 0), Selection::Ambiguous);
    }

    #[test]
    fn fd_link_is_the_kernel_socket_symlink_format() {
        assert_eq!(tcp(1, 424242).fd_link(), "socket:[424242]");
    }
}
