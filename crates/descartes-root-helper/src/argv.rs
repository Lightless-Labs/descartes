//! Fixed-argv parser. Cross-platform, unit-tested everywhere (no `#[cfg(target_os)]` gating
//! here -- only the *resolution* logic in `proc_linux` is Linux-only).
//!
//! Per the helper's I/O contract (see docs/plans/2026-07-11-s3-priv-elevated-read-path.md, the
//! Slice 3 section, and `tools/descartes-cli/src/tools/provenance-elevated.js`), argv MUST be
//! EXACTLY one of three literal forms. Anything else -- missing value, non-digit value, a
//! negative sign, extra tokens, an unknown flag, combined flags, or empty argv -- is a usage
//! error. There is no `--help`-driven dynamic behavior beyond the literal `USAGE` string, and no
//! flag combinators: this parser matches on the whole argument list at once, not flag-by-flag, so
//! there is no way for two recognized flags to combine into a new accepted shape.
//!
//! 2026-10: the bare `--resolve-port <port>` form is GONE, replaced by
//! `--resolve-socket <tcp|tcp6|udp|udp6> <port> <inode>`, which binds the request to the exact
//! socket the caller observed (see `socket.rs` for why). Removing (not keeping alongside) the
//! unbound form is the point: an unbound form would still be invocable by anything in the helper
//! group. The protocol token is matched against a closed set of four literals; `port` must fit
//! `u16`; `inode` must be a nonzero `u64` (inode 0 marks TIME_WAIT/orphan rows, never a holder).

use crate::socket::{Protocol, SocketTarget};

pub const USAGE: &str = "usage: descartes-root-helper --probe | --resolve-pid <pid> | \
--resolve-socket <tcp|tcp6|udp|udp6> <port> <inode>\n\
exit codes: 0 success, 1 resolution failure, 2 usage error, 3 scan truncated (uncertain), \
4 hardening failure, 5 ambiguous owner, 6 procfs pid-namespace mismatch";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Probe,
    ResolvePid(u32),
    ResolveSocket(SocketTarget),
}

/// Parses `args` (already stripped of argv[0], the program name) into exactly one of the three
/// contract forms. Returns `Err(())` for anything else -- the caller prints `USAGE` to stderr and
/// exits with the usage-error code; this function itself never writes anything.
pub fn parse(args: &[String]) -> Result<Command, ()> {
    match args {
        [flag] if flag == "--probe" => Ok(Command::Probe),
        [flag, value] if flag == "--resolve-pid" => parse_digits(value).map(Command::ResolvePid),
        [flag, protocol, port, inode] if flag == "--resolve-socket" => {
            let protocol = Protocol::parse(protocol).ok_or(())?;
            let port = u16::try_from(parse_digits(port)?).map_err(|_| ())?;
            let inode = parse_digits_u64(inode)?;
            if inode == 0 {
                return Err(());
            }
            Ok(Command::ResolveSocket(SocketTarget {
                protocol,
                port,
                inode,
            }))
        }
        _ => Err(()),
    }
}

/// `parse_digits` for a `u64` (socket inodes are `unsigned long` in `/proc/net`).
fn parse_digits_u64(raw: &str) -> Result<u64, ()> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    raw.parse::<u64>().map_err(|_| ())
}

/// Accepts only a non-empty string of ASCII digits (no sign, no whitespace, no leading `+`) --
/// rejects negative numbers and non-numeric garbage before ever reaching `str::parse`, and
/// rejects values too large to fit `u32` (an integer overflow is treated as malformed input, the
/// same as any other argv shape outside the three literal forms).
fn parse_digits(raw: &str) -> Result<u32, ()> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    raw.parse::<u32>().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_probe() {
        assert_eq!(parse(&args(&["--probe"])), Ok(Command::Probe));
    }

    #[test]
    fn accepts_resolve_pid_with_digits() {
        assert_eq!(
            parse(&args(&["--resolve-pid", "1234"])),
            Ok(Command::ResolvePid(1234))
        );
    }

    #[test]
    fn accepts_resolve_socket_with_a_protocol_port_and_inode() {
        assert_eq!(
            parse(&args(&["--resolve-socket", "tcp6", "8080", "424242"])),
            Ok(Command::ResolveSocket(SocketTarget {
                protocol: Protocol::Tcp6,
                port: 8080,
                inode: 424242
            }))
        );
        assert_eq!(
            parse(&args(&[
                "--resolve-socket",
                "udp",
                "53",
                "18446744073709551615"
            ])),
            Ok(Command::ResolveSocket(SocketTarget {
                protocol: Protocol::Udp,
                port: 53,
                inode: u64::MAX
            }))
        );
    }

    #[test]
    fn the_unbound_resolve_port_form_is_gone() {
        // Research finding 2: a bare port is not an identity. The old form must not survive as a
        // still-invocable alias.
        assert_eq!(parse(&args(&["--resolve-port", "8080"])), Err(()));
    }

    #[test]
    fn rejects_malformed_resolve_socket_requests() {
        for case in [
            vec!["--resolve-socket", "tcp", "8080"],    // missing inode
            vec!["--resolve-socket", "8080", "424242"], // missing protocol
            vec!["--resolve-socket", "TCP", "8080", "424242"], // protocol is case-exact
            vec!["--resolve-socket", "raw", "8080", "424242"], // not one of the four
            vec!["--resolve-socket", "tcp", "65536", "424242"], // port overflows u16
            vec!["--resolve-socket", "tcp", "-1", "424242"], // sign
            vec!["--resolve-socket", "tcp", "8080", "0"], // inode 0 is never a holder
            vec!["--resolve-socket", "tcp", "8080", "18446744073709551616"], // inode overflows u64
            vec!["--resolve-socket", "tcp", "8080", "0x10"], // non-digit inode
            vec!["--resolve-socket", "tcp", "8080", "424242", "x"], // extra token
        ] {
            assert_eq!(parse(&args(&case)), Err(()), "{case:?}");
        }
    }

    #[test]
    fn accepts_leading_zeros() {
        assert_eq!(
            parse(&args(&["--resolve-pid", "007"])),
            Ok(Command::ResolvePid(7))
        );
    }

    #[test]
    fn rejects_empty_argv() {
        assert_eq!(parse(&args(&[])), Err(()));
    }

    #[test]
    fn rejects_missing_value() {
        assert_eq!(parse(&args(&["--resolve-pid"])), Err(()));
        assert_eq!(parse(&args(&["--resolve-socket"])), Err(()));
    }

    #[test]
    fn rejects_non_digit_value() {
        assert_eq!(parse(&args(&["--resolve-pid", "abc"])), Err(()));
        assert_eq!(
            parse(&args(&["--resolve-socket", "tcp", "80.80", "1"])),
            Err(())
        );
        assert_eq!(parse(&args(&["--resolve-pid", "12a"])), Err(()));
    }

    #[test]
    fn rejects_negative_value() {
        assert_eq!(parse(&args(&["--resolve-pid", "-5"])), Err(()));
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(parse(&args(&["--resolve-pid", ""])), Err(()));
        assert_eq!(parse(&args(&["--resolve-socket", "tcp", "", "1"])), Err(()));
    }

    #[test]
    fn rejects_overflowing_value() {
        // u32::MAX is 4294967295; one digit past that must be rejected, not silently wrapped.
        assert_eq!(parse(&args(&["--resolve-pid", "42949672960"])), Err(()));
    }

    #[test]
    fn rejects_extra_args() {
        assert_eq!(parse(&args(&["--resolve-pid", "123", "456"])), Err(()));
        assert_eq!(parse(&args(&["--probe", "extra"])), Err(()));
    }

    #[test]
    fn rejects_unknown_flags() {
        assert_eq!(parse(&args(&["--foo"])), Err(()));
        assert_eq!(parse(&args(&["--resolve-pit", "123"])), Err(()));
        assert_eq!(parse(&args(&["-p", "123"])), Err(()));
    }

    #[test]
    fn rejects_combined_flags() {
        assert_eq!(parse(&args(&["--probe", "--resolve-pid", "123"])), Err(()));
        assert_eq!(
            parse(&args(&["--resolve-pid", "123", "--resolve-socket", "tcp"])),
            Err(())
        );
    }

    #[test]
    fn rejects_env_or_config_style_flags() {
        // No env-based or config-file-based behavior of any kind is part of the contract; a
        // flag that looks like it wants to introduce one must be rejected like any other unknown
        // flag, not silently accepted as a synonym.
        assert_eq!(
            parse(&args(&["--config", "/etc/descartes/root-helper.json"])),
            Err(())
        );
    }
}
