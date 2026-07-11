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

pub const USAGE: &str =
    "usage: descartes-root-helper --probe | --resolve-pid <pid> | --resolve-port <port>\n\
exit codes: 0 success, 1 resolution failure, 2 usage error";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Probe,
    ResolvePid(u32),
    ResolvePort(u32),
}

/// Parses `args` (already stripped of argv[0], the program name) into exactly one of the three
/// contract forms. Returns `Err(())` for anything else -- the caller prints `USAGE` to stderr and
/// exits with the usage-error code; this function itself never writes anything.
pub fn parse(args: &[String]) -> Result<Command, ()> {
    match args {
        [flag] if flag == "--probe" => Ok(Command::Probe),
        [flag, value] if flag == "--resolve-pid" => parse_digits(value).map(Command::ResolvePid),
        [flag, value] if flag == "--resolve-port" => parse_digits(value).map(Command::ResolvePort),
        _ => Err(()),
    }
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
    fn accepts_resolve_port_with_digits() {
        assert_eq!(
            parse(&args(&["--resolve-port", "8080"])),
            Ok(Command::ResolvePort(8080))
        );
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
        assert_eq!(parse(&args(&["--resolve-port"])), Err(()));
    }

    #[test]
    fn rejects_non_digit_value() {
        assert_eq!(parse(&args(&["--resolve-pid", "abc"])), Err(()));
        assert_eq!(parse(&args(&["--resolve-port", "80.80"])), Err(()));
        assert_eq!(parse(&args(&["--resolve-pid", "12a"])), Err(()));
    }

    #[test]
    fn rejects_negative_value() {
        assert_eq!(parse(&args(&["--resolve-pid", "-5"])), Err(()));
    }

    #[test]
    fn rejects_empty_value() {
        assert_eq!(parse(&args(&["--resolve-pid", ""])), Err(()));
        assert_eq!(parse(&args(&["--resolve-port", ""])), Err(()));
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
            parse(&args(&["--resolve-pid", "123", "--resolve-port", "456"])),
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
