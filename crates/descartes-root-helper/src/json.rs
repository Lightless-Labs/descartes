//! Hand-rolled JSON emission for the helper's stdout contract. Cross-platform, unit-tested
//! everywhere. Deliberately not `serde_json` in the shipped binary -- the runtime dependency
//! surface of a future CAP_SYS_PTRACE-carrying binary must be nil (see Cargo.toml); `serde_json`
//! is a dev-dependency used only to validate this module's OWN output in tests.
//!
//! The emitted shape is the authoritative contract Node's `parseAndVerifyHelperResponse`
//! (tools/descartes-cli/src/tools/provenance-elevated.js) expects:
//!   pid:    {"requested":{"pid":N},"resolved":{"pid":N,"uid":U,"executable_path":"...","argv":["..."]}}
//!   socket: {"requested":{"protocol":"tcp","port":N,"inode":"I"},"resolved":{...,"holders":H}}
//! Key order and exact formatting are pinned by the shared golden fixture test below.
//!
//! This module's only production call site (`main.rs`'s `run_resolve_pid`/`run_resolve_port`) is
//! Linux-only (`proc_linux` is the only source of a `Resolved`), so on a non-Linux `cargo build`
//! these items are legitimately unreachable outside `#[cfg(test)]` -- allowed below rather than
//! silenced case-by-case, so a genuinely dead item on Linux itself would still warn.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt::Write as _;

use crate::socket::SocketTarget;

/// Per-field raw (pre-escape) truncation bound matching the helper contract's documented cap.
/// Real `/proc` paths and cmdlines are overwhelmingly printable UTF-8; a pathological
/// all-control-byte cmdline could in principle inflate the ESCAPED form past this raw byte count
/// (each control byte can expand to a 6-byte `\u00XX` escape), but Node's own independent
/// MAX_RESPONSE_BYTES check -- applied to the whole response, before `JSON.parse` is even
/// attempted (provenance-elevated.js's `parseAndVerifyHelperResponse`) -- is the backstop that
/// makes such a response safely rejected rather than a helper-side vulnerability.
pub const MAX_FIELD_BYTES: usize = 2048;

/// The echoed request: exactly what was asked for, nothing else in the `requested` object. A pid
/// request echoes `{"pid":N}`; a socket request (2026-10) echoes the full bound identity
/// `{"protocol":"tcp","port":N,"inode":"<digits>"}` -- the inode as a decimal STRING because a
/// `u64` can exceed JavaScript's safe-integer range, and Node compares it verbatim against the
/// inode string it read from `/proc/net`.
pub enum Requested {
    Pid(u32),
    Socket(SocketTarget),
}

/// A complete, successful resolution. Slice 3 emits only complete resolutions -- see
/// `proc_linux::resolve_pid`, which fails the whole lookup rather than emit a partial record.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub pid: u32,
    pub tgid: u32,
    pub start_time: u64,
    pub uid: u32,
    pub executable_path: String,
    pub argv: Vec<String>,
}

/// Escapes `input` for embedding inside a JSON string literal (the literal's surrounding quotes
/// are NOT included -- callers wrap the result themselves). `"` and `\` each get a one-character
/// escape; every control byte below `0x20` becomes a literal `\u00XX` -- deliberately not the
/// shorthand `\n`/`\t`/`\r` forms, so there is exactly one code path for every control byte
/// instead of a lookup table that could silently miss one. Everything else (including non-ASCII
/// UTF-8) passes through unescaped, which is valid inside a JSON string.
pub fn escape_json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Truncates `s` to at most `max_bytes` bytes without splitting a UTF-8 code point, appending a
/// visible ellipsis so a shortened value is never mistaken for the complete original.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &s[..end])
}

/// Emits the single-line JSON response for a verified successful resolution. `requested` echoes
/// exactly the numeric target that was asked for (the Node side compares this with strict `!==`
/// against the numeric request, so it MUST be a JSON number, never a string).
///
/// `holders` (socket requests only) is the number of distinct processes found holding the socket
/// (all running the same executable -- disagreeing holders are never emitted, see `socket.rs`);
/// appended as `"holders":N` inside `resolved`. `None` emits the pid-request shape unchanged.
pub fn emit_response(requested: Requested, resolved: &Resolved, holders: Option<usize>) -> String {
    let requested_field = match requested {
        Requested::Pid(pid) => format!("\"pid\":{pid}"),
        // `protocol.token()` is one of four fixed ASCII literals; no escaping needed.
        Requested::Socket(target) => format!(
            "\"protocol\":\"{}\",\"port\":{},\"inode\":\"{}\"",
            target.protocol.token(),
            target.port,
            target.inode
        ),
    };
    let holders_field = holders.map_or(String::new(), |n| format!(",\"holders\":{n}"));
    let executable_path =
        escape_json_string(&truncate_bytes(&resolved.executable_path, MAX_FIELD_BYTES));
    let argv = resolved
        .argv
        .iter()
        .map(|arg| {
            format!(
                "\"{}\"",
                escape_json_string(&truncate_bytes(arg, MAX_FIELD_BYTES))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"requested\":{{{requested_field}}},\"resolved\":{{\"pid\":{},\"tgid\":{},\"start_time\":{},\"uid\":{},\"executable_path\":\"{executable_path}\",\"argv\":[{argv}]{holders_field}}}}}",
        resolved.pid, resolved.tgid, resolved.start_time, resolved.uid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(
            escape_json_string(r#"say "hi" \ ok"#),
            r#"say \"hi\" \\ ok"#
        );
    }

    #[test]
    fn escapes_newlines_and_tabs_as_u00xx_not_shorthand() {
        assert_eq!(
            escape_json_string("a\nb\tc\rd"),
            "a\\u000ab\\u0009c\\u000dd"
        );
    }

    #[test]
    fn escapes_every_control_byte_below_0x20() {
        for b in 0u32..0x20 {
            let c = char::from_u32(b).unwrap();
            let escaped = escape_json_string(&c.to_string());
            assert_eq!(
                escaped,
                format!("\\u{b:04x}"),
                "control byte {b:#04x} must escape to \\u{b:04x}"
            );
        }
    }

    #[test]
    fn leaves_printable_ascii_and_non_ascii_utf8_untouched() {
        assert_eq!(escape_json_string("app --serve"), "app --serve");
        assert_eq!(escape_json_string("café"), "café");
    }

    #[test]
    fn escaped_output_round_trips_through_a_real_json_parser() {
        let raw = "line1\nline2\t\"quoted\"\\backslash\u{0007}bell";
        let wrapped = format!("\"{}\"", escape_json_string(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&wrapped).expect("escaper must produce valid JSON");
        assert_eq!(parsed.as_str().unwrap(), raw);
    }

    #[test]
    fn truncate_bytes_is_a_no_op_under_the_bound() {
        assert_eq!(truncate_bytes("short", 2048), "short");
    }

    #[test]
    fn truncate_bytes_shortens_and_marks_over_the_bound() {
        let long = "x".repeat(3000);
        let truncated = truncate_bytes(&long, 2048);
        assert!(truncated.starts_with(&"x".repeat(2048)));
        assert!(truncated.ends_with('\u{2026}'));
        assert!(truncated.len() <= 2048 + '\u{2026}'.len_utf8());
    }

    #[test]
    fn truncate_bytes_never_splits_a_multibyte_char() {
        // 'é' is 2 bytes in UTF-8; force a boundary that would otherwise land mid-character.
        let s = "a".repeat(9) + "é"; // 9 ascii bytes + a 2-byte char starting at byte offset 9.
        let truncated = truncate_bytes(&s, 10); // offset 10 is mid-'é' (byte 9 and 10 are its two bytes).
        assert!(truncated.is_char_boundary(truncated.len() - '\u{2026}'.len_utf8()));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn emit_response_matches_the_shared_golden_fixture_byte_for_byte() {
        // Pins key order and formatting: the Node side (parseAndVerifyHelperResponse) and this
        // Rust emitter both read the SAME fixture file as their one source of truth. See
        // tools/descartes-cli/test/provenance-elevated.test.js for the Node-side reader.
        let fixture = include_str!("../tests/fixtures/echo-back-contract.json");
        let resolved = Resolved {
            pid: 4242,
            tgid: 4242,
            start_time: 123,
            uid: 997,
            executable_path: "/opt/svc/bin/app".to_string(),
            argv: vec!["app".to_string(), "--serve".to_string()],
        };
        let target = crate::socket::SocketTarget {
            protocol: crate::socket::Protocol::Tcp,
            port: 8080,
            inode: 424242,
        };
        let emitted = emit_response(Requested::Socket(target), &resolved, Some(1));
        assert_eq!(emitted, fixture.trim());

        // Belt-and-suspenders: also confirm it's valid, correctly-shaped JSON via the dev-only parser.
        let parsed: serde_json::Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(parsed["requested"]["protocol"], "tcp");
        assert_eq!(parsed["requested"]["port"], 8080);
        assert_eq!(
            parsed["requested"]["inode"], "424242",
            "inode echoes as a decimal string (u64 > JS safe integer)"
        );
        assert_eq!(parsed["resolved"]["pid"], 4242);
        assert_eq!(parsed["resolved"]["tgid"], 4242);
        assert_eq!(parsed["resolved"]["start_time"], 123);
        assert_eq!(parsed["resolved"]["uid"], 997);
        assert_eq!(parsed["resolved"]["executable_path"], "/opt/svc/bin/app");
        assert_eq!(
            parsed["resolved"]["argv"],
            serde_json::json!(["app", "--serve"])
        );
        assert_eq!(parsed["resolved"]["holders"], 1);
        // The requested object contains ONLY the three bound-identity keys.
        assert_eq!(parsed["requested"].as_object().unwrap().len(), 3);
    }

    #[test]
    fn emit_response_echoes_a_u64_inode_exactly() {
        let resolved = Resolved {
            pid: 1,
            tgid: 1,
            start_time: 1,
            uid: 0,
            executable_path: "/x".to_string(),
            argv: vec!["x".to_string()],
        };
        let target = crate::socket::SocketTarget {
            protocol: crate::socket::Protocol::Udp6,
            port: 53,
            inode: u64::MAX,
        };
        let emitted = emit_response(Requested::Socket(target), &resolved, Some(2));
        let parsed: serde_json::Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(parsed["requested"]["inode"], u64::MAX.to_string());
        assert_eq!(parsed["requested"]["protocol"], "udp6");
        assert_eq!(parsed["resolved"]["holders"], 2);
    }

    #[test]
    fn emit_response_echoes_a_pid_request_shape() {
        let resolved = Resolved {
            pid: 99,
            tgid: 99,
            start_time: 1,
            uid: 0,
            executable_path: "/bin/sh".to_string(),
            argv: vec!["sh".to_string()],
        };
        let emitted = emit_response(Requested::Pid(99), &resolved, None);
        let parsed: serde_json::Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(parsed["requested"]["pid"], 99);
        assert!(parsed["requested"].get("port").is_none());
        assert!(
            parsed["resolved"].get("holders").is_none(),
            "pid responses keep the pre-2026-10 shape"
        );
    }
}
