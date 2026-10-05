//! Pure, platform-independent classic-BPF compiler for the helper's seccomp policy (2026-10
//! hardening). No I/O, no `libc`, no `#[cfg]` gate: it compiles and its unit tests RUN on every
//! host, including the macOS dev host that cannot execute Linux code at all. `hardening.rs` (Linux
//! only) is the one production caller: it hands `compile()` the concrete `seccomp_policy` rule set
//! and installs the resulting program.
//!
//! Why a hand-rolled compiler instead of the previous flat "syscall number -> ALLOW" cascade: the
//! tightened policy needs ARGUMENT predicates (openat flags, write fd, mmap/mprotect prot, ...),
//! and hand-computing cBPF jump offsets for those inline is exactly the kind of off-by-one a
//! seccomp filter must not have. Isolating the compiler here makes every jump offset unit-testable
//! via the test-only interpreter (`evaluate`) below, on any host.
//!
//! Program shape (each rule is a self-contained block that always ends in a RET, so the
//! accumulator clobbered by argument loads never leaks into the next rule's comparison):
//!
//! ```text
//!   LD arch ; JEQ native ? next : KILL            -- foreign-ABI gate
//!   LD nr   ; [x86_64: JGE X32_BIT ? KILL : next] -- x32 gate
//!   for each rule:
//!     JEQ rule.nr ? enter-block : skip-block
//!     block := <arg checks, each failing check jumps to this block's KILL> ; RET ALLOW ; RET KILL
//!   RET KILL                                      -- default action
//! ```
//!
//! A syscall whose number matches a rule but whose arguments fail that rule's checks is KILLED, not
//! passed on to later rules -- so every syscall number may appear in at most one rule
//! (`CompileError::DuplicateRule`).
//!
//! Argument words: `seccomp_data.args` are `u64`; both supported arches (x86_64, aarch64) are
//! little-endian, so the low word of `args[i]` is at offset `16 + 8*i` and the high word at `+4`.
//! `Low32*` checks compare only the low word -- correct for `int`/`unsigned int` syscall
//! parameters, which the kernel itself truncates to 32 bits (checking the high word there could
//! false-kill a legitimate call on undefined upper register bits). `U64OneOf` additionally requires
//! the high word to be zero, for genuinely `unsigned long` parameters.
#![forbid(unsafe_code)]
// Only production caller is Linux-only `hardening.rs`; on other hosts these items are exercised by
// tests alone (mirrors `json.rs`/`scan.rs`).
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeSet;

// `<linux/bpf_common.h>` / `<linux/filter.h>` opcode bits -- stable kernel UAPI, hand-defined so
// this module needs no `libc` (and so builds on non-Linux hosts).
pub const BPF_LD: u16 = 0x00;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_AND: u16 = 0x50;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;

// `<linux/seccomp.h>` return actions.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `<linux/filter.h>` BPF_MAXINSNS: the kernel rejects longer classic-BPF programs.
pub const BPF_MAXINSNS: usize = 4096;

// `struct seccomp_data` field offsets (`<linux/seccomp.h>`): nr (i32) @0, arch (u32) @4,
// instruction_pointer (u64) @8, args ([u64; 6]) @16.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARGS: u32 = 16;
const MAX_ARGS: u8 = 6;

fn arg_low_offset(arg: u8) -> u32 {
    DATA_ARGS + 8 * u32::from(arg)
}

fn arg_high_offset(arg: u8) -> u32 {
    arg_low_offset(arg) + 4
}

/// One classic-BPF instruction, field-for-field `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

fn stmt(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

fn load(offset: u32) -> Insn {
    stmt(BPF_LD | BPF_W | BPF_ABS, offset)
}

fn ret(action: u32) -> Insn {
    stmt(BPF_RET | BPF_K, action)
}

/// A predicate on one syscall argument. See the module doc for the low-word/high-word semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgCheck {
    /// Low 32 bits of `args[arg]` must equal one of `values`.
    Low32OneOf { arg: u8, values: Vec<u32> },
    /// `args[arg]` (full 64 bits) must equal one of `values`: high word zero, low word in the set.
    U64OneOf { arg: u8, values: Vec<u32> },
    /// Every bit of `mask` must be CLEAR in the low 32 bits of `args[arg]`.
    Low32BitsClear { arg: u8, mask: u32 },
    /// Every bit of `mask` must be SET in the low 32 bits of `args[arg]`.
    Low32BitsSet { arg: u8, mask: u32 },
    /// The low 32 bits of `args[arg]` must not equal `value`.
    Low32NotEqual { arg: u8, value: u32 },
}

/// Allow syscall `nr` iff every check passes; a failing check KILLS (see the module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub nr: u32,
    pub checks: Vec<ArgCheck>,
}

impl Rule {
    /// Unconditional allow (number-only).
    pub fn allow(nr: u32) -> Self {
        Rule {
            nr,
            checks: Vec::new(),
        }
    }

    /// Allow only when every check passes.
    pub fn when(nr: u32, checks: Vec<ArgCheck>) -> Self {
        Rule { nr, checks }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// `AUDIT_ARCH_*` of the one ABI this binary runs under; anything else is killed.
    pub audit_arch: u32,
    /// x86_64 only: `__X32_SYSCALL_BIT`. x32 syscalls report the x86_64 audit arch but OR this bit
    /// into `nr` -- the classic hand-rolled-filter bypass -- so any `nr >= bit` is killed.
    pub x32_syscall_bit: Option<u32>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    DuplicateRule(u32),
    EmptyValueSet(u32),
    EmptyMask(u32),
    ArgIndexOutOfRange(u32),
    JumpTooFar(u32),
    ProgramTooLong(usize),
}

/// Which branch of a conditional jump must be patched to land on the block's KILL.
enum KillSlot {
    True,
    False,
}

fn compile_block(rule: &Rule) -> Result<Vec<Insn>, CompileError> {
    if rule.checks.is_empty() {
        return Ok(vec![ret(SECCOMP_RET_ALLOW)]);
    }
    let mut body: Vec<Insn> = Vec::new();
    let mut kill_jumps: Vec<(usize, KillSlot)> = Vec::new();

    for check in &rule.checks {
        let arg = match check {
            ArgCheck::Low32OneOf { arg, .. }
            | ArgCheck::U64OneOf { arg, .. }
            | ArgCheck::Low32BitsClear { arg, .. }
            | ArgCheck::Low32BitsSet { arg, .. }
            | ArgCheck::Low32NotEqual { arg, .. } => *arg,
        };
        if arg >= MAX_ARGS {
            return Err(CompileError::ArgIndexOutOfRange(rule.nr));
        }
        match check {
            ArgCheck::Low32OneOf { values, .. } | ArgCheck::U64OneOf { values, .. } => {
                if values.is_empty() {
                    return Err(CompileError::EmptyValueSet(rule.nr));
                }
                if values.len() > usize::from(u8::MAX) {
                    return Err(CompileError::JumpTooFar(rule.nr));
                }
                if matches!(check, ArgCheck::U64OneOf { .. }) {
                    body.push(load(arg_high_offset(arg)));
                    kill_jumps.push((body.len(), KillSlot::False));
                    body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));
                }
                body.push(load(arg_low_offset(arg)));
                let n = values.len();
                for (i, value) in values.iter().enumerate() {
                    // A match skips the remaining comparisons and lands on the next check.
                    let to_next_check = (n - 1 - i) as u8;
                    if i == n - 1 {
                        kill_jumps.push((body.len(), KillSlot::False));
                    }
                    body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *value, to_next_check, 0));
                }
            }
            ArgCheck::Low32BitsClear { mask, .. } => {
                if *mask == 0 {
                    return Err(CompileError::EmptyMask(rule.nr));
                }
                body.push(load(arg_low_offset(arg)));
                kill_jumps.push((body.len(), KillSlot::True));
                body.push(jump(BPF_JMP | BPF_JSET | BPF_K, *mask, 0, 0));
            }
            ArgCheck::Low32BitsSet { mask, .. } => {
                if *mask == 0 {
                    return Err(CompileError::EmptyMask(rule.nr));
                }
                body.push(load(arg_low_offset(arg)));
                body.push(stmt(BPF_ALU | BPF_AND | BPF_K, *mask));
                kill_jumps.push((body.len(), KillSlot::False));
                body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *mask, 0, 0));
            }
            ArgCheck::Low32NotEqual { value, .. } => {
                body.push(load(arg_low_offset(arg)));
                kill_jumps.push((body.len(), KillSlot::True));
                body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *value, 0, 0));
            }
        }
    }

    body.push(ret(SECCOMP_RET_ALLOW));
    let kill_at = body.len();
    body.push(ret(SECCOMP_RET_KILL_PROCESS));

    for (index, slot) in kill_jumps {
        let offset =
            u8::try_from(kill_at - (index + 1)).map_err(|_| CompileError::JumpTooFar(rule.nr))?;
        match slot {
            KillSlot::True => body[index].jt = offset,
            KillSlot::False => body[index].jf = offset,
        }
    }
    Ok(body)
}

/// Compiles `policy` into a classic-BPF seccomp program. Fails (never silently truncates or
/// reorders) on any malformed policy -- the caller treats an error as a fail-closed abort.
pub fn compile(policy: &Policy) -> Result<Vec<Insn>, CompileError> {
    let mut program = vec![
        load(DATA_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, policy.audit_arch, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
        load(DATA_NR),
    ];
    if let Some(bit) = policy.x32_syscall_bit {
        program.push(jump(BPF_JMP | BPF_JGE | BPF_K, bit, 0, 1));
        program.push(ret(SECCOMP_RET_KILL_PROCESS));
    }

    let mut seen = BTreeSet::new();
    for rule in &policy.rules {
        if !seen.insert(rule.nr) {
            return Err(CompileError::DuplicateRule(rule.nr));
        }
        let block = compile_block(rule)?;
        let skip = u8::try_from(block.len()).map_err(|_| CompileError::JumpTooFar(rule.nr))?;
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, rule.nr, 0, skip));
        program.extend(block);
    }

    program.push(ret(SECCOMP_RET_KILL_PROCESS));
    if program.len() > BPF_MAXINSNS {
        return Err(CompileError::ProgramTooLong(program.len()));
    }
    Ok(program)
}

/// Test-only `struct seccomp_data` stand-in for `evaluate`.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeccompData {
    pub nr: u32,
    pub arch: u32,
    pub args: [u64; 6],
}

/// Test-only classic-BPF interpreter covering exactly the opcodes `compile` emits. Panics (fails
/// the test) on anything the kernel's own checker would reject: an unknown opcode, an
/// out-of-range program counter, or a load outside `seccomp_data`.
#[cfg(test)]
pub(crate) fn evaluate(program: &[Insn], data: &SeccompData) -> u32 {
    let load_word = |offset: u32| -> u32 {
        match offset {
            DATA_NR => data.nr,
            DATA_ARCH => data.arch,
            o if (DATA_ARGS..DATA_ARGS + 48).contains(&o) && o % 4 == 0 => {
                let index = ((o - DATA_ARGS) / 8) as usize;
                if (o - DATA_ARGS) % 8 == 0 {
                    data.args[index] as u32
                } else {
                    (data.args[index] >> 32) as u32
                }
            }
            other => panic!("load from invalid seccomp_data offset {other}"),
        }
    };
    let mut acc: u32 = 0;
    let mut pc = 0usize;
    loop {
        let insn = *program
            .get(pc)
            .unwrap_or_else(|| panic!("pc {pc} ran off the program"));
        let branch = |taken: bool| pc + 1 + usize::from(if taken { insn.jt } else { insn.jf });
        pc = match insn.code {
            c if c == BPF_LD | BPF_W | BPF_ABS => {
                acc = load_word(insn.k);
                pc + 1
            }
            c if c == BPF_ALU | BPF_AND | BPF_K => {
                acc &= insn.k;
                pc + 1
            }
            c if c == BPF_JMP | BPF_JEQ | BPF_K => branch(acc == insn.k),
            c if c == BPF_JMP | BPF_JGE | BPF_K => branch(acc >= insn.k),
            c if c == BPF_JMP | BPF_JSET | BPF_K => branch(acc & insn.k != 0),
            c if c == BPF_RET | BPF_K => return insn.k,
            other => panic!("unsupported opcode {other:#x} at pc {pc}"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: u32 = 0xC000_003E;

    fn data(nr: u32, args: [u64; 6]) -> SeccompData {
        SeccompData {
            nr,
            arch: ARCH,
            args,
        }
    }

    fn policy(rules: Vec<Rule>) -> Policy {
        Policy {
            audit_arch: ARCH,
            x32_syscall_bit: Some(0x4000_0000),
            rules,
        }
    }

    /// Mirrors the kernel's static checks on a classic-BPF seccomp program: every jump lands
    /// inside the program, and the last instruction is a RET (no fall-off).
    fn assert_structurally_valid(program: &[Insn]) {
        assert!(program.len() <= BPF_MAXINSNS);
        assert_eq!(program.last().unwrap().code, BPF_RET | BPF_K);
        for (pc, insn) in program.iter().enumerate() {
            if insn.code & 0x07 == BPF_JMP {
                assert!(
                    pc + 1 + usize::from(insn.jt) < program.len(),
                    "jt out of range at {pc}"
                );
                assert!(
                    pc + 1 + usize::from(insn.jf) < program.len(),
                    "jf out of range at {pc}"
                );
            }
        }
    }

    #[test]
    fn unlisted_syscalls_and_foreign_arches_are_killed() {
        let program = compile(&policy(vec![Rule::allow(0)])).unwrap();
        assert_structurally_valid(&program);
        assert_eq!(evaluate(&program, &data(0, [0; 6])), SECCOMP_RET_ALLOW);
        assert_eq!(
            evaluate(&program, &data(1, [0; 6])),
            SECCOMP_RET_KILL_PROCESS
        );
        let foreign = SeccompData {
            nr: 0,
            arch: 0x4000_0003,
            args: [0; 6],
        };
        assert_eq!(evaluate(&program, &foreign), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn x32_numbers_are_killed_even_when_the_low_bits_match_an_allowed_syscall() {
        let program = compile(&policy(vec![Rule::allow(0)])).unwrap();
        assert_eq!(
            evaluate(&program, &data(0x4000_0000, [0; 6])),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn low32_one_of_allows_listed_values_only_and_ignores_the_high_word() {
        let program = compile(&policy(vec![Rule::when(
            1,
            vec![ArgCheck::Low32OneOf {
                arg: 0,
                values: vec![1, 2],
            }],
        )]))
        .unwrap();
        assert_structurally_valid(&program);
        for fd in [1u64, 2] {
            assert_eq!(
                evaluate(&program, &data(1, [fd, 0, 0, 0, 0, 0])),
                SECCOMP_RET_ALLOW
            );
        }
        for fd in [0u64, 3, 42] {
            assert_eq!(
                evaluate(&program, &data(1, [fd, 0, 0, 0, 0, 0])),
                SECCOMP_RET_KILL_PROCESS
            );
        }
        // `unsigned int fd`: the kernel truncates, so garbage upper bits must not matter.
        assert_eq!(
            evaluate(&program, &data(1, [0xdead_beef_0000_0001, 0, 0, 0, 0, 0])),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn u64_one_of_requires_a_zero_high_word() {
        let program = compile(&policy(vec![Rule::when(
            7,
            vec![ArgCheck::U64OneOf {
                arg: 1,
                values: vec![4],
            }],
        )]))
        .unwrap();
        assert_structurally_valid(&program);
        assert_eq!(
            evaluate(&program, &data(7, [0, 4, 0, 0, 0, 0])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, &data(7, [0, 1 << 32 | 4, 0, 0, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            evaluate(&program, &data(7, [0, 5, 0, 0, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn bits_clear_and_bits_set_checks_compose_within_one_rule() {
        // mmap-shaped: prot (arg 2) must not have bit 0x4, flags (arg 3) must have bit 0x20.
        let program = compile(&policy(vec![Rule::when(
            9,
            vec![
                ArgCheck::Low32BitsClear { arg: 2, mask: 0x4 },
                ArgCheck::Low32BitsSet { arg: 3, mask: 0x20 },
            ],
        )]))
        .unwrap();
        assert_structurally_valid(&program);
        assert_eq!(
            evaluate(&program, &data(9, [0, 0, 0x3, 0x22, 0, 0])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, &data(9, [0, 0, 0x7, 0x22, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            evaluate(&program, &data(9, [0, 0, 0x3, 0x02, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn low32_not_equal_kills_only_the_forbidden_value() {
        let program = compile(&policy(vec![Rule::when(
            99,
            vec![ArgCheck::Low32NotEqual { arg: 0, value: 7 }],
        )]))
        .unwrap();
        assert_eq!(
            evaluate(&program, &data(99, [6, 0, 0, 0, 0, 0])),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&program, &data(99, [7, 0, 0, 0, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn a_failing_argument_check_kills_rather_than_falling_through_to_later_rules() {
        let program = compile(&policy(vec![
            Rule::when(
                1,
                vec![ArgCheck::Low32OneOf {
                    arg: 0,
                    values: vec![1],
                }],
            ),
            Rule::allow(2),
        ]))
        .unwrap();
        assert_structurally_valid(&program);
        assert_eq!(
            evaluate(&program, &data(1, [3, 0, 0, 0, 0, 0])),
            SECCOMP_RET_KILL_PROCESS
        );
        // The later rule is still reachable for its own syscall number.
        assert_eq!(
            evaluate(&program, &data(2, [3, 0, 0, 0, 0, 0])),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn malformed_policies_are_compile_errors_never_silently_accepted() {
        assert_eq!(
            compile(&policy(vec![Rule::allow(1), Rule::allow(1)])),
            Err(CompileError::DuplicateRule(1))
        );
        assert_eq!(
            compile(&policy(vec![Rule::when(
                1,
                vec![ArgCheck::Low32OneOf {
                    arg: 0,
                    values: vec![]
                }]
            )])),
            Err(CompileError::EmptyValueSet(1))
        );
        assert_eq!(
            compile(&policy(vec![Rule::when(
                1,
                vec![ArgCheck::Low32BitsClear { arg: 6, mask: 1 }]
            )])),
            Err(CompileError::ArgIndexOutOfRange(1))
        );
        assert_eq!(
            compile(&policy(vec![Rule::when(
                1,
                vec![ArgCheck::Low32BitsSet { arg: 0, mask: 0 }]
            )])),
            Err(CompileError::EmptyMask(1))
        );
    }
}
