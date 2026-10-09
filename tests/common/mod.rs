//! Shared by `differential_shell.rs` (bash versus sentinel) and
//! `ast_candidates.rs` (parse-backed versus tokenizer path mining): a seeded
//! generator of shell argument fragments from a small grammar (plain words,
//! single and double quotes with embedded spaces, backslash escapes, `$'...'`
//! ANSI-C strings, `${IFS}` and `$IFS` word splits, brace lists, brace
//! sequences, nested braces, `~/` paths), plus the guard that keeps every
//! fragment inert: nothing in it is a command, a substitution, a redirect or a
//! glob, so `printf` is the only program a fragment can ever run.

#![allow(dead_code)]

/// Deterministic xorshift64* generator; no external dependency.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    pub fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const PLAIN: &[&str] = &["a", "b", "cfg", "id_rsa", "x1", "dir", "s.txt", "Z"];
const SPACED: &[&str] = &["a b", "My Docs", "x  y", "t z"];
const ESCAPES: &[&str] = &["\\ ", "\\'", "\\\"", "\\\\", "\\$", "\\{", "\\,"];
const ANSI_PARTS: &[&str] = &[
    "a", "\\x20", "\\x2f", "\\n", "\\t", "\\x27", "\\\\", "\\x7b", "\\x7d", "q",
];
const SEPARATORS: &[&str] = &[" ", " ", "${IFS}", "$IFS", "${IFS:0:1}"];
const PREFIXES: &[&str] = &["./", "/tmp/d/", "~/"];

fn gen_ansi(rng: &mut Rng) -> String {
    let n = 1 + rng.below(3);
    let mut s = String::from("$'");
    for _ in 0..n {
        s.push_str(rng.pick(ANSI_PARTS));
    }
    s.push('\'');
    s
}

fn gen_brace(rng: &mut Rng, depth: usize) -> String {
    if rng.chance(25) {
        let seqs = ["{1..3}", "{3..1}", "{a..c}", "{x..z}", "{-1..1}"];
        return rng.pick(&seqs).to_string();
    }
    let n = 2 + rng.below(2);
    let mut members = Vec::new();
    for _ in 0..n {
        let member = match rng.below(12) {
            0 if depth < 2 => gen_brace(rng, depth + 1),
            1 => String::new(),
            2 if depth < 2 => format!("{}{}", rng.pick(PLAIN), gen_brace(rng, depth + 1)),
            3 => format!("'{}'", rng.pick(SPACED)),
            // a quoted comma is the documented KNOWN_DIVERGENCES case
            4 => "'b,c'".to_string(),
            _ => rng.pick(PLAIN).to_string(),
        };
        members.push(member);
    }
    format!("{{{}}}", members.join(","))
}

fn gen_segment(rng: &mut Rng) -> String {
    match rng.below(9) {
        0 | 1 => rng.pick(PLAIN).to_string(),
        2 => format!("'{}'", rng.pick(SPACED)),
        3 => format!("\"{}\"", rng.pick(SPACED)),
        4 => format!("{}{}", rng.pick(PLAIN), rng.pick(ESCAPES)),
        5 => gen_ansi(rng),
        6 | 7 => gen_brace(rng, 0),
        _ => format!("{}/{}", rng.pick(PLAIN), rng.pick(PLAIN)),
    }
}

/// One path-like word: a prefix the path miner always recognizes, then one
/// to three segments, at most two of them brace groups so the product of a
/// word's lists usually stays under the engine's 64-way inspection cap.
pub fn gen_word(rng: &mut Rng) -> String {
    let mut w = rng.pick(PREFIXES).to_string();
    let mut braces = 0;
    for _ in 0..1 + rng.below(3) {
        let mut segment = gen_segment(rng);
        if segment.starts_with('{') {
            if braces == 2 {
                segment = rng.pick(PLAIN).to_string();
            } else {
                braces += 1;
            }
        }
        w.push_str(&segment);
    }
    w
}

pub fn gen_fragment(rng: &mut Rng) -> String {
    let mut f = gen_word(rng);
    for _ in 0..rng.below(3) {
        f.push_str(rng.pick(SEPARATORS));
        f.push_str(&gen_word(rng));
    }
    f
}

/// Guard: the generated fragment must contain nothing Bash would execute or
/// expand beyond the modeled constructs. `printf` is the only command.
pub fn assert_inert(fragment: &str) {
    for forbidden in [";", "|", "&", "<", ">", "(", ")", "`", "*", "?", "["] {
        assert!(
            !fragment.contains(forbidden),
            "generator emitted {forbidden:?} in {fragment:?}"
        );
    }
    let bytes = fragment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // an escaped character is literal, whatever it is
            b'\\' => i += 1,
            b'$' => {
                let rest = &fragment[i + 1..];
                assert!(
                    rest.starts_with('\'') || rest.starts_with("IFS") || rest.starts_with("{IFS"),
                    "generator emitted an unmodeled expansion in {fragment:?}"
                );
            }
            _ => {}
        }
        i += 1;
    }
}

/// The command the bash harness runs for a fragment: `printf` prints the
/// words it resolved, NUL separated.
pub fn printf_command(fragment: &str) -> String {
    format!("printf \"%s\\0\" {fragment}")
}
