//! Differential test: Bash's word resolution against Sentinel's.
//!
//! A seeded generator emits argument fragments from a small grammar (plain
//! words, single and double quotes with embedded spaces, backslash escapes,
//! `$'...'` ANSI-C strings, `${IFS}` and `$IFS` word splits, brace lists,
//! brace sequences, nested braces, `~/` paths). Each fragment is appended to
//! `printf "%s\0" ` and run through `bash -c` with an empty environment (HOME
//! points at a scratch directory, PATH is inherited), so the only command that
//! ever executes is `printf`, which prints the words Bash resolved, NUL
//! separated. The same fragment is resolved by Sentinel's own composition:
//! `HookInput::normalize` (shell tokens of the raw command plus the
//! `decode_obfuscation` view, with brace provenance) followed by
//! `brace_expand_checked` on candidates that carry provenance, exactly as the
//! policy engine does before matching `deny.paths`.
//!
//! Divergences are classified as:
//!   - under-resolve: a word Bash produced is not among Sentinel's candidates
//!     (a possible bypass);
//!   - over-resolve: Sentinel produced a plain word Bash did not (a possible
//!     false positive), ignoring the raw undecoded forms Sentinel keeps on
//!     purpose (see NON_GOALS);
//!   - non-goal: constructs the engine deliberately does not model.
//!
//! The test fails on any divergence that is neither a documented non-goal nor
//! in KNOWN_DIVERGENCES. It is `#[ignore]`d because it needs `bash` and runs
//! 2000 subprocesses; the nightly workflow runs it, and locally:
//! `cargo test --test differential_shell -- --ignored`.

#![cfg(unix)]

use sentinel_guard::common::shell::{brace_expand_checked, shell_tokens};
use sentinel_guard::evaluate::hook_schema::HookInput;
use std::collections::BTreeSet;
use std::process::Command;

/// Constructs the generator never emits and the engine does not model. They
/// are listed so a future generator extension classifies them instead of
/// silently failing, and so the scope of this harness is explicit.
const NON_GOALS: &[(&str, &str)] = &[
    (
        "command substitution",
        "`$(...)` and backticks run code; the engine never evaluates them",
    ),
    (
        "parameter expansion",
        "variables other than IFS (`$HOME`, `${X:-y}`, arithmetic) resolve at runtime",
    ),
    (
        "pathname expansion",
        "`*`, `?` and `[...]` depend on the filesystem; rules de-glob candidates instead",
    ),
    (
        "de-obfuscation inside quotes",
        "`$'..'`, `${IFS}` and `$IFS` are decoded even inside quotes because quoted text \
         may be executed by a nested shell (`sh -c '...'`); this over-resolves on literal text",
    ),
    (
        "quoted tilde",
        "`\"~/x\"` is treated as the home directory although Bash leaves it literal \
         (conservative: a quoted tilde is still compared against home rules)",
    ),
    (
        "trailing list punctuation",
        "the path miner trims a trailing `,` or `;` from every candidate (`cp a, b`), so \
         `./x\\,` resolves to `./x`; a protected path never ends in list punctuation",
    ),
    (
        "literal dollar in a path",
        "`\\$` leaves a literal `$` in the word Bash resolves (`./a\\${b,c}` reads `./a$b`); \
         the engine reads `${` as a parameter expansion and never expands it, and no \
         protected path contains `$`",
    ),
];

/// Fragment shapes whose divergence is known, understood and tracked rather
/// than fixed here. Each entry is a predicate over the fragment plus a comment.
/// Keep this list short; every entry is a gap the matcher still has.
type FragmentPredicate = fn(&str) -> bool;

const KNOWN_DIVERGENCES: &[(FragmentPredicate, &str)] = &[(
    brace_group_has_quoted_text,
    "quoted or escaped text inside an unquoted brace group: the tokenizer strips the \
     quotes before brace expansion, so a quoted comma or brace is treated as a list \
     delimiter (`./p{a,'b,c'}` expands to three words instead of two)",
)];

/// Deterministic xorshift64* generator; no external dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
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
fn gen_word(rng: &mut Rng) -> String {
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

fn gen_fragment(rng: &mut Rng) -> String {
    let mut f = gen_word(rng);
    for _ in 0..rng.below(3) {
        f.push_str(rng.pick(SEPARATORS));
        f.push_str(&gen_word(rng));
    }
    f
}

/// True when an unquoted brace group contains quoted or escaped text.
fn brace_group_has_quoted_text(fragment: &str) -> bool {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut chars = fragment.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\\') => {
                chars.next();
                if depth > 0 {
                    return true;
                }
            }
            (None, '\'' | '"') => {
                if depth > 0 {
                    return true;
                }
                quote = Some(c);
            }
            (None, '{') => depth += 1,
            (None, '}') => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Guard: the generated fragment must contain nothing Bash would execute or
/// expand beyond the modeled constructs. `printf` is the only command.
fn assert_inert(fragment: &str) {
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

struct BashRun {
    ok: bool,
    words: Vec<String>,
}

fn run_bash(fragment: &str, home: &std::path::Path) -> BashRun {
    let script = format!("printf \"%s\\0\" {fragment}");
    let path = std::env::var_os("PATH").unwrap_or_default();
    let output = Command::new("bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(&script)
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .current_dir(home)
        .output()
        .expect("bash spawns");
    let home_str = home.to_string_lossy().to_string();
    let words = output
        .stdout
        .split(|&b| b == 0)
        // every generated word carries a prefix, so an empty slice is only the
        // remainder after the final NUL
        .filter(|w| !w.is_empty())
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .map(|w| {
            // Bash expanded `~`; the engine keeps `~` and canonicalizes later.
            if w == home_str {
                "~".to_string()
            } else if let Some(rest) = w.strip_prefix(&format!("{home_str}/")) {
                format!("~/{rest}")
            } else {
                w
            }
        })
        .collect();
    BashRun {
        ok: output.status.success(),
        words,
    }
}

#[derive(Debug)]
struct SentinelView {
    /// Fully resolved candidates the engine would match rules against.
    resolved: BTreeSet<String>,
    /// A candidate whose brace expansion the engine refuses to inspect; it
    /// follows the on_failure posture, so every Bash word counts as covered.
    uncheckable: bool,
    /// `common::shell::shell_tokens` rejected the command as malformed.
    tokenizer_rejected: bool,
}

fn sentinel_view(fragment: &str) -> SentinelView {
    let script = format!("printf \"%s\\0\" {fragment}");
    let input = HookInput {
        tool_name: Some("Bash".into()),
        tool_input: serde_json::json!({ "command": script }),
        cwd: None,
        tool_use_id: None,
        _extra: serde_json::Map::new(),
    };
    let call = input.normalize().expect("Bash input normalizes");
    let mut resolved = BTreeSet::new();
    let mut uncheckable = false;
    for path in &call.paths {
        if path.starts_with("printf") {
            // the defense-in-depth scan of every tool_input string adds the
            // whole command; never a word on its own
            continue;
        }
        if call.shell_expansion_paths.contains(path) {
            match brace_expand_checked(path, 64) {
                Ok(expansions) => resolved.extend(expansions),
                Err(_) => uncheckable = true,
            }
        } else {
            resolved.insert(path.clone());
        }
    }
    SentinelView {
        resolved,
        uncheckable,
        tokenizer_rejected: shell_tokens(&script).is_none(),
    }
}

/// Raw forms the engine keeps next to the decoded ones by design: undecoded
/// `$'..'` or IFS text, escaped characters as written, unexpanded braces from
/// the raw view, and the cwd-joined spelling of a relative candidate.
fn is_additive_artifact(word: &str) -> bool {
    word.contains('$')
        || word.contains('\\')
        || word.contains('{')
        || word.contains('}')
        || word.starts_with("././")
}

enum Divergence {
    Under { missing: Vec<String> },
    Over { extra: Vec<String> },
    TokenizerRejected,
}

impl Divergence {
    fn describe(&self) -> String {
        match self {
            Self::Under { missing } => format!("under-resolve, bash words missing: {missing:?}"),
            Self::Over { extra } => format!("over-resolve, extra sentinel words: {extra:?}"),
            Self::TokenizerRejected => "shell_tokens rejected a command bash accepted".into(),
        }
    }
}

fn describe_all(divergences: &[Divergence]) -> String {
    divergences
        .iter()
        .map(Divergence::describe)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The path miner trims list punctuation (`cp a, b` style) from the end of
/// every candidate, so a word Bash resolved with a trailing `,` or `;` is
/// covered by its trimmed spelling (see NON_GOALS).
fn trim_list_punctuation(word: &str) -> &str {
    word.trim_end_matches([',', ';'])
}

fn compare(bash: &BashRun, sentinel: &SentinelView) -> Vec<Divergence> {
    let mut out = Vec::new();
    if sentinel.tokenizer_rejected {
        out.push(Divergence::TokenizerRejected);
    }
    let bash_words: BTreeSet<&str> = bash.words.iter().map(String::as_str).collect();
    let trimmed_bash_words: BTreeSet<&str> = bash_words
        .iter()
        .map(|w| trim_list_punctuation(w))
        .collect();
    if !sentinel.uncheckable {
        let missing: Vec<String> = bash_words
            .iter()
            .filter(|w| {
                !sentinel.resolved.contains(**w)
                    && !sentinel.resolved.contains(trim_list_punctuation(w))
                    // a literal `$` in a resolved path (from `\$`) is a non-goal
                    && !w.contains('$')
            })
            .map(|w| w.to_string())
            .collect();
        if !missing.is_empty() {
            out.push(Divergence::Under { missing });
        }
    }
    let extra: Vec<String> = sentinel
        .resolved
        .iter()
        .filter(|w| {
            !bash_words.contains(w.as_str())
                && !trimmed_bash_words.contains(w.as_str())
                && !is_additive_artifact(w)
        })
        .cloned()
        .collect();
    if !extra.is_empty() {
        out.push(Divergence::Over { extra });
    }
    out
}

fn bash_available() -> bool {
    Command::new("bash")
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg("printf x")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .map(|o| o.status.success() && o.stdout == b"x")
        .unwrap_or(false)
}

#[test]
#[ignore = "needs bash and spawns 2000 subprocesses; run with --ignored"]
fn sentinel_resolves_every_word_bash_resolves() {
    if !bash_available() {
        eprintln!("differential_shell: bash is not available, skipping");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let count: usize = std::env::var("SENTINEL_DIFF_FRAGMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let mut rng = Rng(0x5EED_2026_1008);
    let mut failures = Vec::new();
    let mut known = 0usize;
    let mut uncheckable = 0usize;
    for _ in 0..count {
        let fragment = gen_fragment(&mut rng);
        assert_inert(&fragment);
        let bash = run_bash(&fragment, home.path());
        assert!(
            bash.ok,
            "generator produced a fragment bash rejects: {fragment:?}"
        );
        let view = sentinel_view(&fragment);
        uncheckable += usize::from(view.uncheckable);
        let divergences = compare(&bash, &view);
        if divergences.is_empty() {
            continue;
        }
        if let Some((_, why)) = KNOWN_DIVERGENCES.iter().find(|(pred, _)| pred(&fragment)) {
            known += 1;
            eprintln!(
                "known divergence ({why}): {fragment:?}: {}",
                describe_all(&divergences)
            );
            continue;
        }
        failures.push(format!(
            "fragment {fragment:?}\n  bash:     {:?}\n  sentinel: {:?}\n  {}",
            bash.words,
            view.resolved,
            describe_all(&divergences)
        ));
    }
    eprintln!(
        "differential_shell: {count} fragments, {known} known divergences, {uncheckable} uncheckable"
    );
    assert!(
        failures.is_empty(),
        "{} unexplained divergence(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn non_goal_list_is_documented() {
    // The list is documentation that the harness carries; keep it non-empty
    // and free of duplicates so the scope statement stays honest.
    let names: BTreeSet<&str> = NON_GOALS.iter().map(|(n, _)| *n).collect();
    assert_eq!(names.len(), NON_GOALS.len());
    assert!(
        KNOWN_DIVERGENCES.len() <= 3,
        "fix gaps instead of listing them"
    );
}

#[test]
fn generator_is_deterministic_and_inert() {
    let mut a = Rng(7);
    let mut b = Rng(7);
    for _ in 0..200 {
        let fa = gen_fragment(&mut a);
        assert_eq!(fa, gen_fragment(&mut b));
        assert_inert(&fa);
    }
}

#[test]
fn quoted_text_inside_brace_group_is_detected() {
    assert!(brace_group_has_quoted_text("./p{a,'b,c'}"));
    assert!(brace_group_has_quoted_text("./p{a,b\\,c}"));
    assert!(!brace_group_has_quoted_text("./p{a,b}'c d'"));
    assert!(!brace_group_has_quoted_text("'{a,b}'"));
}
