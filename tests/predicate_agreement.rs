//! Agreement between the regex and the match block of every bundled rule that
//! carries both (revision 2026-10-09.1 added parse-backed `match` blocks next
//! to four `deny.commands` regexes; the regex stays for one release).
//!
//! Over every Bash command the project pins (the verify set and the 2026-08
//! false-positive corpus), for each such rule:
//!
//!   - the block never fires where the regex does not. This is the
//!     zero-false-positive guard: a block that fired on a command the regex
//!     lets through would be a new block on a pinned benign command, and the
//!     test fails on it unconditionally;
//!   - the regex and the block agree, except where `KNOWN_REGEX_ONLY` says why
//!     the block is narrower on that command. Every entry names a construct
//!     the predicate vocabulary does not express (a shell command quoted
//!     inside an interpreter string, the normalizer's output-path
//!     correlation, a method-call exclusion), so the list is the measured gap
//!     between text matching and structural matching, not a bug list.
//!
//! A rule with a `match` block and no entry here, or a command the regex
//! matches and the block misses without a listed reason, fails the test.

mod common;

use sentinel_guard::install::defaults::default_policy_content;
use sentinel_guard::policy::matcher::command_match_witness;
use sentinel_guard::policy::{match_block_fires, PolicyEngine};

/// Which bundled rule a disagreement belongs to, by a stable fragment of
/// its pattern, and the command shapes where the regex alone matches.
type CommandPredicate = fn(&str) -> bool;

struct RegexOnly {
    /// A substring that identifies the rule's pattern.
    rule: &'static str,
    /// The commands this entry explains.
    applies: CommandPredicate,
    why: &'static str,
}

fn quoted_shell_pipe_inside_interpreter(command: &str) -> bool {
    command.starts_with("python3 -c ") && command.contains("| sh')")
}

fn fetched_file_executed_directly(command: &str) -> bool {
    // `curl -o /tmp/x.sh URL && /tmp/x.sh`, `curl -O URL && ./x.sh`
    command.contains("&& /tmp/x.sh") || command.contains("&& ./x.sh")
}

fn bare_exec_eval_or_system_call(command: &str) -> bool {
    command.contains("exec(") || command.contains("eval(") || command.contains("system(")
}

const KNOWN_REGEX_ONLY: &[RegexOnly] = &[
    RegexOnly {
        rule: "[a-z/]*sh\\b",
        applies: quoted_shell_pipe_inside_interpreter,
        why: "the pipe to a shell sits inside a Python string handed to os.system(); the \
              regex reads text, the block reads shell structure, and the interpreter rule \
              blocks the command either way",
    },
    RegexOnly {
        rule: "(?:source|\\.)[ \\t]+\\S",
        applies: fetched_file_executed_directly,
        why: "direct execution of the fetched output file is the normalizer's output-path \
              correlation (`curl -o x URL && ./x` reads as `sh`); then_exec names shells, \
              not downloaded paths",
    },
    RegexOnly {
        rule: "os\\.system\\(",
        applies: bare_exec_eval_or_system_call,
        why: "a bare `exec(`, `eval(` or `system(` call needs the regex's `[^.\\w]` \
              method-call exclusion (sqlite `db.exec(` must stay allowed), which a \
              substring needle cannot carry",
    },
];

#[test]
fn match_blocks_never_fire_where_the_regex_does_not_and_agree_elsewhere() {
    let engine = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
    let rules: Vec<_> = engine
        .rules()
        .into_iter()
        .filter(|r| r.section == "deny.commands" && r.matcher.is_some())
        .collect();
    assert_eq!(rules.len(), 4, "four bundled rules carry a match block");

    let mut corpus: Vec<(String, String)> = sentinel_guard::verify::bash_commands()
        .into_iter()
        .map(|c| ("verify".to_string(), c))
        .collect();
    corpus.extend(common::fp_corpus());

    let mut new_blocks = Vec::new();
    let mut unexplained = Vec::new();
    let mut explained = 0usize;
    let mut agreed = 0usize;
    let mut touched = 0usize;
    for rule in &rules {
        let spec = rule.matcher.unwrap();
        for (source, command) in &corpus {
            let regex = command_match_witness(rule.pattern, command).is_some();
            let block = match_block_fires(spec, command);
            if regex || block {
                touched += 1;
            }
            match (regex, block) {
                (false, true) => new_blocks.push(format!("{source}: {command:?} ({})", rule.id)),
                (true, false) => {
                    if let Some(entry) = KNOWN_REGEX_ONLY
                        .iter()
                        .find(|e| rule.pattern.contains(e.rule) && (e.applies)(command))
                    {
                        explained += 1;
                        eprintln!("regex only ({}): {command:?}", entry.why);
                    } else {
                        unexplained.push(format!("{source}: {command:?} ({})", rule.id));
                    }
                }
                (true, true) => agreed += 1,
                (false, false) => {}
            }
        }
    }
    eprintln!(
        "predicate_agreement: {} commands x {} rules: {touched} touched, {agreed} agreed, \
         {explained} regex-only (explained), {} unexplained, {} block-only",
        corpus.len(),
        rules.len(),
        unexplained.len(),
        new_blocks.len()
    );
    assert!(
        new_blocks.is_empty(),
        "a match block fires where its regex does not (a new block on a pinned command):\n{}",
        new_blocks.join("\n")
    );
    assert!(
        unexplained.is_empty(),
        "regex matches the block misses, with no listed reason:\n{}",
        unexplained.join("\n")
    );
}

#[test]
fn every_known_regex_only_entry_names_a_bundled_rule_and_is_exercised() {
    let engine = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
    let patterns: Vec<String> = engine
        .rules()
        .into_iter()
        .filter(|r| r.matcher.is_some())
        .map(|r| r.pattern.to_string())
        .collect();
    let corpus = common::fp_corpus();
    for entry in KNOWN_REGEX_ONLY {
        assert!(
            patterns.iter().any(|p| p.contains(entry.rule)),
            "{:?} names no bundled rule with a match block",
            entry.rule
        );
        assert!(
            corpus.iter().any(|(_, c)| (entry.applies)(c)),
            "{:?} explains no pinned command; drop the entry",
            entry.rule
        );
    }
}
