//! De-obfuscation of shell text that RESOLVES TO A REAL TARGET at runtime but
//! evades a literal matcher. Unlike Unicode homoglyph/fullwidth folding (which a
//! shell never resolves - `ｃat` is "command not found", `/ｅtc/passwd` is a
//! nonexistent literal), every transform here is one the shell actually performs
//! before the syscall:
//!
//!   - ANSI-C `$'...'` quoting: `cat $'\x2fetc\x2fpasswd'` runs `cat /etc/passwd`.
//!   - `${IFS}` / `$IFS` word-splitting: `cat${IFS}/etc/passwd` runs `cat /etc/passwd`.
//!   - brace expansion: `cat /etc/{passwd,master.passwd}` reads both real files.
//!
//! All callers test the de-obfuscated form ALONGSIDE the original (additive
//! only), so a benign command is never newly blocked - the de-obfuscated form
//! still has to match a deny rule.

/// Decode ANSI-C `$'...'` escapes and desugar `${IFS}`/`$IFS` into a space.
/// Returns `Some(decoded)` only when the result differs from the input (so the
/// hot path can skip a redundant second match), `None` otherwise.
pub fn decode_obfuscation(cmd: &str) -> Option<String> {
    let step1 = desugar_ifs(cmd);
    let step2 = decode_ansi_c(&step1);
    if step2 != cmd {
        Some(step2)
    } else {
        None
    }
}

/// Replace `${IFS}`, `${IFS:0:1}` (any `${IFS...}`), and a bare `$IFS` (not
/// followed by another word character, so `$IFSX` is left alone) with a space -
/// the word-split the shell performs, which an attacker uses to glue a command
/// word to its argument so it mines as one token.
fn desugar_ifs(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0;
    while i < cmd.len() {
        let rest = &cmd[i..];
        if rest.starts_with("${IFS") {
            if let Some(close) = rest.find('}') {
                out.push(' ');
                i += close + 1;
                continue;
            }
        }
        if let Some(after_ifs) = rest.strip_prefix("$IFS") {
            let after = after_ifs.chars().next();
            if !matches!(after, Some(c) if c.is_alphanumeric() || c == '_') {
                out.push(' ');
                i += 4;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Decode every `$'...'` ANSI-C-quoted span in the command to its literal text.
fn decode_ansi_c(cmd: &str) -> String {
    if !cmd.contains("$'") {
        return cmd.to_string();
    }
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            let mut j = i + 2;
            let mut body = String::new();
            let mut closed = false;
            while j < chars.len() {
                if chars[j] == '\'' {
                    closed = true;
                    break;
                }
                if chars[j] == '\\' && j + 1 < chars.len() {
                    let (decoded, consumed) = decode_escape(&chars[j + 1..]);
                    body.push_str(&decoded);
                    j += 1 + consumed;
                } else {
                    body.push(chars[j]);
                    j += 1;
                }
            }
            if closed {
                out.push_str(&body);
                i = j + 1;
                continue;
            }
            // unterminated $'...': leave as written
            out.push('$');
            out.push('\'');
            i += 2;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Decode one backslash escape (the chars AFTER the backslash). Returns the
/// decoded text and how many chars were consumed past the backslash.
fn decode_escape(rest: &[char]) -> (String, usize) {
    if rest.is_empty() {
        return ("\\".into(), 0);
    }
    match rest[0] {
        'x' => hex_escape(&rest[1..], 2).unwrap_or_else(|| ("x".into(), 1)),
        'u' => hex_escape(&rest[1..], 4).unwrap_or_else(|| ("u".into(), 1)),
        'U' => hex_escape(&rest[1..], 8).unwrap_or_else(|| ("U".into(), 1)),
        '0'..='7' => {
            let oct: String = rest
                .iter()
                .take(3)
                .take_while(|c| ('0'..='7').contains(c))
                .collect();
            match u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
                Some(c) => (c.to_string(), oct.len()),
                None => (oct.clone(), oct.len()),
            }
        }
        'n' => ("\n".into(), 1),
        't' => ("\t".into(), 1),
        'r' => ("\r".into(), 1),
        'e' | 'E' => ("\x1b".into(), 1),
        'a' => ("\x07".into(), 1),
        'b' => ("\x08".into(), 1),
        'f' => ("\x0c".into(), 1),
        'v' => ("\x0b".into(), 1),
        '\\' => ("\\".into(), 1),
        '\'' => ("'".into(), 1),
        '"' => ("\"".into(), 1),
        c => (c.to_string(), 1),
    }
}

/// `\xHH` / `\uHHHH` / `\UHHHHHHHH`: take up to `max` hex digits.
fn hex_escape(rest: &[char], max: usize) -> Option<(String, usize)> {
    let hex: String = rest
        .iter()
        .take(max)
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    let c = u32::from_str_radix(&hex, 16)
        .ok()
        .and_then(char::from_u32)?;
    // +1 for the leading x/u/U selector consumed by the caller's match arm
    Some((c.to_string(), 1 + hex.len()))
}

/// Why a shell brace token could not be inspected completely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BraceExpansionError {
    /// Full list expansion would produce more than the bounded result set.
    LimitExceeded { cap: usize },
    /// Syntax whose output varies across supported Bash versions.
    VersionDependentSequence { expression: String },
}

impl std::fmt::Display for BraceExpansionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded { cap } => {
                write!(f, "brace expansion exceeds the {cap}-way inspection cap")
            }
            Self::VersionDependentSequence { expression } => {
                write!(f, "version-dependent shell brace sequence {{{expression}}}")
            }
        }
    }
}

/// Expand shell brace lists (`a{b,c}d` -> `abd`, `acd`) without silently
/// truncating. Nested and adjacent list groups are handled with Bash's outer
/// group ordering, while groups without a top-level comma remain literal.
/// Version-stable two-endpoint numeric and alphabetic sequences are expanded
/// exactly. Optional steps and padded/signed-zero endpoints vary across the Bash
/// versions Sentinel supports, so they are explicit errors. This distinction is
/// security-critical: a partial or version-dependent expansion is not proof that
/// a protected path is absent.
pub fn brace_expand_checked(path: &str, cap: usize) -> Result<Vec<String>, BraceExpansionError> {
    let mut out = Vec::new();
    expand_brace_lists(path, cap, &mut out)?;
    Ok(out)
}

/// Compatibility wrapper for non-enforcement callers. Security-sensitive code
/// must use `brace_expand_checked` so an uninspectable token is not confused
/// with a literal path or a complete partial expansion.
#[cfg(test)]
pub fn brace_expand(path: &str, cap: usize) -> Vec<String> {
    brace_expand_checked(path, cap).unwrap_or_else(|_| vec![path.to_string()])
}

fn expand_brace_lists(
    word: &str,
    cap: usize,
    out: &mut Vec<String>,
) -> Result<(), BraceExpansionError> {
    if let Some(group) = find_expandable_group(word)? {
        let prefix = &word[..group.open];
        let suffix = &word[group.close + 1..];
        match group.members {
            BraceMembers::List(parts) => {
                for part in parts {
                    let combined = format!("{prefix}{part}{suffix}");
                    expand_brace_lists(&combined, cap, out)?;
                }
            }
            BraceMembers::Sequence(sequence) => {
                sequence.expand(|part| {
                    let combined = format!("{prefix}{part}{suffix}");
                    expand_brace_lists(&combined, cap, out)
                })?;
            }
        }
        return Ok(());
    }

    if out.len() >= cap {
        return Err(BraceExpansionError::LimitExceeded { cap });
    }
    out.push(word.to_string());
    Ok(())
}

struct BraceGroup<'a> {
    open: usize,
    close: usize,
    members: BraceMembers<'a>,
}

enum BraceMembers<'a> {
    List(Vec<&'a str>),
    Sequence(BraceSequence),
}

enum BraceSequence {
    Numeric { start: i64, end: i64 },
    Alpha { start: u8, end: u8 },
}

impl BraceSequence {
    fn expand(
        &self,
        mut emit: impl FnMut(String) -> Result<(), BraceExpansionError>,
    ) -> Result<(), BraceExpansionError> {
        match self {
            Self::Numeric { start, end } => {
                expand_sequence_values(*start as i128, *end as i128, |value| {
                    emit(value.to_string())
                })
            }
            Self::Alpha { start, end } => {
                expand_sequence_values(*start as i128, *end as i128, |value| {
                    emit((value as u8 as char).to_string())
                })
            }
        }
    }
}

/// Find the leftmost shell-expandable list group. An outer group with a
/// top-level comma wins over its nested groups, matching Bash and avoiding
/// duplicate synthetic expansions for `a{b,{c,d}}`. If an outer pair is
/// literal, nested expandable groups are still considered (`{x{a,b}}`).
fn find_expandable_group(word: &str) -> Result<Option<BraceGroup<'_>>, BraceExpansionError> {
    find_expandable_group_in(word, 0, word.len())
}

fn find_expandable_group_in(
    word: &str,
    start: usize,
    end: usize,
) -> Result<Option<BraceGroup<'_>>, BraceExpansionError> {
    let bytes = word.as_bytes();
    let mut open = start;
    while open < end {
        if bytes[open] != b'{' || open.checked_sub(1).is_some_and(|i| bytes[i] == b'$') {
            open += 1;
            continue;
        }
        let Some(close) = matching_brace(bytes, open, end) else {
            // An unmatched brace is a literal in the shell. A later balanced
            // group may still expand, so continue scanning after this opener.
            open += 1;
            continue;
        };
        let inner = &word[open + 1..close];
        if let Some(parts) = split_top_level_commas(inner) {
            return Ok(Some(BraceGroup {
                open,
                close,
                members: BraceMembers::List(parts),
            }));
        }
        match parse_shell_sequence(inner) {
            SequenceParse::Stable(sequence) => {
                return Ok(Some(BraceGroup {
                    open,
                    close,
                    members: BraceMembers::Sequence(sequence),
                }));
            }
            SequenceParse::VersionDependent => {
                return Err(BraceExpansionError::VersionDependentSequence {
                    expression: inner.to_string(),
                });
            }
            SequenceParse::Literal => {}
        }
        if let Some(nested) = find_expandable_group_in(word, open + 1, close)? {
            return Ok(Some(nested));
        }
        open = close + 1;
    }
    Ok(None)
}

fn matching_brace(bytes: &[u8], open: usize, end: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = open + 1;
    while i < end {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_top_level_commas(inner: &str) -> Option<Vec<&str>> {
    let bytes = inner.as_bytes();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (i, byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if parts.is_empty() {
        None
    } else {
        parts.push(&inner[start..]);
        Some(parts)
    }
}

enum SequenceParse {
    Stable(BraceSequence),
    VersionDependent,
    Literal,
}

/// Expand only the subset whose behavior is stable across Bash 3.2 and current
/// Bash: two endpoints, both plain decimal integers (an ordinary leading `-` is
/// allowed, but zero-padded/explicit-plus spellings are not), or two single
/// ASCII letters in the same case. Optional increments, padding, signed zero,
/// and cross-case alpha ranges vary by version and are uncheckable.
fn parse_shell_sequence(inner: &str) -> SequenceParse {
    let parts: Vec<&str> = inner.split("..").collect();
    if parts.len() == 3 && valid_endpoint_pair(parts[0], parts[1]) {
        return SequenceParse::VersionDependent;
    }
    if parts.len() != 2 {
        return SequenceParse::Literal;
    }
    if plain_integer(parts[0]) && plain_integer(parts[1]) {
        let (Ok(start), Ok(end)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) else {
            return SequenceParse::VersionDependent;
        };
        return SequenceParse::Stable(BraceSequence::Numeric { start, end });
    }
    if is_single_ascii_alpha(parts[0]) && is_single_ascii_alpha(parts[1]) {
        let start = parts[0].as_bytes()[0];
        let end = parts[1].as_bytes()[0];
        if start.is_ascii_lowercase() == end.is_ascii_lowercase() {
            return SequenceParse::Stable(BraceSequence::Alpha { start, end });
        }
        return SequenceParse::VersionDependent;
    }
    if valid_endpoint_pair(parts[0], parts[1]) {
        SequenceParse::VersionDependent
    } else {
        SequenceParse::Literal
    }
}

fn is_single_ascii_alpha(value: &str) -> bool {
    value.len() == 1 && value.as_bytes()[0].is_ascii_alphabetic()
}

fn plain_integer(value: &str) -> bool {
    if value == "-0" {
        return false;
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    digits == "0" || !digits.starts_with('0')
}

fn valid_endpoint_pair(start: &str, end: &str) -> bool {
    (start.parse::<i64>().is_ok() && end.parse::<i64>().is_ok())
        || (is_single_ascii_alpha(start) && is_single_ascii_alpha(end))
}

fn expand_sequence_values(
    start: i128,
    end: i128,
    mut emit: impl FnMut(i128) -> Result<(), BraceExpansionError>,
) -> Result<(), BraceExpansionError> {
    let ascending = start <= end;
    let delta = if ascending { 1 } else { -1 };
    let mut value = start;
    while if ascending {
        value <= end
    } else {
        value >= end
    } {
        emit(value)?;
        value += delta;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_c_hex_decodes_to_path() {
        assert_eq!(
            decode_obfuscation("cat $'\\x2fetc\\x2fpasswd'").as_deref(),
            Some("cat /etc/passwd")
        );
    }

    #[test]
    fn ansi_c_decodes_command_word() {
        // $'\x72\x6d' is "rm"
        assert_eq!(
            decode_obfuscation("$'\\x72\\x6d' -rf /").as_deref(),
            Some("rm -rf /")
        );
    }

    #[test]
    fn ansi_c_octal_and_unicode() {
        // \057 octal = '/'
        assert_eq!(
            decode_obfuscation("cat $'\\057etc\\057passwd'").as_deref(),
            Some("cat /etc/passwd")
        );
        // / = '/'
        assert_eq!(
            decode_obfuscation("cat $'\\u002fetc\\u002fpasswd'").as_deref(),
            Some("cat /etc/passwd")
        );
    }

    #[test]
    fn ifs_desugar_brace_and_bare() {
        assert_eq!(
            decode_obfuscation("cat${IFS}/etc/passwd").as_deref(),
            Some("cat /etc/passwd")
        );
        assert_eq!(
            decode_obfuscation("cat${IFS:0:1}/etc/passwd").as_deref(),
            Some("cat /etc/passwd")
        );
        assert_eq!(
            decode_obfuscation("cat$IFS/etc/passwd").as_deref(),
            Some("cat /etc/passwd")
        );
    }

    #[test]
    fn ifs_leaves_unrelated_vars_alone() {
        // $IFSX is a different variable - must not be touched (and no other change
        // => None)
        assert_eq!(decode_obfuscation("echo $IFSXYZ"), None);
        // a plain command with nothing to decode returns None
        assert_eq!(decode_obfuscation("cat /etc/hosts"), None);
    }

    #[test]
    fn brace_expands_path_list() {
        assert_eq!(
            brace_expand("/etc/{passwd,master.passwd}", 64),
            vec!["/etc/passwd".to_string(), "/etc/master.passwd".to_string()]
        );
        // nested / multiple groups expand cartesian
        let r = brace_expand("~/{.ssh,.aws}/{a,b}", 64);
        assert!(r.contains(&"~/.ssh/a".to_string()));
        assert!(r.contains(&"~/.aws/b".to_string()));
        // no comma => left intact
        assert_eq!(
            brace_expand("/etc/{passwd}", 64),
            vec!["/etc/{passwd}".to_string()]
        );
        // no brace => identity
        assert_eq!(
            brace_expand("/etc/passwd", 64),
            vec!["/etc/passwd".to_string()]
        );
        // outer-list ordering avoids duplicate expansion and handles nesting
        assert_eq!(
            brace_expand("a{b,{c,d}}e", 64),
            vec!["abe".to_string(), "ace".to_string(), "ade".to_string()]
        );
        assert_eq!(
            brace_expand("{x{a,b}}", 64),
            vec!["{xa}".to_string(), "{xb}".to_string()]
        );
    }

    #[test]
    fn checked_brace_expansion_reports_cap_instead_of_truncating() {
        assert_eq!(
            brace_expand_checked("{a,b,c}{a,b,c}{a,b,c}{a,b,c}", 10),
            Err(BraceExpansionError::LimitExceeded { cap: 10 })
        );
    }

    #[test]
    fn checked_brace_expansion_matches_version_stable_sequences() {
        assert_eq!(
            brace_expand_checked("/tmp/file{1..3}", 64).unwrap(),
            vec!["/tmp/file1", "/tmp/file2", "/tmp/file3"]
        );
        assert_eq!(
            brace_expand_checked("/tmp/file{3..1}", 64).unwrap(),
            vec!["/tmp/file3", "/tmp/file2", "/tmp/file1"]
        );
        assert_eq!(
            brace_expand_checked("/tmp/file{c..a}", 64).unwrap(),
            vec!["/tmp/filec", "/tmp/fileb", "/tmp/filea"]
        );
        assert_eq!(
            brace_expand_checked("~/.ss{g..i}/id_rsa", 64).unwrap(),
            vec!["~/.ssg/id_rsa", "~/.ssh/id_rsa", "~/.ssi/id_rsa"]
        );
    }

    #[test]
    fn version_dependent_sequences_are_explicitly_uncheckable() {
        for expression in [
            "1..5..2", "1..5..-2", "5..1..2", "5..1..-2", "01..03", "-02..02", "+01..+03", "-0..2",
            "a..e..2", "Z..b",
        ] {
            assert_eq!(
                brace_expand_checked(&format!("/tmp/file{{{expression}}}"), 64),
                Err(BraceExpansionError::VersionDependentSequence {
                    expression: expression.into()
                })
            );
        }
    }

    #[test]
    fn checked_brace_sequence_reports_cap_instead_of_truncating() {
        assert_eq!(
            brace_expand_checked("/tmp/file{1..100}", 64),
            Err(BraceExpansionError::LimitExceeded { cap: 64 })
        );
    }

    #[test]
    fn invalid_sequence_syntax_remains_literal() {
        assert_eq!(
            brace_expand_checked("/tmp/{foo..bar}", 64).unwrap(),
            vec!["/tmp/{foo..bar}".to_string()]
        );
    }
}
