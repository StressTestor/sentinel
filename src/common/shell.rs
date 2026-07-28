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

/// Expand shell brace lists (`a{b,c}d` -> `abd`, `acd`), capped at `cap` results
/// so a pathological `{a,b}{c,d}...` can't explode. A brace group with no comma
/// is left intact (shell does not expand `{x}`). Returns the input itself when
/// there is nothing to expand.
pub fn brace_expand(path: &str, cap: usize) -> Vec<String> {
    if let Some(open) = path.find('{') {
        if let Some(close_rel) = path[open..].find('}') {
            let close = open + close_rel;
            let inner = &path[open + 1..close];
            if inner.contains(',') {
                let prefix = &path[..open];
                let suffix = &path[close + 1..];
                let mut out = Vec::new();
                for part in inner.split(',') {
                    let combined = format!("{prefix}{part}{suffix}");
                    for e in brace_expand(&combined, cap) {
                        out.push(e);
                        if out.len() >= cap {
                            return out;
                        }
                    }
                }
                return out;
            }
        }
    }
    vec![path.to_string()]
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
    }

    #[test]
    fn brace_expansion_is_capped() {
        // a wide cartesian product must not explode past the cap
        let r = brace_expand("{a,b,c}{a,b,c}{a,b,c}{a,b,c}", 10);
        assert!(r.len() <= 10);
    }
}
