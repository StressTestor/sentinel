//! Safe, comment-preserving migration of installed Sentinel policies.
//!
//! Published policies before this module had no generation marker. We rebuild
//! the semantic defaults shipped by 0.4.0 and crates.io 0.4.1 from the current
//! bundled policy, select the closest published base, then perform a field-wise
//! three-way merge: base -> user policy <- current. User-only rules, unknown
//! fields, comments, mode, and non-overlapping rule edits survive. If both the
//! user and Sentinel changed the same field, migration reports a conflict and
//! never writes.

use crate::cli::PolicyMigrateArgs;
use crate::evaluate::{pipeline, resolve_policy_path};
use crate::install::defaults::default_policy_content;
pub use crate::install::defaults::CURRENT_POLICY_REVISION;
use crate::lint::lint_engine;
use crate::policy::{Action, PolicyEngine};
use crate::verify::verify_against;
use std::fmt;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishedGeneration {
    V0_4_0,
    V0_4_1,
    Draft2026_07_28,
    Rev2026_07_28_1,
}

impl fmt::Display for PublishedGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V0_4_0 => write!(f, "published 0.4.0"),
            Self::V0_4_1 => write!(f, "published 0.4.1"),
            Self::Draft2026_07_28 => write!(f, "draft revision 2026-07-28"),
            Self::Rev2026_07_28_1 => write!(f, "revision 2026-07-28.1"),
        }
    }
}

const DRAFT_POLICY_REVISION: &str = "2026-07-28";
const PRIOR_POLICY_REVISION: &str = "2026-07-28.1";

#[derive(Debug)]
pub enum MigrationInspection {
    Current,
    Needed(MigrationPlan),
}

#[derive(Debug)]
pub struct MigrationPlan {
    pub from: PublishedGeneration,
    pub rendered: String,
    pub changes: Vec<String>,
}

#[derive(Debug)]
pub struct AppliedMigration {
    pub from: PublishedGeneration,
    pub backup_path: PathBuf,
    pub changes: Vec<String>,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("failed to read policy at {path}: {error}")]
    Read { path: String, error: String },
    #[error("policy path is a symlink; refusing to replace it atomically: {0}")]
    Symlink(String),
    #[error("invalid policy TOML: {0}")]
    Parse(String),
    #[error("policy has unsupported revision {0:?}; no migration was attempted")]
    UnsupportedRevision(String),
    #[error(
        "could not identify this unversioned policy as published 0.4.0 or 0.4.1 \
         (equal semantic distance {score}); no migration was attempted"
    )]
    AmbiguousGeneration { score: usize },
    #[error("policy migration has conflicts; no file was rewritten:\n{0}")]
    Conflicts(String),
    #[error("policy migration is required from {from} to revision {to}")]
    MigrationRequired {
        from: PublishedGeneration,
        to: &'static str,
    },
    #[error("failed to write {path}: {error}")]
    Write { path: String, error: String },
    #[error(
        "migrated policy failed validation and the original was restored \
         (backup retained at {backup}): {reason}"
    )]
    ValidationRolledBack { reason: String, backup: String },
    #[error(
        "migrated policy failed validation ({validation}) and rollback also failed ({rollback}); \
         recovery backup is at {backup}"
    )]
    RollbackFailed {
        validation: String,
        rollback: String,
        backup: String,
    },
    #[error("internal migration baseline error: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleSection {
    DenyPaths,
    DenyCommands,
    DenySecrets,
    DenyTools,
    AllowPaths,
}

impl RuleSection {
    const ALL: [Self; 5] = [
        Self::DenyPaths,
        Self::DenyCommands,
        Self::DenySecrets,
        Self::DenyTools,
        Self::AllowPaths,
    ];

    fn path(self) -> (&'static str, &'static str) {
        match self {
            Self::DenyPaths => ("deny", "paths"),
            Self::DenyCommands => ("deny", "commands"),
            Self::DenySecrets => ("deny", "secrets"),
            Self::DenyTools => ("deny", "tools"),
            Self::AllowPaths => ("allow", "paths"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::DenyPaths => "deny.paths",
            Self::DenyCommands => "deny.commands",
            Self::DenySecrets => "deny.secrets",
            Self::DenyTools => "deny.tools",
            Self::AllowPaths => "allow.paths",
        }
    }

    fn managed_fields(self) -> &'static [&'static str] {
        match self {
            Self::AllowPaths => &["pattern", "note"],
            _ => &["pattern", "action", "reason"],
        }
    }
}

#[derive(Clone, Copy)]
struct RuleChange {
    section: RuleSection,
    current_pattern: &'static str,
    old_pattern: &'static str,
    old_action: Option<&'static str>,
    old_reason: Option<&'static str>,
}

// the 2026-08 false-positive audit (docs/policy-fp-audit-2026-08.md) split three
// rules that matched a shape rather than a threat. these two lists reverse that
// split, and unlike the 0.4.x ladder they apply to EVERY prior generation - the
// draft included, since it predates the audit.
const CURRENT_TO_2026_07_28_1: &[RuleChange] = &[
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"rm\s+-rf\s+(?:[^\s;&|\n]+\s+)*/+(?:\.{1,2})?(["\x27\s<>;|&]|$|[*?\[{$])"#,
        old_pattern: r#"rm\s+-rf\s+(?:[^\s]+\s+)*/"#,
        old_action: None,
        old_reason: Some("recursive root deletion"),
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"rm\s+-rf\s+(?:~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+)/\.(ssh|aws|gnupg|config|netrc)"#,
        old_pattern: r#"rm\s+-rf\s+~/\.(ssh|aws|gnupg|config|netrc)"#,
        old_action: None,
        old_reason: Some("recursive deletion of credential directory"),
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(curl|wget|fetch)\b.*\s-[oO]\b.*[;&|]\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|]*|[0-9]?[<>]{1,2}&?[^\s;&|]*|[({!])\s*)*(?:(?:[\w.-]*/)*(?:env|nice|nohup|setsid|stdbuf|sudo|doas|time|timeout|ionice|command|exec|xargs|eval)\s+(?:-[^\s]*\s+)*)*(?:(?:[\w.~$-]*/)*(?:ba|z|da|k|c|tc|fi|a)?sh\b|(?:source|\.)[ \t]+\S)"#,
        old_pattern: r#"\b(curl|wget|fetch)\b.*-[oO]\b.*[;&|].*\b(ba|z|da)?sh\b"#,
        old_action: None,
        old_reason: Some("staged fetch-then-run (download then execute)"),
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"(?s)\b(python3?|perl|ruby|node|php|osascript)\b\s+-\w*[ce]\b(?:.*(urllib|requests|socket|httplib|http\.client|net/http|open-uri|\bhttps?\b).*(os\.system|\bexec\b|\beval\b|popen|subprocess|child_process)|.*(os\.system|\bexec\b|\beval\b|popen|subprocess|child_process).*(urllib|requests|socket|httplib|http\.client|net/http|open-uri|\bhttps?\b))"#,
        old_pattern: r#"\b(python3?|perl|ruby|node|php|osascript)\b\s+-\w*[ce]\b.*(urllib|requests|socket|httplib|http\.client|net/http|open-uri|os\.system|\bexec\b|\beval\b|popen|subprocess|child_process)"#,
        old_action: None,
        old_reason: Some("interpreter fetch-exec / inline remote code execution"),
    },
];

const ADDED_AFTER_2026_07_28_1: &[(&str, RuleSection)] = &[
    (
        r#"rm\s+-rf\s+(?:[^\s;&|\n]+\s+)*/(?:bin|sbin|boot|lib|lib64|usr|etc|root|run|srv|proc|sys|System|Library|Applications|dev|cores)(["\x27\s<>;|&/]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"rm\s+-rf\s+(?:[^\s;&|\n]+\s+)*/tmp/?(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"rm\s+-rf\s+(?:[^\s;&|\n]+\s+)*/(?:Users|Volumes|home|mnt|media|var|private|opt|Network)(?:/[^/\s;&|"\x27]+)?/?(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"rm\s+-rf\s+(?:[^\s;&|\n]+\s+)*(?:~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+)/\.[^\s;&|"\x27/]*[*?\[]"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(curl|wget|fetch)\b.*\s-[oO]\b.*[;&|]\s*(?:(?:[\w.-]*/)*(?:sudo|doas)\s+)?chmod\s+(?:-\S+\s+)*(?:[augo]*\+[rwXst]*x|[0-7]*[1357])"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"(?s)\b(python3?|perl|ruby|node|deno|bun|php|osascript)\b\s+(-\w*[ce]\b|--eval\b).*(urllib|httplib|http\.client|net/http|open-uri|requests\.[A-Za-z_]+\(|socket\.socket\(|socket\.create_connection|Net::HTTP|require\(\s*[\x27"](http|https|net|dgram|tls)[\x27"]\s*\)|import\(\s*[\x27"](http|https|net)[\x27"]|fetch\(\s*[\x27"`]https?://)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"(?s)\b(python3?|perl|ruby|node|deno|bun|php|osascript)\b\s+(-\w*[ce]\b|--eval\b).*(os\.system\(|os\.popen\(|os\.dup2|pty\.spawn|shell\s*=\s*True|child_process|\bexecSync\(|\bexecFileSync\(|\bspawnSync\(|(^|[^.\w])exec\(|(^|[^.\w])eval\(|IO\.popen|(^|[^.\w])system\()"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"(?s)\b(python3?|perl|ruby|node|deno|bun|php|osascript)\b\s+(-\w*[ce]\b|--eval\b).*subprocess\.(run|Popen|call|check_call|check_output)\s*\(\s*(?:(?:args\s*=\s*)?(?:\[|\()\s*[\x27\"](?:/[^/\x27\"]+)*\/?(?:ba|z|da|k|c|tc|fi|a)?sh[\x27\"]|.*?\bexecutable\s*=\s*[\x27\"](?:/[^/\x27\"]+)*\/?(?:ba|z|da|k|c|tc|fi|a)?sh[\x27\"])"#,
        RuleSection::DenyCommands,
    ),
];

const CURRENT_TO_0_4_1: &[RuleChange] = &[
    RuleChange {
        section: RuleSection::DenyPaths,
        current_pattern: "~/.sentinel/policy.toml",
        old_pattern: "~/.sentinel/policy.toml",
        old_action: Some("block"),
        old_reason: Some(
            "Sentinel's own enforcement policy - agent writes blocked so an injected agent \
             can't disable the guard mid-session (reconfigure outside the agent)",
        ),
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(rm|mv|ln|cp|chmod|chflags|strip|truncate|dd)\b[^;&|\n]*\bsentinel-guard\b"#,
        old_pattern: r#"\b(rm|mv|ln|cp|chmod|chflags|strip|truncate|dd)\b.*\bsentinel-guard\b"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(rm|mv|ln|cp|chmod|chflags|strip|truncate)\b[^;&|\n]*/sentinel(["\x27\s<>;|&]|$)"#,
        old_pattern: r#"\b(rm|mv|ln|cp|chmod|chflags|strip|truncate)\b.*/sentinel(["\x27\s<>;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(rm|mv)\b[^;&|\n]*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.claude(/settings(\.local)?\.json|/)?(["\x27\s;|&]|$)"#,
        old_pattern: r#"\b(rm|mv)\b.*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.claude(/settings(\.local)?\.json|/)?(["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(rm|mv|truncate|chflags)\b[^;&|\n]*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.sentinel(/|["\x27\s;|&]|$)"#,
        old_pattern: r#"\b(rm|mv)\b.*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.sentinel(/|["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(tee|sponge)\b[^;&|\n]*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_pattern: r#"\b(tee|sponge)\b.*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(cp|install|ln|dd|truncate)\b[^;&|\n]*\.claude/settings(\.local)?\.json(\s+-\S+)*\s*$"#,
        old_pattern: r#"\b(cp|install|ln|dd|truncate)\b.*\.claude/settings(\.local)?\.json(\s+-\S+)*\s*$"#,
        old_action: None,
        old_reason: None,
    },
];

const MCP_TRUST_ADDITIONS: &[(&str, RuleSection)] = &[
    ("~/.sentinel/mcp-baseline.json", RuleSection::DenyPaths),
    (
        r#"(?:^|[;&|]\s*)(?:(?:sudo|doas|env|command|exec|nohup)\s+)*["\x27]?(?:\S*/)?sentinel["\x27]?\s+audit-mcp\b[^;&|\n]*--update(["\x27\s;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(sed|gsed|perl|awk)\b.*\s-i\b.*\.sentinel/mcp-baseline\.json(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(ed|ex)\b\s+\S*\.sentinel/mcp-baseline\.json(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#">>?\|?\s*"?\S*\.sentinel/mcp-baseline\.json(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(tee|sponge)\b[^;&|\n]*\.sentinel/mcp-baseline\.json(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(cp|install|ln|dd|truncate)\b[^;&|\n]*\.sentinel/mcp-baseline\.json(\s+-\S+)*\s*$"#,
        RuleSection::DenyCommands,
    ),
];

const ADDED_AFTER_0_4_1: &[(&str, RuleSection)] = &[
    (
        r#"\b(sed|gsed|perl|awk)\b.*\s-i\b.*\.sentinel/policy\.toml(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(ed|ex)\b\s+\S*\.sentinel/policy\.toml(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#">>?\|?\s*"?\S*\.sentinel/policy\.toml(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(tee|sponge)\b[^;&|\n]*\.sentinel/policy\.toml(["\x27\s<>;|&]|$)"#,
        RuleSection::DenyCommands,
    ),
    (
        r#"\b(cp|install|ln|dd|truncate)\b[^;&|\n]*\.sentinel/policy\.toml(\s+-\S+)*\s*$"#,
        RuleSection::DenyCommands,
    ),
];

const V0_4_1_TO_0_4_0: &[RuleChange] = &[
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"rm\s+-rf\s+(?:[^\s]+\s+)*/"#,
        old_pattern: r#"rm\s+-rf\s+/(\s|$|[^~])"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(curl|wget|fetch)\b[^|]*\|(?:[^|]*\|)*\s*(?:(?:[\w./-]*/)?(?:env|nice|nohup|setsid|stdbuf|sudo|doas|time|timeout|ionice|command|exec|xargs)\b[^|]*\s)?[a-z/]*sh\b"#,
        old_pattern: r#"\b(curl|wget|fetch)\b[^|]*\|\s*[a-z/]*sh\b"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(rm|mv)\b.*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.claude(/settings(\.local)?\.json|/)?(["\x27\s;|&]|$)"#,
        old_pattern: r#"\b(rm|mv)\b.*(~|\$HOME|/Users/[^/ ]+|/home/[^/ ]+)/\.claude(/settings(\.local)?\.json)?(["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(sed|gsed|perl|awk)\b.*\s-i\b.*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_pattern: r#"\b(sed|gsed|perl|awk)\b.*\s-i\b.*\.claude/settings(\.local)?\.json(["\x27\s;|&>]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(ed|ex)\b\s+\S*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_pattern: r#"\b(ed|ex)\b\s+\S*\.claude/settings(\.local)?\.json(["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#">>?\|?\s*"?\S*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_pattern: r#">>?\|?\s*"?\S*\.claude/settings(\.local)?\.json(["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(tee|sponge)\b.*\.claude/settings(\.local)?\.json(["\x27\s<>;|&]|$)"#,
        old_pattern: r#"\b(tee|sponge)\b.*\.claude/settings(\.local)?\.json(["\x27\s;|&]|$)"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"(?i:\b(curl|wget|fetch)\b).*(--data(-binary|-raw|-urlencode)?|--form|--post-data|\s-d\b|\s-F\b)[= ]\S*\$\{?(?i:[a-z_]*(secret|token|key|password|aws_))"#,
        old_pattern: r#"\b(curl|wget|fetch)\b.*(--data(-binary|-raw|-urlencode)?|--form|--post-data|\s-d\b|\s-F\b)[= ]\S*\$\{?(?i:[a-z_]*(secret|token|key|password|aws_))"#,
        old_action: None,
        old_reason: None,
    },
    RuleChange {
        section: RuleSection::DenyCommands,
        current_pattern: r#"\b(nc|ncat)\b(?:\\.|"(?:\\.|[^"\\])*"|\x27[^\x27]*\x27|[^&;|"\x27\\])*<\s*\S"#,
        old_pattern: r#"\b(nc|ncat)\b[^&;|]*<\s*\S"#,
        old_action: None,
        old_reason: None,
    },
];

pub fn inspect_path(path: &Path) -> Result<MigrationInspection, MigrationError> {
    let content = fs::read_to_string(path).map_err(|error| MigrationError::Read {
        path: path.display().to_string(),
        error: error.to_string(),
    })?;
    inspect_content(&content)
}

pub fn inspect_content(content: &str) -> Result<MigrationInspection, MigrationError> {
    let local = parse_document(content)?;
    let (from, base) = match policy_revision(&local)? {
        Some(revision) if revision == CURRENT_POLICY_REVISION => {
            return Ok(MigrationInspection::Current);
        }
        Some(revision) if revision == DRAFT_POLICY_REVISION => (
            PublishedGeneration::Draft2026_07_28,
            draft_default("enforce")?,
        ),
        Some(revision) if revision == PRIOR_POLICY_REVISION => (
            PublishedGeneration::Rev2026_07_28_1,
            prior_default("enforce")?,
        ),
        Some(revision) => return Err(MigrationError::UnsupportedRevision(revision)),
        None => {
            let from = recognize_generation(&local)?;
            (from, published_default(from, "enforce")?)
        }
    };
    let current = parse_document(&default_policy_content("enforce"))?;
    let (merged, changes, conflicts) = merge_documents(local, &base, &current, from)?;
    if !conflicts.is_empty() {
        return Err(MigrationError::Conflicts(conflicts.join("\n")));
    }
    Ok(MigrationInspection::Needed(MigrationPlan {
        from,
        rendered: merged.to_string(),
        changes,
    }))
}

pub fn apply_path(path: &Path) -> Result<Option<AppliedMigration>, MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| MigrationError::Read {
        path: path.display().to_string(),
        error: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(MigrationError::Symlink(path.display().to_string()));
    }
    let original = fs::read_to_string(path).map_err(|error| MigrationError::Read {
        path: path.display().to_string(),
        error: error.to_string(),
    })?;
    let plan = match inspect_content(&original)? {
        MigrationInspection::Current => return Ok(None),
        MigrationInspection::Needed(plan) => plan,
    };

    let permissions = metadata.permissions();
    let backup_path = create_backup(path, &original, permissions.clone())?;
    atomic_write(path, &plan.rendered, permissions.clone())?;

    if let Err(validation) = validate_written_policy(path) {
        return match atomic_write(path, &original, permissions) {
            Ok(()) => Err(MigrationError::ValidationRolledBack {
                reason: validation,
                backup: backup_path.display().to_string(),
            }),
            Err(rollback) => Err(MigrationError::RollbackFailed {
                validation,
                rollback: rollback.to_string(),
                backup: backup_path.display().to_string(),
            }),
        };
    }

    Ok(Some(AppliedMigration {
        from: plan.from,
        backup_path,
        changes: plan.changes,
    }))
}

pub fn run(args: PolicyMigrateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.policy.unwrap_or_else(resolve_policy_path);
    if args.check {
        match inspect_path(&path)? {
            MigrationInspection::Current => {
                println!(
                    "{}: current policy revision {}",
                    path.display(),
                    CURRENT_POLICY_REVISION
                );
                Ok(())
            }
            MigrationInspection::Needed(plan) => {
                println!(
                    "{}: migration required from {} to revision {}",
                    path.display(),
                    plan.from,
                    CURRENT_POLICY_REVISION
                );
                for change in &plan.changes {
                    println!("  - {change}");
                }
                Err(MigrationError::MigrationRequired {
                    from: plan.from,
                    to: CURRENT_POLICY_REVISION,
                }
                .into())
            }
        }
    } else {
        match apply_path(&path)? {
            None => {
                println!(
                    "{}: already at policy revision {}",
                    path.display(),
                    CURRENT_POLICY_REVISION
                );
            }
            Some(applied) => {
                println!(
                    "{}: migrated {} policy to revision {}",
                    path.display(),
                    applied.from,
                    CURRENT_POLICY_REVISION
                );
                println!("backup: {}", applied.backup_path.display());
                for change in &applied.changes {
                    println!("  - {change}");
                }
            }
        }
        Ok(())
    }
}

fn parse_document(content: &str) -> Result<DocumentMut, MigrationError> {
    content
        .parse::<DocumentMut>()
        .map_err(|error| MigrationError::Parse(error.to_string()))
}

fn policy_revision(doc: &DocumentMut) -> Result<Option<String>, MigrationError> {
    let policy = doc
        .get("policy")
        .and_then(Item::as_table)
        .ok_or_else(|| MigrationError::Parse("missing [policy] table".into()))?;
    match policy.get("revision") {
        None => Ok(None),
        Some(item) => item
            .as_str()
            .map(|revision| Some(revision.to_string()))
            .ok_or_else(|| MigrationError::Parse("[policy].revision must be a string".into())),
    }
}

fn recognize_generation(doc: &DocumentMut) -> Result<PublishedGeneration, MigrationError> {
    let v040 = published_default(PublishedGeneration::V0_4_0, "enforce")?;
    let v041 = published_default(PublishedGeneration::V0_4_1, "enforce")?;
    let score040 = semantic_distance(doc, &v040);
    let score041 = semantic_distance(doc, &v041);
    match score040.cmp(&score041) {
        std::cmp::Ordering::Less => Ok(PublishedGeneration::V0_4_0),
        std::cmp::Ordering::Greater => Ok(PublishedGeneration::V0_4_1),
        std::cmp::Ordering::Equal => Err(MigrationError::AmbiguousGeneration { score: score040 }),
    }
}

fn published_default(
    generation: PublishedGeneration,
    mode: &str,
) -> Result<DocumentMut, MigrationError> {
    if generation == PublishedGeneration::Draft2026_07_28 {
        return Err(MigrationError::Internal(
            "draft revision requested through published baseline builder".into(),
        ));
    }
    let mut doc = parse_document(&default_policy_content(mode))?;
    let policy = doc
        .get_mut("policy")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| MigrationError::Internal("current default lacks [policy]".into()))?;
    policy.remove("revision");

    for (pattern, section) in MCP_TRUST_ADDITIONS
        .iter()
        .chain(ADDED_AFTER_0_4_1.iter())
        .chain(ADDED_AFTER_2026_07_28_1.iter())
    {
        remove_rule(&mut doc, *section, pattern)?;
    }
    for change in CURRENT_TO_2026_07_28_1 {
        reverse_rule_change(&mut doc, *change)?;
    }
    for change in CURRENT_TO_0_4_1 {
        reverse_rule_change(&mut doc, *change)?;
    }
    if generation == PublishedGeneration::V0_4_0 {
        for change in V0_4_1_TO_0_4_0 {
            reverse_rule_change(&mut doc, *change)?;
        }
    }
    Ok(doc)
}

fn draft_default(mode: &str) -> Result<DocumentMut, MigrationError> {
    let mut doc = parse_document(&default_policy_content(mode))?;
    let policy = doc
        .get_mut("policy")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| MigrationError::Internal("current default lacks [policy]".into()))?;
    policy.insert("revision", value(DRAFT_POLICY_REVISION));
    for (pattern, section) in MCP_TRUST_ADDITIONS
        .iter()
        .chain(ADDED_AFTER_2026_07_28_1.iter())
    {
        remove_rule(&mut doc, *section, pattern)?;
    }
    for change in CURRENT_TO_2026_07_28_1 {
        reverse_rule_change(&mut doc, *change)?;
    }
    Ok(doc)
}

/// the 2026-07-28.1 revision: the current default minus only the FP-audit split.
/// every other rule is identical, so this is the shallowest baseline in the ladder.
fn prior_default(mode: &str) -> Result<DocumentMut, MigrationError> {
    let mut doc = parse_document(&default_policy_content(mode))?;
    let policy = doc
        .get_mut("policy")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| MigrationError::Internal("current default lacks [policy]".into()))?;
    policy.insert("revision", value(PRIOR_POLICY_REVISION));
    for (pattern, section) in ADDED_AFTER_2026_07_28_1 {
        remove_rule(&mut doc, *section, pattern)?;
    }
    for change in CURRENT_TO_2026_07_28_1 {
        reverse_rule_change(&mut doc, *change)?;
    }
    Ok(doc)
}

fn reverse_rule_change(doc: &mut DocumentMut, change: RuleChange) -> Result<(), MigrationError> {
    let tables = tables_mut(doc, change.section)
        .ok_or_else(|| MigrationError::Internal(format!("missing {}", change.section.label())))?;
    let matches = matching_indices(tables, change.current_pattern);
    if matches.len() != 1 {
        return Err(MigrationError::Internal(format!(
            "{} expected one {:?} rule, found {}",
            change.section.label(),
            change.current_pattern,
            matches.len()
        )));
    }
    let table = tables
        .get_mut(matches[0])
        .expect("matching index came from this array");
    table.insert("pattern", value(change.old_pattern));
    if let Some(action) = change.old_action {
        table.insert("action", value(action));
    }
    if let Some(reason) = change.old_reason {
        table.insert("reason", value(reason));
    }
    Ok(())
}

fn remove_rule(
    doc: &mut DocumentMut,
    section: RuleSection,
    pattern: &str,
) -> Result<(), MigrationError> {
    let tables = tables_mut(doc, section)
        .ok_or_else(|| MigrationError::Internal(format!("missing {}", section.label())))?;
    let matches = matching_indices(tables, pattern);
    if matches.len() != 1 {
        return Err(MigrationError::Internal(format!(
            "{} expected one added {:?} rule, found {}",
            section.label(),
            pattern,
            matches.len()
        )));
    }
    tables.remove(matches[0]);
    Ok(())
}

fn semantic_distance(local: &DocumentMut, base: &DocumentMut) -> usize {
    let mut score = 0;
    for section in RuleSection::ALL {
        let Some(base_tables) = tables(base, section) else {
            continue;
        };
        let local_tables = tables(local, section);
        for base_rule in base_tables.iter() {
            let Some(pattern) = string_field(base_rule, "pattern") else {
                score += 1;
                continue;
            };
            let matches: Vec<&Table> = local_tables
                .into_iter()
                .flat_map(ArrayOfTables::iter)
                .filter(|rule| string_field(rule, "pattern") == Some(pattern))
                .collect();
            if matches.len() != 1 {
                score += section.managed_fields().len();
                continue;
            }
            for field in section.managed_fields() {
                if string_field(matches[0], field) != string_field(base_rule, field) {
                    score += 1;
                }
            }
        }
    }
    score
}

fn merge_documents(
    mut local: DocumentMut,
    base: &DocumentMut,
    current: &DocumentMut,
    generation: PublishedGeneration,
) -> Result<(DocumentMut, Vec<String>, Vec<String>), MigrationError> {
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    let local_policy = local
        .get_mut("policy")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| MigrationError::Parse("missing [policy] table".into()))?;
    let mut revision = value(CURRENT_POLICY_REVISION);
    if let Some(revision_value) = revision.as_value_mut() {
        revision_value
            .decor_mut()
            .set_suffix(" # bundled policy rule generation");
    }
    local_policy.insert("revision", revision);
    changes.push(format!(
        "set [policy].revision = {CURRENT_POLICY_REVISION:?}"
    ));

    for section in RuleSection::ALL {
        let current_rules: Vec<Table> = tables(current, section)
            .map(|rules| rules.iter().cloned().collect())
            .unwrap_or_default();
        let base_rules: Vec<Table> = tables(base, section)
            .map(|rules| rules.iter().cloned().collect())
            .unwrap_or_default();
        if current_rules.is_empty() {
            continue;
        }
        ensure_tables(&mut local, section);
        let local_rules =
            tables_mut(&mut local, section).expect("ensure_tables created the requested array");

        for current_rule in current_rules {
            let Some(current_pattern) = string_field(&current_rule, "pattern") else {
                continue;
            };
            let base_pattern = pattern_for_generation(generation, section, current_pattern);
            let base_rule = match base_pattern.as_deref() {
                Some(pattern) => unique_rule(&base_rules, pattern)?,
                None => None,
            };

            match base_rule {
                None => {
                    let matches = matching_indices(local_rules, current_pattern);
                    match matches.as_slice() {
                        [] => {
                            local_rules.push(current_rule.clone());
                            changes.push(format!(
                                "add {} rule {:?}",
                                section.label(),
                                current_pattern
                            ));
                        }
                        [index] => {
                            let local_rule = local_rules
                                .get(*index)
                                .expect("matching index came from this array");
                            if !managed_equal(section, local_rule, &current_rule) {
                                conflicts.push(format!(
                                    "{} rule {:?}: local custom rule collides with a new bundled rule",
                                    section.label(),
                                    current_pattern
                                ));
                            }
                        }
                        _ => conflicts.push(format!(
                            "{} rule {:?}: duplicate local patterns are ambiguous",
                            section.label(),
                            current_pattern
                        )),
                    }
                }
                Some(base_rule) => {
                    let base_pattern =
                        string_field(base_rule, "pattern").expect("published rules have patterns");
                    let mut matches = matching_indices(local_rules, base_pattern);
                    if current_pattern != base_pattern {
                        matches.extend(matching_indices(local_rules, current_pattern));
                        matches.sort_unstable();
                        matches.dedup();
                    }
                    match matches.as_slice() {
                        [] => {
                            if !managed_equal(section, base_rule, &current_rule) {
                                conflicts.push(format!(
                                    "{} rule {:?}: user deleted a rule that the bundled policy also changed",
                                    section.label(),
                                    base_pattern
                                ));
                            }
                        }
                        [index] => {
                            let local_rule = local_rules
                                .get_mut(*index)
                                .expect("matching index came from this array");
                            merge_rule_fields(
                                section,
                                base_rule,
                                local_rule,
                                &current_rule,
                                &mut changes,
                                &mut conflicts,
                            );
                        }
                        _ => conflicts.push(format!(
                            "{} rule {:?}: duplicate local patterns are ambiguous",
                            section.label(),
                            base_pattern
                        )),
                    }
                }
            }
        }
    }

    Ok((local, changes, conflicts))
}

fn merge_rule_fields(
    section: RuleSection,
    base: &Table,
    local: &mut Table,
    current: &Table,
    changes: &mut Vec<String>,
    conflicts: &mut Vec<String>,
) {
    let identity = string_field(base, "pattern")
        .or_else(|| string_field(current, "pattern"))
        .unwrap_or("<missing pattern>");
    for field in section.managed_fields() {
        let base_value = string_field(base, field);
        let local_value = string_field(local, field);
        let current_value = string_field(current, field);
        if current_value == base_value || local_value == current_value {
            continue;
        }
        if local_value == base_value {
            replace_field_preserving_decor(local, current, field);
            changes.push(format!(
                "update {} rule {:?} field {}",
                section.label(),
                identity,
                field
            ));
        } else {
            conflicts.push(format!(
                "{} rule {:?} field {}: published={:?}, local={:?}, current={:?}",
                section.label(),
                identity,
                field,
                base_value,
                local_value,
                current_value
            ));
        }
    }
}

fn replace_field_preserving_decor(local: &mut Table, current: &Table, field: &str) {
    let Some(source) = current.get(field) else {
        local.remove(field);
        return;
    };
    let old_decor = local
        .get(field)
        .and_then(Item::as_value)
        .map(|value| value.decor().clone());
    let mut replacement = source.clone();
    if let (Some(decor), Some(value)) = (old_decor, replacement.as_value_mut()) {
        *value.decor_mut() = decor;
    }
    local.insert(field, replacement);
}

fn pattern_for_generation(
    generation: PublishedGeneration,
    section: RuleSection,
    current_pattern: &str,
) -> Option<String> {
    // newest layer first: the FP-audit split post-dates every generation here.
    if ADDED_AFTER_2026_07_28_1
        .iter()
        .any(|(pattern, candidate)| *candidate == section && *pattern == current_pattern)
    {
        return None;
    }
    let mut pattern = current_pattern.to_string();
    for change in CURRENT_TO_2026_07_28_1 {
        if change.section == section && change.current_pattern == pattern {
            pattern = change.old_pattern.to_string();
            break;
        }
    }
    if generation == PublishedGeneration::Rev2026_07_28_1 {
        return Some(pattern);
    }
    // the MCP trust rules arrived in 2026-07-28.1, so they exist for that
    // generation and only vanish for the draft and the 0.4.x line.
    if MCP_TRUST_ADDITIONS
        .iter()
        .any(|(mcp, candidate)| *candidate == section && *mcp == current_pattern)
    {
        return None;
    }
    if generation == PublishedGeneration::Draft2026_07_28 {
        return Some(pattern);
    }
    if ADDED_AFTER_0_4_1
        .iter()
        .any(|(added, candidate)| *candidate == section && *added == pattern)
    {
        return None;
    }
    for change in CURRENT_TO_0_4_1 {
        if change.section == section && change.current_pattern == pattern {
            pattern = change.old_pattern.to_string();
            break;
        }
    }
    if generation == PublishedGeneration::V0_4_0 {
        for change in V0_4_1_TO_0_4_0 {
            if change.section == section && change.current_pattern == pattern {
                pattern = change.old_pattern.to_string();
                break;
            }
        }
    }
    Some(pattern)
}

fn managed_equal(section: RuleSection, left: &Table, right: &Table) -> bool {
    section
        .managed_fields()
        .iter()
        .all(|field| string_field(left, field) == string_field(right, field))
}

fn unique_rule<'a>(rules: &'a [Table], pattern: &str) -> Result<Option<&'a Table>, MigrationError> {
    let matches: Vec<&Table> = rules
        .iter()
        .filter(|rule| string_field(rule, "pattern") == Some(pattern))
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [rule] => Ok(Some(*rule)),
        _ => Err(MigrationError::Internal(format!(
            "published baseline contains duplicate pattern {pattern:?}"
        ))),
    }
}

fn string_field<'a>(table: &'a Table, field: &str) -> Option<&'a str> {
    table.get(field).and_then(Item::as_str)
}

fn matching_indices(tables: &ArrayOfTables, pattern: &str) -> Vec<usize> {
    tables
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            (string_field(rule, "pattern") == Some(pattern)).then_some(index)
        })
        .collect()
}

fn tables(doc: &DocumentMut, section: RuleSection) -> Option<&ArrayOfTables> {
    let (root, child) = section.path();
    doc.get(root)?.as_table()?.get(child)?.as_array_of_tables()
}

fn tables_mut(doc: &mut DocumentMut, section: RuleSection) -> Option<&mut ArrayOfTables> {
    let (root, child) = section.path();
    doc.get_mut(root)?
        .as_table_mut()?
        .get_mut(child)?
        .as_array_of_tables_mut()
}

fn ensure_tables(doc: &mut DocumentMut, section: RuleSection) {
    let (root, child) = section.path();
    if !doc.contains_key(root) {
        doc[root] = Item::Table(toml_edit::Table::new());
    }
    let root_table = doc[root]
        .as_table_mut()
        .expect("current policy section root must be a table");
    if !root_table.contains_key(child) {
        root_table.insert(child, Item::ArrayOfTables(ArrayOfTables::new()));
    }
}

fn create_backup(
    path: &Path,
    content: &str,
    permissions: Permissions,
) -> Result<PathBuf, MigrationError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy.toml");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..1000_u32 {
        let candidate = parent.join(format!("{name}.bak.{stamp}.{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                let result = (|| -> Result<(), std::io::Error> {
                    file.write_all(content.as_bytes())?;
                    file.sync_all()?;
                    fs::set_permissions(&candidate, permissions)?;
                    sync_parent(parent);
                    Ok(())
                })();
                if let Err(error) = result {
                    let _ = fs::remove_file(&candidate);
                    return Err(MigrationError::Write {
                        path: candidate.display().to_string(),
                        error: error.to_string(),
                    });
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(MigrationError::Write {
                    path: candidate.display().to_string(),
                    error: error.to_string(),
                });
            }
        }
    }
    Err(MigrationError::Write {
        path: path.display().to_string(),
        error: "could not allocate a unique backup path".into(),
    })
}

fn atomic_write(
    path: &Path,
    content: &str,
    permissions: Permissions,
) -> Result<(), MigrationError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy.toml");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut temp = None;
    for attempt in 0..1000_u32 {
        let candidate = parent.join(format!(
            ".{name}.sentinel-migrate.{}.{}.tmp",
            std::process::id(),
            stamp + u128::from(attempt)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(MigrationError::Write {
                    path: path.display().to_string(),
                    error: error.to_string(),
                });
            }
        }
    }
    let (temp_path, mut file) = temp.ok_or_else(|| MigrationError::Write {
        path: path.display().to_string(),
        error: "could not allocate a unique sibling temporary file".into(),
    })?;
    let result = (|| -> Result<(), std::io::Error> {
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&temp_path, permissions)?;
        drop(file);
        fs::rename(&temp_path, path)?;
        sync_parent(parent);
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(MigrationError::Write {
            path: path.display().to_string(),
            error: error.to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) {
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) {}

fn validate_written_policy(path: &Path) -> Result<(), String> {
    let engine = PolicyEngine::load(path).map_err(|error| error.to_string())?;
    if !matches!(engine.mode(), "audit" | "enforce") {
        return Err(format!("unsupported [policy].mode {:?}", engine.mode()));
    }
    let lint_errors: Vec<String> = lint_engine(&engine)
        .into_iter()
        .filter(|finding| finding.error)
        .map(|finding| finding.message)
        .collect();
    if !lint_errors.is_empty() {
        return Err(format!("policy lint failed: {}", lint_errors.join("; ")));
    }
    let verify = verify_against(&engine);
    if !verify.all_passed() {
        return Err(format!(
            "policy verify failed: {}/{} cases failed",
            verify.failures(),
            verify.results.len()
        ));
    }
    if !engine.has_self_protect_rule() {
        return Err("doctor-equivalent check failed: self-protect rule missing".into());
    }
    let canary = pipeline::evaluate_raw(
        &engine,
        r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#,
    );
    if canary.decision().action != Action::Block {
        return Err("doctor-equivalent check failed: known-bad read was not blocked".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn fixture(generation: PublishedGeneration, mode: &str) -> String {
        published_default(generation, mode).unwrap().to_string()
    }

    fn draft_fixture(mode: &str) -> String {
        draft_default(mode).unwrap().to_string()
    }

    fn append_custom_rule(content: &str, pattern: &str, action: &str) -> String {
        format!(
            "{content}\n# joe custom rule stays here\n[[deny.commands]]\n\
             pattern = '{pattern}'\naction = \"{action}\"\nreason = \"custom\"\nowner = \"joe\"\n"
        )
    }

    fn semantic_digest(content: &str) -> String {
        let value: toml::Value = toml::from_str(content).unwrap();
        let canonical = serde_json::to_vec(&value).unwrap();
        format!("{:x}", Sha256::digest(canonical))
    }

    #[test]
    fn reconstructed_baselines_match_immutable_published_policy_digests() {
        // SHA-256 over canonical TOML semantics (all policy fields plus every
        // ordered rule/table field), captured from policies actually generated
        // by tag v0.4.0 and commit 508046382336bf2347574f4b2a4f20d543745ebf
        // (the immutable crates.io 0.4.1 source).
        assert_eq!(
            semantic_digest(&fixture(PublishedGeneration::V0_4_0, "enforce")),
            "14a3c5cf5c5827808d9af0168e15eefca754727518acf7fdadada846a726e72f"
        );
        assert_eq!(
            semantic_digest(&fixture(PublishedGeneration::V0_4_1, "enforce")),
            "aa2ca92e8a4affcea56c0907e8e31fcbf1102981e50fb04f93221d5c837eeef6"
        );
    }

    #[test]
    fn default_has_explicit_revision_and_schema_accepts_it() {
        let content = default_policy_content("enforce");
        assert!(content.contains(&format!("revision = \"{CURRENT_POLICY_REVISION}\"")));
        assert_eq!(CURRENT_POLICY_REVISION, "2026-08-07.1");
        let engine = PolicyEngine::from_toml_str(&content).unwrap();
        assert_eq!(engine.mode(), "enforce");
    }

    #[test]
    fn current_revision_contains_every_mcp_trust_rule_and_draft_contains_none() {
        let current = parse_document(&default_policy_content("enforce")).unwrap();
        let draft = draft_default("enforce").unwrap();
        assert_eq!(
            policy_revision(&current).unwrap().as_deref(),
            Some(CURRENT_POLICY_REVISION)
        );
        assert_eq!(
            policy_revision(&draft).unwrap().as_deref(),
            Some(DRAFT_POLICY_REVISION)
        );
        for (pattern, section) in MCP_TRUST_ADDITIONS {
            assert_eq!(
                matching_indices(tables(&current, *section).unwrap(), pattern).len(),
                1,
                "current final policy must contain exactly one MCP trust rule {pattern:?}"
            );
            assert!(
                matching_indices(tables(&draft, *section).unwrap(), pattern).is_empty(),
                "prior draft must not contain final MCP trust rule {pattern:?}"
            );
        }
        let current_count: usize = RuleSection::ALL
            .iter()
            .filter_map(|section| tables(&current, *section))
            .map(ArrayOfTables::len)
            .sum();
        let draft_count: usize = RuleSection::ALL
            .iter()
            .filter_map(|section| tables(&draft, *section))
            .map(ArrayOfTables::len)
            .sum();
        assert_eq!(
            current_count - draft_count,
            MCP_TRUST_ADDITIONS.len() + ADDED_AFTER_2026_07_28_1.len()
        );
    }

    #[test]
    fn draft_revision_check_apply_and_idempotence_are_exact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let old = draft_fixture("audit");
        fs::write(&path, &old).unwrap();

        let MigrationInspection::Needed(plan) = inspect_content(&old).unwrap() else {
            panic!("draft revision unexpectedly read current");
        };
        assert_eq!(plan.from, PublishedGeneration::Draft2026_07_28);
        assert_eq!(
            policy_revision(&parse_document(&plan.rendered).unwrap())
                .unwrap()
                .as_deref(),
            Some(CURRENT_POLICY_REVISION)
        );
        assert!(MCP_TRUST_ADDITIONS.iter().all(|(pattern, section)| {
            matching_indices(
                tables(&parse_document(&plan.rendered).unwrap(), *section).unwrap(),
                pattern,
            )
            .len()
                == 1
        }));

        let check_error = run(PolicyMigrateArgs {
            check: true,
            apply: false,
            policy: Some(path.clone()),
        })
        .unwrap_err()
        .to_string();
        assert!(check_error.contains("draft revision 2026-07-28"));
        assert_eq!(fs::read_to_string(&path).unwrap(), old);

        let applied = apply_path(&path).unwrap().expect("draft migration needed");
        assert_eq!(applied.from, PublishedGeneration::Draft2026_07_28);
        assert_eq!(fs::read_to_string(&applied.backup_path).unwrap(), old);
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(migrated.contains("revision = \"2026-08-07.1\""));
        assert!(migrated.contains("mode = \"audit\""));
        assert!(matches!(
            inspect_content(&migrated).unwrap(),
            MigrationInspection::Current
        ));
        assert!(apply_path(&path).unwrap().is_none());
    }

    #[test]
    fn published_generation_fixtures_match_known_rule_counts() {
        for generation in [PublishedGeneration::V0_4_0, PublishedGeneration::V0_4_1] {
            let document = published_default(generation, "enforce").unwrap();
            let count: usize = RuleSection::ALL
                .iter()
                .filter_map(|section| tables(&document, *section))
                .map(ArrayOfTables::len)
                .sum();
            assert_eq!(count, 151, "published {generation} had 151 policy rules");
            assert!(policy_revision(&document).unwrap().is_none());
        }
    }

    #[test]
    fn recognizes_and_migrates_every_published_generation() {
        for generation in [PublishedGeneration::V0_4_0, PublishedGeneration::V0_4_1] {
            let old = fixture(generation, "audit");
            let MigrationInspection::Needed(plan) = inspect_content(&old).unwrap() else {
                panic!("{generation} unexpectedly read current");
            };
            assert_eq!(plan.from, generation);
            let migrated = parse_document(&plan.rendered).unwrap();
            assert_eq!(
                policy_revision(&migrated).unwrap().as_deref(),
                Some(CURRENT_POLICY_REVISION)
            );
            assert_eq!(
                migrated["policy"]["mode"].as_str(),
                Some("audit"),
                "migration must preserve audit mode"
            );
        }
    }

    #[test]
    fn preserves_comments_custom_rules_fields_and_nonoverlapping_edits() {
        let mut old = fixture(PublishedGeneration::V0_4_1, "audit");
        old = old.replace(
            "on_failure = \"closed\"",
            "on_failure = \"open\" # joe keeps fail-open",
        );
        old = old.replace(
            "reason = \"SSH key access\"",
            "reason = \"joe's SSH policy\" # custom reason",
        );
        old = append_custom_rule(&old, r"\bjoe-only-command\b", "warn");
        let MigrationInspection::Needed(plan) = inspect_content(&old).unwrap() else {
            panic!("legacy fixture unexpectedly current");
        };
        assert!(plan.rendered.contains("# joe keeps fail-open"));
        assert!(plan.rendered.contains("# custom reason"));
        assert!(plan.rendered.contains("# joe custom rule stays here"));
        assert!(plan.rendered.contains("owner = \"joe\""));
        assert!(plan.rendered.contains("reason = \"joe's SSH policy\""));
        assert_eq!(
            parse_document(&plan.rendered).unwrap()["policy"]["mode"].as_str(),
            Some("audit")
        );
    }

    #[test]
    fn overlapping_rule_edit_is_a_conflict_and_never_rewrites() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let old = fixture(PublishedGeneration::V0_4_1, "enforce").replace(
            "action = \"block\"\nreason = \"Sentinel's own enforcement policy",
            "action = \"allow\"\nreason = \"Sentinel's own enforcement policy",
        );
        fs::write(&path, &old).unwrap();
        let error = apply_path(&path).unwrap_err();
        assert!(matches!(error, MigrationError::Conflicts(_)));
        assert_eq!(fs::read_to_string(&path).unwrap(), old);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn check_is_read_only_and_reports_migration_needed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let old = fixture(PublishedGeneration::V0_4_0, "audit");
        fs::write(&path, &old).unwrap();
        let args = PolicyMigrateArgs {
            check: true,
            apply: false,
            policy: Some(path.clone()),
        };
        let error = run(args).unwrap_err().to_string();
        assert!(error.contains("migration is required"));
        assert_eq!(fs::read_to_string(path).unwrap(), old);
    }

    #[test]
    fn apply_creates_backup_preserves_permissions_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let old = fixture(PublishedGeneration::V0_4_1, "audit");
        fs::write(&path, &old).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();

        let applied = apply_path(&path).unwrap().expect("migration needed");
        assert_eq!(applied.from, PublishedGeneration::V0_4_1);
        assert_eq!(fs::read_to_string(&applied.backup_path).unwrap(), old);
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(migrated.contains(&format!("revision = \"{CURRENT_POLICY_REVISION}\"")));
        assert!(migrated.contains("mode = \"audit\""));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert_eq!(
                fs::metadata(&applied.backup_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }
        assert!(apply_path(&path).unwrap().is_none());
    }

    #[test]
    fn failed_post_write_validation_rolls_back_original() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let old = append_custom_rule(
            &fixture(PublishedGeneration::V0_4_1, "enforce"),
            "(",
            "block",
        );
        fs::write(&path, &old).unwrap();
        let error = apply_path(&path).unwrap_err();
        let backup = match error {
            MigrationError::ValidationRolledBack { backup, reason } => {
                assert!(reason.contains("lint"));
                PathBuf::from(backup)
            }
            other => panic!("unexpected error: {other}"),
        };
        assert_eq!(fs::read_to_string(&path).unwrap(), old);
        assert_eq!(fs::read_to_string(backup).unwrap(), old);
    }

    #[test]
    fn unknown_revision_and_symlink_fail_without_writes() {
        let unknown =
            default_policy_content("enforce").replace(CURRENT_POLICY_REVISION, "2099-01-01");
        assert!(matches!(
            inspect_content(&unknown),
            Err(MigrationError::UnsupportedRevision(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempdir().unwrap();
            let target = dir.path().join("target.toml");
            let link = dir.path().join("policy.toml");
            let old = fixture(PublishedGeneration::V0_4_1, "enforce");
            fs::write(&target, &old).unwrap();
            symlink(&target, &link).unwrap();
            assert!(matches!(apply_path(&link), Err(MigrationError::Symlink(_))));
            assert_eq!(fs::read_to_string(target).unwrap(), old);
        }
    }
}
