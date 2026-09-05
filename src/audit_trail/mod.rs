use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub tool_name: String,
    pub action: String,
    pub reason: Option<String>,
    pub matched_rule: Option<String>,
    pub mode: String,
    /// Correlation id shared with the process that invoked this evaluation
    /// (e.g. the ghost bridge sets `SENTINEL_CALL_ID` per call), so this audit
    /// line can be joined against the caller's own per-call log. `serde(default)`
    /// so audit lines written before this field existed still parse (-> None);
    /// `skip_serializing_if` so standalone installs (no env var) keep writing
    /// byte-identical lines. Pre phase only: the env var can only reach the
    /// evaluate subprocess a wrapper spawns, never a PostToolUse invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,

    /// Claude Code's per-call tool use id, read from the hook payload. The same
    /// value arrives in the PreToolUse and PostToolUse payloads for one tool
    /// call, so it joins this call's pre line to its post line(s). Same compat
    /// discipline as `call_id`: old lines parse (-> None), all-None lines stay
    /// byte-identical to the previous format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,

    /// Which hook phase wrote this line: "pre" (`sentinel evaluate`) or "post"
    /// (`sentinel post-evaluate`). None on lines written before this field
    /// existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_phase: Option<String>,
}

// THE JOIN CONTRACT (when ghost + sentinel are both current):
//   ghost feed line  <->  sentinel PRE line   via `call_id`   (env-derived)
//   sentinel PRE line <-> sentinel POST lines via `tool_use_id` (payload-derived)
// One governing call = exactly one pre line + zero-or-more post lines. Claude
// Code does not fire PostToolUse for a denied call (verified 2.1.207), so a
// blocked call has zero post lines — that's expected, not missing data.

/// The env var a wrapping caller sets to correlate its own per-call log line
/// with the audit line sentinel writes for the same call.
pub const CALL_ID_ENV: &str = "SENTINEL_CALL_ID";

/// Correlation id for the current evaluation, read from `SENTINEL_CALL_ID`.
/// Missing, empty, or non-unicode values are simply None — a malformed env var
/// must never affect the verdict, error, or write to stdout/stderr (the hook's
/// stdout is a parsed JSON contract).
pub fn call_id_from_env() -> Option<String> {
    normalize_call_id(std::env::var(CALL_ID_ENV).ok())
}

/// The pure normalization behind `call_id_from_env`: trim, drop empties.
fn normalize_call_id(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Read the audit trail back as events (for `sentinel doctor`). Missing/unreadable
/// log → empty; individual unparseable lines are skipped, not fatal.
pub fn read_events() -> Vec<AuditEvent> {
    let Ok(path) = audit_log_path() else {
        return Vec::new();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
        .collect()
}

/// Append an audit event, creating the audit directory/file when needed.
///
/// On Unix, open without following final symlinks, verify regular file and
/// directory identities, and tighten permissions through those handles. An
/// advisory lock serializes complete records from cooperating Sentinel writers.
/// This is not a sandbox against malicious same-user processes replacing paths
/// or ignoring locks. An I/O failure can still leave an incomplete final record.
pub fn log_event(event: &AuditEvent) -> Result<(), std::io::Error> {
    append_event(&audit_log_path()?, event)
}

fn append_event(path: &Path, event: &AuditEvent) -> std::io::Result<()> {
    use std::io::Write;

    let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut file = open_audit_file(path)?;
    // The Unix advisory lock is held until this file handle is dropped, including
    // all partial writes retried by write_all and its error paths.
    file.write_all(&line)
}

fn audit_log_path() -> std::io::Result<PathBuf> {
    Ok(crate::common::home_dir()?
        .join(".sentinel")
        .join("audit.jsonl"))
}

#[cfg(unix)]
fn audit_io_error(action: &str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn create_audit_directory(parent: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(std::io::Error::other(
                "audit directory must be a directory, not a symlink or another file type",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(parent) {
        Ok(()) => Ok(()),
        // Another hook may have created the directory. Its handle and type are
        // checked below before permissions are changed or an event is written.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    loop {
        // SAFETY: file owns the live descriptor for the duration of the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn open_audit_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("audit path has no parent"))?;
    create_audit_directory(parent)
        .map_err(|error| audit_io_error("create audit directory", error))?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|error| audit_io_error("open audit directory", error))?;
    let directory_metadata = directory
        .metadata()
        .map_err(|error| audit_io_error("read audit directory metadata", error))?;
    let named_directory = std::fs::symlink_metadata(parent)
        .map_err(|error| audit_io_error("check audit directory identity", error))?;
    if !named_directory.is_dir()
        || directory_metadata.dev() != named_directory.dev()
        || directory_metadata.ino() != named_directory.ino()
    {
        return Err(std::io::Error::other(
            "audit directory changed while opening it",
        ));
    }

    // Serialize first creation before acquiring the file lock. The directory
    // lock is released once the returned file holds its own lock, keeping
    // cooperating creators out of the open/create transition.
    lock_exclusive(&directory).map_err(|error| audit_io_error("lock audit directory", error))?;

    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("audit path has no filename"))?;
    let name = CString::new(name.as_bytes()).map_err(std::io::Error::other)?;
    // SAFETY: directory owns a live descriptor and name is NUL-terminated. The
    // returned descriptor is checked and transferred into exactly one File.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_APPEND
                | libc::O_CREAT
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(audit_io_error(
            "open audit trail",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: openat returned a new, owned descriptor and ownership moves here.
    let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|error| audit_io_error("read audit file metadata", error))?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("audit trail must be a regular file"));
    }

    lock_exclusive(&file).map_err(|error| audit_io_error("lock audit trail", error))?;
    let named_directory = std::fs::symlink_metadata(parent)
        .map_err(|error| audit_io_error("check audit directory identity", error))?;
    let named_file = std::fs::symlink_metadata(path)
        .map_err(|error| audit_io_error("check audit file identity", error))?;
    if !named_directory.is_dir()
        || directory_metadata.dev() != named_directory.dev()
        || directory_metadata.ino() != named_directory.ino()
        || !named_file.is_file()
        || metadata.dev() != named_file.dev()
        || metadata.ino() != named_file.ino()
    {
        return Err(std::io::Error::other("audit path changed while opening it"));
    }

    // Use the handles we verified, never pathname-based chmod. Preserve more
    // restrictive owner bits while removing group/world access and special bits.
    let directory_mode = directory.metadata()?.permissions().mode() & 0o700;
    directory
        .set_permissions(std::fs::Permissions::from_mode(directory_mode))
        .map_err(|error| audit_io_error("tighten audit directory permissions", error))?;
    let file_mode = file.metadata()?.permissions().mode() & 0o600;
    file.set_permissions(std::fs::Permissions::from_mode(file_mode))
        .map_err(|error| audit_io_error("tighten audit file permissions", error))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_audit_file(path: &Path) -> std::io::Result<std::fs::File> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("audit path has no parent"))?;
    create_audit_directory(parent)?;
    if !std::fs::symlink_metadata(parent)?.is_dir() {
        return Err(std::io::Error::other("audit directory must be a directory"));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(std::io::Error::other("audit trail must be a regular file"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("audit trail must be a regular file"));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(call_id: Option<String>) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-07-13T00:00:00+00:00".into(),
            tool_name: "Bash".into(),
            action: "block".into(),
            reason: Some("pipe to shell execution".into()),
            matched_rule: Some("deny.commands[0]".into()),
            mode: "enforce".into(),
            call_id,
            tool_use_id: None,
            hook_phase: None,
        }
    }

    #[test]
    fn call_id_roundtrips_when_present() {
        let ev = event(Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001".into()));
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.contains("2f1e9c1a-7c39-4b6e-9d1a-000000000001"));
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back.call_id.as_deref(),
            Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001")
        );
    }

    #[test]
    fn call_id_none_keeps_the_line_free_of_the_key_and_roundtrips() {
        let ev = event(None);
        let line = serde_json::to_string(&ev).unwrap();
        assert!(
            !line.contains("call_id"),
            "a standalone install (no env var) must keep writing byte-identical lines: {line}"
        );
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert!(back.call_id.is_none());
    }

    #[test]
    fn old_audit_lines_without_call_id_still_parse() {
        // a literal pre-call_id line, exactly as older sentinels wrote it.
        let old = r#"{"timestamp":"2026-01-01T00:00:00+00:00","tool_name":"Read","action":"allow","reason":null,"matched_rule":null,"mode":"audit"}"#;
        let ev: AuditEvent = serde_json::from_str(old).expect("old lines must keep parsing");
        assert!(ev.call_id.is_none());
        assert_eq!(ev.tool_name, "Read");
    }

    #[test]
    fn tool_use_id_and_hook_phase_roundtrip() {
        let mut ev = event(Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001".into()));
        ev.tool_use_id = Some("toolu_01QoWqbiPYgBoiZQPDuvUHKb".into());
        ev.hook_phase = Some("pre".into());
        let line = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back.tool_use_id.as_deref(),
            Some("toolu_01QoWqbiPYgBoiZQPDuvUHKb")
        );
        assert_eq!(back.hook_phase.as_deref(), Some("pre"));
        // and call_id coexists: the ghost<->pre key and the pre<->post key are
        // independent columns on the same line.
        assert_eq!(
            back.call_id.as_deref(),
            Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001")
        );
    }

    #[test]
    fn all_none_new_fields_keep_the_line_byte_identical_to_the_prior_format() {
        // an event with call_id/tool_use_id/hook_phase all None must serialize
        // to EXACTLY the pre-correlation shape — no new keys, ever.
        let line = serde_json::to_string(&event(None)).unwrap();
        assert_eq!(
            line,
            r#"{"timestamp":"2026-07-13T00:00:00+00:00","tool_name":"Bash","action":"block","reason":"pipe to shell execution","matched_rule":"deny.commands[0]","mode":"enforce"}"#
        );
    }

    #[test]
    fn prior_generation_audit_lines_still_parse() {
        // a #60-era line: call_id present, tool_use_id/hook_phase not yet born.
        let v60 = r#"{"timestamp":"2026-07-13T23:45:53+00:00","tool_name":"Bash","action":"block","reason":"pipe to shell execution","matched_rule":"deny.commands: x","mode":"enforce","call_id":"e1987b56-04bb-4cc1-b0c1-af4eb4fdc7b1"}"#;
        let ev: AuditEvent = serde_json::from_str(v60).expect("#60-era lines must keep parsing");
        assert_eq!(
            ev.call_id.as_deref(),
            Some("e1987b56-04bb-4cc1-b0c1-af4eb4fdc7b1")
        );
        assert!(ev.tool_use_id.is_none());
        assert!(ev.hook_phase.is_none());
    }

    #[test]
    fn normalize_call_id_drops_missing_empty_and_whitespace() {
        assert_eq!(normalize_call_id(None), None);
        assert_eq!(normalize_call_id(Some(String::new())), None);
        assert_eq!(normalize_call_id(Some("   ".into())), None);
        assert_eq!(
            normalize_call_id(Some("  abc-123 ".into())),
            Some("abc-123".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_private_files_and_tightens_existing_modes() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(".sentinel");
        let path = directory.join("audit.jsonl");
        append_event(&path, &event(None)).unwrap();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        append_event(&path, &event(None)).unwrap();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn append_refuses_unsupported_parent_and_file_types() {
        let home = tempfile::tempdir().unwrap();
        let parent = home.path().join(".sentinel");
        std::fs::write(&parent, "keep this file").unwrap();
        assert!(append_event(&parent.join("audit.jsonl"), &event(None)).is_err());
        assert_eq!(std::fs::read_to_string(&parent).unwrap(), "keep this file");

        let other_home = tempfile::tempdir().unwrap();
        let path = other_home.path().join(".sentinel/audit.jsonl");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("keep.txt"), "keep this directory").unwrap();
        assert!(append_event(&path, &event(None)).is_err());
        assert_eq!(
            std::fs::read_to_string(path.join("keep.txt")).unwrap(),
            "keep this directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_linked_paths_without_changing_referents() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let home = tempfile::tempdir().unwrap();
        let referent = home.path().join("data");
        std::fs::create_dir(&referent).unwrap();
        std::fs::set_permissions(&referent, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&referent, home.path().join(".sentinel")).unwrap();
        assert!(append_event(&home.path().join(".sentinel/audit.jsonl"), &event(None)).is_err());
        assert_eq!(
            std::fs::metadata(&referent).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(&referent).unwrap().count(), 0);

        let other_home = tempfile::tempdir().unwrap();
        let directory = other_home.path().join(".sentinel");
        std::fs::create_dir(&directory).unwrap();
        let original = other_home.path().join("notes.txt");
        std::fs::write(&original, "unchanged").unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = directory.join("audit.jsonl");
        symlink(&original, &path).unwrap();
        assert!(append_event(&path, &event(None)).is_err());
        assert_eq!(std::fs::read_to_string(&original).unwrap(), "unchanged");
        assert_eq!(
            std::fs::metadata(&original).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_holds_an_exclusive_lock_until_closed() {
        use std::os::fd::AsRawFd;

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(".sentinel/audit.jsonl");
        let locked = open_audit_file(&path).unwrap();
        let other = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        // SAFETY: other owns a live descriptor; nonblocking flock changes only
        // its advisory lock state and does not read or write memory.
        let result = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(locked);
        // SAFETY: the descriptor is still owned by other and the first lock has
        // been released by dropping its sole file handle.
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_long_records_remain_complete_json_lines() {
        use std::collections::BTreeSet;
        use std::sync::{Arc, Barrier};

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(".sentinel/audit.jsonl");
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for worker in 0..4 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for index in 0..16 {
                    let id = format!("{worker}:{index}:{}", "x".repeat(32 * 1024));
                    append_event(&path, &event(Some(id))).unwrap();
                }
            }));
        }
        let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        for outcome in outcomes {
            outcome.unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.ends_with('\n'));
        let ids: BTreeSet<_> = content
            .lines()
            .map(|line| {
                serde_json::from_str::<AuditEvent>(line)
                    .unwrap()
                    .call_id
                    .unwrap()
            })
            .collect();
        let expected: BTreeSet<_> = (0..4)
            .flat_map(|worker| {
                (0..16).map(move |index| format!("{worker}:{index}:{}", "x".repeat(32 * 1024)))
            })
            .collect();
        assert_eq!(content.lines().count(), expected.len());
        assert_eq!(ids, expected);
    }
}
