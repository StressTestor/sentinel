pub mod normalize;
pub mod shell;
pub mod types;

use std::io::Write;
use std::path::Path;

/// Resolve the user's home without falling back to the process working directory.
pub fn home_dir() -> std::io::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HOME must be set to a nonempty absolute path",
            )
        })?;
    Ok(home)
}

/// A fresh 32-byte salt for a digest store (MCP baseline, overlay store).
pub(crate) fn random_salt(label: &str) -> Result<Vec<u8>, String> {
    let mut salt = vec![0_u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|error| format!("failed to create {label} salt: {error}"))?;
    Ok(salt)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Decode a 32-byte salt written by `encode_hex`. `label` names the store in
/// the error (the value itself is never echoed).
pub(crate) fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid {label} salt"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| format!("invalid {label} salt"))?;
            u8::from_str_radix(text, 16).map_err(|_| format!("invalid {label} salt"))
        })
        .collect()
}

/// Atomically replace `path` with `content` as a private (0600 on Unix) file.
///
/// The temp file is attempt-suffixed and `create_new`-opened with retry: a
/// predictable pid-only temp name lets a pre-created file wedge every future
/// write (2026-08-14 audit). `temp_stem` names the temp file family and
/// `label` names the store in error messages.
pub(crate) fn write_private_atomic(
    path: &Path,
    content: &[u8],
    temp_stem: &str,
    label: &str,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {label} directory: {error}"))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut staged: Option<std::path::PathBuf> = None;
    let result = (|| -> Result<(), String> {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = None;
        for attempt in 0..1000_u32 {
            let candidate = parent.join(format!(
                ".{temp_stem}.{}.{stamp}.{attempt}.tmp",
                std::process::id()
            ));
            match options.open(&candidate) {
                Ok(opened) => {
                    staged = Some(candidate);
                    file = Some(opened);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("failed to stage {label}: {error}")),
            }
        }
        let Some(mut file) = file else {
            return Err(format!("could not allocate a unique {label} temp file"));
        };
        file.write_all(content)
            .map_err(|error| format!("failed to stage {label}: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync {label}: {error}"))?;
        let temp = staged.as_deref().expect("a successful open stages a temp");
        std::fs::rename(temp, path)
            .map_err(|error| format!("failed to atomically replace {label}: {error}"))?;
        staged = None; // renamed away: nothing left to clean up
        Ok(())
    })();
    if result.is_err() {
        if let Some(temp) = staged {
            let _ = std::fs::remove_file(temp);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = (0_u8..32).collect::<Vec<_>>();
        assert_eq!(decode_hex(&encode_hex(&bytes), "test").unwrap(), bytes);
        assert!(decode_hex("zz", "test").is_err());
    }

    #[test]
    fn private_atomic_write_replaces_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store").join("file.json");
        write_private_atomic(&path, b"one", "file", "test store").unwrap();
        write_private_atomic(&path, b"two", "file", "test store").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
