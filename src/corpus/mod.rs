pub mod parser;

use crate::common::types::AttackSequence;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

const BUNDLED_V1: &[(&str, &str)] = &[
    (
        "v1/001-sensitive-file-read.toml",
        include_str!("../../corpus/v1/001-sensitive-file-read.toml"),
    ),
    (
        "v1/002-command-execution.toml",
        include_str!("../../corpus/v1/002-command-execution.toml"),
    ),
    (
        "v1/003-network-request.toml",
        include_str!("../../corpus/v1/003-network-request.toml"),
    ),
];

#[derive(Error, Debug)]
pub enum CorpusError {
    #[error("corpus directory not found: {0}")]
    DirectoryNotFound(PathBuf),
    #[error("no attack sequences found in {0}")]
    EmptyCorpus(PathBuf),
    #[error("failed to read {path}: {source}")]
    ReadError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {message}")]
    ParseError { path: PathBuf, message: String },
    #[error("duplicate attack sequence id: {0}")]
    DuplicateId(String),
}

/// Load an explicitly selected corpus directory, or the project-authored
/// versioned corpus compiled into this package. Nothing is downloaded or
/// selected from mutable user state.
pub fn load(explicit: Option<&Path>) -> Result<Vec<AttackSequence>, CorpusError> {
    match explicit {
        Some(dir) => load_directory(dir),
        None => load_bundled(),
    }
}

fn load_bundled() -> Result<Vec<AttackSequence>, CorpusError> {
    let sequences = BUNDLED_V1
        .iter()
        .map(|(name, content)| {
            parser::parse_sequence(content).map_err(|message| CorpusError::ParseError {
                path: PathBuf::from(name),
                message,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    reject_duplicate_ids(sequences)
}

/// Load every TOML attack sequence below a directory in stable path order.
pub fn load_directory(dir: &Path) -> Result<Vec<AttackSequence>, CorpusError> {
    if !dir.exists() {
        return Err(CorpusError::DirectoryNotFound(dir.to_path_buf()));
    }

    let mut files = Vec::new();
    collect_toml_files(dir, &mut files)?;
    files.sort();

    if files.is_empty() {
        return Err(CorpusError::EmptyCorpus(dir.to_path_buf()));
    }

    let sequences = files
        .into_iter()
        .map(|path| {
            let content =
                std::fs::read_to_string(&path).map_err(|source| CorpusError::ReadError {
                    path: path.clone(),
                    source,
                })?;
            parser::parse_sequence(&content)
                .map_err(|message| CorpusError::ParseError { path, message })
        })
        .collect::<Result<Vec<_>, _>>()?;
    reject_duplicate_ids(sequences)
}

fn reject_duplicate_ids(
    sequences: Vec<AttackSequence>,
) -> Result<Vec<AttackSequence>, CorpusError> {
    let mut seen = BTreeSet::new();
    for sequence in &sequences {
        if !seen.insert(sequence.meta.id.as_str()) {
            return Err(CorpusError::DuplicateId(sequence.meta.id.clone()));
        }
    }
    Ok(sequences)
}

fn collect_toml_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), CorpusError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CorpusError::ReadError {
        path: dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| CorpusError::ReadError {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| CorpusError::ReadError {
            path: path.clone(),
            source,
        })?;

        if file_type.is_dir() {
            collect_toml_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn bundled_corpus_has_stable_versioned_order() {
        let sequences = load(None).unwrap();
        let ids: Vec<_> = sequences
            .iter()
            .map(|sequence| sequence.meta.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "sentinel-v1-sensitive-file-read",
                "sentinel-v1-command-execution",
                "sentinel-v1-network-request"
            ]
        );
    }

    #[test]
    fn explicit_directory_order_is_deterministic() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sentinel-corpus-order-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("z.toml"),
            sequence_toml("z-sequence", "command_execution"),
        )
        .unwrap();
        std::fs::write(
            dir.join("a.toml"),
            sequence_toml("a-sequence", "command_execution"),
        )
        .unwrap();

        let ids: Vec<_> = load_directory(&dir)
            .unwrap()
            .into_iter()
            .map(|sequence| sequence.meta.id)
            .collect();
        assert_eq!(ids, ["a-sequence", "z-sequence"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_sequence_ids_are_rejected() {
        let sequences = vec![
            parser::parse_sequence(&sequence_toml("duplicate", "command_execution")).unwrap(),
            parser::parse_sequence(&sequence_toml("duplicate", "command_execution")).unwrap(),
        ];
        assert!(matches!(
            reject_duplicate_ids(sequences),
            Err(CorpusError::DuplicateId(id)) if id == "duplicate"
        ));
    }

    fn sequence_toml(id: &str, action: &str) -> String {
        format!(
            r#"
[meta]
id = "{id}"
category = "test"
dimension = "test"
severity = "low"

[[steps]]
role = "user"
content = "test"

[expected_vulnerable_behavior]
action = "{action}"
"#
        )
    }
}
