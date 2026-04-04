pub mod parser;

use crate::common::types::AttackSequence;
use std::path::{Path, PathBuf};
use thiserror::Error;

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
}

/// load all attack sequences from a corpus directory.
/// walks the directory recursively, loading every .toml file.
pub fn load_corpus(dir: &Path) -> Result<Vec<AttackSequence>, CorpusError> {
    if !dir.exists() {
        return Err(CorpusError::DirectoryNotFound(dir.to_path_buf()));
    }

    let mut sequences = Vec::new();
    load_recursive(dir, &mut sequences)?;

    if sequences.is_empty() {
        return Err(CorpusError::EmptyCorpus(dir.to_path_buf()));
    }

    tracing::info!("loaded {} attack sequences from {}", sequences.len(), dir.display());
    Ok(sequences)
}

fn load_recursive(dir: &Path, sequences: &mut Vec<AttackSequence>) -> Result<(), CorpusError> {
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

        if path.is_dir() {
            load_recursive(&path, sequences)?;
        } else if path.extension().is_some_and(|ext| ext == "toml") {
            let content = std::fs::read_to_string(&path).map_err(|e| CorpusError::ReadError {
                path: path.clone(),
                source: e,
            })?;
            let seq = parser::parse_sequence(&content).map_err(|msg| CorpusError::ParseError {
                path: path.clone(),
                message: msg,
            })?;
            sequences.push(seq);
        }
    }

    Ok(())
}

/// resolve corpus path: CLI arg > ~/.sentinel/corpus/core/ > embedded default
pub fn resolve_corpus_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }

    let home_corpus = dirs_next().join("core");
    if home_corpus.exists() {
        return home_corpus;
    }

    // fall back to embedded test corpus (for development)
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/corpus"))
}

fn dirs_next() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".sentinel").join("corpus")
}
