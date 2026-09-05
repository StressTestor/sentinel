pub mod normalize;
pub mod shell;
pub mod types;

/// Resolve the user's home without falling back to the process working directory.
pub(crate) fn home_dir() -> std::io::Result<std::path::PathBuf> {
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
