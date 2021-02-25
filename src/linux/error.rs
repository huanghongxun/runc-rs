pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("posix error")]
    Nix(#[from] nix::Error),

    #[error("filesystem {path:?} must be mounted on ordinary directory")]
    MountpointNotDirectory { path: std::path::PathBuf },

    #[error("cannot parse uid_map")]
    UidMapMalformed(#[from] scan_fmt::parse::ScanError),

    #[error("malformed mount flags")]
    MountFlagsMalformed { flags: u64 },

    #[error("user namespaces enabled, but no uid mappings found")]
    NoUidMapping,
    #[error("user namespaces enabled, but no user mapping found")]
    NoUserMapping,
    #[error("user namespaces enabled, but no gid mappings found")]
    NoGidMapping,
    #[error("user namespaces enabled, but no group mapping found")]
    NoGroupMapping,
}
