pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("posix error")]
    Nix(#[from] nix::Error),
    #[error("procfs error")]
    Proc(#[from] procfs::ProcError),

    #[error("filesystem {path:?} must be mounted on ordinary directory")]
    MountpointNotDirectory { path: std::path::PathBuf },

    #[error("Expected working directory {path:?}, but not a directory")]
    CwdNotDirectory { path: std::path::PathBuf },

    #[error("cannot parse uid_map")]
    UidMapMalformed(#[from] scan_fmt::parse::ScanError),

    #[error("user namespaces enabled, but no uid mappings found")]
    NoUidMapping,
    #[error("user namespaces enabled, but no user mapping found")]
    NoUserMapping,
    #[error("user namespaces enabled, but no gid mappings found")]
    NoGidMapping,
    #[error("user namespaces enabled, but no group mapping found")]
    NoGroupMapping,

    #[error("bind mount requires a source")]
    BindWithoutSource { destination: std::path::PathBuf },

    #[error("invalid umask")]
    InvalidUmask(u32),

    #[error("invalid namespace")]
    InvalidNamespace(String),

    #[error("invalid device path")]
    InvalidDevicePath { path: std::path::PathBuf },

    #[error("invalid device type")]
    InvalidDeviceType {
        kind: String,
        path: std::path::PathBuf,
    },

    #[error("invalid device mode")]
    InvalidDeviceMode { path: std::path::PathBuf, mode: u32 },
}
