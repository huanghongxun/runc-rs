use super::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("posix error")]
    Nix(#[from] nix::Error),
    #[error("procfs error")]
    Proc(#[from] procfs::ProcError),
    #[error("seccomp error")]
    Seccomp(#[from] super::seccomp::SeccompError),
    #[error("cgroup error")]
    Cgroup(#[from] cgroups_rs::error::Error),
    #[error("systemd bus error")]
    SystemdBus(#[from] ::systemd::bus::Error),

    #[error("rootfs {path:?} not found or not a directory")]
    RootfsNotDirectory { path: std::path::PathBuf },

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

    #[error("invalid device path {path:?}")]
    InvalidDevicePath { path: std::path::PathBuf },

    #[error("invalid device type")]
    InvalidDeviceType {
        kind: String,
        path: std::path::PathBuf,
    },

    #[error("invalid device mode")]
    InvalidDeviceMode { path: std::path::PathBuf, mode: u32 },

    #[error("invalid capability name")]
    InvalidCapability { capability: String },

    #[error("invalid seccomp action {action:}")]
    InvalidSeccompAction { action: String },
    #[error("invalid seccomp op {op:}")]
    InvalidSeccompOp { op: String },
    #[error("invalid seccomp nr")]
    InvalidSeccompNr,
    #[error("invalid seccomp arg")]
    InvalidSeccompArg {
        index: u32,
        value: u64,
        value_two: Option<u64>,
        op: String,
    },

    #[error("an error occurred when linking /dev/ptmx")]
    DevPtmxFailure { error: std::io::Error },

    #[error("an error occurred when creating symlinks to {destination:?}")]
    DevSymlinksFailure {
        src: std::path::PathBuf,
        destination: std::path::PathBuf,
        error: std::io::Error,
    },

    #[error("an error occurred when mounting {path:?}")]
    Mount {
        path: std::path::PathBuf,
        error: nix::Error,
    },
    #[error("an error occured when setting permission of mountpoint {path:?}")]
    MountpointPermission {
        path: std::path::PathBuf,
        error: std::io::Error,
    },
    #[error("filesystem {path:?} must be mounted on ordinary directory")]
    MountpointNotDirectory { path: std::path::PathBuf },
    #[error("an error ocurred when creating directory for mounting {path:?}")]
    MountpointCreateDirectories {
        path: std::path::PathBuf,
        error: std::io::Error,
    },
    #[error("an error ocurred when remounting mountpoint as readonly")]
    MountpointRemountReadonly {
        path: std::path::PathBuf,
        error: nix::Error,
    },
    #[error("an error ocurred when adjusting mounting propagation flags")]
    MountPropagation {
        path: std::path::PathBuf,
        error: nix::Error,
    },
    #[error("invalid rootfs propagation flag")]
    InvalidRootfsPropagation(u64),
    #[error("cannot find parent mount of {path:?}")]
    NoParentMount { path: std::path::PathBuf },

    #[error("an error occurred when unsharing {namespace:}")]
    UnshareNamespace {
        namespace: namespace::Namespace,
        error: nix::Error,
    },
    #[error("an error occurred when deny setgroups syscall.")]
    DenySetgroups(std::io::Error),
    #[error("an error occurred when update uid mapping.")]
    UpdateUidMapping(std::io::Error),
    #[error("an error occurred when update gid mapping.")]
    UpdateGidMapping(std::io::Error),

    #[error("an error occurred when killing process {pid:}")]
    Kill { pid: libc::pid_t, error: nix::Error },

    #[error("failed to detect user dbus connection to systemd")]
    DbusAddressNotFound,

    #[error("failed to detect owner uid")]
    DetectUID,

    #[error("an error occurred when executing process {command:?}")]
    ProcessError {
        command: String,
        error: std::io::Error,
    },
    #[error("an error occurred when reading process output")]
    ProcessOutputNotUtf8 {
        command: String,
        error: std::string::FromUtf8Error,
    },

    #[error("an error occurred when applying capabilities")]
    CapabilityError(std::io::Error),
}
