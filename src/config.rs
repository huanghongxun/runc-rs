use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub process: Process,

    pub root: Root,

    pub hostname: String,

    #[serde(default)]
    pub mount_label: String,

    #[serde(default)]
    pub root_propagation: u64,

    #[serde(default)]
    pub rootless_euid: bool,

    #[serde(default)]
    pub mounts: Vec<Mount>,

    #[serde(default)]
    pub linux: Linux,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Process {
    #[serde(default)]
    pub user: User,

    #[serde(default)]
    pub env: Vec<String>,

    #[serde(default)]
    pub cwd: Option<PathBuf>,

    pub capabilities: Capabilities,

    #[serde(default)]
    pub rlimits: Vec<Rlimit>,

    #[serde(alias = "noNewPrivileges")]
    pub no_new_privileges: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct User {
    // uid inside container
    pub uid: libc::uid_t,

    // gid inside container
    pub gid: libc::gid_t,

    #[serde(default)]
    pub umask: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub bounding: Vec<String>,

    #[serde(default)]
    pub effective: Vec<String>,

    #[serde(default)]
    pub inheritable: Vec<String>,

    #[serde(default)]
    pub permitted: Vec<String>,

    #[serde(default)]
    pub ambient: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Rlimit {
    #[serde(alias = "type")]
    pub kind: String,

    pub hard: u64,

    pub soft: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Root {
    pub path: PathBuf,
    pub readonly: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Mount {
    pub destination: PathBuf,
    #[serde(alias = "type")]
    pub kind: String,

    pub source: String,

    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Linux {
    #[serde(default, alias = "uidMappings")]
    pub uid_mappings: Vec<IDMap>,

    #[serde(default, alias = "gidMappings")]
    pub gid_mappings: Vec<IDMap>,

    #[serde(default)]
    pub devices: Vec<Device>,

    #[serde(default)]
    pub seccomp: Option<Seccomp>,

    #[serde(default)]
    pub namespaces: Vec<Namespace>,

    #[serde(default)]
    pub masked_paths: Vec<PathBuf>,

    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,

    #[serde(default)]
    pub resources: Option<Resources>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IDMap {
    /// First uid/gid inside guest user namespace.
    #[serde(alias = "containerID")]
    pub container_id: u64,

    /// First uid/gid in host.
    #[serde(alias = "hostID")]
    pub host_id: u64,

    /// Number of uid/gids that this entry maps from host into guest user namespace.
    pub size: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Device {
    #[serde(alias = "type")]
    pub kind: String,

    pub path: PathBuf,

    #[serde(default)]
    pub major: u64,

    #[serde(default)]
    pub minor: u64,

    #[serde(alias = "fileMode")]
    pub file_mode: u32,

    #[serde(default)]
    pub uid: libc::uid_t,

    #[serde(default)]
    pub gid: libc::gid_t,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Seccomp {
    #[serde(alias = "defaultAction")]
    pub default_action: String,

    pub architectures: Vec<String>,

    pub syscalls: Vec<Syscall>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Syscall {
    #[serde(default)]
    pub names: Option<Vec<String>>,

    #[serde(default)]
    pub nr: Option<usize>,

    pub action: String,

    #[serde(default, alias = "errnoRet")]
    pub errno_ret: i64,

    #[serde(default)]
    pub args: Vec<SyscallArg>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SyscallArg {
    pub index: u32,
    pub value: u64,
    #[serde(default, alias = "valueTwo")]
    pub value_two: Option<u64>,
    pub op: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Namespace {
    #[serde(alias = "type")]
    pub kind: String,

    pub path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Resources {
    pub memory: Option<Memory>,

    pub cpu: Option<CPU>,

    pub pids: Option<PIDs>,

    pub unified: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Memory {
    #[serde(default)]
    pub limit: i64,

    #[serde(default)]
    pub reservation: i64,

    #[serde(default)]
    pub swap: i64,

    #[serde(default)]
    pub kernel: i64,

    #[serde(default, alias = "kernelTCP")]
    pub kernel_tcp: i64,

    #[serde(default)]
    pub swappiness: u64,

    #[serde(default, alias = "disableOOMKiller")]
    pub disable_oom_killer: u64,

    #[serde(default, alias = "useHierarchy")]
    pub use_hierarchy: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CPU {
    #[serde(default)]
    pub shares: u64,

    #[serde(default)]
    pub quota: i64,

    #[serde(default)]
    pub period: u64,

    #[serde(default, alias = "realtimeRuntime")]
    pub realtime_runtime: i64,

    #[serde(default, alias = "realtimePeriod")]
    pub realtime_period: u64,

    #[serde(default)]
    pub cpus: String,

    #[serde(default)]
    pub mems: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PIDs {
    #[serde(default)]
    pub limit: u64,
}
