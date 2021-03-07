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
    pub names: Option<Vec<String>>,

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
    pub memory: Option<MemoryResources>,

    pub cpu: Option<CPUResources>,

    pub pids: Option<PIDResources>,

    #[serde(default)]
    pub devices: Vec<DeviceResource>,

    pub unified: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct MemoryResources {
    pub limit: Option<i64>,

    pub reservation: Option<i64>,

    pub swap: Option<i64>,

    pub kernel: Option<i64>,

    #[serde(alias = "kernelTCP")]
    pub kernel_tcp: Option<i64>,

    pub swappiness: Option<u64>,

    #[serde(default, alias = "disableOOMKiller")]
    pub disable_oom_killer: u64,

    #[serde(default, alias = "useHierarchy")]
    pub use_hierarchy: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CPUResources {
    pub shares: Option<u64>,

    pub quota: Option<i64>,

    pub period: Option<u64>,

    #[serde(alias = "realtimeRuntime")]
    pub realtime_runtime: Option<i64>,

    #[serde(alias = "realtimePeriod")]
    pub realtime_period: Option<u64>,

    pub cpus: Option<String>,

    pub mems: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PIDResources {
    pub limit: Option<i64>,
}

/// An enum holding the different types of devices that can be manipulated using this controller.
#[derive(Clone, Debug, Deserialize)]
pub enum DeviceType {
    /// The rule applies to all devices.
    #[serde(rename = "a")]
    All,
    /// The rule only applies to character devices.
    #[serde(rename = "c")]
    Char,
    /// The rule only applies to block devices.
    #[serde(rename = "b")]
    Block,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceResource {
    /// If true, access to the device is allowed, otherwise it's denied.
    pub allow: bool,
    /// `'c'` for character device, `'b'` for block device; or `'a'` for all devices.
    #[serde(alias = "type")]
    pub kind: DeviceType,
    /// The major number of the device.
    pub major: Option<i64>,
    /// The minor number of the device.
    pub minor: Option<i64>,
    /// Sequence of `'r'`, `'w'` or `'m'`, each denoting read, write or mknod permissions.
    pub access: Option<String>,
}
