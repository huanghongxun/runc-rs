use super::*;
use log::{info, trace, warn};

const UNIFIED_MOUNT_POINT: &str = "/sys/fs/cgroup";

static UNIFIED_INIT: once_cell::sync::OnceCell<bool> = once_cell::sync::OnceCell::new();

pub fn is_cgroup_v2_unified_mode() -> bool {
    *UNIFIED_INIT.get_or_init(|| {
        let unifiedMountPoint = std::path::Path::new(UNIFIED_MOUNT_POINT);
        if !unifiedMountPoint.exists() && system::is_running_in_user_namespace() {
            warn!("{} missing, assuming cgroup v1", UNIFIED_MOUNT_POINT);
            return false;
        }
        match nix::sys::statfs::statfs(UNIFIED_MOUNT_POINT) {
            Err(error) => panic!("canot statfs cgroup root: {}", UNIFIED_MOUNT_POINT),
            Ok(stat) => stat.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC,
        }
    })
}

pub fn get_all_subsystems() -> Result<Vec<String>> {
    if is_cgroup_v2_unified_mode() {
        std::fs::read
    }
}

pub fn get_cgroup_mounts() -> error::Result<Vec<mount::Mount>> {
    Ok(mounts)
}
