use super::*;
use log::warn;

const UNIFIED_MOUNT_POINT: &str = "/sys/fs/cgroup";

static UNIFIED_INIT: once_cell::sync::OnceCell<bool> = once_cell::sync::OnceCell::new();

pub fn is_cgroup_v2_unified_mode() -> bool {
    *UNIFIED_INIT.get_or_init(|| {
        let unified_mount_point = std::path::Path::new(UNIFIED_MOUNT_POINT);
        if !unified_mount_point.exists() && system::is_running_in_user_namespace() {
            warn!("{} missing, assuming cgroup v1", UNIFIED_MOUNT_POINT);
            return false;
        }
        match nix::sys::statfs::statfs(UNIFIED_MOUNT_POINT) {
            Err(error) => panic!(
                "canot statfs cgroup root: {} {:?}",
                UNIFIED_MOUNT_POINT, error,
            ),
            Ok(stat) => stat.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC,
        }
    })
}

pub fn get_all_subsystems() -> Result<Vec<String>> {
    if is_cgroup_v2_unified_mode() {
        let controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?;
        Ok(controllers
            .split_whitespace()
            .map(|s| String::from(s))
            .collect())
    } else {
        Ok(procfs::cgroups()?.into_iter().map(|c| c.name).collect())
    }
}

pub struct CgroupMount {
    pub mountpoint: std::path::PathBuf,
    pub root: String,
    pub subsystems: Vec<String>,
}

pub fn get_cgroup_mounts() -> Result<Vec<CgroupMount>> {
    if is_cgroup_v2_unified_mode() {
        let controllers = get_all_subsystems()?;
        Ok(vec![CgroupMount {
            mountpoint: UNIFIED_MOUNT_POINT.into(),
            root: UNIFIED_MOUNT_POINT.into(),
            subsystems: controllers,
        }])
    } else {
        let myself = procfs::process::Process::myself()?;
        let myself_cgroups = myself.cgroups()?;
        let mut myself_subsystems = std::collections::HashMap::new();
        for cgroup in myself_cgroups {
            for controller in cgroup.controllers {
                myself_subsystems.insert(controller, false);
            }
        }

        Ok(myself
            .mountinfo()?
            .into_iter()
            .filter(|mountinfo| mountinfo.fs_type == "cgroup")
            .map(|mountinfo| {
                let mut cgroup_mount = CgroupMount {
                    mountpoint: mountinfo.mount_point,
                    root: mountinfo.root,
                    subsystems: vec![],
                };
                for (option, _) in mountinfo.super_options.iter() {
                    // cgroup filesystems marks its controller type by super options
                    // e.g. mount -t cgroup -o rw,memory cgroup /sys/fs/cgroup/memory
                    if myself_subsystems.contains_key(option) {
                        cgroup_mount.subsystems.push(option.to_string());
                    }
                }
                cgroup_mount
            })
            .collect())
    }
}
