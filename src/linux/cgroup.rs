use super::*;
use cgroups_rs::hierarchies::*;

pub fn get_all_subsystems() -> Result<Vec<String>> {
    if is_cgroup2_unified_mode() {
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
    if is_cgroup2_unified_mode() {
        let controllers = get_all_subsystems()?;
        Ok(vec![CgroupMount {
            mountpoint: UNIFIED_MOUNTPOINT.into(),
            root: UNIFIED_MOUNTPOINT.into(),
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
