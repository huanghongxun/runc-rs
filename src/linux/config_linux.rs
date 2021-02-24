use crate::config::{Config, IDMap};

pub type Result<T> = std::result::Result<T, LinuxProcessError>;

pub enum LinuxProcessError {
    Nix(nix::Error),

    NoUidMapping,
    NoUserMapping,

    NoGidMapping,
    NoGroupMapping,
}

fn get_host_id_from_mapping(container_id: u64, mapping: &Vec<IDMap>) -> Option<u64> {
    for &m in mapping.iter() {
        if container_id >= m.container_id && container_id <= m.container_id + m.size - 1 {
            return Some(m.host_id + container_id - m.container_id);
        }
    }
    None
}

pub fn get_host_uid(config: &Config, container_uid: libc::uid_t) -> Result<libc::uid_t> {
    if let Some(linux) = &config.linux {
        if linux.namespaces.iter().any(|&x| x.kind == "user") {
            if linux.uid_mappings.is_empty() {
                return Err(LinuxProcessError::NoUidMapping);
            }

            return match get_host_id_from_mapping(container_uid as u64, &linux.uid_mappings) {
                None => Err(LinuxProcessError::NoUserMapping),
                Some(host_uid) => Ok(host_uid as libc::uid_t),
            };
        }
    }

    // left unchanged id.
    return Ok(container_uid);
}

pub fn get_host_gid(config: &Config, container_gid: libc::gid_t) -> Result<libc::gid_t> {
    if let Some(linux) = &config.linux {
        if linux.namespaces.iter().any(|&x| x.kind == "user") {
            if linux.gid_mappings.is_empty() {
                return Err(LinuxProcessError::NoGidMapping);
            }

            return match get_host_id_from_mapping(container_gid as u64, &linux.gid_mappings) {
                None => Err(LinuxProcessError::NoGroupMapping),
                Some(host_gid) => Ok(host_gid as libc::gid_t),
            };
        }
    }
    // left unchanged id.
    return Ok(container_gid);
}
