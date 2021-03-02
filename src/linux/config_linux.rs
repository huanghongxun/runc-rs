use super::error::{Error, Result};
use super::*;
use crate::config::{Config, IDMap};
use nix::unistd::{Gid, Uid};

fn get_host_id_from_mapping(container_id: u64, mapping: &Vec<IDMap>) -> Option<u64> {
    for m in mapping.iter() {
        if container_id >= m.container_id && container_id <= m.container_id + m.size - 1 {
            return Some(m.host_id + container_id - m.container_id);
        }
    }
    None
}

pub fn get_host_uid(config: &Config, container_uid: Uid) -> Result<Uid> {
    if has_namespace(config, namespace::Namespace::User) {
        if config.linux.uid_mappings.is_empty() {
            return Err(Error::NoUidMapping);
        }

        return match get_host_id_from_mapping(
            container_uid.as_raw() as u64,
            &config.linux.uid_mappings,
        ) {
            None => Err(Error::NoUserMapping),
            Some(host_uid) => Ok(Uid::from_raw(host_uid as u32)),
        };
    }

    // left unchanged id.
    return Ok(container_uid);
}

pub fn get_host_gid(config: &Config, container_gid: Gid) -> Result<Gid> {
    if has_namespace(config, namespace::Namespace::User) {
        if config.linux.gid_mappings.is_empty() {
            return Err(Error::NoGidMapping);
        }

        return match get_host_id_from_mapping(
            container_gid.as_raw() as u64,
            &config.linux.gid_mappings,
        ) {
            None => Err(Error::NoGroupMapping),
            Some(host_gid) => Ok(Gid::from_raw(host_gid as u32)),
        };
    }

    // left unchanged id.
    return Ok(container_gid);
}

pub fn has_namespace(config: &Config, kind: namespace::Namespace) -> bool {
    config
        .linux
        .namespaces
        .iter()
        .any(|x| x.kind == kind.to_string())
}
