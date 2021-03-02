use super::*;
use once_cell::sync::OnceCell;
use std::io::{self, BufRead};

static RUNNING_IN_USER_NAMESPACE: OnceCell<bool> = OnceCell::new();

pub fn is_running_in_user_namespace() -> bool {
    *RUNNING_IN_USER_NAMESPACE.get_or_init(|| match current_process_uid_map() {
        Ok(uid_map) => uid_map_in_user_namespace(&uid_map),
        Err(_) => false,
    })
}

pub fn uid_map_in_user_namespace(uidmap: &[config::IDMap]) -> bool {
    if uidmap.len() == 1
        && uidmap[0].container_id == 0
        && uidmap[0].host_id == 0
        && uidmap[0].size == 4294967295u64
    {
        return false;
    }
    return true;
}

pub fn current_process_uid_map() -> Result<Vec<config::IDMap>> {
    parse_id_map("/proc/self/uid_map")
}

pub fn current_process_gid_map() -> Result<Vec<config::IDMap>> {
    parse_id_map("/proc/self/gid_map")
}

pub fn parse_id_map<P: AsRef<std::path::Path>>(path: P) -> Result<Vec<config::IDMap>> {
    let file = std::fs::File::open(path)?;
    let mut result: Vec<config::IDMap> = Vec::new();
    for line_result in io::BufReader::new(file).lines() {
        if let Ok(line) = line_result {
            let (id, parent_id, count) = scan_fmt!(line.as_str(), "{}{}{}", u64, u64, u64)?;
            result.push(config::IDMap {
                container_id: id,
                host_id: parent_id,
                size: count,
            });
        }
    }

    Ok(result)
}
