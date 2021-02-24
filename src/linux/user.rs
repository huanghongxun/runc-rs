use std::fs::File;
use std::io::{self, BufRead};

#[derive(Default, Clone)]
pub struct User {
    pub name: String,
    pub password: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub sgids: Vec<libc::gid_t>,
    pub comment: String,
    pub home: String,
    pub shell: String,
}

impl User {
    pub fn find_user(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<User> {
        let users = User::parse_from_file("/etc/passwd")?;
        let groups = Group::parse_from_file("/etc/group")?;
        if let Some(match_user) = users.iter().find(|user| user.uid == uid && user.gid == gid) {
            let mut user = match_user.clone();
            user.sgids = groups
                .iter()
                .filter(|g| g.users.contains(&user.name))
                .map(|g| g.gid)
                .collect();
            Ok(user)
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    pub fn parse_from_file(passwd_path: &str) -> io::Result<Vec<User>> {
        let mut result: Vec<User> = Vec::new();
        let file = File::open(passwd_path)?;
        for line in io::BufReader::new(file).lines() {
            let ok_line = line?;
            let splitted: Vec<&str> = ok_line.split(":").collect();
            if splitted.len() != 7 {
                continue;
            }
            result.push(User {
                name: String::from(splitted[0]),
                password: String::from(splitted[1]),
                uid: match splitted[2].parse::<libc::uid_t>() {
                    Ok(uid) => uid,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expect integral",
                        ))
                    }
                },
                gid: match splitted[3].parse::<libc::gid_t>() {
                    Ok(gid) => gid,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expect integral",
                        ))
                    }
                },
                sgids: vec![], // TODO
                comment: String::from(splitted[4]),
                home: String::from(splitted[5]),
                shell: String::from(splitted[6]),
            });
        }

        Ok(result)
    }
}

#[derive(Default)]
pub struct Group {
    pub name: String,
    pub password: String,
    pub gid: libc::gid_t,
    pub users: Vec<String>,
}

impl Group {
    pub fn parse_from_file(group_path: &str) -> io::Result<Vec<Group>> {
        let mut result: Vec<Group> = Vec::new();
        let file = File::open(group_path)?;
        for line in io::BufReader::new(file).lines() {
            let ok_line = line?;
            let splitted: Vec<&str> = ok_line.split(":").collect();
            if splitted.len() != 4 {
                continue;
            }
            result.push(Group {
                name: String::from(splitted[0]),
                password: String::from(splitted[1]),
                gid: match splitted[2].parse::<libc::gid_t>() {
                    Ok(gid) => gid,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expect integral",
                        ))
                    }
                },
                users: String::from(splitted[4])
                    .split(":")
                    .map(|s| String::from(s))
                    .collect::<Vec<String>>(),
            });
        }

        Ok(result)
    }
}
