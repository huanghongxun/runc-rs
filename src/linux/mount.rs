use super::*;
use nix::mount::*;
use phf::phf_map;
use std::path::PathBuf;

struct Flag {
    clear: bool,
    flag: libc::c_ulong,
}

static FLAGS: phf::Map<&'static str, Flag> = phf_map! {
    "acl" =>           Flag { clear: false, flag: libc::MS_POSIXACL },
    "async" =>         Flag { clear: true,  flag: libc::MS_SYNCHRONOUS },
    "atime" =>         Flag { clear: true,  flag: libc::MS_NOATIME },
    "bind" =>          Flag { clear: false, flag: libc::MS_BIND },
    "defaults" =>      Flag { clear: false, flag: 0 },
    "dev" =>           Flag { clear: true,  flag: libc::MS_NODEV },
    "diratime" =>      Flag { clear: true,  flag: libc::MS_NODIRATIME },
    "dirsync" =>       Flag { clear: false, flag: libc::MS_DIRSYNC },
    "exec" =>          Flag { clear: true,  flag: libc::MS_NOEXEC },
    "iversion" =>      Flag { clear: false, flag: libc::MS_I_VERSION },
    "loud" =>          Flag { clear: true,  flag: libc::MS_SILENT },
    "mand" =>          Flag { clear: false, flag: libc::MS_MANDLOCK },
    "noacl" =>         Flag { clear: true,  flag: libc::MS_POSIXACL },
    "noatime" =>       Flag { clear: false, flag: libc::MS_NOATIME },
    "nodev" =>         Flag { clear: false, flag: libc::MS_NODEV },
    "nodiratime" =>    Flag { clear: false, flag: libc::MS_NODIRATIME },
    "noexec" =>        Flag { clear: false, flag: libc::MS_NOEXEC },
    "noiversion" =>    Flag { clear: true,  flag: libc::MS_I_VERSION },
    "nomand" =>        Flag { clear: true,  flag: libc::MS_MANDLOCK },
    "norelatime" =>    Flag { clear: true,  flag: libc::MS_RELATIME },
    "nostrictatime" => Flag { clear: true,  flag: libc::MS_STRICTATIME },
    "nosuid" =>        Flag { clear: false, flag: libc::MS_NOSUID },
    "rbind" =>         Flag { clear: false, flag: libc::MS_BIND | libc::MS_REC },
    "relatime" =>      Flag { clear: false, flag: libc::MS_RELATIME },
    "remount" =>       Flag { clear: false, flag: libc::MS_REMOUNT },
    "ro" =>            Flag { clear: false, flag: libc::MS_RDONLY },
    "rw" =>            Flag { clear: true,  flag: libc::MS_RDONLY },
    "silent" =>        Flag { clear: false, flag: libc::MS_SILENT },
    "strictatime" =>   Flag { clear: false, flag: libc::MS_STRICTATIME },
    "suid" =>          Flag { clear: true,  flag: libc::MS_NOSUID },
    "sync" =>          Flag { clear: false, flag: libc::MS_SYNCHRONOUS },
};

static PROPAGATION_FLAGS: phf::Map<&'static str, libc::c_ulong> = phf_map! {
    "private" =>     libc::MS_PRIVATE,
    "shared" =>      libc::MS_SHARED,
    "slave" =>       libc::MS_SLAVE,
    "unbindable" =>  libc::MS_UNBINDABLE,
    "rprivate" =>    libc::MS_PRIVATE | libc::MS_REC,
    "rshared" =>     libc::MS_SHARED | libc::MS_REC,
    "rslave" =>      libc::MS_SLAVE | libc::MS_REC,
    "runbindable" => libc::MS_UNBINDABLE | libc::MS_REC,
};

static DEFAULT_MOUNT_FLAGS: libc::c_ulong = libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV;

pub struct Mount {
    pub source: Option<PathBuf>,
    pub destination: PathBuf,
    pub device: String,
    pub data: Vec<String>,
    pub flags: MsFlags,
    pub propagation_flags: Vec<MsFlags>,
}

impl Mount {
    pub fn parse_config<P: AsRef<std::path::Path>>(
        config_mount: &config::Mount,
        rootfs: &P,
    ) -> Result<Mount> {
        let mut mount = Mount {
            source: if config_mount.source == "" {
                None
            } else {
                Some(PathBuf::from(&config_mount.source))
            },
            destination: join::secure_join(&rootfs.as_ref(), &config_mount.destination)?,
            device: config_mount.kind.clone(),
            data: vec![],
            flags: MsFlags::empty(),
            propagation_flags: vec![],
        };
        for option in config_mount.options.iter() {
            if let Some(flag) = FLAGS.get(option.as_str()) {
                if flag.clear {
                    mount.flags &= !MsFlags::from_bits(flag.flag).unwrap();
                } else {
                    mount.flags |= MsFlags::from_bits(flag.flag).unwrap();
                }
            } else if let Some(flag) = PROPAGATION_FLAGS.get(option.as_str()) {
                mount
                    .propagation_flags
                    .push(MsFlags::from_bits(*flag).unwrap());
            } else {
                mount.data.push(option.clone());
            }
        }
        Ok(mount)
    }

    fn _mount(&self, mount_label: &str) -> Result<()> {
        mount(
            self.source.as_ref(),
            &self.destination,
            if self.device == "" {
                None
            } else {
                Some(self.device.as_str())
            },
            self.flags,
            Some(selinux::format_mount_label(self.data.join(",").as_str(), mount_label).as_str()),
        )?;

        for propagation_flag in self.propagation_flags.iter() {
            mount::<str, PathBuf, str, str>(
                None,
                &self.destination,
                None,
                *propagation_flag,
                None,
            )?;
        }

        Ok(())
    }

    fn mount_cgroup_v1(&self, mount_label: &str, in_cgroup_namespace: bool) -> Result<()> {
        std::fs::create_dir_all(&self.destination)?;

        let cgroup_mounts = cgroup::get_cgroup_mounts()?;
        let cgroups: std::collections::HashMap<String, String> =
            procfs::process::Process::myself()?
                .cgroups()?
                .into_iter()
                .flat_map(|p| {
                    let pathname = &p.pathname;
                    p.controllers
                        .into_iter()
                        .map(|c| (c, pathname.clone()))
                        .collect::<Vec<(String, String)>>()
                })
                .collect();

        // /sys/fs/cgroup is tmpfs.
        let tmpfs = Mount {
            source: Some(PathBuf::from("tmpfs")),
            destination: self.destination.clone(),
            device: String::from("tmpfs"),
            data: vec![String::from("mode=755")],
            flags: MsFlags::from_bits(DEFAULT_MOUNT_FLAGS).unwrap(),
            propagation_flags: self.propagation_flags.clone(),
        };
        tmpfs.mount(mount_label, in_cgroup_namespace)?;

        for mount in cgroup_mounts {
            if in_cgroup_namespace {
                std::fs::create_dir_all(&self.destination)?;

                let mut cgroup_mount = Mount {
                    source: Some(PathBuf::from("cgroup")),
                    destination: self.destination.clone(),
                    device: "cgroup".to_string(),
                    // we do not take user's settings except MS_RDONLY.
                    flags: MsFlags::from_bits(DEFAULT_MOUNT_FLAGS).unwrap()
                        | (self.flags & MsFlags::MS_RDONLY),
                    data: vec![
                        match self.destination.file_name().and_then(|f| f.to_str()) {
                            Some(file_name) => file_name.to_string(),
                            None => continue,
                        },
                    ],
                    propagation_flags: vec![],
                };

                if cgroup_mount.data == vec![String::from("name=systemd")] {
                    cgroup_mount.source = Some(PathBuf::from("systemd"));
                }

                cgroup_mount.mount(mount_label, in_cgroup_namespace)?;
            } else {
                let cgroup_mount = Mount {
                    source: Some(
                        mount.mountpoint.join(
                            cgroups[match mount.subsystems.first() {
                                Some(first) => first,
                                None => continue,
                            }]
                            .as_str(),
                        ),
                    ),
                    destination: self.destination.join(match mount.mountpoint.file_name() {
                        Some(t) => t,
                        None => continue,
                    }),
                    device: "bind".to_string(),
                    data: vec![],
                    flags: MsFlags::MS_BIND | MsFlags::MS_REC | self.flags,
                    propagation_flags: self.propagation_flags.clone(),
                };
                cgroup_mount.mount(mount_label, in_cgroup_namespace)?;
            }
        }

        Ok(())
    }

    fn mount_cgroup_v2(&self, mount_label: &str, in_cgroup_namespace: bool) -> Result<()> {
        std::fs::create_dir_all(&self.destination)?;
        match mount(
            self.source.as_ref(),
            &self.destination,
            Some("cgroup2"),
            self.flags,
            Some(selinux::format_mount_label(self.data.join(",").as_str(), mount_label).as_str()),
        ) {
            Err(nix::Error::Sys(nix::errno::Errno::EPERM))
            | Err(nix::Error::Sys(nix::errno::Errno::EBUSY)) => {
                // We are unable to mount cgroup2 when we are in user namespace but cgroup namespace
                // is not unshared. Try to bind systemd cgroup.
                mount::<str, PathBuf, str, str>(
                    Some("/sys/fs/cgroup"),
                    &self.destination,
                    None,
                    self.flags | MsFlags::MS_BIND,
                    None,
                )?;
                Ok(())
            }
            Err(x) => Err(error::Error::Nix(x)),
            Ok(_) => Ok(()),
        }
    }

    fn check_bind(&self) -> Result<()> {
        match &self.source {
            None => return Err(error::Error::BindWithoutSource),
            Some(source) => std::fs::create_dir_all(&source)?,
        }
        Ok(())
    }

    fn remount(&self) -> Result<()> {
        mount::<PathBuf, PathBuf, str, str>(
            self.source.as_ref(),
            &self.destination,
            Some(self.device.as_str()),
            self.flags | MsFlags::MS_REMOUNT,
            None,
        )?;

        Ok(())
    }

    pub fn mount(&self, mount_label: &str, in_cgroup_namespace: bool) -> Result<()> {
        match self.device.as_str() {
            "proc" | "sysfs" => {
                std::fs::create_dir_all(&self.destination)?;
                self._mount("")?;
            }
            "mqueue" => {
                std::fs::create_dir_all(&self.destination)?;
                self._mount("")?;
            }
            "tmpfs" => {
                std::fs::create_dir_all(&self.destination)?;
                let perms = std::fs::metadata(&self.destination)?.permissions();

                self._mount(mount_label)?;

                // restore permission after mounting.
                std::fs::set_permissions(&self.destination, perms);

                if self.flags & MsFlags::MS_RDONLY != MsFlags::empty() {
                    // _mount mounts tmpfs rw, remount here.
                    self.remount()?;
                }
            }
            "bind" => {
                self.check_bind()?;
                self._mount(mount_label)?;

                if self.flags & !(MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_BIND)
                    != MsFlags::empty()
                {
                    self.remount()?;
                }
            }
            "cgroup" => {
                if cgroup::is_cgroup_v2_unified_mode() {
                    self.mount_cgroup_v2(mount_label, in_cgroup_namespace)?;
                } else {
                    self.mount_cgroup_v1(mount_label, in_cgroup_namespace)?;
                }
            }
            _ => {
                std::fs::create_dir_all(&self.destination)?;
                self._mount(mount_label)?;
            }
        }

        Ok(())
    }
}
