use super::*;
use phf::phf_map;

struct Flag {
    clear: bool,
    flag: nix::mount::MsFlags,
}

static FLAGS: phf::Map<&'static str, Flag> = phf_map! {
    "acl" =>           Flag { clear: false, flag: nix::mount::MsFlags::MS_POSIXACL },
    "async" =>         Flag { clear: true,  flag: nix::mount::MsFlags::MS_SYNCHRONOUS },
    "atime" =>         Flag { clear: true,  flag: nix::mount::MsFlags::MS_NOATIME },
    "bind" =>          Flag { clear: false, flag: nix::mount::MsFlags::MS_BIND },
    "defaults" =>      Flag { clear: false, flag: nix::mount::MsFlags::empty() },
    "dev" =>           Flag { clear: true,  flag: nix::mount::MsFlags::MS_NODEV },
    "diratime" =>      Flag { clear: true,  flag: nix::mount::MsFlags::MS_NODIRATIME },
    "dirsync" =>       Flag { clear: false, flag: nix::mount::MsFlags::MS_DIRSYNC },
    "exec" =>          Flag { clear: true,  flag: nix::mount::MsFlags::MS_NOEXEC },
    "iversion" =>      Flag { clear: false, flag: nix::mount::MsFlags::MS_I_VERSION },
    "loud" =>          Flag { clear: true,  flag: nix::mount::MsFlags::MS_SILENT },
    "mand" =>          Flag { clear: false, flag: nix::mount::MsFlags::MS_MANDLOCK },
    "noacl" =>         Flag { clear: true,  flag: nix::mount::MsFlags::MS_POSIXACL },
    "noatime" =>       Flag { clear: false, flag: nix::mount::MsFlags::MS_NOATIME },
    "nodev" =>         Flag { clear: false, flag: nix::mount::MsFlags::MS_NODEV },
    "nodiratime" =>    Flag { clear: false, flag: nix::mount::MsFlags::MS_NODIRATIME },
    "noexec" =>        Flag { clear: false, flag: nix::mount::MsFlags::MS_NOEXEC },
    "noiversion" =>    Flag { clear: true,  flag: nix::mount::MsFlags::MS_I_VERSION },
    "nomand" =>        Flag { clear: true,  flag: nix::mount::MsFlags::MS_MANDLOCK },
    "norelatime" =>    Flag { clear: true,  flag: nix::mount::MsFlags::MS_RELATIME },
    "nostrictatime" => Flag { clear: true,  flag: nix::mount::MsFlags::MS_STRICTATIME },
    "nosuid" =>        Flag { clear: false, flag: nix::mount::MsFlags::MS_NOSUID },
    "rbind" =>         Flag { clear: false, flag: nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC },
    "relatime" =>      Flag { clear: false, flag: nix::mount::MsFlags::MS_RELATIME },
    "remount" =>       Flag { clear: false, flag: nix::mount::MsFlags::MS_REMOUNT },
    "ro" =>            Flag { clear: false, flag: nix::mount::MsFlags::MS_RDONLY },
    "rw" =>            Flag { clear: true,  flag: nix::mount::MsFlags::MS_RDONLY },
    "silent" =>        Flag { clear: false, flag: nix::mount::MsFlags::MS_SILENT },
    "strictatime" =>   Flag { clear: false, flag: nix::mount::MsFlags::MS_STRICTATIME },
    "suid" =>          Flag { clear: true,  flag: nix::mount::MsFlags::MS_NOSUID },
    "sync" =>          Flag { clear: false, flag: nix::mount::MsFlags::MS_SYNCHRONOUS },
};

static PROPAGATION_FLAGS: phf::Map<&'static str, nix::mount::MsFlags> = phf_map! {
    "private" =>     nix::mount::MsFlags::MS_PRIVATE,
    "shared" =>      nix::mount::MsFlags::MS_SHARED,
    "slave" =>       nix::mount::MsFlags::MS_SLAVE,
    "unbindable" =>  nix::mount::MsFlags::MS_UNBINDABLE,
    "rprivate" =>    nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
    "rshared" =>     nix::mount::MsFlags::MS_SHARED | nix::mount::MsFlags::MS_REC,
    "rslave" =>      nix::mount::MsFlags::MS_SLAVE | nix::mount::MsFlags::MS_REC,
    "runbindable" => nix::mount::MsFlags::MS_UNBINDABLE | nix::mount::MsFlags::MS_REC,
};

pub struct Mount {
    pub source: Option<std::path::PathBuf>,
    pub destination: std::path::PathBuf,
    pub device: String,
    pub data: Vec<String>,
    pub flags: nix::mount::MsFlags,
    pub propagation_flags: Vec<nix::mount::MsFlags>,
}

impl Mount {
    pub fn parse_config<P: AsRef<std::path::Path>>(
        config_mount: &config::Mount,
        rootfs: &P,
    ) -> Mount {
        let mut mount = Mount {
            source: if config_mount.source == "" {
                None
            } else {
                Some(std::path::PathBuf::from(config_mount.source))
            },
            destination: if config_mount.destination.starts_with(rootfs) {
                config_mount.destination
            } else {
                rootfs.as_ref().join(config_mount.destination)
            },
            device: config_mount.kind,
            data: vec![],
            flags: nix::mount::MsFlags::empty(),
            propagation_flags: vec![],
        };
        for option in config_mount.options {
            if let Some(&flag) = FLAGS.get(option.as_str()) {
                if flag.clear {
                    mount.flags &= !flag.flag;
                } else {
                    mount.flags |= flag.flag;
                }
            } else if let Some(&flag) = PROPAGATION_FLAGS.get(option.as_str()) {
                mount.propagation_flags.push(flag);
            } else {
                mount.data.push(option);
            }
        }
        mount
    }

    fn _mount(&self, mount_label: &str) -> Result<()> {
        let source = match self.source {
            Some(path) => Some(&path),
            None => None,
        };
        nix::mount::mount(
            source,
            &self.destination,
            if self.device == "" {
                None
            } else {
                Some(self.device.as_str())
            },
            self.flags,
            Some(selinux::format_mount_label(self.data.join(",").as_str(), mount_label).as_str()),
        )?;

        for propagation_flag in self.propagation_flags {
            nix::mount::mount::<str, std::path::PathBuf, str, str>(
                None,
                &self.destination,
                None,
                propagation_flag,
                None,
            )?;
        }

        Ok(())
    }

    fn mount_cgroup_v1(&self, mount_label: &str, enable_cgroups: bool) -> Result<()> {
        std::fs::create_dir_all(self.destination)?;

        Ok(())
    }

    fn mount_cgroup_v2(&self, mount_label: &str, enable_cgroups: bool) -> Result<()> {
        let source = match self.source {
            Some(path) => Some(&path),
            None => None,
        };

        std::fs::create_dir_all(self.destination)?;
        match nix::mount::mount(
            source,
            &self.destination,
            Some("cgroup2"),
            self.flags,
            Some(selinux::format_mount_label(self.data.join(",").as_str(), mount_label).as_str()),
        ) {
            Err(nix::Error::Sys(nix::errno::Errno::EPERM))
            | Err(nix::Error::Sys(nix::errno::Errno::EBUSY)) => {
                // We are unable to mount cgroup2 when we are in user namespace but cgroup namespace
                // is not unshared. Try to bind systemd cgroup.
                nix::mount::mount::<str, std::path::PathBuf, str, str>(
                    Some("/sys/fs/cgroup"),
                    &self.destination,
                    None,
                    self.flags | nix::mount::MsFlags::MS_BIND,
                    None,
                )?;
                Ok(())
            }
            Err(x) => Err(error::Error::Nix(x)),
            Ok(_) => Ok(()),
        }
    }

    pub fn mount(&self, mount_label: &str, enable_cgroups: bool) -> Result<()> {
        match self.device.as_str() {
            "proc" | "sysfs" => {
                match std::fs::metadata(self.destination) {
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            std::fs::create_dir_all(self.destination)?;
                        } else {
                            return Err(error::Error::Io(error));
                        }
                    }
                    Ok(metadata) => {
                        if !metadata.is_dir() {
                            return Err(error::Error::MountpointNotDirectory {
                                path: self.destination,
                            });
                        }
                    }
                };
                self._mount("")?;
            }
            "mqueue" => {
                std::fs::create_dir_all(self.destination)?;
                self._mount("")?;
                // TODO: set file label
            }
            "tmpfs" => {}
            "bind" => {
                prepare_bind_mount(mount, rootfs)?;
                self._mount(mount_label)?;
            }
            "cgroup" => {
                if cgroup::is_cgroup_v2_unified_mode() {
                    mount_cgroup_v2(mount, rootfs, mount_label, enable_cgroups);
                } else {
                    mount_cgroup_v1(mount, rootfs, mount_label, enable_cgroups);
                }
            }
            _ => {}
        }

        Ok(())
    }
}
