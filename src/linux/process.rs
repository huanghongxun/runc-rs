use super::config_linux::{get_host_gid, get_host_uid};
use super::error::{Error, Result};
use super::namespace::Namespace;
use super::user::User;
use super::*;
use crate::config;
use crate::linux::prctl::prctl;
use crate::process::ProcessStatus;
use cgroups_rs::Controller;
use nix::mount::*;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::*;
use std::convert::TryFrom;
use std::ffi::CString;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

fn format_mount_label(src: &str, mount_label: &str) -> String {
    if !mount_label.is_empty() {
        if src.is_empty() {
            format!("context={}", mount_label)
        } else {
            format!("{},context={}", src, mount_label)
        }
    } else {
        String::from(src)
    }
}

fn close_on_exec_from(start_fd: i32) -> Result<()> {
    for dir in std::fs::read_dir("/proc/self/fd")? {
        let ok_dir = dir?;
        if let Some(file_name) = ok_dir.file_name().to_str() {
            if let Ok(fd) = file_name.parse::<i32>() {
                if fd < start_fd {
                    continue;
                }

                // Ignores errors from fcntl because some fds may be already closed.
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
                )?;
            }
        }
    }

    Ok(())
}

// Fixes the permission of standard input/output within the container to the specified user.
// The ownership needs to match because it is created outside of the container.
fn fix_stdio_permissions(user: &User) -> Result<()> {
    let null = nix::sys::stat::stat("/dev/null")?;
    for &fd in [
        io::stdin().as_raw_fd(),
        io::stdout().as_raw_fd(),
        io::stderr().as_raw_fd(),
    ]
    .iter()
    {
        let s = nix::sys::stat::fstat(fd)?;
        if s.st_rdev == null.st_rdev {
            continue;
        }

        match fchown(fd, Some(user.uid), Some(user.gid)) {
            Err(nix::Error::Sys(nix::errno::Errno::EINVAL))
            | Err(nix::Error::Sys(nix::errno::Errno::EPERM)) => {}
            Err(err) => return Err(Error::Nix(err)),
            _ => {}
        }
    }

    Ok(())
}

fn map_capability(cap_name: &str) -> Result<capabilities::Capability> {
    match cap_name {
        "CAP_CHOWN" => Ok(capabilities::Capability::CAP_CHOWN),
        "CAP_DAC_OVERRIDE" => Ok(capabilities::Capability::CAP_DAC_OVERRIDE),
        "CAP_DAC_READ_SEARCH" => Ok(capabilities::Capability::CAP_DAC_READ_SEARCH),
        "CAP_FOWNER" => Ok(capabilities::Capability::CAP_FOWNER),
        "CAP_FSETID" => Ok(capabilities::Capability::CAP_FSETID),
        "CAP_KILL" => Ok(capabilities::Capability::CAP_KILL),
        "CAP_SETGID" => Ok(capabilities::Capability::CAP_SETGID),
        "CAP_SETUID" => Ok(capabilities::Capability::CAP_SETUID),
        "CAP_SETPCAP" => Ok(capabilities::Capability::CAP_SETPCAP),
        "CAP_LINUX_IMMUTABLE" => Ok(capabilities::Capability::CAP_LINUX_IMMUTABLE),
        "CAP_NET_BIND_SERVICE" => Ok(capabilities::Capability::CAP_NET_BIND_SERVICE),
        "CAP_NET_BROADCAST" => Ok(capabilities::Capability::CAP_NET_BROADCAST),
        "CAP_NET_ADMIN" => Ok(capabilities::Capability::CAP_NET_ADMIN),
        "CAP_NET_RAW" => Ok(capabilities::Capability::CAP_NET_RAW),
        "CAP_IPC_LOCK" => Ok(capabilities::Capability::CAP_IPC_LOCK),
        "CAP_IPC_OWNER" => Ok(capabilities::Capability::CAP_IPC_OWNER),
        "CAP_SYS_MODULE" => Ok(capabilities::Capability::CAP_SYS_MODULE),
        "CAP_SYS_RAWIO" => Ok(capabilities::Capability::CAP_SYS_RAWIO),
        "CAP_SYS_CHROOT" => Ok(capabilities::Capability::CAP_SYS_CHROOT),
        "CAP_SYS_PTRACE" => Ok(capabilities::Capability::CAP_SYS_PTRACE),
        "CAP_SYS_PACCT" => Ok(capabilities::Capability::CAP_SYS_PACCT),
        "CAP_SYS_ADMIN" => Ok(capabilities::Capability::CAP_SYS_ADMIN),
        "CAP_SYS_BOOT" => Ok(capabilities::Capability::CAP_SYS_BOOT),
        "CAP_SYS_NICE" => Ok(capabilities::Capability::CAP_SYS_NICE),
        "CAP_SYS_RESOURCE" => Ok(capabilities::Capability::CAP_SYS_RESOURCE),
        "CAP_SYS_TIME" => Ok(capabilities::Capability::CAP_SYS_TIME),
        "CAP_SYS_TTY_CONFIG" => Ok(capabilities::Capability::CAP_SYS_TTY_CONFIG),
        "CAP_MKNOD" => Ok(capabilities::Capability::CAP_MKNOD),
        "CAP_LEASE" => Ok(capabilities::Capability::CAP_LEASE),
        "CAP_AUDIT_WRITE" => Ok(capabilities::Capability::CAP_AUDIT_WRITE),
        "CAP_AUDIT_CONTROL" => Ok(capabilities::Capability::CAP_AUDIT_CONTROL),
        "CAP_SETFCAP" => Ok(capabilities::Capability::CAP_SETFCAP),
        "CAP_MAC_OVERRIDE" => Ok(capabilities::Capability::CAP_MAC_OVERRIDE),
        "CAP_MAC_ADMIN" => Ok(capabilities::Capability::CAP_MAC_ADMIN),
        "CAP_SYSLOG" => Ok(capabilities::Capability::CAP_SYSLOG),
        "CAP_WAKE_ALARM" => Ok(capabilities::Capability::CAP_WAKE_ALARM),
        "CAP_BLOCK_SUSPEND" => Ok(capabilities::Capability::CAP_BLOCK_SUSPEND),
        "CAP_AUDIT_READ" => Ok(capabilities::Capability::CAP_AUDIT_READ),
        _ => Err(error::Error::InvalidCapability {
            capability: cap_name.into(),
        }),
    }
}

impl LinuxProcess {
    pub fn new(name: String, config: config::Config, command: Vec<String>) -> LinuxProcess {
        LinuxProcess {
            name,
            config,
            command,
            pid: None,
            rootless_euid: getegid() != Gid::from_raw(0),
            cgroup: None,
            status: ProcessStatus::Ready,
        }
    }

    pub fn pid(&self) -> Option<Pid> {
        self.pid
    }

    pub fn start(&mut self) -> Result<()> {
        self.setup_ns()?;

        // setup cgroups in parent, so we can collect information from cgroup statistics.
        self.cgroup = self.setup_cgroups()?;

        unsafe {
            match fork()? {
                ForkResult::Parent { child, .. } => {
                    self.pid = Some(child);
                    self.status = ProcessStatus::Running;
                    Ok(())
                }
                ForkResult::Child => self.child(),
            }
        }
    }

    fn child(&self) -> Result<()> {
        let path = CString::new(self.command[0].as_str()).expect("CString::new failed");
        let cstr_args: Vec<CString> = self
            .command
            .iter()
            .map(|args| CString::new(args.as_str()).unwrap())
            .collect();
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(key);
        }
        for env in self.config.process.env.iter() {
            let env_str = env.to_string();
            let mut splitter = env_str.splitn(2, "=");
            std::env::set_var(splitter.next().unwrap(), splitter.next().unwrap());
        }

        // unshare process group, so we can kill all processes forked from current at once.
        setsid()?;
        // we need root privilege (in host or in user namespace)
        setuid(Uid::from_raw(0))?;
        setgid(Gid::from_raw(0))?;

        self.setup_rootfs()?;

        if config_linux::has_namespace(&self.config, namespace::Namespace::Mount) {
            self.finalize_rootfs()?;
        }

        self.setup_hostname()?;
        self.setup_readonly_paths()?;
        self.setup_mask_paths()?;
        self.setup_no_new_privileges()?;

        // Without no new privileges, seccomp is a privileged operation,
        // so we need to do this before dropping capabilities.
        if !self.config.process.no_new_privileges {
            self.setup_seccomp()?;
        }

        self.finalize_namespace()?;

        // We must postpone cgroup setup as close to execvp as possible, so cpu time
        // will be more accurate.
        // enters cgroup in child, to make sure the operation is done before execvp.
        self.enter_cgroups()?;

        // With no new privileges, we must postpone seccomp as close to
        // execvp as possible, so as few syscalls take place afterward.
        // And user can reduce allowed syscalls as they need.
        if self.config.process.no_new_privileges {
            self.setup_seccomp()?;
        }

        execvp(&path, &cstr_args)?;
        Ok(())
    }

    pub fn kill(&self, signal: Signal) -> Result<()> {
        if self.status != ProcessStatus::Running || self.pid.is_none() {
            return Ok(());
        }

        match &self.cgroup {
            Some(cgroup) => {
                let mut result = Ok(());
                // if cgroups is enabled, find all processes to kill by cgroup.procs.
                for task in cgroup.tasks().iter() {
                    // try to kill all processes, instead of reporting error immediately.
                    if let Err(err) =
                        kill(nix::unistd::Pid::from_raw(task.pid as libc::pid_t), signal)
                    {
                        result = Err(error::Error::Kill {
                            pid: task.pid as libc::pid_t,
                            error: err,
                        })
                    }
                }
                return result;
            }
            None => {
                // if cgroups is not initialized, fallback to kill process cgroup.
                kill(self.pid.unwrap(), signal)?;
            }
        }

        Ok(())
    }

    pub fn wait(&mut self) -> Result<ProcessStatus> {
        match &self.status {
            ProcessStatus::Exited(_) | ProcessStatus::Signaled(_) => {
                return Ok(self.status);
            }
            _ => {}
        }

        loop {
            match waitpid(self.pid.unwrap(), None)? {
                WaitStatus::PtraceEvent(..) => {}
                WaitStatus::PtraceSyscall(..) => {}
                WaitStatus::Exited(x, exitcode) => {
                    assert_eq!(x, self.pid.unwrap());

                    self.status = ProcessStatus::Exited(exitcode as u8);
                    return Ok(self.status);
                }
                WaitStatus::Signaled(x, signal, _) => {
                    assert_eq!(x, self.pid.unwrap());
                    self.status = ProcessStatus::Signaled(signal);
                    return Ok(self.status);
                }
                WaitStatus::Stopped(_, _) => unreachable!(),
                WaitStatus::Continued(_) => unreachable!(),
                WaitStatus::StillAlive => unreachable!(),
            }
        }
    }

    fn prepare_root(&self) -> Result<()> {
        if !self.config.root.path.is_dir() {
            return Err(error::Error::RootfsNotDirectory {
                path: self.config.root.path.clone(),
            });
        }

        let flag = if self.config.root_propagation != 0 {
            MsFlags::from_bits(self.config.root_propagation).ok_or(
                error::Error::InvalidRootfsPropagation(self.config.root_propagation),
            )?
        } else {
            MsFlags::MS_SLAVE | MsFlags::MS_REC
        };

        mount::<str, str, str, str>(None, "/", None, flag, None)?;

        // make parent mount private to make sure following bind mount does not
        // propagate in other mount namespaces.
        // And also this helps pivot_root.
        {
            let myself = procfs::process::Process::myself()?;
            let absolute_rootfs = self.config.root.path.canonicalize()?;
            let parent_mount = myself
                .mountinfo()?
                .into_iter()
                .filter(|m| absolute_rootfs.starts_with(&m.mount_point))
                .max_by(|a, b| {
                    a.mount_point
                        .as_os_str()
                        .len()
                        .cmp(&b.mount_point.as_os_str().len())
                })
                .ok_or(error::Error::NoParentMount {
                    path: self.config.root.path.clone(),
                })?;
            let shared_mount = parent_mount.opt_fields.iter().any(|f| match f {
                procfs::process::MountOptFields::Shared(_) => true,
                _ => false,
            });
            if shared_mount {
                // make parent mount private if it was shared. It is needed because
                // firstly pivot_root will fail if parent mount is shared, secondly
                // when we bind mount rootfs it will propagate to parent namespace
                // unexpectedly.
                mount::<str, PathBuf, str, str>(
                    None,
                    &parent_mount.mount_point,
                    None,
                    MsFlags::MS_PRIVATE,
                    None,
                )?;
            }
        }

        mount::<PathBuf, PathBuf, str, str>(
            Some(&self.config.root.path),
            &self.config.root.path,
            Some("bind"),
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None,
        )?;

        Ok(())
    }

    /// Check whether if we should manually setup /dev.
    ///
    /// If user does not bind host /dev to container /dev, we must setup /dev and all devices in /dev.
    fn needs_setup_dev(&self) -> Result<bool> {
        for mount in self.config.mounts.iter() {
            let real_mount = mount::Mount::parse_config(&mount, &self.config.root.path)?;
            if real_mount.device == "bind" && real_mount.destination == PathBuf::from("/dev") {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn bind_device(&self, device: &config::Device, dest: &Path) -> Result<()> {
        if !dest.exists() {
            std::fs::File::create(dest)?;
        }

        nix::mount::mount::<PathBuf, Path, str, str>(
            Some(&device.path),
            dest,
            Some("bind"),
            nix::mount::MsFlags::MS_BIND,
            None,
        )?;

        Ok(())
    }

    fn mknod_device(&self, device: &config::Device, dest: &Path) -> Result<()> {
        let file_mode = match device.kind.as_str() {
            "b" => nix::sys::stat::SFlag::S_IFBLK, // block device
            "c" => nix::sys::stat::SFlag::S_IFCHR, // character device
            "p" => nix::sys::stat::SFlag::S_IFIFO, // fifo
            _ => {
                return Err(error::Error::InvalidDeviceType {
                    kind: device.kind.clone(),
                    path: dest.to_path_buf(),
                })
            }
        };

        nix::sys::stat::mknod(
            dest,
            file_mode,
            match nix::sys::stat::Mode::from_bits(device.file_mode) {
                Some(mode) => mode,
                None => {
                    return Err(error::Error::InvalidDeviceMode {
                        path: dest.to_path_buf(),
                        mode: device.file_mode,
                    })
                }
            },
            nix::sys::stat::makedev(device.major, device.minor),
        )?;
        chown(
            dest,
            Some(Uid::from_raw(device.uid)),
            Some(Gid::from_raw(device.gid)),
        )?;

        Ok(())
    }

    fn create_device(&self, device: &config::Device, bind: bool) -> Result<()> {
        let dest = join::secure_join(&self.config.root.path, &device.path)?;
        match dest.parent() {
            Some(parent) => std::fs::create_dir_all(parent)?,
            None => return Err(error::Error::InvalidDevicePath { path: dest }),
        }

        if bind {
            self.bind_device(device, &dest)?;
        } else {
            self.mknod_device(device, &dest)?;
        }

        Ok(())
    }

    fn default_devices(&self) -> Vec<config::Device> {
        return vec![
            config::Device {
                kind: "c".into(),
                path: "/dev/null".into(),
                major: 1,
                minor: 3,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
            config::Device {
                kind: "c".into(),
                path: "/dev/random".into(),
                major: 1,
                minor: 8,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
            config::Device {
                kind: "c".into(),
                path: "/dev/full".into(),
                major: 1,
                minor: 7,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
            config::Device {
                kind: "c".into(),
                path: "/dev/tty".into(),
                major: 5,
                minor: 0,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
            config::Device {
                kind: "c".into(),
                path: "/dev/zero".into(),
                major: 1,
                minor: 5,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
            config::Device {
                kind: "c".into(),
                path: "/dev/urandom".into(),
                major: 1,
                minor: 9,
                file_mode: 0666,
                uid: 0,
                gid: 0,
            },
        ];
    }

    fn create_devices(&self) -> Result<()> {
        let bind = system::is_running_in_user_namespace()
            || config_linux::has_namespace(&self.config, namespace::Namespace::User);

        let mask = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        defer! { nix::sys::stat::umask(mask); }

        let mut created = std::collections::HashSet::new();

        for device in self
            .config
            .linux
            .devices
            .iter()
            .chain(self.default_devices().iter())
        {
            if device.path == PathBuf::from("/dev/ptmx") {
                // Setup /dev/ptmx by setup_dev_ptmx
                continue;
            }

            if created.contains(&device.path) {
                continue;
            }
            created.insert(device.path.clone());

            self.create_device(&device, bind)?;
        }

        Ok(())
    }

    fn setup_ptmx(&self) -> io::Result<()> {
        let dest = self.config.root.path.join("dev/ptmx");
        if dest.exists() {
            std::fs::remove_file(&dest)?;
        }
        std::os::unix::fs::symlink("pts/ptmx", &dest)?;

        Ok(())
    }

    fn setup_dev_symlinks(&self) -> Result<()> {
        let kcore: PathBuf = "/proc/kcore".into();
        if kcore.exists() {
            std::os::unix::fs::symlink(&kcore, self.config.root.path.join("dev/core")).map_err(
                |e| error::Error::DevSymlinksFailure {
                    src: kcore.into(),
                    destination: self.config.root.path.join("dev/core"),
                    error: e,
                },
            )?;
        }
        for link in [
            ("/proc/self/fd", "dev/fd"),
            ("/proc/self/fd/0", "dev/stdin"),
            ("/proc/self/fd/1", "dev/stdout"),
            ("/proc/self/fd/2", "dev/stderr"),
        ]
        .iter()
        {
            // TODO: maybe we should ignore failure of linking to a existing file.
            std::os::unix::fs::symlink(link.0, self.config.root.path.join(link.1)).map_err(
                |e| error::Error::DevSymlinksFailure {
                    src: link.0.into(),
                    destination: self.config.root.path.join(link.1),
                    error: e,
                },
            )?;
        }

        Ok(())
    }

    fn pivot_root(&self) -> Result<()> {
        let old_root_fd = nix::fcntl::open(
            "/",
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )?;
        defer! { close(old_root_fd); }
        let new_root_fd = nix::fcntl::open(
            &self.config.root.path,
            nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )?;
        defer! { close(new_root_fd); }

        fchdir(new_root_fd)?;

        // Change root mount in the mount namespace to our rootfs.
        // And mount old root mount to the same directory.
        pivot_root(".", ".")?;

        // We need to umount old root.
        fchdir(old_root_fd)?;

        // Make old root slave to make sure our umount will not propagate to the host.
        mount::<str, str, str, str>(None, ".", None, MsFlags::MS_SLAVE | MsFlags::MS_REC, None)?;

        // Unmount the old root mount mounted by pivot_root.
        umount2(".", MntFlags::MNT_DETACH)?;

        // Change to new root.
        chdir("/")?;

        Ok(())
    }

    fn chroot(&self) -> Result<()> {
        chroot(&self.config.root.path)?;
        chdir("/")?;
        Ok(())
    }

    fn setup_rootfs(&self) -> Result<()> {
        self.prepare_root()?;

        let in_cgroup_namespace =
            config_linux::has_namespace(&self.config, namespace::Namespace::Cgroup);

        // report error as early as possible.
        let setup_dev = self.needs_setup_dev()?;

        for config_mount in self.config.mounts.iter() {
            let real_mount =
                super::mount::Mount::parse_config(&config_mount, &self.config.root.path)?;
            real_mount.mount(&self.config.mount_label, in_cgroup_namespace)?;
        }

        if setup_dev {
            self.create_devices()?;
            self.setup_ptmx()
                .map_err(|e| error::Error::DevPtmxFailure { error: e })?;
            self.setup_dev_symlinks()?;
        }

        if config_linux::has_namespace(&self.config, namespace::Namespace::Mount) {
            self.pivot_root()?;
        } else {
            self.chroot()?;
        }

        Ok(())
    }

    fn finalize_rootfs(&self) -> Result<()> {
        if self.config.root.readonly {
            mount::<str, str, str, str>(
                None,
                "/",
                None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None,
            )?;
        }

        match self.config.process.user.umask {
            Some(umask) => {
                nix::sys::stat::umask(match nix::sys::stat::Mode::from_bits(umask) {
                    Some(mode) => mode,
                    None => return Err(error::Error::InvalidUmask(umask)),
                });
            }
            None => {
                nix::sys::stat::umask(
                    nix::sys::stat::Mode::S_IWGRP | nix::sys::stat::Mode::S_IWOTH,
                );
            }
        }

        Ok(())
    }

    fn enter_namespace(&self, ns: namespace::Namespace, path: Option<&String>) -> nix::Result<()> {
        let nstype = ns.to_clone_flag();
        match path {
            None => nix::sched::unshare(nstype),
            Some(path) => {
                let fd = nix::fcntl::open(
                    path.as_str(),
                    nix::fcntl::OFlag::O_RDONLY,
                    nix::sys::stat::Mode::empty(),
                )?;
                nix::sched::setns(fd, nstype)
            }
        }
    }

    fn update_map(&self, path: impl AsRef<Path>, map: &[config::IDMap]) -> io::Result<()> {
        let maplines: Vec<String> = map
            .iter()
            .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
            .collect();
        std::fs::write(path.as_ref(), maplines.join("\n"))
    }

    fn setup_user_ns(&self) -> Result<()> {
        for namespace in self.config.linux.namespaces.iter() {
            let ns = match Namespace::try_from(namespace.kind.as_str()) {
                Ok(ns) => ns,
                Err(_) => return Err(error::Error::InvalidNamespace(namespace.kind.clone())),
            };
            if ns == namespace::Namespace::User {
                // we first unshare user namespace, so we may have root permission to do privileged operations.
                if let Err(err) = self.enter_namespace(ns, namespace.path.as_ref()) {
                    return Err(error::Error::UnshareNamespace {
                        namespace: ns,
                        error: err,
                    });
                }

                if namespace.path.is_none() {
                    // we only update uid/gid mappings when we are not joining an existing user namespace.
                    if let Err(err) =
                        self.update_map("/proc/self/uid_map", &self.config.linux.uid_mappings)
                    {
                        return Err(error::Error::UpdateUidMapping(err));
                    }

                    if !self.config.linux.gid_mappings.is_empty() {
                        // since Linux 3.19, unprivilegd writing of /proc/self/gid_map has been disabled
                        // uinless /proc/self/setgroups is written first to permanently disable the
                        // ability to call set groups in that user namespace.
                        let setgroups: PathBuf = "/proc/self/setgroups".into();
                        if setgroups.exists() {
                            if let Err(err) = std::fs::write(&setgroups, "deny") {
                                return Err(error::Error::DenySetgroups(err));
                            }
                        }
                        if let Err(err) =
                            self.update_map("/proc/self/gid_map", &self.config.linux.gid_mappings)
                        {
                            return Err(error::Error::UpdateGidMapping(err));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Enter namespaces specified in configuration.
    ///
    /// Please note that unshare and setns are called in parent process, not child process.
    /// Because PID namespace only takes effect on child processes, not the calling process.
    fn setup_ns(&self) -> Result<()> {
        self.setup_user_ns()?;
        for namespace in self.config.linux.namespaces.iter() {
            let ns = match Namespace::try_from(namespace.kind.as_str()) {
                Ok(ns) => ns,
                Err(_) => return Err(error::Error::InvalidNamespace(namespace.kind.clone())),
            };
            if ns == namespace::Namespace::User {
                // we have already unshared user namespace in setup_user_ns.
                continue;
            }
            if let Err(err) = self.enter_namespace(ns, namespace.path.as_ref()) {
                return Err(error::Error::UnshareNamespace {
                    namespace: ns,
                    error: err,
                });
            }
        }

        Ok(())
    }

    /// Create cgroups specified in configuration.
    fn setup_cgroups(&self) -> Result<Option<cgroups_rs::Cgroup>> {
        if let Some(config_resources) = &self.config.linux.resources {
            let hier = cgroups_rs::hierarchies::auto();

            let relative_paths: std::collections::HashMap<String, String> =
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

            let cgroup =
                cgroups_rs::Cgroup::new_with_relative_paths(hier, &self.name, relative_paths);
            let mut resources = cgroups_rs::Resources::default();

            if let Some(memory) = &config_resources.memory {
                resources.memory.memory_soft_limit = memory.reservation;
                resources.memory.memory_hard_limit = memory.limit;
                resources.memory.memory_swap_limit = memory.swap;
                resources.memory.kernel_memory_limit = memory.kernel;
                resources.memory.kernel_tcp_memory_limit = memory.kernel_tcp;
                resources.memory.swappiness = memory.swappiness;
                if let Some(controller) =
                    cgroup.controller_of::<cgroups_rs::memory::MemController>()
                {
                    controller.apply(&resources)?;
                }
            }
            if let Some(cpu) = &config_resources.cpu {
                resources.cpu.shares = cpu.shares;
                resources.cpu.quota = cpu.quota;
                resources.cpu.period = cpu.period;
                resources.cpu.realtime_runtime = cpu.realtime_runtime;
                resources.cpu.realtime_period = cpu.realtime_period;
                resources.cpu.cpus = cpu.cpus.clone();
                resources.cpu.mems = cpu.mems.clone();
                if let Some(controller) = cgroup.controller_of::<cgroups_rs::cpu::CpuController>() {
                    controller.apply(&resources)?;
                }
            }
            if let Some(pids) = &config_resources.pids {
                resources.pid.maximum_number_of_processes =
                    pids.limit.map(|limit| cgroups_rs::MaxValue::Value(limit));
                if let Some(controller) = cgroup.controller_of::<cgroups_rs::pid::PidController>() {
                    controller.apply(&resources)?;
                }
            }
            if !config_resources.devices.is_empty() {
                resources.devices.devices = config_resources
                    .devices
                    .iter()
                    .map(|d| cgroups_rs::DeviceResource {
                        allow: d.allow,
                        devtype: match &d.kind {
                            config::DeviceType::All => cgroups_rs::devices::DeviceType::All,
                            config::DeviceType::Char => cgroups_rs::devices::DeviceType::Char,
                            config::DeviceType::Block => cgroups_rs::devices::DeviceType::Block,
                        },
                        major: d.major.unwrap_or(0),
                        minor: d.minor.unwrap_or(0),
                        access: match &d.access {
                            Some(access) => access
                                .chars()
                                .filter_map(|a| match a {
                                    'r' => Some(cgroups_rs::devices::DevicePermissions::Read),
                                    'w' => Some(cgroups_rs::devices::DevicePermissions::Write),
                                    'm' => Some(cgroups_rs::devices::DevicePermissions::MkNod),
                                    _ => None,
                                })
                                .collect(),
                            None => vec![],
                        },
                    })
                    .collect();
                if let Some(controller) =
                    cgroup.controller_of::<cgroups_rs::devices::DevicesController>()
                {
                    controller.apply(&resources)?;
                }
            }
            Ok(Some(cgroup))
        } else {
            Ok(None)
        }
    }

    fn enter_cgroups(&self) -> Result<()> {
        let pid = (nix::unistd::gettid().as_raw() as u64).into();
        if let Some(cgroup) = &self.cgroup {
            if let Some(config_resources) = &self.config.linux.resources {
                if let Some(_) = &config_resources.memory {
                    if let Some(controller) =
                        cgroup.controller_of::<cgroups_rs::memory::MemController>()
                    {
                        controller.add_task(&pid)?;
                    }
                }
                if let Some(_) = &config_resources.cpu {
                    if let Some(controller) =
                        cgroup.controller_of::<cgroups_rs::cpu::CpuController>()
                    {
                        controller.add_task(&pid)?;
                    }
                }
                if let Some(_) = &config_resources.pids {
                    if let Some(controller) =
                        cgroup.controller_of::<cgroups_rs::pid::PidController>()
                    {
                        controller.add_task(&pid)?;
                    }
                }
                if !config_resources.devices.is_empty() {
                    if let Some(controller) =
                        cgroup.controller_of::<cgroups_rs::devices::DevicesController>()
                    {
                        controller.add_task(&pid)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn setup_hostname(&self) -> Result<()> {
        sethostname(self.config.hostname.as_str())?;
        Ok(())
    }

    fn setup_readonly_paths(&self) -> Result<()> {
        for path in self.config.linux.readonly_paths.iter() {
            mount::<PathBuf, PathBuf, str, str>(
                Some(&path),
                &path,
                None,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None,
            )?;

            mount::<PathBuf, PathBuf, str, str>(
                Some(&path),
                &path,
                None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                None,
            )?;
        }

        Ok(())
    }

    fn setup_mask_paths(&self) -> Result<()> {
        for path in self.config.linux.masked_paths.iter() {
            match mount::<str, PathBuf, str, str>(
                Some("/dev/null"),
                &path,
                None,
                MsFlags::MS_BIND,
                None,
            ) {
                Err(nix::Error::Sys(nix::errno::Errno::ENOTDIR)) => {
                    nix::mount::mount(
                        Some("tmpfs"),
                        path,
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY,
                        Some(format_mount_label("", self.config.mount_label.as_str()).as_str()),
                    )?;
                }
                Err(err) => {
                    return Err(err.into());
                }
                _ => {}
            }

            mount::<PathBuf, PathBuf, str, str>(
                Some(&path),
                &path,
                None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                None,
            )?;
        }

        Ok(())
    }

    fn setup_no_new_privileges(&self) -> Result<()> {
        prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)?;
        Ok(())
    }

    fn convert_seccomp_action(&self, action: &str, errno: i64) -> Result<seccomp::Action> {
        match action {
            "SCMP_ACT_KILL" => Ok(seccomp::Action::Kill),
            "SCMP_ACT_KILL_PROCESS" => Ok(seccomp::Action::KillProcess),
            "SCMP_ACT_TRAP" => Ok(seccomp::Action::Trap),
            "SCMP_ACT_ERRNO" => Ok(seccomp::Action::Errno(errno as i32)),
            "SCMP_ACT_TRACE" => Ok(seccomp::Action::Trace(errno as u32)),
            "SCMP_ACT_ALLOW" => Ok(seccomp::Action::Allow),
            _ => Err(error::Error::InvalidSeccompAction {
                action: action.to_string(),
            }),
        }
    }

    fn convert_seccomp_op(&self, op: &str) -> Result<seccomp::Op> {
        match op {
            "SCMP_CMP_NE" => Ok(seccomp::Op::Ne),
            "SCMP_CMP_LT" => Ok(seccomp::Op::Lt),
            "SCMP_CMP_LE" => Ok(seccomp::Op::Le),
            "SCMP_CMP_EQ" => Ok(seccomp::Op::Eq),
            "SCMP_CMP_GE" => Ok(seccomp::Op::Ge),
            "SCMP_CMP_GT" => Ok(seccomp::Op::Gt),
            "SCMP_CMP_MASKED_EQ" => Ok(seccomp::Op::MaskedEq),
            _ => Err(error::Error::InvalidSeccompOp { op: op.to_string() }),
        }
    }

    fn setup_seccomp(&self) -> Result<()> {
        if let Some(s) = &self.config.linux.seccomp {
            let mut context = seccomp::Context::default(
                self.convert_seccomp_action(&s.default_action, libc::EPERM as i64)?,
            )?;

            for syscall in s.syscalls.iter() {
                match syscall.nr {
                    Some(nr) => {
                        let mut rule = seccomp::Rule::new(
                            nr,
                            None,
                            self.convert_seccomp_action(&syscall.action, syscall.errno_ret)?,
                        );
                        for arg in syscall.args.iter() {
                            let mut compare = seccomp::Compare::arg(arg.index)
                                .with(arg.value)
                                .using(self.convert_seccomp_op(&arg.op)?);
                            if let Some(value2) = arg.value_two {
                                compare = compare.and(value2);
                            }
                            match compare.build() {
                                Some(cmp) => rule.add_comparison(cmp),
                                None => {
                                    return Err(error::Error::InvalidSeccompArg {
                                        index: arg.index,
                                        value: arg.value,
                                        value_two: arg.value_two,
                                        op: arg.op.clone(),
                                    })
                                }
                            };
                        }
                        context.add_rule(rule)?;
                    }
                    None => return Err(error::Error::InvalidSeccompNr),
                };
            }

            context.load()?;
        }

        Ok(())
    }

    fn convert_capabilities(capabilities: &Vec<String>) -> Result<Vec<capabilities::Capability>> {
        let mut result = Vec::new();
        for cap in capabilities {
            result.push(map_capability(cap)?);
        }
        return Ok(result);
    }

    fn setup_capabilities(&self) -> Result<()> {
        use capabilities::*;
        let mut cap = Capabilities::new()?;

        if let Some(allowed_capabilities) = &self.config.process.capabilities {
            let effective: Vec<Capability> =
                LinuxProcess::convert_capabilities(&allowed_capabilities.effective)?;
            cap.update(&effective, Flag::Effective, true);

            let permitted: Vec<Capability> =
                LinuxProcess::convert_capabilities(&allowed_capabilities.permitted)?;
            cap.update(&permitted, Flag::Permitted, true);

            let inheritable: Vec<Capability> =
                LinuxProcess::convert_capabilities(&allowed_capabilities.inheritable)?;
            cap.update(&inheritable, Flag::Inheritable, true);

            if let Err(err) = cap.apply() {
                return Err(error::Error::CapabilityError(err));
            }
        }

        Ok(())
    }

    fn finalize_namespace(&self) -> Result<()> {
        // Close all fds other than stdin, stdout, stderr.
        close_on_exec_from(3)?;

        self.setup_capabilities()?;

        // preserve existing capabilities while we change users.
        // prctl::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0)?;

        self.setup_user()?;

        if let Some(cwd) = &self.config.process.cwd {
            if !cwd.is_dir() {
                return Err(error::Error::CwdNotDirectory {
                    path: cwd.to_path_buf(),
                });
            }
            chdir(cwd)?;
        }

        prctl::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0)?;

        Ok(())
    }

    fn setup_user(&self) -> Result<()> {
        let id = &self.config.process.user;
        let user = User::find_user(Uid::from_raw(id.uid), Gid::from_raw(id.gid))?;
        get_host_uid(&self.config, user.uid)?;
        get_host_gid(&self.config, user.gid)?;

        fix_stdio_permissions(&user)?;

        let allow_sgroups = !self.rootless_euid
            && std::fs::read_to_string("/proc/self/setgroups")?.trim() != "deny";
        if allow_sgroups {
            // TODO: read additional groups.
            let supp_groups = &user.sgids;
            setgroups(&supp_groups)?;
        }

        setuid(user.uid)?;
        setgid(user.gid)?;

        if let Err(std::env::VarError::NotPresent) = std::env::var("HOME") {
            // if we didn't get HOME already, set it based on the user's HOME.
            std::env::set_var("HOME", user.home);
        }

        Ok(())
    }
}

impl Drop for LinuxProcess {
    fn drop(&mut self) {
        if let Some(cgroup) = &self.cgroup {
            cgroup.delete();
        }
    }
}
