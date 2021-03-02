use super::config_linux::{get_host_gid, get_host_uid};
use super::error::{Error, Result};
use super::namespace::Namespace;
use super::user::User;
use super::*;
use crate::config;
use crate::linux::prctl::prctl;
use crate::process::ProcessStatus;
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
fn fix_stdio_permissions(config: &config::Config, user: &User) -> Result<()> {
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

impl LinuxProcess {
    pub fn new(config: config::Config, command: Vec<String>) -> LinuxProcess {
        LinuxProcess {
            config: config,
            command: command,
            pid: None,
            status: ProcessStatus::Ready,
        }
    }

    pub fn pid(&self) -> Option<Pid> {
        self.pid
    }

    pub fn start(&mut self) -> Result<()> {
        unsafe {
            match fork()? {
                ForkResult::Parent { child, .. } => {
                    self.pid = Some(child);
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

        self.setup_rootfs()?;

        if config_linux::has_namespace(&self.config, namespace::Namespace::Mount) {
            self.finalize_rootfs()?;
        }

        self.setup_hostname()?;
        self.setup_readonly_paths()?;
        self.setup_mask_paths()?;
        self.setup_no_new_privileges()?;

        if !self.config.process.no_new_privileges {
            self.setup_seccomp()?;
        }

        self.finalize_namespace()?;

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

        kill(self.pid.unwrap(), signal)?;

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
                    assert!(x == self.pid.unwrap());

                    self.status = ProcessStatus::Exited(exitcode as u8);
                    return Ok(self.status);
                }
                WaitStatus::Signaled(x, signal, _) => {
                    assert!(x == self.pid.unwrap());
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
        let flag = if self.config.root_propagation != 0 {
            match MsFlags::from_bits(self.config.root_propagation) {
                Some(bit) => bit,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "root_propagation is not valid",
                    )
                    .into())
                }
            }
        } else {
            MsFlags::MS_SLAVE | MsFlags::MS_REC
        };

        mount::<str, str, str, str>(None, "/", None, flag, None)?;

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
        let dest = self.config.root.path.join(&device.path);
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

    fn create_devices(&self) -> Result<()> {
        let bind = system::is_running_in_user_namespace()
            || config_linux::has_namespace(&self.config, namespace::Namespace::User);

        let mask = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        defer! { nix::sys::stat::umask(mask); }

        for device in self.config.linux.devices.iter() {
            if device.path == PathBuf::from("/dev/ptmx") {
                // Setup /dev/ptmx by setup_dev_ptmx
                continue;
            }

            self.create_device(&device, bind)?;
        }

        Ok(())
    }

    fn setup_ptmx(&self) -> Result<()> {
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
            std::os::unix::fs::symlink(kcore, self.config.root.path.join("dev/core"))?;
        }
        for link in [
            ("/proc/self/fd", "/dev/fd"),
            ("/proc/self/fd/0", "/dev/stdin"),
            ("/proc/self/fd/1", "/dev/stdout"),
            ("/proc/self/fd/2", "/dev/stderr"),
        ]
        .iter()
        {
            // TODO: maybe we should ignore failure of linking to a existing file.
            std::os::unix::fs::symlink(link.0, self.config.root.path.join(link.1))?;
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

    fn setup_chroot(&self) -> Result<()> {
        chroot(&self.config.root.path)?;
        match self.config.process.cwd {
            Some(ref cwd) => chdir(cwd)?,
            None => chdir("/")?,
        }
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
            self.setup_ptmx()?;
            self.setup_dev_symlinks()?;
        }

        std::env::set_current_dir(&self.config.root.path)?;

        if config_linux::has_namespace(&self.config, namespace::Namespace::Mount) {
            self.pivot_root()?;
        } else {
            self.chroot()?;
        }

        if let Some(cwd) = &self.config.process.cwd {
            std::fs::create_dir_all(cwd)?;
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

    // 1.
    fn setup_ns(&self) -> Result<()> {
        for namespace in self.config.linux.namespaces.iter() {
            let nstype = match Namespace::try_from(namespace.kind.as_str()) {
                Ok(ns) => ns,
                Err(_) => return Err(error::Error::InvalidNamespace(namespace.kind.clone())),
            }
            .to_clone_flag();
            match &namespace.path {
                None => {
                    nix::sched::unshare(nstype)?;
                }
                Some(path) => {
                    let fd = nix::fcntl::open(
                        path.as_str(),
                        nix::fcntl::OFlag::O_RDONLY,
                        nix::sys::stat::Mode::empty(),
                    )?;
                    nix::sched::setns(fd, nstype)?;
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

    fn setup_seccomp(&self) -> Result<()> {
        // TODO.

        Ok(())
    }

    fn finalize_namespace(&self) -> Result<()> {
        // Skip stdin, stdout, stderr.
        close_on_exec_from(3)?;

        // TODO: set capabilities

        self.setup_user()?;

        if let Some(ref cwd) = self.config.process.cwd {
            chdir(cwd)?;
        }

        Ok(())
    }

    fn setup_user(&self) -> Result<()> {
        let id = &self.config.process.user;
        let user = User::find_user(Uid::from_raw(id.uid), Gid::from_raw(id.gid))?;
        get_host_uid(&self.config, user.uid)?;
        get_host_gid(&self.config, user.gid)?;

        fix_stdio_permissions(&self.config, &user)?;

        let allow_sgroups = !self.config.rootless_euid
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
