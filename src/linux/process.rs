use super::config_linux::{get_host_gid, get_host_uid, LinuxProcessError};
use super::namespace::Namespace;
use super::user::User;
use super::LinuxProcess;
use crate::config;
use crate::process::ProcessStatus;
use nix::mount::*;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use std::io;
use std::os::unix::io::AsRawFd;
use crate::linux::prctl::prctl;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + 'static>>;

fn format_mount_label(src: &str, mount_label: &str) -> String {
    if !mount_label.is_empty() {
        if src.is_empty() {
            format!("context={}", mount_label)
        } else {
            format!("{},context={}", src, mount_label)
        }
    } else {
        src
    }
}

fn close_fd_from(start_fd: i32) -> Result<()> {
    for dir in std::fs::read_dir("/proc/self/fd")? {
        let ok_dir = dir?;
        let file_name = ok_dir.file_name().into_string()?;
        if let Ok(fd) = file_name.parse::<i32>() {
            if fd < start_fd {
                continue;
            }

            // Ignores errors from fcntl because some fds may be already closed.
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC));
        }
    }

    Ok(())
}

fn mount_to_rootfs(mount: &config::Mount, rootfs: &str, mount_label: &str, enable_cgroups: bool) -> Result<()> {
    let mut dest = mount.destination.clone();
    if !dest.starts_with(rootfs) {
        dest = format!("{}/{}", rootfs, dest);
    }

    match mount.kind.as_str() {
        "proc" | "sysfs" => {
            if std::fs::
        }
        _ => {

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
    ].iter() {
        let s = nix::sys::stat::fstat(fd)?;
        if s.st_rdev == null.st_rdev {
            continue;
        }

        match nix::unistd::fchown(fd, Some(user.uid), Some(user.gid)) {
            Err(nix::Error::Sys(nix::errno::Errno::EINVAL)) |
            Err(nix::Error::Sys(nix::errno::Errno::EPERM)) => {}
            Err(err) => return Err(err),
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
        match fork()? {
            ForkResult::Parent { child, .. } => {
                self.pid = Some(child);
                return Ok(());
            }
            ForkResult::Child => {
                let path = CString::new(self.command[0].as_str()).expect("CString::new failed");
                let cstr_args: Vec<CString> = self
                    .command
                    .iter()
                    .map(|args| CString::new(args.as_str()).unwrap())
                    .collect();
                for (key, _) in std::env::vars_os() {
                    std::env::remove_var(key);
                }
                for &env in self.config.process.env.iter() {
                    let env_str = env.to_string();
                    let mut splitter = env_str.splitn(2, "=");
                    std::env::set_var(splitter.next().unwrap(), splitter.next().unwrap());
                }

                self.setup_rootfs()?;

                if let Some(linux) = &self.config.linux {
                    if linux.namespaces.iter().any(|&n| n.kind == "mount") {
                        self.finalize_rootfs()?;
                    }
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
                    self.setup_seccomp();
                }

                execvp(&path, &cstr_args)?;
                Ok(())
            }
        }
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
                None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "root_propagation is not valid").into())
            }
        } else {
            MsFlags::MS_SLAVE | MsFlags::MS_REC
        };

        mount(None, "/", None, flag, None)?;

        Ok(())
    }

    fn needs_setup_dev(&self) -> bool {
        for mount in self.config.mounts {
            mount_to_rootfs(&mount, self.config.root.path, self.config.mount_label, );
        }

        true
    }

    fn setup_rootfs(&self) -> Result<()> {
        self.prepare_root()?;

        let has_cgroup_ns = self.config.linux.namespaces.iter().any(|&n| n.kind == "cgroup");


    }

    // 1.
    fn setup_ns(&self) -> Result<()> {
        for &namespace in self.config.linux.namespaces.iter() {
            let nstype = Namespace::from(namespace.kind.as_str()).to_clone_flag();
            match &namespace.path {
                None => {
                    nix::sched::unshare(nstype);
                }
                Some(path) => {
                    let fd = nix::fcntl::open(
                        path.as_str(),
                        nix::fcntl::OFlag::O_RDONLY,
                        nix::sys::stat::Mode::empty(),
                    )?;
                    nix::sched::setns(fd, nstype);
                }
            }
        }

        Ok(())
    }

    // 4.
    fn setup_mounts(&self) -> Result<()> {

    }

    // 5.
    fn setup_chroot(&self) -> Result<()> {
        nix::unistd::chroot(self.config.root.path.as_str())?;

        nix::unistd::chdir(self.config.process.cwd.as_str())?;

        Ok(())
    }

    fn setup_hostname(&self) -> Result<()> {
        nix::unistd::sethostname(self.config.hostname.as_str())?;
        Ok(())
    }

    fn setup_readonly_paths(&self) -> Result<()> {
        for &path in self.config.linux.readonly_paths.iter() {
            nix::mount::mount::<str, str, str, str>(
                Some(path.as_str()),
                path.as_str(),
                None,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None,
            )?;

            nix::mount::mount::<str, str, str, str>(
                Some(path.as_str()),
                path.as_str(),
                None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                None,
            )?;
        }

        Ok(())
    }

    fn setup_mask_paths(&self) -> Result<()> {
        for &path in self.config.linux.masked_paths.iter() {
            match nix::mount::mount::<str, str, str, str>(
                Some("/dev/null"),
                path.as_str(),
                None,
                MsFlags::MS_BIND,
                None,
            ) {
                Err(nix::Error::Sys(nix::errno::Errno::ENOTDIR)) => {
                    nix::mount::mount(
                        Some("tmpfs"),
                        path.as_str(),
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY,
                        Some(format_mount_label("", self.config.mount_label.as_str()).as_str()),
                    );
                }
                Err(err) => { return Err(err.into()); }
                _ => {}
            }

            nix::mount::mount::<str, str, str, str>(
                Some(path.as_str()),
                path.as_str(),
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
        close_fd_from(3)?;

        // TODO: set capabilities

        setup_user()?;

        if self.config.process.cwd != "" {
            nix::unistd::chdir(&self.config.process.cwd)?;
        }

        Ok(())
    }

    fn setup_user(&self) -> Result<()> {
        let id = &self.config.process.user;
        let user = User::find_user(id.uid, id.gid)?;
        get_host_uid(&self.config, user.uid)?;
        get_host_gid(&self.config, user.gid)?;

        fix_stdio_permissions(&self.config, &user)?;

        let allow_sgroups = !self.config.rootless_euid && std::fs::read_to_string("/proc/self/setgroups")?.trim() != deny;
        if allow_sgroups {
            // TODO: read additional groups.
            let supp_groups = &user.sgids;

            nix::unistd::setgroups(supp_groups.iter().map(|&g| nix::unistd::Gid::from_raw(g)).collect());
        }

        nix::unistd::setuid(nix::unistd::Uid::from_raw(user.uid))?;
        nix::unistd::setgid(nix::unistd::Gid::from_raw(user.gid))?;

        std::env::set_var("HOME", user.home);

        Ok(())
    }

}
