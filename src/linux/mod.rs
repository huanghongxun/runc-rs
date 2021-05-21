mod cgroup;
mod config_linux;
mod error;
mod join;
mod mount;
mod namespace;
mod prctl;
mod process;
mod seccomp;
mod selinux;
mod systemd;
#[macro_use]
mod system;
mod user;

use crate::config;
use crate::process::ProcessStatus;
use error::Result;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::io::Write;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct LinuxProcess {
    // name of container, used in cgroup creation.
    name: String,
    config: config::Config,
    command: Vec<String>,
    mapped_fds: Vec<(i32, i32)>,
    preserved_fds: Vec<i32>,

    pid: Option<Pid>,

    rootless_euid: bool,

    cgroup: Option<cgroups_rs::Cgroup>,

    status: ProcessStatus,
}

pub fn run(
    config: &config::Config,
    commands: Vec<&str>,
    out_meta: Option<String>,
    mapped_fds: Vec<(i32, i32)>,
    preserved_fds: Vec<i32>,
) -> Result<()> {
    run_impl(config, commands, out_meta, mapped_fds, preserved_fds)?;
    Ok(())
}

fn run_impl(
    config: &config::Config,
    commands: Vec<&str>,
    out_meta: Option<String>,
    mapped_fds: Vec<(i32, i32)>,
    preserved_fds: Vec<i32>,
) -> Result<()> {
    let mut process = LinuxProcess::new(
        format!(
            "runc/{}_{}",
            nix::unistd::getpid(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ),
        config.clone(),
        commands.iter().map(|s| s.to_string()).collect(),
        mapped_fds,
        preserved_fds,
    );
    process.start()?;

    let start_time = SystemTime::now();
    let process_status = process.wait()?;
    let end_time = SystemTime::now();

    // clean all processes.
    process.kill(nix::sys::signal::Signal::SIGKILL)?;

    let exitcode: i32;
    let signal: Option<Signal>;
    match process_status {
        ProcessStatus::Exited(exitcode_) => {
            exitcode = exitcode_ as i32;
            signal = None
        }
        ProcessStatus::Signaled(signal_) => {
            exitcode = signal_ as i32 + 128;
            signal = Some(signal_)
        }
        _ => {
            unreachable!()
        }
    }

    if let Some(out_meta_f) = &out_meta {
        let f = std::fs::File::create(&out_meta_f);
        if f.is_err() {
            return Err(error::Error::WriteOutMeta {
                path: out_meta_f.into(),
                error: f.unwrap_err(),
            });
        }
        collect_status(
            &mut f.unwrap(),
            config,
            &process,
            exitcode,
            signal,
            end_time.duration_since(start_time).unwrap(),
        );
    }

    Ok(())
}

fn collect_status(
    out_meta: &mut std::fs::File,
    config: &config::Config,
    process: &LinuxProcess,
    exitcode: i32,
    signal: Option<Signal>,
    wall_time: Duration,
) {
    let mut cpu_time = 0.0;
    let mut oom = false;
    let mut tle = false;
    if let Some(cgroup) = &process.cgroup {
        if let Some(mem) = cgroup.controller_of::<cgroups_rs::memory::MemController>() {
            let memstat = mem.memory_stat();
            writeln!(out_meta, "memory-bytes: {}", memstat.max_usage_in_bytes);

            if memstat.oom_control.oom_kill > 0 {
                oom = true;
            }
        }
        if let Some(cpuacct) = cgroup.controller_of::<cgroups_rs::cpuacct::CpuAcctController>() {
            let acct = cpuacct.cpuacct();
            writeln!(out_meta, "user-time: {}", acct.usage_user as f64 / 1e9);
            writeln!(out_meta, "sys-time: {}", acct.usage_sys as f64 / 1e9);
            writeln!(out_meta, "cpu-time: {}", acct.usage as f64 / 1e9);

            cpu_time = acct.usage as f64 / 1e9;
            if let Some(limit) = config.limits.cpu_limit {
                if cpu_time > limit {
                    tle = true;
                }
            }
        }
    }

    writeln!(out_meta, "wall-time: {}", wall_time.as_secs_f64());
    writeln!(out_meta, "exit-code: {}", exitcode);

    if let Some(limit) = config.limits.wall_limit {
        if wall_time.as_secs_f64() > limit {
            tle = true;
        }
    } else if let Some(limit) = config.limits.cpu_limit {
        // wall_limit is assumed as triple of cpu_limit
        if wall_time.as_secs_f64() > 3.0 * limit {
            tle = true;
        }
    }

    if let Some(sig) = signal {
        writeln!(out_meta, "signal: {}", sig as libc::c_int);
    }

    if oom {
        writeln!(out_meta, "memory-result: oom");
    } else {
        writeln!(out_meta, "memory-result:");
    }

    if tle {
        writeln!(out_meta, "time-result: hard-timelimit");
    } else {
        writeln!(out_meta, "time-result:");
    }
}
