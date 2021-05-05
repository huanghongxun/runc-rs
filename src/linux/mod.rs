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
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct LinuxProcess {
    // name of container, used in cgroup creation.
    name: String,
    config: config::Config,
    command: Vec<String>,

    pid: Option<Pid>,

    rootless_euid: bool,

    cgroup: Option<cgroups_rs::Cgroup>,

    status: ProcessStatus,
}

pub fn run(config: &config::Config, commands: Vec<&str>) -> Result<()> {
    run_impl(config, commands)?;
    Ok(())
}

fn run_impl(config: &config::Config, commands: Vec<&str>) -> Result<()> {
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

    collect_status(
        config,
        &process,
        exitcode,
        signal,
        end_time.duration_since(start_time).unwrap(),
    );

    Ok(())
}

fn collect_status(
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
            println!("memory-bytes: {}", memstat.max_usage_in_bytes);

            if memstat.oom_control.oom_kill > 0 {
                oom = true;
            }
        }
        if let Some(cpuacct) = cgroup.controller_of::<cgroups_rs::cpuacct::CpuAcctController>() {
            let acct = cpuacct.cpuacct();
            println!("user-time: {}", acct.usage_user as f64 / 1e9);
            println!("sys-time: {}", acct.usage_sys as f64 / 1e9);
            println!("cpu-time: {}", acct.usage as f64 / 1e9);

            cpu_time = acct.usage as f64 / 1e9;
            if let Some(limit) = config.limits.cpu_limit {
                if cpu_time > limit {
                    tle = true;
                }
            }
        }
    }

    println!("wall-time: {}", wall_time.as_secs_f64());
    println!("exit-code: {}", exitcode);

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
        println!("signal: {}", sig as libc::c_int);
    }

    if oom {
        println!("memory-result: oom");
    } else {
        println!("memory-result:");
    }

    if tle {
        println!("time-result: hard-timelimit");
    } else {
        println!("time-result:");
    }
}
