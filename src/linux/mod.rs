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
    println!("Run {:?} {:?} {:?}", exitcode, signal, wall_time);
    if let Some(cgroup) = &process.cgroup {
        let mem: &cgroups_rs::memory::MemController = cgroup
            .controller_of()
            .expect("Memory controller is required");
        let memstat = mem.memory_stat();
        println!("Memory {}", memstat.max_usage_in_bytes);
    }
}
