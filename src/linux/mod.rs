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
    config: config::Config,
    command: Vec<String>,

    pid: Option<Pid>,

    status: ProcessStatus,
}

pub fn run(config: &config::Config, commands: Vec<&str>) -> ! {
    run_impl(config, commands).expect("Failed to run container");

    std::process::exit(0)
}

fn run_impl(config: &config::Config, commands: Vec<&str>) -> Result<()> {
    let mut process = LinuxProcess::new(
        config.clone(),
        commands.iter().map(|s| s.to_string()).collect(),
    );
    process.start()?;

    let start_time = SystemTime::now();
    let process_status = process.wait()?;
    let end_time = SystemTime::now();

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
        exitcode,
        signal,
        end_time.duration_since(start_time).unwrap(),
    );

    Ok(())
}

fn collect_status(
    config: &config::Config,
    exitcode: i32,
    signal: Option<Signal>,
    wall_time: Duration,
) {
    println!("Run {:?} {:?} {:?}", exitcode, signal, wall_time);
}
