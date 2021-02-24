#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcessStatus {
    /// The process is ready to run
    Ready,

    /// The process is running
    Running,

    /// The process exited normally with the given exit code.
    Exited(u8),

    /// The process was killed by the given signal.
    Signaled(nix::sys::signal::Signal),
}
