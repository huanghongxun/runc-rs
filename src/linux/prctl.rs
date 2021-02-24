use libc::{self, c_ulong, c_int};

use nix::errno::Errno;
use nix::Result;

pub fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> Result<()> {
    let res = unsafe { libc::prctl(option as c_int, arg2, arg3, arg4, arg5) };

    Errno::result(res).map(drop)
}
