use super::*;
use ::systemd::bus::*;
use std::path::PathBuf;

pub fn new_user_systemd_dbus() -> error::Result<Bus> {
    let bus = Bus::default_system()?;
    return Ok(bus);
}

pub fn start_unit(dbus: &Bus) {}

struct SystemdBus {
    bus: Bus,
    jobs: std::collections::HashMap<std::ffi::CString, Box<dyn FnOnce(String) -> ()>>,
}

static DESTINATION: &str = "org.freedesktop.systemd1";
static PATH: &str = "/org/freedesktop/systemd1";
static INTERFACE: &str = "org.freedesktop.systemd1.Manager";

impl SystemdBus {
    // fn start_transient_unit(&self, name: &str, mode: &str, properties: &[Property]) {}

    fn start_job(
        &mut self,
        message: &mut Message,
        usec: u64,
        f: Box<dyn FnOnce(String) -> ()>,
    ) -> error::Result<()> {
        unsafe {
            let mut reply = message.call(usec)?;

            let object_path_cstr = reply
                .iter()?
                .read_basic_raw(b'c', |raw: *const libc::c_char| {
                    std::ffi::CStr::from_ptr(raw)
                })?
                .unwrap();
            self.jobs
                .insert(std::ffi::CString::from(object_path_cstr), f);

            Ok(())
        }
    }

    fn new_method_call(&mut self, member: &str) -> std::io::Result<Message> {
        self.bus.new_method_call(
            BusName::from_bytes(DESTINATION.as_bytes()).expect("systemd BusName parse failure"),
            ObjectPath::from_bytes(PATH.as_bytes()).expect("systemd ObjectPath parse failure"),
            InterfaceName::from_bytes(INTERFACE.as_bytes())
                .expect("systemd InterfaceName parse failure"),
            MemberName::from_bytes(member.as_bytes()).expect("systemd MemberName parse failure"),
        )
    }
}

// fn detect_uid() -> Result<nix::unistd::Uid> {
//     if !system::is_running_in_user_namespace() {
//         return Ok(nix::unistd::getuid());
//     }
//
//     let bus_status = String::from_utf8(
//         std::process::Command::new("busctl")
//             .args(&["--user", "--no-pager", "status"])
//             .output()
//             .map_err(|e| error::Error::ProcessError {
//                 command: "busctl --user --no-pager status".into(),
//                 error: e,
//             })?
//             .stdout,
//     )
//     .map_err(|e| error::Error::ProcessOutputNotUtf8 {
//         command: "busctl --user --no-pager status".into(),
//         error: e,
//     })?;
//
//     for line in bus_status.lines() {
//         if line.starts_with("OwnerUID=") {
//             let owner_uid_str = line.trim_start_matches("OwnerUID=");
//             if let Ok(owner_uid) = owner_uid_str.parse::<u32>() {
//                 return Ok(nix::unistd::Uid::from_raw(owner_uid));
//             }
//         }
//     }
//
//     return Err(error::Error::DetectUID);
// }
//
// fn get_dbus_address() -> Result<String> {
//     if let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
//         return Ok(addr);
//     }
//
//     if let Ok(xdr) = std::env::var("XDG_RUNTIME_DIR") {
//         let path = PathBuf::from(xdr).join("bus");
//         if path.is_file() {
//             if let Some(strpath) = path.to_str() {
//                 return Ok(format!("unix:path={}", strpath));
//             }
//         }
//     }
//
//     let systemd_env = String::from_utf8(
//         std::process::Command::new("systemctl")
//             .args(&["--user", "--no-pager", "show-environment"])
//             .output()
//             .map_err(|e| error::Error::ProcessError {
//                 command: "systemctl --user --no-pager show-environment".into(),
//                 error: e,
//             })?
//             .stdout,
//     )
//     .map_err(|e| error::Error::ProcessOutputNotUtf8 {
//         command: "systemctl --user --no-pager show-environment".into(),
//         error: e,
//     })?;
//
//     for line in systemd_env.lines() {
//         if line.starts_with("DBUS_SESSION_BUS_ADDRESS=") {
//             return Ok(line.trim_start_matches("DBUS_SESSION_BUS_ADDRESS=").into());
//         }
//     }
//
//     return Err(error::Error::DbusAddressNotFound);
// }
