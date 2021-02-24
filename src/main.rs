mod config;
mod linux;
mod process;

use clap::{App, Arg};

fn main() {
    let matches = App::new("runguard")
        .author("huangyuhui <i@huangyuhui.net>")
        .about(
            "runguard is a rootless command line client for running applications in container.

            runguard requires a Linux kernel > v4.18.0 and fuse-overlayfs to mount overlayfs in rootless container.

            To run a new container:

                $ runguard -f <config-toml>

            Where \"<config-toml>\" is a file to guide container configuration.
            ",
        )
        .arg(Arg::with_name("file").short("f").long("file").takes_value(true).help("a toml file that guides container configuration"))
        .arg(Arg::with_name("config").short("c").long("config").takes_value(true).help("pass toml configuration in command line"))
        .arg(Arg::with_name("commands").required(true).min_values(1))
        .get_matches();

    if matches.value_of("file").is_some() == matches.value_of("config").is_some() {
        eprintln!("Options --file and --config must not appear together.");
        std::process::exit(1)
    }

    let config_str = if let Some(file) = matches.value_of("file") {
        std::fs::read_to_string(file).expect("Failed to read configuration file")
    } else if let Some(raw_config) = matches.value_of("config") {
        String::from(raw_config)
    } else {
        unreachable!()
    };

    let config: config::Config =
        toml::from_str(config_str.as_str()).expect("Configuration unparsable");

    if cfg!(target_os = "linux") {
        linux::run(&config, matches.values_of("commands").unwrap().collect());
    } else {
        eprintln!("Unsupported operating system");
        std::process::exit(1);
    }
}
