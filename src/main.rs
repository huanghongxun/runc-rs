mod config;
mod linux;
mod process;

#[macro_use]
extern crate scan_fmt;
#[macro_use]
extern crate scopeguard;

use clap::{App, Arg};

fn parse_config(config_str: &str) -> config::Config {
    match toml::from_str(config_str) {
        Ok(x) => return x,
        Err(err1) => match serde_json::from_str(config_str) {
            Ok(x) => return x,
            Err(err2) => {
                panic!("Configuration unparsable\ntoml:{}\njson:{}", err1, err2);
            }
        },
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        .arg(Arg::with_name("out-meta").long("out-meta").takes_value(true).help("write runguard monitor results (run time, exitcode, memory usage, ...) to file"))
        .arg(Arg::with_name("map-fd").long("map-fd").multiple(true).takes_value(true).value_names(&["from", "to"]).validator(|p| match p.parse::<i32>() {
            Err(_) => Err(String::from("file descriptors are number")),
            Ok(_) => Ok(()),
        }).help("map specific file descriptor"))
        .arg(Arg::with_name("preserve-fd").long("preserve-fd").multiple(true).takes_value(true).validator(|p| match p.parse::<i32>() {
            Err(_) => Err(String::from("file descriptors are number")),
            Ok(_) => Ok(()),
        }).help("preserve opened file descriptor to application in container"))
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

    let mapped_fds = if let Some(mapfd) = matches.values_of("map-fd") {
        mapfd
            .collect::<Vec<&str>>()
            .chunks(2)
            .map(|arr| {
                (
                    arr[0].parse::<i32>().expect("fd must be number"),
                    arr[1].parse::<i32>().expect("fd must be number"),
                )
            })
            .collect::<Vec<(i32, i32)>>()
    } else {
        vec![]
    };

    let preserved_fds = if let Some(preservefd) = matches.values_of("preserve-fd") {
        preservefd.map(|p| p.parse::<i32>().unwrap()).collect()
    } else {
        vec![]
    };

    let out_meta = matches.value_of("out-meta").map(|s| s.to_string());

    let config: config::Config = parse_config(&config_str);

    if cfg!(target_os = "linux") {
        linux::run(
            &config,
            matches.values_of("commands").unwrap().collect(),
            out_meta,
            mapped_fds,
            preserved_fds,
        )?;
        Ok(())
    } else {
        eprintln!("Unsupported operating system");
        std::process::exit(1);
    }
}
