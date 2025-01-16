mod bridge;
mod buffers;
mod socket;

use bridge::Bridge;
use buffers::Pool;
use clap::{command, Arg};
use log::{debug, info};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use socket::BufferedSocket;
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
use std::process::{Command, ExitCode};
use std::thread;

fn main() -> ExitCode {
    env_logger::init();

    let args = command!()
        .arg(
            Arg::new("bufsz")
                .long("bufsz")
                .default_value("1538")
                .value_parser(clap::value_parser!(u32))
                .help("buffer size for sending/receiving packets"),
        )
        .arg(
            Arg::new("bufcnt")
                .long("bufcnt")
                .default_value("1024")
                .value_parser(clap::value_parser!(u32).range(1..))
                .help("number of buffers (of size bufsz) to use"),
        )
        .arg(
            Arg::new("cmd")
                .num_args(1..)
                .trailing_var_arg(true)
                .help("command to run"),
        )
        .get_matches();

    let (here, there) = UnixDatagram::pair().unwrap();
    fcntl(there.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();

    let bufsz: usize = (*args.get_one::<u32>("bufsz").unwrap()).try_into().unwrap();
    let bufcnt: usize = (*args.get_one::<u32>("bufcnt").unwrap())
        .try_into()
        .unwrap();

    let mut br = Bridge::new(Pool::new(bufcnt, bufsz), BufferedSocket::new(here).unwrap());

    let cmd: Vec<_> = args
        .get_many::<String>("cmd")
        .unwrap()
        .map(|s| s.replace("{}", &there.as_raw_fd().to_string()))
        .collect();

    info!(cmd:?; "running child command");
    let mut child = Command::new(&cmd[0]).args(&cmd[1..]).spawn().unwrap();

    thread::spawn(move || loop {
        match br.process() {
            Ok(_) => (),
            Err(x) => debug!(x:?; "invalid packet"),
        }
    });

    if let Some(x) = child.wait().unwrap().code() {
        ExitCode::from(x as u8)
    } else {
        ExitCode::FAILURE
    }
}
