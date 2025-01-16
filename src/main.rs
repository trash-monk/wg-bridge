mod bridge;
mod buffers;
mod socket;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use bridge::Bridge;
use buffers::Pool;
use clap::{command, Arg, ArgAction, ArgGroup, Id};
use log::{debug, info};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use rand_core::{OsRng, RngCore};
use socket::BufferedSocket;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
use std::process::{exit, Command, ExitCode};
use std::thread;

fn main() -> ExitCode{
    env_logger::init();

    let args = command!()
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_parser(clap::value_parser!(String))
                .help("use the given config file, in the format of `wg setconf`"),
        )
        .arg(
            Arg::new("demo")
                .long("demo")
                .action(ArgAction::SetTrue)
                .help("connect to the public demo server (NOT SECURE)"),
        )
        .arg(
            Arg::new("bufsz")
                .long("bufsz")
                .default_value("9038")
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
        .group(
            ArgGroup::new("cfg_source")
                .args(["demo", "config"])
                .required(true),
        )
        .get_matches();

    let (sock, tun) = match args.get_one::<Id>("cfg_source").unwrap().as_str() {
        "demo" => demo_config(),
        "config" => todo!(),
        _ => unreachable!(),
    };

    let (here, there) = UnixDatagram::pair().unwrap();
    fcntl(there.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();

    let bufsz: usize = (*args.get_one::<u32>("bufsz").unwrap()).try_into().unwrap();
    let bufcnt: usize = (*args.get_one::<u32>("bufcnt").unwrap())
        .try_into()
        .unwrap();

    let mut br = Bridge::new(
        Pool::new(bufcnt, bufsz),
        BufferedSocket::new(here).unwrap(),
        sock,
        tun,
    );

    let cmd: Vec<_> = args
        .get_many::<String>("cmd")
        .unwrap()
        .map(|s| s.replace("{}", &there.as_raw_fd().to_string()))
        .collect();

    info!(cmd:?; "running child command");
    let mut child = Command::new(&cmd[0]).args(&cmd[1..]).spawn().unwrap();

/*     thread::spawn(move || if let Some(x) = child.wait().unwrap().code() {
        exit(x)
    } else {
        exit(123)
    }); */

    loop {
        match br.process() {
            Ok(_) => (),
            Err(x) => debug!(x:?; "invalid packet"),
        }
    }
}

fn demo_config() -> (BufferedSocket<UdpSocket>, Tunn) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);

    let mut conn = TcpStream::connect("demo.wireguard.com:42912").unwrap();
    debug!("connected to demo server");

    conn.write_fmt(format_args!("{}\n", BASE64_STANDARD.encode(pk)))
        .unwrap();
    debug!(pk:?;"sent pubkey");

    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).unwrap();

    let resp = String::from_utf8(buf).unwrap();
    let cfg: Vec<&str> = resp.trim().split(':').collect();
    debug!(cfg:?; "fetched config");
    assert_eq!(cfg[0], "OK");

    let port: u16 = cfg[2].parse().unwrap();
    let mut peer_key = [0u8; 32];
    BASE64_STANDARD.decode_slice(cfg[1], &mut peer_key).unwrap();

    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    sock.connect(("demo.wireguard.com", port)).unwrap();

    (
        BufferedSocket::new(sock).unwrap(),
        Tunn::new(
            sk,
            PublicKey::from(peer_key),
            None,
            Some(25),
            OsRng.next_u32(),
            None,
        )
        .unwrap(),
    )
}
