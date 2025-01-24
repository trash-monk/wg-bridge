use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixDatagram;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use clap::{command, Arg, ArgAction, ArgGroup, Id};
use log::{debug, info};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;

use bridge::Bridge;
use buffers::Pool;
use socket::BufferedSocket;

mod bridge;
mod buffers;
mod socket;

fn main() -> ! {
    env_logger::init();

    let args = command!()
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
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
                .default_value("8192")
                .value_parser(clap::value_parser!(u32))
                .help("buffer size for sending/receiving packets"),
        )
        .arg(
            Arg::new("bufcnt")
                .long("bufcnt")
                .default_value("65536")
                .value_parser(clap::value_parser!(u32).range(1..))
                .help("number of buffers (of size bufsz) to use"),
        )
        .arg(
            Arg::new("listen")
                .required(true)
                .help("path to server socket to bind"),
        )
        .arg(
            Arg::new("connect")
                .required(true)
                .help("path to QEMU's server socket"),
        )
        .group(
            ArgGroup::new("cfg_source")
                .args(["demo", "config"])
                .required(true),
        )
        .get_matches();

    let listen_path = args.get_one::<String>("listen").unwrap();
    let connect_path = args.get_one::<String>("connect").unwrap();
    let buf_sz: usize = (*args.get_one::<u32>("bufsz").unwrap()).try_into().unwrap();
    let buf_cnt: usize = (*args.get_one::<u32>("bufcnt").unwrap())
        .try_into()
        .unwrap();

    let (peer_addr, sock, tun) = match args.get_one::<Id>("cfg_source").unwrap().as_str() {
        "demo" => demo_config(),
        "config" => load_config(args.get_one::<String>("config").unwrap()),
        _ => unreachable!(),
    };

    match fs::remove_file(listen_path) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => Err(e).unwrap(),
    }
    let rx = UnixDatagram::bind(listen_path).unwrap();
    let tx = UnixDatagram::unbound().unwrap();

    let mut br = Bridge::new(
        Pool::new(buf_cnt, buf_sz),
        BufferedSocket::new(rx, None).unwrap(),
        BufferedSocket::new(tx, Some(connect_path.into())).unwrap(),
        sock,
        tun,
        peer_addr,
    );

    loop {
        match br.process() {
            Ok(_) => (),
            Err(err) => debug!(err:?; "invalid packet"),
        }
    }
}

fn demo_config() -> (IpAddr, BufferedSocket<UdpSocket>, Tunn) {
    let address = ("demo.wireguard.com", 42912);
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);

    let mut conn = TcpStream::connect(address).unwrap();
    info!(address:?; "connected to demo server");

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

    let endpoint = (address.0, port);
    info!(endpoint:?;"connecting to wg server");
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    sock.connect(endpoint).unwrap();

    (
        conn.peer_addr().unwrap().ip(),
        BufferedSocket::new(sock, None).unwrap(),
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

#[derive(Deserialize, Debug)]
struct Interface {
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "ListenPort")]
    listen_port: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct Peer {
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "PresharedKey")]
    preshared_key: Option<String>,
    #[serde(rename = "Endpoint")]
    endpoint: String,
    #[serde(rename = "PersistentKeepalive")]
    persistent_keepalive: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct Config {
    #[serde(rename = "Peer")]
    peer: Peer,
    #[serde(rename = "Interface")]
    interface: Interface,
}

fn load_config(pth: &str) -> (IpAddr, BufferedSocket<UdpSocket>, Tunn) {
    let cfg: Config = toml::from_str(&std::fs::read_to_string(pth).unwrap()).unwrap();
    info!(cfg:?; "loaded config");

    let mut buf = [0u8; 32];
    BASE64_STANDARD
        .decode_slice(cfg.interface.private_key, &mut buf)
        .unwrap();
    let sk = StaticSecret::from(buf);
    BASE64_STANDARD
        .decode_slice(cfg.peer.public_key, &mut buf)
        .unwrap();
    let pk = PublicKey::from(buf);
    let psk = cfg.peer.preshared_key.map(|x| {
        let mut buf = [0u8; 32];
        BASE64_STANDARD.decode_slice(x, &mut buf).unwrap();
        buf
    });

    let endpoint: SocketAddr = cfg.peer.endpoint.parse().unwrap();
    let sock = UdpSocket::bind((
        Ipv4Addr::UNSPECIFIED,
        cfg.interface.listen_port.unwrap_or(0),
    ))
    .unwrap();
    sock.connect(endpoint).unwrap();

    (
        endpoint.ip(),
        BufferedSocket::new(sock, None).unwrap(),
        Tunn::new(
            sk,
            pk,
            psk,
            cfg.peer.persistent_keepalive,
            OsRng.next_u32(),
            None,
        )
        .unwrap(),
    )
}
