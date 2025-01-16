use anyhow::Result;
use clap::{command, Arg};
use log::{debug, info, trace};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
use std::process::{Command, ExitCode};
use std::thread;

fn main() -> ExitCode {
    env_logger::init();

    let (here, there) = UnixDatagram::pair().unwrap();

    fcntl(there.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();

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

    let bufsz: u32 = *args.get_one("bufsz").unwrap();
    let bufcnt: u32 = *args.get_one("bufcnt").unwrap();
    let mut pool = Vec::new();
    info!(bufcnt,bufsz; "allocating buffer pool");
    for _ in 0..bufcnt {
        let mut buf: Vec<u8> = Vec::new();
        buf.reserve_exact(bufsz.try_into().unwrap());
        pool.push(buf)
    }

    let cmd: Vec<_> = args
        .get_many::<String>("cmd")
        .unwrap()
        .map(|s| s.replace("{}", &there.as_raw_fd().to_string()))
        .collect();

    info!(cmd:?; "running child command");
    let mut child = Command::new(&cmd[0]).args(&cmd[1..]).spawn().unwrap();

    thread::spawn(move || loop {
        match bridge(&here) {
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

fn bridge(pipe: &UnixDatagram) -> Result<()> {
    let mut buf = vec![0; 9001];
    let n = pipe.recv(buf.as_mut_slice()).unwrap();
    trace!(len=n, buf:?=&buf[..n]; "got packet");

    let packet = EthernetFrame::new_checked(&buf[..n])?;

    match packet.ethertype() {
        EthernetProtocol::Arp => {
            trace!(pkt:?=ArpRepr::parse(&ArpPacket::new_checked(packet.payload())?)?; "arp")
        }
        EthernetProtocol::Ipv4 => {
            trace!(pkt:?=Ipv4Repr::parse(&Ipv4Packet::new_checked(packet.payload())?, &ChecksumCapabilities::default())?; "ipv4")
        }
        EthernetProtocol::Ipv6 => {
            trace!(pkt:?=Ipv6Repr::parse(&Ipv6Packet::new_checked(packet.payload())?)?; "ipv6")
        }
        EthernetProtocol::Unknown(x) => debug!(ethertype=x; "dropping unknown packet"),
    }

    Ok(())
}

trait Socket {
    fn send(&self, buf: &[u8]) -> Result<usize>;
    fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}
