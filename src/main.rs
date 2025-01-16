use anyhow::Result;
use clap::{command, Arg};
use log::{debug, info, trace, warn};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};
use std::process::{Command, ExitCode};
use std::thread;

fn main() -> ExitCode {
    env_logger::init();

    let (here, there) = UnixDatagram::pair().unwrap();
    fcntl(there.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
    let mut pipe = BufferedSocket::new(here).unwrap();

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
        match bridge(&mut pool, &mut pipe) {
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

fn bridge<T: Socket>(pool: &mut Vec<Vec<u8>>, pipe: &mut BufferedSocket<T>) -> Result<()> {
    let mut pollfds = [pipe.poll_fd(pool)];
    poll(&mut pollfds, PollTimeout::NONE)?;
    let revents = [pollfds[0].revents().unwrap()];
    pipe.handle_pollfd(pool, &revents[0]);

    while let Some(buf) = pipe.recv() {
        trace!(buf:?; "got packet");

        let packet = EthernetFrame::new_checked(&buf)?;
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

        pool.push(buf);
    }

    Ok(())
}

struct BufferedSocket<T: Socket> {
    sndbuf: VecDeque<Vec<u8>>,
    rcvbuf: VecDeque<Vec<u8>>,
    inner: T,
}

impl<T: Socket> BufferedSocket<T> {
    fn new(sock: T) -> Result<Self> {
        sock.set_nonblocking(true)?;
        Ok(Self {
            sndbuf: VecDeque::new(),
            rcvbuf: VecDeque::new(),
            inner: sock,
        })
    }

    fn send(&mut self, buf: Vec<u8>) {
        self.sndbuf.push_back(buf)
    }
    fn recv(&mut self) -> Option<Vec<u8>> {
        self.rcvbuf.pop_front()
    }

    fn batch_send(&mut self, pool: &mut Vec<Vec<u8>>) {
        while let Some(buf) = self.sndbuf.pop_front() {
            match self.inner.send(&buf) {
                Ok(_) => {
                    pool.push(buf);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    self.sndbuf.push_front(buf);
                    return;
                }
                Err(e) => panic!("send: {}", e),
            }
        }
    }

    fn batch_recv(&mut self, pool: &mut Vec<Vec<u8>>) {
        while let Some(mut buf) = pool.pop() {
            unsafe { buf.set_len(buf.capacity()) };
            match self.inner.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    self.rcvbuf.push_back(buf);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    buf.clear();
                    pool.push(buf);
                    return;
                }
                Err(e) => panic!("recv: {}", e),
            }
        }

        info!("stall on empty buffer pool")
    }

    fn poll_fd(&self, pool: &[Vec<u8>]) -> PollFd {
        let mut events = PollFlags::empty();
        if !pool.is_empty() {
            events.insert(PollFlags::POLLIN);
        }
        if !self.sndbuf.is_empty() {
            events.insert(PollFlags::POLLOUT)
        }
        PollFd::new(self.inner.as_fd(), events)
    }

    fn handle_pollfd(&mut self, pool: &mut Vec<Vec<u8>>, revents: &PollFlags) {
        for bit in revents.iter() {
            match bit {
                PollFlags::POLLIN => self.batch_recv(pool),
                PollFlags::POLLOUT => self.batch_send(pool),
                x => panic!("poll event: {:?}", x),
            }
        }
    }
}

trait Socket: AsFd {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()>;
}

impl Socket for UnixDatagram {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf)
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}

impl Socket for UdpSocket {
    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf)
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}
