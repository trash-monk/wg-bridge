use anyhow::Result;
use nix::poll::{PollFd, PollFlags};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;

use crate::buffers::{Buffer, Pool};

pub trait Socket: AsFd {
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

pub struct BufferedSocket<T: Socket> {
    sndbuf: VecDeque<Buffer>,
    rcvbuf: VecDeque<Buffer>,
    inner: T,
}

impl<T: Socket> BufferedSocket<T> {
    pub fn new(sock: T) -> Result<Self> {
        sock.set_nonblocking(true)?;
        Ok(Self {
            sndbuf: VecDeque::new(),
            rcvbuf: VecDeque::new(),
            inner: sock,
        })
    }

    pub fn send(&mut self, buf: Buffer) {
        self.sndbuf.push_back(buf)
    }

    pub fn recv(&mut self) -> Option<Buffer> {
        self.rcvbuf.pop_front()
    }

    fn batch_send(&mut self, pool: &mut Pool) {
        while let Some(buf) = self.sndbuf.pop_front() {
            match self.inner.send(buf.as_ref()) {
                Ok(_) => (),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    self.sndbuf.push_front(buf);
                    return;
                }
                Err(e) => panic!("send: {}", e),
            }
        }
    }

    fn batch_recv(&mut self, pool: &mut Pool) {
        loop {
            let mut buf = pool.get();
            match self.inner.recv(buf.as_mut()) {
                Ok(n) => {
                    buf.truncate(n);
                    self.rcvbuf.push_back(buf);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    return;
                }
                Err(e) => panic!("recv: {}", e),
            }
        }
    }

    pub fn poll_fd(&self, pool: &Pool) -> PollFd {
        let mut events = PollFlags::empty();
            events.insert(PollFlags::POLLIN);
        if !self.sndbuf.is_empty() {
            events.insert(PollFlags::POLLOUT)
        }
        PollFd::new(self.inner.as_fd(), events)
    }

    pub fn handle(&mut self, pool: &mut Pool, revents: &PollFlags) {
        for bit in revents.iter() {
            match bit {
                PollFlags::POLLIN => self.batch_recv(pool),
                PollFlags::POLLOUT => self.batch_send(pool),
                x => panic!("poll event: {:?}", x),
            }
        }
    }
}
