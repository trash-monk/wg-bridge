use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;

use anyhow::Result;
use nix::poll::{PollFd, PollFlags};

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
    snd_buf: VecDeque<Buffer>,
    rcv_buf: VecDeque<Buffer>,
    inner: T,
}

impl<T: Socket> BufferedSocket<T> {
    pub fn new(sock: T) -> Result<Self> {
        sock.set_nonblocking(true)?;
        Ok(Self {
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            inner: sock,
        })
    }

    pub fn send(&mut self, buf: Buffer) {
        self.snd_buf.push_back(buf)
    }

    pub fn recv(&mut self) -> Option<Buffer> {
        self.rcv_buf.pop_front()
    }

    fn batch_send(&mut self) {
        while let Some(buf) = self.snd_buf.pop_front() {
            match self.inner.send(buf.as_ref()) {
                Ok(_) => continue,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    self.snd_buf.push_front(buf);
                    return;
                }
                Err(err) => panic!("send: {}", err),
            }
        }
    }

    fn batch_recv(&mut self, pool: &mut Pool) {
        while pool.available() > 0 {
            let mut buf = pool.get();
            match self.inner.recv(buf.as_mut()) {
                Ok(n) => {
                    buf.truncate(n);
                    self.rcv_buf.push_back(buf);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(err) => panic!("recv: {}", err),
            }
        }
    }

    pub fn poll_fd(&self, pool: &Pool) -> PollFd {
        let mut events = PollFlags::empty();
        if pool.available() > 0 {
            events.insert(PollFlags::POLLIN)
        }
        if !self.snd_buf.is_empty() {
            events.insert(PollFlags::POLLOUT)
        }
        PollFd::new(self.inner.as_fd(), events)
    }

    pub fn batch_io(&mut self, pool: &mut Pool, revents: &PollFlags) {
        for bit in revents.iter() {
            match bit {
                PollFlags::POLLIN => self.batch_recv(pool),
                PollFlags::POLLOUT => self.batch_send(),
                x => panic!("poll event: {:?}", x),
            }
        }
    }
}
