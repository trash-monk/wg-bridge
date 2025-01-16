use crate::buffers::{Buffer, Pool};
use crate::socket::BufferedSocket;
use anyhow::{Ok, Result};
use boringtun::noise::{Tunn, TunnResult};
use log::{debug, trace};
use nix::poll::{poll, PollTimeout};
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, Ipv4Address, Ipv6Address,
};
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;

pub struct Bridge {
    pool: Pool,
    pipe: BufferedSocket<UnixDatagram>,
    sock: BufferedSocket<UdpSocket>,
    tun: Tunn,
    hwaddr: Option<EthernetAddress>,
}

fn fake_mac(addr: Ipv4Address) -> EthernetAddress {
    EthernetAddress([0x22, 0x69, addr.0[0], addr.0[1], addr.0[2], addr.0[3]])
}

impl Bridge {
    pub fn new(
        mut pool: Pool,
        pipe: BufferedSocket<UnixDatagram>,
        mut sock: BufferedSocket<UdpSocket>,
        mut tun: Tunn,
    ) -> Self {
        let mut buf = pool.get().unwrap();
        let handshake_init = match tun.format_handshake_initiation(buf.as_mut(), false) {
            TunnResult::Done => unreachable!(),
            TunnResult::Err(x) => panic!("handshake failed: {:?}", x),
            TunnResult::WriteToNetwork(x) => x,
            TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
            TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
        };
        let handshake_len = handshake_init.len();
        buf.truncate(handshake_len);
        trace!(buf:?; "handshake init");
        sock.send(buf);

        Self {
            pool,
            pipe,
            sock,
            tun,
            hwaddr: None,
        }
    }

    pub fn process(&mut self) -> Result<()> {
        let mut pollfds = [self.pipe.poll_fd(&self.pool), self.sock.poll_fd(&self.pool)];
        poll(&mut pollfds, PollTimeout::NONE)?;
        let revents = [pollfds[0].revents().unwrap(), pollfds[1].revents().unwrap()];
        self.pipe.handle(&mut self.pool, &revents[0]);
        self.sock.handle(&mut self.pool, &revents[1]);

        while let Some(pkt) = self.pipe.recv() {
            trace!(pkt:?; "recv pipe");

            let frame = EthernetFrame::new_checked(&pkt)?;
            match frame.ethertype() {
                EthernetProtocol::Arp => self.handle_arp(
                    ArpRepr::parse(&ArpPacket::new_checked(frame.payload())?)?,
                    pkt,
                ),
                EthernetProtocol::Ipv4 => {
                    let mut buf = self.pool.get().unwrap();
                    match self.tun.encapsulate(frame.payload(), buf.as_mut()) {
                        TunnResult::Done => unreachable!(),
                        TunnResult::Err(x) => panic!("decapsulate: {:?}", x),
                        TunnResult::WriteToNetwork(x) => {
                            let buf_len = x.len();
                            buf.truncate(buf_len);
                            self.sock.send(buf);
                        }
                        TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
                        TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
                    }
                    self.pool.put(pkt);
                }
                EthernetProtocol::Ipv6 => {
                    trace!("drop lan ipv6");
                    self.pool.put(pkt);
                }
                EthernetProtocol::Unknown(x) => {
                    debug!(ethertype=x; "drop lan unknown");
                    self.pool.put(pkt);
                }
            }
        }

        while let Some(mut pkt) = self.sock.recv() {
            trace!(pkt:?; "recv sock");

            let mut queued = false;
            loop {
                let mut buf = self.pool.get().unwrap();
                // TODO fill in src_addr?
                match self.tun.decapsulate(None, pkt.as_ref(), buf.as_mut()) {
                    TunnResult::Done => self.pool.put(buf),
                    TunnResult::Err(x) => panic!("decapsulate: {:?}", x),
                    TunnResult::WriteToNetwork(x) => {
                        let buf_len = x.len();
                        buf.truncate(buf_len);
                        trace!(buf:?; "queued sock send");
                        self.sock.send(buf);
                        queued = true;
                        pkt.truncate(0);
                        continue;
                    }
                    TunnResult::WriteToTunnelV4(x, dst) => {
                        let buf_len = x.len();
                        buf.truncate(buf_len);
                        self.handle_ipv4(dst.into(), buf);

                        if queued {
                            continue;
                        }
                    }
                    TunnResult::WriteToTunnelV6(x, dst) => {
                        let buf_len = x.len();
                        buf.truncate(buf_len);
                        self.handle_ipv6(dst.into(), buf);

                        if queued {
                            continue;
                        }
                    }
                }

                self.pool.put(pkt);
                break;
            }
        }

        Ok(())
    }

    fn handle_arp(&mut self, info: ArpRepr, mut buf: Buffer) {
        trace!(info:?; "arp");
        match info {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Unknown(x),
                ..
            } => {
                debug!(op=x;"unknown arp operation");
                self.pool.put(buf);
            }
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr: EthernetAddress([0, 0, 0, 0, 0, 0]),
                target_protocol_addr,
            } => {
                self.hwaddr = Some(source_hardware_addr);

                let target_hardware_addr = fake_mac(target_protocol_addr);
                let reply = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: target_hardware_addr,
                    source_protocol_addr: target_protocol_addr,
                    target_hardware_addr: source_hardware_addr,
                    target_protocol_addr: source_protocol_addr,
                };
                let hdr = EthernetRepr {
                    src_addr: target_hardware_addr,
                    dst_addr: source_hardware_addr,
                    ethertype: EthernetProtocol::Arp,
                };

                buf.reset();
                let mut packet = EthernetFrame::new_checked(buf.as_mut()).unwrap();
                let mut payload = ArpPacket::new_checked(packet.payload_mut()).unwrap();
                reply.emit(&mut payload);
                hdr.emit(&mut packet);
                buf.truncate(hdr.buffer_len() + reply.buffer_len());

                trace!(buf:?; "arp reply");
                self.pipe.send(buf);
            }
            _ => debug!("unexpected arp packet"),
        }
    }

    fn handle_ipv4(&mut self, src: Ipv4Address, buf: Buffer) {
        let dst = if let Some(x) = self.hwaddr {
            x
        } else {
            trace!("destination mac not set, dropping packet");
            self.pool.put(buf);
            return;
        };

        let hdr = EthernetRepr {
            src_addr: fake_mac(src),
            dst_addr: dst,
            ethertype: EthernetProtocol::Ipv4,
        };

        let mut pkt = self.pool.get().unwrap();
        let mut packet = EthernetFrame::new_checked(pkt.as_mut()).unwrap();
        for i in 0..buf.as_ref().len() {
            packet.payload_mut()[i] = buf.as_ref()[i];
        }
        hdr.emit(&mut packet);
        pkt.truncate(hdr.buffer_len() + buf.as_ref().len());

        trace!(pkt:?; "tun ipv4");
        self.pipe.send(pkt);
        self.pool.put(buf);
    }

    fn handle_ipv6(&mut self, dst: Ipv6Address, buf: Buffer) {
        trace!(dst:?; "drop tun ipv6");
        self.pool.put(buf);
    }
}
