use std::net::{IpAddr, UdpSocket};
use std::os::unix::net::UnixDatagram;

use anyhow::{bail, Result};
use boringtun::noise::{Tunn, TunnResult};
use log::{debug, trace};
use nix::poll::poll;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
};

use crate::buffers::{Buffer, Pool};
use crate::socket::BufferedSocket;

pub struct Bridge {
    pool: Pool,
    pipe: BufferedSocket<UnixDatagram>,
    sock: BufferedSocket<UdpSocket>,
    tun: Tunn,
    mac: Option<EthernetAddress>,
    peer: IpAddr,
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
        peer: IpAddr,
    ) -> Self {
        let mut buf = pool.get();
        let handshake_init = match tun.format_handshake_initiation(buf.as_mut(), false) {
            TunnResult::Done => unreachable!(),
            TunnResult::Err(err) => panic!("handshake failed: {:?}", err),
            TunnResult::WriteToNetwork(x) => x,
            TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
            TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
        };
        let handshake_len = handshake_init.len();
        buf.truncate(handshake_len);
        debug!("wg handshake");
        sock.send(buf);

        Self {
            pool,
            pipe,
            sock,
            tun,
            peer,
            mac: None,
        }
    }

    pub fn process(&mut self) -> Result<()> {
        let mut poll_fds = [self.pipe.poll_fd(), self.sock.poll_fd()];
        poll(&mut poll_fds, rand::random::<u16>() % 500 + 500).unwrap();
        let revents = [
            poll_fds[0].revents().unwrap(),
            poll_fds[1].revents().unwrap(),
        ];
        self.pipe.batch_io(&mut self.pool, &revents[0]);
        self.sock.batch_io(&mut self.pool, &revents[1]);

        while let Some(pkt) = self.pipe.recv() {
            self.handle_pipe(pkt)?;
        }

        while let Some(pkt) = self.sock.recv() {
            self.handle_sock(pkt)?;
        }

        let mut buf = self.pool.get();
        match self.tun.update_timers(buf.as_mut()) {
            TunnResult::Done => {}
            TunnResult::Err(err) => panic!("wg: {:?}", err),
            TunnResult::WriteToNetwork(x) => {
                trace!("wg timer send");
                let buf_len = x.len();
                buf.truncate(buf_len);
                self.sock.send(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
            TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
        }

        Ok(())
    }

    fn handle_sock(&mut self, mut pkt: Buffer) -> Result<()> {
        let mut queued = false;
        loop {
            let mut buf = self.pool.get();
            match self
                .tun
                .decapsulate(Some(self.peer), pkt.as_ref(), buf.as_mut())
            {
                TunnResult::Done => (),
                TunnResult::Err(err) => bail!("wg decapsulate: {:?}", err),
                TunnResult::WriteToNetwork(x) => {
                    let buf_len = x.len();
                    buf.truncate(buf_len);
                    trace!("wg queued send");
                    self.sock.send(buf);
                    queued = true;
                    pkt.truncate(0);
                    continue;
                }
                TunnResult::WriteToTunnelV4(x, dst) => {
                    let buf_len = x.len();
                    buf.truncate(buf_len);
                    self.handle_ipv4(dst.into(), buf)?;

                    if queued {
                        continue;
                    }
                }
                TunnResult::WriteToTunnelV6(x, dst) => {
                    let buf_len = x.len();
                    buf.truncate(buf_len);
                    self.handle_ipv6(dst.into(), buf)?;

                    if queued {
                        continue;
                    }
                }
            }

            break Ok(());
        }
    }

    fn handle_pipe(&mut self, pkt: Buffer) -> Result<()> {
        let frame = EthernetFrame::new_checked(&pkt)?;
        match frame.ethertype() {
            EthernetProtocol::Arp => self.handle_arp(
                ArpRepr::parse(&ArpPacket::new_checked(frame.payload())?)?,
                pkt,
            )?,
            EthernetProtocol::Ipv4 => {
                let repr = Ipv4Repr::parse(
                    &Ipv4Packet::new_checked(frame.payload())?,
                    &ChecksumCapabilities::default(),
                );
                trace!(repr:?; "<-ipv4");

                let mut buf = self.pool.get();
                match self.tun.encapsulate(frame.payload(), buf.as_mut()) {
                    TunnResult::Done => (),
                    TunnResult::Err(err) => bail!("wg encapsulate: {:?}", err),
                    TunnResult::WriteToNetwork(x) => {
                        let buf_len = x.len();
                        buf.truncate(buf_len);
                        self.sock.send(buf);
                    }
                    TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
                    TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
                }
            }
            EthernetProtocol::Ipv6 => {
                let repr = Ipv6Repr::parse(&Ipv6Packet::new_checked(frame.payload())?);
                debug!(repr:?; "<-ipv6 drop");
            }
            EthernetProtocol::Unknown(x) => {
                debug!(ethertype=x; "<-??? drop");
            }
        }

        Ok(())
    }

    fn handle_arp(&mut self, info: ArpRepr, mut buf: Buffer) -> Result<()> {
        trace!(info:?; "arp");
        match info {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Unknown(x),
                ..
            } => {
                bail!("unknown arp operation {}", x);
            }
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr: EthernetAddress([0, 0, 0, 0, 0, 0]),
                target_protocol_addr,
            } => {
                self.mac = Some(source_hardware_addr);

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
                trace!(hdr:?, reply:?; "arp reply");

                buf.reset();
                let mut packet = EthernetFrame::new_checked(buf.as_mut()).unwrap();
                let mut payload = ArpPacket::new_checked(packet.payload_mut()).unwrap();
                reply.emit(&mut payload);
                hdr.emit(&mut packet);
                buf.truncate(hdr.buffer_len() + reply.buffer_len());

                self.pipe.send(buf);
            }
            x => bail!("unexpected arp packet: {:?}", x),
        }

        Ok(())
    }

    fn handle_ipv4(&mut self, src: Ipv4Address, mut pkt: Buffer) -> Result<()> {
        let repr = Ipv4Repr::parse(
            &Ipv4Packet::new_checked(pkt.as_ref())?,
            &ChecksumCapabilities::default(),
        );
        trace!(src:?,repr:?; "->ipv4");

        let dst = if let Some(x) = self.mac {
            x
        } else {
            bail!("destination mac not set, dropping packet");
        };

        let hdr = EthernetRepr {
            src_addr: fake_mac(src),
            dst_addr: dst,
            ethertype: EthernetProtocol::Ipv4,
        };

        let payload_len = pkt.as_ref().len();
        pkt.reset();
        pkt.as_mut().copy_within(0..payload_len, hdr.buffer_len());
        let mut packet = EthernetFrame::new_checked(pkt.as_mut()).unwrap();
        hdr.emit(&mut packet);
        pkt.truncate(hdr.buffer_len() + payload_len);

        self.pipe.send(pkt);
        Ok(())
    }

    fn handle_ipv6(&mut self, dst: Ipv6Address, pkt: Buffer) -> Result<()> {
        let repr = Ipv6Repr::parse(&Ipv6Packet::new_checked(pkt.as_ref())?);
        debug!(dst:?, repr:?; "->ipv6 drop");
        Ok(())
    }
}
