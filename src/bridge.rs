use crate::buffers::{Buffer, Pool};
use crate::socket::{BufferedSocket, Socket};
use anyhow::Result;
use log::{debug, trace};
use nix::poll::{poll, PollTimeout};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

pub struct Bridge<T: Socket> {
    pool: Pool,
    pipe: BufferedSocket<T>,
}

impl<T: Socket> Bridge<T> {
    pub fn new(pool: Pool, pipe: BufferedSocket<T>) -> Self {
        Self { pool, pipe }
    }

    pub fn process(&mut self) -> Result<()> {
        let mut pollfds = [self.pipe.poll_fd(&self.pool)];
        poll(&mut pollfds, PollTimeout::NONE)?;
        let revents = [pollfds[0].revents().unwrap()];
        self.pipe.handle(&mut self.pool, &revents[0]);

        while let Some(buf) = self.pipe.recv() {
            trace!(buf:?; "got packet");

            let packet = EthernetFrame::new_checked(&buf)?;
            match packet.ethertype() {
                EthernetProtocol::Arp => self.handle_arp(
                    ArpRepr::parse(&ArpPacket::new_checked(packet.payload())?)?,
                    buf,
                ),
                EthernetProtocol::Ipv4 => self.handle_ipv4(
                    Ipv4Repr::parse(
                        &Ipv4Packet::new_checked(packet.payload())?,
                        &ChecksumCapabilities::default(),
                    )?,
                    buf,
                ),
                EthernetProtocol::Ipv6 => self.handle_ipv6(
                    Ipv6Repr::parse(&Ipv6Packet::new_checked(packet.payload())?)?,
                    buf,
                ),
                EthernetProtocol::Unknown(x) => debug!(ethertype=x; "dropping unknown packet"),
            }
        }

        Ok(())
    }

    fn handle_arp(&mut self, pkt: ArpRepr, buf: Buffer) {
        trace!(pkt:?; "arp");
        match pkt {
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Unknown(x),
                ..
            } => debug!(op=x;"unknown arp operation"),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr: EthernetAddress([0, 0, 0, 0, 0, 0]),
                target_protocol_addr,
            } => {
                return self.reply_arp(
                    source_hardware_addr,
                    source_protocol_addr,
                    target_protocol_addr,
                    buf,
                )
            }
            _ => debug!("unexpected arp packet"),
        }
        self.pool.put(buf);
    }

    fn reply_arp(
        &mut self,
        sha: EthernetAddress,
        spa: Ipv4Address,
        tpa: Ipv4Address,
        mut buf: Buffer,
    ) {
        let fake_mac = EthernetAddress([0x22, 0x69, tpa.0[0], tpa.0[1], tpa.0[2], tpa.0[3]]);

        let hdr = EthernetRepr {
            src_addr: fake_mac,
            dst_addr: sha,
            ethertype: EthernetProtocol::Arp,
        };
        let reply = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: fake_mac,
            source_protocol_addr: tpa,
            target_hardware_addr: sha,
            target_protocol_addr: spa,
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

    fn handle_ipv4(&mut self, pkt: Ipv4Repr, buf: Buffer) {
        trace!(pkt:?; "ipv4");
        self.pool.put(buf);
    }

    fn handle_ipv6(&mut self, pkt: Ipv6Repr, buf: Buffer) {
        trace!(pkt:?; "ipv6");
        self.pool.put(buf);
    }
}
