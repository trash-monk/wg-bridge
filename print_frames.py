#!/usr/bin/env python3

import os
import os.path
import socket
import sys

from scapy import all as scapy

# qemu-system-x86_64 -m 512 -boot d -cdrom alpine-virt-3.19.1-x86_64.iso --accel kvm -netdev dgram,id=vpn,local.type=unix,local.path=local,remote.type=unix,remote.path=remote -device virtio-net-pci,netdev=vpn

send_socket_path = 'local'
recv_socket_path = 'remote'
if os.path.exists(recv_socket_path):
    os.remove(recv_socket_path)

send_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
recv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
recv_sock.bind(recv_socket_path)

ready = False
while True:
	frame = scapy.Ether(recv_sock.recv(9001))
	print(repr(frame))
	print("")

	if not isinstance(frame.payload, scapy.ARP):
		continue
	if frame.payload.op != 1: # who-has
		continue

	if frame.payload.pdst == "192.168.100.101":
		resp_bytes = scapy.raw((scapy.Ether(
			dst="52:54:00:12:34:56",
			src="52:54:00:12:34:ff",
		) / scapy.ARP(
			op=2, # is-at
			hwsrc="52:54:00:12:34:ff",
			psrc="192.168.100.101",
			hwdst="52:54:00:12:34:56",
			pdst="192.168.100.100",
		)))
		send_sock.sendto(resp_bytes, send_socket_path)
		ready = True
