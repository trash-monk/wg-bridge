#!/usr/bin/env python3

import os
import os.path
import socket
import sys
import shutil
import subprocess

from scapy import all as scapy

(here, there) = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

qemu = subprocess.Popen(
        [
            shutil.which('qemu-system-x86_64'),
            '-m', '512',
            '-boot', 'd',
            '-cdrom', sys.argv[1],
            '--accel', 'kvm',
            '-netdev', f'dgram,id=vpn,local.type=fd,local.str={there.fileno()}',
            '-device', 'virtio-net-pci,netdev=vpn',
        ],
        pass_fds=[there.fileno()],
)
there.close()
print(qemu.args)

while True:
	frame = scapy.Ether(here.recv(9001))
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
		here.send(resp_bytes)
