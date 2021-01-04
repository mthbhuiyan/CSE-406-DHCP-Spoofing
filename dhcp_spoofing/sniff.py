#!/usr/bin/python3

import sys
from scapy.all import *

print("SNIFFING PACKETS.........")

interface=''

def print_pkt(packet):                       
	print(ls(packet))
   	print("\n")

if __name__ == "__main__":
	if len(sys.argv) > 1:
		interface=sys.argv[1]
	else:
		sys.exit(1)

	pkt = sniff(iface=interface, filter='ip and not (port 67 or 68)',prn=print_pkt)
