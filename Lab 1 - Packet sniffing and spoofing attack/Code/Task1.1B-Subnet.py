#!/usr/bin/python3
from scapy.all import *
print("SNIFFING PACKETS...")
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface = "br-****",filter='src net 172.17.0.0/24', prn=print_pkt)

