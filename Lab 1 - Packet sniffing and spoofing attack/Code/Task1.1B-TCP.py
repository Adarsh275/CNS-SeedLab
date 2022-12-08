#!/usr/bin/python3
from scapy.all import *
print ("SNIFFING PACKETS...")
def print_pkt(pkt):
    pkt.show()
pkt = sniff (iface = "br-****",filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)

