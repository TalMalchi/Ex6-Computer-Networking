
from scapy.all import *
from scapy.layers.inet import IP

a = IP()
a.show()
# python3 code.py
###[ IP ]###
version = 4
ihl = None


def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface='enp0s3', filter='net 128.230.0.0/16', prn=print_pkt)






