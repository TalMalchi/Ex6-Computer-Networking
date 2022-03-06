from scapy.layers.inet import IP, ICMP
from scapy.all import *

a = IP()
a.src = '8.1.2.3'
a.dst = '10.0.2.3'
b = ICMP()
p = a / b
send(p)
