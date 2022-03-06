from scapy.layers.inet import IP, ICMP
from scapy.all import *

inRoute = True
i = 1
while inRoute:
    a = IP(dst='8.8.8.8', ttl=i)
    response = sr1(a / ICMP(), verbose=0)

    if response is None:
        print("Request timed out")

    elif response.type == 0:
        print(response.src)
        inRoute = False
    else:
        print(response.src)

    i = i + 1
