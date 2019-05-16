#! /usr/bin/env python3
# run as sudo

# ----- DO NOT RUN IN PUBLIC NETWORK

from scapy.all import *
import sys
from datetime import datetime
import time
import datetime


def sniffer(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    try:
        if DNSQR in pkt and pkt.dport == 53:
            print('[**] Detected DNS QR Message at: ' + pkt_time)
            poisoner(pkt)
        elif DNSRR in pkt and pkt.sport == 53:
            print('[**] Detected DNS RR Message at: ' + pkt_time)
            # print(pkt.decode())
        # if IP in pkt:
        #     # print("---- source : " + pkt[IP].src)
        #     # print("---- destination : " + pkt[IP].dst)
        #     pass
    except:
        pass

def poisoner(pkt):
    #### poison = IP(src=src , dst=dst , ttl=128 )/UDP(dport=53)/DNS(rd=1 , qd=DNSQR(qname=qname ,qtype=qtype))
    qname = pkt[DNSQR].qname.decode() 
    src = pkt[IP].src
    dst = pkt[IP].dst
    dns_id = pkt.id
    dns_packet = IP(pkt.get_payload())
    print(dns_packet.show())
    # if dns_packet.haslayer(DNSRR):
    #     print(dns_packet.show())
    pass

if __name__ == "__main__":
    try:
        gate = input("[WARNING] Make Sure Selected Interface is in PRIVATE NETWORK!![yN]")
        if gate == "y" or gate == "Y":
            interface = 'wlp0s20f3'
            filter_bpf = 'udp and port 53'
            sniff(iface=interface, filter=filter_bpf, store=0,  prn=sniffer)
    except:
        sys.exit(1)