#! /usr/bin/env python3
# run as sudo
from scapy.all import *
import sys



def main(interface, dnsTarget, victim, host):

    # interface = "wlp0s20f3"                    # Interface you want to use
    # victim = "192.168.66.45"               # IP of that interface
    # dnsTarget = ["ip1","ip2","ip3"] # List of DNS Server IPs
    dnsTarget="8.8.8.8"
    time_to_live = 128
    query_name = "google.com"
    query_type = ["ANY", "A","AAAA","CNAME","MX","NS","PTR","CERT","SRV","TXT", "SOA"]

    for i in range(0,len(query_type)):
        
        packet = IP(src=victim, dst=dnsTarget, ttl=time_to_live) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=query_type[i]))
        try:
            answer = sr1(packet, iface=interface, timeout=10)
            print(answer[DNS].summary())
        except TypeError:
            print("time out")

if __name__ == "__main__":
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
