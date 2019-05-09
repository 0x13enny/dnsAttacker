#! /usr/bin/env python3
# run as sudo
from scapy.all import *
import sys



def main(interface, dnsTarget, victim, host):
    answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.thepacketgeek.com")),verbose=0)
    print(answer[DNS].show())


if __name__ == "__main__":
    main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
