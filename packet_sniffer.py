#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)

def process_sniffed_packets(packet):
    print(packet)

sniff("eth0")