#!/usr/env/bin python3

import scapy.all as scapy
import optparse

def get_ip_range():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help="Target IP / IP range")
    options, argumets = parser.parse_args()
    if not options.target:
        parser.error("[+] Please scpecify an IP target, use --help for info")
    return options.target

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    #srp lets us send a Ether packet with a cusom dst
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    
    client_list = []
    for element in answered_list:
        client = {'IP': element[1].psrc, 'MAC': element[1].hwsrc}
        client_list.append(client)
    return client_list    

def print_clinets(list):
    print('\n')
    print("IP\t\tMAC Address\n- - - - - - - - - - - - - - - - -")
    for element in list:
        print(element["IP"] + "\t" + element["MAC"])


ips = get_ip_range()
result_list = scan(ips)
print_clinets(result_list)