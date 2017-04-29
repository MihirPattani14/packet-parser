# -*- coding: utf-8 -*-
"""
Created on Wed Apr 12 22:39:59 2017

@author: mihir
"""

import dpkt
import sys
import socket
from dpkt.compat import compat_ord

def conv_mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

if __name__ == "__main__":
    filename = sys.argv[1]
    pcapdata = open(filename)
    pcap = dpkt.pcap.Reader(pcapdata)
    packet_num = 0
    for ts, buf in pcap:
        packet_num += 1
        print "--------------------------------------------------"
        print "\t\tPacket Number: ", packet_num
        print "--------------------------------------------------"
        eth = dpkt.ethernet.Ethernet(buf)
        print "Src MAC address:\t|\t", conv_mac_addr(eth.src)
        print "Dst MAC address:\t|\t", conv_mac_addr(eth.dst)
        ip = eth.data
        if type(eth.data) == dpkt.ip.IP:
            print "\n"
            print "Src IP address:\t\t|\t", socket.inet_ntoa(ip.src)
            print "Dst IP address:\t\t|\t", socket.inet_ntoa(ip.dst)
            print "\n"
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                print "Packet Type:\t\t|\tTCP\n"
                print "Src Port number:\t|\t", tcp.sport
                print "Dst Port number:\t|\t", tcp.dport
                print "Checksum: \t\t|\t", tcp.sum
            elif type(ip.data) == dpkt.udp.UDP:
                udp = ip.data
                print "Packet Type:\t\t|\tUDP\n"
                print "Src Port number:\t|\t", udp.sport
                print "Dst Port number:\t|\t", udp.dport
            else:
                print "Packet Type:\t\t|\tother\n"
        else:
            print "Non IP Packet"
        print "\n"
    pcapdata.close()