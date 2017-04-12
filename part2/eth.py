# -*- coding: utf-8 -*-
"""
Created on Mon Apr 10 20:34:16 2017

@author: mihir
"""

#!/usr/bin/env python

import dpkt
import socket
import sys
import Connection

class TCP_Connection:
    def __init__(self):
        self.num_conns = 0
        self.active_conns = []
        
    def exists_connection(self, sip, dip, sport, dport):
        i = 0
        for connection in self.active_conns:
            if connection.sip == sip and connection.sport == sport:
                if connection.dip == dip and connection.dport == dport:
                    return True, i, connection.state
            elif connection.sip == dip and connection.sport == dport:
                if connection.dip == sip and connection.dport == sport:
                    return True, i, connection.state
            i = i + 1
        return False, i, -1

    def new_connection_allow(self, sip, dip, sport, dport):
        for connection in self.active_conns:
            if connection.sip == sip and connection.sport == sport:
                return False
            elif connection.sip == dip and connection.sport == dport:
                return False
            elif connection.dip == sip and connection.dport == sport:
                return False
            elif connection.dip == dip and connection.dport == dport:
                return False
        return True
                
        
    def establish_connection(self, packet):
        exists, conn_num, state = self.exists_connection(packet.sip, packet.dip, packet.sport, packet.dport)
        allow =True        
        if exists == False:
            allow = self.new_connection_allow(packet.sip, packet.dip, packet.sport, packet.dport)
        else:
            allow = False
        return allow, conn_num, state
        
    def process_packet(self, packet_num, data):
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if type(ip.data) == dpkt.tcp.TCP:
            print "Packet Num", packet_num
            tcp = ip.data
            packet = Connection.Packet()
            packet.sip = src_ip
            packet.dip = dst_ip
            packet.sport = tcp.sport
            packet.dport = tcp.dport
            packet.ack = tcp.ack
            packet.seq = tcp.seq
            packet.packet_size = len(tcp.data)
            packet.flags = tcp.flags
            packet.data = tcp.data
            print "Packets Vals: Ack: ", packet.ack, " SEQ: ", packet.seq
            
            syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
            ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0           
            fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
            rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
            psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
#            print "syn, ack", syn_flag, ack_flag
#            urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
#            ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
#            cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0  
            allow, conn_num, state = self.establish_connection(packet)
            
            if allow and syn_flag:
                conn = Connection.Connection()
                conn.num = conn_num
                conn.sip = packet.sip
                conn.dip = packet.dip
                conn.sport = packet.sport
                conn.dport = packet.dport
                conn.spackets += 1
                conn.state = Connection.Connection.SYN
                print "SYN", conn.sip, conn.dip, conn.sport, conn.dport
                conn.s_noAck.append(packet)
                self.active_conns.append(conn)
            elif syn_flag and ack_flag:
                current_connection = self.active_conns[conn_num]
                print current_connection.s_noAck[0].seq
                print packet.ack
                if current_connection.s_noAck[0].seq + 1 == packet.ack:
                    current_connection.dpackets += 1
                    current_connection.state = Connection.Connection.SYN_ACK
                    del current_connection.s_noAck[0]
                    current_connection.d_noAck.append(packet)
                    print "SYN-ACK"
            elif ack_flag and not syn_flag and not allow and state == Connection.Connection.SYN_ACK:
                current_connection = self.active_conns[conn_num]
                print current_connection.d_noAck[0].ack, packet.seq
                if current_connection.d_noAck[0].seq + 1 == packet.ack and current_connection.d_noAck[0].ack == packet.seq:
                    print "here:"
                    current_connection.spackets += 1
                    del current_connection.d_noAck[0]                    
                    current_connection.s_noAck.append(packet)
                    current_connection.state = Connection.Connection.ACK_CONN
                    print "SYN-ACK_ACK"             
            elif not syn_flag and not fin_flag and state == Connection.Connection.ACK_CONN:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    current_connection.s_noAck.append(packet)
                    current_connection.state = Connection.Connection.CONNECTED
                    if not len(packet.data) == 0: 
                        current_connection.sbytes += len(packet.data)
                        print current_connection.sbytes
                elif packet.sip == current_connection.dip:
                    current_connection.spackets += 1
                    if current_connection.s_noAck[0].seq == packet.ack and current_connection.s_noAck[0].ack == packet.seq:
                        del current_connection.s_noAck[0]                    
                        current_connection.d_noAck.append(packet)
                        current_connection.state = Connection.Connection.CONNECTED
                        if not len(packet.data) == 0: 
                            current_connection.dbytes += len(packet.data)
                        print current_connection.dbytes
                
            elif not syn_flag and not fin_flag and state == Connection.Connection.CONNECTED:
                print "Main to hoon pagal"
#                print len(packet.data)
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    print "SIP"
                    current_connection.spackets += 1
                    if not len(packet.data) == 0:
                        current_connection.s_noAck.append(packet)
                    current_connection.sbytes += len(packet.data)                    
                    if not len(current_connection.d_noAck) == 0:
                        print "######",packet.ack, current_connection.d_noAck[0].seq + len(current_connection.d_noAck[0].data)
                        if packet.ack == current_connection.d_noAck[0].seq + len(current_connection.d_noAck[0].data):
                            del current_connection.d_noAck[0]
                        else:
#                            for i in range(1, len(current_connection.d_noAck)):
#                                packet.ack == current_connection.d_noAck[0].seq + len(current_connection.d_noAck[].data)
                            current_connection.d_noAck[:] = []
                    
                elif packet.sip == current_connection.dip:
                    print "DIP"                    
                    current_connection.dpackets += 1
                    if not len(packet.data) == 0:
                        current_connection.d_noAck.append(packet)
#                    current_connection.d_noAck.append(packet)
                    
                    if not len(current_connection.s_noAck) == 0:
                        print "######",packet.ack, current_connection.s_noAck[0].seq + len(current_connection.s_noAck[0].data), current_connection.s_noAck[0].seq, len(current_connection.s_noAck[0].data)
                        if packet.ack == current_connection.s_noAck[0].seq + len(current_connection.s_noAck[0].data):
                            del current_connection.s_noAck[0]
                        else:
                            current_connection.s_noAck[:] = []
                    current_connection.dbytes += len(packet.data)                    
                print len(current_connection.s_noAck), len(current_connection.d_noAck)            
            elif not syn_flag and fin_flag and state == Connection.Connection.CONNECTED:
                print "M"
                current_connection = self.active_conns[conn_num]
                if pack                
#                    if ack_flag and 
#                    current_connection.state = Connection.Connection.CONNECTED
#                    if not len(packet.data) == 0: 
#                        current_connection.sbytes += len(packet.data)
#                        print current_connection.sbytes
                
#                print "Dest: ", self.active_conns[0].dbytes+1, self.active_conns[0].dpackets, "    SRC: ", self.active_conns[0].sbytes+1, self.active_conns[0].spackets 
            print "\n\n"    
                
if __name__ == "__main__":
    filename = sys.argv[1]
    pcapdata = open(filename)
    print sys.argv[2]
    pcap = dpkt.pcap.Reader(pcapdata)
    packet_num = 0
    i = 0
    tcp_conn = TCP_Connection()
    for ts, buf in pcap:
        packet_num += 1
        if type(dpkt.ethernet.Ethernet(buf).data.data) == dpkt.tcp.TCP:
            i = i + 1
#            print "Animesh: ", i
        tcp_conn.process_packet(packet_num, buf)
            
            
    pcapdata.close()