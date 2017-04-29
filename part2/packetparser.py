# -*- coding: utf-8 -*-
"""
Created on Wed Apr 12 20:35:58 2017

@author: mihir
"""

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
import subprocess

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
        
    def write_data_file(self, conn_number, s_or_d, data):
        if s_or_d == 's':
            filename = str(conn_number+1)+".initiator"
            f = open(filename, "a")
            f.write(data)
            f.close()
        elif s_or_d == 'd':
            filename = str(conn_number+1)+".responder"
            f = open(filename, "a")
            f.write(data)
            f.close()
    
    def process_packet_from_init(self, packet, current_connection, conn_num):
        current_connection.spackets += 1
        if not len(packet.data) == 0:
            current_connection.s_noAck.append(packet)
        current_connection.sbytes += len(packet.data)                    
        if not len(current_connection.d_noAck) == 0:
            if packet.ack == current_connection.d_noAck[0].seq + len(current_connection.d_noAck[0].data):
                self.write_data_file(conn_num, 'd', current_connection.d_noAck[0].data)                          
                del current_connection.d_noAck[0]
            else:
                flag = 0
                for i in range(1, len(current_connection.d_noAck)):
                    if packet.ack == current_connection.d_noAck[i].seq + len(current_connection.d_noAck[i].data):
                        self.write_data_file(conn_num, 'd', current_connection.d_noAck[i].data)
                        del current_connection.d_noAck[0:i+1]
                        current_connection.ddup = i
                        print "here"
                        flag = 1                                    
                        break
                if flag == 0:
                    print "here"
                    current_connection.ddup = len(current_connection.d_noAck) 
                    current_connection.d_noAck[:] = []
    
    def process_packet_from_resp(self, packet, current_connection, conn_num):
        current_connection.dpackets += 1
        if not len(packet.data) == 0:
            current_connection.d_noAck.append(packet)
        
        if not len(current_connection.s_noAck) == 0:
            if packet.ack == current_connection.s_noAck[0].seq + len(current_connection.s_noAck[0].data):
                self.write_data_file(conn_num, 's', current_connection.s_noAck[0].data)             
                del current_connection.s_noAck[0]
            else:
                flag = 0
                for i in range(1, len(current_connection.s_noAck)):
                    if packet.ack == current_connection.s_noAck[i].seq + len(current_connection.s_noAck[i].data):
                        self.write_data_file(conn_num, 's', current_connection.s_noAck[i].data)
                        del current_connection.s_noAck[0:i+1]
                        current_connection.sdup = i
                        flag = 1
                        break
                if flag == 0:
                    current_connection.sdup = len(current_connection.s_noAck)
                    current_connection.s_noAck[:] = []
        current_connection.dbytes += len(packet.data)
        
    def process_packet(self, packet_num, data):
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if type(ip.data) == dpkt.tcp.TCP:
            print "Packet Num", packet_num
            tcp = ip.data
            packet = Connection.Packet()
            packet.packet_num = packet_num
            packet.sip = src_ip
            packet.dip = dst_ip
            packet.sport = tcp.sport
            packet.dport = tcp.dport
            packet.ack = tcp.ack
            packet.seq = tcp.seq
            packet.packet_size = len(tcp.data)
            packet.flags = tcp.flags
            packet.data = tcp.data
            
            syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
            ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0           
            fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
            rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
            psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
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
                conn.s_noAck.append(packet)
                self.active_conns.append(conn)
            elif syn_flag and ack_flag:
                current_connection = self.active_conns[conn_num]
                if current_connection.s_noAck[0].seq + 1 == packet.ack:
                    current_connection.dpackets += 1
                    current_connection.state = Connection.Connection.SYN_ACK
                    del current_connection.s_noAck[0]
                    current_connection.d_noAck.append(packet)
            elif ack_flag and not syn_flag and not allow and state == Connection.Connection.SYN_ACK:
                current_connection = self.active_conns[conn_num]
                print current_connection.d_noAck[0].ack, packet.seq
                if current_connection.d_noAck[0].seq + 1 == packet.ack and current_connection.d_noAck[0].ack == packet.seq:
                    current_connection.spackets += 1
                    del current_connection.d_noAck[0]                    
                    current_connection.s_noAck.append(packet)
                    current_connection.state = Connection.Connection.ACK_CONN
            elif not syn_flag and not fin_flag and state == Connection.Connection.ACK_CONN:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    if current_connection.d_noAck[0].seq == packet.ack and current_connection.d_noAck[0].ack == packet.seq:
                        del current_connection.d_noAck[0] 
                        current_connection.s_noAck.append(packet)
                        current_connection.state = Connection.Connection.CONNECTED
                        if not len(packet.data) == 0: 
                            current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    if current_connection.s_noAck[0].seq == packet.ack and current_connection.s_noAck[0].ack == packet.seq:
                        del current_connection.s_noAck[0]                    
                        current_connection.d_noAck.append(packet)
                        current_connection.state = Connection.Connection.CONNECTED
                        if not len(packet.data) == 0: 
                            current_connection.dbytes += len(packet.data)
                        print current_connection.dbytes
            
            elif not syn_flag and rst_flag:  
                print " m"
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num)
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num)

            elif not syn_flag and not fin_flag and state == Connection.Connection.CONNECTED:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num)
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num)
                
            elif not syn_flag and fin_flag and state == Connection.Connection.CONNECTED:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num)
                    current_connection.state = Connection.Connection.FIN_S
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num)
                    current_connection.state = Connection.Connection.FIN_D                    
            elif not syn_flag and state == Connection.Connection.FIN_S and not fin_flag:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                elif packet.sip == current_connection.dip:
                    print "here"
                    self.process_packet_from_resp(packet, current_connection, conn_num)

            elif not syn_flag and state == Connection.Connection.FIN_D and not fin_flag:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    current_connection.dbytes += len(packet.data)
            
            elif not syn_flag and state == Connection.Connection.FIN_D and fin_flag:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    current_connection.dbytes += len(packet.data)
                current_connection.state = Connection.Connection.ACK_2

            elif not syn_flag and state == Connection.Connection.FIN_S and fin_flag:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    current_connection.dbytes += len(packet.data)                
                current_connection.state = Connection.Connection.ACK_2

            elif ack_flag and state == Connection.Connection.ACK_2:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    current_connection.dbytes += len(packet.data)
                current_connection.state = Connection.Connection.ACK_3

            elif ack_flag and state == Connection.Connection.ACK_3:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    current_connection.dbytes += len(packet.data)
                current_connection.state = Connection.Connection.END
                
            print  "    SRC: ", self.active_conns[0].sbytes, self.active_conns[0].spackets, "Dest: ", self.active_conns[0].dbytes, self.active_conns[0].dpackets
            print "\n"    
                
if __name__ == "__main__":
    filename = sys.argv[1]
    pcapdata = open(filename)
    print len(sys.argv)
    if(len(sys.argv) == 2):
        print len(sys.argv)
        string = "./packetparse "+filename
#        string = "python print_details.py "+ filename         
        subprocess.call(string, shell=True)
    elif sys.argv[2] == "-t":
        pcap = dpkt.pcap.Reader(pcapdata)
        packet_num = 0
        i = 0
        tcp_conn = TCP_Connection()
        for ts, buf in pcap:
            packet_num += 1
            tcp_conn.process_packet(packet_num, buf)
        for i in range(len(tcp_conn.active_conns)):
            filename = str(i+1)+".meta"
            f = open(filename, "a")
            data_str = "Initiator IP: " + str(tcp_conn.active_conns[i].sip)
            data_str = data_str + "\nResponder IP: " + str(tcp_conn.active_conns[i].dip)
            data_str = data_str + "\nInitiator Port: " + str(tcp_conn.active_conns[i].sport)
            data_str = data_str + "\nResponder Port: " + str(tcp_conn.active_conns[i].dport)
            data_str = data_str + "\nPackets Sent by Initiator: " + str(tcp_conn.active_conns[i].spackets)
            data_str = data_str + "\nPackets Sent by Responder: " + str(tcp_conn.active_conns[i].dpackets)
            data_str = data_str + "\nBytes Sent by Initiator: " + str(tcp_conn.active_conns[i].sbytes)
            data_str = data_str + "\nBytes Sent by Responder: " + str(tcp_conn.active_conns[i].dbytes)
            data_str = data_str + "\nDuplicate Packets Sent by Initiator: " + str(tcp_conn.active_conns[i].sdup)
            data_str = data_str + "\nDuplicate Packets Sent by Responder: " + str(tcp_conn.active_conns[i].ddup)
            data_str = data_str + "\nConnection Ended before EOF: " + str(tcp_conn.active_conns[0].state == Connection.Connection.END)             
            f.write(data_str)
            f.close()
        print tcp_conn.active_conns[0].state == Connection.Connection.END

        pcapdata.close()