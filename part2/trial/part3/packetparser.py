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

    def write_smtp_file(self, smtp_conn):
        filename = str(smtp_conn.mail_count) + ".mail"
        f = open(filename, "w")
        data = "Source IP: "+ smtp_conn.sip+"\nDestination IP: "+smtp_conn.dip
        f.write(data)
        if smtp_conn.rec_acc == smtp_conn.rec_count:
            data = "\n\nMessage: Accepted\n"
        else:
            data = "\nMessage: Unaccepted\n"
        f.write(data)
        data = "\nHEADERS\n" + smtp_conn.headers
        f.write(data)
        data = "\nMESSAGE\n"+smtp_conn.message
        f.write(data)
        f.close()            
    
    def process_packet_from_init(self, packet, current_connection, conn_num, argt):
        current_connection.spackets += 1
        if not len(current_connection.s_noAck) == 0:
            for i in range(len(current_connection.s_noAck)):
                if packet.seq == current_connection.s_noAck[i].seq:
                    del current_connection.s_noAck[i:]
                    break
        if not len(packet.data) == 0:
            current_connection.s_noAck.append(packet)
        current_connection.sbytes += len(packet.data)                    
        if not len(current_connection.d_noAck) == 0:
            if packet.ack == current_connection.d_noAck[0].seq + len(current_connection.d_noAck[0].data):
                if argt == "-t":
                    self.write_data_file(conn_num, 'd', current_connection.d_noAck[0].data)                          
                elif argt == "-m":
                    pack = current_connection.d_noAck[0]
                    if pack.sport == 25 or pack.sport == 587 or pack.dport == 25 or pack.dport == 587:
                        self.process_smtp_from_init(pack, current_connection, conn_num)
                elif argt == "-c":
                    self.process_cookies(current_connection.d_noAck[0], current_connection, conn_num)                
                del current_connection.d_noAck[0]
            else:
                flag = 0
                for i in range(1, len(current_connection.d_noAck)):
                    if packet.ack == current_connection.d_noAck[i].seq + len(current_connection.d_noAck[i].data):
                        for j in range(i+1):
                            if argt == "-t":
                                self.write_data_file(conn_num, 'd', current_connection.d_noAck[j].data)                            
                            elif argt == "-m":
                                pack = current_connection.d_noAck[j]
                                if pack.sport == 25 or pack.sport == 587 or pack.dport == 25 or pack.dport == 587:
                                    self.process_smtp_from_init(pack, current_connection, conn_num)
                            elif argt == "-c":
                                self.process_cookies(current_connection.d_noAck[j], current_connection, conn_num)                            
                            
                        del current_connection.d_noAck[0:i+1]
                        current_connection.ddup = i
                        flag = 1                                    
                        break
                if flag == 0:
                    current_connection.ddup = len(current_connection.d_noAck) 
                    current_connection.d_noAck[:] = []
    
    def process_packet_from_resp(self, packet, current_connection, conn_num, argt):
        current_connection.dpackets += 1
        if not len(current_connection.d_noAck) == 0:
            for i in range(len(current_connection.d_noAck)):
                if packet.seq == current_connection.d_noAck[i].seq:
                    del current_connection.d_noAck[i:]
                    break
        if not len(packet.data) == 0:
            current_connection.d_noAck.append(packet)
        
        if not len(current_connection.s_noAck) == 0:
            if packet.ack == current_connection.s_noAck[0].seq + len(current_connection.s_noAck[0].data):
                if argt == "-t":
                    self.write_data_file(conn_num, 's', current_connection.s_noAck[0].data)             
                elif argt == "-m":
                    pack = current_connection.s_noAck[0]
                    if pack.sport == 25 or pack.sport == 587 or pack.dport == 25 or pack.dport == 587:
                        self.process_smtp_from_init(pack, current_connection, conn_num)
                elif argt == "-c":
                    self.process_cookies(current_connection.s_noAck[0], current_connection, conn_num)
                del current_connection.s_noAck[0]
            else:
                flag = 0
                for i in range(1, len(current_connection.s_noAck)):
                    
                    if packet.ack == current_connection.s_noAck[i].seq + len(current_connection.s_noAck[i].data):
                        for j in range(i+1):
                            if argt == "-t":
                                self.write_data_file(conn_num, 's', current_connection.s_noAck[j].data)
                            elif argt == "-m":
                                pack = current_connection.s_noAck[j]
                                if pack.sport == 25 or pack.sport == 587 or pack.dport == 25 or pack.dport == 587:
                                    self.process_smtp_from_init(pack, current_connection, conn_num)
                            elif argt == "-c":
                                self.process_cookies(current_connection.s_noAck[j], current_connection, conn_num)                            
                            
                        del current_connection.s_noAck[0:i+1]
                        current_connection.sdup = i
                        flag = 1
                        break
                if flag == 0:
                    current_connection.sdup = len(current_connection.s_noAck)
                    current_connection.s_noAck[:] = []
        current_connection.dbytes += len(packet.data)
        
    def process_smtp_from_init(self, packet, current_connection, conn_num):
        smtp_conn = current_connection.smtp
        if smtp_conn.ehlo == -1 and ("EHLO" in packet.data or "HELO" in packet.data):
            smtp_conn.ehlo = Connection.SMTP_mail.EHLO
        elif smtp_conn.ehlo == Connection.SMTP_mail.EHLO and "250" in packet.data and smtp_conn.status == -1:
            smtp_conn.ehlo = Connection.SMTP_mail.EHLO_ACK
            smtp_conn.status = Connection.SMTP_mail.INIT
        elif smtp_conn.ehlo == Connection.SMTP_mail.EHLO_ACK:
            if smtp_conn.status == Connection.SMTP_mail.INIT:
                if "AUTH LOGIN" in packet.data:
                    smtp_conn.status = Connection.SMTP_mail.AUTH
            elif smtp_conn.status == Connection.SMTP_mail.AUTH and "235" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.AUTH_ACCEPT
            elif (smtp_conn.status == Connection.SMTP_mail.AUTH_ACCEPT or smtp_conn.status == Connection.SMTP_mail.INIT or smtp_conn.status == Connection.SMTP_mail.DOT_ACCEPT) and "MAIL FROM:" in packet.data:
                if smtp_conn.status == Connection.SMTP_mail.DOT_ACCEPT:
                    self.headers = ""
                    self.message = ""
                    self.accepted = ""
                    self.rec_count = 0
                    self.rec_acc = 0
                smtp_conn.status = Connection.SMTP_mail.MAIL_FROM
                smtp_conn.headers = packet.data
                smtp_conn.sip = packet.sip
                smtp_conn.dip = packet.dip
            elif smtp_conn.status == Connection.SMTP_mail.MAIL_FROM and "250" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.MAIL_ACCEPT
            elif smtp_conn.status == Connection.SMTP_mail.MAIL_ACCEPT and "RCPT TO:" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.RCPT
                smtp_conn.rec_count += 1
                smtp_conn.headers += packet.data                
            elif smtp_conn.status == Connection.SMTP_mail.RCPT or smtp_conn.status == Connection.SMTP_mail.RCPT_MULTI and "250" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.RCPT_ACCEPT
                smtp_conn.rec_acc += 1                 
            elif smtp_conn.status == Connection.SMTP_mail.RCPT_ACCEPT and "RCPT TO:" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.RCPT_MULTI
                smtp_conn.rec_count += 1
                smtp_conn.headers += packet.data                
            elif smtp_conn.status == Connection.SMTP_mail.RCPT_MULTI and "250" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.RCPT_PART_ACCEPT
                smtp_conn.rec_acc += 1
            elif (smtp_conn.status == Connection.SMTP_mail.RCPT_ACCEPT or smtp_conn.status == Connection.SMTP_mail.RCPT_PART_ACCEPT):
                if "DATA" in packet.data:
#                    smtp_conn.headers += "MESSAGE"#packet.data
                    smtp_conn.status = Connection.SMTP_mail.DATA
                elif packet.sip == smtp_conn.sip:
                    smtp_conn.headers += packet.data
            elif smtp_conn.status == Connection.SMTP_mail.DATA and "354" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.DATA_ACCEPT
            elif smtp_conn.status == Connection.SMTP_mail.DATA_ACCEPT and "\r\n.\r\n" not in packet.data:
                smtp_conn.message += packet.data
            elif smtp_conn.status == Connection.SMTP_mail.DATA_ACCEPT and "\r\n.\r\n" in packet.data:
                smtp_conn.message += packet.data.split("\r\n.\r\n")[0]
                smtp_conn.status = Connection.SMTP_mail.DOT
            elif smtp_conn.status == Connection.SMTP_mail.DOT and "250" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.DOT_ACCEPT
                smtp_conn.mail_count += 1
                self.write_smtp_file(smtp_conn)
            elif smtp_conn.status == Connection.SMTP_mail.DOT_ACCEPT and "QUIT" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.QUIT
            elif smtp_conn.status == Connection.SMTP_mail.QUIT and "221" in packet.data:
                smtp_conn.status = Connection.SMTP_mail.QUIT_ACCEPT
                smtp_conn = Connection.SMTP_mail()

    def process_cookies(self, packet, current_connection, conn_num):
        data = packet.data
        if "Set" in data:
            cookie_data = data
            while len(cookie_data) > 0:
                start = cookie_data.find("Set")
#                cookie_data = cookie_data[start:]
                end = cookie_data.find("\r\n")
                filename = str(current_connection.cookie_count + 1) + ".cookie"
                if "Cookie" in cookie_data[start:end+2]:
                    f = open(filename, "w")
                    f.write(cookie_data[start:end+2])
                    current_connection.cookie_count += 1
                    f.close()
                cookie_data = cookie_data[end+2:]
                
                
    def process_packet(self, packet_num, data, argt):
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if type(ip.data) == dpkt.tcp.TCP:
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
#            self.process_cookies(packet, self.active_conns[conn_num], conn_num)
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
                if current_connection.d_noAck[0].seq + 1 == packet.ack and current_connection.d_noAck[0].ack == packet.seq:
                    current_connection.spackets += 1
                    del current_connection.d_noAck[0]                    
                    current_connection.s_noAck.append(packet)
                    current_connection.state = Connection.Connection.ACK_CONN
            elif not syn_flag and not fin_flag and state == Connection.Connection.ACK_CONN:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                    if not len(current_connection.d_noAck) == 0:                    
                        if current_connection.d_noAck[0].seq == packet.ack and current_connection.d_noAck[0].ack == packet.seq:
                            del current_connection.d_noAck[0] 
                    current_connection.s_noAck.append(packet)
                    current_connection.state = Connection.Connection.CONNECTED
                    if not len(packet.data) == 0: 
                        current_connection.sbytes += len(packet.data)
                elif packet.sip == current_connection.dip:
                    current_connection.dpackets += 1
                    if not len(current_connection.d_noAck) == 0:                    
                        if current_connection.s_noAck[0].seq == packet.ack and current_connection.s_noAck[0].ack == packet.seq:
                            del current_connection.s_noAck[0]                    
                    current_connection.d_noAck.append(packet)
                    current_connection.state = Connection.Connection.CONNECTED
                    if not len(packet.data) == 0: 
                        current_connection.dbytes += len(packet.data)
            
            elif not syn_flag and rst_flag:  
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num, argt)
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num, argt)

            elif not syn_flag and not fin_flag and state == Connection.Connection.CONNECTED:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num, argt)
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num, argt)
                
            elif not syn_flag and fin_flag and state == Connection.Connection.CONNECTED:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num, argt)
                    current_connection.state = Connection.Connection.FIN_S
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num, argt)
                    current_connection.state = Connection.Connection.FIN_D                    
            elif not syn_flag and state == Connection.Connection.FIN_S and not fin_flag:
                current_connection = self.active_conns[conn_num]
                if packet.sip == current_connection.sip:
                    current_connection.spackets += 1
                elif packet.sip == current_connection.dip:
                    self.process_packet_from_resp(packet, current_connection, conn_num, argt)

            elif not syn_flag and state == Connection.Connection.FIN_D and not fin_flag:
                current_connection = self.active_conns[conn_num]
                current_connection.spackets += 1
                if packet.sip == current_connection.sip:
                    self.process_packet_from_init(packet, current_connection, conn_num, argt)
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
                                
if __name__ == "__main__":
    filename = sys.argv[1]
    pcapdata = open(filename)
    if(len(sys.argv) == 2):
        string = "./packetparse "+filename
        subprocess.call(string, shell=True)
    elif sys.argv[2] == "-t" or sys.argv[2] == "-m" or sys.argv[2] == "-c":
        pcap = dpkt.pcap.Reader(pcapdata)
        packet_num = 0
        i = 0
        tcp_conn = TCP_Connection()        
        for ts, buf in pcap:
            packet_num += 1
            tcp_conn.process_packet(packet_num, buf, sys.argv[2])
        if sys.argv[2] == "-t":
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
        pcapdata.close()