# -*- coding: utf-8 -*-
"""
Created on Mon Apr 10 21:57:41 2017

@author: mihir
"""

class Connection:
    SYN = 0
    SYN_ACK = 1
    ACK_CONN = 2
    CONNECTED = 3
    FIN_S = 4
    FIN_D = 5
    FIN_ACK = 6
    ACK_2 = 7
    ACK_3 = 7.5
    ACK = 8
    END = 9
    RST = 10    
    def __init__(self):
        self.num = -1
        self.sip = ""
        self.dip = ""
        self.sport = 0
        self.dport = 0
        self.spackets = 0
        self.dpackets = 0
        self.sbytes = 0
        self.dbytes = 0
        self.sdup = 0
        self.ddup = 0
        self.state = -1
        self.s_noAck = []
        self.d_noAck = []
        self.smtp = SMTP_mail()

class Packet:
    def __init__(self):
        self.packet_num = 0
        self.sip = ""
        self.dip = ""
        self.sport = 0
        self.dport = 0
        self.packet_size = 0
        self.seq = 0
        self.ack = 0
        self.flags = 0
        self.data = ""
        
class SMTP_mail:
    EHLO = 0
    EHLO_ACK = 1
    INIT = 1
    MAIL_FROM = 2
    AUTH = 2.5
    MAIL_ACCEPT = 3
    AUTH_ACCEPT = 3.5
    RCPT = 4
    RCPT_ACCEPT = 5
    RCPT_MULTI = 5.5
    RCPT_PART_ACCEPT = 6
    DATA = 7
    DATA_ACCEPT = 8
    DOT = 9
    DOT_ACCEPT = 10
    QUIT = 11
    QUIT_ACCEPT = 12    
    def __init__(self):
        self.mail_count = 0
        self.sip = 0
        self.dip = 0
        self.status = -1
        self.ehlo = -1
        self.headers = ""
        self.message = ""
        self.accepted = ""
        self.rec_count = 0
        self.rec_sent = []
        self.rec_acc = 0