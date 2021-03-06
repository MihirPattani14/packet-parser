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