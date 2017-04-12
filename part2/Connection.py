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
    FIN_1 = 4
    ACK_1 = 5
    FIN_ACK = 6
    ACK_2 = 7
    ACK = 8    
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
        self.sip = ""
        self.dip = ""
        self.sport = 0
        self.dport = 0
        self.packet_size = 0
        self.seq = 0
        self.ack = 0
        self.flags = 0
        self.data = ""