# -*- coding: utf-8 -*-
"""
Created on Mon Apr 10 21:28:07 2017

@author: mihir
"""

import dpkt
import Connection

class wtf:
    def __init__(self):
        self.tlist = []
        
    def something(self, i):
        p = Connection.Packet()
        p.ack = i
        self.tlist.append(p)

if __name__ == "__main__":
    w = wtf()    
    for i in range(3):
        w.something(i)
    for i in range(3):
        print w.tlist[i].ack