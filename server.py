# Packet sniffer in python for Linux
# Sniffs only incoming TCP packet
import signal
import socket
import sys
from datetime import datetime as dTime
from os import getuid
from struct import *

communications = dict()
duplicated_packet = 1

def bits2string(b=None):
    return ''.join([chr(int(x, 2)) for x in b])

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
        #for a given ip
        value = communications[s_addr]
        i = 0;
        j = 0;
        #calculate and round time
        for date in value:
            if first:
                lastTime = date
                first = False
            else:
                sb = str(round(abs((lastTime - date).total_seconds())))

                #we need list of bit words ( 7th length - 0000000, 0000000...)
                if len(binary) == j:
                    binary.append(sb)
                else:
                    binary[j] = binary[j] + sb

                i += 1
                if i % 7 == 0 and i > 0:
                    j += 1

                #print ("bit: " + sb)
                lastTime = date

    print(binary)
    ascii = bits2string(binary)
    print("EXFILTRATED DATA: " + ascii)

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

    ########## workaround for internal duplicated packets - 127.0.0.1
    if str(s_addr) == "127.0.0.1":
        if duplicated_packet:
            duplicated_packet = 0
            continue
        else:
            duplicated_packet = 1
    ##########

    last = now = dTime.now()
    print('Packet received from: ' + str(s_addr) + " at: " + str(now))

    if str(s_addr) in communications and len(communications[str(s_addr)]) > 0:
        last = communications[str(s_addr)][-1]

    if (now - last).total_seconds() > 10:
        clear_data(str(s_addr))

    if int((now - last).total_seconds()) > 4 and int((now - last).total_seconds()) < 6:
        print('FIN packet noticed for: ' + str(s_addr))
        callculate_offsets(str(s_addr))
        clear_data(str(s_addr))
    else:
        if str(s_addr) in communications:
            communications[str(s_addr)].append(now)
        else:
            communications[str(s_addr)] = [now]

    #print(communications)
