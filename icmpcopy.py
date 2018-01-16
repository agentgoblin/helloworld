#!/usr/bin/env python3

import socket
import struct
import sys

MAGICMAGIC = 0xC05E
MAGICINVERSE = ~MAGICMAGIC & 0xFFFF

ICMP_ECHO_REQEST = 8
ICMP_ECHO_REPLY = 0

def usage():
    usageInfo = '''
icmpcopy - copy files via icmp
Usage:
    Receive data and place to file:
        icmpcopy <filename>

    Read from file and send via icmp:
        icmpcopy <address> <filename>
'''
    print(usageInfo)

def calculateSum(packet):
    '''Calculate 16-bit one's complement sum for packet
    '''
    aligning = len(packet) % 4  # RFC729: If the total length is odd, the received data
    packet += b'\x00' * aligning # is padded with one octet of zeros for computing the checksum.
    MOD = 1 << 16
    checksum = 0
    for i in range(0, len(packet), 2):
        num = (packet[i] << 8) + packet[i+1]
        checksum += num
        if checksum >= MOD:
            checksum = (checksum + 1) % MOD
    return ~checksum & 0xFFFF

def icmppacket(data, seq, identifier=MAGICMAGIC):
    '''Make ICMP packet
    '''
    icmpType = ICMP_ECHO_REQEST
    icmpCode = 0
    checksum = 0
    packetData = struct.pack('!'+str(len(data))+'s', data) if len(data) != 0 else b''
    packetEmptyChecksum = struct.pack('!BBHHH', icmpType, icmpCode, checksum, identifier, seq) + packetData
    checksum = calculateSum(packetEmptyChecksum)
    return struct.pack('!BBHHH', icmpType, icmpCode, checksum, identifier, seq) + packetData

def icmpparse(rawPacket):
    '''Parse received ICMP packet
    '''
    # FIXME: Naive realisation - work right only for ICMP ECHO packets
    unpacked = struct.unpack('!BBHHH', rawPacket[:8])
    packet = {}
    packet['icmpType'] = unpacked[0]
    packet['icmpCode'] = unpacked[1]
    packet['checksum'] = unpacked[2] # TODO: Check checksum
    packet['identifier'] = unpacked[3]
    packet['sequence'] = unpacked[4]
    packet['data'] = rawPacket[8:]
    return packet

def icmpsend(host, filename, size=256):
    '''Send file via ICMP
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as src:
        src.settimeout(10)
        src.bind(('', 0))
        src.sendto(icmppacket('', 0, identifier=MAGICINVERSE), (host, 0))
        seq = 1
        with open(filename, 'rb') as srcfile:
            while True:
                data = srcfile.read(size)
                if len(data) == 0:
                    break
                src.sendto(icmppacket(data, seq), (host, 0))
                seq += 1
        src.sendto(icmppacket('', seq, identifier=MAGICINVERSE), (host, 0))

def icmprecv(filename):
    '''Receive file via ICMP
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as dest:
        dest.settimeout(1)
        dest.bind(('localhost', 0))
        session = False # Used for transmission control
        print('ok, listen')
        with open(filename, 'wb') as dstfile:
            while True:
                try:
                    rawPacket, address = dest.recvfrom(1500)
                    packet = icmpparse(rawPacket[20:]) # Avoid 20 bytes of IP header
                    if packet['icmpType'] == ICMP_ECHO_REQEST:
                        print('ICMP echo request get')
                        if packet['identifier'] == MAGICINVERSE:
                            print('Inverse magic found')
                            if not session:
                                print('New session established')
                                session = True
                                continue
                            else:
                                print('Session close')
                                break
                        if packet['identifier'] == MAGICMAGIC and session:
                            print('Magic found. Write data to file')
                            dstfile.write(packet['data']) # TODO: Check sequence before writing
                except socket.timeout:
                    pass

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()

    if len(sys.argv) == 2:
        icmprecv(sys.argv[1])

    if len(sys.argv) == 3:
        icmpsend(sys.argv[1], sys.argv[2])
