#!/usr/bin/env/python3
#
# Simple ICMP Traceroute - Jason Wangsadinata
#
# To run:
#   sudo python3 icmp_traceroute.py
#

import argparse
import socket
import struct
import sys
import time

class IcmpTraceroute():

    def __init__(self, src_ip, dst_ip, ip_id, ip_ttl, icmp_id, icmp_seqno):

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_id = ip_id
        self.max_ttl = ip_ttl
        self.ip_ttl = 1
        self.icmp_id = icmp_id
        self.icmp_seqno = icmp_seqno
        self.rtt = None
        self.sending_time = None
        self.rtt_storage = []
        print('ICMP traceroute created')

    def run_traceroute(self):

        # Print the user interface header
        print ("----- Traceroute Statistics -----")

        # Iterate as many times as TTL values
        for ttl in range (1, self.max_ttl + 1):

            # Create ICMP pkt, process response and compute statistics
            src = self.traceroute()

            # Print statistics for this run
            rtts = ' '.join([ str(x) + " ms" for x in self.rtt_storage ])
            print (ttl, " ", "(" + src + ")", rtts)

            # Update variables for next run
            self.ip_id = self.ip_id + 1
            self.icmp_id = self.ip_id + 1
            self.ip_ttl = ttl

            # Clear the rtt_storage
            self.rtt_storage = []

    def traceroute(self):

        # Create packet
        ip_header = self.create_ip_header()
        icmp_header = self.create_icmp_header()
        bin_echo_req = ip_header + icmp_header

        # Create send and receive sockets
        send_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Set IP_HDRINCL flag so kernel does not rewrite header fields
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Set receive socket timeout to 2 seconds
        recv_sock.settimeout(2.0)

        # Do this three times to get three different rtt values
        counter = 0
        while (counter < 3):
            # Send packet to destination
            try:
                self.sending_time = time.time()
                send_sock.sendto(bin_echo_req, (self.dst_ip, 0))
            except OSError as e:
                print('Unable to send packet, exiting')
                exit(0)

            # Receive echo reply (hopefully)
            try:
                [bin_echo_reply, addr] = recv_sock.recvfrom(1024)
                self.rtt = round((time.time() - self.sending_time)*1000.0,3)
            except OSError as e:
                print('No response, exiting')
                exit(0)

            # Extract info from ip_header
            [ip_header_length, ip_identification, ip_protocol,
                    ip_src_addr] = self.decode_ip_header(bin_echo_reply)

            # Extract info from icmp_header
            [icmp_type, icmp_code] = self.decode_icmp_header(
                    bin_echo_reply, ip_header_length)

            # Error checking IP Protocol
            if ip_protocol != 1 :
                # error checking
                print ("IP Protocol is not ICMP, exiting")
                exit(0)

            # Update variables for next iteration of rtt capture
            self.rtt_storage.append(self.rtt)
            counter += 1

        return ip_src_addr

    def create_ip_header(self):

        IP_VER = 4
        MIN_HDR_LEN = 5
        DEFAULT_LEN = 576
        FLAGS_NO_FRAG = 2
        PROTO_ICMP = 1

        # IP header info from https://tools.ietf.org/html/rfc791
        ip_version = IP_VER         # 4 bits
        ip_hdr_len = MIN_HDR_LEN    # 4 bits
        ip_tos = 0                  # 8 bits
        ip_len = DEFAULT_LEN        # 16 bits
        ip_id = self.ip_id          # 16 bits
        ip_flags = FLAGS_NO_FRAG    # 3 bits
        ip_frag_offset = 0          # 13 bits
        ip_ttl = self.ip_ttl        # 8 bits
        ip_proto = PROTO_ICMP       # 8 bits
        ip_checksum = 0             # 16 bits
        ip_src = self.src_ip        # 32 bits
        ip_dst = self.dst_ip        # 32 bits

        # Creating the header using struct.pack in network order
        # & with hexadecimals operator is for error checking
        header = struct.pack('!BBHHHBBH',                           # ! means network order
            ((ip_version & 0x0f) << 4 | (ip_hdr_len & 0x0f)),       # B = unsigned char = 8 bits
            (ip_tos & 0xff),                                        # B = unsigned char = 8 bits
            (ip_len & 0xffff),                                      # H = unsigned short = 16 bits
            (ip_id & 0xffff),                                       # H = unsigned short = 16 bits
            ((ip_flags & 0x07) << 13 | (ip_frag_offset & 0x1fff)),  # H = unsigned short = 16 bits
            (ip_ttl & 0xff),                                        # B = unsigned char = 8 bits
            (ip_proto & 0xff),                                      # B = unsigned char = 8 bits
            (ip_checksum & 0xffff))                                 # H = unsigned short = 16 bits

        # Combining the ip_src and ip_dst
        ip_header = header + socket.inet_aton(ip_src) + socket.inet_aton(ip_dst)          

        return ip_header

    def create_icmp_header(self):

        ECHO_REQUEST_TYPE = 8
        ECHO_CODE = 0

        # ICMP header info from https://tools.ietf.org/html/rfc792
        icmp_type = ECHO_REQUEST_TYPE      # 8 bits
        icmp_code = ECHO_CODE              # 8 bits
        icmp_checksum = 0                  # 16 bits
        icmp_identification = self.icmp_id # 16 bits
        icmp_seq_number = self.icmp_seqno  # 16 bits

        # ICMP header is packed binary data in network order
        icmp_header = struct.pack('!BBHHH', # ! means network order
        icmp_type,           # B = unsigned char = 8 bits
        icmp_code,           # B = unsigned char = 8 bits
        icmp_checksum,       # H = unsigned short = 16 bits
        icmp_identification, # H = unsigned short = 16 bits
        icmp_seq_number)     # H = unsigned short = 16 bits

        return icmp_header

    def decode_ip_header(self, bin_echo_reply):
        # Decode ip_header
        # First 20 bytes of the response will be the IP header
        res = ""
        try:
            res = struct.unpack('!BBHHHBBH4s4s', bin_echo_reply[:20])
        except struct.error as e:
            print ("Error:", e, ", exiting")
            exit(0)

        if len(res) != 10:
            print ("Error: IP header is not of the correct length, exiting")
            exit(0)

        # Checking for using socket.inet_ntoa
        if type(res[8]) != bytes or len(res[8]) != 4:
            print ("Error: Incorrect IP Source address, exiting")
            exit(0)

        # Extract fields of interest
        # & with hexadecimals operator is for error checking
        ip_header_length = (res[0] & 0x0f)
        ip_identification = (res[3] & 0xffff)
        ip_protocol = (res[6] & 0xff)
        ip_src_addr = socket.inet_ntoa(res[8])

        return [ip_header_length, ip_identification,
                ip_protocol, ip_src_addr]

    def decode_icmp_header(self, bin_echo_reply, ip_header_length):
        # Decode icmp_header
        pos = ip_header_length * 4
        res = ""
        try:
            res = struct.unpack('!BBHHH', bin_echo_reply[pos:pos+8])
        except struct.error as e:
            print ("Error:", e, ", exiting")
            exit(0)

        if len(res) != 5:
            print ("Error: ICMP header is not of the correct length")
            exit(0)

        # Extract fields of interest
        # & with hexadecimals operator is for error checking
        icmp_type = (res[0] & 0xff)
        icmp_code = (res[1] & 0xff)

        return [icmp_type, icmp_code]

def main():

    src_ip = '192.168.1.14'   # My IP addr (e.g., IP address of VM)
    dst_ip = '172.16.100.1'   # Dst IP (IP addr behind Wesleyan firewall)
    ip_id = 111               # IP header in wireshark should have
    ip_ttl = 2                # IP TTL
    icmp_id = 222             # ICMP header in wireshark should have
    icmp_seqno = 1            # Starts at 1, by convention

    # Parse command line parameters - for easier testing
    parser = argparse.ArgumentParser()

    parser.add_argument('--src_ip', default=src_ip, help='Source IP address')    
    parser.add_argument('--dst_ip', default=dst_ip, help='Destination IP address')
    parser.add_argument('--ip_id', type=int, default=ip_id, help='IP Identification')
    parser.add_argument('--ip_ttl', type=int, default=ip_ttl, help='IP Maximum TTL')
    parser.add_argument('--icmp_id', type=int, default=icmp_id, help='ICMP Identification')
    parser.add_argument('--icmp_seqno', type=int, default=icmp_seqno, help='ICMP Sequence Number')

    args = parser.parse_args()

    # Create IcmpTraceroute class
    traceroute = IcmpTraceroute(
            args.src_ip, args.dst_ip, args.ip_id, 
            args.ip_ttl, args.icmp_id, args.icmp_seqno)
    traceroute.run_traceroute()

if __name__ == '__main__':
    main()