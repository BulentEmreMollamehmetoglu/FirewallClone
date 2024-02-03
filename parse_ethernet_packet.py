#! /bin/env python3
import struct
import sys
import socket
import binascii
import textwrap
import threading
import requests
import subprocess
import json
import socketserver
import http.server
import queue
import base64
#The form '!' represents the network byte order which is always big-endian as defined in IETF RFC 1700.
# docs from https://docs.python.org/3/library/struct.html
# ------ print(pack("! 6s 6s 2s", 1,2.2,3))
#def ethernet_packet(data):

# TAB CONSTANTS

TAB_data = lambda num: " "*num
TAB_t_data = lambda num: "\t"*num + "- "
TAB_t_data_multi_line = lambda num: "\t"*num
'''
We want to display the values like

Ethernet
    IPV4
        Data afkmwafla
        adawd
        TCP
            Data alfkwam
            alfmwakla

'''

#We need to share information between threads. Threads share the same memory space, so we can use a shared variable or a queue to pass data between them.
data_queue = queue.Queue() # global queue variable for communication between threads

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):

        if not data_queue.empty():
            # Get the latest data from the queue
            socket_data = data_queue.get_nowait()

            # Combine socket data with additional data
            combined_data = {
                "socket_data": socket_data
                    }
            #json_data = json.dumps(combined_data).encode("utf-8",errors="replace")
            modified_data = [{key: json.dumps(value) if isinstance(value,str) else base64.b64encode(value).decode('utf-8') if isinstance(value,bytes)  else value for key,value in item.items()} for item in combined_data["socket_data"]]
            json_bytes = json.dumps(modified_data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", len(json_bytes))
            self.end_headers()
            #AttributeError: 'str' object has no attribute 'items'

            # Send the JSON data as the response
            self.wfile.write(json_bytes)


        else:
            # If there's no socket data, respond with only the default message
            data = {"message": "Hello, this is JSON data!"}
            json_data = json.dumps(data).encode("utf-8")

            # Set headers to indicate JSON content
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", len(json_data))
            self.end_headers()

            # Send the JSON data as the response
            self.wfile.write(json_data)
def run_http_server():
    #command = "python3 -m http.server 8080"
    #subprocess.call(command, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    handler = MyHandler
    port = 8080
    httpd = socketserver.TCPServer(("", port), handler)

    socket_thread = threading.Thread(target=run_socket, args=(data_queue,))


    httpd.serve_forever()

    socket_thread.join()
    do_GET()

def run_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    data_list = [] # the values that will be added to global queue.
    data_list_for_if = []
    while True:
        raw_data,addr = s.recvfrom(65565) # waits for any incoming data and takes the data (i mean ethernet packets not the case other packets should as well be taken)
        #ethernet_frame(raw_data)
        dest_mac,src_mac,eth_proto,data = ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print(TAB_t_data(1) + "Destination MAC: {}, Source MAC: {}, Protocol : {}".format(src_mac,dest_mac,eth_proto))
        #version, header_length ,ttl,proto, src_ip, dst_ip, real_data = ipv4_packets(raw_data) # data?

        #if eth_proto == 8: # means we are using standart internet protocol
        version, header_length ,ttl,proto , src_ip, dst_ip, real_data = ipv4_packets(raw_data)


        print(TAB_t_data(1) + "IPv4 Packet: ")
        print(TAB_t_data(2) + "Version : {}, Header Length : {}, TTL : {}".format(version, header_length ,ttl))
        print(TAB_t_data(2) + "IPv4 Protocol : {}, Source IP: {}, Destination IP : {}".format(proto , dst_ip, src_ip))
        # Before printing the ipv4 data how we know which data is it? (TCP,UDP or ICMP)
        # ICMP is internet control message protocol. It is created mostly with pings. When you ping another network device, the ping program will generate an ICMP packet
        data_list.append({
            "dest_mac": dest_mac,
            "src_mac": src_mac,
            "eth_proto": eth_proto,
            "version": version,
            "header_length": header_length,
            "ttl": ttl,
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip
            #"real_data": real_data
        })

        data_queue.put(data_list)
        if proto == 1: # This indicates that packet is icmp packet
            icmp_type, code, checksum = icmp_packets(data)
            data_list_for_if.append({
                    "icmp_type": icmp_type,
                    "code": code,
                    "checksum": checksum
                    })

            print(TAB_t_data(2) + "ICMP Packets: ")
            print(TAB_t_data(2) + "ICMP Type : {}, Type : {}, Code : {}",format(icmp_type, code, checksum))
            print(TAB_t_data(2) + "Data: ")
            print(TAB_t_data(3) + data)
        elif proto == 6: # This indicates that packets is TCP Packet
            src_port, dst_port,sequence, acknowledgement, flag_urg , flag_ack , flag_psh , flag_rst, flag_syn , flag_fin , tcp_data = tcp_packets(data)
            data_list_for_if.append({
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "sequence": sequence,
                    "acknowledgement": acknowledgement,
                    "flag_urg": flag_urg,
                    "flag_ack": flag_ack,
                    "flag_psh": flag_psh,
                    "flag_rst": flag_rst,
                    "flag_syn": flag_syn,
                    "flag_fin": flag_fin,
                    "tcp_data": tcp_data
                    })

            print(TAB_t_data(2) + "TCP Packets: ")
            print(TAB_t_data(2) + "Source Port : {}, Destination Port : {}, Sequence : {}, Acknowledgement: {}".format(src_port, dst_port,sequence, acknowledgement))
            print(TAB_t_data(2) + "Flags: ")
            print(TAB_t_data(3) + "URG : {} , ACK : {} , PSH : {} , RST: {}, SYN : {} , FIN : {}".format(flag_urg , flag_ack , flag_psh , flag_rst, flag_syn,flag_fin))
            print(TAB_t_data(2) + "TCP Data: ")
            returned_str = format_multi_line(TAB_t_data(3),tcp_data)
            print(returned_str)
            '''
            try:
                decoded_byte_data = tcp_data.decode('utf-8',errors='replace')
                print(TAB_t_data(3) + decoded_byte_data)
            except UnicodeDecodeError as e:
                # Handle the decoding error
                print(f'Error decoding byte data: {e}')
            '''
        elif proto == 17 : #This indicates that packets is UDP Packets
            src_port,dst_port,size,udp_data = udp_packets(data)
            data_list_for_if.append({
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "size": size,
                    "udp_data": udp_data

                    })

            print(TAB_t_data(2) + "UDP Packets: ")
            print(TAB_t_data(3) + "Source Port : {}, Destination Port : {}, Size : {}, Data: {}".format(src_port,dst_port,size,udp_data))
        #else:
            print("Data :")
            print(raw_data)
        #print("DST_MAC: {} \t SRC_MAC: {} \t PROTO: {} \n Data : {} \n******* SRC_IP_ADDR: {} \t DST_IP_ADDR: {}".format(dest_mac,src_mac,proto,data,dst_ip,src_ip))
            # Wait for threads to finish

def main():
    #command = "python3 -m http.server 8080"
    #subprocess.call(command, shell=True,stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL) # silent
    #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    http_server_thread = threading.Thread(target=run_http_server)
    socket_thread = threading.Thread(target=run_socket)

    # Start the threads
    http_server_thread.start()
    socket_thread.start()

    # Wait for threads to finish
    http_server_thread.join()
    socket_thread.join()

# Unpack the ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto = struct.unpack("! 6s 6s H",data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac), socket.htons(proto), data[14:] # htons what signifies in? -> it translates the short byte order to internet packet frame order.

# Return properly formatted MAC Addresses
def get_mac_addr(bytes): # b'4500002811ce'
    byte_string = binascii.hexlify(bytes).decode()
    return ':'.join([byte_string[i:i+2] for i in range(0,len(byte_string),2)])
    # map('{:02x}.format',byte_string) #  in there x means -> hexadecimal format for hexadecimals.

def ipv4_packets(data):
    version_header_length = data[0] # it means very first bit of data is header_length -> equals 1 byte / 8 bits.
    #print("version_header_length :")
    #print(version_header_length)
    # how we can extract the version in version_header_length -> with bitwise operations
    # if we shift this out with 4 bits then in the version_header_length the header_length parth will be shifted away.
    version = version_header_length >> 4 # bitwise operation (shift)
    #print("version :")
    #print(version)
    #In bitwise AND operations, using 15 (binary 1111) allows you to selectively keep the lower 4 bits of a binary value while setting the higher bits to 0
    header_length = (version_header_length & 15) * 4 # 15 in binary -> 1111 we do that because the very first byte of version header length is version and it the represented with 4 bytes.
    #print("header_length : ")
    #print(header_length)
    # so we get rid of the version part of this section and multiplying by 4 means -> convert it this decimal number to the bytes again.
    # note : the real data comes after the header_length so in order the get acutal data you need to write data[header_length:]
    ttl,protocol,src,target = struct.unpack("! 8x B B 2x 4s 4s",data[:20])
    #print("TTL: {} \t Proto: {} \t SRC: {} \n TARGET : {} ".format(ttl,proto,src,target))
    return version, header_length ,ttl,protocol,get_ipv4(src),get_ipv4(target), data[header_length:]
    #
    '''
    !: Indicates network byte order (big-endian).
    8x: Skips 8 bytes (used for padding). -> means 64 bits. So first 2 rows.
    B B: Unpacks two unsigned bytes (8 bits each). -> ttl and protocol.
    2x: Skips 2 bytes (more padding). -> skips header checksum.
    4s 4s: Unpacks two groups of 4 bytes each as strings. -> source and destination ip
    '''

'''
EXAMPLE OUTPUT :
version_header_length :
69
version :
4
header_length :
20
TTL: 255         Proto: 6        SRC: b'\x8e\xfb\x8d$'
 TARGET : b'\n\x00\x02\x0f'

'''
def get_ipv4(ip_data):
    #byte_string = binascii.hexlify(ip_data).decode()
    #return socket.inet_ntoa(bytes.fromhex(byte_string))
    return socket.inet_ntoa(ip_data)

def icmp_packets(data):
    icmp_type, code, checksum = struct.unpack("! B B H",data[:4])
    return icmp_type, code, checksum , data[4:]


def tcp_packets(data):
    src_port, dst_port,sequence, acknowledgement, offset_reserverd_flags = struct.unpack("! H H L L H",data[:14])
    offset = (offset_reserverd_flags >> 12) * 4
    flag_urg = (offset_reserverd_flags & 32) >> 5
    flag_ack = (offset_reserverd_flags & 16) >> 4
    flag_psh = (offset_reserverd_flags & 8) >> 3
    flag_rst = (offset_reserverd_flags & 4) >> 2
    flag_syn = (offset_reserverd_flags & 2) >> 1
    flag_fin = (offset_reserverd_flags & 1)
    return src_port, dst_port,sequence, acknowledgement, flag_urg , flag_ack , flag_psh , flag_rst, flag_syn , flag_fin , data[offset:] # last part is your tcp header aka actual data

def udp_packets(data):
    src_port,dst_port,size = struct.unpack("! H H 2x H",data[:8])
    return src_port,dst_port,size , data[8:]

def format_multi_line(prefix,string,size=80):
    size -=len(prefix)
    if isinstance(string,bytes):
        string = ''.join(r'x{:02x}'.format(byte) for byte in string) # this part takes each part of byte_string and joins these strings together into one string.
        if size %2 :
            size-=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])


if __name__ == '__main__':
    main()

