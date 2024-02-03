#! /bin/env python3
import socket
from struct import *
import binascii
import textwrap
import subprocess
import json
import base64


combined_data = {
    "socket_data": [{'dest_mac': '45:00:00:2c:b5:cf', 'src_mac': '00:00:40:06:ac:ec', 'eth_proto': 10, 'version': 4, 'header_length': 20, 'ttl': 64, 'proto': 6, 'src_ip': '10.0.2.2', 'dst_ip': '10.0.2.15', 'real_data': b'\xd0B\x1f\x90\x17\x83\x88\x01\x00\x00\x00\x00`\x02\xff\xff\xf0\xbe\x00\x00\x02\x04\x05\xb4'}, {'dest_mac': '45:00:00:28:b5:d0', 'src_mac': '00:00:40:06:ac:ef', 'eth_proto': 10, 'version': 4, 'header_length': 20, 'ttl': 64, 'proto': 6, 'src_ip': '10.0.2.2', 'dst_ip': '10.0.2.15', 'real_data': b'\xd0B\x1f\x90\x17\x83\x88\x02\xc4\xb0O\xfbP\x10\xff\xff\xf3\xbf\x00\x00'}, {'dest_mac': '45:00:00:f1:b5:d1', 'src_mac': '00:00:40:06:ac:25', 'eth_proto': 10, 'version': 4, 'header_length': 20, 'ttl': 64, 'proto': 6, 'src_ip': '10.0.2.2', 'dst_ip': '10.0.2.15', 'real_data': b'\xd0B\x1f\x90\x17\x83\x88\x02\xc4\xb0O\xfbP\x18\xff\xff8\x8b\x00\x00GET / HTTP/1.1\r\nUser-Agent: PostmanRuntime/7.36.0\r\nAccept: */*\r\nPostman-Token: bb967a95-4d3d-4999-ba78-6f4efcd9a9f5\r\nHost: localhost:8080\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n\r\n'}]
        }
modified_data = [{key: json.dumps(value) if isinstance(value,str) else base64.b64encode(value).decode('utf-8') if isinstance(value,bytes)  else value for key,value in item.items()} for item in combined_data]

print(modified_data)
# Define a byte string
byte_string = b"hello world"
byte_string2 = b'\x01\xbb\x8e\xc6\x0f\xf4\xf6\x02<g\x95\x0cP\x18'
test_str = '00:00:40:06:a6:e9'
# Convert the byte string to a string using the decode() method
#encoded_str = base64.b64encode(test_str).decode('utf-8')

# Print the decoded string
#print(encoded_str)
