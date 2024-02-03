#! /bin/env python3
import socket
from struct import *
import binascii
import textwrap
import subprocess
import json
import base64
#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# AF_INET -> means IPV4 packets
# RAW_Socket
# TCP Protocol
'''
#input_byte = 52 # 110100
input_byte = b'\n\x00\x02\x0f'
#mac_address = ':'.join([input_str[i:i+2] for i in range(0, len(input_str), 2)])
#print((input_byte & 15)* 4)
input_decoded = binascii.hexlify(input_byte).decode()
decimal_ip = socket.inet_ntoa(bytes.fromhex(input_decoded))
#last_version = int(input_decoded,16)
print(decimal_ip)
'''
#command = "ls -la"
#subprocess.call(command, shell=True)
'''

'''

#print(json_data)
print('- ' * 20)
modified_data = [{key: json.dumps(value) if isinstance(value,str) else base64.b64encode(value).decode('utf-8') if isinstance(value,bytes)  else value for key,value in item.items()} for item in json_data]
#modified_data = [{key: value.replace("'", "\"") if isinstance(value, str) else value.decode('utf-8') if isinstance(value, bytes) else value for key, value in item.items()} for item in json_data]

#modified_data = [{key: value.replace("'", "\"") if isinstance(value, str) else value.decode('utf-8',errors='replace').replace("'", "\"") if isinstance(value, bytes) else value for key, value in item.items()} for item in json_data]
print(modified_data)




'''
def decode_bytes_to_str(data):
    if isinstance(data, dict):
        # If the value is a dictionary, iterate through key-value pairs
        for key, value in data.items():
            if isinstance(value, bytes):r: invalid syntax

                # If the value is bytes, decode it to string
                data[key] = value.decode('utf-8', errors='replace')
            elif isinstance(value, (list, dict)):
                # If the value is a nested list or dictionary, recursively decode
                decode_bytes_to_str(value)
    elif isinstance(data, list):
        # If the value is a list, iterate through the elements
        for i, item in enumerate(data):
            if isinstance(item, bytes):
                # If the element is bytes, decode it to string
                data[i] = item.decode('utf-8', errors='replace')
            elif isinstance(item, (list, dict))
                # If the element is a nested list or dictionary, recursively decode
                decode_bytes_to_str(item)
'''
#loaded_data = json.loads(json_data)
'''
modified_data = [{key: value.replace("'", "\"") if isinstance(value, str) else value for key, value in item.items()} for item in json_data]

print(json_data.replace(''))
# Check and decode bytes to string
#decode_bytes_to_str(loaded_data)

# Display the decoded data
#print(loaded_data)
#print(unpack("! 6s",b'\x00\x00\xff\x06T\x13'))
#print(calcsize("! 6s"))
#print(b'4500002811ce'.decode())
'''

'''
my_str = "4500002811ce"
my_str2 = ""
for i in range(0,len(my_str),2):
    my_replace_str = ":".join(my_str[i:i+2])
    print(my_replace_str)
#print(my_str)

while True:
    print(s.recvfrom(65565)) # helps us the receive all data packets in the stream
    #65565 -> max buffer size
'''


