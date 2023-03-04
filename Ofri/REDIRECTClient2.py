import json
import socket
from scapy.all import IP,UDP,Raw

# set the host IP address and server_port number
host = 'localhost'
server_port = 20054
client_port = 30353
seq = [0]
timeout = 5
# create a UDP packet using Scapy
raw_layer = {
    'RUDP': {
        'seq': seq,
        'timeout': timeout,
        'Version': '1.1',
        'Host': 'the_famous_cat.com'
    },
    'HTTP': {
        'method': 'GET',
        'Path': 'HTTP',
        'Version': '1.1',
        'Host': 'the_famous_cat.com'
    }
}

# create a UDP packet using Scapy
packet = IP(dst=host) / \
         UDP(sport=client_port,dport=server_port) / \
         Raw(load=json.dumps(raw_layer))

# serialize the packet to bytes
packet_bytes = bytes(packet)

# create a UDP socket object
client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client_socket.bind((host,client_port))

# send the packet to the server
client_socket.sendto(packet_bytes,(host,server_port))

# receive the response from the server
response,server_address = client_socket.recvfrom(1024)
print(f"Received response from {server_address}: {response.decode()}")

# close the socket
client_socket.close()
