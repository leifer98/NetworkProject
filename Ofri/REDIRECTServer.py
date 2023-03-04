import json
import socket
from scapy.all import IP, UDP, Raw

# set the host IP address and server_port number
host = 'localhost'
server_port = 20054

# create a UDP socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# bind the socket to a specific address and server_port
server_socket.bind((host, server_port))

print(f"UDP server is listening on {host}:{server_port}")

while True:
    # receive the packet from the client
    packet_data, client_address = server_socket.recvfrom(1024)

    # parse the packet using Scapy
    packet = IP(packet_data)

    # extract the data from the packet
    client_port = packet[UDP].sport
    data = json.loads(packet[Raw].load)

    # print the extracted data
    print(f"Received data from {client_address}: {data}")

    # send a response back to the client
    server_socket.sendto("Hello from server".encode(), client_address)
    exit(1)
