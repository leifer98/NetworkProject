import socket
from scapy.all import *

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)
    print(f"Received message from {addr}")
    data = SCTP(data)
    data.show()
    packet = IP(dst=addr[0]) / UDP(dport=addr[1]) / SCTP(sport=4005,dport=UDP_PORT) / \
             SCTPChunkInitAck()
    send(packet)
