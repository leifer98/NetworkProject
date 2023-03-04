import socket
from scapy.all import *

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

# Send message using scapy
packet = IP(dst=UDP_IP)/UDP(dport=UDP_PORT, sport=4005)/SCTP(sport=4005,dport=UDP_PORT) /\
                   SCTPChunkInit(init_tag=RandInt())
send(packet)

# Receive reply message using socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, 4005))

while True:
    data, addr = sock.recvfrom(1024)
    print(f"Received message:  {addr}")
    data = SCTP(data)
    data.show()
