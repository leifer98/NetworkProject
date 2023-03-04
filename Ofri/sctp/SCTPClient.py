from scapy.all import *
from SCTPSocket import SCTPSocket

# Create an instance of the SCTPSocket class

# Define the client and server ports
server_port = 30353
client_port = 20054
packet_size = 65536

sctp_socket = SCTPSocket(delay = 1)
sctp_socket.bind(('localhost',client_port))
print(f'sending message!')
sctp_socket.connect(('localhost',server_port))
sctp_socket.sendto(b'11', ('localhost',server_port))
sctp_socket.close()
