import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP
from SCTPSocket import SCTPSocket

# Create an instance of the SCTPSocket class


sctpchunktypes = {
    0: "data",
    1: "init",
    2: "init-ack",
    3: "sack",
    4: "heartbeat-req",
    5: "heartbeat-ack",
    6: "abort",
    7: "shutdown",
    8: "shutdown-ack",
    9: "error",
    10: "cookie-echo",
    11: "cookie-ack",
    14: "shutdown-complete",
    15: "authentication",
    0x80: "address-configuration-ack",
    0xc1: "address-configuration",
}

server_port = 30353
client_port = 20054
packet_size = 65536

# Function to check SCTP flags
def check_sctp_flags(pkt):
    if not isinstance(pkt, SCTP):
        print("Not an SCTP packet")
        return

    if pkt.chksum == 0x04:
        print("Packet is a SACK")
    elif pkt.chksum == 0x02:
        print("Packet has the 'Unordered' flag set")
    elif pkt.chksum == 0x01:
        print("Packet has the 'Begining' flag set")
    elif pkt.chksum == 0x80:
        print("Packet has the 'End' flag set")
    else:
        print("Packet has unknown flags set")


# Create a socket and bind to the server port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sctp_socket = SCTPSocket(server_socket, delay = 1)
sctp_socket.bind(('localhost', server_port))
# server_socket.bind(('localhost', server_port))

print(f"Listening on port {server_port}...")
sctp_socket.listen()
data = sctp_socket.recvfrom(packet_size)
print(f"message received: {data}")
sctp_socket.close()
