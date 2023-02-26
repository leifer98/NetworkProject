import socket
import struct

# Define the DNS query to send
query = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'

# Send the DNS query to the server and receive the response
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    server_address = ('localhost', 53)
    client_socket.sendto(query, server_address)
    response, _ = client_socket.recvfrom(1024)

# Parse the DNS response data
transaction_id = response[:2]
flags = response[2:4]
qdcount = response[4:6]
ancount = response[6:8]
nscount = response[8:10]
arcount = response[10:12]
qname = response[12:24]
qtype = response[-8:-6]
qclass = response[-6:-4]
answer = response[-12:-4]

# Print the response data
print(f"Transaction ID: {struct.unpack('!H', transaction_id)[0]}")
print(f"Answer count: {struct.unpack('!H', ancount)[0]}")
print(f"Query name: {qname}")
print(f"Query type: {struct.unpack('!H', qtype)[0]}")
print(f"Query class: {struct.unpack('!H', qclass)[0]}")
print(f"Answer: {socket.inet_ntoa(answer)}")
# print(f"Answer: {answer}")