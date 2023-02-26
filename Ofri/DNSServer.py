import socket
import struct

# Define a function to handle incoming DNS queries and generate responses
def handle_query(query, addr):
    # Parse the incoming query data
    transaction_id = query[:2]
    flags = query[2:4]
    qdcount = query[4:6]
    qname = query[12:]
    qtype = query[-4:-2]
    qclass = query[-2:]

    # Generate the response data
    response_header = transaction_id + b"\x81\x80" + flags[2:] + b"\x00\x01\x00\x01"  # Set response type and answer count
    response_question = qname + qtype + qclass
    response_answer = struct.pack('!HHHLH4s', 0xc00c, 1, 1, 60, 4, b"\x7f\x00\x00\x01")  # Set the IP address to 127.0.0.1

    # Combine the response data into a single byte string
    response = response_header + response_question + response_answer

    # Send the response back to the client
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.sendto(response, addr)

# Define a function to start the server and listen for incoming queries
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind(('localhost', 53))
        print('Server started and listening on port 53...')
        while True:
            query, addr = server_socket.recvfrom(1024)
            print(f'Query received from {addr}')
            handle_query(query, addr)

if __name__ == '__main__':
    start_server()
