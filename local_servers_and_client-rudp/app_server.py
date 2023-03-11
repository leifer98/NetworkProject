from scapy.all import *
import socket
import random
from SCTPSocket import SCTPSocket

server_port = 30353
# Define a list of servers to load balance between
servers = [
    'http://localhost:30354',  # got cat1.png
    'http://localhost:30355',  # got cat2.png
    'http://localhost:30356',  # got cat3.png
]


# Define a function to handle incoming requests and redirect them to the appropriate server
def handle_request(conn, addr):
    print("started recieving")
    request = conn.recvfrom(1024).decode()
    # extract the host address from the request
    host_adress = request.split('Host: ')[1]
    if "localhost" in host_adress:
        selected_server = random.choice(servers)
        redirect_response = f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {selected_server}\r\n\r\n"
    else:
        redirect_response = "HTTP/1.1 404 Not Found\r\n\r\n"
    print(f"Returning response: {redirect_response} to {addr}")
    conn.sendto(redirect_response.encode(),addr)
    print("ended sending")
    while conn.connected:
        continue
    print("dissconected from client")

    # conn.close()


# Define a function to start the server and listen for incoming connections
def start_server():
    server_socket =  SCTPSocket(packet_size=1024)
    server_socket.bind(('localhost', server_port))
    print(f'Server started and listening on server_port {server_port}...')
    server_socket.listen()
    print("waiting for connection from client...")
    server_socket.accept()
    print(f"Request received from {server_socket.peer_tuple}")
    handle_request(server_socket, server_socket.peer_tuple)
    del server_socket
    start_server()


if __name__ == '__main__':
    start_server()
