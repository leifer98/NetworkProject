from scapy.all import *
import socket
import random

server_port = 30353
# Define a list of servers to load balance between
servers = [
    'http://localhost:30354',  # got cat1.png
    'http://localhost:30355',  # got cat2.png
    'http://localhost:30356',  # got cat3.png
]


# Define a function to handle incoming requests and redirect them to the appropriate server
def handle_request(conn, addr):
    request = conn.recv(1024).decode()
    # extract the host address from the request
    host_adress = request.split('Host: ')[1]
    if "localhost" in host_adress:
        selected_server = random.choice(servers)
        redirect_response = f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {selected_server}\r\n\r\n"
    else:
        redirect_response = "HTTP/1.1 404 Not Found\r\n\r\n"
    print(f"Returning response: {redirect_response} to {addr}")
    conn.sendall(redirect_response.encode())
    conn.close()


# Define a function to start the server and listen for incoming connections
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', server_port))
        server_socket.listen()
        print(f'Server started and listening on server_port {server_port}...')
        while True:
            conn, addr = server_socket.accept()
            print(f"Request received from {addr}")
            handle_request(conn, addr)


if __name__ == '__main__':
    start_server()
