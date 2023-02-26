import socket
import random

# Define a list of servers to load balance between
servers = ['http://server1.com', 'http://server2.com', 'http://server3.com']

# Define a function to handle incoming requests and redirect them to a randomly selected server
def handle_request(conn, addr):
    selected_server = random.choice(servers)
    redirect_response = f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {selected_server}\r\n\r\n"
    conn.sendall(redirect_response.encode())
    conn.close()

# Define a function to start the server and listen for incoming connections
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 8000))
        server_socket.listen()
        print('Server started and listening on port 8000...')
        while True:
            conn, addr = server_socket.accept()
            print(f'Request received from {addr}')
            handle_request(conn, addr)

if __name__ == '__main__':
    start_server()
