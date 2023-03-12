from scapy.all import *
import socket
import random

server_port = 30353
# Define a list of servers to load balance between
servers = [
    'https://www.mypets.net.au/wp-content/uploads/2019/05/Turkish-Van-Cat.jpg',  # work
    'https://www.mypets.net.au/wp-content/uploads/2019/05/White-Angora-Cat-1.jpg',  # work
    'https://www.mypets.net.au/wp-content/uploads/2019/05/Birman-Cat1.jpg',  # work
    'https://a.storyblok.com/f/176726/1087x721/81335569ea/turkish-van-cat-food.webp/m/'  # works
    # ,'https://petkeen.com/wp-content/uploads/2021/04/turkish-van_Lea-Rae_Shutterstock-e1619183156872.jpg',
    # 'https://www.catbreedslist.com/uploads/cat-pictures/turkish-van-2.jpg',
    # 'https://excitedcats.com/wp-content/uploads/2020/10/10Turkish-Van.jpg',
    # 'https://www.mypets.net.au/wp-content/uploads/2019/05/Turkish-Van-Cat.jpg',
    # 'https://thecatsite.com/attachments/turkish-van-jpg.181747/',
    # 'https://www.animalfunfacts.net/images/stories/pets/cats/turkish_van_cat_l.jpg',
    # 'https://a.storyblok.com/f/176726/1087x721/81335569ea/turkish-van-cat-food.webp/m/',
    # 'https://web5.lifelearn.com/wp-content/uploads/2011/08/TurkishVan1-300x200.jpg'
]


# Define a function to handle incoming requests and redirect them to the appropriate server
def handle_request(conn, addr):
    request = conn.recv(1024).decode()
    # extract the host address from the request
    host_address = request.split(' ')[3].split('\n')[0]
    if "the_famous_cat.com" in host_address:
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
        print(f"Server started and listening on server_port {server_port}...")
        while True:
            conn, addr = server_socket.accept()
            print(f"Request received from {addr}")
            handle_request(conn, addr)


if __name__ == '__main__':
    start_server()
