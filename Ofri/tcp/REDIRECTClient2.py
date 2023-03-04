import socket
import requests
from PIL import Image
from io import BytesIO


server_port = 30353
client_port = 20054
server_address = ('localhost', server_port)

def show_img(url):
    print(url)
    response = requests.get(url)
    img_bytes = BytesIO(response.content)
    # print(img_bytes.getvalue())
    img = Image.open(img_bytes)
    img.show()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.bind(('localhost',client_port))
    client_socket.connect(server_address)
    request = b'GET / HTTP/1.1\r\nHost: the_famous_cat.com\r\n\r\n'
    client_socket.sendall(request)
    response = client_socket.recv(1024).decode()
    print(response)
    url = response.split(' ')[4].splitlines()[0]
    show_img(url)

