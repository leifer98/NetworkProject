import socket
import requests
from PIL import Image
from io import BytesIO
from urllib.parse import urlparse
import urllib.parse
server_port = 30353
client_port = 20054

def send_request(server_address, request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.bind(('localhost',client_port))
        client_socket.connect(server_address)
        client_socket.sendall(request)
        response = client_socket.recv(1024).decode()
        return response


def get_image_data(url):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as img_socket:
        img_socket.connect((url.netloc, 80))
        img_socket.sendall(f'GET {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n'.encode())
        response = img_socket.recv(4096)
        headers = response.split(b'\r\n\r\n')[0]
        content_length = int(headers.split(b'Content-Length: ')[1].split(b'\r\n')[0])
        img_data = response.split(b'\r\n\r\n')[1]
        while len(img_data) < content_length:
            response = img_socket.recv(4096)
            img_data += response
        return img_data


def show_image(img_data):
    img = Image.open(BytesIO(img_data))
    img.show()


def save_image(img_data):
    img = Image.open(BytesIO(img_data))
    img.save('cat.png', format='PNG')


if __name__ == '__main__':
    server_address = ('localhost', server_port)
    request = b'GET / HTTP/1.1\r\nHost: the_famous_cat.com\r\n\r\n'
    response = send_request(server_address, request)
    url = urlparse(response.split(' ')[4].splitlines()[0])
    img_data = get_image_data(url)
    show_image(img_data)
    save_image(img_data)
