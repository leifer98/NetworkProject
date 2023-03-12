import time
import random
import socket
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import *
from PIL import Image
from io import BytesIO
from urllib.parse import urlparse
from SCTPSocket import SCTPSocket

IFACE = conf.iface
client_mac = ""
APP_SERVER_P = 30353
CLIENT_P = 20054
APP_SERVER_ADDR = "the_famous_cat.com"

def generate_random_mac():
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def get_dns_ip():  # Get the DNS server IP address from the DHCP server
    # create dhcp discover packet
    dhcp_discover = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0", dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / BOOTP(chaddr=client_mac, xid=RandInt()) / \
        DHCP(options=[("message-type", "discover"),
                      ("requested_addr",
                       "0.0.0.0"),
                      "end"])
    # Send the DHCP discover packet and wait for a response
    temp_ip = ""
    count = 0
    discover_received = False
    while not discover_received:
        sendp(dhcp_discover)
        time.sleep(1)
        print("DHCP discover sent, waiting for offer...")
        for packet in sniff(filter="udp and dst port 68 ",iface=IFACE, timeout=1, count=1):
            if (DHCP in packet) and (packet[DHCP].options[0][1] == 2):
                temp_ip = packet[BOOTP].yiaddr
                discover_received = True
                dns_server = next(
                    (x[1] for x in packet[DHCP].options if x[0] == "name_server"), None)
                print("DHCP offer received, IP address is " +
                      temp_ip + ", DNS server is " + dns_server)
                break
        count += 1
        if count == 3:
            print("No DHCP offer received")
            return None, None

    # Define the DHCP request packet
    print(temp_ip)
    dhcp_request = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
        BOOTP(chaddr=client_mac, xid=RandInt()) / \
        DHCP(options=[("message-type", "request"),
                      ("requested_addr", temp_ip),
                      "end"])

    # Send the DHCP request packet and wait for a response
    offer_received = False
    while not offer_received:
        sendp(dhcp_request)
        time.sleep(1)
        # print(dhcp_request.summary)
        print("DHCP request sent, waiting for ack...")
        for packet in sniff(filter="udp and dst port 68 ",iface=IFACE, timeout=1, count=1):
            if DHCP in packet and packet[DHCP].options[0][1] == 5:  # DHCP ACK
                offer_received = True
                break

    # Extract the assigned IP address and DNS server address from the DHCP offer packet
    offered_ip = packet[BOOTP].yiaddr
    conf.ip = offered_ip  # Set the IP address to use
    return dns_server, offered_ip


# Get the IP address of the requested domain name from the DNS server
def get_app_ip(domain_name, dns_server):
    # create DNS request packet
    dns_request = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="127.0.0.1", dst=dns_server) / UDP(
        sport=20534, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain_name))
    # Send the packet and wait for a response
    sendp(dns_request)
    response_received = False
    while not response_received:
        for packet in sniff(filter=f"udp src port 53 and ip src {dns_server}",iface=IFACE, timeout=1, count=1):
            if DNS in packet and packet[DNS].rcode == 3:  # DNS error
                print("Domain name not found")
                return None
            if DNS in packet and packet[DNS].ancount > 0:
                response_received = True
                break
    return packet[DNS].an.rdata


def send_request(server_address, request):
    # change parmameters to print more or less data, and to change packet loss,
    # default packet loss is -1 which means no packet loss
    client_socket = SCTPSocket(packet_size=1024, pkt_printer=True, cc_printer=True, packet_loss=0.2)
    client_socket.bind(('localhost', CLIENT_P))
    client_socket.connect(server_address)
    client_socket.sendto(request)
    response = client_socket.recvfrom(1024).decode()
    print(response)
    client_socket.close()
    return response


def get_image_data(url):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as img_socket:
        img_socket.connect((url.netloc, 80))
        img_socket.sendall(
            f'GET {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n'.encode())
        response = img_socket.recv(4096)
        headers = response.split(b'\r\n\r\n')[0]
        content_length = int(headers.split(
            b'Content-Length: ')[1].split(b'\r\n')[0])
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
    random_name = str(random.randint(0, 1000000))
    img.save(f'cat{random_name}.png', format='PNG')


def get_img_from_local_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    # send http get request
    s.send(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    # receive all image data
    data = b''
    s.settimeout(2)
    while True:
        try:
            part = s.recv(1024)
            data += part
        except:
            if data == b'': continue
            else: break
    s.close()
    return data


def get_img_and_show(app_ip):
    request = b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
    response = send_request((app_ip, APP_SERVER_P), request)
    url = urlparse(response.split('\r\n')[1].split(' ')[1])
    h = url.netloc.split(':')[0]
    p = url.netloc.split(':')[1]
    # from here change to clientttt!!!!!
    print((h,p))
    img_data = get_img_from_local_server(h, p)
    print(f'got {len(img_data)} bytes')
    show_image(img_data)
    save_image(img_data)
    print("saved image to curent directory")


if __name__ == "__main__":
    """
    In test 3 we test the congection control. 
    We change the packet loss of the socket to 0.2(you may change in line 109), and we show the image if the transfer is succssesful.
    
    Make sure to run first app_server and multi-server.
    """
    client_mac = generate_random_mac()
    app_ip = "127.0.0.1"
    get_img_and_show(app_ip)
    time.sleep(1)
    print("Test3 passed successfuly")
