from scapy.all import *
from scapy.all import IP, sendp, sniff, UDP, Ether, BOOTP, DHCP
DHCP_SERVER_IP = "192.168.1.100"
DNS_SERVER_IP = "192.168.1.200"
DHCP_PORT = 67
DHCP_SERVER_MAC = "00:00:00:00:00:01"

ip_dic = {}  # Dictionary to store the MAC address and the assigned IP address of each client

# DHCP server is a server that assign IP addresses to clients on a network
# DHCP DISCOVER: Client broadcasts that it needs to lease an IP configuration from a DHCP server
# DHCP OFFER: Server broadcasts to offer an IP configuration
# DHCP REQUEST: Client broadcasts to formally ask for the offered IP configuration
# DHCP ACKNOWLEDGE (ACK): Server broadcasts confirming the leased IP configuration


def is_ip_assigned(requested_ip):
    return requested_ip in ip_dic.values()


def generate_ip():
    return "10.100.102." + str(random.randint(27, 255))


def handle_dhcp_discover(packet):
    print("DHCP discover received")

    # Extract the client's MAC address from the DHCP discover packet
    client_mac = packet[Ether].src
    if client_mac in ip_dic:
        print("Client already has an IP address")
        return

    # Generate a random IP address from the pool and check if it's already assigned
    offered_ip = None
    while not offered_ip:
        ip_address = generate_ip()
        if not is_ip_assigned(ip_address):
            offered_ip = ip_address

    # Define the DHCP options to be sent to the client with the ip address genarated
    dhcp_options = [("message-type", "offer"), ("subnet_mask", "255.255.255.0"), ("router", DHCP_SERVER_IP),
                    ("name_server", DNS_SERVER_IP), "end"]
    print(f"Offering IP address {offered_ip} to client {client_mac}")
    time.sleep(1)
    # Send the DHCP offer packet. xid is the ID of the DHCP discover packet
    dhcp_offer = Ether(src=DHCP_SERVER_MAC, dst=client_mac) / \
        IP(src=DHCP_SERVER_IP, dst="255.255.255.255") / UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr=offered_ip, siaddr=DHCP_SERVER_IP, chaddr=client_mac, xid=packet[BOOTP].xid) / \
        DHCP(options=dhcp_options)
    sendp(dhcp_offer)


def handle_dhcp_request(packet):
    # Extract the client's MAC address
    client_mac = packet[Ether].src
    # Extract the client's requested IP address
    requested_ip = packet[DHCP].options[1][1]

    # Check if the requested IP address is available
    if is_ip_assigned(requested_ip):
        print(f"IP address {requested_ip} is not available")
        return
    ip_dic.update({client_mac: requested_ip})
    print(f"Assigning IP address {requested_ip} to client {client_mac}")
    time.sleep(1)
    # send the DHCP ACK packet
    dhcp_ack = Ether(src=DHCP_SERVER_MAC, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src=DHCP_SERVER_IP, dst="255.255.255.255") / \
        UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr=requested_ip, siaddr=DHCP_SERVER_IP, chaddr=client_mac, xid=packet[BOOTP].xid) / \
        DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"), ("router", DHCP_SERVER_IP),
                      ("name_server", DNS_SERVER_IP), "end"])
    sendp(dhcp_ack)
    print("Current dic is: ")
    print(ip_dic)
    print("Sent ack. waiting for next packet...")


def handle_dhcp(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP discover
        handle_dhcp_discover(packet)
    if DHCP in packet and packet[DHCP].options[0][1] == 3:  # DHCP request
        handle_dhcp_request(packet)


if __name__ == '__main__':
    # Start sniffing for DHCP packets
    print("Starting DHCP server")
    sniff(
        filter=f"udp and dst port 67", iface="Ethernet", prn=handle_dhcp)
