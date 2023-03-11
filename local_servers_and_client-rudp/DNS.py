from scapy.all import *
from scapy.all import DNS, DNSRR, IP, sendp, sniff, UDP, Ether
DNS_SERVER_IP = "192.168.1.200"
DNS_SERVER_PORT = 53
DNS_MAC_ADDRESS = "00:00:00:00:00:02"
domains_list = [("the_famous_cat.com.", "127.0.0.1"),
                ("www.google.com.", "8.8.8.8")]


def check_domain_name(domain_name):
    for domain in domains_list:
        if domain_name == domain[0]:
            return domain[1]
    return None


def handle_dns_request(packet):
    print("DNS request received")
    domain_ip = check_domain_name(packet[DNS].qd.qname.decode("utf-8"))
    if domain_ip is None:  # domain not found -- return error code 3
        dns_response = Ether(src=DNS_MAC_ADDRESS, dst="ff:ff:ff:ff:ff:ff") / \
            IP(src=DNS_SERVER_IP, dst=packet[IP].src) / \
            UDP(sport=DNS_SERVER_PORT, dport=packet[UDP].sport) / \
            DNS(id=packet[DNS].id, qr=1, aa=1, rcode=3,
                qd=packet[DNS].qd)
    else:  # domain found -- return domain ip
        dns_response = Ether(src=DNS_MAC_ADDRESS, dst="ff:ff:ff:ff:ff:ff") / \
            IP(src=DNS_SERVER_IP, dst=packet[IP].src) / \
            UDP(sport=DNS_SERVER_PORT, dport=packet[UDP].sport) / \
            DNS(id=packet[DNS].id, qr=1, aa=1,
                qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=domain_ip))
    sendp(dns_response)
    print("DNS response sent. waiting for next request...")


if __name__ == '__main__':
    print(
        f"Starting DNS server on IP {DNS_SERVER_IP} and port {DNS_SERVER_PORT}")
    sniff(
        filter=f"udp dst port 53 and ip dst {DNS_SERVER_IP}",iface=conf.iface, prn=handle_dns_request)
