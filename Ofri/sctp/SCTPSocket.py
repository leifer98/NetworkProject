import random
import socket
import time

from scapy.all import *


class SCTPSocket:

    def __init__(self,sock=None,a_rwnd=1,n_out_streams=1,n_in_streams=1,
                 packet_size=1024,peer_tsn=0,sent_packets={},received_packets={},
                 acknowledged_packets={},cwnd=1,ssthresh=1,rtt=0,rtt_var=0,congestion_event=False,
                 peer_rwnd=0,local_rwnd=0,in_flight=[], delay = 0):

        self.a_rwnd = a_rwnd
        self.n_out_streams = n_out_streams
        self.n_in_streams = n_in_streams
        self.connected = False
        self.addr = 'localhost'
        self.port = RandInt() + 3000
        self.packet_size = packet_size
        self.peer_tsn = 0
        self.local_tsn = random.randint(1,999999)
        self.sent_packets = sent_packets
        self.received_packets = received_packets
        self.acknowledged_packets = acknowledged_packets
        self.cwnd = cwnd
        self.ssthresh = ssthresh
        self.rtt = rtt
        self.rtt_var = rtt_var
        self.congestion_event = congestion_event
        self.peer_rwnd = peer_rwnd
        self.local_rwnd = local_rwnd
        self.in_flight = in_flight
        self.peer_tuple = None
        self.delay = delay
        self.seq = 0
        self.data_buffer = ""

        if sock is None:
            self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        else:
            self.socket = sock

    def bind(self,tuple):
        self.addr = tuple[0]
        self.port = tuple[1]
        self.socket.bind(tuple)

    def connect(self, tuple):
        self.handshake(tuple)
        self.peer_tuple = tuple

    def listen(self):
        self.receive_handshake(self.packet_size)

    def close(self):
        if self.connected:
            self.shutdown(self.peer_tuple)
        self.socket.close()

    def sendto(self,payload,tuple = None):
        if tuple is None:
            tuple = self.peer_tuple
        if not self.connected:
            self.connect(tuple)
        self.send_data(payload, tuple)
        # self.shutdown(tuple)


    def recvfrom(self,packet_size = 1024):
        if not self.connected:
            self.receive_handshake(packet_size)
        print("waiting for data")
        while True:
            data,addr = self.socket.recvfrom(packet_size)
            pkt = SCTP(data)
            if pkt.haslayer(SCTPChunkData):
                self.parse_data_packet(pkt[SCTPChunkData])
                sctp_pkt_ack = self.create_data_ack_packet(pkt, addr)
                send(sctp_pkt_ack,verbose=False,inter=self.delay)
                self.data_buffer += pkt[SCTPChunkData].data.decode()
            elif pkt.haslayer(SCTPChunkShutdown):
                self.parse_shutdown_packet(pkt[SCTPChunkShutdown])
                sctp_pkt_ack = self.create_shutdown_ack_packet(pkt,addr)
                send(sctp_pkt_ack,verbose=False,inter=self.delay)
                return self.data_buffer

    def handshake(self,tuple):
        sctp_pkt = self.create_init_packet(tuple)
        send(sctp_pkt, verbose=False,inter=self.delay)
        while True:
            data,addr = self.socket.recvfrom(self.packet_size)
            pkt = SCTP(data)
            if pkt.haslayer(SCTPChunkInitAck):
                self.parse_init_ack_packet(pkt[SCTPChunkInitAck])
                self.connected = True
                break

    def receive_handshake(self,packet_size):
        while True:
            data,addr = self.socket.recvfrom(packet_size)
            pkt = SCTP(data)
            if pkt.haslayer(SCTPChunkInit):
                self.parse_init_packet(pkt[SCTPChunkInit], addr)
                sctp_pkt_ack = self.create_init_ack_packet(pkt, addr)
                send(sctp_pkt_ack,verbose=False,inter=self.delay)
                break

    def send_data(self, payload, tuple):
        sctp_pkt = self.create_data_packet(tuple,payload)
        send(sctp_pkt,verbose=False,inter=self.delay)
        print("waiting for ack")
        while True:
            data,addr = self.socket.recvfrom(self.packet_size)
            pkt = SCTP(data)
            if pkt.haslayer(SCTPChunkSACK):
                self.parse_data_ack_packet(pkt[SCTPChunkSACK])
                break

    def shutdown(self, tuple):
        sctp_pkt = self.create_shutdown_packet(tuple)
        send(sctp_pkt,verbose=False,inter=self.delay)
        while True:
            data,addr = self.socket.recvfrom(self.packet_size)
            pkt = SCTP(data)
            if pkt.haslayer(SCTPChunkShutdownAck):
                self.parse_shutdown_ack_packet(pkt[SCTPChunkShutdownAck])
                break

    def create_init_packet(self,tuple):
        packet = IP(dst=tuple[0],src=self.addr) /\
                 UDP(sport=self.port,dport=tuple[1]) /\
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkInit(init_tag=RandInt(),
                               a_rwnd=self.a_rwnd,
                               n_out_streams=self.n_out_streams,
                               n_in_streams=self.n_in_streams,
                               init_tsn=self.local_tsn)

        self.sent_packets[self.local_tsn] = packet
        self.in_flight.append(packet)
        self.peer_tsn = self.local_tsn
        self.local_tsn += 1

        return packet

    def create_init_ack_packet(self,pkt, addr):
        init_pkt =pkt[SCTPChunkInit]
        packet = IP(dst=addr[0],src=self.addr) / \
                 UDP(sport=self.port,dport=addr[1]) / \
                 SCTP(sport=self.port,dport=addr[1]) / \
                 SCTPChunkInitAck(init_tag=init_pkt.init_tag,
                                  a_rwnd=self.a_rwnd,
                                  n_out_streams=self.n_out_streams,
                                  n_in_streams=self.n_in_streams,
                                  init_tsn=init_pkt.init_tsn)

        self.sent_packets[self.local_tsn] = packet
        self.in_flight.append(packet)


        return packet

    def create_data_packet(self,tuple,data):
        packet = IP(dst=tuple[0],src=self.addr) / \
                 UDP(sport=self.port,dport=tuple[1]) / \
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkData(
                     beginning=1,ending=1,stream_seq=self.seq,
                     tsn=self.local_tsn,proto_id=0,data=data
                 )

        self.sent_packets[self.local_tsn] = packet
        self.local_tsn += 1
        self.in_flight.append(packet)

        return packet

    def create_data_ack_packet(self,pkt, addr):
        data_pkt = pkt[SCTPChunkData]
        packet = IP(dst=addr[0],src=self.addr) / \
                 UDP(sport=self.port,dport=addr[1]) / \
                 SCTP(sport=self.port,dport=addr[1]) / \
                 SCTPChunkSACK(cumul_tsn_ack=data_pkt.tsn,
                               a_rwnd=self.a_rwnd)

        self.sent_packets[self.local_tsn] = packet
        self.local_tsn += 1
        self.in_flight.append(packet)

        return packet

    def create_shutdown_packet(self,tuple):
        packet = IP(dst=tuple[0],src=self.addr) / \
                 UDP(sport=self.port,dport=tuple[1]) / \
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkShutdown(
                     cumul_tsn_ack=self.local_tsn
                 )

        self.sent_packets[self.local_tsn] = packet
        self.local_tsn += 1
        self.in_flight.append(packet)

        return packet

    def create_shutdown_ack_packet(self,pkt,tuple):
        packet = IP(dst=tuple[0],src=self.addr) / \
                 UDP(sport=self.port,dport=tuple[1]) / \
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkShutdownAck()

        return packet

    def parse_init_packet(self,data, addr):
        self.peer_tuple = addr
        self.connected = True

        data.show()
        return True

    def parse_init_ack_packet(self,data):
        data.show()

        return True

    def parse_data_packet(self,data):
        data.show()

        return True

    def parse_data_ack_packet(self,data):
        data.show()

        return True

    def parse_shutdown_packet(self,data):
        self.connected = False

        data.show()
        return True

    def parse_shutdown_ack_packet(self,data):
        self.connected = False

        data.show()
        return True

