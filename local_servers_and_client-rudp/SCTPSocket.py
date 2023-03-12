import random
import socket
import time
import threading
from scapy.all import *
from CubicCC import CubicCC


class SCTPSocket:

    def __init__(self,sock=None,a_rwnd=50,n_out_streams=1,n_in_streams=1,
                 packet_size=65536,peer_tsn=0,sent_packets={},received_packets={},
                 acknowledged_packets={},in_flight={}, delay = 0, verbose = False,
                 timeout = 1.5, cc_printer = False, pkt_printer = False,
                 packet_loss= -1):
        self.cc_printer = cc_printer
        self.pkt_printer = pkt_printer

        self.a_rwnd = a_rwnd
        self.n_out_streams = n_out_streams
        self.n_in_streams = n_in_streams
        self.connected = False
        self.transfering_data = False
        self.addr = 'localhost'
        self.port = RandInt() + 3000
        self.packet_size = packet_size
        self.peer_tsn = 0
        self.local_tsn = random.randint(1,999999)
        self.sent_packets = sent_packets
        self.received_packets = received_packets
        self.dup_packets = {}
        self.acknowledged_packets = acknowledged_packets
        self.in_flight = in_flight
        self.peer_tuple = None
        self.delay = delay
        self.seq = 0
        self.sniff_thread = None
        self.missplaced_packet = None
        self.verbose = verbose
        self.cc = CubicCC()
        self.sent_series = False
        self.last_pkts = None
        self.timeout_counter = 0
        self.start_time = time.time()
        self.timeout = timeout
        self.packet_loss = packet_loss
        self.len = 100
        self.data_buffer = []
        for i in range(0,self.len):
            self.data_buffer.append(None)

        self.close_flag = True
        if sock is None:
            self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        else:
            self.socket = sock

        # self.socket.settimeout(timeout)  # set a timeout of 2 seconds
        self.socket.settimeout(0.2)  # set a timeout of 2 seconds

    def bind(self,tuple):
        self.addr = tuple[0]
        self.port = tuple[1]
        self.socket.bind(tuple)

    def connect(self, tuple):
        self.start()
        self.handshake(tuple)
        self.peer_tuple = tuple

    def listen(self):
        self.start()

    def accept(self):
        self.received_packets = {}
        self.sent_packets = {}
        self.acknowledged_packetsc = {}
        self.dup_packets = {}
        self.connected = False

        self.receive_handshake(self.packet_size)

    def close(self):
        if self.connected:
            self.shutdown(self.peer_tuple)
        self.close_flag = True
        time.sleep(2)
        self.socket.close()

    def sendto(self,payload,tuple = None):
        if tuple is None:
            tuple = self.peer_tuple
        if not self.connected:
            return

        self.data_buffer = self.chunk_data(payload,self.packet_size)
        self.len = len(self.data_buffer)

        self.cc.cubic_reset()
        self.transfering_data = True
        self.send_data(tuple)

    def recvfrom(self,packet_size = 1024):
        if not self.connected:
            self.receive_handshake(packet_size)
        self.reset_dup()
        self.a_rwnd = 50
        self.transfering_data = True
        if self.pkt_printer:
            print(f"waiting for data\ttsn={self.local_tsn}\tptsn={self.peer_tsn}")
        while True:
            if not self.connected: return
            self.check_timer()
            try:
                if self.local_tsn in self.received_packets.keys():
                    pkt = self.received_packets[self.local_tsn]
                    if pkt.haslayer(SCTPChunkData):
                        self.parse_data_packet(pkt, self.peer_tuple)
                        if pkt[SCTPChunkData].ending == 1 and not self.transfering_data:
                            return self.unite_data()
            except:
                continue

    def handshake(self,tuple):
        sctp_pkt = self.create_init_packet(tuple)
        send(sctp_pkt, verbose=self.verbose,inter=self.delay)
        self.start_timer([sctp_pkt])
        while True:
            self.check_timer()
            try:
                if self.peer_tsn in self.received_packets.keys():
                    pkt = self.received_packets[self.peer_tsn]
                    if pkt.haslayer(SCTPChunkInitAck):
                        self.parse_init_ack_packet(pkt[SCTPChunkInitAck])
                        self.connected = True
                        return
            except:
                continue

    def receive_handshake(self,packet_size):
        while True:
            data = None
            try:
                for tsn, p in self.received_packets.items():
                    if p.haslayer(SCTPChunkInit):
                        self.local_tsn = tsn
                        pkt = p
                        if pkt.haslayer(SCTPChunkInit):
                            self.parse_init_packet(pkt[SCTPChunkInit], self.peer_tuple)
                            sctp_pkt_ack = self.create_init_ack_packet(pkt, self.peer_tuple)
                            send(sctp_pkt_ack,verbose=self.verbose,inter=self.delay)
                            return
            except:
                continue

    def send_data(self, tuple):
        self.sent_series = False
        pkts = self.create_data_packet(tuple)
        self.start_timer(pkts)
        if self.pkt_printer:
            print(f"waiting for ack\tseq={self.seq}\tcwnd={self.cc.int_cwnd}\t"
              f"tsn={self.local_tsn}\tptsn={self.peer_tsn}")
        if self.cc_printer:
            self.cc.print()
        while True:
            try:
                if not self.connected: return
                self.check_timer()
                if self.peer_tsn in self.received_packets.keys():
                    pkt = self.received_packets[self.peer_tsn]
                    if pkt.haslayer(SCTPChunkSACK):
                        flag = self.parse_data_ack_packet(pkt[SCTPChunkSACK])
                        if flag:
                            self.transfering_data = False
                            return
            except:
                continue
    def shutdown(self, tuple):
        sctp_pkt = self.create_shutdown_packet(tuple)
        send(sctp_pkt,verbose=self.verbose,inter=self.delay)
        if self.pkt_printer:
            print(f"waiting for ack\t"
              f"tsn={self.local_tsn}\tptsn={self.peer_tsn}")
        while True:
            try:
                if 0 in self.received_packets.keys():
                    pkt = self.received_packets[0]
                    if pkt.haslayer(SCTPChunkShutdownAck):
                        self.parse_shutdown_ack_packet(pkt[SCTPChunkShutdownAck])
                        return
            except:
                continue

    def start(self):
        # Start the packet sniffing thread
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def sniff_packets(self):
        print("started thread")
        while self.close_flag:
            try:
                data,addr = self.socket.recvfrom(self.packet_size)
                pkt = SCTP(data)

                if pkt.haslayer(SCTPChunkShutdown):
                    self.parse_shutdown_packet(pkt[SCTPChunkShutdown])
                    break
                elif pkt.haslayer(SCTPChunkShutdownAck):
                    self.received_packets[0] = pkt
                    break
                elif pkt.haslayer(SCTPChunkData):
                    rand_num = random.random()
                    if rand_num < self.packet_loss:
                        # Packet loss
                        if self.cc_printer:
                            print(f"packet loss! tsn - {pkt[SCTPChunkData].tsn}")
                        continue
                    if pkt[SCTPChunkData].tsn in self.dup_packets.keys():
                        self.dup_packets[pkt[SCTPChunkData].tsn]+=1
                        self.check_dup()
                    else:
                        self.received_packets[pkt[SCTPChunkData].tsn] = pkt
                        self.dup_packets[pkt[SCTPChunkData].tsn] = 0
                elif pkt.haslayer(SCTPChunkSACK):
                    rand_num = random.random()
                    if rand_num < self.packet_loss:
                        # Packet loss
                        if self.cc_printer:
                            print(f"packet loss! tsn - {pkt[SCTPChunkSACK].cumul_tsn_ack}")
                        continue
                    if pkt[SCTPChunkSACK].cumul_tsn_ack in self.dup_packets.keys():
                        self.dup_packets[pkt[SCTPChunkSACK].cumul_tsn_ack]+=1
                        self.check_dup()
                    else:
                        self.received_packets[pkt[SCTPChunkSACK].cumul_tsn_ack] = pkt
                        self.dup_packets[pkt[SCTPChunkSACK].cumul_tsn_ack] = 0
                elif pkt.haslayer(SCTPChunkInit):
                    if pkt[SCTPChunkInit].init_tsn in self.dup_packets.keys():
                        self.dup_packets[pkt[SCTPChunkInit].init_tsn]+=1
                        self.check_dup()
                    else:
                        self.received_packets[pkt[SCTPChunkInit].init_tsn] = pkt
                        self.dup_packets[pkt[SCTPChunkInit].init_tsn] = 0
                    self.peer_tuple = addr
                elif pkt.haslayer(SCTPChunkInitAck):
                    if pkt[SCTPChunkInitAck].init_tsn in self.dup_packets.keys():
                        self.dup_packets[pkt[SCTPChunkInitAck].init_tsn]+=1
                        self.check_dup()
                    else:
                        self.received_packets[pkt[SCTPChunkInitAck].init_tsn] = pkt
                        self.dup_packets[pkt[SCTPChunkInitAck].init_tsn] = 0
                    self.peer_tuple = addr
                else:
                    self.missplaced_packet = pkt
            except:
                continue
        print("ended thread")

    def create_init_packet(self,tuple):
        self.local_tsn = random.randint(1,999999)

        packet = IP(dst=tuple[0],src=self.addr) /\
                 UDP(sport=self.port,dport=tuple[1]) /\
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkInit(init_tag=random.randint(1,999999),
                               a_rwnd=self.a_rwnd,
                               n_out_streams=self.n_out_streams,
                               n_in_streams=self.n_in_streams,
                               init_tsn=self.local_tsn)

        # Reliability
        self.sent_packets[self.local_tsn] = packet
        self.in_flight[self.local_tsn] = packet
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

        self.peer_tuple = addr

        # Reliability
        self.local_tsn = init_pkt.init_tsn + 1
        self.peer_tsn = self.local_tsn

        return packet

    # SCTPChunkData(_pkt, /, *, type=0, reserved=None, delay_sack=0,
    # unordered=0, beginning=0, ending=0, len=None, tsn=None,
    # stream_id=None, stream_seq=None, proto_id=None, data=None)
    def create_data_packet(self,tuple):
        packets = []
        for i in range(0,self.cc.int_cwnd):
            if self.seq+i+1 > self.len:
                self.peer_tsn = self.local_tsn+i
                break
            delay_sack = beginning = ending = 0
            if self.seq == 0 and i == 0:
                beginning = 1
            if self.seq+i+1 == self.len:
                ending = 1
                delay_sack = 1
            if i + 1 == self.cc.int_cwnd:
                delay_sack = 1

            packet = IP(dst=tuple[0],src=self.addr) / \
                     UDP(sport=self.port,dport=tuple[1]) / \
                     SCTP(sport=self.port,dport=tuple[1]) / \
                     SCTPChunkData(
                         beginning=beginning,ending=ending,stream_seq=self.seq+i,
                         tsn=self.local_tsn+i,proto_id=0,delay_sack=delay_sack,
                         data=self.data_buffer[self.seq+i]
                     )

            packets += [packet]
            if not self.sent_series:
                self.sent_packets[self.local_tsn] = packet
                self.in_flight[self.local_tsn] = packet
                self.peer_tsn = self.local_tsn+i
            if self.pkt_printer:
                print("----------------sent--------------------------")
                print(f"type-{packet[SCTPChunkData].type}\t"
                      f"tsn-{packet[SCTPChunkData].tsn}\t"
                      f"seq-{packet[SCTPChunkData].stream_seq}\t"
                      f"ds-{packet[SCTPChunkData].delay_sack}"
                      )

            send(packet,verbose=self.verbose,inter=self.delay)

            if ending == 1:
                break

        if not self.sent_series:
            self.sent_series = True

        return packets


    # SCTPChunkSACK( _pkt, /, *,type = 3,flags = None,len = None,
    # cumul_tsn_ack = None,a_rwnd = None,n_gap_ack = None,n_dup_tsn = None,
    # gap_ack_list = [],dup_tsn_list = [])
    def create_data_ack_packet(self,pkt, addr):

        data_pkt = pkt[SCTPChunkData]
        packet = IP(dst=addr[0],src=self.addr) / \
                 UDP(sport=self.port,dport=addr[1]) / \
                 SCTP(sport=self.port,dport=addr[1]) / \
                 SCTPChunkSACK(cumul_tsn_ack=data_pkt.tsn,
                               a_rwnd=self.a_rwnd)

        # Reliability
        self.sent_packets[self.local_tsn] = packet
        self.local_tsn += 1

        return packet

    def create_shutdown_packet(self,tuple):
        packet = IP(dst=tuple[0],src=self.addr) / \
                 UDP(sport=self.port,dport=tuple[1]) / \
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkShutdown(
                     cumul_tsn_ack=self.local_tsn
                 )

        # Reliability
        self.in_flight[self.local_tsn] = packet
        self.sent_packets[self.local_tsn] = packet
        self.peer_tsn = self.local_tsn

        return packet

    def create_shutdown_ack_packet(self,pkt,tuple):
        packet = IP(dst=tuple[0],src=self.addr) / \
                 UDP(sport=self.port,dport=tuple[1]) / \
                 SCTP(sport=self.port,dport=tuple[1]) / \
                 SCTPChunkShutdownAck()

        return packet

    def parse_init_packet(self,pkt, addr):
        self.cc.peer_w_max = pkt[SCTPChunkInit].a_rwnd

        pkt.show()
            # Reliability
        self.peer_tsn = pkt[SCTPChunkInit].init_tsn + 1
        self.local_tsn = self.peer_tsn
        self.connected = True

        return True

    def parse_init_ack_packet(self,pkt):
        self.cc.peer_w_max = pkt[SCTPChunkInitAck].a_rwnd
        pkt.show()

        # Reliability
        self.peer_tsn = pkt[SCTPChunkInitAck].init_tsn
        self.received_packets[self.peer_tsn] = pkt
        self.acknowledged_packets[self.peer_tsn] = pkt
        if self.peer_tsn in self.in_flight:
            del self.in_flight[self.peer_tsn]

        return True

    def parse_data_packet(self,pkt, addr):
        if pkt[SCTPChunkData].stream_seq > self.len-10:
            self.len += 100
            for i in range(0,100):
                self.data_buffer.append(None)

        if pkt[SCTPChunkData].delay_sack == 1:
            flag = True
            for i in range(0,pkt[SCTPChunkData].stream_seq):
                if self.data_buffer[i] is None:
                    flag = False

            if flag:
                if self.pkt_printer:
                    print("----------------recieved--------------------------")
                    print(f"type-{pkt[SCTPChunkData].type}\t"
                          f"tsn-{pkt[SCTPChunkData].tsn}\t"
                          f"seq-{pkt[SCTPChunkData].stream_seq}\t"
                          f"ds-{pkt[SCTPChunkData].delay_sack}"
                          )
                self.received_packets[pkt[SCTPChunkData].tsn] = pkt
                self.data_buffer[pkt[SCTPChunkData].stream_seq] = pkt[SCTPChunkData].data
                self.peer_tsn = pkt[SCTPChunkData].tsn
                self.local_tsn = pkt[SCTPChunkData].tsn

                sctp_pkt_ack = self.create_data_ack_packet(pkt,addr)

                if self.pkt_printer:
                    print("----------------sent--------------------------")
                    print(f"type-{sctp_pkt_ack[SCTPChunkSACK].type}\t"
                          f"tsn-{sctp_pkt_ack[SCTPChunkSACK].cumul_tsn_ack}\t"
                          f"seq-{pkt[SCTPChunkData].stream_seq}\t"
                          f"a_rwnd-{sctp_pkt_ack[SCTPChunkSACK].a_rwnd}\t"
                          )

                send(sctp_pkt_ack,verbose=self.verbose,inter=self.delay)
                self.start_timer([sctp_pkt_ack])
                if pkt[SCTPChunkData].ending == 1:
                    self.transfering_data = False
        else:
            if self.pkt_printer:
                print("----------------recieved--------------------------")
                print(f"type-{pkt[SCTPChunkData].type}\t"
                      f"tsn-{pkt[SCTPChunkData].tsn}\t"
                      f"seq-{pkt[SCTPChunkData].stream_seq}\t"
                      f"ds-{pkt[SCTPChunkData].delay_sack}"
                      )
            self.received_packets[pkt[SCTPChunkData].tsn] = pkt
            self.data_buffer[pkt[SCTPChunkData].stream_seq] = pkt[SCTPChunkData].data
            self.local_tsn += 1
            self.peer_tsn = self.local_tsn

        return True

    def parse_data_ack_packet(self,pkt):
        self.cc.on_packet_acknowledged(pkt[SCTPChunkSACK].a_rwnd)

        if self.pkt_printer:
            print("----------------recieved--------------------------")
            print(f"type-{pkt[SCTPChunkSACK].type}\t"
                  f"tsn-{pkt[SCTPChunkSACK].cumul_tsn_ack}\t"
                  f"a_rwnd-{pkt[SCTPChunkSACK].a_rwnd}\t"
                  )

        # Reliability
        self.seq += pkt[SCTPChunkSACK].cumul_tsn_ack - self.local_tsn + 1
        self.local_tsn = pkt[SCTPChunkSACK].cumul_tsn_ack + 1
        self.peer_tsn = pkt[SCTPChunkSACK].cumul_tsn_ack
        self.received_packets[self.peer_tsn] = pkt
        self.acknowledged_packets[self.peer_tsn] = pkt
        for key in list(self.in_flight.keys()):
            if key <= self.peer_tsn:
                del self.in_flight[key]

        if self.seq < self.len:
            self.send_data(self.peer_tuple)

        return True

    def parse_shutdown_packet(self,pkt):
        pkt.show()

        # Reliability
        self.peer_tsn = pkt[SCTPChunkShutdown].cumul_tsn_ack
        self.received_packets[self.peer_tsn] = pkt
        self.local_tsn = pkt[SCTPChunkShutdown].cumul_tsn_ack
        sctp_pkt_ack = self.create_shutdown_ack_packet(pkt,self.peer_tuple)
        send(sctp_pkt_ack,verbose=self.verbose,inter=self.delay)

        if self.pkt_printer:
            print("session summary: ")
            print(f"recieved packets: {self.received_packets.keys()}")
            print(f"sent packets: {self.sent_packets.keys()}")
            print(f"in flight packets: {self.in_flight.keys()}")
            print(f"acknowledged packets: {self.acknowledged_packets.keys()}")

        self.peer_tsn = 0
        self.sent_packets = {}
        self.received_packets = {}
        self.acknowledged_packets = {}
        self.in_flight = {}
        self.connected = False


        return True

    def parse_shutdown_ack_packet(self,pkt):
        pkt.show()
        # Reliability
        self.peer_tsn = self.local_tsn
        self.received_packets[self.peer_tsn] = pkt
        self.acknowledged_packets[self.peer_tsn] = pkt
        if self.peer_tsn in self.in_flight:
            del self.in_flight[self.peer_tsn]

        if self.pkt_printer:
            print("session summary: ")
            print(f"recieved packets: {self.received_packets.keys()}")
            print(f"sent packets: {self.sent_packets.keys()}")
            print(f"in flight packets: {self.in_flight.keys()}")
            print(f"acknowledged packets: {self.acknowledged_packets.keys()}")


        # reset for next session
        self.peer_tsn = 0
        self.sent_packets = {}
        self.received_packets = {}
        self.acknowledged_packets = {}
        self.in_flight = {}
        self.connected = False

        return True

    def chunk_data(self, data, max_packet_size):
        chunks = []
        start = 0
        max_packet_size -= 100
        end = max_packet_size

        while start < len(data):
            chunk = data[start:end]
            chunks.append(chunk)
            start += max_packet_size
            end += max_packet_size

        return chunks

    def unite_data(self):
        data = None
        for x in self.data_buffer:
            if x is None: break
            if data is None: data = x
            else: data += x
        return data

    def start_timer(self, pkts):
        if pkts is not None:
            self.timeout_counter = 0
            self.last_pkts = pkts
        self.start_time = time.time()

    def check_timer(self):

        if self.timeout_counter > 2:
            if self.cc_printer:
                print("timeout detected")
            self.cc.on_timeout()
            self.timeout_counter-=3


        if time.time() - self.start_time > self.timeout:
            self.timeout_counter += 1
            self.start_time = time.time()
            try:
                if self.cc_printer:
                    print(f"resended last packets")
                for p in self.last_pkts:
                    send(p,verbose=self.verbose,inter=self.delay)
                self.start_timer(None)
            except:
                return

    def check_dup(self):
        dup_acks = 0
        dup_pkts = 0
        try:
            for tsn in self.dup_packets.keys():
                while self.dup_packets[tsn] > 2:
                    if self.received_packets[tsn].haslayer(SCTPChunkSACK):
                        dup_acks += 1
                    else:
                        dup_pkts += 1
                    self.dup_packets[tsn] -= 3

                    if self.cc_printer:
                        print(f"duplicate packets detected, tsn - {tsn}")
                    # try:
                    if tsn in self.sent_packets.keys():
                        for i in range(0,3):
                            send(self.sent_packets[tsn],verbose=self.verbose,inter=self.delay)
                        if self.cc_printer:
                            print("sent 3 duplicate acks")
                    else:
                        print("failed to send 3 duplicate acks")
                    # except:
                    #     if self.cc_printer:
                    #         print("failed to send 3 duplicate acks")

        except:
            self.check_dup()
            return
        if dup_pkts > 0:
            self.a_rwnd = max(int(self.a_rwnd/(dup_pkts+1)),1)
        if dup_acks > 0:
            if self.cc_printer:
                print("duplicate acks detected")
            try:
                for p in self.last_pkts:
                    send(p,verbose=self.verbose,inter=self.delay)
                if self.cc_printer:
                    print("success to resend packets")
            except:
                if self.cc_printer:
                    print("failed to resend packets")
            self.cc.on_triple_ack()
        else:
            self.a_rwnd = min(self.a_rwnd*2,50)

    def reset_dup(self):
        for tsn in self.dup_packets.keys():
            self.dup_packets[tsn] = 0



