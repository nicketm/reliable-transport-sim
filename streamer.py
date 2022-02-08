# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures.thread import ThreadPoolExecutor
import time
import hashlib
import threading

HEADER_SIZE = 24
PACKET_SIZE = 1472 - HEADER_SIZE     # data able to be sent, accounting for header 1472
ACK_TIMEOUT = 0.25

# Go-Back-N
# Send all PACKETS back to back, receive ACK for lowest received (if PACKET is dropped in middle, an ACK for the next
#   PACKET will refer to the ACK of the lowest received)
# As soon as the next expected ACK is received, restart timer and increase expected ACK by 1
# If timer goes off, resend every PACKET since expected ACK

# In flight array: everything goes into it once it is sent, comes out once arrived, FIN isn't sent until empty
# expected ACK variable: gives the sequence number of the next ACK we want to get



def get_seq_num(pack):
    header = pack[:HEADER_SIZE]
    h_data = struct.unpack('ii' + '16s', header)
    return h_data[0]

def get_ack_num(pack):
    header = pack[:HEADER_SIZE]
    h_data = struct.unpack('ii' + '16s', header)
    return h_data[1]

def get_hash(pack):
    header = pack[:HEADER_SIZE]
    h_data = struct.unpack('ii' + '16s', header)
    return h_data[2]

def to_hash(seq, ack, data):
    m = hashlib.md5()
    m.update(seq)
    m.update(ack)
    m.update(data)
    return m.digest()


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.recv_base = 0
        self.seq_num = 0
        self.buf = {}
        self.acked = False

        self.closed = False
        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.listener)

        #self.timer = time.time()
        #self.lock = threading.Lock()
        #self.flight = []
        #self.flight_seq = []

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        data_size = len(data_bytes)

        while data_size > PACKET_SIZE:
            first_1472 = data_bytes[:PACKET_SIZE]
            data_bytes = data_bytes[PACKET_SIZE::]
            data_size -= PACKET_SIZE

            hash_header = to_hash(struct.pack('i', self.seq_num), struct.pack('i', 0), first_1472)

            tcp_header = struct.pack('ii' + '16s', self.seq_num, 0, hash_header)
                                  # (seq_num, ack_num, hash_key)
            first_1472 = tcp_header + first_1472

            #self.flight_seq.append(self.seq_num)
            #self.flight.append(first_1472)
            self.seq_num += 1
            self.acked = False

            while not self.acked:
                self.socket.sendto(first_1472, (self.dst_ip, self.dst_port))
                time.sleep(ACK_TIMEOUT)

        hash_header = to_hash(struct.pack('i', self.seq_num), struct.pack('i', 0), data_bytes)
        tcp_header = struct.pack('ii' + '16s', self.seq_num, 0, hash_header)
                              # (seq_num, ack_num, hash_key)
        data_bytes = tcp_header + data_bytes

        #self.flight_seq.append(self.seq_num)
        #self.flight.append(data_bytes)
        self.seq_num += 1
        self.acked = False

        while not self.acked:
            self.socket.sendto(data_bytes, (self.dst_ip, self.dst_port))
            time.sleep(ACK_TIMEOUT)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        while self.seq_num not in self.buf:
            continue

        data = self.buf[self.seq_num]
        data_no_header = data[HEADER_SIZE::]
        del self.buf[self.seq_num]
        self.seq_num += 1
        return data_no_header

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        # self.acked = False

        #while len(self.flight_seq) != 0:
        #    continue

        fin_hash = to_hash(struct.pack('i', self.recv_base), struct.pack('i', 299), b'')
        fin_packet = struct.pack('ii' + '16s', self.recv_base, 299, fin_hash)
        while not self.acked:
            self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
            time.sleep(ACK_TIMEOUT)

        time.sleep(2)
        print("Closed.")
        self.closed = True
        self.socket.stoprecv()

    def listener(self):
        count = 1
        while not self.closed:  # a later hint will explain self.closed
            #print(f"listener loop #{count}")
            count += 1

            try:
                data, addr = self.socket.recvfrom()
                seq_number = get_seq_num(data)
                ack_number = get_ack_num(data)
                hash_val_header = get_hash(data)

                data_no_header = data[HEADER_SIZE::]
                hash_val_data = to_hash(struct.pack('i', seq_number), struct.pack('i', ack_number), data_no_header)

                if hash_val_header != 0 and hash_val_data != hash_val_header and ack_number == 0:
                    #print("HASH DOESN'T MATCH")
                    continue
                elif ack_number == 0:         # data
                    if seq_number not in self.buf:
                        self.buf[seq_number] = data

                    ack_hash = to_hash(struct.pack('i', self.recv_base), struct.pack('i', 200), b'')
                    ack_send = struct.pack('ii' + '16s', self.recv_base, 200, ack_hash)
                    self.socket.sendto(ack_send, (self.dst_ip, self.dst_port))
                elif ack_number == 200:     # ACK
                    if get_hash(data) == to_hash(struct.pack('i', seq_number), struct.pack('i', 200), b''):
                        self.acked = True
                        #with self.lock:
                        #    if seq_number == min(self.flight_seq):
                        #        self.timer = time.time()
                        #        self.flight_seq.remove(seq_number)
                        #        self.flight.pop(0)
                        #    elif seq_number > min(self.flight_seq):
                        #        resend_num = seq_number - min(self.flight_seq)
                        #        for i in range(resend_num):
                        #            self.flight_seq.remove(min(self.flight_seq))
                        #            self.flight.pop(0)
                        #        self.timer = time.time()

                elif ack_number == 299:     # FIN
                    if get_hash(data) == to_hash(struct.pack('i', seq_number), struct.pack('i', 299), b''):
                        fin_ack_hash = to_hash(struct.pack('i', self.recv_base), struct.pack('i', 200), b'')
                        ack_send = struct.pack('ii' + '16s', self.recv_base, 200, fin_ack_hash)
                        self.socket.sendto(ack_send, (self.dst_ip, self.dst_port))

            except Exception as e:
                if not self.closed:
                    print("listener died!")
                    print(e)
