import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

def send_ack(sock, address, seq_num):
    ack_header = PacketHeader(type=TYPE_ACK, seq_num=seq_num, length=0, checksum=0)
    ack_header.checksum = compute_checksum(ack_header)
    sock.sendto(bytes(ack_header), address)

def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    in_connection = False
    expected_seq_num = 0
    buffer = {}
    received_data = []

    while True:
        pkt, address = s.recvfrom(2048)
        if len(pkt) < 16:
            continue
        
        pkt_header = PacketHeader(pkt[:16])
        msg = pkt[16 : 16 + pkt_header.length]

        pkt_checksum = pkt_header.checksum
        pkt_header.checksum = 0
        computed_checksum = compute_checksum(pkt_header / msg)
        if pkt_checksum != computed_checksum:
            continue

        if pkt_header.type == TYPE_START:
            if not in_connection:
                in_connection = True
                expected_seq_num = 1
                send_ack(s, address, expected_seq_num)
            continue

        if not in_connection:
            continue

        if pkt_header.type == TYPE_DATA:
            seq = pkt_header.seq_num
            if seq >= expected_seq_num + window_size:
                continue
            if seq >= expected_seq_num:
                if seq not in buffer:
                    buffer[seq] = msg
                while expected_seq_num in buffer:
                    received_data.append(buffer.pop(expected_seq_num))
                    expected_seq_num += 1
                    
            send_ack(s, address, seq)

        elif pkt_header.type == TYPE_END:
            if pkt_header.seq_num == expected_seq_num:
                send_ack(s, address, expected_seq_num + 1)
                sys.stdout.buffer.write(b"".join(received_data))
                sys.stdout.flush()
                break

    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()