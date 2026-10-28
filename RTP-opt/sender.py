import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

MAX_PAYLOAD = 1456
TIMEOUT_SEC = 0.5
END_RETRY_SEC = 0.1


def make_packet(pkt_type, seq_num, payload=b""):
    header = PacketHeader(
        type=pkt_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def parse_and_verify_ack(raw_pkt):
    if len(raw_pkt) < 16:
        return None

    header = PacketHeader(raw_pkt[:16])
    payload = raw_pkt[16 : 16 + header.length]

    orig_csum = header.checksum
    header.checksum = 0
    if orig_csum != compute_checksum(header / payload):
        return None

    if header.type != TYPE_ACK:
        return None

    return header.seq_num


def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest_addr = (receiver_ip, receiver_port)

    raw_data = sys.stdin.buffer.read()
    data_packets = []
    for idx, i in enumerate(range(0, len(raw_data), MAX_PAYLOAD), start=1):
        chunk = raw_data[i : i + MAX_PAYLOAD]
        data_packets.append(make_packet(TYPE_DATA, seq_num=idx, payload=chunk))

    total_packets = len(data_packets)

    start_pkt = make_packet(TYPE_START, seq_num=0)
    while True:
        s.sendto(start_pkt, dest_addr)
        deadline = time.time() + TIMEOUT_SEC

        ack_received = False
        while True:
            time_left = deadline - time.time()
            if time_left <= 0:
                break
            s.settimeout(time_left)
            try:
                raw_pkt, _ = s.recvfrom(2048)
                ack_seq = parse_and_verify_ack(raw_pkt)
                if ack_seq == 1:
                    ack_received = True
                    break
            except socket.timeout:
                break

        if ack_received:
            break

    base = 1
    next_seq_num = 1
    timer_start = None
    acked_packets = set()  

    while base <= total_packets:
        while next_seq_num < base + window_size and next_seq_num <= total_packets:
            s.sendto(data_packets[next_seq_num - 1], dest_addr)
            if timer_start is None:
                timer_start = time.time()
            next_seq_num += 1

        time_left = TIMEOUT_SEC - (time.time() - timer_start)
        if time_left <= 0:
            for seq in range(base, next_seq_num):
                if seq not in acked_packets:
                    s.sendto(data_packets[seq - 1], dest_addr)
            timer_start = time.time()
            continue

        s.settimeout(time_left)
        try:
            raw_pkt, _ = s.recvfrom(2048)
            ack_seq = parse_and_verify_ack(raw_pkt)
            if ack_seq is not None and base <= ack_seq < next_seq_num:
                acked_packets.add(ack_seq)
                if ack_seq == base:
                    while base in acked_packets:
                        base += 1
                    if base < next_seq_num:
                        timer_start = time.time()
                    else:
                        timer_start = None
        except socket.timeout:
            for seq in range(base, next_seq_num):
                if seq not in acked_packets:
                    s.sendto(data_packets[seq - 1], dest_addr)
            timer_start = time.time()

    end_seq = total_packets + 1
    end_pkt = make_packet(TYPE_END, seq_num=end_seq)

    s.sendto(end_pkt, dest_addr)
    end_deadline = time.time() + TIMEOUT_SEC
    next_retry = time.time() + END_RETRY_SEC

    while True:
        now = time.time()
        if now >= end_deadline:
            break

        if now >= next_retry:
            s.sendto(end_pkt, dest_addr)
            next_retry = now + END_RETRY_SEC

        wait_time = min(end_deadline, next_retry) - now
        s.settimeout(max(0.001, wait_time))

        try:
            raw_pkt, _ = s.recvfrom(2048)
            ack_seq = parse_and_verify_ack(raw_pkt)
            if ack_seq == end_seq + 1:
                break
        except socket.timeout:
            continue

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

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()