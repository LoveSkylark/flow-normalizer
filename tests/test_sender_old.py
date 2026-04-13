import argparse
import random
import socket
import struct
import time


_NF5_HDR = struct.Struct("!HHIIIIBBH")
_NF5_REC = struct.Struct("!IIIHHIIIIHHxBBBHHBB2x")


def ip4(s: str) -> int:
    return struct.unpack("!I", socket.inet_aton(s))[0]


def build_nf5_record(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    packets: int,
    octets: int,
    first: int,
    last: int,
    proto: int = 6,
    tos: int = 0,
    tcp_flags: int = 0x10,
    src_as: int = 0,
    dst_as: int = 0,
    src_mask: int = 24,
    dst_mask: int = 24,
    input_if: int = 1,
    output_if: int = 2,
    nexthop: str = "0.0.0.0",
) -> bytes:
    return _NF5_REC.pack(
        ip4(src_ip),
        ip4(dst_ip),
        ip4(nexthop),
        input_if,
        output_if,
        packets,
        octets,
        first,
        last,
        src_port,
        dst_port,
        tcp_flags,
        proto,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
    )


def build_nf5_packet(records: list[bytes], seq: int, sampling_rate: int) -> bytes:
    now = int(time.time())
    uptime_ms = int((time.monotonic() % 3600) * 1000)

    header = _NF5_HDR.pack(
        5,                  # version
        len(records),       # count
        uptime_ms,          # sys_uptime
        now,                # unix_secs
        0,                  # unix_nsecs
        seq,                # flow_sequence
        0,                  # engine_type
        0,                  # engine_id
        sampling_rate & 0x3FFF,
    )
    return header + b"".join(records)


def make_profile_records(profile: str, now_ms: int) -> list[bytes]:
    records: list[bytes] = []

    def add(flow_id: int, packets: int, avg_size: int, n: int) -> None:
        for i in range(n):
            src = f"10.0.{flow_id}.{(i % 250) + 1}"
            dst = f"192.0.2.{(i % 250) + 1}"
            sport = 10000 + ((flow_id * 100 + i) % 50000)
            dport = 80 if flow_id % 2 == 0 else 443
            octets = packets * avg_size
            records.append(
                build_nf5_record(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    packets=packets,
                    octets=octets,
                    first=max(0, now_ms - random.randint(100, 5000)),
                    last=now_ms,
                    proto=6,
                )
            )

    if profile == "mixed":
        add(1, 1, 120, 10)      # tiny
        add(2, 2, 200, 10)      # tiny
        add(3, 10, 300, 10)     # small
        add(4, 100, 700, 10)    # medium
        add(5, 1000, 900, 10)   # large
    elif profile == "tiny":
        add(1, 1, 120, 30)
    elif profile == "small":
        add(2, 10, 300, 30)
    elif profile == "large":
        add(3, 1000, 900, 30)
    else:
        raise ValueError(f"unknown profile: {profile}")

    return records


def chunked(seq_records: list[bytes], chunk_size: int):
    for i in range(0, len(seq_records), chunk_size):
        yield seq_records[i:i + chunk_size]


def main() -> None:
    parser = argparse.ArgumentParser(description="Send synthetic NetFlow v5 packets")
    parser.add_argument("--host", default="127.0.0.1", help="proxy host")
    parser.add_argument("--port", type=int, default=2055, help="proxy port")
    parser.add_argument(
        "--sampling-rate",
        type=int,
        default=1,
        help="embedded device sampling rate in NFv5 header",
    )
    parser.add_argument(
        "--profile",
        choices=["mixed", "tiny", "small", "large"],
        default="mixed",
        help="traffic mix to generate",
    )
    parser.add_argument(
        "--records-per-packet",
        type=int,
        default=30,
        help="NFv5 records per datagram",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="number of datagrams to send",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.2,
        help="seconds between datagrams",
    )
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 1

    for _ in range(args.repeat):
        now_ms = int((time.monotonic() % 3600) * 1000)
        records = make_profile_records(args.profile, now_ms)
        for group in chunked(records, args.records_per_packet):
            pkt = build_nf5_packet(group, seq, args.sampling_rate)
            sock.sendto(pkt, (args.host, args.port))
            print(
                f"sent nf5 packet seq={seq} records={len(group)} "
                f"sampling_rate={args.sampling_rate} to {args.host}:{args.port}"
            )
            seq += len(group)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()