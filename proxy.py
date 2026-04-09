import asyncio
import os
import random
import socket
import struct
import sys

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 6343))
FORWARD_RATE = int(os.environ.get("FORWARD_RATE", 100))  # sampling rate stamped on all forwarded flows
DEFAULT_SAMPLING_RATE = int(os.environ.get("DEFAULT_SAMPLING_RATE", 512))
FORWARD_IP = os.environ["FORWARD_IP"]
FORWARD_PORT = int(os.environ.get("FORWARD_PORT", 6343))


def _load_device_rates() -> dict[str, int]:
    """Parse DEVICE_RATES env var into a lookup table.

    Format: comma-separated ip:rate pairs, e.g.
        DEVICE_RATES=192.168.1.1:1000,10.0.0.5:512
    """
    raw = os.environ.get("DEVICE_RATES", "").strip()
    if not raw:
        return {}
    rates: dict[str, int] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 2:
            print(f"device_rates: skipping invalid entry {entry!r} (expected ip:rate)", file=sys.stderr)
            continue
        ip, rate_str = parts[0].strip(), parts[1].strip()
        try:
            rates[ip] = int(rate_str)
        except ValueError:
            print(f"device_rates: skipping invalid rate {rate_str!r} for {ip}", file=sys.stderr)
    return rates


DEVICE_RATES: dict[str, int] = _load_device_rates()

DATAGRAM_HEADER_SIZE = 28
SAMPLE_TYPE_FLOW = 1
SAMPLE_TYPE_COUNTER = 2

_TCP_FRAME = struct.Struct("!I")  # 4-byte big-endian length prefix


def normalize_flow_sample(data: bytes, agent_ip: str | None = None) -> bytes | None:
    # Flow sample layout (offsets within sample_data):
    #   0: sequence_number  uint32
    #   4: source_id        uint32
    #   8: sampling_rate    uint32  ← read/rewrite
    #  12: sample_pool      uint32
    #  16: drops            uint32
    #  20: input_if         uint32
    #  24: output_if        uint32
    if len(data) < 28:
        raise ValueError(f"Flow sample too short: {len(data)} bytes")

    device_rate = struct.unpack_from("!I", data, 8)[0]

    if agent_ip is not None and agent_ip in DEVICE_RATES:
        # Per-device override — use the configured rate regardless of what the
        # device embedded. Takes precedence over both the embedded rate and
        # DEFAULT_SAMPLING_RATE.
        device_rate = DEVICE_RATES[agent_ip]
    elif device_rate == 0:
        # rate=0 means the device embedded no rate info — fall back to configured default
        device_rate = DEFAULT_SAMPLING_RATE

    if device_rate > FORWARD_RATE:
        # Device samples less often than target — scale sample_pool up so
        # the collector sees the correct traffic volume.
        ratio = device_rate // FORWARD_RATE
    elif device_rate < FORWARD_RATE:
        # Device samples more often than target — probabilistically drop
        # this sample so the expected flow count matches FORWARD_RATE.
        # On average: forwarded_flows × FORWARD_RATE = device_rate × captured_flows
        if random.random() >= device_rate / FORWARD_RATE:
            return None
        ratio = 1
    else:
        ratio = 1

    data = bytearray(data)
    struct.pack_into("!I", data, 8, FORWARD_RATE)

    if ratio > 1:
        sample_pool = struct.unpack_from("!I", data, 12)[0]
        struct.pack_into("!I", data, 12, sample_pool * ratio)

    return bytes(data)


def parse_datagram(data: bytes) -> bytes | None:
    if len(data) < DATAGRAM_HEADER_SIZE:
        raise ValueError(f"Datagram too short: {len(data)} bytes")

    version = struct.unpack_from("!I", data, 0)[0]
    if version != 5:
        raise ValueError(f"Unsupported sFlow version: {version}")

    # Extract agent_address for per-device rate table lookup.
    # Header layout: version(4) addr_type(4) addr_ip(4) ...
    # addr_type=1 means IPv4; addr_ip is the 4 raw bytes at offset 8.
    agent_ip: str | None = None
    if struct.unpack_from("!I", data, 4)[0] == 1:  # IPv4
        agent_ip = socket.inet_ntoa(data[8:12])

    num_samples = struct.unpack_from("!I", data, 24)[0]

    out = bytearray(data[:DATAGRAM_HEADER_SIZE])
    offset = DATAGRAM_HEADER_SIZE
    out_samples = 0

    for _ in range(num_samples):
        if offset + 8 > len(data):
            raise ValueError("Truncated sample record header")

        sample_type, sample_length = struct.unpack_from("!II", data, offset)
        record_header = data[offset : offset + 8]
        sample_data = data[offset + 8 : offset + 8 + sample_length]

        if len(sample_data) < sample_length:
            raise ValueError(
                f"Truncated sample data: expected {sample_length}, got {len(sample_data)}"
            )

        if sample_type == SAMPLE_TYPE_FLOW:
            sample_data = normalize_flow_sample(sample_data, agent_ip)
            if sample_data is None:
                offset += 8 + sample_length
                continue  # probabilistically dropped
            record_header = struct.pack("!II", sample_type, len(sample_data))

        out += record_header
        out += sample_data
        out_samples += 1
        offset += 8 + sample_length

    if out_samples == 0:
        return None  # nothing left to forward

    struct.pack_into("!I", out, 24, out_samples)
    return bytes(out)


class SFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, forward_sock: socket.socket) -> None:
        self._sock = forward_sock

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            packet = parse_datagram(data)
        except Exception as exc:
            print(
                f"DROP {addr[0]} len={len(data)}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        if packet is not None:
            self._sock.sendto(packet, (FORWARD_IP, FORWARD_PORT))

    def error_received(self, exc: Exception) -> None:
        print(f"Socket error: {exc}", file=sys.stderr, flush=True)


async def handle_tcp_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peer = writer.get_extra_info("peername", ("unknown", 0))
    try:
        fwd_reader, fwd_writer = await asyncio.open_connection(FORWARD_IP, FORWARD_PORT)
    except Exception as exc:
        print(f"TCP fwd connect failed from {peer[0]}: {exc}", file=sys.stderr, flush=True)
        writer.close()
        await writer.wait_closed()
        return

    try:
        while True:
            try:
                length_bytes = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                break  # clean disconnect
            length = _TCP_FRAME.unpack(length_bytes)[0]
            try:
                data = await reader.readexactly(length)
            except asyncio.IncompleteReadError:
                break

            try:
                packet = parse_datagram(data)
            except Exception as exc:
                print(
                    f"DROP TCP {peer[0]} len={length}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                continue

            if packet is not None:
                fwd_writer.write(_TCP_FRAME.pack(len(packet)) + packet)
                await fwd_writer.drain()
    except Exception as exc:
        print(f"TCP {peer[0]}: {exc}", file=sys.stderr, flush=True)
    finally:
        fwd_writer.close()
        try:
            await fwd_writer.wait_closed()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: SFlowProtocol(forward_sock),
        local_addr=("0.0.0.0", LISTEN_PORT),
    )

    tcp_server = await asyncio.start_server(
        handle_tcp_connection,
        "0.0.0.0",
        LISTEN_PORT,
    )

    override_info = f" device_overrides={len(DEVICE_RATES)}" if DEVICE_RATES else ""
    print(
        f"sflow-normalizer listening on :{LISTEN_PORT} (UDP+TCP) "
        f"→ {FORWARD_IP}:{FORWARD_PORT} "
        f"forward_rate={FORWARD_RATE} default_rate={DEFAULT_SAMPLING_RATE}"
        f"{override_info}",
        flush=True,
    )

    try:
        async with tcp_server:
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()
        forward_sock.close()


if __name__ == "__main__":
    asyncio.run(main())
