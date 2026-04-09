"""
sflow-normalizer test harness.

Starts a mock collector on COLLECTOR_PORT, sends crafted sFlow v5 packets
to the proxy on PROXY_PORT, and verifies the collector receives the expected
normalized output.

Usage (proxy must already be running):
    FORWARD_PORT=16343 FORWARD_RATE=100 DEFAULT_SAMPLING_RATE=512 python proxy.py &
    python test_sender.py
"""

import socket
import struct
import sys
import threading
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6343
COLLECTOR_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 16343
# Optional: pass "ip:rate" as 3rd arg to test per-device override.
# The proxy must have been started with DEVICE_RATES=<ip>:<rate> matching.
# Example: python3 test_sender.py 16344 16343 127.0.0.1:200
OVERRIDE_ARG = sys.argv[3] if len(sys.argv) > 3 else None
FORWARD_RATE = 100
DEFAULT_SAMPLING_RATE = 512


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def build_datagram_header(num_samples: int, seq: int = 1) -> bytes:
    # sFlow v5 datagram header is 28 bytes:
    #   version(4) + addr_type(4) + addr_ip(4) + sub_agent_id(4)
    #   + sequence_number(4) + uptime(4) + num_samples(4)
    return struct.pack(
        "!IIIIIII",
        5,               # version
        1,               # address type: IPv4
        0x7F000001,      # agent_address 127.0.0.1
        0,               # sub_agent_id
        seq,             # sequence_number
        12345,           # uptime ms
        num_samples,
    )


def build_flow_sample(
    sampling_rate: int,
    sample_pool: int = 1000,
    drops: int = 0,
    input_if: int = 1,
    output_if: int = 2,
    seq: int = 1,
    source_id: int = 0,
) -> bytes:
    # Minimal flow sample with no flow records
    return struct.pack(
        "!IIIIIII",
        seq,
        source_id,
        sampling_rate,
        sample_pool,
        drops,
        input_if,
        output_if,
    )


def build_counter_sample(raw_bytes: bytes) -> bytes:
    return raw_bytes


def wrap_sample(sample_type: int, sample_data: bytes) -> bytes:
    return struct.pack("!II", sample_type, len(sample_data)) + sample_data


def make_flow_packet(device_rate: int, seq: int = 1) -> bytes:
    flow = build_flow_sample(sampling_rate=device_rate, sample_pool=500)
    sample = wrap_sample(1, flow)
    header = build_datagram_header(num_samples=1, seq=seq)
    return header + sample


def make_counter_packet(payload: bytes = b"\x00" * 88) -> bytes:
    sample = wrap_sample(2, payload)
    header = build_datagram_header(num_samples=1, seq=99)
    return header + sample


def make_malformed_packet() -> bytes:
    return b"\xFF" * 10


# ---------------------------------------------------------------------------
# Mock collectors
# ---------------------------------------------------------------------------

received: list[bytes] = []
tcp_received: list[bytes] = []
lock = threading.Lock()


def collector_thread(sock: socket.socket, stop_event: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            data, _ = sock.recvfrom(65535)
            with lock:
                received.append(data)
        except socket.timeout:
            continue


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def tcp_collector_thread(server_sock: socket.socket, stop_event: threading.Event) -> None:
    server_sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            conn, _ = server_sock.accept()
        except socket.timeout:
            continue
        conn.settimeout(1.0)
        try:
            while True:
                header = _recv_exact(conn, 4)
                if not header:
                    break
                length = struct.unpack("!I", header)[0]
                data = _recv_exact(conn, length)
                if data is None:
                    break
                with lock:
                    tcp_received.append(data)
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_flow_sample_rate(data: bytes) -> int:
    """Extract sampling_rate from the first flow sample in a datagram."""
    offset = 28  # skip datagram header
    sample_type, sample_length = struct.unpack_from("!II", data, offset)
    if sample_type != 1:
        raise ValueError(f"Expected flow sample (type=1), got type={sample_type}")
    sample_data = data[offset + 8 : offset + 8 + sample_length]
    return struct.unpack_from("!I", sample_data, 8)[0]


def parse_flow_sample_pool(data: bytes) -> int:
    offset = 28
    _, sample_length = struct.unpack_from("!II", data, offset)
    sample_data = data[offset + 8 : offset + 8 + sample_length]
    return struct.unpack_from("!I", sample_data, 12)[0]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = PASS if cond else FAIL
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    results.append((name, cond, detail))


def _run_override_test(send_and_wait) -> None:
    """Test per-device rate override (DEVICE_RATES).

    Requires the proxy to be started with DEVICE_RATES matching OVERRIDE_ARG,
    e.g. DEVICE_RATES=127.0.0.1:200 for OVERRIDE_ARG=127.0.0.1:200.
    All test packets use agent_address=127.0.0.1.
    """
    override_ip, override_rate = OVERRIDE_ARG.split(":")
    override_rate = int(override_rate)

    print(f"\n=== device rate override test ===")
    print(f"override: {override_ip} → {override_rate} (FORWARD_RATE={FORWARD_RATE})\n")

    # Send a packet with a deliberately wrong embedded rate.
    # The proxy should ignore the embedded rate and use the override.
    wrong_embedded = 1 if override_rate != 1 else 999
    pkt = make_flow_packet(device_rate=wrong_embedded)
    got = send_and_wait(pkt)
    if not got:
        check("packet received", False, "no packet at collector")
        return

    rate = parse_flow_sample_rate(got)
    check("output rate == FORWARD_RATE (not embedded rate)", rate == FORWARD_RATE, f"rate={rate}")

    if override_rate > FORWARD_RATE:
        ratio = override_rate // FORWARD_RATE
        pool_out = parse_flow_sample_pool(got)
        check(
            f"sample_pool ×{ratio} (override {override_rate} > {FORWARD_RATE})",
            pool_out == 500 * ratio,
            f"pool_out={pool_out}",
        )
    elif override_rate < FORWARD_RATE:
        check(f"override {override_rate} < {FORWARD_RATE} — probabilistic drop applied", True)
    else:
        pool_out = parse_flow_sample_pool(got)
        check("sample_pool unchanged (override == FORWARD_RATE)", pool_out == 500, f"pool={pool_out}")


def run_tests() -> None:
    # UDP collector
    collector_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    collector_sock.bind(("127.0.0.1", COLLECTOR_PORT))

    # TCP collector (same port number — different protocol, no conflict)
    tcp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server_sock.bind(("127.0.0.1", COLLECTOR_PORT))
    tcp_server_sock.listen(8)

    stop_event = threading.Event()
    threading.Thread(target=collector_thread, args=(collector_sock, stop_event), daemon=True).start()
    threading.Thread(target=tcp_collector_thread, args=(tcp_server_sock, stop_event), daemon=True).start()

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_and_wait(pkt: bytes, wait: float = 0.3) -> bytes | None:
        with lock:
            received.clear()
        send_sock.sendto(pkt, (PROXY_HOST, PROXY_PORT))
        time.sleep(wait)
        with lock:
            return received[0] if received else None

    def tcp_send_and_wait(pkt: bytes, wait: float = 0.3) -> bytes | None:
        with lock:
            tcp_received.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((PROXY_HOST, PROXY_PORT))
        sock.sendall(struct.pack("!I", len(pkt)) + pkt)
        sock.close()
        time.sleep(wait)
        with lock:
            return tcp_received[0] if tcp_received else None

    # When testing device rate overrides, the proxy must be started with
    # DEVICE_RATES matching the override arg. Because all test packets use
    # agent_address=127.0.0.1, any active override affects every test — so
    # the two modes run exclusively.
    if OVERRIDE_ARG:
        _run_override_test(send_and_wait)
        stop_event.set()
        send_sock.close()
        collector_sock.close()
        tcp_server_sock.close()
        total = len(results)
        passed = sum(1 for _, ok, _ in results if ok)
        print(f"\n{'=' * 38}")
        print(f"Results: {passed}/{total} passed")
        if passed < total:
            sys.exit(1)
        return

    print("\n=== sflow-normalizer test suite ===\n")

    # -----------------------------------------------------------------------
    # Scenario 1: 1/1 → 1/100
    # Device samples every packet (rate=1). Proxy sub-samples probabilistically
    # so that forwarded flows at rate=100 represent the same traffic volume.
    # Expected: ~1% of flows forwarded, all stamped rate=100.
    # -----------------------------------------------------------------------
    print("Scenario 1: rate 1/1 → 1/100 (probabilistic sub-sampling)")
    N = 1000
    with lock:
        received.clear()
    for i in range(N):
        send_sock.sendto(make_flow_packet(device_rate=1, seq=i), (PROXY_HOST, PROXY_PORT))
    time.sleep(0.8)
    with lock:
        n_fwd = len(received)
        rates_1 = [parse_flow_sample_rate(p) for p in received]
    # With p=0.01 and n=1000: expected≈10, P(0 forwarded)≈0.004% — accept 1..40
    check(f"forwarded 1–40 of {N} (expected ~{N//100})", 1 <= n_fwd <= 40, f"forwarded={n_fwd}")
    check("all forwarded at rate=100", all(r == FORWARD_RATE for r in rates_1), f"rates={set(rates_1)}")

    # -----------------------------------------------------------------------
    # Scenario 2: 1/1000 → 1/100
    # Device samples 1-in-1000. Proxy scales counts ×10 so the collector sees
    # the correct traffic volume at rate=100.
    # -----------------------------------------------------------------------
    print("\nScenario 2: rate 1/1000 → 1/100 (count scaling ×10)")
    pkt = make_flow_packet(device_rate=1000)
    got = send_and_wait(pkt)
    if got:
        rate = parse_flow_sample_rate(got)
        pool_in = struct.unpack_from("!I", build_flow_sample(1000, 500), 12)[0]
        pool_out = parse_flow_sample_pool(got)
        check("rate == 100", rate == FORWARD_RATE, f"rate={rate}")
        check("sample_pool ×10", pool_out == pool_in * 10, f"pool_in={pool_in} pool_out={pool_out}")
    else:
        check("packet received", False, "no packet at collector")

    # -----------------------------------------------------------------------
    # Scenario 3: no embedded rate → 1/100
    # Device sends rate=0 (no rate info in header). Proxy substitutes
    # DEFAULT_SAMPLING_RATE and always stamps FORWARD_RATE in the output.
    # -----------------------------------------------------------------------
    print("\nScenario 3: no embedded rate (rate=0) → 1/100")
    pkt = make_flow_packet(device_rate=0)
    got = send_and_wait(pkt)
    if got:
        rate = parse_flow_sample_rate(got)
        check("rate stamped as 100", rate == FORWARD_RATE, f"rate={rate}")
        # DEFAULT=512 > TARGET=100 → pool also scaled ×5 to preserve volume
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE
        pool_out = parse_flow_sample_pool(got)
        check(
            f"sample_pool ×{expected_ratio} (DEFAULT={DEFAULT_SAMPLING_RATE} applied)",
            pool_out == 500 * expected_ratio,
            f"pool_out={pool_out}",
        )
    else:
        check("packet received", False, "no packet at collector")

    # --- Exact match (sanity) -------------------------------------------
    print("\nTest: Exact match (device_rate=100, target=100)")
    pkt = make_flow_packet(device_rate=100)
    got = send_and_wait(pkt)
    if got:
        rate = parse_flow_sample_rate(got)
        pool_out = parse_flow_sample_pool(got)
        check("rate == FORWARD_RATE", rate == FORWARD_RATE, f"rate={rate}")
        check("sample_pool unchanged", pool_out == 500, f"pool={pool_out}")
    else:
        check("packet received", False, "no packet at collector")

    # --- Upscale: device_rate=50 — probabilistic drop -------------------
    print("\nTest: Upscale (device_rate=50, target=100) — probabilistic drop")
    N = 200
    with lock:
        received.clear()
    for i in range(N):
        send_sock.sendto(make_flow_packet(device_rate=50, seq=i), (PROXY_HOST, PROXY_PORT))
    time.sleep(0.8)
    with lock:
        n_fwd = len(received)
        rates = [parse_flow_sample_rate(p) for p in received]
    lo, hi = int(N * 0.30), int(N * 0.70)
    check(f"forwarded [{lo}–{hi}] of {N}", lo <= n_fwd <= hi, f"forwarded={n_fwd}")
    check("all forwarded at rate=100", all(r == FORWARD_RATE for r in rates), f"rates={set(rates)}")

    # --- Counter sample pass-through ------------------------------------
    print("\nTest: Counter sample (byte-identical pass-through)")
    counter_payload = bytes(range(88))
    pkt = make_counter_packet(counter_payload)
    got = send_and_wait(pkt)
    if got:
        check("packet received", True)
        check("byte-identical to input", got == pkt, f"in={len(pkt)}B out={len(got)}B")
    else:
        check("packet received", False, "no packet at collector")

    # --- Malformed packet (drop, no crash) ------------------------------
    print("\nTest: Malformed packet (drop + no crash)")
    with lock:
        received.clear()
    send_sock.sendto(make_malformed_packet(), (PROXY_HOST, PROXY_PORT))
    # Then immediately send a valid packet to confirm loop still runs
    pkt = make_flow_packet(device_rate=100, seq=200)
    got = send_and_wait(pkt)
    check("proxy still alive after malformed packet", got is not None)

    # -----------------------------------------------------------------------
    # TCP tests
    # -----------------------------------------------------------------------
    print("\n--- TCP ---")

    # --- TCP Downscale --------------------------------------------------
    print("\nTest TCP: Downscale (device_rate=1000, target=100)")
    pkt = make_flow_packet(device_rate=1000)
    got = tcp_send_and_wait(pkt)
    if got:
        rate = parse_flow_sample_rate(got)
        pool_out = parse_flow_sample_pool(got)
        check("TCP rate == FORWARD_RATE", rate == FORWARD_RATE, f"rate={rate}")
        check("TCP sample_pool scaled ×10", pool_out == 500 * 10, f"pool_out={pool_out}")
    else:
        check("TCP packet received", False, "no packet at collector")

    # --- TCP Counter sample pass-through --------------------------------
    print("\nTest TCP: Counter sample (byte-identical pass-through)")
    counter_payload = bytes(range(88))
    pkt = make_counter_packet(counter_payload)
    got = tcp_send_and_wait(pkt)
    if got:
        check("TCP packet received", True)
        check("TCP byte-identical to input", got == pkt, f"in={len(pkt)}B out={len(got)}B")
    else:
        check("TCP packet received", False, "no packet at collector")

    # --- TCP Malformed (drop, no crash) ---------------------------------
    print("\nTest TCP: Malformed packet (drop + no crash)")
    with lock:
        tcp_received.clear()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((PROXY_HOST, PROXY_PORT))
    # Send a valid-looking length prefix but truncated body
    sock.sendall(struct.pack("!I", 100) + b"\xFF" * 10)
    sock.close()
    pkt = make_flow_packet(device_rate=100, seq=201)
    got = tcp_send_and_wait(pkt)
    check("TCP proxy still alive after malformed packet", got is not None)

    # --- Summary --------------------------------------------------------
    stop_event.set()
    send_sock.close()
    collector_sock.close()
    tcp_server_sock.close()

    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{'=' * 38}")
    print(f"Results: {passed}/{total} passed")
    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
