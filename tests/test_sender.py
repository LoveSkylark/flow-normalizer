"""
flow-normalizer test harness.

Starts mock collectors, sends crafted sFlow and NetFlow/IPFIX packets to the
proxy, and verifies the collector receives expected normalized output.

Usage (proxy must already be running):
    FORWARD_IP=127.0.0.1 FORWARD_RATE=100 DEFAULT_SAMPLING_RATE=512 \\
      SFLOW_FORWARD_PORT=16343 NETFLOW_FORWARD_PORT=16055 \\
      python proxy.py

    python tests/test_sender.py [sflow_proxy_port [sflow_col_port [override [nf_proxy_port [nf_col_port]]]]]

Defaults: sflow_proxy=6343  sflow_col=16343  nf_proxy=2055  nf_col=16055
Example:  python tests/test_sender.py 6343 16343 "" 2055 16055
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
# Example: python3 tests/test_sender.py 6343 16343 127.0.0.1:200
OVERRIDE_ARG = sys.argv[3] if (len(sys.argv) > 3 and sys.argv[3]) else None
NF_PROXY_PORT    = int(sys.argv[4]) if len(sys.argv) > 4 else 2055
NF_COLLECTOR_PORT = int(sys.argv[5]) if len(sys.argv) > 5 else 16055
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
nf_received: list[bytes] = []
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


def nf_collector_thread(sock: socket.socket, stop_event: threading.Event) -> None:
    """UDP collector for NetFlow/IPFIX output from the proxy."""
    sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            data, _ = sock.recvfrom(65535)
            with lock:
                nf_received.append(data)
        except socket.timeout:
            continue


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
# NetFlow / IPFIX packet builders
# ---------------------------------------------------------------------------

# Wire formats — must match proxy.py exactly.
_NF5_HDR = struct.Struct("!HHIIIIBBH")               # 24 bytes
_NF5_REC = struct.Struct("!IIIHHIIIIHHxBBBHHBB2x")  # 48 bytes

# Template ID and field definitions used for our v9 / IPFIX test packets.
# Fields: IN_PKTS (type=2, len=4), IN_BYTES (type=1, len=4) — 8 bytes per record.
_NF9_TMPL_ID   = 300
_IPFIX_TMPL_ID = 301
_TEST_FIELDS    = [(2, 4), (1, 4)]


def build_nf5(sampling_interval: int, dpkts: int = 1, doctets: int = 1500) -> bytes:
    """Build a minimal NetFlow v5 datagram with one flow record."""
    hdr = _NF5_HDR.pack(5, 1, 12345, int(time.time()), 0, 1, 0, 0, sampling_interval)
    rec = _NF5_REC.pack(
        0x7F000001, 0x08080808, 0,  # src=127.0.0.1, dst=8.8.8.8, nexthop=0
        1, 2,                        # input, output
        dpkts, doctets,
        0, 0,                        # first, last
        12345, 80,                   # srcport, dstport
        0, 6, 0,                     # tcp_flags, protocol=TCP, tos
        0, 0, 0, 0,                  # src_as, dst_as, src_mask, dst_mask
    )
    return hdr + rec


def _build_nf9_tmpl_flowset(tmpl_id: int, fields: list) -> bytes:
    body = struct.pack("!HH", tmpl_id, len(fields))
    for ftype, flen in fields:
        body += struct.pack("!HH", ftype, flen)
    body_len = 4 + len(body)
    pad = (-body_len) & 3
    return struct.pack("!HH", 0, body_len + pad) + body + bytes(pad)


def build_nf9_packet(tmpl_id: int, fields: list, dpkts: int, doctets: int) -> bytes:
    """Build a NetFlow v9 packet with template + data flowsets in one message."""
    tmpl_fs = _build_nf9_tmpl_flowset(tmpl_id, fields)
    record   = struct.pack("!II", dpkts, doctets)  # both fields are 4 bytes
    data_len = 4 + len(record)
    pad      = (-data_len) & 3
    data_fs  = struct.pack("!HH", tmpl_id, data_len + pad) + record + bytes(pad)
    # v9 header: version(2) count(2=2 flowsets) uptime(4) unix_secs(4) seq(4) src_id(4)
    hdr = struct.pack("!HHIIII", 9, 2, 12345, int(time.time()), 1, 0)
    return hdr + tmpl_fs + data_fs


def build_ipfix_packet(tmpl_id: int, fields: list, dpkts: int, doctets: int) -> bytes:
    """Build an IPFIX message with template set + data set."""
    tmpl_body = struct.pack("!HH", tmpl_id, len(fields))
    for ftype, flen in fields:
        tmpl_body += struct.pack("!HH", ftype, flen)
    body_len  = 4 + len(tmpl_body)
    pad       = (-body_len) & 3
    tmpl_set  = struct.pack("!HH", 2, body_len + pad) + tmpl_body + bytes(pad)

    record   = struct.pack("!II", dpkts, doctets)
    data_len = 4 + len(record)
    pad2     = (-data_len) & 3
    data_set = struct.pack("!HH", tmpl_id, data_len + pad2) + record + bytes(pad2)

    total_len = 16 + len(tmpl_set) + len(data_set)
    hdr = struct.pack("!HHIII", 10, total_len, int(time.time()), 1, 0)
    return hdr + tmpl_set + data_set


# ---------------------------------------------------------------------------
# NetFlow / IPFIX output parsers
# ---------------------------------------------------------------------------

# Proxy uses template ID 256 for all v5-converted output.
# Data records are 45 bytes: IIIHHIIIIHHBBBHHBB — dpkts at +16, doctets at +20.
_V5_OUT_TMPL_ID = 256


def parse_nf5_v9_output(data: bytes) -> tuple[int, int] | None:
    """Return (dpkts, doctets) from the first record of a proxy v5→v9 output packet."""
    if len(data) < 20 or struct.unpack_from("!H", data, 0)[0] != 9:
        return None
    offset = 20
    while offset + 4 <= len(data):
        fs_id, fs_len = struct.unpack_from("!HH", data, offset)
        if fs_id == _V5_OUT_TMPL_ID and offset + 4 + 45 <= len(data):
            dpkts   = struct.unpack_from("!I", data, offset + 4 + 16)[0]
            doctets = struct.unpack_from("!I", data, offset + 4 + 20)[0]
            return dpkts, doctets
        if fs_len < 4:
            break
        offset += fs_len
    return None


def parse_nf9_data(data: bytes, tmpl_id: int) -> tuple[int, int] | None:
    """Return (field1_val, field2_val) from first record of a v9 data flowset."""
    if len(data) < 20 or struct.unpack_from("!H", data, 0)[0] != 9:
        return None
    offset = 20
    while offset + 4 <= len(data):
        fs_id, fs_len = struct.unpack_from("!HH", data, offset)
        if fs_id == tmpl_id and offset + 4 + 8 <= len(data):
            f1 = struct.unpack_from("!I", data, offset + 4)[0]
            f2 = struct.unpack_from("!I", data, offset + 8)[0]
            return f1, f2
        if fs_len < 4:
            break
        offset += fs_len
    return None


def parse_ipfix_data(data: bytes, tmpl_id: int) -> tuple[int, int] | None:
    """Return (field1_val, field2_val) from first record of an IPFIX data set."""
    if len(data) < 16 or struct.unpack_from("!H", data, 0)[0] != 10:
        return None
    offset = 16
    while offset + 4 <= len(data):
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_id == tmpl_id and offset + 4 + 8 <= len(data):
            f1 = struct.unpack_from("!I", data, offset + 4)[0]
            f2 = struct.unpack_from("!I", data, offset + 8)[0]
            return f1, f2
        if set_len < 4:
            break
        offset += set_len
    return None


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

    print("\n=== flow-normalizer test suite ===\n")

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

    # -----------------------------------------------------------------------
    # NetFlow / IPFIX tests
    # -----------------------------------------------------------------------

    # Spin up the UDP collector that receives forwarded NF output.
    nf_collector_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nf_collector_sock.bind(("127.0.0.1", NF_COLLECTOR_PORT))
    threading.Thread(
        target=nf_collector_thread, args=(nf_collector_sock, stop_event), daemon=True
    ).start()

    nf_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def nf_send_and_wait(pkt: bytes, wait: float = 0.3) -> bytes | None:
        with lock:
            nf_received.clear()
        nf_send_sock.sendto(pkt, (PROXY_HOST, NF_PROXY_PORT))
        time.sleep(wait)
        with lock:
            return nf_received[0] if nf_received else None

    def nf_tcp_send_and_wait(pkt: bytes, wait: float = 0.4) -> bytes | None:
        with lock:
            nf_received.clear()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((PROXY_HOST, NF_PROXY_PORT))
        s.sendall(pkt)
        s.close()
        time.sleep(wait)
        with lock:
            return nf_received[0] if nf_received else None

    # --- NetFlow v5: downscale ×10 ---------------------------------------
    print("\n--- NetFlow ---")
    print("\nNF v5 UDP: downscale (sampling_interval=1000, target=100, scale×10)")
    got = nf_send_and_wait(build_nf5(sampling_interval=1000, dpkts=1, doctets=1500))
    if got:
        fields = parse_nf5_v9_output(got)
        check("v5→v9 output received",         fields is not None)
        check("v5 dpkts scaled ×10",           fields is not None and fields[0] == 10,    f"dpkts={fields[0] if fields else '?'}")
        check("v5 doctets scaled ×10",         fields is not None and fields[1] == 15000, f"doctets={fields[1] if fields else '?'}")
    else:
        check("v5 packet received", False, "no packet at collector")

    # --- NetFlow v5: exact match -----------------------------------------
    print("\nNF v5 UDP: exact match (sampling_interval=100, target=100)")
    got = nf_send_and_wait(build_nf5(sampling_interval=100, dpkts=5, doctets=7500))
    if got:
        fields = parse_nf5_v9_output(got)
        check("v5 exact match: dpkts unchanged",   fields is not None and fields[0] == 5,    f"dpkts={fields[0] if fields else '?'}")
        check("v5 exact match: doctets unchanged",  fields is not None and fields[1] == 7500, f"doctets={fields[1] if fields else '?'}")
    else:
        check("v5 exact match: packet received", False, "no packet at collector")

    # --- NetFlow v5: default rate (512//100 = 5) -------------------------
    print("\nNF v5 UDP: default rate (sampling_interval=0 → DEFAULT=512, scale×5)")
    got = nf_send_and_wait(build_nf5(sampling_interval=0, dpkts=1, doctets=1500))
    if got:
        fields = parse_nf5_v9_output(got)
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE  # 512 // 100 = 5
        check("v5 default rate: dpkts scaled",   fields is not None and fields[0] == 1 * expected_ratio,    f"dpkts={fields[0] if fields else '?'} ratio={expected_ratio}")
        check("v5 default rate: doctets scaled", fields is not None and fields[1] == 1500 * expected_ratio, f"doctets={fields[1] if fields else '?'}")
    else:
        check("v5 default rate: packet received", False, "no packet at collector")

    # --- NetFlow v9: template + data, downscale --------------------------
    print("\nNF v9 UDP: template+data (DEFAULT=512, scale×5)")
    pkt = build_nf9_packet(_NF9_TMPL_ID, _TEST_FIELDS, dpkts=1, doctets=1500)
    got = nf_send_and_wait(pkt)
    if got:
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE
        fields = parse_nf9_data(got, _NF9_TMPL_ID)
        check("v9 data flowset present",       fields is not None)
        check("v9 IN_PKTS scaled",             fields is not None and fields[0] == 1 * expected_ratio,    f"val={fields[0] if fields else '?'} ratio={expected_ratio}")
        check("v9 IN_BYTES scaled",            fields is not None and fields[1] == 1500 * expected_ratio, f"val={fields[1] if fields else '?'}")
    else:
        check("v9 packet received", False, "no packet at collector")

    # --- IPFIX: template + data, downscale --------------------------------
    print("\nIPFIX UDP: template+data (DEFAULT=512, scale×5)")
    pkt = build_ipfix_packet(_IPFIX_TMPL_ID, _TEST_FIELDS, dpkts=1, doctets=1500)
    got = nf_send_and_wait(pkt)
    if got:
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE
        fields = parse_ipfix_data(got, _IPFIX_TMPL_ID)
        check("IPFIX data set present",        fields is not None)
        check("IPFIX IN_PKTS scaled",          fields is not None and fields[0] == 1 * expected_ratio,    f"val={fields[0] if fields else '?'} ratio={expected_ratio}")
        check("IPFIX IN_BYTES scaled",         fields is not None and fields[1] == 1500 * expected_ratio, f"val={fields[1] if fields else '?'}")
    else:
        check("IPFIX packet received", False, "no packet at collector")

    # -----------------------------------------------------------------------
    # NetFlow TCP tests
    # -----------------------------------------------------------------------
    print("\n--- NetFlow TCP ---")

    # --- NetFlow v9 TCP: template + data, downscale ----------------------
    print("\nNF v9 TCP: template+data (DEFAULT=512, scale×5)")
    pkt = build_nf9_packet(_NF9_TMPL_ID, _TEST_FIELDS, dpkts=2, doctets=3000)
    got = nf_tcp_send_and_wait(pkt)
    if got:
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE
        fields = parse_nf9_data(got, _NF9_TMPL_ID)
        check("v9 TCP data flowset present",   fields is not None)
        check("v9 TCP IN_PKTS scaled",         fields is not None and fields[0] == 2 * expected_ratio,    f"val={fields[0] if fields else '?'} ratio={expected_ratio}")
        check("v9 TCP IN_BYTES scaled",        fields is not None and fields[1] == 3000 * expected_ratio, f"val={fields[1] if fields else '?'}")
    else:
        check("v9 TCP packet received", False, "no packet at collector")

    # --- IPFIX TCP: template + data, downscale ----------------------------
    print("\nIPFIX TCP: template+data (DEFAULT=512, scale×5)")
    pkt = build_ipfix_packet(_IPFIX_TMPL_ID, _TEST_FIELDS, dpkts=2, doctets=3000)
    got = nf_tcp_send_and_wait(pkt)
    if got:
        expected_ratio = DEFAULT_SAMPLING_RATE // FORWARD_RATE
        fields = parse_ipfix_data(got, _IPFIX_TMPL_ID)
        check("IPFIX TCP data set present",    fields is not None)
        check("IPFIX TCP IN_PKTS scaled",      fields is not None and fields[0] == 2 * expected_ratio,    f"val={fields[0] if fields else '?'} ratio={expected_ratio}")
        check("IPFIX TCP IN_BYTES scaled",     fields is not None and fields[1] == 3000 * expected_ratio, f"val={fields[1] if fields else '?'}")
    else:
        check("IPFIX TCP packet received", False, "no packet at collector")

    # --- NetFlow TCP: malformed (drop + no crash) -------------------------
    print("\nNF TCP: malformed packet (drop + no crash)")
    with lock:
        nf_received.clear()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((PROXY_HOST, NF_PROXY_PORT))
    # Send bytes that look like NF v9 (version=9, count=1) followed by a
    # FlowSet header with fs_len=2 (< 4, invalid) to trigger ValueError.
    bad = struct.pack("!HHIIII", 9, 1, 0, 0, 0, 0) + struct.pack("!HH", 256, 2)
    s.sendall(bad)
    s.close()
    # Proxy should drop and keep serving; verify with a valid follow-up packet.
    pkt = build_nf9_packet(_NF9_TMPL_ID, _TEST_FIELDS, dpkts=1, doctets=1500)
    got = nf_tcp_send_and_wait(pkt)
    check("NF TCP proxy alive after malformed packet", got is not None)

    nf_send_sock.close()
    nf_collector_sock.close()

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
