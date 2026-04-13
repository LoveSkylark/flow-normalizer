import asyncio
import os
import random
import socket
import struct
import sys
import time
import math

SFLOW_PORT = int(os.environ.get("SFLOW_PORT", 6343))
FORWARD_RATE = int(os.environ.get("FORWARD_RATE", 100))  # sampling rate stamped on all forwarded flows
DEFAULT_SAMPLING_RATE = int(os.environ.get("DEFAULT_SAMPLING_RATE", 512))
FORWARD_IP = os.environ["FORWARD_IP"]
SFLOW_FORWARD_PORT = int(os.environ.get("SFLOW_FORWARD_PORT", 6343))

NETFLOW_LISTEN_PORT = int(os.environ.get("NETFLOW_LISTEN_PORT", 2055))
NETFLOW_FORWARD_PORT = int(os.environ.get("NETFLOW_FORWARD_PORT", 2055))


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
        # IPv6 addresses must be in bracket notation: [::1]:1000
        if entry.startswith("["):
            bracket_end = entry.find("]")
            if bracket_end == -1 or not entry[bracket_end + 1:bracket_end + 2] == ":":
                print(f"device_rates: skipping invalid IPv6 entry {entry!r} (expected [addr]:rate)", file=sys.stderr)
                continue
            ip = entry[1:bracket_end]
            rate_str = entry[bracket_end + 2:]
        else:
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

# When true, forwarded UDP packets are sent with the original device's source IP
# instead of this host's IP, so the downstream collector sees the real exporter.
# UDP only — TCP transparent proxying requires kernel-level TPROXY (not implemented).
# Requires CAP_NET_ADMIN; add to docker-compose.yml: cap_add: [NET_ADMIN]
SPOOF_UDP_SOURCE = os.environ.get("SPOOF_UDP_SOURCE", "").lower() in ("1", "true", "yes")
_IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)  # Linux constant = 19

# How long a source must be silent before it is logged again (seconds).
SOURCE_LOG_INTERVAL = int(os.environ.get("SOURCE_LOG_INTERVAL", 300))
_source_last_seen: dict[str, float] = {}
_fwd_last_seen: dict[str, float] = {}

# Per-source UDP sockets used when SPOOF_UDP_SOURCE is enabled.
_udp_spoof_socks: dict[str, socket.socket] = {}

# Maximum number of entries in any per-source cache dict before the oldest is evicted.
_CACHE_MAXSIZE = 1000

# Safety limits for NetFlow/IPFIX over TCP framing.
_NF_MAX_MSG = 65535
_NF_MAX_FLOWSETS = 4096


def _maybe_evict(d: dict) -> None:
    """Remove the oldest (first-inserted) entry when d is at capacity."""
    if len(d) >= _CACHE_MAXSIZE:
        d.pop(next(iter(d)))


def _get_udp_spoof_sock(src_ip: str) -> socket.socket:
    """Return a UDP socket bound to src_ip via IP_TRANSPARENT, cached per source IP.

    IP_TRANSPARENT lets the socket bind to a non-local address so the forwarded
    packet reaches the collector with the original device IP as its UDP source,
    rather than this host's IP.  Requires CAP_NET_ADMIN.
    Supports both IPv4 and IPv6 source addresses.
    """
    sock = _udp_spoof_socks.get(src_ip)
    if sock is None:
        if len(_udp_spoof_socks) >= _CACHE_MAXSIZE:
            old_ip = next(iter(_udp_spoof_socks))
            _udp_spoof_socks.pop(old_ip).close()
        family = socket.AF_INET6 if ":" in src_ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, _IP_TRANSPARENT, 1)
        sock.bind((src_ip, 0))
        _udp_spoof_socks[src_ip] = sock
    return sock

DATAGRAM_HEADER_SIZE = 28
SAMPLE_TYPE_FLOW = 1
SAMPLE_TYPE_COUNTER = 2

_TCP_FRAME = struct.Struct("!I")  # 4-byte big-endian length prefix


# ─── NetFlow ──────────────────────────────────────────────────────────────────

# NetFlow v5 wire formats.
# Header (24 bytes): version(2) count(2) uptime(4) unix_secs(4) unix_nsecs(4)
#                    flow_seq(4) engine_type(1) engine_id(1) sampling_interval(2)
# Record (48 bytes): srcaddr(4) dstaddr(4) nexthop(4) input(2) output(2)
#                    dPkts(4) dOctets(4) first(4) last(4) srcport(2) dstport(2)
#                    pad1(1) tcp_flags(1) prot(1) tos(1) src_as(2) dst_as(2)
#                    src_mask(1) dst_mask(1) pad2(2)
_NF5_HDR = struct.Struct("!HHIIIIBBH")              # 24 bytes, 9 fields
_NF5_REC = struct.Struct("!IIIHHIIIIHHxBBBHHBB2x")  # 48 bytes, 18 fields (pads skipped)

# NetFlow v9 / IPFIX field type IDs used for normalization.
_NF_IN_PKTS   = 2
_NF_IN_BYTES  = 1
_NF_OUT_PKTS  = 24
_NF_OUT_BYTES = 23

# Template ID assigned to v5-converted flows in v9 output.
_V5_TMPL_ID = 256

# Template field definitions for v5→v9 output (18 fields, 45 bytes per record).
_V5_TMPL_FIELDS: list[tuple[int, int]] = [
    (8,  4),  # IPV4_SRC_ADDR
    (12, 4),  # IPV4_DST_ADDR
    (15, 4),  # IPV4_NEXT_HOP
    (10, 2),  # INPUT_SNMP
    (14, 2),  # OUTPUT_SNMP
    (2,  4),  # IN_PKTS
    (1,  4),  # IN_BYTES
    (22, 4),  # FIRST_SWITCHED
    (21, 4),  # LAST_SWITCHED
    (7,  2),  # L4_SRC_PORT
    (11, 2),  # L4_DST_PORT
    (6,  1),  # TCP_FLAGS
    (4,  1),  # PROTOCOL
    (5,  1),  # SRC_TOS
    (16, 2),  # SRC_AS
    (17, 2),  # DST_AS
    (9,  1),  # SRC_MASK
    (13, 1),  # DST_MASK
]

# Packing struct for v9 data records produced during v5→v9 conversion.
_V5_DATA_REC = struct.Struct("!IIIHHIIIIHHBBBHHBB")  # 45 bytes


def _build_v9_template_flowset() -> bytes:
    """Return the v9 Template FlowSet bytes included in every v5-converted packet."""
    tmpl = struct.pack("!HH", _V5_TMPL_ID, len(_V5_TMPL_FIELDS))
    tmpl += b"".join(struct.pack("!HH", t, l) for t, l in _V5_TMPL_FIELDS)
    body_len = 4 + len(tmpl)   # FlowSet header (4) + template record
    pad = (-body_len) & 3      # pad to 4-byte boundary
    return struct.pack("!HH", 0, body_len + pad) + tmpl + bytes(pad)


_V9_TMPL_FLOWSET = _build_v9_template_flowset()

# Template cache: src_ip → domain_id → template_id → [(field_type, field_length)]
_tmpl_cache: dict[str, dict[int, dict[int, list[tuple[int, int]]]]] = {}

# Frozenset for O(1) membership test in hot-path field scanning.
_NF_SCALE_TYPES = frozenset({_NF_IN_PKTS, _NF_IN_BYTES, _NF_OUT_PKTS, _NF_OUT_BYTES})

# Struct and max-value lookup for fast counter scaling of common field widths.
_SCALE_STRUCT: dict[int, struct.Struct] = {
    2: struct.Struct("!H"),
    4: struct.Struct("!I"),
    8: struct.Struct("!Q"),
}
_SCALE_MAX: dict[int, int] = {2: 0xFFFF, 4: 0xFFFF_FFFF, 8: 0xFFFF_FFFF_FFFF_FFFF}


def _read_uint_be(buf: bytes | bytearray, offset: int, size: int) -> int:
    return int.from_bytes(buf[offset:offset + size], "big")


def _write_uint_be(buf: bytearray, offset: int, size: int, value: int) -> None:
    max_value = (1 << (size * 8)) - 1
    buf[offset:offset + size] = max(0, min(int(value), max_value)).to_bytes(size, "big")


def _binomial_sample(n: int, p: float) -> int:
    if n <= 0 or p <= 0.0:
        return 0
    if p >= 1.0:
        return n

    fn = getattr(random, "binomialvariate", None)
    if fn is not None:
        return fn(n, p)

    # Use faster approximate for large n, small p (Poisson-like fallback)
    if n > 100 and p < 0.1:
        lmbda = n * p
        L = math.exp(-lmbda)
        k = 0
        prod = 1.0
        while prod > L:
            k += 1
            prod *= random.random()
        return k - 1

    if p > 0.5:
        return n - _binomial_sample(n, 1.0 - p)

    return sum(1 for _ in range(n) if random.random() < p)


def _thin_packet_counter(packet_count: int, p: float) -> int:
    """Accept pre-computed probability instead of device_rate."""
    if packet_count <= 0 or p <= 0.0:
        return 0
    if p >= 1.0:
        return packet_count
    return _binomial_sample(packet_count, p)


def _thin_octet_counter(octet_count: int, original_packets: int, kept_packets: int) -> int:
    if octet_count <= 0 or original_packets <= 0 or kept_packets <= 0:
        return 0
    if kept_packets >= original_packets:
        return octet_count
    avg_size = octet_count / original_packets
    return min(int(round(kept_packets * avg_size)), int(octet_count))


def _int_upscale_ratio(device_rate: int) -> int:
    """Integer upscale ratio: e.g. device_rate=512, FORWARD_RATE=100 → 5."""
    if FORWARD_RATE <= 0:
        return 1
    return max(1, device_rate // FORWARD_RATE)


# ─── sFlow processing ─────────────────────────────────────────────────────────

def _sflow_agent(data: bytes) -> tuple[str | None, int]:
    """Return (agent_ip_string, header_size) for an sFlow v5 datagram.

    sFlow header size depends on the agent address type:
      addr_type=1 → IPv4 (4-byte address)  → 28-byte header
      addr_type=2 → IPv6 (16-byte address) → 40-byte header

    Returns (None, 28) if the datagram is too short or the address type is unknown.
    The header_size is always valid so callers can safely use it for offset arithmetic.
    """
    if len(data) < 8:
        return None, DATAGRAM_HEADER_SIZE
    addr_type = struct.unpack_from("!I", data, 4)[0]
    if addr_type == 1:  # IPv4
        if len(data) >= 12:
            return socket.inet_ntoa(data[8:12]), 28
        return None, 28
    if addr_type == 2:  # IPv6
        if len(data) >= 24:
            return socket.inet_ntop(socket.AF_INET6, data[8:24]), 40
        return None, 40
    return None, DATAGRAM_HEADER_SIZE

def _maybe_log_sflow_source(data: bytes, transport: str) -> None:
    """Log a sFlow source on first appearance and again after SOURCE_LOG_INTERVAL silence.

    Reads the raw datagram before any normalization so the log reflects exactly
    what the device is sending.
    """
    agent_ip, hdr_size = _sflow_agent(data)
    if agent_ip is None or len(data) < hdr_size:
        return

    now = time.monotonic()
    last = _source_last_seen.get(agent_ip)
    if last is not None and now - last < SOURCE_LOG_INTERVAL:
        return
    if agent_ip not in _source_last_seen:
        _maybe_evict(_source_last_seen)
    _source_last_seen[agent_ip] = now

    label = "NEW_SOURCE" if last is None else "SOURCE_REAPPEARED"

    # sFlow header offsets are relative to hdr_size (varies with addr_type).
    # IPv4 hdr=28: sub_agent_id=12, seq=16, num_samples=24
    # IPv6 hdr=40: sub_agent_id=24, seq=28, num_samples=36
    sub_agent_id = struct.unpack_from("!I", data, hdr_size - 16)[0]
    seq           = struct.unpack_from("!I", data, hdr_size - 12)[0]
    num_samples   = struct.unpack_from("!I", data, hdr_size - 4)[0]

    # Walk samples to tally types and grab the first embedded flow rate.
    flow_count = counter_count = 0
    embedded_rate: int | None = None
    offset = hdr_size
    for _ in range(num_samples):
        if offset + 8 > len(data):
            break
        sample_type, sample_length = struct.unpack_from("!II", data, offset)
        if sample_type == SAMPLE_TYPE_FLOW:
            flow_count += 1
            if embedded_rate is None and offset + 16 + 4 <= len(data):
                # sampling_rate sits at byte 8 inside the flow sample data,
                # which starts at offset+8 — so it is at offset+16 overall.
                embedded_rate = struct.unpack_from("!I", data, offset + 16)[0]
        elif sample_type == SAMPLE_TYPE_COUNTER:
            counter_count += 1
        offset += 8 + sample_length

    # Describe what rate the proxy will apply and why.
    if embedded_rate is not None:
        if agent_ip in DEVICE_RATES:
            applied = DEVICE_RATES[agent_ip]
            rate_src = f"override={applied}"
        elif embedded_rate == 0:
            applied = DEFAULT_SAMPLING_RATE
            rate_src = f"no_rate→default={DEFAULT_SAMPLING_RATE}"
        else:
            applied = embedded_rate
            rate_src = f"embedded={embedded_rate}"

        if applied > FORWARD_RATE:
            action = f"downscale×{applied // FORWARD_RATE}"
        elif applied < FORWARD_RATE:
            action = f"upscale_prob={round(applied / FORWARD_RATE * 100)}%_forwarded"
        else:
            action = "exact_match"
        rate_info = f"embedded_rate={embedded_rate} rate_src={rate_src} action={action}"
    else:
        rate_info = "flow_samples=0"

    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(
        f"{ts} {label}"
        f" agent={agent_ip} transport={transport}"
        f" sub_agent_id={sub_agent_id} seq={seq}"
        f" flow_samples={flow_count} counter_samples={counter_count}"
        f" {rate_info}",
        flush=True,
    )


def _maybe_log_sflow_forward(packet: bytes, transport: str) -> None:
    """Log a forwarded sFlow packet, rate-limited per agent by SOURCE_LOG_INTERVAL."""
    agent_ip, hdr_size = _sflow_agent(packet)
    if agent_ip is None or len(packet) < hdr_size:
        return

    now = time.monotonic()
    last = _fwd_last_seen.get(agent_ip)
    if last is not None and now - last < SOURCE_LOG_INTERVAL:
        return
    if agent_ip not in _fwd_last_seen:
        _maybe_evict(_fwd_last_seen)
    _fwd_last_seen[agent_ip] = now

    seq         = struct.unpack_from("!I", packet, hdr_size - 12)[0]
    num_samples = struct.unpack_from("!I", packet, hdr_size - 4)[0]
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(
        f"{ts} SFLOW_FORWARDED agent={agent_ip} transport={transport}"
        f" dst={FORWARD_IP}:{SFLOW_FORWARD_PORT}"
        f" seq={seq} samples={num_samples} len={len(packet)}",
        flush=True,
    )


def _normalize_sflow_sample(data: bytes, agent_ip: str | None = None) -> bytes | None:
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


def _parse_sflow_datagram(data: bytes) -> bytes | None:
    if len(data) < DATAGRAM_HEADER_SIZE:
        raise ValueError(f"Datagram too short: {len(data)} bytes")

    version = struct.unpack_from("!I", data, 0)[0]
    if version != 5:
        raise ValueError(f"Unsupported sFlow version: {version}")

    # Extract agent_address for per-device rate table lookup.
    # hdr_size varies: 28 for IPv4 agents, 40 for IPv6 agents.
    agent_ip, hdr_size = _sflow_agent(data)

    num_samples = struct.unpack_from("!I", data, hdr_size - 4)[0]

    hdr   = bytearray(data[:hdr_size])
    parts: list[bytes | bytearray] = []
    offset     = hdr_size
    out_samples = 0

    for _ in range(num_samples):
        if offset + 8 > len(data):
            raise ValueError("Truncated sample record header")

        sample_type, sample_length = struct.unpack_from("!II", data, offset)
        record_header = data[offset : offset + 8]
        sample_data   = data[offset + 8 : offset + 8 + sample_length]

        if len(sample_data) < sample_length:
            raise ValueError(
                f"Truncated sample data: expected {sample_length}, got {len(sample_data)}"
            )

        if sample_type == SAMPLE_TYPE_FLOW:
            sample_data = _normalize_sflow_sample(sample_data, agent_ip)
            if sample_data is None:
                offset += 8 + sample_length
                continue  # probabilistically dropped
            record_header = struct.pack("!II", sample_type, len(sample_data))

        parts.append(record_header)
        parts.append(sample_data)
        out_samples += 1
        offset += 8 + sample_length

    if out_samples == 0:
        return None  # nothing left to forward

    struct.pack_into("!I", hdr, hdr_size - 4, out_samples)
    return bytes(hdr) + b"".join(parts)


# ─── NetFlow processing ───────────────────────────────────────────────────────

def _nf_device_rate(src_ip: str, embedded_rate: int = 0) -> int:
    """Resolve effective device sampling rate for a NetFlow/IPFIX source.

    Priority: DEVICE_RATES override → embedded rate → DEFAULT_SAMPLING_RATE.
    """
    if src_ip in DEVICE_RATES:
        return DEVICE_RATES[src_ip]
    return embedded_rate if embedded_rate > 0 else DEFAULT_SAMPLING_RATE


def _maybe_log_nf_source(data: bytes, src_ip: str, transport: str = "UDP") -> None:
    """Log a NetFlow/IPFIX source on first appearance and after SOURCE_LOG_INTERVAL silence.

    Uses the same _source_last_seen table as sFlow so a device is never
    double-logged within the interval regardless of which protocol it sends.
    """
    if len(data) < 2:
        return

    now = time.monotonic()
    last = _source_last_seen.get(src_ip)
    if last is not None and now - last < SOURCE_LOG_INTERVAL:
        return
    if src_ip not in _source_last_seen:
        _maybe_evict(_source_last_seen)
    _source_last_seen[src_ip] = now

    label = "NF_NEW_SOURCE" if last is None else "NF_SOURCE_REAPPEARED"
    version = struct.unpack_from("!H", data, 0)[0]
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")

    if version == 5:
        if len(data) < _NF5_HDR.size:
            return
        _, count, _, _, _, flow_seq, _etype, _eid, sampling_int = _NF5_HDR.unpack_from(data, 0)
        sampling_value = sampling_int & 0x3FFF
        device_rate = _nf_device_rate(src_ip, sampling_value)

        if src_ip in DEVICE_RATES:
            rate_src = f"override={device_rate}"
        elif sampling_value > 0:
            rate_src = f"embedded={sampling_value}"
        else:
            rate_src = f"no_rate→default={DEFAULT_SAMPLING_RATE}"

        if device_rate < FORWARD_RATE:
            action = f"binomial_thin_p={device_rate / FORWARD_RATE:.6f}"
        elif device_rate == FORWARD_RATE:
            action = "exact_match"
        else:
            action = f"upscale_ratio={device_rate / FORWARD_RATE:.6f}"
        extra = (
            f" flow_records={count} seq={flow_seq}"
            f" sampling_interval={sampling_int} rate_src={rate_src} action={action} →v9"
        )

    elif version == 9:
        if len(data) < 20:
            return
        _, count, _, _, pkg_seq, source_id = struct.unpack_from("!HHIIII", data, 0)
        device_rate = _nf_device_rate(src_ip)
        rate_src = (
            f"override={device_rate}"
            if src_ip in DEVICE_RATES
            else f"default={DEFAULT_SAMPLING_RATE}"
        )
        extra = f" records={count} seq={pkg_seq} source_id={source_id} rate_src={rate_src}"

    elif version == 10:  # IPFIX
        if len(data) < 16:
            return
        _, msg_len, _, seq_num, obs_domain_id = struct.unpack_from("!HHIII", data, 0)
        device_rate = _nf_device_rate(src_ip)
        rate_src = (
            f"override={device_rate}"
            if src_ip in DEVICE_RATES
            else f"default={DEFAULT_SAMPLING_RATE}"
        )
        extra = (
            f" msg_len={msg_len} seq={seq_num}"
            f" obs_domain_id={obs_domain_id} rate_src={rate_src}"
        )

    else:
        return  # unknown version — parse_netflow will raise, skip logging

    print(f"{ts} {label} src={src_ip} transport={transport} version={version}{extra}", flush=True)


def _maybe_log_nf_forward(packet: bytes, src_ip: str, transport: str = "UDP") -> None:
    """Log a forwarded NetFlow/IPFIX packet, rate-limited per source by SOURCE_LOG_INTERVAL."""
    if len(packet) < 2:
        return

    now = time.monotonic()
    last = _fwd_last_seen.get(src_ip)
    if last is not None and now - last < SOURCE_LOG_INTERVAL:
        return
    if src_ip not in _fwd_last_seen:
        _maybe_evict(_fwd_last_seen)
    _fwd_last_seen[src_ip] = now

    version = struct.unpack_from("!H", packet, 0)[0]
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")

    if version == 9 and len(packet) >= 20:
        _, count, _, _, pkg_seq, source_id = struct.unpack_from("!HHIIII", packet, 0)
        print(
            f"{ts} NF_FORWARDED src={src_ip} transport={transport} dst={FORWARD_IP}:{NETFLOW_FORWARD_PORT}"
            f" version=9 records={count} seq={pkg_seq} source_id={source_id} len={len(packet)}",
            flush=True,
        )
    elif version == 10 and len(packet) >= 16:
        _, msg_len, _, seq_num, obs_domain_id = struct.unpack_from("!HHIII", packet, 0)
        print(
            f"{ts} NF_FORWARDED src={src_ip} transport={transport} dst={FORWARD_IP}:{NETFLOW_FORWARD_PORT}"
            f" version=10 msg_len={msg_len} seq={seq_num} obs_domain_id={obs_domain_id} len={len(packet)}",
            flush=True,
        )


def _cache_nf9_templates(
    data: bytes, start: int, end: int, src_ip: str, domain_id: int
) -> None:
    """Parse v9 Template FlowSet records in data[start:end] and update _tmpl_cache."""
    if src_ip not in _tmpl_cache:
        _maybe_evict(_tmpl_cache)
    domain = _tmpl_cache.setdefault(src_ip, {}).setdefault(domain_id, {})
    off = start
    while off + 4 <= end:
        tmpl_id, field_count = struct.unpack_from("!HH", data, off)
        off += 4
        if tmpl_id < 256:
            break  # padding
        fields: list[tuple[int, int]] = []
        for _ in range(field_count):
            if off + 4 > end:
                break
            ftype, flen = struct.unpack_from("!HH", data, off)
            off += 4
            fields.append((ftype, flen))
        domain[tmpl_id] = fields


def _cache_ipfix_templates(
    data: bytes, start: int, end: int, src_ip: str, domain_id: int
) -> None:
    """Parse IPFIX Template Set records in data[start:end] and update _tmpl_cache.

    Enterprise-specific fields (bit 15 of field type = 1) consume an extra
    4-byte enterprise ID; the stripped type (bit 15 cleared) is cached.
    """
    if src_ip not in _tmpl_cache:
        _maybe_evict(_tmpl_cache)
    domain = _tmpl_cache.setdefault(src_ip, {}).setdefault(domain_id, {})
    off = start
    while off + 4 <= end:
        tmpl_id, field_count = struct.unpack_from("!HH", data, off)
        off += 4
        if tmpl_id < 256:
            break  # padding
        fields: list[tuple[int, int]] = []
        for _ in range(field_count):
            if off + 4 > end:
                break
            ftype, flen = struct.unpack_from("!HH", data, off)
            off += 4
            if ftype & 0x8000:    # enterprise bit set
                off += 4          # skip 4-byte enterprise ID
                ftype &= 0x7FFF
            fields.append((ftype, flen))
        domain[tmpl_id] = fields


def _normalize_data_flowset(
    flowset: bytes,
    tmpl_id: int,
    src_ip: str,
    domain_id: int,
    device_rate: int,
) -> bytes | None:
    """Normalise packet and byte counters in a v9 or IPFIX data FlowSet.

    device_rate > FORWARD_RATE: upscale counters (unbiased stochastic rounding)
    device_rate < FORWARD_RATE: binomial thinning
    device_rate == FORWARD_RATE: pass through unchanged
    """
    fields = _tmpl_cache.get(src_ip, {}).get(domain_id, {}).get(tmpl_id)
    if fields is None:
        return flowset

    if FORWARD_RATE <= 0 or device_rate == FORWARD_RATE:
        return flowset

    upscale_ratio = _int_upscale_ratio(device_rate) if device_rate > FORWARD_RATE else 1
    p_keep = (device_rate / FORWARD_RATE) if device_rate < FORWARD_RATE else 1.0

    record_size = sum(flen for _, flen in fields)
    if record_size == 0:
        return flowset

    # Build offset index for all fields once.
    pkt_meta: dict[int, tuple[int, int]] = {}   # ftype → (offset, len)
    byte_meta: list[tuple[int, int, int]] = []   # (ftype, offset, len)
    rec_off = 0
    for ftype, flen in fields:
        if ftype in (_NF_IN_PKTS, _NF_OUT_PKTS):
            pkt_meta[ftype] = (rec_off, flen)
        elif ftype in (_NF_IN_BYTES, _NF_OUT_BYTES):
            byte_meta.append((ftype, rec_off, flen))
        rec_off += flen

    out_parts: list[bytes] = []
    out_len = 0
    offset = 4
    end = len(flowset)

    while offset + record_size <= end:
        record = bytearray(flowset[offset : offset + record_size])

        if device_rate > FORWARD_RATE:
            # Upscale: multiply all counters by integer ratio.
            for pkt_type in (_NF_IN_PKTS, _NF_OUT_PKTS):
                meta = pkt_meta.get(pkt_type)
                if not meta:
                    continue
                pkt_off, pkt_len = meta
                pkt_val = _read_uint_be(record, pkt_off, pkt_len)
                max_val = _SCALE_MAX.get(pkt_len, (1 << (pkt_len * 8)) - 1)
                _write_uint_be(record, pkt_off, pkt_len, min(pkt_val * upscale_ratio, max_val))

            for _btype, byte_off, byte_len in byte_meta:
                byte_val = _read_uint_be(record, byte_off, byte_len)
                max_val = _SCALE_MAX.get(byte_len, (1 << (byte_len * 8)) - 1)
                _write_uint_be(record, byte_off, byte_len, min(byte_val * upscale_ratio, max_val))

            out_parts.append(bytes(record))
            out_len += record_size

        else:
            # Downscale: binomial thinning per record.
            had_pkt_field = False
            any_kept = False
            orig_pkts: dict[int, int] = {}
            kept_pkts: dict[int, int] = {}

            for pkt_type in (_NF_IN_PKTS, _NF_OUT_PKTS):
                meta = pkt_meta.get(pkt_type)
                if not meta:
                    continue
                had_pkt_field = True
                pkt_off, pkt_len = meta
                pkt_val = _read_uint_be(record, pkt_off, pkt_len)
                kept = _thin_packet_counter(pkt_val, p_keep)
                orig_pkts[pkt_type] = pkt_val
                kept_pkts[pkt_type] = kept
                _write_uint_be(record, pkt_off, pkt_len, kept)
                if kept > 0:
                    any_kept = True

            if had_pkt_field and not any_kept:
                offset += record_size
                continue

            for btype, byte_off, byte_len in byte_meta:
                byte_val = _read_uint_be(record, byte_off, byte_len)
                pkt_type = _NF_IN_PKTS if btype == _NF_IN_BYTES else _NF_OUT_PKTS
                orig = orig_pkts.get(pkt_type, 0)
                kept = kept_pkts.get(pkt_type, 0)
                new_bytes = _thin_octet_counter(byte_val, orig, kept) if orig > 0 else int(round(byte_val * p_keep))
                _write_uint_be(record, byte_off, byte_len, new_bytes)

            out_parts.append(bytes(record))
            out_len += record_size

        offset += record_size

    if not out_parts:
        return None

    pad = (-out_len) & 3
    total = 4 + out_len + pad
    hdr = bytearray(flowset[:4])
    struct.pack_into("!H", hdr, 2, total)
    return bytes(hdr) + b"".join(out_parts) + bytes(pad)


def convert_nf5_to_nf9(data: bytes, src_ip: str) -> bytes | None:
    """Parse a NetFlow v5 datagram and return normalize
    """
    if len(data) < _NF5_HDR.size:
        raise ValueError(f"NF v5 too short: {len(data)}")

    version, count, uptime, unix_secs, _unix_nsecs, flow_seq, \
        _engine_type, _engine_id, sampling_int = _NF5_HDR.unpack_from(data, 0)

    if version != 5:
        raise ValueError(f"Expected NF v5, got version={version}")

    expected = _NF5_HDR.size + count * _NF5_REC.size
    if len(data) < expected:
        raise ValueError(f"NF v5 truncated: need {expected} bytes, got {len(data)}")

    device_rate = _nf_device_rate(src_ip, sampling_int & 0x3FFF)

    upscale_ratio = _int_upscale_ratio(device_rate) if device_rate > FORWARD_RATE else 1
    p_keep = (device_rate / FORWARD_RATE) if device_rate < FORWARD_RATE else 1.0

    out_records: list[bytes] = []
    for i in range(count):
        srcaddr, dstaddr, nexthop, inp, outp, dpkts, doctets, \
            first, last, srcport, dstport, tcp_flags, prot, tos, \
            src_as, dst_as, src_mask, dst_mask = \
            _NF5_REC.unpack_from(data, _NF5_HDR.size + i * _NF5_REC.size)

        if device_rate > FORWARD_RATE and FORWARD_RATE > 0:
            # Upscale: keep all records, integer ratio scaling.
            kept_pkts   = min(dpkts   * upscale_ratio, 0xFFFF_FFFF)
            kept_octets = min(doctets * upscale_ratio, 0xFFFF_FFFF)
        elif device_rate < FORWARD_RATE and FORWARD_RATE > 0:
            # Downscale: binomial thinning.
            kept_pkts = _thin_packet_counter(dpkts, p_keep)
            if kept_pkts <= 0:
                continue
            kept_octets = _thin_octet_counter(doctets, dpkts, kept_pkts)
        else:
            kept_pkts   = dpkts
            kept_octets = doctets

        out_records.append(_V5_DATA_REC.pack(
            srcaddr, dstaddr, nexthop, inp, outp,
            kept_pkts, kept_octets, first, last,
            srcport, dstport, tcp_flags, prot, tos,
            src_as, dst_as, src_mask, dst_mask,
        ))

    if not out_records:
        return None

    v9_hdr = struct.pack("!HHIIII", 9, 1 + len(out_records), uptime, unix_secs, flow_seq, 0)

    raw = b"".join(out_records)
    data_len = 4 + len(raw)
    pad = (-data_len) & 3
    data_flowset = struct.pack("!HH", _V5_TMPL_ID, data_len + pad) + raw + bytes(pad)

    return v9_hdr + _V9_TMPL_FLOWSET + data_flowset


def normalize_nf9(data: bytes, src_ip: str) -> bytes | None:
    """Parse a NetFlow v9 datagram, normalise data FlowSets, return modified datagram.

    Template FlowSets are cached so their field layout is known for normalisation,
    then forwarded unchanged.  Data FlowSets are normalised using the same
    upscale / downscale logic as sFlow, with device rate resolved from
    DEVICE_RATES / DEFAULT_SAMPLING_RATE (v9 Options Templates are not parsed
    for sampling info).
    """
    if len(data) < 20:
        raise ValueError(f"NF v9 too short: {len(data)}")

    version, _count, uptime, unix_secs, pkg_seq, source_id = \
        struct.unpack_from("!HHIIII", data, 0)
    if version != 9:
        raise ValueError(f"Not NF v9: version={version}")

    device_rate = _nf_device_rate(src_ip)

    out_flowsets: list[bytes] = []
    offset = 20

    while offset < len(data):
        if offset + 4 > len(data):
            break
        fs_id, fs_len = struct.unpack_from("!HH", data, offset)
        if fs_len < 4 or offset + fs_len > len(data):
            raise ValueError(f"Invalid v9 FlowSet at offset {offset}: id={fs_id} len={fs_len}")

        flowset = bytes(data[offset : offset + fs_len])

        if fs_id == 0:      # Template FlowSet
            _cache_nf9_templates(data, offset + 4, offset + fs_len, src_ip, source_id)
            out_flowsets.append(flowset)
        elif fs_id == 1:    # Options Template FlowSet — forward as-is
            out_flowsets.append(flowset)
        elif fs_id >= 256:  # Data FlowSet
            norm = _normalize_data_flowset(flowset, fs_id, src_ip, source_id, device_rate)
            if norm is not None:
                out_flowsets.append(norm)

        offset += fs_len

    if not out_flowsets:
        return None

    return bytes(data[:20]) + b"".join(out_flowsets)


def normalize_ipfix(data: bytes, src_ip: str) -> bytes | None:
    """Parse an IPFIX message, normalise data Sets, return modified message.

    Template Sets are cached and forwarded unchanged.  Data Sets are normalised
    with the same logic as NetFlow v9.  The IPFIX message length field is
    updated to reflect any dropped records.
    """
    if len(data) < 16:
        raise ValueError(f"IPFIX too short: {len(data)}")

    # IPFIX header: version(2) length(2) export_time(4) seq_num(4) obs_domain_id(4)
    version, _msg_len, _export_time, _seq_num, obs_domain_id = \
        struct.unpack_from("!HHIII", data, 0)
    if version != 10:
        raise ValueError(f"Not IPFIX: version={version}")

    device_rate = _nf_device_rate(src_ip)

    out_sets: list[bytes] = []
    offset = 16

    while offset < len(data):
        if offset + 4 > len(data):
            break
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4 or offset + set_len > len(data):
            raise ValueError(f"Invalid IPFIX Set at offset {offset}: id={set_id} len={set_len}")

        set_bytes = bytes(data[offset : offset + set_len])

        if set_id == 2:      # Template Set
            _cache_ipfix_templates(data, offset + 4, offset + set_len, src_ip, obs_domain_id)
            out_sets.append(set_bytes)
        elif set_id == 3:    # Options Template Set — forward as-is
            out_sets.append(set_bytes)
        elif set_id >= 256:  # Data Set
            norm = _normalize_data_flowset(set_bytes, set_id, src_ip, obs_domain_id, device_rate)
            if norm is not None:
                out_sets.append(norm)

        offset += set_len

    if not out_sets:
        return None

    out_data = b"".join(out_sets)
    hdr = bytearray(data[:16])
    struct.pack_into("!H", hdr, 2, 16 + len(out_data))
    return bytes(hdr) + out_data


def parse_netflow(data: bytes, src_ip: str) -> bytes | None:
    """Detect NetFlow / IPFIX version and route to the appropriate handler.

    v5  → converted to v9 with normalised flow counts
    v9  → normalised in place (template FlowSets cached and forwarded unchanged)
    v10 → IPFIX, normalised in place
    """
    if len(data) < 2:
        raise ValueError("Packet too short to detect version")
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return convert_nf5_to_nf9(data, src_ip)
    if version == 9:
        return normalize_nf9(data, src_ip)
    if version == 10:
        return normalize_ipfix(data, src_ip)
    raise ValueError(f"Unknown NetFlow/IPFIX version: {version}")


# ─── Protocol handlers ────────────────────────────────────────────────────────

class SFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, forward_sock: socket.socket) -> None:
        self._sock = forward_sock

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        _maybe_log_sflow_source(data, "UDP")
        try:
            packet = _parse_sflow_datagram(data)
        except Exception as exc:
            print(
                f"DROP {addr[0]} len={len(data)}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        if packet is not None:
            if SPOOF_UDP_SOURCE:
                _get_udp_spoof_sock(addr[0]).sendto(packet, (FORWARD_IP, SFLOW_FORWARD_PORT))
            else:
                self._sock.sendto(packet, (FORWARD_IP, SFLOW_FORWARD_PORT))
            _maybe_log_sflow_forward(packet, "UDP")

    def error_received(self, exc: Exception) -> None:
        print(f"Socket error: {exc}", file=sys.stderr, flush=True)


class NetFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, forward_sock: socket.socket) -> None:
        self._sock = forward_sock

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        _maybe_log_nf_source(data, addr[0])
        try:
            packet = parse_netflow(data, addr[0])
        except Exception as exc:
            print(
                f"NF DROP {addr[0]} len={len(data)}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            return
        if packet is not None:
            if SPOOF_UDP_SOURCE:
                _get_udp_spoof_sock(addr[0]).sendto(packet, (FORWARD_IP, NETFLOW_FORWARD_PORT))
            else:
                self._sock.sendto(packet, (FORWARD_IP, NETFLOW_FORWARD_PORT))
            _maybe_log_nf_forward(packet, addr[0])

    def error_received(self, exc: Exception) -> None:
        print(f"NetFlow socket error: {exc}", file=sys.stderr, flush=True)


async def _read_sflow_tcp_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one length-prefixed sFlow TCP frame."""
    length_bytes = await reader.readexactly(4)
    length = _TCP_FRAME.unpack(length_bytes)[0]
    return await reader.readexactly(length)


async def _read_nf_tcp_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one NetFlow v9 or IPFIX message from TCP.

    IPFIX has explicit message length.
    NetFlow v9 has no message length on TCP, so read one FlowSet minimum then
    keep reading additional FlowSets until a short idle gap.
    """
    hdr = await reader.readexactly(4)
    version, second = struct.unpack_from("!HH", hdr, 0)

    if version == 10:  # IPFIX
        remaining = second - 4
        if not (0 <= remaining <= _NF_MAX_MSG):
            raise ValueError(f"IPFIX message length out of range: {second}")
        return hdr + await reader.readexactly(remaining)

    if version != 9:
        raise ValueError(f"Unsupported NetFlow version over TCP: {version}")

    hdr_rest = await reader.readexactly(16)
    parts: list[bytes] = [hdr, hdr_rest]
    total = 20

    # Require at least one FlowSet.
    fs_hdr = await reader.readexactly(4)
    fs_len = struct.unpack_from("!H", fs_hdr, 2)[0]
    if not (4 <= fs_len <= _NF_MAX_MSG):
        raise ValueError(f"NetFlow v9 FlowSet length invalid: {fs_len}")
    fs_body = await reader.readexactly(fs_len - 4)
    parts.extend([fs_hdr, fs_body])
    total += fs_len

    # Best-effort: collect more FlowSets until stream goes idle briefly.
    while total < _NF_MAX_MSG:
        try:
            fs_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=0.02)
        except asyncio.TimeoutError:
            break
        except asyncio.IncompleteReadError:
            break

        fs_len = struct.unpack_from("!H", fs_hdr, 2)[0]
        if not (4 <= fs_len <= _NF_MAX_MSG):
            raise ValueError(f"NetFlow v9 FlowSet length invalid: {fs_len}")

        fs_body = await reader.readexactly(fs_len - 4)
        parts.extend([fs_hdr, fs_body])
        total += fs_len

    return b"".join(parts)


async def handle_tcp_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peer = writer.get_extra_info("peername", ("unknown", 0))
    try:
        fwd_reader, fwd_writer = await asyncio.open_connection(FORWARD_IP, SFLOW_FORWARD_PORT)
    except Exception as exc:
        print(f"TCP fwd connect failed from {peer[0]}: {exc}", file=sys.stderr, flush=True)
        writer.close()
        await writer.wait_closed()
        return

    try:
        while True:
            try:
                data = await _read_sflow_tcp_frame(reader)
            except asyncio.IncompleteReadError:
                break  # clean disconnect

            _maybe_log_sflow_source(data, "TCP")
            try:
                packet = _parse_sflow_datagram(data)
            except Exception as exc:
                print(
                    f"DROP TCP {peer[0]} len={len(data)}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                continue

            if packet is not None:
                fwd_writer.write(_TCP_FRAME.pack(len(packet)) + packet)
                await fwd_writer.drain()
                _maybe_log_sflow_forward(packet, "TCP")
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


async def handle_nf_tcp_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    fwd_sock: socket.socket,
) -> None:
    """Accept a NetFlow/IPFIX TCP session, process frames, and forward via UDP.

    Uses _read_nf_tcp_frame for self-delimiting IPFIX (v10) and FlowSet-walked
    NetFlow v9 framing.  Forwarding reuses the same UDP path as the UDP handler,
    including SPOOF_UDP_SOURCE if enabled.
    """
    peer = writer.get_extra_info("peername", ("unknown", 0))
    peer_ip = peer[0]

    try:
        while True:
            try:
                data = await _read_nf_tcp_frame(reader)
            except asyncio.IncompleteReadError:
                break  # clean disconnect
            _maybe_log_nf_source(data, peer_ip, "TCP")
            try:
                packet = parse_netflow(data, peer_ip)
            except Exception as exc:
                print(
                    f"NF DROP TCP {peer_ip} len={len(data)}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            if packet is not None:
                if SPOOF_UDP_SOURCE:
                    _get_udp_spoof_sock(peer_ip).sendto(packet, (FORWARD_IP, NETFLOW_FORWARD_PORT))
                else:
                    fwd_sock.sendto(packet, (FORWARD_IP, NETFLOW_FORWARD_PORT))
                _maybe_log_nf_forward(packet, peer_ip, "TCP")
    except Exception as exc:
        print(f"NF TCP {peer_ip}: {exc}", file=sys.stderr, flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    print(
        f"RUNNING {__file__} | _NF_MAX_MSG={_NF_MAX_MSG} _NF_MAX_FLOWSETS={_NF_MAX_FLOWSETS}",
        flush=True,
    )
    if SPOOF_UDP_SOURCE:
        try:
            _test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _test.setsockopt(socket.SOL_IP, _IP_TRANSPARENT, 1)
            _test.close()
        except OSError as exc:
            print(
                f"SPOOF_UDP_SOURCE=true but IP_TRANSPARENT failed: {exc}\n"
                f"  → Add 'cap_add: [NET_ADMIN]' to the Docker service.",
                file=sys.stderr, flush=True,
            )
            sys.exit(1)

    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nf_forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: SFlowProtocol(forward_sock),
        local_addr=("0.0.0.0", SFLOW_PORT),
    )

    tcp_server = await asyncio.start_server(
        handle_tcp_connection,
        "0.0.0.0",
        SFLOW_PORT,
    )

    nf_transport, _ = await loop.create_datagram_endpoint(
        lambda: NetFlowProtocol(nf_forward_sock),
        local_addr=("0.0.0.0", NETFLOW_LISTEN_PORT),
    )

    nf_tcp_server = await asyncio.start_server(
        lambda r, w: handle_nf_tcp_connection(r, w, nf_forward_sock),
        "0.0.0.0",
        NETFLOW_LISTEN_PORT,
    )

    override_info = f" device_overrides={len(DEVICE_RATES)}" if DEVICE_RATES else ""
    spoof_info = " udp_src_spoof=on" if SPOOF_UDP_SOURCE else ""
    print(
        f"sflow is listening on :{SFLOW_PORT} (UDP+TCP) "
        f"→ {FORWARD_IP}:{SFLOW_FORWARD_PORT} "
        f"forward_rate={FORWARD_RATE} default_rate={DEFAULT_SAMPLING_RATE}"
        f"{override_info}{spoof_info}",
        flush=True,
    )
    print(
        f"netflow is listening on :{NETFLOW_LISTEN_PORT} (UDP+TCP) "
        f"→ {FORWARD_IP}:{NETFLOW_FORWARD_PORT} "
        f"(v5→v9 conversion, v9/IPFIX normalise-in-place){spoof_info}",
        flush=True,
    )

    try:
        async with tcp_server, nf_tcp_server:
            await asyncio.gather(
                tcp_server.serve_forever(),
                nf_tcp_server.serve_forever(),
            )
    finally:
        udp_transport.close()
        forward_sock.close()
        nf_transport.close()
        nf_forward_sock.close()


if __name__ == "__main__":
    asyncio.run(main())
