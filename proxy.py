import asyncio
import os
import random
import socket
import struct
import sys
import time

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

# How long a source must be silent before it is logged again (seconds).
SOURCE_LOG_INTERVAL = int(os.environ.get("SOURCE_LOG_INTERVAL", 300))
_source_last_seen: dict[str, float] = {}

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


# ─── sFlow helpers ────────────────────────────────────────────────────────────

def _maybe_log_source(data: bytes, transport: str) -> None:
    """Log a source on first appearance and again after SOURCE_LOG_INTERVAL silence.

    Reads the raw datagram before any normalization so the log reflects exactly
    what the device is sending.
    """
    if len(data) < DATAGRAM_HEADER_SIZE:
        return
    if struct.unpack_from("!I", data, 4)[0] != 1:  # only IPv4 agent addresses
        return

    agent_ip = socket.inet_ntoa(data[8:12])
    now = time.monotonic()
    last = _source_last_seen.get(agent_ip)
    if last is not None and now - last < SOURCE_LOG_INTERVAL:
        return
    _source_last_seen[agent_ip] = now

    label = "NEW_SOURCE" if last is None else "SOURCE_REAPPEARED"

    sub_agent_id = struct.unpack_from("!I", data, 12)[0]
    seq           = struct.unpack_from("!I", data, 16)[0]
    num_samples   = struct.unpack_from("!I", data, 24)[0]

    # Walk samples to tally types and grab the first embedded flow rate.
    flow_count = counter_count = 0
    embedded_rate: int | None = None
    offset = DATAGRAM_HEADER_SIZE
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


# ─── NetFlow processing ───────────────────────────────────────────────────────

def _nf_device_rate(src_ip: str, embedded_rate: int = 0) -> int:
    """Resolve effective device sampling rate for a NetFlow/IPFIX source.

    Priority: DEVICE_RATES override → embedded rate → DEFAULT_SAMPLING_RATE.
    """
    if src_ip in DEVICE_RATES:
        return DEVICE_RATES[src_ip]
    return embedded_rate if embedded_rate > 0 else DEFAULT_SAMPLING_RATE


def _maybe_log_nf_source(data: bytes, src_ip: str) -> None:
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

        if device_rate > FORWARD_RATE:
            action = f"downscale×{device_rate // FORWARD_RATE}"
        elif device_rate < FORWARD_RATE:
            action = f"upscale_prob={round(device_rate / FORWARD_RATE * 100)}%_forwarded"
        else:
            action = "exact_match"

        extra = (f" flow_records={count} seq={flow_seq}"
                 f" sampling_interval={sampling_int} rate_src={rate_src} action={action} →v9")

    elif version == 9:
        if len(data) < 20:
            return
        _, count, _, _, pkg_seq, source_id = struct.unpack_from("!HHIIII", data, 0)
        device_rate = _nf_device_rate(src_ip)
        rate_src = (f"override={device_rate}" if src_ip in DEVICE_RATES
                    else f"default={DEFAULT_SAMPLING_RATE}")
        extra = f" records={count} seq={pkg_seq} source_id={source_id} rate_src={rate_src}"

    elif version == 10:  # IPFIX
        if len(data) < 16:
            return
        _, msg_len, _, seq_num, obs_domain_id = struct.unpack_from("!HHIII", data, 0)
        device_rate = _nf_device_rate(src_ip)
        rate_src = (f"override={device_rate}" if src_ip in DEVICE_RATES
                    else f"default={DEFAULT_SAMPLING_RATE}")
        extra = (f" msg_len={msg_len} seq={seq_num}"
                 f" obs_domain_id={obs_domain_id} rate_src={rate_src}")

    else:
        return  # unknown version — parse_netflow will raise, skip logging

    print(f"{ts} {label} src={src_ip} version={version}{extra}", flush=True)


def _cache_nf9_templates(
    data: bytes, start: int, end: int, src_ip: str, domain_id: int
) -> None:
    """Parse v9 Template FlowSet records in data[start:end] and update _tmpl_cache."""
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
    """Normalise IN_PKTS / IN_BYTES fields in a v9 or IPFIX data FlowSet.

    Returns the modified FlowSet bytes, the original FlowSet if the template is
    not yet cached (unknown template), or None if every record was dropped.
    """
    fields = _tmpl_cache.get(src_ip, {}).get(domain_id, {}).get(tmpl_id)
    if fields is None:
        return flowset  # unknown template — forward as-is

    record_size = sum(flen for _, flen in fields)
    if record_size == 0:
        return flowset

    # Pre-compute (offset_within_record, field_len) for fields we need to scale.
    scale_fields: list[tuple[int, int]] = []
    rec_off = 0
    for ftype, flen in fields:
        if ftype in (_NF_IN_PKTS, _NF_IN_BYTES, _NF_OUT_PKTS, _NF_OUT_BYTES):
            scale_fields.append((rec_off, flen))
        rec_off += flen

    out_records = bytearray()
    offset = 4   # skip 4-byte FlowSet header
    end = len(flowset)

    while offset + record_size <= end:
        record = bytearray(flowset[offset : offset + record_size])

        if device_rate < FORWARD_RATE:
            if random.random() >= device_rate / FORWARD_RATE:
                offset += record_size
                continue  # probabilistically dropped

        if device_rate > FORWARD_RATE and scale_fields:
            ratio = device_rate // FORWARD_RATE
            for foff, flen in scale_fields:
                val = int.from_bytes(record[foff : foff + flen], "big")
                val = min(val * ratio, (1 << (flen * 8)) - 1)
                record[foff : foff + flen] = val.to_bytes(flen, "big")

        out_records += record
        offset += record_size

    if not out_records:
        return None

    pad = (-len(out_records)) & 3
    total = 4 + len(out_records) + pad
    hdr = bytearray(flowset[:4])
    struct.pack_into("!H", hdr, 2, total)
    return bytes(hdr) + bytes(out_records) + bytes(pad)


def convert_nf5_to_nf9(data: bytes, src_ip: str) -> bytes | None:
    """Parse a NetFlow v5 datagram, normalise flows, and return a NetFlow v9 datagram.

    The v9 output includes a Template FlowSet (template ID 256) followed by a
    Data FlowSet.  Sampling rate resolution (highest priority first):
      1. DEVICE_RATES override keyed by src_ip
      2. Embedded sampling_interval from the v5 header (lower 14 bits, if > 0)
      3. DEFAULT_SAMPLING_RATE fallback
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

    out_records: list[bytes] = []
    for i in range(count):
        srcaddr, dstaddr, nexthop, inp, outp, dpkts, doctets, \
            first, last, srcport, dstport, tcp_flags, prot, tos, \
            src_as, dst_as, src_mask, dst_mask = \
            _NF5_REC.unpack_from(data, _NF5_HDR.size + i * _NF5_REC.size)

        if device_rate < FORWARD_RATE:
            if random.random() >= device_rate / FORWARD_RATE:
                continue  # probabilistically dropped

        if device_rate > FORWARD_RATE:
            ratio = device_rate // FORWARD_RATE
            dpkts   = min(dpkts   * ratio, 0xFFFF_FFFF)
            doctets = min(doctets * ratio, 0xFFFF_FFFF)

        out_records.append(_V5_DATA_REC.pack(
            srcaddr, dstaddr, nexthop, inp, outp,
            dpkts, doctets, first, last,
            srcport, dstport, tcp_flags, prot, tos,
            src_as, dst_as, src_mask, dst_mask,
        ))

    if not out_records:
        return None

    # v9 header: version(2) count(2) uptime(4) unix_secs(4) pkg_seq(4) source_id(4)
    # count = 1 template record + N data records
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
        _maybe_log_source(data, "UDP")
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
            self._sock.sendto(packet, (FORWARD_IP, SFLOW_FORWARD_PORT))

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
            self._sock.sendto(packet, (FORWARD_IP, NETFLOW_FORWARD_PORT))

    def error_received(self, exc: Exception) -> None:
        print(f"NetFlow socket error: {exc}", file=sys.stderr, flush=True)


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
                length_bytes = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                break  # clean disconnect
            length = _TCP_FRAME.unpack(length_bytes)[0]
            try:
                data = await reader.readexactly(length)
            except asyncio.IncompleteReadError:
                break

            _maybe_log_source(data, "TCP")
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

    override_info = f" device_overrides={len(DEVICE_RATES)}" if DEVICE_RATES else ""
    print(
        f"flow-normalizer sflow listening on :{SFLOW_PORT} (UDP+TCP) "
        f"→ {FORWARD_IP}:{SFLOW_FORWARD_PORT} "
        f"forward_rate={FORWARD_RATE} default_rate={DEFAULT_SAMPLING_RATE}"
        f"{override_info}",
        flush=True,
    )
    print(
        f"netflow-normalizer listening on :{NETFLOW_LISTEN_PORT} (UDP) "
        f"→ {FORWARD_IP}:{NETFLOW_FORWARD_PORT} "
        f"(v5→v9 conversion, v9/IPFIX normalise-in-place)",
        flush=True,
    )

    try:
        async with tcp_server:
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()
        forward_sock.close()
        nf_transport.close()
        nf_forward_sock.close()


if __name__ == "__main__":
    asyncio.run(main())
