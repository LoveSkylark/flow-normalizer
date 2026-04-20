import os
import sys
import struct

import pytest

# Add parent directory to path so we can import test_sender
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault("FORWARD_IP", "127.0.0.1")

import proxy
from tests.test_sender_old import build_nf5_packet, build_nf5_record


def _set_random_draws(monkeypatch: pytest.MonkeyPatch, draws: list[float]) -> None:
    values = iter(draws)

    monkeypatch.delattr(proxy.random, "binomialvariate", raising=False)

    def fake_random() -> float:
        return next(values)

    monkeypatch.setattr(proxy.random, "random", fake_random)


def _extract_v5_converted_records(packet: bytes) -> list[tuple]:
    version, count, _, _, _, _ = struct.unpack_from("!HHIIII", packet, 0)
    assert version == 9

    offset = 20
    tmpl_fs_id, tmpl_fs_len = struct.unpack_from("!HH", packet, offset)
    assert tmpl_fs_id == 0

    offset += tmpl_fs_len
    data_fs_id, data_fs_len = struct.unpack_from("!HH", packet, offset)
    assert data_fs_id == proxy._V5_TMPL_ID

    body = packet[offset + 4: offset + data_fs_len]
    data_record_count = count - 1
    return [
        proxy._V5_DATA_REC.unpack_from(body, i * proxy._V5_DATA_REC.size)
        for i in range(data_record_count)
    ]


def _build_simple_flowset(tmpl_id: int, records: list[tuple[int, int]]) -> bytes:
    body = b"".join(
        pkts.to_bytes(4, "big") + octets.to_bytes(4, "big")
        for pkts, octets in records
    )
    total_len = 4 + len(body)
    pad = (-total_len) & 3
    return struct.pack("!HH", tmpl_id, total_len + pad) + body + bytes(pad)


def _extract_simple_flowset_records(flowset: bytes) -> list[tuple[int, int]]:
    fs_id, fs_len = struct.unpack_from("!HH", flowset, 0)
    assert fs_id >= 256
    body = flowset[4:fs_len]

    out: list[tuple[int, int]] = []
    for off in range(0, len(body), 8):
        chunk = body[off:off + 8]
        if len(chunk) < 8:
            break
        pkts = int.from_bytes(chunk[0:4], "big")
        octets = int.from_bytes(chunk[4:8], "big")
        out.append((pkts, octets))
    return out


@pytest.fixture(autouse=True)
def _clear_proxy_state():
    proxy._tmpl_cache.clear()
    proxy._source_last_seen.clear()
    proxy._fwd_last_seen.clear()
    yield
    proxy._tmpl_cache.clear()
    proxy._source_last_seen.clear()
    proxy._fwd_last_seen.clear()


def test_convert_nf5_to_nf9_drops_record_when_all_packets_thinned(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(proxy, "FORWARD_RATE", 100)

    _set_random_draws(monkeypatch, [0.99])

    record = build_nf5_record(
        src_ip="10.0.0.1",
        dst_ip="192.0.2.1",
        src_port=12345,
        dst_port=80,
        packets=1,
        octets=120,
        first=1000,
        last=2000,
    )
    packet = build_nf5_packet([record], seq=1, sampling_rate=1)

    out = proxy.convert_nf5_to_nf9(packet, "198.51.100.10")

    assert out is None


def test_convert_nf5_to_nf9_partially_keeps_large_flow(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(proxy, "FORWARD_RATE", 100)

    # p = 20 / 100 = 0.2, so exactly 2 of 5 packets survive here.
    _set_random_draws(monkeypatch, [0.10, 0.90, 0.05, 0.80, 0.70])

    record = build_nf5_record(
        src_ip="10.0.0.2",
        dst_ip="192.0.2.2",
        src_port=23456,
        dst_port=443,
        packets=5,
        octets=500,
        first=1000,
        last=2000,
    )
    packet = build_nf5_packet([record], seq=10, sampling_rate=20)

    out = proxy.convert_nf5_to_nf9(packet, "198.51.100.11")

    assert out is not None

    records = _extract_v5_converted_records(out)
    assert len(records) == 1

    rec = records[0]
    assert rec[5] == 2
    assert rec[6] == 200


def test_convert_nf5_to_nf9_keeps_counts_when_input_is_already_more_sampled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(proxy, "FORWARD_RATE", 10)

    record = build_nf5_record(
        src_ip="10.0.0.3",
        dst_ip="192.0.2.3",
        src_port=34567,
        dst_port=53,
        packets=7,
        octets=700,
        first=1000,
        last=2000,
        proto=17,
    )
    packet = build_nf5_packet([record], seq=20, sampling_rate=100)

    out = proxy.convert_nf5_to_nf9(packet, "198.51.100.12")

    assert out is not None

    records = _extract_v5_converted_records(out)
    assert len(records) == 1

    rec = records[0]
    assert rec[5] == 7
    assert rec[6] == 700


def test_normalize_data_flowset_uses_template_cache_and_drops_zero_packet_record(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(proxy, "FORWARD_RATE", 2)

    src_ip = "198.51.100.20"
    domain_id = 1234
    tmpl_id = 300

    proxy._tmpl_cache[src_ip] = {
        domain_id: {
            tmpl_id: [
                (proxy._NF_IN_PKTS, 4),
                (proxy._NF_IN_BYTES, 4),
            ]
        }
    }

    # device_rate=1, FORWARD_RATE=2 => p=0.5
    # first record: 1 packet -> 0 kept
    # second record: 4 packets -> 2 kept
    _set_random_draws(monkeypatch, [0.9, 0.1, 0.9, 0.2, 0.8])

    flowset = _build_simple_flowset(
        tmpl_id,
        [
            (1, 100),
            (4, 400),
        ],
    )

    out = proxy._normalize_data_flowset(
        flowset=flowset,
        tmpl_id=tmpl_id,
        src_ip=src_ip,
        domain_id=domain_id,
        device_rate=1,
    )

    assert out is not None

    fs_id, fs_len = struct.unpack_from("!HH", out, 0)
    assert fs_id == tmpl_id
    assert fs_len == 12
    assert _extract_simple_flowset_records(out) == [(2, 200)]


def test_binomial_sample_edge_cases():
    """Test _binomial_sample with edge cases."""
    assert proxy._binomial_sample(0, 0.5) == 0
    assert proxy._binomial_sample(10, 0.0) == 0
    assert proxy._binomial_sample(10, 1.0) == 10
    assert proxy._binomial_sample(-5, 0.5) == 0


def test_thin_packet_counter_edge_cases(monkeypatch: pytest.MonkeyPatch):
    """Test _thin_packet_counter with edge cases."""
    monkeypatch.setattr(proxy, "FORWARD_RATE", 100)

    assert proxy._thin_packet_counter(0, 50) == 0
    assert proxy._thin_packet_counter(-1, 50) == 0

    monkeypatch.setattr(proxy, "FORWARD_RATE", 0)
    assert proxy._thin_packet_counter(100, 50) == 100


def test_thin_octet_counter_edge_cases():
    """Test _thin_octet_counter with edge cases."""
    assert proxy._thin_octet_counter(0, 10, 5) == 0
    assert proxy._thin_octet_counter(100, 0, 5) == 0
    assert proxy._thin_octet_counter(100, 10, 0) == 0
    assert proxy._thin_octet_counter(100, 10, 10) == 100


def test_thin_octet_counter_scales_proportionally():
    """Test that byte scaling is proportional to packet thinning."""
    assert proxy._thin_octet_counter(1000, 100, 50) == 500
    assert proxy._thin_octet_counter(1000, 100, 25) == 250
    assert proxy._thin_octet_counter(500, 50, 10) == 100


def test_convert_nf5_to_nf9_rejects_wrong_version():
    """Test that non-v5 packets are rejected."""
    packet = struct.pack("!HHIIIIBBH", 4, 1, 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="Expected NF v5"):
        proxy.convert_nf5_to_nf9(packet, "198.51.100.1")


def test_convert_nf5_to_nf9_rejects_truncated_packet():
    """Test that truncated packets are rejected."""
    packet = b"\x00\x05"
    with pytest.raises(ValueError, match="NF v5 too short"):
        proxy.convert_nf5_to_nf9(packet, "198.51.100.1")


def test_convert_nf5_to_nf9_multiple_records_mixed_survival(monkeypatch: pytest.MonkeyPatch):
    """Test that multiple records are handled correctly with mixed survival rates."""
    monkeypatch.setattr(proxy, "FORWARD_RATE", 100)

    # Three records: tiny (1 pkt), small (5 pkts), large (100 pkts)
    # p = 10/100 = 0.1
    # tiny: 1 packet with draw 0.95 -> 0 survive (0.95 >= 0.1)
    # small: 5 packets with draws all >= 0.1 -> 0 survive
    # large: 10 packets with draws all < 0.1 -> 10 survive
    _set_random_draws(
        monkeypatch,
        [0.95] +  # tiny: 1 packet, p=0.1 -> 0 survive
        [0.15, 0.20, 0.11, 0.19, 0.12] +  # small: 5 packets, p=0.1 -> 0 survive (all >= 0.1)
        [0.01] * 10,  # large: 10 packets, p=0.1 -> 10 survive
    )

    records = [
        build_nf5_record("10.0.1.1", "192.0.2.1", 10000, 80, packets=1, octets=120, first=1000, last=2000),
        build_nf5_record("10.0.2.1", "192.0.2.2", 10001, 80, packets=5, octets=500, first=1000, last=2000),
        build_nf5_record("10.0.3.1", "192.0.2.3", 10002, 80, packets=10, octets=1000, first=1000, last=2000),
    ]
    packet = build_nf5_packet(records, seq=1, sampling_rate=10)

    out = proxy.convert_nf5_to_nf9(packet, "198.51.100.1")

    assert out is not None
    out_records = _extract_v5_converted_records(out)
    assert len(out_records) == 1

    rec_large = out_records[0]
    assert rec_large[5] == 10
    assert rec_large[6] == 1000


def test_normalize_data_flowset_with_no_template():
    """Test that flowset is returned unchanged if template is missing."""
    src_ip = "198.51.100.1"
    domain_id = 1234
    tmpl_id = 300

    flowset = _build_simple_flowset(tmpl_id, [(10, 1000)])

    out = proxy._normalize_data_flowset(
        flowset=flowset,
        tmpl_id=tmpl_id,
        src_ip=src_ip,
        domain_id=domain_id,
        device_rate=1,
    )

    assert out == flowset


def test_normalize_data_flowset_drops_all_records_if_all_zero_packets():
    """Test that flowset returns None if all records are thinned to zero packets."""
    monkeypatch: pytest.MonkeyPatch = pytest.MonkeyPatch()
    monkeypatch.setattr(proxy, "FORWARD_RATE", 1000)

    src_ip = "198.51.100.1"
    domain_id = 1234
    tmpl_id = 300

    proxy._tmpl_cache[src_ip] = {
        domain_id: {
            tmpl_id: [
                (proxy._NF_IN_PKTS, 4),
                (proxy._NF_IN_BYTES, 4),
            ]
        }
    }

    _set_random_draws(monkeypatch, [0.99, 0.99])

    flowset = _build_simple_flowset(tmpl_id, [(1, 100), (1, 100)])

    out = proxy._normalize_data_flowset(
        flowset=flowset,
        tmpl_id=tmpl_id,
        src_ip=src_ip,
        domain_id=domain_id,
        device_rate=1,
    )

    assert out is None


def test_normalize_data_flowset_scales_bytes_without_packet_field(monkeypatch: pytest.MonkeyPatch):
    """Test byte scaling when only byte field is present (no packet field)."""
    monkeypatch.setattr(proxy, "FORWARD_RATE", 2)

    src_ip = "198.51.100.1"
    domain_id = 1234
    tmpl_id = 300

    proxy._tmpl_cache[src_ip] = {
        domain_id: {
            tmpl_id: [
                (proxy._NF_IN_BYTES, 4),
            ]
        }
    }

    flowset = _build_simple_flowset(tmpl_id, [(0, 1000)])

    out = proxy._normalize_data_flowset(
        flowset=flowset,
        tmpl_id=tmpl_id,
        src_ip=src_ip,
        domain_id=domain_id,
        device_rate=1,
    )

    assert out is not None
    records = _extract_simple_flowset_records(out)
    assert len(records) == 1
    assert records[0][1] == 500