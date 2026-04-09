# flow-normalizer

A UDP/TCP proxy that receives **sFlow v5**, **NetFlow v5/v9**, and **IPFIX**
packets, normalises embedded sampling rates to a single configured target, and
forwards them to a downstream collector. Every device in your network can
sample at whatever rate it likes; the collector always sees one consistent rate
in every flow record.

sFlow is handled on one port (default 6343, UDP + TCP); NetFlow / IPFIX on a
separate port (default 2055, UDP only). NetFlow v5 input is converted to
NetFlow v9 on output. NetFlow v9 and IPFIX are normalised in place.

---

## How it works

sFlow v5 embeds a `sampling_rate` field in every flow sample. A device set to
1-in-1000 sampling will send far fewer flow records than a device set to
1-in-100, and a naïve collector that receives both will produce inconsistent
traffic-volume estimates unless it tracks per-device rates.

The proxy solves this by rewriting the `sampling_rate` field to `FORWARD_RATE`
on every outgoing packet and adjusting the flow counts accordingly:

| Device rate vs `FORWARD_RATE` | What the proxy does |
|---|---|
| `device_rate > FORWARD_RATE` | Scales `sample_pool` up by `device_rate / FORWARD_RATE`, stamps `FORWARD_RATE`. Collector sees correct traffic volume. |
| `device_rate == FORWARD_RATE` | Stamps `FORWARD_RATE`. No other changes. |
| `device_rate < FORWARD_RATE` | Probabilistically drops each flow sample with probability `1 − device_rate / FORWARD_RATE`, stamps `FORWARD_RATE` on those that pass. Expected traffic volume is preserved. |
| `device_rate == 0` (no rate embedded) | Assumes device is sampling at `DEFAULT_SAMPLING_RATE` (input assumption only), then applies the rule above. Output is still stamped `FORWARD_RATE`. |

Counter samples (type 2) are passed through byte-for-byte untouched — they
contain absolute hardware counters that are independent of sampling rate.

### Source identity is preserved

The sFlow v5 datagram header contains an `agent_address` field (the originating
device's own IP). The proxy copies the entire header verbatim, so the downstream
collector can still distinguish flows from different devices by `agent_address`
even though all packets arrive from the proxy's IP at the network layer.

---

## Transport

The proxy listens on the same port for both UDP and TCP simultaneously.

**UDP** — standard sFlow transport. Each datagram is self-contained; the proxy
receives, normalises, and re-sends as a single UDP datagram.

**TCP** — each sFlow datagram is framed with a 4-byte big-endian length prefix
(`uint32` byte count followed by the datagram bytes). The proxy maintains a
separate outbound TCP connection to the collector for each inbound TCP
connection, preserving the per-source session structure.

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`
and edit before starting.

| Variable | Default | Required | Description |
|---|---|---|---|
| `FORWARD_IP` | — | **yes** | Downstream collector IP address |
| `SFLOW_FORWARD_PORT` | `6343` | no | Downstream collector UDP/TCP port for sFlow |
| `FORWARD_RATE` | `100` | no | Sampling rate stamped into all forwarded flow samples |
| `DEFAULT_SAMPLING_RATE` | `512` | no | Assumed input rate for devices that send no embedded rate. Has no effect on the output rate — all output is always stamped `FORWARD_RATE`. |
| `DEVICE_RATES` | — | no | Per-device rate overrides — see below |
| `SFLOW_PORT` | `6343` | no | UDP/TCP port the proxy binds for sFlow. In Docker this is the **external** host port — the container always binds internally on 6343. |
| `NETFLOW_LISTEN_PORT` | `2055` | no | UDP port the proxy binds for NetFlow / IPFIX. In Docker this is the **external** host port — the container always binds internally on 2055. |
| `NETFLOW_FORWARD_PORT` | `2055` | no | Downstream collector UDP port for NetFlow / IPFIX output |

### Per-device rate overrides (`DEVICE_RATES`)

Some devices send flow data with no embedded rate and you know exactly what
rate they are running at. Others may embed a rate but it is wrong. `DEVICE_RATES`
lets you pin the assumed input rate per device IP, overriding both the embedded
rate and `DEFAULT_SAMPLING_RATE`.

For **sFlow** the match key is the `agent_address` field in the datagram header
— the device's own self-reported IP, not the network-layer source address.

For **NetFlow / IPFIX** the match key is the UDP source IP of the packet
(NetFlow v5 has no equivalent of sFlow's agent_address field).

```
# .env
DEVICE_RATES=192.168.1.1:1000,10.0.0.5:512,172.16.0.3:256
```

Format: comma-separated `ip:rate` pairs. The override is applied before any
other rate logic. `FORWARD_RATE` still controls what is stamped in the output
— `DEVICE_RATES` only affects the input-side assumption.

---

## Quick start

### Docker Compose

```sh
cp .env.example .env
# Edit .env — set FORWARD_IP to your collector's IP
docker compose up -d
```

### Direct (Python 3.11+)

```sh
FORWARD_IP=192.168.1.10 python3 proxy.py
```

No pip dependencies — stdlib only.

The proxy will listen on both sFlow (`:6343 UDP+TCP`) and NetFlow (`:2055 UDP`)
simultaneously and forward both streams to the same downstream collector IP.

---

## Files

```
proxy.py          Main proxy — single asyncio event loop, UDP + TCP
Dockerfile        python:3.11-slim, copies proxy.py, runs with -u
docker-compose.yml  Service definition, loads .env
.env              Local configuration (not committed)
.env.example      Template — copy to .env and fill in FORWARD_IP
test_sender.py    Test harness — crafts raw sFlow v5 packets, runs assertions
```

---

## Normalisation in depth

### Downscale — `device_rate > FORWARD_RATE`

A device sampling 1-in-1000 means each captured flow represents 1000 real
packets. Forwarded at `FORWARD_RATE = 100`, the collector would think each
flow represents only 100 packets — a 10× undercount.

The proxy multiplies `sample_pool` by the ratio so the collector's traffic
volume estimate remains correct:

```
ratio        = device_rate / FORWARD_RATE   → 1000 / 100 = 10
sample_pool  = original_pool × ratio        → 500 × 10   = 5000
sampling_rate rewritten to FORWARD_RATE     → 100
```

### Upscale — `device_rate < FORWARD_RATE`

A device sampling 1-in-50 captures more flows than `FORWARD_RATE` would imply.
Stamping `FORWARD_RATE = 100` without adjustment would make each flow appear to
represent twice the traffic it actually does.

Rather than fabricate or modify real flows, the proxy probabilistically drops
each sample:

```
p(forward) = device_rate / FORWARD_RATE   → 50 / 100 = 0.50
```

On average, half the flows are forwarded. Each forwarded flow stamped at
rate 100 gives the correct expected volume across the stream. Individual
packets are dropped randomly — there is no deterministic pattern.

### No embedded rate — `device_rate == 0`

Some devices emit `sampling_rate = 0`, meaning the header carries no useful
rate information. `DEFAULT_SAMPLING_RATE` is the proxy's assumption about what
that device is actually sampling at — it is used purely to decide whether to
scale counts up, scale them down, or probabilistically drop. It has no bearing
on the output rate: like every other case, the outgoing packet is always stamped
with `FORWARD_RATE`.

Set `DEFAULT_SAMPLING_RATE` to the rate you know (or believe) your devices run
at when they omit the field.

---

## Counter samples — known limitation

sFlow counter samples (type 2) contain absolute cumulative hardware counters
(total bytes, packets, errors since boot). These are ground truth from the
interface and have no relationship to sampling rate.

The proxy passes them through untouched. A monitoring tool that
cross-references flow samples against counter samples will see an inconsistency:
the counters reflect true interface volume while the normalised flows imply a
different volume.

**Recommended fix:** configure your monitoring tool to source interface counters
via SNMP directly from the devices, and use the proxy only for flow analysis.
Do not attempt to scale counter values in the proxy — they are hardware truth.

---

## Running the tests

The test harness starts its own mock collector, sends crafted sFlow v5 packets
to a running proxy, and asserts the normalised output.

```sh
# Terminal 1 — start the proxy
FORWARD_IP=127.0.0.1 FORWARD_PORT=16343 LISTEN_PORT=16344 \
FORWARD_RATE=100 DEFAULT_SAMPLING_RATE=512 python3 proxy.py

# Terminal 2 — run tests
python3 test_sender.py 16344 16343
```

### Test coverage

| Test | Input rate | Expected output |
|---|---|---|
| Scenario 1: 1/1 → 1/100 | `device_rate=1` | ~1% of flows forwarded, all at rate 100 |
| Scenario 2: 1/1000 → 1/100 | `device_rate=1000` | `sample_pool ×10`, rate 100 |
| Scenario 3: no embedded rate → 1/100 | `device_rate=0` | `DEFAULT_SAMPLING_RATE` applied, rate 100 |
| Exact match | `device_rate=100` | Unchanged, rate 100 |
| Upscale probabilistic | `device_rate=50` | ~50% forwarded, all at rate 100 |
| Counter sample pass-through | type=2 | Byte-identical to input |
| Malformed packet | 10 bytes of `0xFF` | Dropped, proxy stays up |
| TCP downscale | `device_rate=1000` over TCP | `sample_pool ×10`, rate 100 |
| TCP counter pass-through | type=2 over TCP | Byte-identical to input |
| TCP malformed | Truncated TCP frame | Dropped, proxy stays up |

---

## NetFlow / IPFIX

### Inputs and output format

| Input | Output | Notes |
|---|---|---|
| NetFlow v5 | NetFlow v9 | Template FlowSet (ID 256) prepended to every packet |
| NetFlow v9 | NetFlow v9 | Template FlowSets cached, forwarded unchanged |
| IPFIX (v10) | IPFIX (v10) | Template Sets cached, forwarded unchanged; message length field updated |

### Sampling rate resolution (NetFlow / IPFIX)

NetFlow v9 and IPFIX carry sampling rate information in Options Templates,
which vary by vendor and are complex to parse reliably. The proxy uses a
simpler, predictable resolution order:

1. `DEVICE_RATES` override for the source IP — highest priority
2. Embedded `sampling_interval` from the NetFlow v5 header (lower 14 bits, if non-zero)
3. `DEFAULT_SAMPLING_RATE` fallback

For v9 and IPFIX, where there is no single embedded sampling rate field in the
data FlowSet, the proxy always falls back to `DEVICE_RATES` or
`DEFAULT_SAMPLING_RATE`. Set `DEVICE_RATES` per exporter IP for accurate
normalisation.

### What is normalised

For NetFlow v5, each flow record's `dPkts` and `dOctets` fields are scaled
(downscale: multiply by ratio; upscale: probabilistic drop). The v9 output is
stamped with the normalised counts — no separate sampling rate field in the
data record.

For NetFlow v9 and IPFIX, the proxy locates `IN_BYTES` (field 1), `IN_PKTS`
(field 2), `OUT_BYTES` (field 23), and `OUT_PKTS` (field 24) within each data
record using the cached template and scales them by the same ratio. If a
template has not yet been received for a given data FlowSet, those records are
forwarded as-is.

---

## Architecture

```
asyncio event loop
  ├── sFlow UDP DatagramProtocol  (LISTEN_PORT)
  │     datagram_received()
  │       └── parse_datagram() → normalize_flow_sample()
  │             └── forward_sock.sendto() → FORWARD_IP:FORWARD_PORT (UDP)
  │
  ├── sFlow TCP asyncio.start_server  (LISTEN_PORT)
  │     handle_tcp_connection()  [one coroutine per inbound connection]
  │       read 4-byte length prefix + body
  │       └── parse_datagram() → normalize_flow_sample()
  │             └── asyncio.open_connection() → FORWARD_IP:FORWARD_PORT (TCP)
  │                   write 4-byte length prefix + normalised body
  │
  └── NetFlow UDP DatagramProtocol  (NETFLOW_LISTEN_PORT)
        datagram_received()
          └── parse_netflow()
                ├── v5 → convert_nf5_to_nf9()     normalise + convert
                ├── v9 → normalize_nf9()           cache templates, normalise data
                └── v10 → normalize_ipfix()        cache templates, normalise data
                      └── nf_forward_sock.sendto() → NETFLOW_FORWARD_IP:NETFLOW_FORWARD_PORT
```

Rules:
- Single asyncio event loop, no threads
- One persistent UDP send socket per protocol (sFlow, NetFlow)
- One outbound TCP connection per inbound sFlow TCP connection
- No buffering, no queuing — process and forward in the same callback
- NetFlow v9/IPFIX template cache is in-process memory (stateful — templates
  are lost on restart, but re-populated on the next template packet from the device)
- Malformed packets are logged to stderr and dropped; they never crash the loop

---

## sFlow v5 packet structure reference

```
Datagram header (28 bytes)
  version         uint32  = 5
  addr_type       uint32  = 1 (IPv4)
  agent_address   uint32  (IPv4)
  sub_agent_id    uint32
  sequence_number uint32
  uptime          uint32
  num_samples     uint32

Per sample record:
  sample_type     uint32  (1 = flow, 2 = counter)
  sample_length   uint32
  sample_data     <sample_length bytes>

Flow sample (type=1) layout inside sample_data:
  sequence_number uint32
  source_id       uint32
  sampling_rate   uint32  ← read and rewritten by proxy
  sample_pool     uint32  ← scaled by proxy when device_rate > FORWARD_RATE
  drops           uint32
  input_if        uint32
  output_if       uint32
  ... (flow records follow)
```

Full specification: https://sflow.org/sflow_version_5.txt

---

## NetFlow v5 packet structure reference

```
Header (24 bytes)
  version           uint16  = 5
  count             uint16  (number of flow records)
  sys_uptime        uint32  (ms)
  unix_secs         uint32
  unix_nsecs        uint32
  flow_sequence     uint32
  engine_type       uint8
  engine_id         uint8
  sampling_interval uint16  (bits [15:14] = mode, bits [13:0] = interval)

Flow record (48 bytes) — repeated count times
  srcaddr    uint32   IPV4_SRC_ADDR
  dstaddr    uint32   IPV4_DST_ADDR
  nexthop    uint32   IPV4_NEXT_HOP
  input      uint16   INPUT_SNMP
  output     uint16   OUTPUT_SNMP
  dPkts      uint32   IN_PKTS      ← scaled by proxy
  dOctets    uint32   IN_BYTES     ← scaled by proxy
  first      uint32   FIRST_SWITCHED
  last       uint32   LAST_SWITCHED
  srcport    uint16   L4_SRC_PORT
  dstport    uint16   L4_DST_PORT
  pad1       uint8    (zero)
  tcp_flags  uint8    TCP_FLAGS
  prot       uint8    PROTOCOL
  tos        uint8    SRC_TOS
  src_as     uint16   SRC_AS
  dst_as     uint16   DST_AS
  src_mask   uint8    SRC_MASK
  dst_mask   uint8    DST_MASK
  pad2       uint16   (zero)
```

The proxy converts each v5 packet to a v9 packet containing:
1. A Template FlowSet (ID=0) describing the 18 fields above (minus padding)
2. A Data FlowSet (ID=256) with the normalised flow records

## NetFlow v9 / IPFIX packet structure reference

```
NetFlow v9 header (20 bytes)
  version           uint16  = 9
  count             uint16  (total records in PDU)
  sys_uptime        uint32  (ms)
  unix_secs         uint32
  package_sequence  uint32
  source_id         uint32

IPFIX header (16 bytes)
  version           uint16  = 10
  length            uint16  (total message length, updated by proxy)
  export_time       uint32
  sequence_number   uint32
  observation_domain_id  uint32

FlowSet / Set header (4 bytes, shared by v9 and IPFIX)
  id     uint16  (0 = Template, 1 = Options Template, 256+ = Data)
  length uint16  (total including this header)
```

Full specifications: RFC 3954 (NetFlow v9), RFC 7011 (IPFIX)
