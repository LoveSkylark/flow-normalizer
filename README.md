# flow-normalizer

## Why this exists

This tool exists because a lot of devices export flow data badly.

Different vendors implement sFlow, NetFlow, and IPFIX inconsistently. Sampling
rates don’t line up, some devices don’t report them at all, and others report
the wrong values. You end up chasing mismatched traffic numbers and wasting
time trying to make collectors interpret garbage correctly.

In many cases, you only realize things are broken after hours of tweaking.

flow-normalizer fixes that by sitting in the middle. It takes whatever comes in
and forces it into a consistent format the collector can actually use.

---

## What it does

Receives **sFlow v5**, **NetFlow v5/v9**, and **IPFIX**, normalizes sampling,
and forwards everything to a collector.

* One consistent sampling rate on output
* sFlow: UDP and TCP (default 6343)
* NetFlow/IPFIX: UDP and TCP (default 2055)
* NetFlow v5 converted to v9
* v9 and IPFIX normalized in place

---

## How it works

All flow samples are rewritten to use `FORWARD_RATE`. The proxy adjusts the
data so traffic volume stays correct.

| Case                          | Action                      |
| ----------------------------- | --------------------------- |
| `device_rate > FORWARD_RATE`  | Scale counts up             |
| `device_rate == FORWARD_RATE` | No change                   |
| `device_rate < FORWARD_RATE`  | Drop samples randomly       |
| `device_rate == 0`            | Use `DEFAULT_SAMPLING_RATE` |

Counter samples are passed through unchanged.

### Source identity

By default the collector sees the normalizer's IP as the exporter because
forwarded UDP packets carry this host's source address.  Set
`SPOOF_UDP_SOURCE=true` to preserve the original device IP — forwarded packets
then appear to come directly from the source device.  Requires `CAP_NET_ADMIN`
(TCP transport is not spoofable without kernel-level TPROXY).

---

## Transport

| Protocol   | sFlow                                       | NetFlow / IPFIX                                  |
| ---------- | ------------------------------------------- | ------------------------------------------------ |
| UDP        | stateless, one packet in → one packet out   | stateless, one packet in → one packet out        |
| TCP        | length-prefixed frames, one downstream TCP connection per inbound session | self-delimiting frames (IPFIX header length / NF9 FlowSet walk), forwarded via UDP |

---

## Configuration

Set via environment variables.

| Variable                | Default | Required | Notes                                      |
| ----------------------- | ------- | -------- | ------------------------------------------ |
| `FORWARD_IP`            |         | yes      |                                            |
| `FORWARD_RATE`          | 100     | no       | Sampling rate stamped on all output flows  |
| `DEFAULT_SAMPLING_RATE` | 512     | no       | Used when device sends no embedded rate    |
| `DEVICE_RATES`          |         | no       | Per-device overrides, see below            |
| `SFLOW_PORT`            | 6343    | no       | Listen port (UDP + TCP)                    |
| `SFLOW_FORWARD_PORT`    | 6343    | no       |                                            |
| `NETFLOW_LISTEN_PORT`   | 2055    | no       | Listen port (UDP + TCP)                    |
| `NETFLOW_FORWARD_PORT`  | 2055    | no       |                                            |
| `SPOOF_UDP_SOURCE`      | false   | no       | Requires `CAP_NET_ADMIN`                   |
| `SOURCE_LOG_INTERVAL`   | 300     | no       | Seconds between repeated source log lines  |

### DEVICE_RATES

Force input rates per device when they are missing or wrong.

```id="k2u8p1"
DEVICE_RATES=192.168.1.1:1000,10.0.0.5:512
```

* sFlow: matches `agent_address`
* NetFlow/IPFIX: matches source IP

Only affects input logic. Output is always `FORWARD_RATE`.

---

## Quick start

### Docker

```sh id="z6k3vp"
cp .env.example .env
docker compose up -d
```

No dependencies.

---

## Normalization rules

* Too low sampling → scale counts up
* Too high sampling → drop samples
* Missing sampling → assume default

Counter samples are never modified.

---

## NetFlow / IPFIX

### Behavior

| Input      | Output     |
| ---------- | ---------- |
| NetFlow v5 | NetFlow v9 |
| NetFlow v9 | NetFlow v9 |
| IPFIX      | IPFIX      |

### Rate priority

| Protocol       | 1st              | 2nd                          | 3rd                     |
| -------------- | ---------------- | ---------------------------- | ----------------------- |
| sFlow          | `DEVICE_RATES`   | Embedded rate in flow sample | `DEFAULT_SAMPLING_RATE` |
| NetFlow v5     | `DEVICE_RATES`   | `sampling_interval` header field | `DEFAULT_SAMPLING_RATE` |
| NetFlow v9     | `DEVICE_RATES`   | —                            | `DEFAULT_SAMPLING_RATE` |
| IPFIX          | `DEVICE_RATES`   | —                            | `DEFAULT_SAMPLING_RATE` |

NetFlow v9 and IPFIX have no standard per-packet sampling rate field in the header, so always configure `DEVICE_RATES` or `DEFAULT_SAMPLING_RATE` for those sources.

### Fields adjusted

* v5: `dPkts`, `dOctets`
* v9/IPFIX: packet and byte counters from templates

If templates are missing, data passes through unchanged.

---

## Architecture

```
asyncio event loop
  sFlow UDP     → parse → normalize → forward UDP (FORWARD_IP:SFLOW_FORWARD_PORT)
  sFlow TCP     → parse → normalize → forward TCP (FORWARD_IP:SFLOW_FORWARD_PORT)
  NetFlow UDP   → parse → normalize → forward UDP (FORWARD_IP:NETFLOW_FORWARD_PORT)
  NetFlow TCP   → parse → normalize → forward UDP (FORWARD_IP:NETFLOW_FORWARD_PORT)
```

* Single loop, no threads, no buffering
* NetFlow TCP accepts both v9 (FlowSet-walked framing) and IPFIX (header length field)
* NetFlow TCP forwards via UDP — same output path as NetFlow UDP
* sFlow TCP forwards via TCP — one downstream connection per inbound session
* In-memory template cache per source IP (v9/IPFIX)
* Malformed packets are dropped and logged, never crash the loop

---

## Tests

Start the proxy, then run the harness:

```sh id="q1v4mt"
# Terminal 1
FORWARD_IP=127.0.0.1 FORWARD_RATE=100 DEFAULT_SAMPLING_RATE=512 \
  SFLOW_FORWARD_PORT=16343 NETFLOW_FORWARD_PORT=16055 \
  python proxy.py

# Terminal 2
python test_sender.py 6343 16343 "" 2055 16055
```

The harness covers:

| Area | Scenarios |
| ---- | --------- |
| sFlow UDP | Probabilistic drop (rate < target), count scale-up (rate > target), missing rate → default, exact match, counter pass-through, malformed packet |
| sFlow TCP | Count scale-up, counter pass-through, malformed frame |
| NetFlow v5 UDP | Count scale-up (×10), exact match, missing rate → default (DEFAULT_SAMPLING_RATE) |
| NetFlow v9 UDP | Template + data, count scale-up |
| IPFIX UDP | Template + data, count scale-up |
| NetFlow v9 TCP | Template + data over TCP, count scale-up |
| IPFIX TCP | Template + data over TCP, count scale-up |
| NetFlow TCP | Malformed frame, proxy survives |

