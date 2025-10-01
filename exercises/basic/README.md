
# Implementing Basic Forwarding

## Overview

This P4 program implements an IPv4 router with advanced Equal-Cost Multipath (ECMP) forwarding, flowlet-aware load balancing, per-port byte counters, and a custom in-band monitoring protocol for collecting switch statistics remotely.

**Key Features**
- L2/L3 packet parsing (Ethernet, IPv4, TCP, custom monitor packets)
- Advanced ECMP with flowlet-aware path selection
- Custom in-band monitor protocol for real-time statistics
- Per-port byte counting and per-flowlet state tracking
- Standard IPv4 forwarding with LPM fallback

---

## Architecture

### Header Definitions

| Header        | Description                                      |
|---------------|--------------------------------------------------|
| `ethernet_t`  | Standard Ethernet header                         |
| `ipv4_t`      | Standard IPv4 header                             |
| `tcp_t`       | Standard TCP header                              |
| `monitor_t`   | Custom 12-byte monitoring header                 |

- **Monitor Header Details**
   - Activated when IPv4 protocol == 253
   - Fields: opcode (1B), port_idx (2B), pad (2B), value (8B)
   - Supports query (`opcode=1`) and reply (`opcode=2`) operations

### Register State

| Register             | Description                                 |
|----------------------|---------------------------------------------|
| `bytes_per_port[512]`| 64-bit counters per egress port             |
| `fl_last_ts[4096]`   | Per-flowlet timestamp tracking              |
| `fl_choice[4096]`    | Per-flowlet pinned ECMP next-hop selection  |
| `packet_seq[1]`      | Global sequence counter                     |

### Constants

```p4
const bit<16> TYPE_IPV4       = 0x800;
const bit<8>  PROTO_TCP       = 6;
const bit<8>  PROTO_MONITOR   = 253;  // Custom monitoring protocol
const bit<8>  OPCODE_QUERY    = 1;
const bit<8>  OPCODE_REPLY    = 2;
const bit<32> NUM_PORTS       = 512;
const bit<32> FLOWLET_BUCKETS = 4096;
```

---

## Processing Pipeline

### Parser

1. Parse Ethernet header
2. Parse IPv4 header (if EtherType matches)
3. Conditionally parse TCP (protocol=6) or monitor (protocol=253) headers

### Ingress Processing

#### Monitor Protocol Handling

- Intercepts packets with IPv4 protocol=253
- For query packets (`opcode=1`):
   - Reads byte counter for specified port
   - Swaps source/destination addresses
   - Replies with counter value
   - Sends back to ingress port

#### ECMP Path Selection

Three load balancing modes:

1. **Flowlet-aware**: `set_flowlet_select(base, count, timeout_us)`
2. **Round-robin**: `set_rr_select(base, count)`
3. **Hash-based**: `set_ecmp_select(base, count)`

#### Forwarding Tables

| Table        | Key                        | Actions                                 |
|--------------|----------------------------|-----------------------------------------|
| `ecmp_group` | `hdr.ipv4.dstAddr` (LPM)   | set_flowlet_select, set_rr_select, set_ecmp_select, drop |
| `ecmp_nhop`  | `meta.ecmp_select` (exact) | set_nhop, drop                          |
| `ipv4_lpm`   | `hdr.ipv4.dstAddr` (LPM)   | ipv4_forward, drop                      |

### Egress Processing

- Counts bytes for all outgoing packets
- Updates per-port byte counters in real-time

---

## Monitor Protocol Usage

### Querying Port Statistics

Send an IPv4 packet to the switch with:

```
IPv4 Header:
   protocol = 253

Monitor Header:
   opcode = 1 (query)
   port_idx = <target_port_number>
   pad = 0
   value = 0 (ignored)
```

### Response Format

The switch replies with:

```
IPv4 Header:
   Source/destination swapped
   protocol = 253

Monitor Header:
   opcode = 2 (reply)
   port_idx = <queried_port>
   pad = 0
   value = <cumulative_bytes_on_port>
```

---

## Flowlet Algorithm

1. **Flow Identification**: Hash 5-tuple (src_ip, dst_ip, protocol, src_port, dst_port) to bucket
2. **Gap Detection**: Compare current timestamp with last packet timestamp
3. **Path Selection**:
    - If gap > timeout OR no previous choice: select new random path
    - Else: reuse previously pinned path
4. **State Update**: Record new timestamp and path choice

This balances load while maintaining per-flow ordering within flowlets.

---

## Deployment Notes

- **Target**: BMv2 simple_switch (v1model architecture)
- **Control Plane**: Table population via P4Runtime or bmv2 CLI
- **Registers**: Accessible via control plane for initialization/monitoring
- **Checksum**: IPv4 header checksum automatically computed

---

## Use Cases

- Network Telemetry: In-band collection of per-port statistics
- Load Balancing Research: Flowlet vs. traditional ECMP
- SDN Experimentation: Custom forwarding logic with real-time monitoring
- Traffic Engineering: Dynamic path selection based on network conditions

---

## How to Run the Lab

### Milestone 1

- **Task 1**: Settings in **hw1** folder
- **Task 2**: Settings in **hw1-2** folder  
   - Compile: `make 1-2`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python receive.py`
   - On h1:  
      ```bash
      for i in $(seq 1 200); do python send.py 10.0.2.2 "ecmp test $i" --sport $i; done
      ```
- **Task 3**: Settings in **hw1-3** folder  
   - Compile: `make 1-3`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python receive.py`
   - On h1:  
      ```bash
      for i in $(seq 1 50); do python send.py 10.0.2.2 "ecmp test $i" -sport $i; done
      ```
   - Monitor:  
      ```bash
      tcpdump -i eth0 'ip proto 253' -vv -XX & python hw1-3/monitor_packets.py 2 --iface eth0 --dst 10.0.1.1
      ```

### Milestone 2

- **Task 1**: Settings in **hw2-1** folder  
   - Compile: `make 2-1`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python receive.py`
   - On h1:  
      ```bash
      python ./hw2-1/ecmp_random_flow.py --port 2 3 --iface eth0
      ```
- **Task 2**: Settings in **hw2-2** folder  
   - Compile: `make 2-2`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python receive.py`
   - On h1:  
      ```bash
      python ./hw2-1/ecmp_random_flow.py --port 2 3 --iface eth0 --flows 5000
      ```
- **Task 3**: Settings in **hw2-3** folder  
   - Compile: `make 2-3`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python ./hw2-3/recv_seq.py`
   - On h1: `python ./hw2-3/send_seq.py`

### Milestone 3

- **Task 1 & 2**: Settings in **hw3-1,3-2** folder  
   - Registers added: `fl_last_ts`, `fl_choice`
   - Bucket index: stable hash of 5-tuple (4096 buckets)
   - Compile: `make 3-1,3-2`
   - Start Mininet: `xterm h1 h2`
   - On h2: `python ./hw3-1,3-2/recv_seq.py`
   - On h1: `python ./hw3-1,3-2/send_seq.py`

---

**Notes:**  
Use the provided Python scripts (e.g., `monitor_packets.py`, `ecmp_random_flow.py`) to automate traffic generation and monitor port statistics.  
Test by generating traffic first, then sending queries to verify counter updates.

All the different ECMP implementations are in basic.p4, it just in different milestone's different task, I have the settings set in **2h4w.json**(for latency etc) and **s1-runtime.json**(because mostly the changes are with switch 1).
