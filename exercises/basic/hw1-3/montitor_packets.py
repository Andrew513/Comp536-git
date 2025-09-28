#!/usr/bin/env python3
import argparse, struct, time
from scapy.all import Ether, IP, Raw, get_if_hwaddr, sendp, hexdump, AsyncSniffer

PROTO_MONITOR = 253
OPCODE_QUERY  = 1
OPCODE_REPLY  = 2

def build_payload_query(port_idx: int):
    # P4 header: opcode(1) + port_idx(2) + pad(2) + value(8) = 13 bytes
    return struct.pack("!B H H Q", OPCODE_QUERY, port_idx & 0xFFFF, 0, 0)

def try_parse_payload(b: bytes):
    if len(b) < 13:
        return None
    opcode, port_idx, _pad, value = struct.unpack("!B H H Q", b[:13])
    return opcode, port_idx, value

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int, help="egress port index to query")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--dst", default="10.0.1.1")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()

    my_mac = get_if_hwaddr(args.iface)
    payload = build_payload_query(args.port)
    pkt = Ether(src=my_mac, dst=my_mac) / IP(dst=args.dst, proto=PROTO_MONITOR, ttl=64) / Raw(load=payload)

    # Start sniffer FIRST to avoid race
    bpf = "ip proto 253"
    sniffer = AsyncSniffer(iface=args.iface, filter=bpf, store=True)
    sniffer.start()
    # tiny guard so pcap is ready
    time.sleep(0.05)

    print(f"[send] iface={args.iface} src_mac={my_mac} dst_mac={my_mac} ip.dst={args.dst} proto=253 port_idx={args.port}")
    sendp(pkt, iface=args.iface, verbose=False)

    # Wait a bit for the reply, then stop sniffer
    time.sleep(args.timeout)
    pkts = sniffer.stop()

    if not pkts:
        print("[timeout] sniffer saw nothing (race avoided, so check P4 again).")
        return

    got = False
    for i, p in enumerate(pkts, 1):
        raw = bytes(p.getlayer(Raw).load) if p.haslayer(Raw) else b""
        print(f"[seen {i}] {p[IP].src} -> {p[IP].dst}, len(raw)={len(raw)}")
        if raw:
            hexdump(raw)
            meta = try_parse_payload(raw)
            if meta:
                opcode, port_idx, value = meta
                print(f"[OK] opcode={opcode}, port_idx={port_idx}, bytes={value}")
                got = True
    if not got:
        print("[warn] Saw proto 253 but payload didn’t match header (length/layout mismatch).")
        print("      Ensure P4 monitor_t is opcode(1) + port_idx(2) + pad(2) + value(8) and deparser emits hdr.monitor.")

if __name__ == "__main__":
    main()
