#!/usr/bin/env python3
# ecmp_eval.py
import argparse, random, struct, time
from scapy.all import Ether, IP, TCP, Raw, sendp, get_if_list, get_if_hwaddr, AsyncSniffer

PROTO_MONITOR=253; OPCODE_QUERY=1
MAX_TCP_PL = 1460  # MTU 1500 - IP 20 - TCP 20

def pick_iface():
    for i in get_if_list():
        if "eth0" in i: return i
    raise RuntimeError("no eth0-like iface")

def query_counter(port, iface, dst_ip):
    """Send monitor query (opcode=1, port_idx=port) and return 64-bit value."""
    payload = struct.pack("!B H H Q", OPCODE_QUERY, port & 0xFFFF, 0, 0)  # 13 bytes
    my_mac  = get_if_hwaddr(iface)
    pkt = Ether(src=my_mac, dst=my_mac)/IP(dst=dst_ip, proto=PROTO_MONITOR, ttl=64)/Raw(load=payload)
    sniffer = AsyncSniffer(iface=iface, filter="ip proto 253", store=True)
    sniffer.start(); time.sleep(0.05); sendp(pkt, iface=iface, verbose=False); time.sleep(0.6)
    pkts = sniffer.stop()
    for p in pkts:
        if not p.haslayer(Raw): continue
        b = bytes(p[Raw])
        if len(b) >= 13:
            op, port_idx, _pad, val = struct.unpack("!B H H Q", b[:13])
            if op == 2: return val
    raise RuntimeError("no reply to monitor query")

def rand_ip(prefix="10.0.1."):
    return prefix + str(random.randint(2,254))

def send_flows(dst_ip, iface, flows, sizes):
    src_mac = get_if_hwaddr(iface)
    total_wire = 0
    for i in range(flows):
        size = min(random.choice(sizes), MAX_TCP_PL)
        pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/
               IP(src=rand_ip(), dst=dst_ip)/
               TCP(sport=random.randint(1024,65535), dport=random.randint(1024,65535))/
               Raw(bytes(random.getrandbits(8) for _ in range(size))))
        sendp(pkt, iface=iface, verbose=False)
        total_wire += len(bytes(pkt))
        print(f"Sent flow {i+1}: {pkt[IP].src}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport}, size={size}")
    return total_wire

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--dst-ip", default="10.0.2.2")    # traffic destination
    ap.add_argument("--mon-ip", default="10.0.1.1")    # your host’s IP for monitor replies
    ap.add_argument("--ports", type=int, nargs=2, required=True, help="ECMP egress ports: upper lower")
    ap.add_argument("--flows", type=int, default=100)
    ap.add_argument("--sizes", type=int, nargs="*", default=[100,500,1000,1400])
    args = ap.parse_args()

    iface = args.iface or pick_iface()
    upper, lower = args.ports

    # 1) Baseline counters
    upper0 = query_counter(upper, iface, args.mon_ip)
    lower0 = query_counter(lower, iface, args.mon_ip)

    # 2) Generate flows
    total_wire = send_flows(args.dst_ip, iface, args.flows, args.sizes)

    # 3) Read counters again
    upper1 = query_counter(upper, iface, args.mon_ip)
    lower1 = query_counter(lower, iface, args.mon_ip)

    up = max(0, upper1-upper0); lo = max(0, lower1-lower0); tot = up+lo
    up_pct = (up/tot*100) if tot else 0.0; lo_pct = (lo/tot*100) if tot else 0.0

    print("\n=== ECMP Report ===")
    print(f"Source total bytes (approx on-wire): {total_wire}")
    print(f"Upper path bytes: {up}  ({up_pct:.1f}%)")
    print(f"Lower path bytes: {lo}  ({lo_pct:.1f}%)")
    if tot and abs(tot-total_wire)/max(tot,total_wire) > 0.2:
        print("Note: difference vs. on-wire total can occur due to L2/L3 overheads or other ports.")

if __name__ == "__main__":
    main()
