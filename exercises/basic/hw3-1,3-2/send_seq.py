# send_seq.py (run on h1)
#!/usr/bin/env python3
import argparse, struct, time, random
from scapy.all import Ether, IP, TCP, Raw, sendp, get_if_hwaddr

MAX_PL = 1460

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--dst-ip", default="10.0.2.2")   # Host2
    ap.add_argument("--sport", type=int, default=5000)
    ap.add_argument("--dport", type=int, default=5001)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--size",  type=int, default=200) # TCP payload bytes
    args = ap.parse_args()

    mac = get_if_hwaddr(args.iface)
    size = min(args.size, MAX_PL)
    pad  = bytes(random.getrandbits(8) for _ in range(max(0, size-8)))

    for seq in range(args.count):
        # payload = 8B sequence (big endian) + padding
        payload = struct.pack("!Q", seq) + pad
        pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
               IP(src="10.0.1.1", dst=args.dst_ip, ttl=64) /
               TCP(sport=args.sport, dport=args.dport) /
               Raw(load=payload))
        sendp(pkt, iface=args.iface, verbose=False)
        if (seq+1) % 200 == 0:
            time.sleep(0.01)
            print(f"sent {seq+1} packets")
        # optional pacing to amplify reordering visibility
        # time.sleep(0.0005)

if __name__ == "__main__":
    main()
