# recv_seq.py (run on h2)
#!/usr/bin/env python3
import argparse, struct
from scapy.all import sniff, IP, TCP, Raw

def count_global_inversions(a):
    # merge-sort inversion count
    def sort_count(arr):
        n=len(arr)
        if n<2: return arr,0
        m=n//2
        L,cL = sort_count(arr[:m])
        R,cR = sort_count(arr[m:])
        i=j=0; merged=[]; inv=cL+cR
        while i<len(L) and j<len(R):
            if L[i] <= R[j]:
                merged.append(L[i]); i+=1
            else:
                merged.append(R[j]); j+=1
                inv += len(L)-i
        merged.extend(L[i:]); merged.extend(R[j:])
        return merged, inv
    _, inv = sort_count(list(a))
    return inv

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--sport", type=int, default=5000)
    ap.add_argument("--dport", type=int, default=5001)
    ap.add_argument("--count", type=int, default=2000)
    args = ap.parse_args()

    seqs = []

    def pick(p):
        return (p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw)
                and p[TCP].sport==args.sport and p[TCP].dport==args.dport)

    print(f"sniffing {args.count} pkts on {args.iface} sport={args.sport} dport={args.dport}")
    pkts = sniff(iface=args.iface, lfilter=pick, count=args.count, timeout=100)

    for p in pkts:
        b = bytes(p[Raw].load)
        if len(b) >= 8:
            seq = struct.unpack("!Q", b[:8])[0]
            seqs.append(seq)

    n = len(seqs)
    if n == 0:
        print("no packets captured"); return

    # metrics
    local_inv = sum(1 for i in range(n-1) if seqs[i] > seqs[i+1])
    global_inv = count_global_inversions(seqs)
    reorders = 0
    max_seen = -1
    for x in seqs:
        if x < max_seen: reorders += 1
        if x > max_seen: max_seen = x

    print("\n=== Reordering report ===")
    print(f"Packets captured: {n}")
    print(f"Local inversions:  {local_inv}")
    print(f"Global inversions: {global_inv}")
    print(f"Reordered packets: {reorders}  ({reorders/n*100:.2f}%)")

if __name__ == "__main__":
    main()
