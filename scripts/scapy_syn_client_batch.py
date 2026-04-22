# ~/iw/scripts/scapy_syn_client_batch.py
from scapy.all import Ether, IP, TCP, sendp
import sys

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <start_sport> <count> <dport>")
    sys.exit(1)

start_sport = int(sys.argv[1])
count = int(sys.argv[2])
dport = int(sys.argv[3])

pkts = []
for sport in range(start_sport, start_sport + count):
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=sport, dport=dport, flags="S", seq=1000)
    )
    pkts.append(pkt)

sendp(pkts, iface="vethA", verbose=False)
print(f"Sent {count} SYN packets: sports {start_sport}..{start_sport + count - 1} -> dport {dport}")
