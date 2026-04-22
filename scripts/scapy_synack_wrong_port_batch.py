# ~/iw/scripts/scapy_synack_wrong_port_batch.py
from scapy.all import Ether, IP, TCP, sendp
import sys

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <start_dport> <count> <sport>")
    sys.exit(1)

start_dport = int(sys.argv[1])
count = int(sys.argv[2])
sport = int(sys.argv[3])

pkts = []
for dport in range(start_dport, start_dport + count):
    pkt = (
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=sport, dport=dport, flags="SA", seq=2000, ack=1001)
    )
    pkts.append(pkt)

sendp(pkts, iface="vethB", verbose=False)
print(f"Sent {count} fake SYN-ACK packets: sport {sport} -> dports {start_dport}..{start_dport + count - 1}")
