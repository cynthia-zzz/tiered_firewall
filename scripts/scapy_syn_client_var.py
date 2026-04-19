from scapy.all import Ether, IP, TCP, sendp
import random
import sys

sport = int(sys.argv[1]) if len(sys.argv) > 1 else random.randint(1024, 65535)
dport = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

pkt = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=sport, dport=dport, flags="S", seq=1000)
)

sendp(pkt, iface="vethA", verbose=True)
print(f"Sent SYN 10.0.0.1:{sport} -> 10.0.0.2:{dport}")
