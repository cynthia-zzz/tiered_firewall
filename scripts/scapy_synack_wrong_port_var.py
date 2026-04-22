# ~/iw/scripts/scapy_synack_wrong_port_var.py
from scapy.all import Ether, IP, TCP, sendp
import sys

dport = int(sys.argv[1])

pkt = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=8080, dport=dport, flags="SA", seq=2000, ack=1001)
)

sendp(pkt, iface="vethB", verbose=False)
print(f"Sent wrong-port SYN-ACK 10.0.0.2:8080 -> 10.0.0.1:{dport}")
