# scapy_syn_client.py
# inserts outbound flow seed by sending SYN on vethA
# expected result: syn seen (key 0) incremented
from scapy.all import Ether, IP, TCP, sendp

pkt = (
    Ether()
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=8080, flags="S", seq=1000)
)

sendp(pkt, iface="vethA", verbose=True)
print("Sent client SYN from 10.0.0.1:12345 -> 10.0.0.2.:8080")
