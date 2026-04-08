# sends server SYN-ACK w/o first inserting a SYN

from scapy.all import Ether, IP, TCP, sendp

pkt = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=8080, dport=12345, flags="SA", seq=2000, ack=1001)
)

sendp(pkt, iface="vethA", verbose=True)
print("Sent server SYN-ACK from 10.0.0.2:8080 -> 10.0.0.1:12345")
