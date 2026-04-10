# scapy_synack_from_nsS.py
# sends synack from server namespace on vethB, not from root on vethA
# expected result: unsolicted (key 2) incremented
from scapy.all import Ether, IP, TCP, sendp

pkt = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=8080, dport=12345, flags="SA", seq=2000, ack=1001)
)

sendp(pkt, iface="vethB", verbose=True)
print("Sent SYN-ACK from nsS/vethB: 10.0.0.2:8080 -> 10.0.0.1:12345")
