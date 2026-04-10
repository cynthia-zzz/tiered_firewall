# scapy_synack_wrong_port.py
# sends a SYNACK with the wrong dst port
# expected: unsolicted (key 2) incremented
from scapy.all import Ether, IP, TCP, sendp

pkt = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=8080, dport=55555, flags="SA", seq=2000, ack=1001)
)

sendp(pkt, iface="vethB", verbose=True)
print("Sent wrong dst port SYN-ACK from nsS/vethB: 10.0.0.2:8080 -> 10.0.0.1:55555")
