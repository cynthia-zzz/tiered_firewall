# scapy_synack_wrong_src_port.py
# sends a SYNACK with the wrong src port
# expected result: unsolicited (key 2) incremented

from scapy.all import Ether, IP, TCP, sendp

pkt = (
    Ether()
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / TCP(sport=9090, dport=12345, flags="SA", seq=3000, ack=1001)
)

sendp(pkt, iface="vethB", verbose=True)
print("Sent wrong src port SYN-ACK from nsS/vethB: 10.0.0.2:9090 -> 10.0.0.1:12345")
