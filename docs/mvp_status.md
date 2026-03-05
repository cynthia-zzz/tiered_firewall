# MVP Status (XDP TCP Bloom)

We attach the same XDP program to:
- nsS/vethB (server ingress): sees client->server traffic (SYNs), inserts flow key into Bloom filter
- root/vethA (client ingress): sees server->client replies, checks Bloom membership of reverse flow to classify solicited vs unsolicited

Current behavior:
- SYNs are counted and inserted on server-ingress instance (syn_seen > 0)
- Reply-side instance sees packets but classifies them as unsolicited because its Bloom map is separate (solicited stays 0, unsolicited increases)

Reason:
- Attaching the ELF object separately creates distinct BPF map instances per attach.
Next milestone:
- Use a loader (libbpf) to load once, pin/reuse the same maps, and attach the same program to both interfaces.

# MVP Result

Test setup:
- client: root namespace (vethA 10.0.0.1)
- server: nsS namespace (vethB 10.0.0.2)
- HTTP server running in nsS
- XDP program attached to both interfaces via libbpf loader
- Bloom filter tracks client SYN flows

Test:
curl -4 --interface vethA http://10.0.0.2:8080/

Counters:

syn_seen = 1
solicited = 1
unsolicited = 0
other_tcp ≈ 10

Interpretation:
The server's SYN-ACK was correctly recognized as solicited because the Bloom filter contained the client SYN tuple.
