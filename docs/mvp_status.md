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
