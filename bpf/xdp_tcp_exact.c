#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* ------------------ FLOW KEY ------------------ */

struct flow5 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

/* ------------------ EXACT FLOW TABLE ------------------ */

/*
 * Exact per-flow state:
 * key   = full 5-tuple
 * value = timestamp (or just a marker that the flow exists)
 *
 * This is the exact baseline firewall state table.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow5);
    __type(value, __u64);
} flows SEC(".maps");

/* ------------------ COUNTERS ------------------ */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/*
counters[0] = syn_seen
counters[1] = solicited
counters[2] = unsolicited
counters[3] = other_tcp
*/

static __always_inline void counter_inc(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ------------------ XDP PROGRAM ------------------ */

SEC("xdp")
int xdp_tcp_exact(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow5 f = {};
    f.src_ip = ip->saddr;
    f.dst_ip = ip->daddr;
    f.src_port = tcp->source;
    f.dst_port = tcp->dest;
    f.proto = IPPROTO_TCP;

    /* Case 1: client SYN (initiation) */
    if (tcp->syn && !tcp->ack) {
        __u64 now = bpf_ktime_get_ns();  // current kernel time in ns
        counter_inc(0);                  // syn_seen++
        bpf_map_update_elem(&flows, &f, &now, BPF_ANY);
        return XDP_PASS;
    }

    /* Case 2: server SYN-ACK (response) */
    if (tcp->syn && tcp->ack) {
        struct flow5 rev = {};
        rev.src_ip = f.dst_ip;
        rev.dst_ip = f.src_ip;
        rev.src_port = f.dst_port;
        rev.dst_port = f.src_port;
        rev.proto = IPPROTO_TCP;

        __u64 *v = bpf_map_lookup_elem(&flows, &rev);
        if (v) {
            counter_inc(1);  // solicited
        } else {
            counter_inc(2);  // unsolicited
        }

        return XDP_PASS;
    }

    /* Everything else */
    counter_inc(3);  // other_tcp
    return XDP_PASS;
}
