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

/* ------------------ SIMPLE HASH ------------------ */

static __always_inline __u32 mix32(__u32 x) {
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static __always_inline __u32 flow_hash(struct flow5 *f, __u32 seed) {
    __u32 h = seed;
    h ^= mix32(f->src_ip);
    h ^= mix32(f->dst_ip);
    h ^= mix32(((__u32)f->src_port << 16) | f->dst_port);
    h ^= mix32(f->proto);
    return mix32(h);
}

/* ------------------ BLOOM FILTER ------------------ */

#define BLOOM_BITS (1 << 12)
#define BLOOM_WORDS (BLOOM_BITS / 64)
#define BLOOM_K 3

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BLOOM_WORDS);
    __type(key, __u32);
    __type(value, __u64);
} bloom SEC(".maps");

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
counters[3] = other_tcp -> packets_seen_any
*/

static __always_inline void counter_inc(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ------------------ BLOOM OPS ------------------ */

static __always_inline void bloom_set(__u32 bit) {
    __u32 word = bit >> 6;
    __u32 offset = bit & 63;
    __u64 mask = 1ULL << offset;

    __u64 *val = bpf_map_lookup_elem(&bloom, &word);
    if (val)
        __sync_fetch_and_or(val, mask);
}

static __always_inline int bloom_test(__u32 bit) {
    __u32 word = bit >> 6;
    __u32 offset = bit & 63;
    __u64 mask = 1ULL << offset;

    __u64 *val = bpf_map_lookup_elem(&bloom, &word);
    if (!val)
        return 0;

    return (*val & mask) != 0;
}

static __always_inline void bloom_add(struct flow5 *f) {
#pragma unroll
    for (int i = 0; i < BLOOM_K; i++) {
        __u32 h = flow_hash(f, 0x9e3779b9U * (i + 1));
        __u32 bit = h & (BLOOM_BITS - 1);
        bloom_set(bit);
    }
}

static __always_inline int bloom_contains(struct flow5 *f) {
#pragma unroll
    for (int i = 0; i < BLOOM_K; i++) {
        __u32 h = flow_hash(f, 0x9e3779b9U * (i + 1));
        __u32 bit = h & (BLOOM_BITS - 1);
        if (!bloom_test(bit))
            return 0;
    }
    return 1;
}

/* ------------------ XDP PROGRAM ------------------ */

SEC("xdp")
int xdp_tcp_bloom(struct xdp_md *ctx)
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
	return XDP_PASS;

    struct flow5 f = {};
    f.src_ip = ip->saddr;
    f.dst_ip = ip->daddr;
    f.src_port = tcp->source;
    f.dst_port = tcp->dest;
    f.proto = IPPROTO_TCP;

    /* If TCP SYN and not ACK -> treat as client initiation */
    if (tcp->syn && !tcp->ack) {
        counter_inc(0);
        bloom_add(&f);
        return XDP_PASS;
    }

    /* Reverse flow */
    if (tcp->syn && tcp->ack) {
	/* Reverse flow: client->server tuple that should have been seen as SYN */
    	struct flow5 rev = {};
    	rev.src_ip = f.dst_ip;
    	rev.dst_ip = f.src_ip;
    	rev.src_port = f.dst_port;
    	rev.dst_port = f.src_port;
    	rev.proto = IPPROTO_TCP;

    	if (bloom_contains(&rev)) {
        	counter_inc(1);  // solicited
    	} else {
        	counter_inc(2);  // unsolicited
	}
    } else {
	counter_inc(3); // other_tcp
    }
    return XDP_PASS;
}
