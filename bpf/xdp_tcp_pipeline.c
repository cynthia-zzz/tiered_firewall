// derived from xdp_tcp_bloom.c and xdp_tcp_exact_v2.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* -------------------------- CONSTANTS -------------------------- */
// how long a SYN token remains valid for SYN-ACK verification (1 min for now)
#define HANDSHAKE_TTL_NS 60000000000ULL

// bounded exact state
#define MAX_FLOWS 16384
#define MAX_COUNTERS 9

// #define BLOOM_BITS (1 << 15) // 32K bits (~4KB)
#define BLOOM_BITS (1 << 14)
#define BLOOM_WORDS (BLOOM_BITS / 64)
#define BLOOM_K 3

/* -------------------------- FLOW STRUCTS -------------------------- */
struct flow5 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad1;
    __u16 pad2;
};

struct flow_state {
    __u64 inserted_ns;
};

/* ------------------------- COUNTERS ------------------------- */
/*
key 0 = total packets seen
key 1 = prased IPv4/TCP
key 2 = outbound SYN inserted into BF + Exact
key 3 = BF negative response on inbound candidate reply
key 4 = BF positive response ("maybe") on inbound candidate reply
key 5 = Exact positive response (flow actually exists)
key 6 = Exact negative response (flow doesn't actually exist)
key 7 = Exact stale (flow not retained past window time)
key 8 = parse errors / nonIPv4/non-TCP/malformed
*/
enum counter_idx {
    COUNTER_PKTS_SEEN = 0,
    COUNTER_PARSED_TCP_IPV4,
    COUNTER_OUTBOUND_SYN_INSERTED,
    COUNTER_BLOOM_NEGATIVE,
    COUNTER_BLOOM_MAYBE,
    COUNTER_EXACT_POSITIVE,
    COUNTER_EXACT_NEGATIVE,
    COUNTER_EXACT_STALE,
    COUNTER_PARSE_ERRORS,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* -------------------------- BLOOM MAP -------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BLOOM_WORDS);
    __type(key, __u32);
    __type(value, __u64);
} bloom SEC(".maps");

/* -------------------------- EXACT MAP --------------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow5);
    __type(value, struct flow_state);
} flows SEC(".maps");

/* -------------------------- SHARED HELPERS -------------------------- */
static __always_inline void inc_counter(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int parse_tcp_ipv4(
    void *data,
    void *data_end,
    struct iphdr **iph_out,
    struct tcphdr **tcph_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->version != 4)
        return -1;

    if (iph->protocol != IPPROTO_TCP)
        return -1;

    // ihl is in 32-bit words
    __u32 ihl_bytes = iph->ihl * 4;
    if (ihl_bytes < sizeof(*iph))
        return -1;

    if ((void *)iph + ihl_bytes > data_end)
        return -1;

    struct tcphdr *tcph = (void *)iph + ihl_bytes;
    if ((void *)(tcph + 1) > data_end)
        return -1;

    // doff is in 32-bit words
    __u32 doff_bytes = tcph->doff * 4;
    if (doff_bytes < sizeof(*tcph))
        return -1;

    if ((void *)tcph + doff_bytes > data_end)
        return -1;

    *iph_out = iph;
    *tcph_out = tcph;
    return 0;
}

static __always_inline struct flow5 make_flow(struct iphdr *iph, struct tcphdr *tcph)
{
    struct flow5 f = {};
    f.src_ip   = iph->saddr;
    f.dst_ip   = iph->daddr;
    f.src_port = tcph->source;
    f.dst_port = tcph->dest;
    f.proto    = IPPROTO_TCP;
    return f;
}

static __always_inline struct flow5 reverse_flow(struct flow5 f)
{
    struct flow5 r = {};
    r.src_ip   = f.dst_ip;
    r.dst_ip   = f.src_ip;
    r.src_port = f.dst_port;
    r.dst_port = f.src_port;
    r.proto    = f.proto;
    return r;
}

/* -------------------------- BLOOM HELPERS -------------------------- */
static __always_inline __u32 mix32(__u32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static __always_inline __u32 flow_hash(struct flow5 *f, __u32 seed)
{
    __u32 h = seed;
    h ^= mix32(f->src_ip);
    h ^= mix32(f->dst_ip);
    h ^= mix32(((__u32)f->src_port << 16) | f->dst_port);
    h ^= mix32(f->proto);
    return mix32(h);
}

static __always_inline void bloom_set(__u32 bit)
{
    __u32 word = bit >> 6;
    __u32 offset = bit & 63;
    __u64 mask = 1ULL << offset;

    __u64 *val = bpf_map_lookup_elem(&bloom, &word);
    if (val)
        __sync_fetch_and_or(val, mask);
}

static __always_inline int bloom_test(__u32 bit)
{
    __u32 word = bit >> 6;
    __u32 offset = bit & 63;
    __u64 mask = 1ULL << offset;

    __u64 *val = bpf_map_lookup_elem(&bloom, &word);
    if (!val)
        return 0;

    return (*val & mask) != 0;
}

static __always_inline void bloom_add(struct flow5 *f)
{
#pragma unroll
    for (int i = 0; i < BLOOM_K; i++) {
        __u32 h = flow_hash(f, 0x9e3779b9U * (i + 1));
        __u32 bit = h & (BLOOM_BITS - 1);
        bloom_set(bit);
    }
}

static __always_inline int bloom_contains(struct flow5 *f)
{
#pragma unroll
    for (int i = 0; i < BLOOM_K; i++) {
        __u32 h = flow_hash(f, 0x9e3779b9U * (i + 1));
        __u32 bit = h & (BLOOM_BITS - 1);
        if (!bloom_test(bit))
            return 0;
    }
    return 1;
}

/* -------------------------- EXACT HELPERS -------------------------- */

static __always_inline void exact_add(struct flow5 *f, __u64 now)
{
    struct flow_state st = {
        .inserted_ns = now,
    };
    bpf_map_update_elem(&flows, f, &st, BPF_ANY);
}

/*
 * return:
 *   0 = not found
 *   1 = found and fresh
 *   2 = found but stale (and deleted)
 */
static __always_inline int exact_check_and_consume(struct flow5 *f, __u64 now)
{
    struct flow_state *st = bpf_map_lookup_elem(&flows, f);
    if (!st)
        return 0;

    if (now - st->inserted_ns > HANDSHAKE_TTL_NS) {
        bpf_map_delete_elem(&flows, f);
        return 2;
    }

    bpf_map_delete_elem(&flows, f);
    return 1;
}

/* -------------------------- XDP PIPELINE -------------------------- */
SEC("xdp")
SEC("xdp")
int xdp_tcp_pipeline(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(COUNTER_PKTS_SEEN);

    struct iphdr *iph;
    struct tcphdr *tcph;
    if (parse_tcp_ipv4(data, data_end, &iph, &tcph) < 0) {
        inc_counter(COUNTER_PARSE_ERRORS);
        return XDP_PASS;
    }

    inc_counter(COUNTER_PARSED_TCP_IPV4);

    struct flow5 f = make_flow(iph, tcph);
    __u64 now = bpf_ktime_get_ns();

    /*
     * Stage 1: outbound initiation
     * Current prototype uses TCP SYN without ACK as the signal to seed state.
     */
    if (tcph->syn && !tcph->ack) {
        bloom_add(&f);
        exact_add(&f, now);
        inc_counter(COUNTER_OUTBOUND_SYN_INSERTED);
        return XDP_PASS;
    }

    /*
     * Stage 2: inbound candidate reply
     * Current prototype uses SYN-ACK as the reply we want to validate.
     */
    if (tcph->syn && tcph->ack) {
        struct flow5 rev = reverse_flow(f);

        if (!bloom_contains(&rev)) {
            inc_counter(COUNTER_BLOOM_NEGATIVE);
            return XDP_DROP;
        }

        inc_counter(COUNTER_BLOOM_MAYBE);

        int exact = exact_check_and_consume(&rev, now);
        if (exact == 2) {
            inc_counter(COUNTER_EXACT_STALE);
            return XDP_DROP;
        }

        if (exact == 0) {
            inc_counter(COUNTER_EXACT_NEGATIVE);
            return XDP_DROP;
        }

        inc_counter(COUNTER_EXACT_POSITIVE);
        return XDP_PASS;
    }

    return XDP_PASS;
}
