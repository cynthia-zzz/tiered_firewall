// stores only a small, short-lived exact set of pending client-initiated connection>
// client IP, server IP, client port, server port, protocol, insertion time
// excludes payload, byte counters, packet history, long retention, full session tracking>

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
#define MAX_COUNTERS 8

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
enum counter_idx {
    COUNTER_PKTS_SEEN = 0,
    COUNTER_NON_TCP_IPV4,
    COUNTER_SYN_STORED,
    COUNTER_SYNACK_VERIFIED,
    COUNTER_UNSOLICITED_SYNACK,
    COUNTER_STALE_SYNACK,
    COUNTER_FLOW_DELETED_ON_SUCCESS,
    COUNTER_PARSE_ERRORS,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/*
 * Exact short-lived verifier state
 * LRU keeps this bounded and emphasizes this is not a full flow log
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow5);
    __type(value, struct flow_state);
} flows SEC(".maps");

/* ----------------------------- HELPERS ---------------------------- */
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

/* ----------------------------- XDP ----------------------------- */
SEC("xdp")
int xdp_tcp_exact(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(COUNTER_PKTS_SEEN);

    struct iphdr *iph;
    struct tcphdr *tcph;
    if (parse_tcp_ipv4(data, data_end, &iph, &tcph) < 0) {
        // Not all parse failures are "bad"; most are just non-IPv4/non-TCP
        // Still useful to count
        inc_counter(COUNTER_PARSE_ERRORS);
        return XDP_PASS;
    }

    // From here on, we know this is IPv4 TCP; extra counter 
    // incremented only for successfully parsed IPv4/TCP
    // general parsed-TCP marker
    inc_counter(COUNTER_NON_TCP_IPV4);

    struct flow5 f = make_flow(iph, tcph);
    __u64 now = bpf_ktime_get_ns();

    /*
     * Case 1: Client-initiated SYN
     * Store exact short-lived token
     */
    if (tcph->syn && !tcph->ack) {
        struct flow_state st = {
            .inserted_ns = now,
        };

        bpf_map_update_elem(&flows, &f, &st, BPF_ANY);
        inc_counter(COUNTER_SYN_STORED);
        return XDP_PASS;
    }

    /*
     * Case 2: Server SYN-ACK
     * Verify against reverse flow
     */
    if (tcph->syn && tcph->ack) {
        struct flow5 rev = reverse_flow(f);
        struct flow_state *st = bpf_map_lookup_elem(&flows, &rev);

        if (!st) {
            inc_counter(COUNTER_UNSOLICITED_SYNACK);
            return XDP_DROP;
        }

        if (now - st->inserted_ns > HANDSHAKE_TTL_NS) {
            bpf_map_delete_elem(&flows, &rev);
            inc_counter(COUNTER_STALE_SYNACK);
            return XDP_DROP;
        }

        // Verified successfully
        inc_counter(COUNTER_SYNACK_VERIFIED);

        // Consume the token so this behaves like a one-shot verifier
        // rather than a lingering flow record
        bpf_map_delete_elem(&flows, &rev);
        inc_counter(COUNTER_FLOW_DELETED_ON_SUCCESS);

        return XDP_PASS;
    }

    /*
     * All other TCP traffic passes
     * This exact verifier is only about validating SYN-ACKs against
     * recent SYNs, not maintaining broader flow telemetry
     */
    return XDP_PASS;
}
