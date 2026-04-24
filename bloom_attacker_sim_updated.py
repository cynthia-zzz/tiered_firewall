import json
import math
import random
import socket
import struct
import sys
from typing import List, Tuple, Set

Flow = Tuple[int, int, int, int, int]  # src_ip, dst_ip, src_port, dst_port, proto


def mix32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= (x >> 16)
    x = (x * 0x7FEB352D) & 0xFFFFFFFF
    x ^= (x >> 15)
    x = (x * 0x846CA68B) & 0xFFFFFFFF
    x ^= (x >> 16)
    return x & 0xFFFFFFFF


def flow_hash(flow: Flow, seed: int) -> int:
    src_ip, dst_ip, src_port, dst_port, proto = flow
    h = seed & 0xFFFFFFFF
    h ^= mix32(src_ip)
    h ^= mix32(dst_ip)
    h ^= mix32(((src_port & 0xFFFF) << 16) | (dst_port & 0xFFFF))
    h ^= mix32(proto)
    return mix32(h)


def bloom_bit_positions(flow: Flow, bloom_bits: int, bloom_k: int) -> List[int]:
    positions = []
    for i in range(bloom_k):
        seed = (0x9E3779B9 * (i + 1)) & 0xFFFFFFFF
        h = flow_hash(flow, seed)
        bit = h & (bloom_bits - 1)
        positions.append(bit)
    return positions


def load_bloom_dump(path: str, bloom_words: int) -> List[int]:
    with open(path, "r") as f:
        arr = json.load(f)

    max_key = max(int(entry["key"]) for entry in arr) if arr else -1
    print(f"DEBUG bloom dump max key = {max_key}, expected max key = {bloom_words - 1}")

    words = [0] * bloom_words
    for entry in arr:
        key = int(entry["key"])
        value = int(entry["value"])
        words[key] = value
    return words


def bloom_contains(words: List[int], flow: Flow, bloom_bits: int, bloom_k: int) -> bool:
    for bit in bloom_bit_positions(flow, bloom_bits, bloom_k):
        word = bit >> 6
        offset = bit & 63
        mask = 1 << offset
        if (words[word] & mask) == 0:
            return False
    return True


def ip_to_u32_bpf(ip: str) -> int:
    # Match BPF-side representation seen in your map dumps
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def port_to_u16_bpf(port: int) -> int:
    # Match tcp->source / tcp->dest representation seen in your map dumps
    return socket.htons(port)


def make_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int = 6) -> Flow:
    return (
        ip_to_u32_bpf(src_ip),
        ip_to_u32_bpf(dst_ip),
        port_to_u16_bpf(src_port),
        port_to_u16_bpf(dst_port),
        proto,
    )


def debug_one_flow(words: List[int], flow: Flow, label: str, bloom_bits: int, bloom_k: int):
    bits = bloom_bit_positions(flow, bloom_bits, bloom_k)
    print(f"\nDEBUG {label}")
    print("flow =", flow)
    print("bits =", bits)
    for bit in bits:
        word = bit >> 6
        offset = bit & 63
        mask = 1 << offset
        present = (words[word] & mask) != 0
        print(f"  bit={bit} word={word} offset={offset} present={present} word_value={words[word]}")


def generate_real_flows(start_port: int, count: int, dport: int = 8080) -> List[Flow]:
    return [
        make_flow("10.0.0.1", "10.0.0.2", p, dport)
        for p in range(start_port, start_port + count)
    ]


def generate_fake_flows(real_src_ports: Set[int], count: int, dport: int = 8080) -> List[Flow]:
    fake = []
    used = set(real_src_ports)
    while len(fake) < count:
        sport = random.randint(20000, 65000)
        if sport in used:
            continue
        fake.append(make_flow("10.0.0.1", "10.0.0.2", sport, dport))
        used.add(sport)
    return fake


def main():
    if len(sys.argv) < 5 or len(sys.argv) > 7:
        print(
            f"Usage: {sys.argv[0]} <bloom_dump.json> <inserted_count_n> <fake_count> <bloom_bits_m> [bloom_k] [attacker_prior_p]\n"
            f"Example: {sys.argv[0]} ~/iw/test_outputs/bloom_m12_n1000.json 1000 10000 4096 3 0.000001\n\n"
            f"attacker_prior_p is P(flow is real) for the attacker query distribution.\n"
            f"Use a tiny value for a large flow-ID space, or 0.0026 to model 26 true member guesses per 10,000 probes."
        )
        sys.exit(1)

    bloom_path = sys.argv[1]
    inserted_count = int(sys.argv[2])
    fake_count = int(sys.argv[3])
    bloom_bits = int(sys.argv[4])
    bloom_k = int(sys.argv[5]) if len(sys.argv) >= 6 else 3
    attacker_prior_p = float(sys.argv[6]) if len(sys.argv) == 7 else 1e-6

    if not (0.0 <= attacker_prior_p <= 1.0):
        print("Error: attacker_prior_p must be between 0 and 1.")
        sys.exit(1)

    if bloom_bits <= 0 or (bloom_bits & (bloom_bits - 1)) != 0:
        print("Error: bloom_bits must be a positive power of two.")
        sys.exit(1)

    bloom_words = bloom_bits // 64
    if bloom_bits % 64 != 0:
        print("Error: bloom_bits must be divisible by 64.")
        sys.exit(1)

    inserted_start_port = 10000
    inserted_dport = 8080

    words = load_bloom_dump(bloom_path, bloom_words)

    print("sanity 12345->8080 =", make_flow("10.0.0.1", "10.0.0.2", 12345, 8080))

    known = make_flow("10.0.0.1", "10.0.0.2", inserted_start_port, inserted_dport)
    debug_one_flow(words, known, f"known inserted flow {inserted_start_port}->{inserted_dport}", bloom_bits, bloom_k)

    real_flows = generate_real_flows(inserted_start_port, inserted_count, inserted_dport)
    fake_flows = generate_fake_flows(
        set(range(inserted_start_port, inserted_start_port + inserted_count)),
        fake_count,
        inserted_dport,
    )

    tp = sum(1 for f in real_flows if bloom_contains(words, f, bloom_bits, bloom_k))
    fp = sum(1 for f in fake_flows if bloom_contains(words, f, bloom_bits, bloom_k))
    fn = inserted_count - tp
    tn = fake_count - fp

    # ---------------------------------------------------------------------
    # Updated metrics
    # ---------------------------------------------------------------------
    # For a standard Bloom filter, inserted/real flows should always return
    # "maybe" unless there is an implementation mismatch. This TP/recall
    # check is therefore mainly a sanity check, not a privacy metric.
    recall = tp / inserted_count if inserted_count > 0 else 0.0

    # False-positive behavior over non-member probes. This is the central BF
    # measurement for privacy and exact-layer workload.
    observed_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Analytical Bloom-filter false positive rate for comparison.
    analytical_fpr = (1.0 - math.exp(-bloom_k * inserted_count / bloom_bits)) ** bloom_k

    # System cost: for adversarial/non-member probes, this is the fraction of
    # traffic that passes the approximate BF layer and must be checked by the
    # exact verifier.
    exact_layer_burden = observed_fpr

    # Corrected attacker confidence: posterior probability that a queried flow
    # actually exists after the Bloom filter returns "maybe".
    #
    #     Pr(real | BF+) = P / (P + (1-P) f)
    #
    # P is NOT learned from the Bloom filter alone. It is the attacker/prior
    # query base rate: the fraction of guessed flow identifiers that are real.
    # In realistic flow-ID spaces this should be tiny.
    def posterior_confidence(prior_p: float, fpr: float) -> float:
        denom = prior_p + (1.0 - prior_p) * fpr
        return prior_p / denom if denom > 0 else 0.0

    corrected_confidence_observed = posterior_confidence(attacker_prior_p, observed_fpr)
    corrected_confidence_analytical = posterior_confidence(attacker_prior_p, analytical_fpr)

    # This is the old metric. It is retained only as an experimental precision
    # for the artificial probe mixture used by this script. It is not a stable
    # privacy metric because it changes if we choose to test more or fewer real
    # flows, even when the Bloom filter itself is unchanged.
    empirical_probe_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    empirical_probe_prior = inserted_count / (inserted_count + fake_count) if (inserted_count + fake_count) > 0 else 0.0

    print("\n=== Bloom attacker simulation ===")
    print(f"Inserted real flows in Bloom filter (n): {inserted_count}")
    print(f"Non-member/adversarial probes tested: {fake_count}")
    print(f"Bloom filter size (m bits): {bloom_bits}")
    print(f"Hash functions (k): {bloom_k}")

    print("\n--- Raw BF outcome counts ---")
    print(f"TP / inserted flows returning BF+ (sanity): {tp}")
    print(f"FN / inserted flows returning BF- (should be 0): {fn}")
    print(f"FP / non-member probes returning BF+: {fp}")
    print(f"TN / non-member probes returning BF-: {tn}")

    print("\n--- Functional sanity check ---")
    print(f"Recall on inserted flows, Pr(BF+ | real): {recall:.6f}")

    print("\n--- Bloom-filter privacy/workload metrics ---")
    print(f"Observed false positive rate f = Pr(BF+ | not real): {observed_fpr:.6f}")
    print(f"Analytical false positive rate (1 - exp(-kn/m))^k: {analytical_fpr:.6f}")
    print(f"Exact-layer burden on non-member/adversarial probes: {exact_layer_burden:.6f}")

    print("\n--- Corrected attacker confidence ---")
    print(f"Assumed attacker prior P = Pr(random guessed flow is real): {attacker_prior_p:.12g}")
    print(f"Corrected confidence using observed f, Pr(real | BF+): {corrected_confidence_observed:.6f}")
    print(f"Corrected confidence using analytical f, Pr(real | BF+): {corrected_confidence_analytical:.6f}")

    print("\n--- Deprecated/comparison metric ---")
    print(f"Empirical probe prior in this script, n/(n+fake_count): {empirical_probe_prior:.6f}")
    print(f"Old TP/(TP+FP) over this artificial probe mix: {empirical_probe_precision:.6f}")
    print("Note: TP/(TP+FP) is valid only as precision for this chosen probe mix;")
    print("      it should not be reported as attacker confidence unless that mix")
    print("      matches the attacker's real query distribution.")


if __name__ == "__main__":
    main()
