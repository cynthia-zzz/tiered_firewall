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
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def port_to_u16_bpf(port: int) -> int:
    return socket.htons(port)


def make_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int = 6) -> Flow:
    return (
        ip_to_u32_bpf(src_ip),
        ip_to_u32_bpf(dst_ip),
        port_to_u16_bpf(src_port),
        port_to_u16_bpf(dst_port),
        proto,
    )


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
            f"Usage: {sys.argv[0]} <bloom_dump.json> <inserted_count_n> <fake_count> <bloom_bits_m> [bloom_k] [attacker_prior_p]"
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

    recall = tp / inserted_count if inserted_count > 0 else 0.0
    observed_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    analytical_fpr = (1.0 - math.exp(-bloom_k * inserted_count / bloom_bits)) ** bloom_k
    exact_layer_burden = observed_fpr

    def posterior_confidence(prior_p: float, fpr: float) -> float:
        denom = prior_p + (1.0 - prior_p) * fpr
        return prior_p / denom if denom > 0 else 0.0

    attacker_confidence_observed = posterior_confidence(attacker_prior_p, observed_fpr)
    attacker_confidence_analytical = posterior_confidence(attacker_prior_p, analytical_fpr)

    empirical_probe_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    print("\n=== Bloom attacker simulation ===")
    print(f"Observed false positive rate: {observed_fpr:.6f}")
    print(f"Analytical false positive rate: {analytical_fpr:.6f}")
    print(f"Exact-layer burden: {exact_layer_burden:.6f}")
    print(f"Attacker confidence (observed): {attacker_confidence_observed:.6f}")
    print(f"Attacker confidence (analytical): {attacker_confidence_analytical:.6f}")
    print(f"Recall (sanity check): {recall:.6f}")

if __name__ == "__main__":
    main()
