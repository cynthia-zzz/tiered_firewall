# bloom_attacker_sim.py
import json
import random
import socket
import struct
from typing import List, Tuple, Set

# BLOOM_BITS = 1 << 15
BLOOM_BITS = 1 << 14
BLOOM_WORDS = BLOOM_BITS // 64
BLOOM_K = 3

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


def bloom_bit_positions(flow: Flow) -> List[int]:
    positions = []
    for i in range(BLOOM_K):
        seed = (0x9E3779B9 * (i + 1)) & 0xFFFFFFFF
        h = flow_hash(flow, seed)
        bit = h & (BLOOM_BITS - 1)
        positions.append(bit)
    return positions


#def load_bloom_dump(path: str) -> List[int]:
#    with open(path, "r") as f:
#        arr = json.load(f)
#
#    words = [0] * BLOOM_WORDS
#    for entry in arr:
#        key = entry["key"]
#        value = entry["value"]
#        words[key] = value
#    return words

def load_bloom_dump(path: str) -> List[int]:
    with open(path, "r") as f:
        arr = json.load(f)

    max_key = max(int(entry["key"]) for entry in arr) if arr else -1
    print(f"DEBUG bloom dump max key = {max_key}, expected max key = {BLOOM_WORDS - 1}")

    words = [0] * BLOOM_WORDS
    for entry in arr:
        key = int(entry["key"])
        value = int(entry["value"])
        words[key] = value
    return words

def bloom_contains(words: List[int], flow: Flow) -> bool:
    for bit in bloom_bit_positions(flow):
        word = bit >> 6
        offset = bit & 63
        mask = 1 << offset
        if (words[word] & mask) == 0:
            return False
    return True


def ip_to_u32(ip: str) -> int:
    # network byte order integer
    return struct.unpack("<I", socket.inet_aton(ip))[0]

def port_to_u16(port: int) -> int:
    # matches tcp->source / tcp->dest representation
    return socket.htons(port)

def make_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int = 6) -> Flow:
    # match BPF representation:
    # IPs in network byte order, ports in network byte order
    return (
        ip_to_u32(src_ip),
        ip_to_u32(dst_ip),
        port_to_u16(src_port),
        port_to_u16(dst_port),
        proto,
    )

def generate_real_flows(start_port: int, count: int, dport: int = 8080) -> List[Flow]:
    return [
        make_flow("10.0.0.1", "10.0.0.2", p, dport)
        for p in range(start_port, start_port + count)
    ]


def generate_fake_flows(real_src_ports: Set[int], count: int) -> List[Flow]:
    fake = []
    used = set(real_src_ports)
    while len(fake) < count:
        sport = random.randint(20000, 65000)
        if sport in used:
            continue
        fake.append(make_flow("10.0.0.1", "10.0.0.2", sport, 8080))
        used.add(sport)
    return fake

def debug_one_flow(words: List[int], flow: Flow, label: str):
    bits = bloom_bit_positions(flow)
    print(f"\nDEBUG {label}")
    print("flow =", flow)
    print("bits =", bits)
    for bit in bits:
        word = bit >> 6
        offset = bit & 63
        mask = 1 << offset
        present = (words[word] & mask) != 0
        print(f"  bit={bit} word={word} offset={offset} present={present} word_value={words[word]}")


def main():
    bloom_path = "/home/vbox-user/iw/test_outputs/bloom_after_inserted_flows_2p15.json"

    inserted_start_port = 10000
    inserted_count = 1000
    inserted_dport = 8080
    fake_count = 10000

    words = load_bloom_dump(bloom_path)

    print("sanity 12345->8080 =", make_flow("10.0.0.1", "10.0.0.2", 12345, 8080))

    real_flows = generate_real_flows(inserted_start_port, inserted_count, inserted_dport)
    fake_flows = generate_fake_flows(
        set(range(inserted_start_port, inserted_start_port + inserted_count)),
        fake_count,
    )

    known = make_flow("10.0.0.1", "10.0.0.2", 10000, 8080)
    debug_one_flow(words, known, "known inserted flow 10000->8080")

    tp = sum(1 for f in real_flows if bloom_contains(words, f))
    fp = sum(1 for f in fake_flows if bloom_contains(words, f))
    fn = inserted_count - tp
    tn = fake_count - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / fake_count if fake_count > 0 else 0.0
    recall = tp / inserted_count if inserted_count > 0 else 0.0

    print("\n=== Bloom attacker simulation ===")
    print(f"Real flows tested: {inserted_count}")
    print(f"Fake flows tested: {fake_count}")
    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print(f"TN: {tn}")
    print(f"Recall (TP rate): {recall:.4f}")
    print(f"False positive rate: {fpr:.4f}")
    print(f'Attacker confidence / precision P(real | Bloom says "yes"): {precision:.4f}')


if __name__ == "__main__":
    main()
