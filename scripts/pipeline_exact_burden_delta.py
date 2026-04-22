# ~/iw/scripts/pipeline_exact_burden_delta.py
import json
import sys


def load_counters(path: str) -> dict[int, int]:
    with open(path, "r") as f:
        arr = json.load(f)
    return {int(entry["key"]): int(entry["value"]) for entry in arr}


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <before_json> <after_json>")
        sys.exit(1)

    before = load_counters(sys.argv[1])
    after = load_counters(sys.argv[2])

    delta = {}
    for k in set(before) | set(after):
        delta[k] = after.get(k, 0) - before.get(k, 0)

    bloom_reject = delta.get(3, 0)
    bloom_maybe = delta.get(4, 0)
    exact_accept = delta.get(5, 0)
    exact_reject = delta.get(6, 0)

    exact_total = exact_accept + exact_reject

    efficiency = (exact_accept / exact_total) if exact_total > 0 else 0.0
    reject_fraction = (exact_reject / exact_total) if exact_total > 0 else 0.0
    fraction_reaching_exact = (
        bloom_maybe / (bloom_maybe + bloom_reject)
        if (bloom_maybe + bloom_reject) > 0 else 0.0
    )

    print("=== Exact-layer burden metrics (delta) ===")
    print(f"Bloom reject delta (key 3): {bloom_reject}")
    print(f"Bloom maybe  delta (key 4): {bloom_maybe}")
    print(f"Exact accept delta (key 5): {exact_accept}")
    print(f"Exact reject delta (key 6): {exact_reject}")
    print()
    print(f"Exact load (number of exact lookups): {bloom_maybe}")
    print(f"Wasted exact work (rejects): {exact_reject}")
    print(f"Exact efficiency = accept / (accept + reject): {efficiency:.4f}")
    print(f"Exact reject fraction = reject / (accept + reject): {reject_fraction:.4f}")
    print(f"Fraction of inbound candidates reaching Exact = maybe / (maybe + bloom_reject): {fraction_reaching_exact:.4f}")


if __name__ == "__main__":
    main()
