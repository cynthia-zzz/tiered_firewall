# Tiered, Privacy-Preserving Stateful Firewall

Cynthia Zhang · Princeton ECE · Senior thesis (2026–27), advised by Prof. Prateek Mittal
and Prof. Jennifer Rexford. Builds on junior independent work (ECE 399, Spring 2026)
advised by Sophia Yoo and Prof. Jennifer Rexford.

## Overview

Stateful firewalls keep per-flow state (5-tuples, timestamps) to tell legitimate
replies from unsolicited traffic. That state doubles as a log of who talked to whom
and when, and it is exposed if the firewall is compromised, misconfigured, audited,
or backed up.

This project splits firewall state across trust domains:

- **Approximate tier (perimeter):** a Bloom filter of recent outbound flows. It drops
  most unsolicited traffic without storing an enumerable list of connections.
- **Exact tier (verifier):** precise per-flow state held in a smaller trust domain
  (the endpoint, or later a department gateway). It resolves the Bloom filter's
  false positives so legitimate traffic is never dropped and unsolicited traffic is
  never delivered.

**Thesis question:** given compromised firewall state, how much of the underlying
communication graph can an adversary reconstruct, and how can tiered state be
designed to bound that leakage while preserving correct filtering?

## Status

| Component | State |
|---|---|
| eBPF/XDP prototype (SYN / SYN-ACK handling) | Working (IW) |
| IW evaluation: false-positive rate, exact-tier load | Done (IW) |
| Threat model and compromise classes | In progress (thesis) |
| Offline graph-reconstruction simulator | Planned, Fall 2026 |
| Bloom filter epoch rotation, TC egress insertion | Planned |
| Full TCP lifecycle, keyed/PRF state, gateway placement | Planned, Spring 2027 |

### Known limitations of the current prototype

- Both tiers run in one XDP program with shared maps on one host, so the trust
  separation is modeled, not deployed.
- Direction is inferred from TCP flags, not the interface. Inbound SYNs are inserted
  into state and passed.
- Only SYN and SYN-ACK are filtered. All other packets pass.
- The Bloom filter is never cleared, so it retains every flow since load.
- The IW privacy metric ("attacker confidence" with an assumed prior P = 1e-6) is
  being replaced by reconstruction advantage over a prior-only baseline.

## Repository layout

```
bpf/
  xdp_tcp_pipeline.c   combined Bloom filter + exact verifier (main system)
  xdp_tcp_bloom.c      Bloom-filter-only variant
  xdp_tcp_exact.c      exact-map-only variant
user/
  loader.c             loads a BPF object, pins maps to /sys/fs/bpf/iw,
                       attaches XDP to vethA and vethB (in netns nsS)
scripts/
  00_reset.sh          tear down veths, netns, pinned maps
  01_mount_bpffs.sh    mount bpffs
  02_net_setup.sh      create vethA (10.0.0.1) <-> vethB (10.0.0.2, netns nsS)
  03_build.sh          build BPF objects
  scapy_*.py           traffic generators (SYN, valid/invalid SYN-ACK, batches)
  bloom_attacker_sim.py  offline membership-query simulator over a map dump
  plot_results.py      IW figures
docs/
  functionality_demo_trace.md  step-by-step functional check (IW Table 1)
  test_bloom_configs_m.md      Bloom size sweep, n = 1000 (IW Table 3)
  test_bloom_configs_n.md      flow-count sweep, m = 2^12 bits (IW Table 4)
test_outputs/          IW results: map dumps, simulator output, figures
```

## Requirements

Linux with XDP support, root access, `clang`, `libbpf` (+ `libelf`), `bpftool`,
`iproute2`, Python 3 with `scapy`; for plots: `pandas`, `numpy`, `matplotlib`,
`matplotx`.

## Quick start

The scripts assume the repo is cloned at `~/iw`.

```bash
sudo ~/iw/scripts/00_reset.sh
sudo ~/iw/scripts/01_mount_bpffs.sh
sudo ~/iw/scripts/02_net_setup.sh
~/iw/scripts/03_build.sh          # builds bpf/*.o
make user                         # builds user/loader
sudo ~/iw/user/loader ~/iw/bpf/xdp_tcp_pipeline.o   # keep running in its own terminal
```

Maps are pinned under `/sys/fs/bpf/iw/` (`bloom`, `flows`, `counters`) and can be
inspected with `sudo bpftool map dump pinned /sys/fs/bpf/iw/<map>`. Because the
maps carry BTF, bpftool prints JSON-formatted key/value entries, which is the
format `bloom_attacker_sim.py` reads.

### Functional check (IW Table 1)

Full trace: [`docs/functionality_demo_trace.md`](docs/functionality_demo_trace.md).

```bash
sudo python3 ~/iw/scripts/scapy_syn_client.py                       # SYN 10.0.0.1:12345 -> 10.0.0.2:8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/flows                   # 1 flow present
sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_server_nsS.py   # matching SYN-ACK: accepted, entry consumed
sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port.py   # mismatched SYN-ACK: dropped
sudo bpftool map dump pinned /sys/fs/bpf/iw/counters
```

The valid SYN-ACK must arrive within the handshake TTL (1 minute). Keys 0 and 8
also tick up from background kernel packets; ignore them.

Pipeline counter indices (`xdp_tcp_pipeline.c`):

| Key | Meaning |
|---|---|
| 0 | packets seen |
| 1 | parsed IPv4/TCP |
| 2 | outbound SYN inserted |
| 3 | Bloom negative (dropped) |
| 4 | Bloom "maybe" |
| 5 | exact positive (accepted) |
| 6 | exact negative (dropped) |
| 7 | exact stale (dropped) |
| 8 | parse errors / non-IPv4-TCP |

`xdp_tcp_exact.c` uses a different 8-entry layout; see its source.

### Bloom filter parameter sweeps (IW Tables 3–4)

Full commands: [`docs/test_bloom_configs_m.md`](docs/test_bloom_configs_m.md) and
[`docs/test_bloom_configs_n.md`](docs/test_bloom_configs_n.md). These use the
Bloom-only program `xdp_tcp_bloom.o`, and the environment must be reset for every
run. For each configuration:

1. Set `BLOOM_BITS` (e.g. `(1 << 12)`) in `bpf/xdp_tcp_bloom.c`, then reset, set
   up, build, and load `xdp_tcp_bloom.o` as in Quick start.
2. Insert n flows (source ports 10000…10000+n−1, destination port 8080):
   ```bash
   sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 <n> 8080
   ```
3. Dump the filter:
   ```bash
   sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m<log2 bits>_n<n>.json
   ```
4. Run the offline simulator (10,000 non-member probes, k = 3). Note that the
   fourth argument is the filter size **in bits**:
   ```bash
   python3 ~/iw/scripts/bloom_attacker_sim.py \
     ~/iw/test_outputs/test_bloom_configs/bloom_m<log2 bits>_n<n>.json \
     <n> 10000 <bits> 3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m<log2 bits>_n<n>.txt
   ```

IW tables label the filter size as m = 10…14. These are log2 values; the filters
were 2^10…2^14 bits. Result files follow the same `m<log2 bits>` naming.

**Known file mix-up (2^11):** the m = 2^12 block in `docs/test_bloom_configs_m.md`
writes to `m11` filenames, so `bloom_m11_n1000.json` and
`results/bloom_sim_m11_n1000.txt` actually hold a **2^12-bit** run (the dump is
identical to `bloom_m12_n1000.json`). The real 2^11-bit dump is
`bloom_m11_n1000_check.json`, and the IW-reported 2^11 numbers (ε = 0.457) are in
`results/bloom_sim_m11_n1000_report.txt`.

**Fidelity:** recomputing the Bloom bits in Python from the known inserted flows
reproduces every saved dump (`bloom_*.json` and `*_check.json`) bit-for-bit, so
the Python hash matches the eBPF hash exactly.

### Exact-tier load (IW §6.4)

The procedure loads `xdp_tcp_pipeline.o`, inserts n flows, dumps `counters`,
sends 10,000 unsolicited SYN-ACKs from `nsS`
(`scapy_synack_wrong_port_batch.py 20000 10000 8080`), dumps `counters` again,
and compares keys 3–6. Its write-up (`docs/test_pipeline_burden.md`) and helper
script (`scripts/pipeline_exact_burden_delta.py`) were removed in commit
`9a05352` and can be restored with:

```bash
git checkout 9a05352^ -- docs/test_pipeline_burden.md scripts/pipeline_exact_burden_delta.py
```

The only result still in git history is for a 2^12-bit filter
(`test_outputs/pipeline_burden_10000_2p12.txt` at commit `bda4ec7`): 1,374 of
10,000 unsolicited SYN-ACKs (13.74%) reached the exact tier, and all were rejected.

## Reproducing IW figures

`python3 scripts/plot_results.py` regenerates `test_outputs/fig_m.png` and
`fig_n.png`. The values are currently hard-coded in the script, copied from
`test_outputs/test_bloom_configs/results/`.

## Documents

- IW report: *A Tiered, Scalable, and Privacy-Preserving Stateful Firewall* (April 2026)
- Thesis interim report: Fall 2026 (forthcoming)

## AI use

Parts of this repository's code and documentation were drafted with AI assistance
and reviewed by the author, in accordance with course policy.

## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0).
See [LICENSE](LICENSE). The eBPF programs also declare `"GPL"` to the kernel,
which certain BPF helpers require.
