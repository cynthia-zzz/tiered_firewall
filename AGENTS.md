# AGENTS.md — tiered_firewall

Guidance for AI coding agents (Codex, Claude Code, etc.) working in this repo.
Human-facing docs live in README.md. If anything here conflicts with an explicit
instruction from Cynthia in the current session, follow Cynthia.

## What this project is

Senior thesis (Princeton ECE 498/499, advisors Prateek Mittal and Jennifer Rexford),
extending a junior IW prototype. Research question:

> Given compromised firewall state, how much of the underlying communication graph
> can an adversary reconstruct, and how can tiered firewall state be designed to
> bound that leakage while preserving correct filtering?

Architecture: an upstream **approximate** tier (Bloom filter of recent outbound flows,
at a campus/enterprise perimeter) and a downstream **exact** verifier (endpoint or
department gateway). The prototype implements both in eBPF/XDP on a veth pair.

## Notation (use these names consistently in code, comments, plots)

| Symbol | Meaning | Code name |
|---|---|---|
| G_W = (V, E_W) | true communication graph over window W | `true_graph` |
| O_C | firewall state observed under compromise class C | `snapshot` |
| Z | attacker auxiliary knowledge | `aux` / `prior` |
| A(O_C, Z) | reconstruction attacker | `attack_*` |
| m | Bloom filter size **in bits** (not log2) | `m_bits` |
| k | number of hash functions | `k` |
| n | flows inserted in the current retention window | `n` |
| ε | false-positive rate | `fpr` |
| Δ | rotation epoch length | `epoch_s` |
| S | candidate source-port space size | `S_ports` |

Compromise classes: **C1** state-only leak (no keys), **C2** full memory snapshot
(state + keys), **C3** repeated snapshots, **C4** persistent compromise (out of scope
after time of compromise).

Headline metric is always **advantage over the Z-only baseline**
(e.g. edge AUC with O_C and Z minus edge AUC with Z alone). Never report a raw
posterior computed from an assumed prior as a privacy result.

## Repo layout

```
bpf/        eBPF/XDP programs (C). xdp_tcp_pipeline.c is the combined system;
            xdp_tcp_bloom.c and xdp_tcp_exact.c are single-tier variants.
user/       loader.c — loads a .o, pins maps to /sys/fs/bpf/iw, attaches XDP to
            vethA (root ns) and vethB (netns nsS). Interface names are hard-coded.
scripts/    00–03 setup scripts, Scapy traffic generators, bloom_attacker_sim.py,
            plot_results.py
docs/       step-by-step reproduction traces for the IW experiments
            (functionality demo, Bloom m- and n-sweeps). Keep these in sync when
            changing scripts or map names.
test_outputs/  IW-era results (bpftool map dumps as JSON, simulator outputs, figures)
```

Scripts and docs assume the repo lives at `~/iw`.

Planned for the thesis (create when needed): `sim/` (offline reconstruction
simulator, Python), `experiments/<id>/` (configs + results), `docs/` (notes, memo).

## Build and run

Requires Linux, root, clang, libbpf, bpftool, Python 3 with scapy.

See `docs/*.md` for exact per-experiment commands.

```bash
make                       # builds bpf/*.o and user/loader
scripts/00_reset.sh        # detach XDP, delete veths/netns, remove pinned maps
scripts/01_mount_bpffs.sh
scripts/02_net_setup.sh    # vethA 10.0.0.1 <-> vethB 10.0.0.2 (in netns nsS)
sudo user/loader bpf/xdp_tcp_pipeline.o   # leave running
sudo bpftool map dump pinned /sys/fs/bpf/iw/<map>   # BTF -> JSON key/value output
```

Bloom parameters are compile-time `#define`s (`BLOOM_BITS`, `BLOOM_K`) in each
`bpf/*.c`; change them and rebuild.

## Invariants — do not break

1. **Hash parity.** `mix32` / `flow_hash` / seed schedule (`0x9e3779b9 * (i+1)`) in
   `bpf/*.c` and in every Python reimplementation must stay bit-for-bit identical.
   If you change one, change all and rerun the fidelity check (Python simulator vs
   a real `bpftool` dump must agree on every bit and on observed ε).
2. **Byte order.** Flow keys are hashed in network byte order as stored in the
   packet (`ip_to_u32_bpf`, `port_to_u16_bpf` in the Python sim). Keep it.
3. `BLOOM_BITS` must be a power of two and a multiple of 64.
4. Counter indices are an interface used by scripts and saved results. Do not
   renumber; append new counters at the end. (Note: `xdp_tcp_exact.c` and
   `xdp_tcp_pipeline.c` currently use different counter layouts.)
5. Report m in bits. IW tables label log2(m) as "m"; do not propagate that.

## Experiment conventions

- Every run: fixed RNG seed, a saved config file (YAML/JSON) next to its results,
  and the git commit hash recorded in the output.
- One directory per run: `experiments/<exp_id>/<timestamp>_<short_desc>/`.
- **Never overwrite or edit existing results** (including everything in
  `test_outputs/`). Write new runs to new directories.
- Plots are generated from saved result files by a script, never from numbers
  hard-coded in the plotting script.
- Simulator code must not require root or the kernel; the eBPF prototype is
  only used for fidelity checks and systems measurements.

## Known limitations of the current prototype (don't "discover" these as new)

- Both tiers run in one XDP program with shared maps on one host.
- Direction is inferred from TCP flags, not interface: inbound SYNs are inserted
  and passed.
- Only SYN and SYN-ACK are handled; all other packets return `XDP_PASS`.
- The Bloom filter is never cleared or rotated.
- No performance measurements exist yet.

## Do not

- Run anything with `sudo`, or the 00–03 scripts, without asking first.
- Delete or modify files in `test_outputs/` or `experiments/`.
- Change hash functions, map layouts, or counter indices without updating every
  consumer and saying so.
- Commit build artifacts (`*.o`, `user/loader`).
- Make claims in docs/comments that results don't support (e.g., "prevents replay
  attacks", "negligible leakage") — state assumptions explicitly.
- Push to remote or open PRs unless asked.
