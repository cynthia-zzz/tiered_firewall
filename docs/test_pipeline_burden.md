# test_pipeline_burden
---
### Environment Setup (must rerun for every test):
```
sudo ~/iw/scripts/00_reset.sh
sudo ~/iw/scripts/01_mount_bpffs.sh
sudo ~/iw/scripts/02_net_setup.sh
~/iw/scripts/03_build.sh
make user
sudo ~/iw/user/loader ~/iw/bpf/xdp_tcp_pipeline.o
```

### Test Format:
1. send n SYNs (real flows)
2. dump and save `counters` pre-attack
3. send 10000 invalid (wrong port) SYN-ACKs (attacker flows)
4. dump and save `counters` post-attack
5. run `pipeline_exact_burden_delta.py` to calculate pipeline metrics


## a. VARY M
### m = 2^11, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m11_n1000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m11_n1000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m11_n1000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m11_n1000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m11_n1000.txt
```

### m = 2^12, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n1000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n1000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n1000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n1000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n1000.txt
```

### m = 2^13, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m13_n1000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m13_n1000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m13_n1000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m13_n1000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m13_n1000.txt
```

### m = 2^14, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m14_n1000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m14_n1000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m14_n1000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m14_n1000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m14_n1000.txt
```

## b. VARY N
### n=100
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 100 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n100.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n100.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n100.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n100.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n100.txt
```

### n=500
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 500 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n500.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n500.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n500.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n500.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n500.txt
```

### n=2000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 2000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n2000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n2000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n2000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n2000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n2000.txt
```

### n=5000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 5000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n5000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n5000.json

python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n5000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n5000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n5000.txt
```

### n=10000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n10000.json

sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port_batch.py 20000 10000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n10000.json
python3 ~/iw/scripts/pipeline_exact_burden_delta.py ~/iw/test_outputs/test_pipeline_burden/pipeline_before_attack_m12_n10000.json ~/iw/test_outputs/test_pipeline_burden/pipeline_after_attack_m12_n10000.json | tee ~/iw/test_outputs/test_pipeline_burden/results/pipeline_burden_m12_n10000.txt
```
