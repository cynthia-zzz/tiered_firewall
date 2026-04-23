# test_bloom_configs (n variation)
---
### Environment Setup (must rerun for every test):
```
sudo ~/iw/scripts/00_reset.sh
sudo ~/iw/scripts/01_mount_bpffs.sh
sudo ~/iw/scripts/02_net_setup.sh
sudo ~/iw/scripts/03_build.sh
gcc -O2 -g -Wall ~/iw/user/loader.c -o ~/iw/user/loader -lbpf -lelf
sudo ~/iw/user/loader ~/iw/bpf/xdp_tcp_bloom.o

```

### Test Setup and Format:
1. send n (modify parameter `<number of attacker flows> **<n>** <dport>`) SYNs (real flows)
2. dump and save `blooms` pre-attack
3. run `bloom_attacker_sim.py` on the saved `blooms` file along with desired parameter arguments `**<n>** <number of attacker flows (10000)> <2^m> <k>` and save the results


### m = 2^12, n = 100
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 100 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n100.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n100.json \
  100 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n100.txt
```

### m = 2^12, n = 500
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 500 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n500.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n500.json \
  500 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n500.txt
```

### m = 2^12, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n1000.json \
  1000 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n1000.txt
```

### m = 2^12, n = 2000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 2000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n2000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n2000.json \
  2000 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n2000.txt
```

### m = 2^12, n = 5000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 5000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n5000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n5000.json \
  5000 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n5000.txt
```

### m = 2^12, n = 10000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 10000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m12_n10000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m12_n10000.json \
  10000 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m12_n10000.txt
```
