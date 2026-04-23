# test_bloom_configs (m variation)
---
### Environment Setup (must rerun for every test):
```
sudo ~/iw/scripts/00_reset.sh
sudo ~/iw/scripts/01_mount_bpffs.sh
sudo ~/iw/scripts/02_net_setup.sh
~/iw/scripts/03_build.sh
make user
sudo ~/iw/user/loader ~/iw/bpf/xdp_tcp_bloom.o
```

### Test Setup and Format:
1. modify `BLOOM_BITS` value in `bpf/xdp\_tcp\_bloom.c` to match the desired m parameter, then run environment setup
2. send n (= 1000) SYNs (real flows)
3. dump and save `blooms` pre-attack
4. run `bloom_attacker_sim.py` on the saved `blooms` file along with desired parameter arguments `<n> <number of attacker flows (10000)> **<2^m>** <k>` and save the results

### m = 2^10, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m10_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m10_n1000.json \
  1000 \
  10000 \
  1024 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m10_n1000.txt
```

### m = 2^11, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m11_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m11_n1000.json \
  1000 \
  10000 \
  2048 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m11_n1000.txt
```

### m = 2^12, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m11_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m11_n1000.json \
  1000 \
  10000 \
  4096 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m11_n1000.txt
```

### m = 2^13, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080

sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m13_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m13_n1000.json \
  1000 \
  10000 \
  8192 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m13_n1000.txt
```


### m = 2^14, n = 1000
```
sudo python3 ~/iw/scripts/scapy_syn_client_batch.py 10000 1000 8080
sudo bpftool map dump pinned /sys/fs/bpf/iw/bloom > ~/iw/test_outputs/test_bloom_configs/bloom_m14_n1000.json

python3 ~/iw/scripts/bloom_attacker_sim.py \
  ~/iw/test_outputs/test_bloom_configs/bloom_m14_n1000.json \
  1000 \
  10000 \
  16384 \
  3 | tee ~/iw/test_outputs/test_bloom_configs/results/bloom_sim_m14_n1000.txt
```
