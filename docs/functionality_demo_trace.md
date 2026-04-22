# Functionality Demos
---
### Environment Setup:

```
sudo ~/iw/scripts/00_reset.sh
sudo ~/iw/scripts/01_mount_bpffs.sh
sudo ~/iw/scripts/02_net_setup.sh
sudo ~/iw/scripts/03_build.sh
gcc -O2 -g -Wall ~/iw/user/loader.c -o ~/iw/user/loader -lbpf -lelf
sudo ~/iw/user/loader ~/iw/bpf/xdp_tcp_pipeline.o
```

*Note: For `counters`, **packets seen (key 0)** and **parse errors/non-relevant packets (key 8)** will increment due to the kernel occasionally sending/receiving a few background packets; these are not important for the demo traces and can be ignored.*

## 1. SYN INSERTS FLOW

```
sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_functionality_demo/counters_baseline.txt
sudo bpftool map dump pinned /sys/fs/bpf/iw/flows > ~/iw/test_outputs/test_functionality_demo/flows_baseline.txt

sudo python3 ~/iw/scripts/scapy_syn_client.py

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_functionality_demo/counters_after_syn.txt
sudo bpftool map dump pinned /sys/fs/bpf/iw/flows > ~/iw/test_outputs/test_functionality_demo/flows_after_syn.txt
```

**SYN seen (key 1)** and **flow inserted (key 2)** in `counters` should increase, and there should be 1 flow in `flows`.

## 2. Valid (accepted) SYN-ACK (must be within TTL window (currently 1 min)

```
sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_server_nsS.py

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_functionality_demo/counters_after_valid_synack.txt
sudo bpftool map dump pinned /sys/fs/bpf/iw/flows > ~/iw/test_outputs/test_functionality_demo/flows_after_valid_synack.txt
```

**Bloom "maybe" (key 4)** and **exact accept (key 5)** should increase, and `flows` map should be empty.

## 3. Invalid (wrong port) SYN-ACK

```
sudo ip netns exec nsS python3 ~/iw/scripts/scapy_synack_wrong_port.py

sudo bpftool map dump pinned /sys/fs/bpf/iw/counters > ~/iw/test_outputs/test_functionality_demo/counters_after_invalid_synack.txt
```

**Bloom reject (key 3)** should increase.

*Note: technically the false positive behavior (Bloom "maybe" (key 4) + exact reject (key 6) increase) is also possible, but since we're only sending 1 flow this won't happen.*
