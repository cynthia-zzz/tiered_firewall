CLANG ?= clang
CFLAGS := -O2 -g -Wall

# Output targets
BPF_OBJ := bpf/xdp_tcp_bloom.o
USER_BIN := user/loader

# Default target
all: $(BPF_OBJ)

# Compile BPF program
$(BPF_OBJ): bpf/xdp_tcp_bloom.c
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $@ -I/usr/include/x86_64-linux-gnu

# Compile userspace loader (optional for later)
$(USER_BIN): user/loader.c
	$(CLANG) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
