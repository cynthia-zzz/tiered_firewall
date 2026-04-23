CLANG ?= clang
CC ?= gcc

BPF_CFLAGS := -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu
USER_CFLAGS := -O2 -g -Wall
USER_LDLIBS := -lbpf -lelf

BPF_DIR := bpf
USER_DIR := user

BPF_TARGETS := \
	$(BPF_DIR)/xdp_tcp_bloom.o \
	$(BPF_DIR)/xdp_tcp_exact.o \
	$(BPF_DIR)/xdp_tcp_pipeline.o

USER_TARGETS := \
	$(USER_DIR)/loader

.PHONY: all bpf user clean rebuild

all: bpf user

bpf: $(BPF_TARGETS)

user: $(USER_TARGETS)

$(BPF_DIR)/xdp_tcp_bloom.o: $(BPF_DIR)/xdp_tcp_bloom.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_DIR)/xdp_tcp_exact.o: $(BPF_DIR)/xdp_tcp_exact.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_DIR)/xdp_tcp_pipeline.o: $(BPF_DIR)/xdp_tcp_pipeline.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_DIR)/loader: $(USER_DIR)/loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -f $(BPF_DIR)/*.o $(USER_DIR)/loader

rebuild: clean all
