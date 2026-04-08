#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <sys/stat.h>

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static int open_netns_fd(const char *netns_name) {
    char path[256];
    snprintf(path, sizeof(path), "/var/run/netns/%s", netns_name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open netns file %s: %s\n", path, strerror(errno));
        return -1;
    }
    return fd;
}

static int attach_xdp_by_ifname(const char *ifname, int prog_fd, __u32 xdp_flags) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
        return -1;
    }
    struct bpf_xdp_attach_opts opts;
    memset(&opts, 0, sizeof(opts));
    // opts.sz is required on newer libbpf; harmless if ignored on older
    opts.sz = sizeof(opts);

    int err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
    if (err) {
        fprintf(stderr, "bpf_xdp_attach(if=%s idx=%d) failed: %s\n",
                ifname, ifindex, strerror(-err));
        return -1;
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    const char *obj_path = (argc > 1) ? argv[1] : "bpf/xdp_tcp_bloom.o";
    const char *pin_dir    = "/sys/fs/bpf/iw";
    const char *if_root    = "vethA";
    const char *netns_name = "nsS";
    const char *if_ns      = "vethB";

    __u32 xdp_flags = 0; // Native XDP if possible
    // If your driver doesn't support native XDP, you can switch to SKB mode:
    // xdp_flags = XDP_FLAGS_SKB_MODE;

    libbpf_set_print(libbpf_print_fn);

    // Save original netns so we can return after attaching in nsS.
    int orig_netns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (orig_netns < 0) die("open(/proc/self/ns/net)");

    // Open and load BPF object once
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) die("bpf_object__open_file");

    if (bpf_object__load(obj)) die("bpf_object__load");

    // Find program by section name "xdp" (SEC("xdp"))
    struct bpf_program *prog = NULL;
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (sec && strcmp(sec, "xdp") == 0)
            break;
    }
    if (!prog) {
        fprintf(stderr, "Could not find SEC(\"xdp\") program in %s\n", obj_path);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) die("bpf_program__fd");

    // Pin maps for easier debugging with bpftool (optional but useful)
    // This pins ALL maps from the object into pin_dir/<mapname>
    // (Requires bpffs mounted at /sys/fs/bpf)
    (void)mkdir(pin_dir, 0700);
    int err = bpf_object__pin_maps(obj, pin_dir);
    if (err) {
        fprintf(stderr, "Warning: bpf_object__pin_maps(%s) failed: %s\n",
                pin_dir, strerror(-err));
        // Not fatal: attachments will still share maps within this process.
    } else {
        fprintf(stderr, "[*] Pinned maps under %s\n", pin_dir);
    }

    // Attach to root interface (vethA)
    fprintf(stderr, "[*] Attaching to root if %s...\n", if_root);
    if (attach_xdp_by_ifname(if_root, prog_fd, xdp_flags) != 0) {
        fprintf(stderr, "Failed attaching to %s\n", if_root);
        return 1;
    }

    // Switch to nsS and attach to vethB
    int nsfd = open_netns_fd(netns_name);
    if (nsfd < 0) return 1;

    fprintf(stderr, "[*] setns() into netns %s...\n", netns_name);
    if (setns(nsfd, CLONE_NEWNET) != 0) die("setns(nsS)");

    fprintf(stderr, "[*] Attaching to ns if %s...\n", if_ns);
    if (attach_xdp_by_ifname(if_ns, prog_fd, xdp_flags) != 0) {
        fprintf(stderr, "Failed attaching to %s in netns %s\n", if_ns, netns_name);
        return 1;
    }

    // Return to original netns
    if (setns(orig_netns, CLONE_NEWNET) != 0) die("setns(orig)");

    fprintf(stderr, "[*] Attached XDP to %s (root) and %s (netns %s).\n", if_root, if_ns, netns_name);
    fprintf(stderr, "[*] Loader is now keeping the BPF object/maps alive.\n");
    fprintf(stderr, "    Leave this running during your tests. Ctrl+C to exit.\n");

    // Keep process alive so links remain attached; detach on exit is optional.
    while (1) pause();

    // Unreachable in this minimal version
    bpf_object__close(obj);
    close(nsfd);
    close(orig_netns);
    return 0;
}
