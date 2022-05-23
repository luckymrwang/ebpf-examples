#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

SEC("xdp_drop_ipv6")
int xdp_drop_prog(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";