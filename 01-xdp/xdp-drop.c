#include <linux/bpf.h>

/*
 * Comments from Linux Kernel:
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader.
 * End of comments

 * You can either use the helper header file below
 * so that you don't need to define it yourself:
 * #include <bpf/bpf_helpers.h> 
 */
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx) {
    // 意思是无论什么网络数据包，都drop丢弃掉
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";