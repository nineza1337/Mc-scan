typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef int __s32;
typedef long long __s64;

#include <bpf/bpf_helpers.h>

#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP 17
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";
