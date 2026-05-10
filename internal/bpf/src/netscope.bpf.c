// SPDX-License-Identifier: GPL-2.0
//
// netscope: per-CPU byte counter on tcx ingress.
// Phase 0 hello-world — observation only, never alters packet disposition.
//
// This file is GPL-2.0 (single-file exception within an Apache-2.0 repo),
// matching the BPF "GPL" license string below. Required for use of
// GPL-only BPF helpers; the rest of the project remains Apache-2.0.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// netscope_rx_bytes: per-CPU byte counter, single key (0). Userspace sums
// across all possible CPUs at scrape time. Counter only — no eviction.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} netscope_rx_bytes SEC(".maps");

SEC("tcx/ingress")
int count_rx(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&netscope_rx_bytes, &key);
    if (val) {
        __sync_fetch_and_add(val, skb->len);
    }
    return TC_ACT_UNSPEC;
}
