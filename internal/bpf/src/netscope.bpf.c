// SPDX-License-Identifier: GPL-2.0
//
// netscope: per-CPU byte counter on tcx ingress + per-CPU TCP retransmit
// counter via fentry on tcp_retransmit_skb.
// Observation only — never alters packet disposition or socket state.
//
// This file is GPL-2.0 (single-file exception within an Apache-2.0 repo),
// matching the BPF "GPL" license string below. Required for use of
// GPL-only BPF helpers and for attaching to GPL-only kernel symbols
// (tcp_retransmit_skb is exported with EXPORT_SYMBOL_GPL).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

// netscope_tcp_retransmits: per-CPU TCP retransmit counter, single key (0).
// Same shape as netscope_rx_bytes; userspace sums across possible CPUs at
// scrape time. v1 is intentionally a single counter — per-4-tuple keying
// (src/dst IP+port, peer IP+port) is deferred to a follow-up.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} netscope_tcp_retransmits SEC(".maps");

// fentry on tcp_retransmit_skb fires at function entry, which is the moment
// the kernel has decided to retransmit (RTO, fast-retransmit, etc.). We use
// fentry rather than fexit because we don't need the return value and would
// rather count the decision than the outcome — a retransmit that failed to
// build an skb is still meaningful signal.
//
// We do not dereference the sk/skb arguments here. Phase 2.5 will key by
// 4-tuple (which requires reading struct sock fields and thus vmlinux.h);
// v1 keeps the program minimal so the verifier sees nothing but a per-CPU
// map increment — same shape as count_rx above.
SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(count_tcp_retransmit)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&netscope_tcp_retransmits, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}
