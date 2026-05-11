// SPDX-License-Identifier: GPL-2.0
//
// netscope: per-CPU byte counter on tcx ingress + per-CPU TCP retransmit
// counter via fentry on tcp_retransmit_skb + per-CPU SRTT histogram via
// fentry on tcp_rcv_established.
// Observation only — never alters packet disposition or socket state.
//
// This file is GPL-2.0 (single-file exception within an Apache-2.0 repo),
// matching the BPF "GPL" license string below. Required for use of
// GPL-only BPF helpers and for attaching to GPL-only kernel symbols
// (tcp_retransmit_skb and tcp_rcv_established are both EXPORT_SYMBOL_GPL).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Forward-declare struct sock. We never read fields from it directly —
// the pointer flows through bpf_skc_to_tcp_sock to get a verifier-typed
// tcp_sock. An incomplete declaration is enough for the helper signature.
struct sock;

// Shadowed kernel struct declaration for CO-RE. We don't include a full
// vmlinux.h (it'd be ~5-10MB checked into the repo); instead we declare
// just the one field we touch and let libbpf rewrite the offset at load
// time using the target kernel's BTF. preserve_access_index is what makes
// the relocation happen — without it the compiler bakes in whatever offset
// our local declaration implies, which would be wrong against the real
// kernel struct.
struct tcp_sock {
    __u32 srtt_us;
} __attribute__((preserve_access_index));

// Verifier-blessed type narrowing. tcp_rcv_established's first argument is
// BTF-typed as struct sock * (size ~1232 bytes on Talos 6.18.9, varies by
// kernel). The verifier refuses to read srtt_us via a plain
// (struct tcp_sock *)sk cast because that offset (~1672 bytes on this
// kernel) lies beyond sizeof(struct sock) from the verifier's perspective —
// even though tcp_sock embeds struct sock as its first member in actual
// memory layout, the BPF type system has no way to know that.
//
// bpf_skc_to_tcp_sock is a BTF-typed kernel function (libbpf surfaces it
// via bpf_helper_defs.h, which bpf_helpers.h includes above). It checks at
// runtime that the sock is a TCP stream socket and returns a
// struct tcp_sock * (or NULL). The function's return BTF tells the
// verifier the returned pointer is genuinely tcp_sock-typed, so the
// srtt_us field load is legal. In practice the NULL path is essentially
// unreachable from tcp_rcv_established (which is only called on
// established fullsocks), but the verifier still requires us to handle it.

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

// netscope_tcp_srtt_buckets: per-CPU log2 histogram of TCP smoothed RTT.
// 24 buckets covering ~1µs through ~8s, last bucket is overflow. Userspace
// sums across possible CPUs and converts to cumulative `le`-style Prometheus
// buckets at scrape time.
//
// The kernel stores srtt_us as actual_microseconds * 8 (3-bit fixed-point);
// we deliberately bucket on the *scaled* value because bucket boundaries are
// powers of two — shifting by 3 just renames the buckets, it doesn't change
// the math. Userspace knows about the >>3 when labelling the `le` boundaries.
#define NETSCOPE_SRTT_NUM_BUCKETS 24
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NETSCOPE_SRTT_NUM_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} netscope_tcp_srtt_buckets SEC(".maps");

// fentry on tcp_rcv_established fires on every received segment of an
// established TCP connection (the "slow path" name is a historical misnomer;
// it's the common path for data segments). SRTT is freshly updated in this
// function, so reading tcp_sock->srtt_us at function entry actually gives us
// the previous segment's smoothed value — close enough for a histogram, and
// avoids an fexit which would cost a return-probe stack frame per packet.
//
// CO-RE: direct field access through the preserve_access_index tcp_sock
// struct is rewritten by libbpf at load time against the target kernel's
// actual offset. No vmlinux.h required.
//
// Two verifier traps to avoid:
//   1. fentry/fexit programs MUST use direct memory access, not the
//      BPF_CORE_READ macro — it expands to bpf_probe_read_kernel() which
//      this program type forbids by design (fentry already has direct
//      access via typed arguments).
//   2. Direct cast (struct tcp_sock *)sk does NOT compile-pass the verifier
//      either: it knows sk is struct sock (~1232 bytes) and rejects loads
//      at offset ~1672. Use bpf_skc_to_tcp_sock to get a verifier-typed
//      tcp_sock pointer; the helper checks at runtime that sk is actually
//      a full TCP stream socket and returns NULL otherwise.
SEC("fentry/tcp_rcv_established")
int BPF_PROG(record_tcp_srtt, struct sock *sk)
{
    struct tcp_sock *tsk = bpf_skc_to_tcp_sock(sk);
    if (!tsk) {
        // Not a TCP stream socket (or partial sock — e.g. request socks
        // during the SYN/SYN-ACK handshake). Skip silently.
        return 0;
    }
    __u32 srtt_us = tsk->srtt_us;
    if (srtt_us == 0) {
        // Pre-handshake or freshly reset connection — no SRTT sample yet.
        // Skipping keeps the histogram from being dominated by a bucket-0
        // spike on every new connection.
        return 0;
    }

    // log2 bucket: floor(log2(srtt_us)) clamped to [0, NUM_BUCKETS-1].
    // We avoid __builtin_clz here because the LLVM-14 BPF backend
    // available in the Debian-bookworm builder image segfaults during
    // SelectionDAG legalization on a CLZ node — a known toolchain quirk
    // that doesn't surface in newer clang releases. The unrolled
    // shift-and-compare loop generates a fixed, branchy sequence the
    // verifier and backend both handle without issue.
    __u32 bucket = 0;
    __u32 v = srtt_us;
    #pragma unroll
    for (__u32 i = 1; i < NETSCOPE_SRTT_NUM_BUCKETS; i++) {
        v >>= 1;
        if (v) {
            bucket = i;
        }
    }

    __u64 *val = bpf_map_lookup_elem(&netscope_tcp_srtt_buckets, &bucket);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}
