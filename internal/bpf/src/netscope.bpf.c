// SPDX-License-Identifier: GPL-2.0
//
// netscope: per-CPU byte counter on tcx ingress + per-CPU TCP retransmit
// counter via fentry on tcp_retransmit_skb + per-CPU SRTT histogram via
// fentry on tcp_rcv_established + per-CPU DNS query latency histogram via
// fentry on udp_sendmsg / fexit on udp_recvmsg + per-domain DNS query
// latency breakdown via a ringbuf carrying query/response payloads to
// userspace (v2).
// Observation only — never alters packet disposition or socket state.
//
// This file is GPL-2.0 (single-file exception within an Apache-2.0 repo),
// matching the BPF "GPL" license string below. Required for use of
// GPL-only BPF helpers and for attaching to GPL-only kernel symbols
// (tcp_retransmit_skb, tcp_rcv_established, udp_sendmsg, and udp_recvmsg
// are all EXPORT_SYMBOL_GPL).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Shadowed kernel struct declarations for CO-RE. We declare only the fields
// we touch and let libbpf rewrite offsets at load time against the target
// kernel's BTF (preserve_access_index). For the DNS hooks we need to read
// the 4-tuple (saddr, sport, daddr, dport) out of struct sock; for the SRTT
// hook the pointer is narrowed by bpf_skc_to_tcp_sock and we read srtt_us
// off the resulting struct tcp_sock.
//
// sock_common's union-of-{addrpair, {daddr, saddr}} and union-of-{portpair,
// {dport, num}} are flattened here — preserve_access_index lets libbpf
// resolve named-field offsets regardless of the surrounding union layout in
// our local declaration. Field NAMES must match the kernel.
struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16  skc_num;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

// Forward declarations for fexit signatures that take pointer args we never
// dereference. We only need the names to type-check the BPF_PROG argument
// list; the verifier doesn't require a body.
//
// For the v2 per-domain DNS work we DO want to dereference msghdr (to reach
// the iovec and read the on-the-wire DNS payload). We shadow the relevant
// fields below with preserve_access_index so libbpf rewrites offsets against
// the target kernel's BTF at load time. Field NAMES must match the kernel;
// the layout is otherwise irrelevant to us.
//
// We intentionally only model the subset of struct iov_iter we actually
// touch: iter_type to gate on the iovec flavor, and the embedded __iov
// pointer that ITER_IOVEC uses. ITER_UBUF and other flavors are not
// supported in this revision (we drop the payload-read silently and the
// userspace correlator just won't get a qname for those queries).
//
// Kernel constants (lib/iov_iter.c, include/linux/uio.h):
//   ITER_IOVEC = 0  (struct iovec * via __iov)
//   ITER_KVEC  = 1  (kernel iovec — different memory domain, skip)
//   ITER_BVEC  = 2  (skip)
//   ITER_XARRAY = 3 (skip)
//   ITER_DISCARD = 4 (no data)
//   ITER_UBUF = 5   (single user buffer, ubuf field — skip in v1)
// Numeric values are stable across 6.x.
#define NETSCOPE_ITER_IOVEC 0

struct iovec {
    void __attribute__((__user__)) *iov_base;
    __u64 iov_len;
};

struct iov_iter {
    __u8 iter_type;
    // __iov is the first iovec pointer for ITER_IOVEC. iov_iter is a
    // tagged union internally; we only read this field, and only after
    // gating on iter_type == ITER_IOVEC.
    const struct iovec *__iov;
} __attribute__((preserve_access_index));

struct msghdr {
    struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

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

// =============================================================================
// DNS query latency
// =============================================================================
//
// Strategy: in-kernel correlation (option A from the design notes). On
// udp_sendmsg with sk_dport == 53 we stash the start timestamp under a
// 4-tuple key. On udp_recvmsg fexit with a positive return (bytes copied)
// and the same 4-tuple, we compute delta = now - start and bucket it.
//
// 4-tuple correlation is intentional. Extracting the DNS transaction id from
// msghdr's iov_iter would require either bpf_probe_read_user on the iovec
// base (which is workable on fentry but fragile across iov_iter flavors —
// ITER_UBUF, ITER_IOVEC, ITER_KVEC all coexist in 6.x) or copying the first
// two bytes from the payload before the kernel does. For v1 we assume one
// outstanding query per (saddr, sport, daddr, dport=53), which holds in
// practice: stub resolvers ephemeral-port-per-query and the kernel rejects
// duplicate ports for connected sockets.
//
// Option (B) — emitting a ringbuf event with the parsed qname so userspace
// can label per-domain histograms — is intentionally deferred to a follow-up
// PR. This PR ships only the aggregate histogram.
//
// Coverage limitation: we filter on sk->__sk_common.skc_dport == htons(53),
// which is populated only for connected UDP sockets (those that called
// connect() before sendmsg, or that had skc_dport set by connect()-emulating
// machinery in the resolver). systemd-resolved and Go's net.Resolver do this;
// glibc's classic res_send(3) path uses sendto() with msg_name and leaves
// skc_dport == 0 — we miss those. Documented as a follow-up; a future PR
// could parse msghdr->msg_name to recover sendto() callers.

// netscope_dns_query_starts: hashmap from 4-tuple to start-timestamp (ns).
// Sized at 8192 entries — DNS query bursts cap naturally well below that,
// and LRU is not needed because we delete on response. If a query times out
// without a response, the entry leaks until the same 4-tuple is reused (we
// upsert with BPF_ANY on every send, so existing-key updates always succeed).
// Only *new-key* inserts can fail with -E2BIG, and only once 8192 distinct
// stale entries accumulate; at ~1s typical query lifetime this is comfortable
// headroom. We deliberately don't surface the -E2BIG case — losing a single
// query sample is preferable to noisy logs on a saturated map.
struct dns_flow_key {
    __be32 saddr;
    __be32 daddr;
    __u16  sport; // host byte order (skc_num)
    __be16 dport; // network byte order (always htons(53) when present)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct dns_flow_key);
    __type(value, __u64);
} netscope_dns_query_starts SEC(".maps");

// netscope_dns_latency_buckets: per-CPU log2 histogram of DNS query latency
// in microseconds. 24 buckets covering ~1µs through ~16s, last bucket is
// overflow. Same shape as the SRTT histogram; userspace converts to
// cumulative `le`-style Prometheus buckets at scrape time.
#define NETSCOPE_DNS_NUM_BUCKETS 24
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NETSCOPE_DNS_NUM_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} netscope_dns_latency_buckets SEC(".maps");

// Build a 4-tuple key from struct sock. The kernel stores skc_dport in
// network byte order and skc_num (sport) in host byte order; we keep both in
// the same units as the kernel so we don't have to translate on lookup.
//
// Inlined rather than a separate static helper to keep the verifier's call
// graph trivial — fentry+helpers nest deep enough already.
static __always_inline void
dns_build_key(struct dns_flow_key *k, struct sock *sk)
{
    // Zero the key first so any padding the compiler inserts between fields
    // is deterministic — the verifier tracks stack init at byte granularity,
    // and a hash-map lookup against partly-uninitialized stack memory is one
    // of the more common verifier rejections in tracing programs.
    __builtin_memset(k, 0, sizeof(*k));
    k->saddr = sk->__sk_common.skc_rcv_saddr;
    k->daddr = sk->__sk_common.skc_daddr;
    k->sport = sk->__sk_common.skc_num;
    k->dport = sk->__sk_common.skc_dport;
}

// =============================================================================
// Per-domain DNS query latency (v2): ringbuf-fed userspace correlation
// =============================================================================
//
// In addition to the in-kernel 4-tuple latency histogram above, we emit
// ringbuf events carrying the raw DNS payload (capped at 256 bytes — enough
// for the question section in every reasonable DNS query). Userspace parses
// the qname, applies suffix bucketing for cardinality control, and emits a
// per-suffix Prometheus histogram. The in-kernel histogram is preserved
// unchanged for dashboard backward compatibility.
//
// Why ringbuf-from-kernel rather than parse-in-kernel:
//   - bpf_probe_read_user on the iovec is well-defined in fentry, but the
//     iov_iter union flavors (ITER_IOVEC vs ITER_UBUF vs ITER_KVEC/BVEC)
//     change the layout of the iovec lookup. We handle only ITER_IOVEC here
//     and silently skip the rest.
//   - DNS label parsing requires bounded loops and pointer-following over
//     untrusted on-wire data. The verifier hates this. Userspace can do it
//     safely with the full Go standard library and good test coverage.
//
// Cardinality control happens entirely in userspace (see cmd/agent/dns.go):
// suffix bucketing (last 2-3 labels), LRU cap of 100 suffixes, "_other_"
// bucket for everything beyond that.

// netscope_dns_events: ringbuf carrying raw DNS payloads to userspace. 256KB
// is sized for the typical homelab query rate (low hundreds/sec across all
// pods). At ~280 bytes per event (4-tuple + header + 256 payload) that's
// ~900 events buffered before backpressure, well above the userspace reader
// drain interval. If we ever saturate (e.g. a misbehaving resolver loop),
// bpf_ringbuf_output returns -ENOSPC and we drop the event silently — the
// in-kernel aggregate histogram still captures the latency, we just miss
// the per-domain breakdown for that event.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} netscope_dns_events SEC(".maps");

// Event types emitted on the ringbuf. The userspace correlator pairs query
// events to response events by 4-tuple within a short window.
#define NETSCOPE_DNS_EVENT_QUERY    1
#define NETSCOPE_DNS_EVENT_RESPONSE 2

// 256 bytes is enough for the full question section in every realistic DNS
// query: max QNAME is 255 bytes (RFC 1035) + 4 bytes QTYPE/QCLASS + 12-byte
// header = 271. We clamp at 256 because we only need the qname (first
// question), which lives within the first ~270 bytes for any reasonable
// query; truncating QTYPE is fine.
#define NETSCOPE_DNS_PAYLOAD_BYTES 256

// dns_event: ringbuf record shape. Keep this layout in sync with
// cmd/agent/dns.go (the userspace parser uses unsafe-cast or
// encoding/binary to read the same fields).
//
// Field order is chosen to minimize padding on x86_64 / arm64 (8-byte and
// 4-byte fields first, then __u16, then __u8). We zero the whole struct
// before populating so the verifier sees a fully-initialized event.
struct dns_event {
    __u64 timestamp_ns;        // bpf_ktime_get_ns at emission point
    __be32 saddr;
    __be32 daddr;
    __u16  sport;              // host byte order (matches dns_flow_key)
    __be16 dport;              // network byte order
    __u8   event_type;         // QUERY or RESPONSE
    __u8   payload_truncated;  // 1 if the userland buffer was shorter than we read
    __u16  payload_len;        // actual bytes valid in payload[]
    __u8   payload[NETSCOPE_DNS_PAYLOAD_BYTES];
};

// dns_event_scratch: per-CPU staging area for the event struct. Defining
// `struct dns_event` on the stack (~280 bytes) would consume most of the
// 512-byte BPF stack budget; putting it in a per-CPU array map with a
// single key (0) lets the verifier track initialization at byte granularity
// without exhausting the stack. This is the canonical pattern for tracing
// programs that emit large ringbuf records.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_event);
} netscope_dns_event_scratch SEC(".maps");

// Emit a ringbuf event for the given sock + msghdr. Reads up to
// NETSCOPE_DNS_PAYLOAD_BYTES of user data from the first iovec when the
// msg_iter flavor is ITER_IOVEC. Silently drops on:
//   - non-ITER_IOVEC iter flavors (ITER_UBUF, ITER_KVEC, etc.)
//   - bpf_probe_read_user failure (user munmap'd, fault, etc.)
//   - ringbuf full (-ENOSPC from bpf_ringbuf_output)
//
// Returning void rather than int because every caller ignores the result;
// emission is best-effort relative to the aggregate histogram.
static __always_inline void
dns_emit_event(struct sock *sk, struct msghdr *msg, __u8 event_type)
{
    __u32 zero = 0;
    struct dns_event *e = bpf_map_lookup_elem(&netscope_dns_event_scratch, &zero);
    if (!e) {
        // Per-CPU array with one slot is allocated at load time; lookup
        // never fails in practice. The verifier still requires the check.
        return;
    }

    // Zero header bytes only — we'll set payload_len based on what we
    // actually read, and the trailing payload bytes don't need to be
    // pre-zeroed because we send `sizeof(header) + payload_len` to ringbuf,
    // not the full struct size.
    e->timestamp_ns = bpf_ktime_get_ns();
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->sport = sk->__sk_common.skc_num;
    e->dport = sk->__sk_common.skc_dport;
    e->event_type = event_type;
    e->payload_truncated = 0;
    e->payload_len = 0;

    // Read iter_type to gate on iovec flavor. For non-ITER_IOVEC flavors
    // the __iov field is not the right way to reach the data and we'd
    // either read garbage or fail the verifier on an out-of-bounds load.
    __u8 iter_type = msg->msg_iter.iter_type;
    if (iter_type != NETSCOPE_ITER_IOVEC) {
        goto emit;
    }

    const struct iovec *iov = msg->msg_iter.__iov;
    if (!iov) {
        goto emit;
    }

    // Direct field access via the preserve_access_index iovec shadow. fentry
    // forbids bpf_probe_read_kernel (see the SRTT comment above), so we
    // dereference iov directly. The verifier classifies pointers loaded out
    // of BTF-typed kernel struct fields as PTR_TO_BTF_ID, which permits
    // direct dereference; iov came from msg->msg_iter.__iov which is itself
    // a field load against a BTF-typed msghdr argument.
    void *base = (void *)iov->iov_base;
    __u64 user_len = iov->iov_len;
    if (!base || user_len == 0) {
        goto emit;
    }

    // Clamp the read to our payload buffer size. The verifier needs the
    // size argument to bpf_probe_read_user to be a compile-time-bounded
    // value the verifier can prove fits in the destination; we use a
    // fixed constant.
    __u32 to_read = NETSCOPE_DNS_PAYLOAD_BYTES;
    if (user_len < to_read) {
        to_read = (__u32)user_len;
    } else {
        e->payload_truncated = 1;
    }

    // bpf_probe_read_user is fentry-legal (unlike bpf_probe_read which is
    // restricted to kprobe-class programs on modern kernels). It returns 0
    // on success and -EFAULT on user-page fault. The verifier requires the
    // size to be a constant or a register the verifier proved fits the
    // destination buffer; NETSCOPE_DNS_PAYLOAD_BYTES is a #define so the
    // bound is propagated through `to_read`'s upper bound below.
    //
    // We pass the fixed NETSCOPE_DNS_PAYLOAD_BYTES rather than to_read on
    // older verifiers that don't track the upper bound of to_read; reading
    // a few extra bytes that may be uninitialized is fine for DNS framing
    // (we trim with payload_len in userspace) and far safer than fighting
    // the verifier here. Trade: payload[payload_len..] may carry garbage.
    long ret = bpf_probe_read_user(e->payload, NETSCOPE_DNS_PAYLOAD_BYTES, base);
    if (ret == 0) {
        e->payload_len = (__u16)to_read;
    }
    // On ret != 0 (e.g. user page faulted out): payload_len stays 0 and
    // userspace will skip qname parsing for this event but still see the
    // 4-tuple correlation.

emit:
    // BPF_RB_NO_WAKEUP would let us batch wakeups; default flags (0) wakes
    // the userspace epoll loop opportunistically per the kernel's heuristic.
    // For our event rates (sub-1k/sec) the default is fine.
    // Always send the full struct (fixed size). Variable-length output
    // would require bpf_ringbuf_reserve/_submit with a dynamic size, which
    // the verifier accepts but complicates the staging-buffer pattern.
    // Userspace truncates to payload_len before parsing. The fixed-size
    // trade is ~270 bytes of ringbuf bandwidth per event vs ~12+payload_len
    // for the dynamic flavor; at <1k events/sec the difference is noise.
    bpf_ringbuf_output(&netscope_dns_events, e, sizeof(*e), 0);
}

// fentry on udp_sendmsg. Signature is:
//     int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// We only need sk. We deliberately ignore IPv6 (udpv6_sendmsg is a separate
// symbol); a follow-up can wire that up if we see meaningful AAAA-over-UDP6
// traffic in the homelab.
//
// Verifier notes: sk is BTF-typed via fentry, so direct field access through
// the preserve_access_index sock_common shadow declaration is legal — no
// bpf_probe_read_kernel required. We do NOT narrow via any bpf_sk_to_*
// helper because there isn't a UDPv4-flavored variant exposed to BPF (only
// bpf_skc_to_udp6_sock for v6); reading the common sock_common fields
// directly is the established pattern.
SEC("fentry/udp_sendmsg")
int BPF_PROG(record_dns_query, struct sock *sk, struct msghdr *msg)
{
    if (sk->__sk_common.skc_dport != bpf_htons(53)) {
        return 0;
    }
    struct dns_flow_key key;
    dns_build_key(&key, sk);
    __u64 now = bpf_ktime_get_ns();
    // BPF_ANY: insert-or-update. If a previous query under this 4-tuple
    // never got a response (timed out, dropped), we overwrite — the new
    // query is what we care about. The stale entry would otherwise pin
    // a slot until eviction.
    bpf_map_update_elem(&netscope_dns_query_starts, &key, &now, BPF_ANY);

    // Emit the query payload to userspace for per-domain breakdown.
    // Failure is silent: the in-kernel aggregate histogram still records
    // this query/response pair regardless.
    dns_emit_event(sk, msg, NETSCOPE_DNS_EVENT_QUERY);
    return 0;
}

// fexit on udp_recvmsg. Signature is:
//     int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
//                     int flags, int *addr_len)
// fexit gives us the return value as the trailing arg; we only treat the
// call as a real response if ret > 0 (bytes actually copied to userspace).
// A blocking call returning -EAGAIN, -ERESTARTSYS, etc. is not a response.
//
// Why fexit instead of fentry: at fentry the receive queue check hasn't
// happened yet, and we'd false-positive on every poll/select wakeup. fexit
// runs after the dequeue/copy path, so a positive ret is a real datagram.
SEC("fexit/udp_recvmsg")
int BPF_PROG(record_dns_response, struct sock *sk, struct msghdr *msg,
             unsigned long len, int flags, int *addr_len, int ret)
{
    if (ret <= 0) {
        return 0;
    }
    if (sk->__sk_common.skc_dport != bpf_htons(53)) {
        return 0;
    }
    struct dns_flow_key key;
    dns_build_key(&key, sk);
    __u64 *start = bpf_map_lookup_elem(&netscope_dns_query_starts, &key);
    if (!start) {
        // No matching query — recv on a DNS sock without a preceding send
        // (e.g. agent started mid-flow, or a non-resolver app pinning to
        // port 53). Skip silently.
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    __u64 t0 = *start;
    bpf_map_delete_elem(&netscope_dns_query_starts, &key);

    // Guard against clock skew / wraparound paranoia. Monotonic ktime should
    // never go backwards, but a defensive check costs one branch and avoids
    // a 2^64-µs spike in the overflow bucket if it ever does.
    if (now < t0) {
        return 0;
    }
    __u64 delta_us = (now - t0) / 1000;
    // Sub-microsecond samples (localhost responder, cached resolver) fall into
    // bucket 0 naturally: the log2 loop starts with bucket=0 and only advances
    // when (v >>= 1) is still non-zero, so delta_us in {0, 1} both leave
    // bucket=0. No explicit clamp needed — the value=0 case is real signal and
    // is counted, not dropped.

    // Same log2-bucketing loop as the SRTT histogram. See SRTT comment for
    // why we don't use __builtin_clz.
    __u32 bucket = 0;
    __u64 v = delta_us;
    #pragma unroll
    for (__u32 i = 1; i < NETSCOPE_DNS_NUM_BUCKETS; i++) {
        v >>= 1;
        if (v) {
            bucket = i;
        }
    }
    __u64 *cell = bpf_map_lookup_elem(&netscope_dns_latency_buckets, &bucket);
    if (cell) {
        __sync_fetch_and_add(cell, 1);
    }

    // Emit the response payload to userspace. Lets the per-domain
    // correlator close the loop on this 4-tuple even if the query event
    // dropped on the ringbuf (the response carries the qname too in the
    // echoed Question section, per RFC 1035 §4.1.1).
    dns_emit_event(sk, msg, NETSCOPE_DNS_EVENT_RESPONSE);
    return 0;
}
