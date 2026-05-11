# SRTT histogram: three iterations through the BPF verifier

- **Date:** 2026-05-10 / 2026-05-11
- **Status:** Resolved
- **Authors:** gjcourt (with Claude Code)
- **Component:** `internal/bpf/src/netscope.bpf.c` — `record_tcp_srtt` fentry program
- **Related PRs:** [#7](https://github.com/gjcourt/netscope/pull/7), [#8](https://github.com/gjcourt/netscope/pull/8), [#9](https://github.com/gjcourt/netscope/pull/9), [#11](https://github.com/gjcourt/netscope/pull/11)
- **Tracking issue:** [#10](https://github.com/gjcourt/netscope/issues/10)

## Summary

Adding the TCP SRTT histogram (Phase 2 metric #2 — an fentry program on `tcp_rcv_established` that reads `tcp_sock->srtt_us` into a per-CPU log2 histogram) took three merged PRs to land. CI passed on all three because the build pipeline compiles the BPF object but never loads it into a kernel; both failure modes were verifier rejections at `bpf_object__load()` time on the target node. The root cause class was the same in both bad iterations: misunderstanding which kinds of memory access the BPF verifier permits from an fentry program, distinct from what the C type system says is legal.

## Timeline

All times UTC.

| When | PR | Change | Outcome |
|---|---|---|---|
| 2026-05-10 23:07 | [#7](https://github.com/gjcourt/netscope/pull/7) opened | `BPF_CORE_READ((struct tcp_sock *)sk, srtt_us)` | CI green, merged 23:16 |
| 2026-05-10 ~23:20 | deploy on Talos node | — | Agent crashloops. Verifier log: `program of this type cannot use helper bpf_probe_read#4`. fentry programs are not permitted to call `bpf_probe_read*`, and `BPF_CORE_READ` expands to exactly that. |
| 2026-05-10 23:27 | [#8](https://github.com/gjcourt/netscope/pull/8) opened | direct field access: `((struct tcp_sock *)sk)->srtt_us` with a `preserve_access_index` shim struct | CI green, merged 23:34 |
| 2026-05-10 ~23:40 | deploy | — | Agent crashloops. Verifier log: `permission denied: access beyond struct sock at off 1672 size 4`. The verifier sees `sk` as `struct sock *` (~1232 bytes on this kernel) and refuses the load at offset ~1672. A C cast to `struct tcp_sock *` does not change the verifier's view of the pointer. |
| 2026-05-11 00:39 | [#9](https://github.com/gjcourt/netscope/pull/9) opened | `struct tcp_sock *tsk = bpf_skc_to_tcp_sock(sk); if (!tsk) return 0; tsk->srtt_us` | CI green, merged 00:47 |
| 2026-05-11 ~00:50 | deploy | — | Verifier accepts. SRTT histogram flowing. Confirmed in Prometheus within one scrape interval. |
| 2026-05-11 01:08 | [#11](https://github.com/gjcourt/netscope/pull/11) opened | DNS query latency histogram (separate fentry program) | First-try pass — applied lessons from #7/#8/#9 up front. |

Total elapsed: ~1h40m from #7 open to #9 deployed. Three production deploys; no data loss; the failures were contained to the netscope DaemonSet crashlooping.

## Root causes

Two distinct verifier rules tripped us up. They look similar from the outside (both manifest as "the program won't load") but they are independent and have to be understood separately.

### 1. fentry/fexit programs forbid `bpf_probe_read*` helpers

fentry and fexit attach at function-entry/exit BTF trampolines. They get their arguments as BTF-typed pointers with direct memory access — the verifier proves the loads safe statically using the function's BTF signature. Because of that, the kernel deliberately forbids `bpf_probe_read`, `bpf_probe_read_kernel`, and friends from these program types. The helper would be redundant at best and would erase the BTF-typed access guarantees at worst.

The mental model that worked for us: fentry args are like "fat pointers" that carry their type and size with them at verification time. A `probe_read` would be the verifier equivalent of laundering through a `void *` and reading raw bytes — exactly what BTF-typed access was added to avoid.

`BPF_CORE_READ` and `BPF_CORE_READ_INTO` are macros that expand to a chain of `bpf_probe_read_kernel` calls with CO-RE offset relocations baked in. They are the right tool for kprobes, tracepoints, and raw_tracepoints — program types that get untyped registers. **They are the wrong tool for fentry/fexit.** From fentry, you read fields off the BTF-typed argument directly:

```c
// WRONG in fentry — expands to bpf_probe_read_kernel:
__u32 srtt = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);

// RIGHT in fentry — direct typed load (modulo rule #2 below):
__u32 srtt = tsk->srtt_us;
```

### 2. The verifier does not follow C casts between kernel struct types

`struct tcp_sock` embeds `struct inet_connection_sock` which embeds `struct inet_sock` which embeds `struct sock` as its first member. In memory, a `struct sock *` pointing at a real TCP socket *is* in fact also a valid `struct tcp_sock *` — `srtt_us` lives at some offset past the end of the embedded `struct sock`. C lets you cast freely between these and the load is correct at runtime.

The verifier does not see it that way. It tracks each pointer's BTF type. A `struct sock *` argument is bounded by `sizeof(struct sock)` (~1232 bytes on Talos 6.18.9). Any load past that — `srtt_us` at offset ~1672 — gets rejected with `access beyond struct sock at off N size M`. A C-level cast `(struct tcp_sock *)sk` does not retype the pointer in the verifier's eyes. The verifier has no way to know that the runtime pointer is genuinely a fullsock and not, say, a request_sock or a timewait_sock.

The escape hatch is `bpf_skc_to_tcp_sock(sk)`. It's a kernel helper whose BTF signature returns `struct tcp_sock *`. At runtime it checks the socket's state and returns NULL if `sk` is not a fully-established TCP stream socket — request socks during the SYN/SYN-ACK handshake, timewait socks, non-TCP socks, etc. The verifier sees the returned pointer as genuinely `tcp_sock`-typed and allows the field load. We're required to handle the NULL path even though, from `tcp_rcv_established`, it's essentially unreachable (tcp_rcv_established is only called on established fullsocks).

Why doesn't the verifier just trust the C cast? Because BPF programs are loaded by unprivileged or semi-privileged callers, and a cast that the verifier can't prove safe is indistinguishable from an attacker forging a pointer. The BTF type system is the verifier's only ground truth about what a pointer points at; the C type system is unobservable to it.

```c
// Final pattern, from netscope.bpf.c:
SEC("fentry/tcp_rcv_established")
int BPF_PROG(record_tcp_srtt, struct sock *sk)
{
    struct tcp_sock *tsk = bpf_skc_to_tcp_sock(sk);
    if (!tsk) return 0;
    __u32 srtt_us = tsk->srtt_us;
    ...
}
```

The sibling helpers are worth remembering: `bpf_skc_to_udp6_sock`, `bpf_skc_to_unix_sock`, `bpf_skc_to_mptcp_sock`, `bpf_sk_fullsock`. Same pattern: hand the verifier a typed pointer, get to use direct field access.

## Why CI missed it

The repo's CI compiles the BPF object (`make build`), runs the Go test suite (no BPF load), builds and pushes the container image. None of these steps loads the .o into a running kernel. Verifier rejection happens at `bpf_object__load()` time, which is only exercised when the DaemonSet actually starts on a node.

The asymmetry is significant: clang and libbpf are tolerant of programs that the verifier will reject. The .o builds, the image builds, the pod starts, and only then does `cilium/ebpf` call `BPF_PROG_LOAD` and get back `-EACCES` or `-EINVAL` with a verifier log. CI green means nothing about loadability.

This is structurally similar to type-checking vs. runtime: clang is the type-checker and the verifier is the actual runtime that decides whether your program is allowed to exist. We were shipping with only the type-checker green. The fix is to add a runtime gate — load the program against a kernel during CI — not to ask developers to read more carefully.

Tracked at [#10](https://github.com/gjcourt/netscope/issues/10): add a kernel-load smoke step (run the agent against a kernel — KIND with a recent kernel, or a Talos-flavored VM — and assert all `SEC()`s load). The smoke doesn't need to be a full integration test; just `bpf_object__load()` returning 0 on every program is enough to catch both failure modes from this incident. Until that lands, the first signal that a BPF change is bad will continue to be a crashlooping pod after deploy, and the operational workaround is: deploy BPF changes single-node first.

## What we changed

- **Code:** `record_tcp_srtt` uses `bpf_skc_to_tcp_sock` for narrowing, with the NULL-handling boilerplate. The shim `struct tcp_sock { __u32 srtt_us; } __attribute__((preserve_access_index));` lets us avoid pulling in `vmlinux.h` while still getting CO-RE offset relocation.
- **Comments in `internal/bpf/src/netscope.bpf.c`:** a block above `record_tcp_srtt` documents both traps explicitly, naming `bpf_probe_read`, `BPF_CORE_READ`, and the `(struct tcp_sock *)sk` cast as anti-patterns for fentry. The intent is that anyone touching this file or adding a new fentry program reads the rules before writing the program.
- **PR [#11](https://github.com/gjcourt/netscope/pull/11) (DNS query latency):** a separate fentry program on `udp_recvmsg`/`udp_sendmsg`. It hit none of these traps on first try because the comment block in the same file documented the pattern. This is the load-bearing evidence that the writeup pays for itself.

## Action items

- **Open — [#10](https://github.com/gjcourt/netscope/issues/10):** kernel-load CI smoke test. Should fail fast on any program that the verifier rejects, before merge.
- **Closed:** SRTT histogram is deployed and stable. Comment trail in `internal/bpf/src/netscope.bpf.c` documents both traps.
- **Closed:** This postmortem.

## Lessons / heuristics

- **fentry/fexit means BTF-typed direct access. No `bpf_probe_read*`.** Use it for kprobes/tracepoints/raw_tracepoints, not for fentry/fexit. `BPF_CORE_READ` is a `bpf_probe_read*` macro and inherits the same constraint.
- **When reaching into a sub-type of a kernel struct from a BTF-typed program, always reach for a verifier-blessed narrowing helper first.** `bpf_skc_to_*`, `bpf_sk_fullsock`, `bpf_dynptr_*`, `bpf_rdonly_cast`. A C cast is not a narrowing helper.
- **CI green is not loadability.** Until [#10](https://github.com/gjcourt/netscope/issues/10) lands, assume any BPF code change might be a deploy-time failure. Roll out behind a single-node canary before pushing the DaemonSet.
- **Read the verifier log line one.** "helper call is not allowed in probe" and "access beyond struct X at off N" are different problems with different fixes. Don't fix-by-pattern-matching.
- **Document the trap inline.** A comment block above the program is cheaper than a postmortem — PR #11 confirmed this empirically.

## References

- PR [#7](https://github.com/gjcourt/netscope/pull/7) — initial SRTT with `BPF_CORE_READ`
- PR [#8](https://github.com/gjcourt/netscope/pull/8) — switch to direct field access
- PR [#9](https://github.com/gjcourt/netscope/pull/9) — switch to `bpf_skc_to_tcp_sock`
- PR [#11](https://github.com/gjcourt/netscope/pull/11) — DNS query latency (clean first-try)
- Issue [#10](https://github.com/gjcourt/netscope/issues/10) — kernel-load CI smoke
- Project plan: [brainstorm/03-001-ebpf-based-network-traffic-analyzer](https://github.com/gjcourt/brainstorm/blob/main/03-homelab-automation/03-001-ebpf-based-network-traffic-analyzer.md)
- Kernel docs:
  - [BPF program types: fentry/fexit](https://docs.kernel.org/bpf/libbpf/program_types.html) and `bpf-helpers(7)`
  - [`bpf_skc_to_tcp_sock` and siblings](https://docs.kernel.org/bpf/helpers.html) — the "type cast" helpers section
  - [libbpf CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) — Andrii Nakryiko's reference, especially the section on when `BPF_CORE_READ` is and isn't appropriate
