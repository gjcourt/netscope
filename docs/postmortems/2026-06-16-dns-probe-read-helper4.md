# DNS per-domain breakdown: `bpf_probe_read#4` from kernel lockdown

- **Date:** 2026-06-16
- **Status:** Fixed and **deploy-verified on a real Talos 6.18.9 node** (see "Validation").
- **Authors:** gjcourt (with Claude Code)
- **Component:** `internal/bpf/src/netscope.bpf.c` — `dns_emit_event` (inlined into `record_dns_query` / `record_dns_response`); CI `kernel-smoke` job
- **Related PRs:** [#13](https://github.com/gjcourt/netscope/pull/13) (kernel-smoke), [#14](https://github.com/gjcourt/netscope/pull/14) (the regression), [#15](https://github.com/gjcourt/netscope/pull/15) (a fix attempt that did NOT work)
- **Prior art:** [docs/postmortems/2026-05-10-srtt-verifier-iterations.md](2026-05-10-srtt-verifier-iterations.md)

## Summary

PR #14 ("per-domain DNS latency breakdown", merge `61d5a15`) added a ringbuf
path that reads the on-the-wire DNS payload out of the `msghdr` iovec. It
passed all of CI — including the `kernel-smoke` kernel-load job — and then
**crashlooped on the Talos 6.18.9 nodes** at program load:

```
program record_dns_query: load program: invalid argument:
  program of this type cannot use helper bpf_probe_read#4 (89 line(s) omitted)
```

PR #15 then "fixed" it by switching the iovec dereference from a direct field
access to an explicit `bpf_probe_read_kernel`, confirmed the disassembly showed
no `call 4`, watched `kernel-smoke` go green, and merged (`7f774e4`). **It
crashlooped again with the identical error.** This postmortem is the
ground-truth investigation that found the real cause.

## Real root cause: kernel lockdown, not the toolchain

The earlier theory — "bookworm clang-14 lowers a CO-RE field deref to the
generic `bpf_probe_read#4` while CI's newer clang emits a direct load" — was
**wrong**. It was disproven directly:

1. Compiling the failing source with the **actual shipping toolchain**
   (`golang:1.23-bookworm`, clang-14.0.6) produces an object whose iovec reads
   are `call 113` (`bpf_probe_read_kernel`) and `call 112`
   (`bpf_probe_read_user`) — **there is no `call 4` in the object at all.** So
   "clang-14 emits #4" is false.

2. Loading that exact object on a **real Talos 6.18.9 node** (via a privileged
   pod that mounts `/sys/kernel/btf`) still fails — and the verifier log shows
   the rejection is on the `bpf_probe_read_kernel` (#113) call:

   ```
   ; if (bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base) != 0) {  @ netscope.bpf.c:506
   53: (b7) r2 = 8
   54: (bf) r3 = r8
   55: (85) call bpf_probe_read#4
   program of this type cannot use helper bpf_probe_read#4
   ```

   The kernel prints `bpf_probe_read#4` for **any** probe_read variant — the
   "#4" is the canonical name of the rejected proto, not the helper you called.

3. A one-line fentry program whose *only* helper is `bpf_probe_read_kernel`
   (#113) is rejected on the real node. So is one whose only helper is
   `bpf_probe_read_user` (#112). On this kernel, **no probe_read variant is
   available to tracing (fentry/fexit) programs.**

### The gate is `lockdown=confidentiality`

From `kernel/trace/bpf_trace.c`, the proto for tracing programs is gated:

```c
case BPF_FUNC_probe_read:
    return security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0
           ? NULL : &bpf_probe_read_compat_proto;
```

(The `_user`/`_kernel` flavors route through the same lockdown gate.) Talos
boots **every node** with kernel lockdown in *confidentiality* mode — visible
on the cluster:

```
$ cat /proc/cmdline
talos.platform=metal ... selinux=1 module.sig_enforce=1 lockdown=confidentiality
$ cat /sys/kernel/security/lockdown
none integrity [confidentiality]
```

Under `lockdown=confidentiality`, `security_locked_down(LOCKDOWN_BPF_READ_KERNEL)`
returns `< 0`, the proto is `NULL`, and the verifier rejects the program with
`program of this type cannot use helper bpf_probe_read#4`. This has **nothing
to do with the compiler** and nothing to do with which `_user`/`_kernel`
variant you pick — lockdown removes them all.

For completeness: `CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE` **is** set on
the Talos x86_64 kernel (`=y`), the opposite of what the earlier postmortem
claimed. It is not the discriminating factor here; lockdown is.

## Why both CI and a bare QEMU VM were false-greens

A vmtest VM — and a bare `qemu-system-x86_64` boot of *either* the fedora38
vmtest kernel *or* the actual Talos kernel image — boots **without lockdown**.
With lockdown off, the probe_read proto is returned and the failing object
**loads fine** (`CISMOKE_EXIT=0`). That is exactly the false green:
`kernel-smoke` had kernel-version fidelity but not **boot-parameter fidelity**.

This was confirmed by experiment (QEMU + a busybox initramfs running cismoke):

| Kernel            | `lockdown=confidentiality`? | Pre-fix object | Post-fix object |
|-------------------|-----------------------------|----------------|-----------------|
| fedora38 (vmtest) | no  (CI default)            | **LOAD ok** ❌ | LOAD ok         |
| fedora38 (vmtest) | yes                         | rejected #4 ✅ | **LOAD ok** ✅  |
| 6.18.9-talos      | no                          | LOAD ok ❌     | LOAD ok         |
| 6.18.9-talos      | yes                         | rejected #4 ✅ | LOAD ok         |
| 6.18.9-talos (real node) | yes (Talos boots it) | rejected #4 ✅ | **LOAD ok** ✅  |

The bottom row is the acceptance test: the real cluster kernel.

## The fix

There is **no probe_read recipe** that loads under lockdown, so the per-domain
payload feature (which fundamentally needs to read the iovec in kernel memory
and the DNS payload in user memory) **cannot run as a tracing program on
Talos.** We remove it:

- Deleted `dns_emit_event`, the `netscope_dns_events` ringbuf, the
  `dns_event` struct, the per-CPU scratch map, and the `struct iovec` /
  `struct iov_iter` / `struct msghdr` shadow declarations.
- Removed the two `dns_emit_event(...)` calls from `record_dns_query` and
  `record_dns_response`. The `struct msghdr *msg` argument stays in the
  `BPF_PROG` signatures (it is the real 2nd arg of `udp_sendmsg`/`udp_recvmsg`)
  but is no longer dereferenced.
- Removed the userspace consumer (`cmd/agent/dns.go`, the
  `dnsBreakdownCollector` and its ringbuf reader) and the `internal/dnsparse`
  package, plus the ringbuf wiring in `cmd/agent/main.go`.

What remains is the **in-kernel aggregate DNS latency histogram** (the original
feature from PR #11): `record_dns_query`/`record_dns_response` read the
4-tuple via **direct BTF-typed field loads** off the trusted `sk` fentry
argument (`sk->__sk_common.skc_*`) and use only map ops (`lookup`/`update`/
`delete`), `bpf_ktime_get_ns`, and `bpf_skc_to_tcp_sock`. None of those touch
probe_read, so they load cleanly under lockdown. The
`netscope_dns_query_microseconds` metric is unchanged; only the
`_by_suffix` per-domain breakdown is gone.

The correct general rule for a tracing program on a hardened kernel: **read
only through trusted `PTR_TO_BTF_ID` arguments with direct field access.** If a
value can only be reached via probe_read (a pointer loaded out of a struct
field, or user memory), it is not obtainable from fentry/fexit under
`lockdown=confidentiality` — move that work to userspace via data you *can*
emit, or attach a different program type.

## The CI fix

`kernel-smoke` now boots the vmtest VM with `kernel_args: lockdown=confidentiality`.
That single argument reproduces the Talos gate on the stock fedora38 kernel —
no need to ship the Talos kernel image (which also lacks the 9p/virtio-builtin
config vmtest needs to mount the workspace). Verified: with the arg present the
pre-fix object is rejected with `bpf_probe_read#4` and the post-fix object
loads and attaches; without it both pass. We keep compiling the `.o` with the
bookworm clang-14 builder image for byte-for-byte fidelity (good hygiene, even
though it was not the cause here).

## Validation status — honest accounting

- **Verified on a real Talos 6.18.9 node** (`talos-lmh-kyf`, via a privileged
  pod in `netscope-stage` mounting `/sys/kernel/btf`): the fixed object's
  `cismoke` reports `LOAD: ok (5 programs verified)` and all five programs —
  including `record_dns_query` and `record_dns_response` — `ATTACH ... ok`,
  exit 0. The pre-fix object on the same node fails with the production
  `bpf_probe_read#4` error.
- **CI catch verified** by QEMU experiment (table above): the pre-fix object is
  rejected, and the post-fix object accepted, on the fedora38 kernel **only
  when booted with `lockdown=confidentiality`** — the arg the CI job now sets.

## Lessons / heuristics

- **Boot-parameter fidelity matters as much as kernel-version fidelity.** A
  smoke that boots the right kernel version with the wrong *command line* is
  still a false green. Talos's `lockdown=confidentiality` changes which BPF
  helpers exist; reproduce it.
- **`bpf_probe_read#4` in the verifier log names the rejected proto, not the
  helper you called.** A `bpf_probe_read_kernel` (#113) call is reported as
  `#4` when the lockdown gate NULLs the proto. Don't infer the offending
  source line from the helper number — read the `; ... @ file:line` comment in
  the verifier log (here it pointed straight at the `bpf_probe_read_kernel`
  line) and disassemble the actual object.
- **Switching `bpf_probe_read` → `bpf_probe_read_kernel` is not a fix on a
  locked-down kernel.** Lockdown removes the whole family. The only fixes are:
  read via trusted BTF args, or don't read it from a tracing program.
- **Verify the merged fix on the real target before closing.** PR #15 trusted a
  clean disassembly and a green CI and shipped a non-fix. The acceptance test is
  loading on the actual cluster kernel, not CI.
- **Distrust a postmortem's root cause until it is reproduced.** The first draft
  of this very document asserted a toolchain cause that the evidence later
  contradicted on all four of its load-bearing claims.
