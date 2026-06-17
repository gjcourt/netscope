# DNS per-domain breakdown: `bpf_probe_read#4` from a toolchain mismatch

- **Date:** 2026-06-16
- **Status:** Fix in review (not yet deploy-verified on Talos)
- **Authors:** gjcourt (with Claude Code)
- **Component:** `internal/bpf/src/netscope.bpf.c` — `dns_emit_event` (inlined into `record_dns_query` / `record_dns_response`); CI `kernel-smoke` job
- **Related PRs:** [#13](https://github.com/gjcourt/netscope/pull/13) (kernel-smoke), [#14](https://github.com/gjcourt/netscope/pull/14) (the regression)
- **Prior art:** [docs/postmortems/2026-05-10-srtt-verifier-iterations.md](2026-05-10-srtt-verifier-iterations.md)

## Summary

PR #14 ("per-domain DNS latency breakdown", merge `61d5a15`) added a ringbuf
path that reads the on-the-wire DNS payload out of the `msghdr` iovec. It
passed all of CI — including the `kernel-smoke` kernel-load job added in #13 —
and then **crashlooped on the Talos 6.18.9 nodes** at program load:

```
level=ERROR msg="netscope exiting" err="new bpf collection: program record_dns_query:
       load program: invalid argument: program of this type cannot use helper bpf_probe_read#4 (93 line(s) omitted)"
```

This is the *same verifier error string* as the SRTT #7 incident, but a
**different root cause**: not a `BPF_CORE_READ` in the source, but a generic
`bpf_probe_read#4` that the **bookworm clang-14 builder** emitted from a plain
CO-RE field dereference — while the **CI compiled the object with a newer
clang** that emits a direct load instead. CI verified an object that was never
the one we shipped.

## The offending read

In `dns_emit_event`, after gating on `iter_type == ITER_IOVEC`, the code
dereferenced the iovec to get the user buffer:

```c
const struct iovec *iov = msg->msg_iter.__iov;   // pointer loaded out of a struct field
...
void *base = (void *)iov->iov_base;              // <-- offending dereference
__u64 user_len = iov->iov_len;                   // <-- offending dereference
```

`iov` is a pointer **loaded out of another struct field** (`msg->msg_iter.__iov`),
not a top-level BTF-typed fentry argument. That distinction is everything:

- **clang ≥ 17** lowers a CO-RE field access through such a derived
  `preserve_access_index` pointer to a **direct typed load** (`r = *(u64*)(iov+off)`),
  which the verifier accepts as a `PTR_TO_BTF_ID` dereference.
- **clang-14** (Debian bookworm — what the Dockerfile builder ships) lowers the
  *same* source to a **generic `bpf_probe_read` (helper #4)** with a CO-RE
  offset relocation.

On x86_64, helper #4 is not available to tracing programs at all — see below —
so the kernel rejects the program at load.

Confirmed by disassembly. Compiling the v2 source and dumping helper IDs:

- clang-21: reads at `iov+0` / `iov+8` are direct `ldx` loads; the only
  `probe_read` helper in the program is the explicit `bpf_probe_read_user`
  (#112) for the payload. No #4.
- The bookworm clang-14 image (what `Dockerfile` uses) is the one that emits #4
  for those two reads.

## Why x86 makes #4 specifically fatal

From `kernel/trace/bpf_trace.c`, `bpf_tracing_func_proto()`:

```c
case BPF_FUNC_probe_read_user:        return &bpf_probe_read_user_proto;     // #112 — always OK
case BPF_FUNC_probe_read_kernel:      return ... &bpf_probe_read_kernel_proto; // #113 — OK (sans lockdown)
#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
case BPF_FUNC_probe_read:             return ... &bpf_probe_read_compat_proto; // #4 — gated out on x86
#endif
```

`CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE` is **not** set on x86_64 (x86
has overlapping kernel/user address ranges), so the `BPF_FUNC_probe_read` arm
is compiled out. `tracing_prog_func_proto` therefore returns NULL for helper
#4, and the verifier reports `program of this type cannot use helper
bpf_probe_read#4`. The generic `bpf_probe_read` is a legacy compatibility
shim; on x86 the kernel wants you to use the explicit `_user` / `_kernel`
flavor that names the address space.

### Correction to the SRTT postmortem

The 2026-05-10 writeup says "fentry/fexit programs forbid `bpf_probe_read*`
helpers" — *all* of them. That is an over-generalization. The kernel forbids
only the **generic `bpf_probe_read` (#4)** from tracing programs on x86 (it is
compiled out). The explicit **`bpf_probe_read_kernel` (#113)** and
**`bpf_probe_read_user` (#112)** are **permitted** from fentry/fexit. The repo
already relied on this: `dns_emit_event` calls `bpf_probe_read_user` for the
payload, and that program loads. The accurate rule is:

> Tracing programs (fentry/fexit) must not emit a **generic** `bpf_probe_read`
> (#4). `BPF_CORE_READ` is still wrong because *on old clang* it can lower to
> #4 (and it adds nothing over direct access for BTF-typed args). But the
> **explicit** `_kernel` / `_user` probe-read helpers are fine and are the
> correct tool when you must dereference a pointer that the verifier doesn't
> treat as a trusted `PTR_TO_BTF_ID` (e.g. a pointer loaded out of a struct
> field, where old clang would otherwise emit #4).

## The fix

Read the iovec fields with an **explicit `bpf_probe_read_kernel`** instead of a
direct dereference:

```c
void *base = NULL;
__u64 user_len = 0;
if (bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base) != 0)
    goto emit;
if (bpf_probe_read_kernel(&user_len, sizeof(user_len), &iov->iov_len) != 0)
    goto emit;
```

The iovec struct lives in **kernel** memory, so `_kernel` is the correct
flavor; only `iov_base`'s *target* is user memory, which we already read with
`bpf_probe_read_user`. An explicit helper call compiles to helper #113 on
*every* clang — there is no toolchain-dependent lowering — so the generic #4 is
eliminated regardless of builder image.

Re-disassembled after the fix: the two iovec reads are now `call 0x71`
(`bpf_probe_read_kernel`, #113); no `call 0x4` anywhere in the object.

The `iter_type` and `__iov` reads are kept as direct loads off the trusted
`msg` argument — those are top-level-arg field accesses, the same safe pattern
the `sk->__sk_common` and `tsk->srtt_us` reads use, and they do not lower to #4.

## Why CI missed it

The `kernel-smoke` job (added in #13, issue #10) *does* load every program into
a real 6.18 kernel — that part worked. The gap was upstream of the load: the
job compiled the BPF object with **`make bpf` on the `ubuntu-latest` runner**,
whose clang is much newer than the bookworm clang-14 the **shipped image** uses.
The newer clang emitted a direct load (no #4), so the object the smoke loaded
was verifier-clean — but it was **not the object that ships**. The Dockerfile
builds the real `.o` with bookworm clang-14, which emits #4.

In short: the smoke had kernel fidelity but not **toolchain fidelity**. CO-RE
lowering is clang-version-dependent, so "compiles and loads here" only
generalizes to production if "here" uses the production compiler.

## What we changed

- **Code:** `dns_emit_event` reads `iov->iov_base` / `iov->iov_len` via
  `bpf_probe_read_kernel`. Comments corrected (the old comment claimed the
  direct dereference was required and safe; it was the bug).
- **CI:** `kernel-smoke` now compiles the BPF object **inside
  `golang:1.23-bookworm`** (the Dockerfile builder image) rather than with the
  runner's clang, so the smoke loads byte-for-byte what we deploy. Kept the
  6.18 vmtest kernel (matches Talos 6.18.x and rejects #4).
- **Docs:** this postmortem, and a correction to the SRTT writeup's
  over-broad "no `bpf_probe_read*`" rule.

## Validation status — honest accounting

- **Verified locally:** the v2 source compiles clean under clang (`-Werror`);
  disassembly shows the offending reads were direct `ldx` (pre-fix) and are now
  `bpf_probe_read_kernel`/#113 (post-fix); **no `bpf_probe_read#4` in the
  object** after the fix. Kernel-source analysis confirms #4 is compiled out
  for tracing programs on x86 while #112/#113 are exposed.
- **NOT yet verified:** loading the fixed object on the real **6.18.9-talos**
  kernel. That is the deploy-verify step the human runs after merge. Do not
  read this postmortem as "confirmed fixed on Talos" — it is "verifier hazard
  removed at the bytecode level; awaiting on-cluster load."
- **CI clang-14 reproduction** of the *original* #4 (to prove the smoke now
  catches it) was reasoned from the kernel source + the source comments'
  own reference to the bookworm LLVM-14 backend, not reproduced on this
  workstation (no bookworm/clang-14 available locally). The hardened
  `kernel-smoke` job will exercise the real reproduction in CI.

## Lessons / heuristics

- **CI must compile BPF with the production compiler.** CO-RE lowering is
  clang-version-dependent; "loads in CI" only transfers to production when CI
  used the shipping toolchain. Build the `.o` in the same image the Dockerfile
  uses.
- **The forbidden helper is the generic `bpf_probe_read#4`, not all probe
  reads.** `bpf_probe_read_kernel`/`_user` are legal from fentry/fexit and are
  the right tool for dereferencing a pointer the verifier won't treat as a
  trusted `PTR_TO_BTF_ID` (e.g. a pointer loaded out of a struct field).
- **A pointer loaded out of a struct field is not the same as a top-level
  BTF-typed argument.** Direct field access off an fentry arg is safe; chasing
  a *derived* pointer can lower to #4 on old clang. When in doubt, read it
  explicitly with the named-address-space helper.
- **Same verifier string can have different root causes.** "cannot use helper
  bpf_probe_read#4" was a `BPF_CORE_READ` in #7 and a clang-14 CO-RE-deref
  lowering in #14. Read the *source* the compiler produced, not just the error.
