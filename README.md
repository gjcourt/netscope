# netscope

eBPF-based network traffic analyzer for the Talos homelab.

A per-node DaemonSet that attaches eBPF programs to host network interfaces and key kernel hooks, aggregates kernel-level traffic and TCP-stack signals into per-CPU BPF maps, and exposes them as Prometheus metrics.

Targets signals **not** covered by Cilium/Hubble: TCP retransmits, smoothed RTT, DNS resolver-side latency, and traffic outside Cilium's view (host-network, node-to-node management plane, off-cluster LAN).

## Status

Phase 0 (feasibility spike). See [brainstorm 03-001](https://github.com/gjcourt/brainstorm/blob/main/03-homelab-automation/03-001-ebpf-based-network-traffic-analyzer.md) for the full plan.

What works today:

- Single tcx/ingress program counting bytes on a host interface; the agent discovers the IPv4 default-route interface from `/proc/net/route` at startup, with `NETSCOPE_IFACE` as an explicit operator override
- Per-CPU `BPF_MAP_TYPE_PERCPU_ARRAY` summed at scrape time
- Single Prometheus counter `netscope_rx_bytes_total{iface=...}` on `:9101/metrics`
- DaemonSet manifest pinned to one stage worker, hostNetwork, narrow caps (`BPF`, `PERFMON`, `NET_ADMIN`)
- Coexists with Cilium 1.19's tcx programs on the same hook (returns `TC_ACT_UNSPEC` so we never alter packet disposition)

## Repo layout

```text
cmd/agent/        Go entrypoint — loads the embedded BPF object and exposes /metrics
internal/bpf/     BPF C source + go:embed of the compiled .o
deploy/           Kubernetes manifests (namespace, DaemonSet)
.github/workflows GitHub Actions: build + push to ghcr.io
Dockerfile        Multi-stage: clang+Go builder → distroless runtime
Makefile          Convenience targets
```

## Build

The image is built natively on amd64 by GitHub Actions and pushed to `ghcr.io/gjcourt/netscope`. Local Docker builds from arm64 Macs hit QEMU/Go segfault issues — use CI.

```bash
# locally on an amd64 Linux host with clang + libbpf-dev installed:
make bpf      # compile internal/bpf/netscope.bpf.o
make build    # docker build (linux/amd64)
make push     # push to ghcr.io
```

## Deploy

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/daemonset.yaml
```

Pod targets a single stage node (`talos-18u-ski`) via `nodeSelector` while we validate. Remove the selector to roll across all stage nodes.

## Verify

```bash
# attachment via cilium-agent's bpftool:
kubectl -n kube-system exec ds/cilium -- bpftool net show dev eno1 | grep netscope

# scrape:
kubectl -n netscope-stage port-forward ds/netscope-agent 9101:9101 &
curl -s localhost:9101/metrics | grep netscope_
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
