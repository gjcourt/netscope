<!-- readme-type: exporter -->
# netscope

eBPF-based network traffic analyzer for the Talos homelab, exposing kernel-level TCP/DNS metrics to Prometheus

Cilium's Hubble reports what crosses the pod network, but not host-network traffic, node-to-node control-plane paths outside the mesh, or *why* a connection is slow rather than that it happened. netscope is a per-node DaemonSet that attaches eBPF programs to a host interface and a handful of kernel TCP/UDP functions, aggregates the results in per-CPU BPF maps, and exposes them as Prometheus metrics: TCP retransmits, smoothed RTT, DNS resolver-side latency, and byte counts on interfaces Cilium doesn't see.

**Status:** running in the homelab staging environment (`netscope-stage`, all 4 nodes) since 2026-05-10, scraped by Prometheus every 30s with alerting and a Grafana dashboard; there is no separate production environment for this app. See the [homelab runbook](https://github.com/gjcourt/homelab/blob/master/docs/operations/apps/netscope.md).

## Why

Cilium/Hubble's visibility stops at the pod network: it can't say whether a node's TCP stack is retransmitting more than its peers, whether round-trip time is drifting upward, or whether a latency spike is actually DNS resolution taking too long, and it never sees host-network or node-to-node management-plane traffic at all. netscope answers those questions from the kernel's own view of the TCP/UDP stack, independent of whatever CNI dataplane sits in front of it.

## Metrics

Served on `:9101/metrics` (Prometheus text format); `:9101/healthz` returns 200 unconditionally.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `netscope_rx_bytes_total` | counter | `iface` | Bytes received at `tcx/ingress` on the resolved interface |
| `netscope_tcp_retransmits_total` | counter | none | Calls to `tcp_retransmit_skb` (one per retransmitted segment) |
| `netscope_tcp_srtt_microseconds` | histogram | none | TCP smoothed RTT samples, recorded on `tcp_rcv_established` |
| `netscope_dns_query_microseconds` | histogram | none | DNS query-to-response latency, observed at `udp_sendmsg`/`udp_recvmsg` |

Notes:

- `netscope_tcp_retransmits_total` carries no `iface` label: retransmits are a per-socket event and the egress NIC can differ from the RX side. Distinguish by node instead (e.g. a `nodename` label promoted by your scrape config).
- Both histograms bucket on powers of two, computed in-kernel, and report `_sum` as `0` — it isn't tracked yet, so `_bucket`/`_count` work but `histogram_quantile` on `_sum`-derived averages won't.
- DNS latency only sees *connected* UDP sockets (systemd-resolved, Go's `net.Resolver`); classic `res_send`/`sendto` resolvers aren't matched.

The query that answers the Why — TCP RTT drift, cluster-wide p95:

```promql
histogram_quantile(0.95, sum(rate(netscope_tcp_srtt_microseconds_bucket[5m])) by (le))
```

## Quick start

Needs: a Kubernetes cluster with a BTF-enabled kernel (`CONFIG_DEBUG_INFO_BTF=y`) and Helm 3.

```bash
git clone https://github.com/gjcourt/netscope && cd netscope
helm install netscope deploy/helm/netscope --namespace netscope --create-namespace
kubectl -n netscope port-forward ds/netscope-agent 9101:9101 &
curl -s localhost:9101/metrics | grep ^netscope_
```

## Configuration

The agent takes no flags. The only input is one environment variable:

| Variable | Default | Meaning |
|---|---|---|
| `NETSCOPE_IFACE` | (unset) | Interface to attach `tcx/ingress` to. If unset, the agent discovers the IPv4 default-route interface from `/proc/net/route` at startup and exits with an error if none is found — there is no static fallback. |

The listen address (`:9101`) is not currently configurable; it's a constant in `cmd/agent/main.go` and matches `EXPOSE 9101` in the Dockerfile.

Deploying via the Helm chart exposes the rest of the knobs that matter operationally — `iface`, `nodeSelector`/`tolerations`, `priorityClassName`, `capabilities`, `metrics.port`/`metrics.hostPort`, resource requests/limits, and probe timing. See [`deploy/helm/netscope/values.yaml`](deploy/helm/netscope/values.yaml) for the full set and their defaults.

## How it works

netscope discovers the node's IPv4 default-route interface from `/proc/net/route` at startup (unless `NETSCOPE_IFACE` overrides it), attaches a `tcx/ingress` program that counts bytes without altering packet disposition (`TC_ACT_UNSPEC`, so it coexists with Cilium's own tcx programs on the same hook), and attaches `fentry`/`fexit` programs on `tcp_retransmit_skb`, `tcp_rcv_established`, and the `udp_sendmsg`/`udp_recvmsg` pair to observe retransmits, smoothed RTT, and DNS latency. Results land in per-CPU `BPF_MAP_TYPE_PERCPU_ARRAY` maps that are summed at scrape time and served in Prometheus text format. See [`docs/architecture.md`](docs/architecture.md) for the full userspace/kernel split and map inventory, and [`docs/postmortems/`](docs/postmortems) for the verifier issues that shaped the BPF code.

## Development

Requires Go 1.23 and, for anything that touches the BPF object, `clang` + `libbpf-dev` (the Go build embeds `internal/bpf/netscope.bpf.o` via `go:embed`, so `go build`/`go test` fail until it exists).

```bash
make bpf      # compile internal/bpf/src/netscope.bpf.c -> internal/bpf/netscope.bpf.o
make test     # go test ./...
make cismoke  # build the kernel-load smoke binary (bin/cismoke)
make tidy     # go mod tidy
make helm-lint      # helm lint deploy/helm/netscope
make helm-template  # render the chart with default values
```

The image is amd64-only: the BPF object is compiled with `-D__TARGET_ARCH_x86`. Local Docker builds from arm64 hosts hit QEMU/Go segfaults, so CI (`.github/workflows/build.yml`) is the build path — it pushes to `ghcr.io/gjcourt/netscope` on push to `main`.

CI runs two jobs on every PR: `lint` (compile the BPF object, `gofmt`, `go vet`, `go test`, a `go mod tidy` diff, `helm lint` + `helm template`) and `kernel-smoke`, which loads the compiled `.o` and attempts every attach (`cmd/cismoke`) against a real 6.18 kernel in a VM booted with `lockdown=confidentiality`. That boot flag reproduces a Talos-specific gate that rejects the `bpf_probe_read` helper family in tracing programs — compile-only checks can't see it, and it's caused two real regressions (see `docs/postmortems/`). Don't weaken it. See [`AGENTS.md`](AGENTS.md) for repo conventions.

## Deployment

netscope runs as a DaemonSet in the `netscope-stage` namespace on every cluster node, deployed via Flux/Kustomize from [`gjcourt/homelab`](https://github.com/gjcourt/homelab); the image is pinned by tag + digest in [`apps/base/netscope/daemonset.yaml`](https://github.com/gjcourt/homelab/blob/master/apps/base/netscope/daemonset.yaml). See the [homelab runbook](https://github.com/gjcourt/homelab/blob/master/docs/operations/apps/netscope.md) for architecture, alerting, and troubleshooting.

## License

Apache License 2.0 — see [LICENSE](LICENSE). `internal/bpf/src/netscope.bpf.c` is the one exception, licensed GPL-2.0 (see the SPDX header in that file), as required by the GPL-only BPF helpers and kernel symbols it uses.
