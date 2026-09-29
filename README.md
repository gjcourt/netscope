# netscope

netscope is a per-node eBPF exporter for the Talos homelab cluster. It attaches
BPF programs to a host NIC and to a handful of kernel TCP/UDP functions,
aggregates the results in per-CPU BPF maps, and exposes them as Prometheus
metrics on `:9101`. It exists to cover signals that Cilium/Hubble doesn't:
TCP retransmits, smoothed RTT, DNS resolver-side latency, and traffic on
interfaces outside Cilium's pod-netns view (host-network, node-to-node
management plane, off-cluster LAN).

For the full design — the userspace/kernel split, the BPF program and map
inventory, the end-to-end scrape flow, and the reasoning behind each design
decision — see [`docs/architecture.md`](docs/architecture.md). The
[`docs/postmortems/`](docs/postmortems) directory has the incident writeups
behind some of the less obvious choices in the BPF code.

## Metrics

Served on `:9101/metrics` (Prometheus text format); `:9101/healthz` returns
200 unconditionally.

| Metric | Type | Labels | Source hook |
|---|---|---|---|
| `netscope_rx_bytes_total` | counter | `iface` | `tcx/ingress` on the resolved interface |
| `netscope_tcp_retransmits_total` | counter | none | `fentry/tcp_retransmit_skb` |
| `netscope_tcp_srtt_microseconds` | histogram | none | `fentry/tcp_rcv_established` |
| `netscope_dns_query_microseconds` | histogram | none | `fentry/udp_sendmsg` + `fexit/udp_recvmsg` |

Notes:

- `netscope_tcp_retransmits_total` carries no `iface` label: retransmits are a
  per-socket event and the egress NIC can differ from the RX side. Distinguish
  by node instead (e.g. a `nodename` label promoted by your scrape config).
- Both histograms bucket on powers of two, computed in-kernel, and report
  `_sum` as `0` — it isn't tracked yet, so `_bucket`/`_count` work but
  `histogram_quantile` on `_sum`-derived averages won't.
- DNS latency only sees *connected* UDP sockets (systemd-resolved, Go's
  `net.Resolver`); classic `res_send`/`sendto` resolvers aren't matched.

## Configuration

The agent takes no flags. The only input is one environment variable:

| Variable | Default | Purpose |
|---|---|---|
| `NETSCOPE_IFACE` | (unset) | Interface to attach `tcx/ingress` to. If unset, the agent discovers the IPv4 default-route interface from `/proc/net/route` at startup and exits with an error if none is found — there is no static fallback. |

The listen address (`:9101`) is not currently configurable; it's a constant in
`cmd/agent/main.go` and matches `EXPOSE 9101` in the Dockerfile.

Deploying via the Helm chart exposes the rest of the knobs that matter
operationally — `iface`, `nodeSelector`/`tolerations`, `priorityClassName`,
`capabilities`, `metrics.port`/`metrics.hostPort`, resource requests/limits,
and probe timing. See [`deploy/helm/netscope/values.yaml`](deploy/helm/netscope/values.yaml)
for the full set and their defaults.

## Running / Deployment

netscope needs `hostNetwork: true`, a BTF-enabled kernel (`CONFIG_DEBUG_INFO_BTF=y`),
and `/sys/kernel/btf` + `/sys/fs/bpf` mounted from the host. It runs as
`runAsUser: 0` (not `privileged`) with a narrow capability set: `BPF`,
`PERFMON`, `NET_ADMIN`, and `SYS_ADMIN` (the last is needed at startup to
enumerate loaded BPF programs so netscope can anchor its `tcx` attach ahead of
Cilium's ingress program).

**Helm chart** (parameterized, recommended for anything beyond a single pinned node):

```bash
helm install netscope deploy/helm/netscope --namespace netscope --create-namespace
```

**Plain manifests** (pinned to one node by hostname, image tag `dev` — useful
for a quick local trial, not a template for production):

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/daemonset.yaml
```

Both are standalone equivalents of what actually runs in the homelab: there,
netscope is deployed via Flux/Kustomize from a separate GitOps repo, on all
cluster nodes, with a digest-pinned image and a `ServiceMonitor` scraping
every 30s. See the "Deployment" section of `docs/architecture.md` for that
layout.

**Verify it's attached and scraping** (using the plain-manifest install, namespace
`netscope-stage`, DaemonSet `netscope-agent`; adjust names for a Helm release):

```bash
# confirm the tcx program is attached (via cilium-agent's bpftool):
kubectl -n kube-system exec ds/cilium -- bpftool net show dev eno1 | grep netscope

# scrape:
kubectl -n netscope-stage port-forward ds/netscope-agent 9101:9101 &
curl -s localhost:9101/metrics | grep netscope_
```

## Development

Requires Go 1.23 and, for anything that touches the BPF object, `clang` +
`libbpf-dev` (the Go build embeds `internal/bpf/netscope.bpf.o` via
`go:embed`, so `go build`/`go test` fail until it exists).

```bash
make bpf      # compile internal/bpf/src/netscope.bpf.c -> internal/bpf/netscope.bpf.o
make test     # go test ./...
make cismoke  # build the kernel-load smoke binary (bin/cismoke)
make build    # docker buildx build (linux/amd64 only — see below)
make tidy     # go mod tidy
make helm-lint      # helm lint deploy/helm/netscope
make helm-template  # render the chart with default values
```

The image is amd64-only: the BPF object is compiled with `-D__TARGET_ARCH_x86`.
Local Docker builds from arm64 hosts hit QEMU/Go segfaults, so CI
(`.github/workflows/build.yml`) is the build path — it pushes to
`ghcr.io/gjcourt/netscope` on push to `main`.

CI runs two jobs on every PR: `lint` (compile the BPF object, `gofmt`,
`go vet`, `go test`, a `go mod tidy` diff, `helm lint` + `helm template`) and
`kernel-smoke`, which loads the compiled `.o` and attempts every attach
(`cmd/cismoke`) against a real 6.18 kernel in a VM booted with
`lockdown=confidentiality`. That boot flag reproduces a Talos-specific gate
that rejects the `bpf_probe_read` helper family in tracing programs —
compile-only checks can't see it, and it's caused two real regressions (see
`docs/postmortems/`). Don't weaken it.

## License

Apache License 2.0 — see [LICENSE](LICENSE). `internal/bpf/src/netscope.bpf.c`
is the one exception, licensed GPL-2.0 (see the SPDX header in that file), as
required by the GPL-only BPF helpers and kernel symbols it uses.
