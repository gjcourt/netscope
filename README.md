# netscope

eBPF-based network traffic analyzer for the Talos homelab.

A per-node DaemonSet that attaches eBPF programs to host network interfaces and key kernel hooks, aggregates kernel-level traffic and TCP-stack signals into per-CPU BPF maps, and exposes them as Prometheus metrics.

Targets signals **not** covered by Cilium/Hubble: TCP retransmits, smoothed RTT, DNS resolver-side latency, and traffic outside Cilium's view (host-network, node-to-node management plane, off-cluster LAN).

## Status

Phase 0 (feasibility spike). See [brainstorm 03-001](https://github.com/gjcourt/brainstorm/blob/main/03-homelab-automation/03-001-ebpf-based-network-traffic-analyzer.md) for the full plan.

## License

MIT
