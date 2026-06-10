// Package main is the netscope agent entrypoint. It loads the embedded BPF
// object, attaches the tcx/ingress program to a discovered host interface,
// and exposes per-CPU map values as Prometheus counters on :9101/metrics.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	netscopebpf "github.com/gjcourt/netscope/internal/bpf"
)

const (
	metricsListenAddr     = ":9101"
	mapKey                = uint32(0)
	ciliumIngressProgName = "cil_from_netdev"
	ifaceEnvVar           = "NETSCOPE_IFACE"

	// srttNumBuckets must match NETSCOPE_SRTT_NUM_BUCKETS in netscope.bpf.c;
	// we assert this at startup against the loaded map's MaxEntries. The
	// kernel stores srtt_us as actual_µs * 8, so the 24 buckets bucket the
	// scaled value [2^0, 2^24) — real RTT coverage is 0.125µs through
	// overflow at ~1.05s (bucket 23's upper le ≈ 2.1s, captures everything
	// at or above that).
	srttNumBuckets = 24

	// dnsNumBuckets must match NETSCOPE_DNS_NUM_BUCKETS in netscope.bpf.c.
	// Same shape as srttNumBuckets: 24 log2 buckets, last is overflow. Bucket
	// i covers delta_us in [2^i, 2^(i+1)); the le boundary we emit is the
	// upper bound in *seconds* = 2^(i+1) / 1e6. Range: ~2µs through ~16s.
	dnsNumBuckets = 24
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("netscope exiting", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ifaceName, source, err := resolveIface()
	if err != nil {
		return err
	}
	slog.Info("resolved interface", "iface", ifaceName, "source", source)

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q (%s): %w", ifaceName, source, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netscopebpf.Object))
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["count_rx"]
	if prog == nil {
		return errors.New("program count_rx not found in collection")
	}

	rxMap := coll.Maps["netscope_rx_bytes"]
	if rxMap == nil {
		return errors.New("map netscope_rx_bytes not found in collection")
	}

	retransmitProg := coll.Programs["count_tcp_retransmit"]
	if retransmitProg == nil {
		return errors.New("program count_tcp_retransmit not found in collection")
	}

	retransmitMap := coll.Maps["netscope_tcp_retransmits"]
	if retransmitMap == nil {
		return errors.New("map netscope_tcp_retransmits not found in collection")
	}

	srttProg := coll.Programs["record_tcp_srtt"]
	if srttProg == nil {
		return errors.New("program record_tcp_srtt not found in collection")
	}

	srttMap := coll.Maps["netscope_tcp_srtt_buckets"]
	if srttMap == nil {
		return errors.New("map netscope_tcp_srtt_buckets not found in collection")
	}
	// Guard against drift between the Go-side constant and the BPF-side
	// #define. If they diverge, the collector either misses buckets or
	// loops past max_entries and surfaces "lookup bucket N: ENOENT" warns
	// on every scrape — fail loudly at startup instead.
	if got := srttMap.MaxEntries(); got != srttNumBuckets {
		return fmt.Errorf("srtt bucket count drift: bpf map max_entries=%d, go srttNumBuckets=%d", got, srttNumBuckets)
	}

	dnsQueryProg := coll.Programs["record_dns_query"]
	if dnsQueryProg == nil {
		return errors.New("program record_dns_query not found in collection")
	}

	dnsResponseProg := coll.Programs["record_dns_response"]
	if dnsResponseProg == nil {
		return errors.New("program record_dns_response not found in collection")
	}

	dnsLatencyMap := coll.Maps["netscope_dns_latency_buckets"]
	if dnsLatencyMap == nil {
		return errors.New("map netscope_dns_latency_buckets not found in collection")
	}
	// Same drift guard as srtt: if the BPF #define and Go constant disagree,
	// fail loudly at startup rather than emit silently-truncated histograms.
	if got := dnsLatencyMap.MaxEntries(); got != dnsNumBuckets {
		return fmt.Errorf("dns bucket count drift: bpf map max_entries=%d, go dnsNumBuckets=%d", got, dnsNumBuckets)
	}

	// Attach ahead of Cilium's cil_from_netdev so we observe every packet,
	// not just the ones Cilium leaves with TC_ACT_UNSPEC. link.Head() (sets
	// BPF_F_BEFORE without a target) does not take effect on this kernel
	// when another program is already attached, so we discover Cilium's
	// program ID and anchor against it explicitly. Safe because count_rx
	// only reads skb->len and returns TC_ACT_UNSPEC; Cilium's policy
	// decisions are unaffected.
	opts := link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	}
	ciliumID, err := findProgramByName(ciliumIngressProgName)
	switch {
	case err == nil:
		slog.Info("anchoring before cilium ingress program", "name", ciliumIngressProgName, "id", ciliumID)
		opts.Anchor = link.BeforeProgramByID(ciliumID)
	case errors.Is(err, os.ErrNotExist):
		slog.Info("no cilium ingress program found; attaching with default ordering")
	default:
		// e.g. EPERM if CAP_SYS_ADMIN is missing. Surface it loudly rather
		// than silently degrading to default ordering — that's exactly the
		// failure mode this PR is trying to prevent.
		return fmt.Errorf("discover cilium program: %w", err)
	}

	tcxLink, err := link.AttachTCX(opts)
	if err != nil {
		return fmt.Errorf("attach tcx ingress on %s: %w", iface.Name, err)
	}
	defer tcxLink.Close()

	slog.Info("attached", "iface", iface.Name, "ifindex", iface.Index)

	// fentry on tcp_retransmit_skb. The symbol is GPL-only (the BPF
	// LICENSE string in netscope.bpf.c is "GPL"), and the program type
	// is Tracing — distinct from the tcx classifier above, so it needs
	// its own link.AttachTracing call.
	retransmitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    retransmitProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry tcp_retransmit_skb: %w", err)
	}
	defer retransmitLink.Close()

	slog.Info("attached fentry", "program", "tcp_retransmit_skb")

	// fentry on tcp_rcv_established for the SRTT histogram. Same Tracing
	// program-type machinery as the retransmit counter above, so it needs
	// its own AttachTracing call and its own link to close on shutdown.
	srttLink, err := link.AttachTracing(link.TracingOptions{
		Program:    srttProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry tcp_rcv_established: %w", err)
	}
	defer srttLink.Close()

	slog.Info("attached fentry", "program", "tcp_rcv_established")

	// fentry on udp_sendmsg captures outbound DNS queries (sk->dport == 53).
	// In-kernel correlation: the BPF program stashes a start timestamp under
	// a 4-tuple key in netscope_dns_query_starts. See netscope.bpf.c for the
	// design rationale (4-tuple vs txid, connected-sock-only coverage, etc.).
	dnsQueryLink, err := link.AttachTracing(link.TracingOptions{
		Program:    dnsQueryProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry udp_sendmsg: %w", err)
	}
	defer dnsQueryLink.Close()

	slog.Info("attached fentry", "program", "udp_sendmsg")

	// fexit on udp_recvmsg matches inbound responses against the in-flight
	// query and increments the latency histogram. fexit (rather than fentry)
	// because we need the return value to distinguish a real datagram copy
	// from -EAGAIN / -ERESTARTSYS wakeups.
	dnsResponseLink, err := link.AttachTracing(link.TracingOptions{
		Program:    dnsResponseProg,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return fmt.Errorf("attach fexit udp_recvmsg: %w", err)
	}
	defer dnsResponseLink.Close()

	slog.Info("attached fexit", "program", "udp_recvmsg")

	rxBytes := prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name:        "netscope_rx_bytes_total",
			Help:        "Total bytes received on the host's primary interface, observed at tcx ingress.",
			ConstLabels: prometheus.Labels{"iface": iface.Name},
		},
		func() float64 {
			total, err := readPerCPUSum(rxMap)
			if err != nil {
				slog.Warn("read map", "err", err)
				return 0
			}
			return float64(total)
		},
	)
	prometheus.MustRegister(rxBytes)

	// netscope_tcp_retransmits_total: host-wide retransmit counter. No
	// per-iface label — retransmits are a per-socket event, not a per-NIC
	// one, and TCP can pick a different egress NIC than the rx side. The
	// ServiceMonitor promotes nodename, which is the dimension that matters
	// for "is one node retransmitting more than its peers".
	retransmitCounter := prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "netscope_tcp_retransmits_total",
			Help: "Total TCP retransmits observed via fentry on tcp_retransmit_skb.",
		},
		func() float64 {
			total, err := readPerCPUSum(retransmitMap)
			if err != nil {
				slog.Warn("read retransmit map", "err", err)
				return 0
			}
			return float64(total)
		},
	)
	prometheus.MustRegister(retransmitCounter)

	prometheus.MustRegister(&srttHistogramCollector{
		m: srttMap,
		desc: prometheus.NewDesc(
			"netscope_tcp_srtt_microseconds",
			"TCP smoothed-RTT histogram observed via fentry on tcp_rcv_established. "+
				"Buckets are powers of two on the kernel's scaled srtt_us value "+
				"(actual µs × 8); le labels are converted to seconds.",
			nil, nil,
		),
	})

	// DNS query latency histogram. Same log2 shape as SRTT but bucketing
	// directly on real microseconds (no /8 scaling), so the le boundary for
	// bucket i is 2^(i+1) / 1e6 seconds. Bucket 23 is overflow; everything
	// >= ~8.4s lands there.
	prometheus.MustRegister(&dnsLatencyHistogramCollector{
		m: dnsLatencyMap,
		desc: prometheus.NewDesc(
			"netscope_dns_query_microseconds",
			"DNS query latency histogram. Measured as the wall-clock interval "+
				"from udp_sendmsg (sk_dport == 53) to a successful udp_recvmsg "+
				"return on the same 4-tuple. Buckets are powers of two on µs; "+
				"le labels are converted to seconds.",
			nil, nil,
		),
	})

	// Per-domain DNS latency breakdown (v2): correlate query/response events
	// from the netscope_dns_events ringbuf in userspace and expose a
	// per-suffix histogram alongside the in-kernel aggregate above.
	dnsEventsMap := coll.Maps["netscope_dns_events"]
	if dnsEventsMap == nil {
		return errors.New("map netscope_dns_events not found in collection")
	}
	dnsBreakdown, err := newDNSBreakdownCollector(dnsEventsMap)
	if err != nil {
		return fmt.Errorf("dns breakdown ringbuf reader: %w", err)
	}
	prometheus.MustRegister(dnsBreakdown)

	// Signal context drives both the ringbuf reader's lifetime and the
	// shutdown select below.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go dnsBreakdown.run(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:              metricsListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("metrics server listening", "addr", metricsListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("metrics server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("server shutdown", "err", err)
	}
	return nil
}

// resolveIface returns the interface name to attach to, along with a short
// human-readable source ("env" or "default-route") for logging and errors.
//
// Resolution order:
//  1. NETSCOPE_IFACE env var (explicit operator override — the DaemonSet
//     can set this to pin to a specific NIC name for predictability).
//  2. The IPv4 default-route interface as read from /proc/net/route.
//
// There is intentionally no static fallback: if discovery fails and no
// override is set, the agent exits with a clear error rather than silently
// attaching to a wrong or nonexistent interface (the failure mode this work
// was meant to eliminate).
func resolveIface() (name, source string, err error) {
	if v := os.Getenv(ifaceEnvVar); v != "" {
		return v, "env:" + ifaceEnvVar, nil
	}
	iface, err := discoverDefaultRouteIface()
	if err != nil {
		return "", "", fmt.Errorf("discover default-route interface (set %s to override): %w", ifaceEnvVar, err)
	}
	return iface, "default-route", nil
}

// findProgramByName iterates loaded BPF programs and returns the ID of the
// first one whose Info().Name matches. Used to anchor our tcx attach against
// Cilium's ingress program by name (program IDs are not stable across cilium
// agent restarts, so we resolve fresh at startup).
//
// Returns os.ErrNotExist when no matching program is loaded (the kernel's
// BPF_PROG_GET_NEXT_ID surfaces end-of-iteration as ENOENT). Other errors
// (e.g. EPERM when CAP_SYS_ADMIN is missing) propagate so callers can
// distinguish "Cilium isn't here" from "we can't see the program list".
func findProgramByName(name string) (ebpf.ProgramID, error) {
	var curID ebpf.ProgramID
	for {
		nextID, err := ebpf.ProgramGetNextID(curID)
		if err != nil {
			// ErrNotExist signals end-of-iteration; any other error is
			// real (permissions, etc.) and the caller needs to see it.
			return 0, err
		}
		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			// Program may have been unloaded between GetNextID and
			// NewProgramFromID, or we lack permission to open this one.
			// Skip and continue iterating.
			curID = nextID
			continue
		}
		info, infoErr := prog.Info()
		prog.Close()
		if infoErr == nil && info.Name == name {
			return nextID, nil
		}
		curID = nextID
	}
}

// srttHistogramCollector exposes the BPF-side per-CPU log2 histogram of
// SRTT samples as a Prometheus histogram metric.
//
// The BPF map holds NETSCOPE_SRTT_NUM_BUCKETS per-CPU u64 counters keyed by
// bucket index. We read all of them at scrape time, sum across CPUs into a
// dense []uint64, then emit cumulative `le` buckets — Prometheus expects
// bucket counts to be monotonically non-decreasing across le boundaries.
//
// The kernel stores srtt as actual_microseconds * 8 and we bucket on that
// scaled value, so bucket i corresponds to scaled values in [2^i, 2^(i+1)).
// In real-µs terms that's [2^i / 8, 2^(i+1) / 8) µs, and the le boundary we
// emit is the upper bound of that range in *seconds*. We label `le` with the
// upper-edge actual-time in seconds: le_seconds = (2^(i+1) / 8) / 1e6.
//
// _sum is reported as 0 — we don't keep a side u64 counter for the sum yet
// (kept out of scope to keep this PR small). Histogram _bucket and _count
// are still useful: rate(), quantile estimation via histogram_quantile, and
// "did this distribution shift" alerting all work without _sum.
type srttHistogramCollector struct {
	m    *ebpf.Map
	desc *prometheus.Desc
}

func (c *srttHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *srttHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	totals, err := readPerCPUSlice(c.m, srttNumBuckets)
	if err != nil {
		// Surface the failure to Prometheus rather than silently dropping
		// the metric — a silent zero scrape looks identical to "no SRTT
		// samples yet", which is the wrong story to tell during an outage.
		slog.Warn("read srtt map", "err", err)
		ch <- prometheus.NewInvalidMetric(c.desc, err)
		return
	}

	// Build cumulative buckets keyed by upper-edge `le` in seconds.
	// Bucket i covers scaled srtt_us in [2^i, 2^(i+1)). Real µs = scaled/8,
	// so the upper bound in seconds is 2^(i+1) / 8 / 1e6.
	buckets := make(map[float64]uint64, srttNumBuckets)
	var cumulative, count uint64
	for i := 0; i < srttNumBuckets; i++ {
		cumulative += totals[i]
		le := math.Ldexp(1, i+1) / 8.0 / 1e6 // (2^(i+1) / 8) / 1e6 seconds
		buckets[le] = cumulative
		count += totals[i]
	}

	ch <- prometheus.MustNewConstHistogram(
		c.desc,
		count,
		0, // sum not tracked yet — see type doc.
		buckets,
	)
}

// dnsLatencyHistogramCollector exposes the BPF-side per-CPU log2 histogram of
// DNS query latency samples as a Prometheus histogram metric.
//
// Same structure as srttHistogramCollector: read all per-CPU u64 counters,
// sum across CPUs, emit cumulative `le` buckets in seconds. The only
// difference from SRTT is the µs↔s conversion — DNS buckets directly on
// real microseconds (no /8 kernel-scaling), so the le boundary for bucket i
// is 2^(i+1) / 1e6 seconds. _sum is reported as 0 for the same reason as
// SRTT (kept out of scope to keep the PR small).
type dnsLatencyHistogramCollector struct {
	m    *ebpf.Map
	desc *prometheus.Desc
}

func (c *dnsLatencyHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *dnsLatencyHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	totals, err := readPerCPUSlice(c.m, dnsNumBuckets)
	if err != nil {
		slog.Warn("read dns latency map", "err", err)
		ch <- prometheus.NewInvalidMetric(c.desc, err)
		return
	}

	buckets := make(map[float64]uint64, dnsNumBuckets)
	var cumulative, count uint64
	for i := 0; i < dnsNumBuckets; i++ {
		cumulative += totals[i]
		// Bucket i covers delta_us in [2^i, 2^(i+1)); upper bound in seconds
		// is 2^(i+1) / 1e6. No /8 scaling here, unlike SRTT.
		le := math.Ldexp(1, i+1) / 1e6
		buckets[le] = cumulative
		count += totals[i]
	}

	ch <- prometheus.MustNewConstHistogram(
		c.desc,
		count,
		0, // sum not tracked yet — see type doc.
		buckets,
	)
}

func readPerCPUSlice(m *ebpf.Map, n int) ([]uint64, error) {
	out := make([]uint64, n)
	cpuCount := ebpf.MustPossibleCPU()
	perCPU := make([]uint64, cpuCount)
	for i := uint32(0); i < uint32(n); i++ {
		if err := m.Lookup(i, &perCPU); err != nil {
			return nil, fmt.Errorf("lookup bucket %d: %w", i, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[i] = sum
	}
	return out, nil
}

func readPerCPUSum(m *ebpf.Map) (uint64, error) {
	// BPF per-CPU maps are sized by the kernel's nr_cpu_ids (i.e. all
	// possible CPUs including offline/hot-plug slots). runtime.NumCPU()
	// reflects what Go sees, which on cgroup-restricted or hot-plug
	// systems may differ from the kernel's view and silently truncate
	// the lookup. ebpf.MustPossibleCPU() returns the right size.
	perCPU := make([]uint64, ebpf.MustPossibleCPU())
	if err := m.Lookup(mapKey, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}
