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
	defaultIface          = "eno1"
	metricsListenAddr     = ":9101"
	mapKey                = uint32(0)
	ciliumIngressProgName = "cil_from_netdev"
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
	ifaceName := os.Getenv("NETSCOPE_IFACE")
	if ifaceName == "" {
		ifaceName = defaultIface
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
