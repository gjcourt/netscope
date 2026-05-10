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
	defaultIface      = "eno1"
	metricsListenAddr = ":9101"
	mapKey            = uint32(0)
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

	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
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
