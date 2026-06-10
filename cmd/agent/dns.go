package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"math"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gjcourt/netscope/internal/dnsparse"
)

// Per-domain DNS latency breakdown (v2). The BPF side (netscope.bpf.c) emits a
// dns_event on netscope_dns_events for every DNS query (udp_sendmsg, dport 53)
// and response (udp_recvmsg). This file is the userspace correlator: it pairs
// query→response by 4-tuple, parses the qname out of the query payload, buckets
// by domain suffix for cardinality control, and exposes a per-suffix histogram
// (netscope_dns_query_microseconds_by_suffix) aligned with the aggregate
// netscope_dns_query_microseconds.
//
// Parsing in userspace (not the kernel) is deliberate: DNS label walking needs
// bounded loops over untrusted data that the eBPF verifier rejects, and Go has
// the stdlib + test coverage to do it safely.

const (
	// dnsEventSize is the wire size of struct dns_event in netscope.bpf.c.
	// Keep in sync with that struct: u64 + 2×u32 + 2×u16 + 2×u8 + u16 + 256.
	dnsPayloadBytes = 256
	dnsEventSize    = 24 + dnsPayloadBytes // 280

	// Event type tags — match NETSCOPE_DNS_EVENT_* in netscope.bpf.c.
	dnsEventQuery    = 1
	dnsEventResponse = 2

	// maxSuffixes caps active per-suffix series. Beyond this, new suffixes are
	// folded into "_other_". Cumulative counters mean we never evict (that
	// would lose monotonic history); this is a hard cap with overflow, not an
	// LRU. 100 keeps scrape cardinality bounded on a busy resolver.
	maxSuffixes  = 100
	otherSuffix  = dnsparse.OtherSuffix
	unknownLabel = "_unparsed_"

	// pendingCap bounds the in-flight query correlation map (mirrors the
	// kernel netscope_dns_query_starts max_entries). When full we sweep stale
	// entries; queries that never get a response would otherwise leak.
	pendingCap = 8192
	// pendingMaxAgeNs evicts correlations whose response never arrived.
	pendingMaxAgeNs = uint64(10 * 1e9) // 10s
)

// flowKey is the 12-byte 4-tuple (saddr,daddr,sport,dport) lifted verbatim from
// the dns_event. Query and response events for the same exchange carry
// identical bytes, so the raw slice is a stable correlation key regardless of
// byte order.
type flowKey [12]byte

type pendingQuery struct {
	suffix  string
	tsNanos uint64
}

// suffixHist is a log2-bucketed latency histogram for one domain suffix. Bucket
// i counts samples with delta_us in [2^i, 2^(i+1)); the same shape as the
// kernel aggregate so the two metrics line up.
type suffixHist struct {
	buckets    [dnsNumBuckets]uint64
	count      uint64
	sumSeconds float64
}

func (h *suffixHist) observe(deltaUs uint64) {
	h.buckets[dnsBucketIndex(deltaUs)]++
	h.count++
	h.sumSeconds += float64(deltaUs) / 1e6
}

// dnsBucketIndex replicates the kernel's log2 bucketing loop exactly so the
// per-suffix histogram aligns with netscope_dns_query_microseconds. delta_us in
// {0,1}→0, {2,3}→1, {4..7}→2, … last bucket is overflow.
func dnsBucketIndex(deltaUs uint64) int {
	bucket := 0
	v := deltaUs
	for i := 1; i < dnsNumBuckets; i++ {
		v >>= 1
		if v != 0 {
			bucket = i
		}
	}
	return bucket
}

// dnsBreakdownCollector reads the ringbuf, correlates query/response, and
// exposes one Prometheus histogram per domain suffix.
type dnsBreakdownCollector struct {
	reader *ringbuf.Reader
	desc   *prometheus.Desc

	// pending is touched only by the reader goroutine — no lock.
	pending map[flowKey]pendingQuery

	// mu guards hists, which Collect (scrape goroutine) reads concurrently
	// with the reader goroutine's writes.
	mu    sync.Mutex
	hists map[string]*suffixHist
}

func newDNSBreakdownCollector(m *ebpf.Map) (*dnsBreakdownCollector, error) {
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	return &dnsBreakdownCollector{
		reader:  reader,
		pending: make(map[flowKey]pendingQuery),
		hists:   make(map[string]*suffixHist),
		desc: prometheus.NewDesc(
			"netscope_dns_query_microseconds_by_suffix",
			"Per-domain-suffix DNS query latency histogram. Same 4-tuple "+
				"send→recv measurement as netscope_dns_query_microseconds, "+
				"broken down by the last two labels of the queried name "+
				"(suffix). Cardinality is capped at "+
				"100 suffixes; the rest fold into suffix=\"_other_\".",
			[]string{"suffix"}, nil,
		),
	}, nil
}

// run drains the ringbuf until the context is cancelled. Closing the reader
// makes the blocking Read return os.ErrClosed, which ends the loop.
func (c *dnsBreakdownCollector) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = c.reader.Close()
	}()
	for {
		rec, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("dns ringbuf read", "err", err)
			continue
		}
		c.handle(rec.RawSample)
	}
}

func (c *dnsBreakdownCollector) handle(raw []byte) {
	if len(raw) < dnsEventSize {
		return
	}
	// Field offsets within struct dns_event.
	tsNanos := binary.LittleEndian.Uint64(raw[0:8]) // host order
	var key flowKey
	copy(key[:], raw[8:20]) // saddr,daddr,sport,dport bytes verbatim
	eventType := raw[20]
	payloadLen := int(binary.LittleEndian.Uint16(raw[22:24]))
	if payloadLen > dnsPayloadBytes {
		payloadLen = dnsPayloadBytes
	}
	payload := raw[24 : 24+payloadLen]

	switch eventType {
	case dnsEventQuery:
		suffix := unknownLabel
		if name, ok := dnsparse.ParseQuestionName(payload); ok {
			suffix = dnsparse.SuffixBucket(name)
		}
		if len(c.pending) >= pendingCap {
			c.sweepPending(tsNanos)
		}
		if len(c.pending) < pendingCap {
			c.pending[key] = pendingQuery{suffix: suffix, tsNanos: tsNanos}
		}
	case dnsEventResponse:
		q, ok := c.pending[key]
		if !ok {
			return
		}
		delete(c.pending, key)
		if tsNanos < q.tsNanos {
			return // monotonic ktime paranoia
		}
		deltaUs := (tsNanos - q.tsNanos) / 1000
		c.record(q.suffix, deltaUs)
	}
}

// sweepPending drops correlations whose response never arrived within
// pendingMaxAgeNs, bounding the map under query loss.
func (c *dnsBreakdownCollector) sweepPending(now uint64) {
	for k, v := range c.pending {
		if now >= v.tsNanos && now-v.tsNanos > pendingMaxAgeNs {
			delete(c.pending, k)
		}
	}
}

func (c *dnsBreakdownCollector) record(suffix string, deltaUs uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.hists[suffix]
	if !ok {
		// Hard cap with "_other_" overflow — never evict (cumulative).
		if len(c.hists) >= maxSuffixes && suffix != otherSuffix && suffix != unknownLabel {
			suffix = otherSuffix
			h, ok = c.hists[suffix]
		}
		if !ok {
			h = &suffixHist{}
			c.hists[suffix] = h
		}
	}
	h.observe(deltaUs)
}

func (c *dnsBreakdownCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *dnsBreakdownCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for suffix, h := range c.hists {
		buckets := make(map[float64]uint64, dnsNumBuckets)
		var cumulative uint64
		for i := 0; i < dnsNumBuckets; i++ {
			cumulative += h.buckets[i]
			le := math.Ldexp(1, i+1) / 1e6 // upper bound in seconds
			buckets[le] = cumulative
		}
		ch <- prometheus.MustNewConstHistogram(
			c.desc, h.count, h.sumSeconds, buckets, suffix,
		)
	}
}
