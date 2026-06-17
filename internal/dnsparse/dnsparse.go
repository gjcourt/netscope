// Package dnsparse contains the pure, platform-agnostic DNS parsing used by the
// netscope agent's per-domain latency breakdown: extracting a query's name from
// an on-the-wire DNS message and reducing it to a low-cardinality suffix.
//
// It's deliberately separate from cmd/agent (which is linux-only — it pulls in
// cilium/ebpf) so this logic builds and is unit-tested on any platform.
package dnsparse

import (
	"encoding/binary"
	"strings"
)

// OtherSuffix is the catch-all bucket for names that can't be reduced to a
// meaningful suffix.
const OtherSuffix = "_other_"

const (
	dnsHeaderLen = 12
	// maxNameLen / maxLabels are RFC 1035 §3.1 limits; we bail past them
	// rather than trust an attacker-controlled length to bound the loop.
	maxNameLen = 255
	maxLabels  = 127
)

// ParseQuestionName extracts the first QNAME from a DNS message (12-byte header
// + question section), lowercased and dot-joined without a trailing dot. It
// returns false when the message is too short, has QDCOUNT 0, is truncated
// mid-name, exceeds RFC limits, or uses a compression pointer in the question
// (which never appears in a well-formed query — only in answers). DNS names are
// case-insensitive, so we lowercase for stable bucketing.
func ParseQuestionName(msg []byte) (string, bool) {
	if len(msg) < dnsHeaderLen+1 {
		return "", false
	}
	if binary.BigEndian.Uint16(msg[4:6]) == 0 { // QDCOUNT
		return "", false
	}
	off := dnsHeaderLen
	labels := make([]string, 0, 8)
	total := 0
	for {
		if off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		if l == 0 { // root terminator
			break
		}
		if l&0xc0 != 0 {
			// Top two bits set = compression pointer / reserved. Not valid
			// in a query's question section; bail rather than chase it.
			return "", false
		}
		off++
		if off+l > len(msg) {
			return "", false
		}
		total += l + 1
		if total > maxNameLen || len(labels) >= maxLabels {
			return "", false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.ToLower(strings.Join(labels, ".")), true
}

// SuffixBucket reduces a qname to its last two labels for cardinality control:
//
//	"a.b.svc.cluster.local" → "cluster.local"
//	"x.burntbytes.com"      → "burntbytes.com"
//	"localhost"             → "localhost"
//
// An empty or dot-only name maps to OtherSuffix.
func SuffixBucket(qname string) string {
	labels := strings.Split(qname, ".")
	for len(labels) > 0 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1] // drop trailing-dot empties
	}
	if len(labels) == 0 {
		return OtherSuffix
	}
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
