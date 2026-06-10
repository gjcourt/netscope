package dnsparse

import "testing"

// dnsQuery builds a minimal DNS query message: 12-byte header (QDCOUNT=1) plus
// a question section for the given dotted name with QTYPE/QCLASS = A/IN.
func dnsQuery(name string) []byte {
	msg := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: standard query, RD
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	if name != "" {
		for _, label := range splitDots(name) {
			msg = append(msg, byte(len(label)))
			msg = append(msg, label...)
		}
	}
	msg = append(msg, 0x00)       // root terminator
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func TestParseQuestionName(t *testing.T) {
	tests := []struct {
		name   string
		msg    []byte
		want   string
		wantOK bool
	}{
		{"simple", dnsQuery("burntbytes.com"), "burntbytes.com", true},
		{"subdomain", dnsQuery("auth.burntbytes.com"), "auth.burntbytes.com", true},
		{"k8s service", dnsQuery("adguard.adguard-prod.svc.cluster.local"), "adguard.adguard-prod.svc.cluster.local", true},
		{"single label", dnsQuery("localhost"), "localhost", true},
		{"uppercase lowercased", dnsQuery("WWW.Example.COM"), "www.example.com", true},
		{"too short", []byte{0x00, 0x01}, "", false},
		{"qdcount zero", func() []byte { m := dnsQuery("x.com"); m[5] = 0x00; return m }(), "", false},
		{"root only", dnsQuery(""), "", false},
		{
			"truncated mid-label",
			[]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05, 'a', 'b'}, // claims 5, only 2
			"", false,
		},
		{
			"compression pointer in question",
			[]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c},
			"", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseQuestionName(tt.msg)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("ParseQuestionName() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestParseQuestionNameRejectsOverlongName(t *testing.T) {
	// 128 single-char labels exceeds the 255-byte / 127-label limits.
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for range 200 {
		msg = append(msg, 0x01, 'a')
	}
	msg = append(msg, 0x00)
	if _, ok := ParseQuestionName(msg); ok {
		t.Fatal("expected rejection of overlong name")
	}
}

func TestSuffixBucket(t *testing.T) {
	tests := []struct {
		qname string
		want  string
	}{
		{"burntbytes.com", "burntbytes.com"},
		{"auth.burntbytes.com", "burntbytes.com"},
		{"a.b.svc.cluster.local", "cluster.local"},
		{"localhost", "localhost"},
		{"x.y.z.google.com", "google.com"},
		{"trailing.dot.com.", "dot.com"},
		{"", OtherSuffix},
		{".", OtherSuffix},
	}
	for _, tt := range tests {
		t.Run(tt.qname, func(t *testing.T) {
			if got := SuffixBucket(tt.qname); got != tt.want {
				t.Fatalf("SuffixBucket(%q) = %q, want %q", tt.qname, got, tt.want)
			}
		})
	}
}
