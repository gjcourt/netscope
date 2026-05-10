package main

import (
	"strings"
	"testing"
)

func TestParseDefaultRouteIface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "single default route",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eno1\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eno1\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			want: "eno1",
		},
		{
			name: "multiple default routes, lowest metric wins",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"ppp0\t00000000\t0102A8C0\t0003\t0\t0\t300\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "default route without RTF_GATEWAY is skipped",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eno1\t00000000\t00000000\t0001\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "no default route returns error",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eno1\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			wantErr: true,
		},
		{
			name:    "empty table returns error",
			input:   "",
			wantErr: true,
		},
		{
			name:    "header only returns error",
			input:   "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
			wantErr: true,
		},
		{
			name: "blank lines tolerated",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"\n" +
				"eno1\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eno1",
		},
		{
			name: "malformed flags row skipped, valid row wins",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"bad0\t00000000\t0102A8C0\tZZZZ\t0\t0\t50\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "short row skipped",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"truncated\t00000000\t0102A8C0\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "tie on metric picks first encountered (stable)",
			input: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"eth1\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDefaultRouteIface(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDefaultRouteIface() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDefaultRouteIface() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseDefaultRouteIface() = %q, want %q", got, tt.want)
			}
		})
	}
}
