// Default-route interface discovery.
//
// The agent attaches its tcx ingress program to a single host interface.
// Historically this was hardcoded to "eno1" because every Talos node in the
// homelab happened to have that NIC name, but that's a footgun on
// heterogeneous hardware: the agent would silently fail to attach on any
// node whose primary NIC is named differently.
//
// We read /proc/net/route directly instead of pulling in
// vishvananda/netlink — the kernel's procfs table is stable, parseable
// without any deps, and works in the minimal container image.
package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// procNetRoutePath is the kernel's IPv4 routing table. Overridable for tests.
const procNetRoutePath = "/proc/net/route"

// rtfGateway is the RTF_GATEWAY flag from <linux/route.h>. A default route is
// the row whose Destination == 00000000 and whose Flags field has this bit set.
const rtfGateway = 0x2

// discoverDefaultRouteIface returns the name of the interface that carries the
// IPv4 default route with the lowest metric. Returns an error if no such route
// exists or the table can't be read.
func discoverDefaultRouteIface() (string, error) {
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", procNetRoutePath, err)
	}
	defer f.Close()
	return parseDefaultRouteIface(f)
}

// parseDefaultRouteIface parses the /proc/net/route format and returns the
// interface name for the default route with the lowest metric. Split out from
// the file open so tests can drive it with a fixture string.
//
// Format (tab-separated, with a header row):
//
//	Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
//	eno1   00000000     0102A8C0 0003   0       0    100     00000000 0  0       0
//
// All numeric fields are hex, little-endian. The default route has
// Destination == "00000000" and the RTF_GATEWAY (0x2) flag set.
func parseDefaultRouteIface(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)

	// Skip header row. An empty file is a valid (if unusual) input — no
	// header, no default route — so treat scanner.Scan() returning false
	// as "no default route" rather than an error.
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read %s: %w", procNetRoutePath, err)
		}
		return "", fmt.Errorf("no default route found in %s (empty table)", procNetRoutePath)
	}

	bestIface := ""
	bestMetric := uint64(math.MaxUint64)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		// Need at least: Iface, Destination, Gateway, Flags, RefCnt, Use, Metric.
		if len(fields) < 7 {
			continue
		}

		iface := fields[0]
		destination := fields[1]
		flagsHex := fields[3]
		metricStr := fields[6]

		if destination != "00000000" {
			continue
		}

		flags, err := strconv.ParseUint(flagsHex, 16, 32)
		if err != nil {
			continue
		}
		if flags&rtfGateway == 0 {
			continue
		}

		// Metric is decimal in /proc/net/route, not hex (one of the few
		// non-hex columns in the table). Lower is preferred.
		metric, err := strconv.ParseUint(metricStr, 10, 64)
		if err != nil {
			continue
		}

		if metric < bestMetric {
			bestMetric = metric
			bestIface = iface
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", procNetRoutePath, err)
	}

	if bestIface == "" {
		return "", fmt.Errorf("no default route found in %s", procNetRoutePath)
	}
	return bestIface, nil
}
