// Package main is the netscope CI kernel-load smoke test. It exists to catch
// verifier rejections that compile-only CI cannot see: the BPF .o builds fine
// under clang but a real kernel rejects the program when the verifier walks
// it at load or attach time.
//
// Concretely, PRs #7-#9 each shipped a SRTT histogram that passed `make bpf`
// in CI and only blew up on the cluster:
//
//   - PR #7: "program of this type cannot use helper bpf_probe_read#4"
//     (fentry forbids probe_read helpers).
//   - PR #8: "permission denied: access beyond struct sock at off 1672 size
//     4" (the C-level cast to struct tcp_sock didn't satisfy the BPF type
//     system; bpf_skc_to_tcp_sock is the verifier-blessed narrowing).
//
// This binary is meant to be run inside a vmtest VM pinned to a kernel close
// to the production target (Talos ships 6.18.x). It:
//
//  1. Loads the embedded BPF object via ebpf.LoadCollectionSpecFromReader.
//  2. Calls ebpf.NewCollection — this is what walks the verifier and
//     surfaces the per-program rejection messages.
//  3. Attempts the same attach calls the production agent does (tcx ingress
//     on `lo`, fentry/fexit on the tracing programs). Some failures only
//     show up at attach time (e.g. missing kernel symbol), so loading alone
//     is not sufficient.
//  4. Reports SUCCESS / FAILURE per program with the underlying error text
//     and exits non-zero if any program failed.
//
// The smoke does NOT exercise the programs with traffic — that is explicitly
// out of scope (see issue #10). The goal is "verifier accepts and the kernel
// has the symbols we need", not "the agent produces correct metrics".
package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	netscopebpf "github.com/gjcourt/netscope/internal/bpf"
)

// attachStep describes one attach attempt. We model attach as a function
// rather than a struct of options because the cilium/ebpf link API uses
// different option types per attach kind (TCXOptions vs TracingOptions).
//
// Returning a link.Link lets main() close it before moving on so a single
// kernel program slot doesn't pin live attachments through the rest of the
// run — vmtest VMs are short-lived but we'd rather be tidy than rely on it.
type attachStep struct {
	progName string
	// describe is a human-readable summary of what we're trying to do, used
	// only in log lines. The kernel symbol name is the load-bearing part for
	// tracing attaches; the rest is for the operator reading CI output.
	describe string
	attach   func(prog *ebpf.Program) (link.Link, error)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cismoke: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// RemoveMemlock is a no-op on kernels >= 5.11, which charge BPF memory
	// against memcg rather than RLIMIT_MEMLOCK. The vmtest kernel here is
	// 6.18 (matches Talos production), so we don't need it for the load to
	// succeed. Production Talos nodes are also >= 5.11.
	//
	// We still call it because the cilium/ebpf rlimit helper is conservative
	// and will downgrade RLIMIT_MEMLOCK on older kernels if anyone ever runs
	// this binary outside CI. But its memcg-detection probe trips on the
	// minimal vmtest initramfs ("function not implemented") even though
	// cgroup2 is mounted — the kernel image lacks the per-cgroup memory
	// controller config. Log and continue rather than abort: the subsequent
	// NewCollection call is the real load test and will report the truth.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "cismoke: rlimit.RemoveMemlock failed (continuing, kernel >= 5.11 doesn't need it): %v\n", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netscopebpf.Object))
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	// Snapshot the program names we expect to find before NewCollection
	// consumes the spec. The list comes from the spec itself rather than a
	// hand-maintained constant so adding a new SEC() to netscope.bpf.c does
	// not silently bypass the smoke test.
	expected := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		expected = append(expected, name)
	}

	// NewCollection is where the verifier runs. If any program is rejected
	// the error wraps a *ebpf.VerifierError whose Log() carries the full
	// verifier trace — exactly the message we wanted CI to surface.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		printVerifierError(err)
		return fmt.Errorf("new bpf collection: %w", err)
	}
	defer coll.Close()

	fmt.Printf("LOAD: ok (%d programs verified)\n", len(expected))
	for _, name := range expected {
		fmt.Printf("  - %s\n", name)
	}

	// `lo` is always present in the vmtest VM and tcx ingress doesn't care
	// which interface we use to prove the program attaches — we are not
	// generating traffic.
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("lookup loopback interface: %w", err)
	}
	// Defensive: a zero ifindex would silently send the tcx attach to "any"
	// and the resulting error is confusing. Real Linux always returns >0 for
	// `lo`, but guard against an unusual kernel/netns combination here.
	if loIface.Index == 0 {
		return fmt.Errorf("loopback interface returned zero ifindex (unexpected on Linux)")
	}

	steps := []attachStep{
		{
			progName: "count_rx",
			describe: "tcx/ingress on lo",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTCX(link.TCXOptions{
					Interface: loIface.Index,
					Program:   prog,
					Attach:    ebpf.AttachTCXIngress,
				})
			},
		},
		{
			progName: "count_tcp_retransmit",
			describe: "fentry tcp_retransmit_skb",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_tcp_srtt",
			describe: "fentry tcp_rcv_established",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_dns_query",
			describe: "fentry udp_sendmsg",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_dns_response",
			describe: "fexit udp_recvmsg",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFExit,
				})
			},
		},
	}

	// Sanity: every program in the .o has a corresponding attach step here.
	// If a future PR adds a SEC() without wiring an attach into this list,
	// the smoke would silently miss any attach-time failure for it — fail
	// loudly instead. This is the "don't make the smoke brittle by silently
	// passing" guardrail from issue #10.
	covered := make(map[string]struct{}, len(steps))
	for _, s := range steps {
		covered[s.progName] = struct{}{}
	}
	var missing []string
	for _, name := range expected {
		if _, ok := covered[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("smoke test missing attach coverage for programs: %s "+
			"(add an entry to steps in cmd/cismoke/main.go)", strings.Join(missing, ", "))
	}

	var failures int
	for _, step := range steps {
		prog := coll.Programs[step.progName]
		if prog == nil {
			fmt.Printf("FAIL %s: program not present in collection\n", step.progName)
			failures++
			continue
		}
		l, err := step.attach(prog)
		if err != nil {
			fmt.Printf("FAIL %s (%s): %v\n", step.progName, step.describe, err)
			failures++
			continue
		}
		fmt.Printf("ATTACH %s (%s): ok\n", step.progName, step.describe)
		// Close immediately so we don't hold every attachment open at once.
		// Order matters less than freeing fds before the next attach call.
		if cerr := l.Close(); cerr != nil {
			fmt.Printf("WARN %s: close link: %v\n", step.progName, cerr)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d program(s) failed to load or attach", failures)
	}
	fmt.Println("OK: all programs verified and attached")
	return nil
}

// printVerifierError pulls the full verifier log out of an error chain and
// dumps it to stderr. The cilium/ebpf library wraps verifier rejections in
// *ebpf.VerifierError whose default Error() truncates the log; Log() carries
// the full trace, which is exactly what we want CI to capture so the
// operator does not have to re-run with extra flags to see why.
func printVerifierError(err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		fmt.Fprintln(os.Stderr, "--- verifier log ---")
		for _, line := range verr.Log {
			fmt.Fprintln(os.Stderr, line)
		}
		fmt.Fprintln(os.Stderr, "--- end verifier log ---")
	}
}
