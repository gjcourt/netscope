// Package bpf embeds the compiled BPF object as a byte slice.
//
// The BPF source lives next to this file and is compiled to netscope.bpf.o
// by the Dockerfile builder stage. Local `go build` outside Docker will fail
// here unless the .o has been produced first via `make bpf`.
package bpf

import _ "embed"

//go:embed netscope.bpf.o
var Object []byte
