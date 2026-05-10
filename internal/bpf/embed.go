// Package bpf embeds the compiled BPF object as a byte slice.
//
// The BPF C source lives in src/ (kept out of this Go package directory so
// `go vet` doesn't try to treat it as cgo). It compiles to netscope.bpf.o
// alongside this file via `make bpf`. Local `go build` outside Docker will
// fail until the .o is produced.
package bpf

import _ "embed"

//go:embed netscope.bpf.o
var Object []byte
