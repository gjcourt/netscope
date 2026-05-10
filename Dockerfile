# syntax=docker/dockerfile:1.7

# Builder: compile the BPF object with clang, then build the Go binary
# (which embeds the .o via go:embed).
FROM golang:1.23-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Compile BPF object. -target bpf produces BPF bytecode; -O2 helps the verifier.
# Use the bookworm libbpf headers (/usr/include/bpf, /usr/include/linux).
RUN clang -O2 -g -Wall -Werror \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I/usr/include/x86_64-linux-gnu \
    -c internal/bpf/netscope.bpf.c \
    -o internal/bpf/netscope.bpf.o

# Build a static Go binary so it runs in distroless static.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/netscope-agent ./cmd/agent

# Runtime: static distroless. The agent reads /sys/fs/bpf and /sys/kernel/btf
# from host mounts; nothing else is needed at runtime.
#
# Runs as root (uid 0) so the kernel grants the BPF/PERFMON/NET_ADMIN caps
# requested by the DaemonSet. Phase 1+ may move to a non-root uid once we
# verify tcx attach works without root on this Talos kernel.
FROM gcr.io/distroless/static-debian12:latest AS runtime

COPY --from=builder /out/netscope-agent /netscope-agent

USER 0:0
EXPOSE 9101
ENTRYPOINT ["/netscope-agent"]
