# netscope — eBPF network traffic analyzer for the Talos homelab

## Overview

netscope is a per-node DaemonSet that attaches eBPF programs to host network
interfaces and key kernel hooks, aggregates kernel-level traffic and TCP-stack
signals into per-CPU BPF maps, and exposes them as Prometheus metrics on
`:9101`. It targets signals **not** covered by Cilium/Hubble: TCP retransmits,
smoothed RTT, DNS resolver-side latency, and traffic outside Cilium's view
(host-network, node-to-node management plane, off-cluster LAN).

The production Talos nodes run kernel 6.18.x with `lockdown=confidentiality`,
which gates the `probe_read` helper family for tracing programs — see the long
comment in `.github/workflows/build.yml` and the postmortems under
`docs/postmortems/` before touching the BPF code.

## Layout

- `cmd/agent/` — the DaemonSet agent (`main.go`); attaches programs, serves `/metrics`.
- `cmd/cismoke/` — kernel-load smoke binary used by CI to verify BPF attach in a VM.
- `internal/bpf/src/netscope.bpf.c` — BPF C source; compiled to `internal/bpf/netscope.bpf.o` and embedded via `go:embed`.
- `internal/` — Go collectors and agent logic.
- `deploy/helm/netscope/` — Helm chart.
- `docs/` — design notes and postmortems.
- `Dockerfile` — compiles the BPF object with clang, then a static Go binary (distroless, amd64).

## Develop

Go 1.23; BPF compilation needs clang + libbpf-dev locally. Common tasks (see `Makefile`):

- `make bpf` — compile the BPF object (required before `go build`/`go test` since it is embedded)
- `make test` — `go test ./...`
- `make cismoke` — build the static kernel-load smoke binary
- `make build` — build the container image (compiles BPF + Go in the builder stage)
- `make helm-lint` / `make helm-template` — lint and smoke-render the chart
- `make tidy` — `go mod tidy`

CI (`.github/workflows/build.yml`) runs on every pull request and on push to
`main`: a `lint` job (compile BPF, gofmt, `go vet`, `go test`, `go mod tidy`
diff, helm lint + template) and a `kernel-smoke` job that loads the compiled
`.o` against a real 6.18 kernel in a VM with `lockdown=confidentiality` to
reproduce the Talos verifier gate. Do not weaken the kernel-smoke settings.

## Container image & deploy

Built and pushed to `ghcr.io/gjcourt/netscope` by `.github/workflows/build.yml`
on push to `main` and via `workflow_dispatch` (GHCR login uses
`${{ secrets.GITHUB_TOKEN }}`). Image is **amd64-only** — the BPF object is
compiled for `__TARGET_ARCH_x86`, so it is not multi-arch. Tags emitted
additively:

- `main` — branch tag (moving)
- `<sha7>` — short commit sha
- `YYYY-MM-DD` — date tag
- `YYYY-MM-DD-<sha7>` — immutable pin tag (use this to pin a deploy)
- `latest`

Deployed in the homelab via GitOps; the image is pinned by tag + digest in
`homelab/apps/base/netscope/daemonset.yaml`. Bump the pin there — do not
repoint `latest`.

## Conventions

- All changes go through a branch and a pull request; never commit directly to
  `main`. Get the PR reviewed and let CI pass before merge.
