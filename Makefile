IMAGE       ?= ghcr.io/gjcourt/netscope
TAG         ?= dev
PLATFORM    ?= linux/amd64

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-20s %s\n", $$1, $$2}'

.PHONY: bpf
bpf: ## Compile BPF object (requires clang + libbpf-dev locally)
	clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
	  -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu \
	  -c internal/bpf/src/netscope.bpf.c -o internal/bpf/netscope.bpf.o

.PHONY: build
build: ## Build container image (compiles BPF + Go inside the builder stage)
	docker buildx build --platform=$(PLATFORM) --load -t $(IMAGE):$(TAG) .

.PHONY: push
push: ## Push image to registry
	docker push $(IMAGE):$(TAG)

.PHONY: tidy
tidy: ## Update go.mod / go.sum
	go mod tidy

.PHONY: test
test: ## Run unit tests (none yet — placeholder)
	go test ./...

.PHONY: helm-lint
helm-lint: ## Lint the netscope Helm chart
	helm lint deploy/helm/netscope

.PHONY: helm-template
helm-template: ## Render the chart with default values (smoke test)
	helm template netscope deploy/helm/netscope --namespace netscope-stage

.PHONY: clean
clean: ## Remove build artifacts
	rm -f internal/bpf/*.o
