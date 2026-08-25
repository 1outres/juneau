.PHONY: generate generate-proto generate-bpf generate-bpf-linux generate-bpf-docker bpf-builder-image verifier-check

UNAME_S := $(shell uname -s)

DOCKER ?= docker
PROTOC ?= protoc
GO ?= go
SUDO ?= sudo
BPF_BUILDER_IMAGE ?= juneau-bpf-builder:local
BPF_BUILDER_PLATFORM ?= $(shell $(DOCKER) version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || printf 'linux/amd64')
REPO_ROOT := $(abspath ..)
DOCKER_WORKDIR := /workspace/daemon
VERIFIER_CHECK_PIN_DIR ?= /sys/fs/bpf/juneau-verifiercheck

generate: generate-proto generate-bpf

generate-proto:
	$(PROTOC) --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/cnipb/cni.proto
	$(PROTOC) --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/debugpb/debug.proto

generate-bpf:
	@if [ "$(UNAME_S)" = "Linux" ]; then \
		$(MAKE) generate-bpf-linux; \
	elif [ "$(UNAME_S)" = "Darwin" ]; then \
		$(MAKE) generate-bpf-docker; \
	else \
		echo "unsupported host OS for eBPF generation: $(UNAME_S)"; \
		exit 1; \
	fi

generate-bpf-linux:
	juneau-gen-vmlinux bpf/vmlinux.h
	$(GO) generate ./internal/daemon/bpf

generate-bpf-docker: bpf-builder-image
	$(DOCKER) run --rm \
		-v "$(REPO_ROOT):/workspace" \
		-w "$(DOCKER_WORKDIR)" \
		$(BPF_BUILDER_IMAGE) \
		sh -c 'printf "%s\n" "#!/bin/sh" "exec go run github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 \"\$$@\"" > /usr/local/bin/bpf2go && chmod +x /usr/local/bin/bpf2go && bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h && go generate ./internal/daemon/bpf'

bpf-builder-image:
	$(DOCKER) build --platform $(BPF_BUILDER_PLATFORM) --load -t $(BPF_BUILDER_IMAGE) -f bpf/Dockerfile .

# verifier-check loads the generated eBPF objects into the running
# kernel and prints how much of the verifier's instruction budget each
# program spends. Run it after changing anything under bpf/: the
# compiler says nothing when a program goes over the budget, and the
# next sign is a daemon in crashloop.
#
# The load needs root and a mounted bpffs, so the binary is built as
# you and only the run goes through $(SUDO) (set SUDO= when you are
# already root). The maps are pinned in VERIFIER_CHECK_PIN_DIR, which
# the run creates and removes on its own, so a daemon running on this
# host keeps its maps.
verifier-check:
	$(GO) build -o bin/verifiercheck ./cmd/verifiercheck
	$(SUDO) bin/verifiercheck -pin-dir $(VERIFIER_CHECK_PIN_DIR)
