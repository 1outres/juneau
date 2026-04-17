.PHONY: generate generate-proto generate-bpf generate-bpf-linux generate-bpf-docker bpf-builder-image

UNAME_S := $(shell uname -s)

DOCKER ?= docker
PROTOC ?= protoc
GO ?= go
BPF_BUILDER_IMAGE ?= juneau-bpf-builder:local
BPF_BUILDER_PLATFORM ?= $(shell $(DOCKER) version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || printf 'linux/amd64')
REPO_ROOT := $(abspath ..)
DOCKER_WORKDIR := /workspace/daemon

generate: generate-proto generate-bpf

generate-proto:
	$(PROTOC) --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/cnipb/cni.proto

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
