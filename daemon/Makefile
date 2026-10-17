.PHONY: generate generate-proto generate-bpf generate-bpf-native generate-bpf-container verify-bpf verifier-check

UNAME_S := $(shell uname -s)

DOCKER ?= docker
PROTOC ?= protoc
GO ?= go
SUDO ?= sudo
REPO_ROOT := $(abspath ..)
NIX_VERSION ?= 2.35.3
NIX_IMAGE ?= nixos/nix:$(NIX_VERSION)
VERIFIER_CHECK_PIN_DIR ?= /sys/fs/bpf/juneau-verifiercheck

generate: generate-proto generate-bpf

generate-proto:
	$(PROTOC) --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/cnipb/cni.proto
	$(PROTOC) --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/debugpb/debug.proto

# The flake only has Linux dev shells, so Darwin runs the same flake inside
# a Linux container.
ifeq ($(UNAME_S),Linux)
generate-bpf: generate-bpf-native
else ifeq ($(UNAME_S),Darwin)
generate-bpf: generate-bpf-container
else
generate-bpf:
	$(error unsupported host OS for eBPF generation: $(UNAME_S))
endif

generate-bpf-native:
	$(GO) generate ./internal/daemon/bpf

# The repository and its git dir are mounted at their host paths because a
# git worktree points to its git dir by an absolute path, and nix reads the
# flake through git. The /nix store and the Go caches are kept in volumes so
# that the toolchain is downloaded only once. The /nix volume name holds the
# Nix version because the image runs the nix binary from that store. The
# mounted files belong to the host user, not to root in the container, so
# git has to be told to trust them.
generate-bpf-container:
	git_dir="$$(git -C "$(REPO_ROOT)" rev-parse --path-format=absolute --git-common-dir)" && \
	$(DOCKER) run --rm \
		-v "$(REPO_ROOT):$(REPO_ROOT)" \
		-v "$$git_dir:$$git_dir" \
		-v juneau-bpf-nix-$(NIX_VERSION):/nix \
		-v juneau-bpf-cache:/root/.cache \
		-e GOMODCACHE=/root/.cache/go-mod \
		-w "$(REPO_ROOT)" \
		$(NIX_IMAGE) \
		sh -c 'git config --global safe.directory "*" && exec nix --extra-experimental-features "nix-command flakes" develop .#bpf -c make -C daemon generate-bpf-native'

verify-bpf: generate-bpf
	@if [ -n "$$(git status --porcelain -- internal/daemon/bpf)" ]; then \
		git status --short -- internal/daemon/bpf; \
		echo "The committed eBPF objects do not match the sources. Run 'make daemon-generate-bpf' and commit the result." >&2; \
		exit 1; \
	fi

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
