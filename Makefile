# Shared repository entrypoint.

LOCALBIN ?= $(CURDIR)/bin
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOLANGCI_LINT_PACKAGE ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.11.4
CRDDOC ?= $(LOCALBIN)/crddoc
CRDDOC_VERSION ?= latest

DOCKER ?= docker
PUBLISH_PLATFORMS ?= linux/amd64,linux/arm64
PUBLISH_TAG ?= dev
GHCR_NAMESPACE ?= ghcr.io/1outres/juneau

CONTROLLER_IMAGE ?= controller:latest
WEBHOOKCERTJOB_IMAGE ?= webhookcertjob:latest
DAEMON_IMAGE ?= daemon:latest
BGP_SPEAKER_IMAGE ?= bgp-speaker:latest

PUBLISH_CONTROLLER_IMAGE ?= $(GHCR_NAMESPACE)/controller:$(PUBLISH_TAG)
PUBLISH_WEBHOOKCERTJOB_IMAGE ?= $(GHCR_NAMESPACE)/webhookcertjob:$(PUBLISH_TAG)
PUBLISH_DAEMON_IMAGE ?= $(GHCR_NAMESPACE)/daemon:$(PUBLISH_TAG)
PUBLISH_BGP_SPEAKER_IMAGE ?= $(GHCR_NAMESPACE)/bgp-speaker:$(PUBLISH_TAG)

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: help

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: controller-generate
controller-generate: ## Generate controller code.
	$(MAKE) -C controller LOCALBIN=$(LOCALBIN) generate

.PHONY: controller-manifests
controller-manifests: ## Generate controller manifests.
	$(MAKE) -C controller LOCALBIN=$(LOCALBIN) manifests

.PHONY: controller-setup-envtest
controller-setup-envtest: ## Install controller envtest assets.
	$(MAKE) -C controller LOCALBIN=$(LOCALBIN) setup-envtest

.PHONY: daemon-generate-proto
daemon-generate-proto: ## Generate daemon protobuf bindings.
	$(MAKE) -C daemon generate-proto

.PHONY: daemon-generate-bpf
daemon-generate-bpf: ## Generate daemon eBPF bindings.
	$(MAKE) -C daemon generate-bpf

.PHONY: docs-build
docs-build: docs-api-reference ## Build documentation locally.
	mkdocs build --strict

.PHONY: docs-serve
docs-serve: docs-api-reference ## Serve documentation locally.
	mkdocs serve

.PHONY: docs-api-reference
docs-api-reference: crddoc ## Generate API reference documentation.
	mkdir -p docs/api-reference
	$(CRDDOC) document crds --output docs/api-reference/v1alpha1.md ./controller/api/v1alpha1

.PHONY: build-webhookcertjob-bin
build-webhookcertjob-bin: ## Build the webhook cert job binary for Tilt.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C controller -o bin/webhookcertjob ./cmd/webhookcertjob/main.go

.PHONY: build-controller-bin
build-controller-bin: controller-generate ## Build the controller manager binary for Tilt.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C controller -o bin/manager ./cmd/main.go

.PHONY: build-cni-bin
build-cni-bin: ## Build the CNI binary for Tilt.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C daemon -o bin/cni ./cmd/cni

.PHONY: build-daemon-bin
build-daemon-bin: build-cni-bin ## Build the daemon binary for Tilt.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C daemon -o bin/daemon ./cmd/juneaud

.PHONY: build-bgp-speaker-bin
build-bgp-speaker-bin: ## Build the BGP speaker binary for Tilt.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C bgp-speaker -o bin/bgpspeaker ./cmd/bgpspeaker/main.go

.PHONY: build-kubectl-juneau-bin
build-kubectl-juneau-bin: ## Build the kubectl-juneau plugin binary.
	$(MAKE) -C kubectl-juneau LOCALBIN=$(CURDIR)/kubectl-juneau/bin build

##@ Quality

.PHONY: lint
lint: lint-controller lint-daemon lint-bgp-speaker lint-kubectl-juneau lint-e2e ## Run repository linters.

.PHONY: lint-controller
lint-controller:
	$(MAKE) -C controller LOCALBIN=$(LOCALBIN) lint

.PHONY: lint-daemon
lint-daemon: golangci-lint build-cni-bin
	cd daemon && $(GOLANGCI_LINT) run --config ../.golangci.yml ./...

.PHONY: lint-bgp-speaker
lint-bgp-speaker: golangci-lint
	cd bgp-speaker && $(GOLANGCI_LINT) run --config ../.golangci.yml ./...

.PHONY: lint-kubectl-juneau
lint-kubectl-juneau: golangci-lint
	cd kubectl-juneau && $(GOLANGCI_LINT) run --config ../.golangci.yml ./...

.PHONY: lint-e2e
lint-e2e: golangci-lint
	cd test/e2e && $(GOLANGCI_LINT) run --config ../../.golangci.yml ./...

.PHONY: test
test: test-controller test-daemon test-bgp-speaker test-kubectl-juneau ## Run non-E2E tests.

.PHONY: test-controller
test-controller:
	$(MAKE) -C controller LOCALBIN=$(LOCALBIN) test

.PHONY: test-daemon
test-daemon: build-cni-bin
	cd daemon && go test ./...

.PHONY: test-bgp-speaker
test-bgp-speaker:
	cd bgp-speaker && go test ./...

.PHONY: test-kubectl-juneau
test-kubectl-juneau:
	cd kubectl-juneau && go test ./...

.PHONY: verify
verify: lint test images ## Run CI verification targets.

##@ Images

.PHONY: images
images: image-controller image-webhookcertjob image-daemon image-bgp-speaker ## Build all runtime images.

# `buildx build --load` engages BuildKit so the Dockerfiles' cache mounts
# (/go/pkg/mod, /root/.cache/go-build) actually persist across runs, which
# is what makes incremental rebuilds for E2E finish in seconds.
.PHONY: image-controller
image-controller: ## Build the controller image.
	$(DOCKER) buildx build --load -f controller/Dockerfile -t $(CONTROLLER_IMAGE) controller

.PHONY: image-webhookcertjob
image-webhookcertjob: ## Build the webhook cert job image.
	$(DOCKER) buildx build --load -f controller/Dockerfile.webhookcertjob -t $(WEBHOOKCERTJOB_IMAGE) controller

.PHONY: image-daemon
image-daemon: ## Build the daemon image.
	$(DOCKER) buildx build --load -f daemon/Dockerfile -t $(DAEMON_IMAGE) .

.PHONY: image-bgp-speaker
image-bgp-speaker: ## Build the BGP speaker image.
	$(DOCKER) buildx build --load -f bgp-speaker/Dockerfile -t $(BGP_SPEAKER_IMAGE) .

.PHONY: publish
publish: publish-controller publish-webhookcertjob publish-daemon publish-bgp-speaker ## Build and publish all runtime images.

.PHONY: publish-controller
publish-controller:
	$(DOCKER) buildx build --platform $(PUBLISH_PLATFORMS) --push -f controller/Dockerfile -t $(PUBLISH_CONTROLLER_IMAGE) controller

.PHONY: publish-webhookcertjob
publish-webhookcertjob:
	$(DOCKER) buildx build --platform $(PUBLISH_PLATFORMS) --push -f controller/Dockerfile.webhookcertjob -t $(PUBLISH_WEBHOOKCERTJOB_IMAGE) controller

.PHONY: publish-daemon
publish-daemon:
	$(DOCKER) buildx build --platform $(PUBLISH_PLATFORMS) --push -f daemon/Dockerfile -t $(PUBLISH_DAEMON_IMAGE) .

.PHONY: publish-bgp-speaker
publish-bgp-speaker:
	$(DOCKER) buildx build --platform $(PUBLISH_PLATFORMS) --push -f bgp-speaker/Dockerfile -t $(PUBLISH_BGP_SPEAKER_IMAGE) .

##@ Integration

.PHONY: e2e
e2e: ## Run repository end-to-end tests.
	$(MAKE) -C test/e2e test

##@ Dependencies

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION) ## Download golangci-lint locally if necessary.
	ln -sf $(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION) $(GOLANGCI_LINT)

.PHONY: crddoc
crddoc: $(CRDDOC) ## Download crddoc locally if necessary.

$(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),$(GOLANGCI_LINT_PACKAGE),$(GOLANGCI_LINT_VERSION))

$(CRDDOC): $(LOCALBIN)
	$(call go-install-tool,$(CRDDOC),github.com/theunrepentantgeek/crddoc,$(CRDDOC_VERSION))

define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
