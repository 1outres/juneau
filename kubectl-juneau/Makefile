# kubectl-juneau is consumed via the top-level Makefile. The targets
# here are intentionally minimal: a binary build for local use plus the
# usual go test / go vet pair. The plugin has no manifests, image, or
# generated code, so there is no reason to mirror controller's heavier
# scaffolding.

LOCALBIN ?= $(CURDIR)/bin
BIN ?= $(LOCALBIN)/kubectl-juneau

GOFLAGS ?=

VERSION_PKG = github.com/1outres/juneau/kubectl-juneau/internal/version
GIT_COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
GIT_TAG    ?= $(shell git describe --tags --dirty --always 2>/dev/null)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS ?= -X $(VERSION_PKG).gitCommit=$(GIT_COMMIT) -X $(VERSION_PKG).gitTag=$(GIT_TAG) -X $(VERSION_PKG).buildDate=$(BUILD_DATE)

.PHONY: build
build: ## Build the kubectl-juneau binary into ./bin.
	mkdir -p $(LOCALBIN)
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/kubectl-juneau

.PHONY: test
test: ## Run unit tests.
	go test ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: tidy
tidy: ## Tidy module dependencies.
	go mod tidy

.PHONY: clean
clean: ## Remove build artefacts.
	rm -rf $(LOCALBIN)
