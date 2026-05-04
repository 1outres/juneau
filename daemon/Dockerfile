# syntax=docker/dockerfile:1
FROM docker.io/golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.work go.work
COPY daemon/go.mod daemon/go.mod
COPY daemon/go.sum daemon/go.sum
COPY bgp-speaker/go.mod bgp-speaker/go.mod
COPY bgp-speaker/go.sum bgp-speaker/go.sum
COPY controller/go.mod controller/go.mod
COPY controller/go.sum controller/go.sum
COPY test/e2e/go.mod test/e2e/go.mod

# Pre-download module deps before pulling source so the cache layer is
# only invalidated when go.mod/go.sum changes. The cache mount keeps
# /go/pkg/mod warm across builds even when this layer rebuilds.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download -C daemon

COPY controller/ controller/
COPY daemon/ daemon/

# BuildKit cache mounts let the Go build cache + module cache survive
# across invocations. -a forced full rebuilds and is dropped.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -C daemon -o bin/cni ./cmd/cni
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -C daemon -o /workspace/juneaud ./cmd/juneaud

FROM docker.io/debian:bookworm-slim

WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends iptables bpftool && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /sys/fs/bpf

COPY --from=builder /workspace/juneaud /juneaud

USER 0:0

ENTRYPOINT ["/juneaud"]
