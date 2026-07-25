# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM docker.io/golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.work go.work
COPY bgp-speaker/go.mod bgp-speaker/go.mod
COPY bgp-speaker/go.sum bgp-speaker/go.sum
COPY daemon/go.mod daemon/go.mod
COPY daemon/go.sum daemon/go.sum
COPY controller/go.mod controller/go.mod
COPY controller/go.sum controller/go.sum
COPY kubectl-juneau/go.mod kubectl-juneau/go.mod
COPY kubectl-juneau/go.sum kubectl-juneau/go.sum
COPY test/e2e/go.mod test/e2e/go.mod

# Pre-download module deps so the cache layer is only invalidated when
# go.mod/go.sum changes; the cache mount keeps /go/pkg/mod warm across
# rebuilds either way.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download -C bgp-speaker

COPY controller/ controller/
COPY bgp-speaker/ bgp-speaker/

# Cache mounts make incremental rebuilds finish in seconds; -a forced
# full rebuilds and is dropped.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -C bgp-speaker -o /workspace/bgpspeaker ./cmd/bgpspeaker

FROM docker.io/alpine:3.23

WORKDIR /

# alpine 3.23 ships BIRD 3.1.6 (with BMP + adj-rib-in pre/post policy monitoring).
# The package is called `bird` (not `bird2`) since the merge in 3.23.
RUN apk add --no-cache bird

COPY --from=builder /workspace/bgpspeaker /bgpspeaker

USER 0:0

ENTRYPOINT ["/bgpspeaker"]
