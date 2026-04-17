FROM docker.io/golang:1.24 AS builder

WORKDIR /workspace

COPY go.work go.work
COPY daemon/go.mod daemon/go.mod
COPY daemon/go.sum daemon/go.sum
COPY bgp-speaker/go.mod bgp-speaker/go.mod
COPY bgp-speaker/go.sum bgp-speaker/go.sum
COPY controller/go.mod controller/go.mod
COPY controller/go.sum controller/go.sum
COPY test/e2e/go.mod test/e2e/go.mod

COPY controller/ controller/
COPY daemon/ daemon/

RUN go build -C daemon -o bin/cni ./cmd/cni
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -C daemon -a -o /workspace/juneaud ./cmd/juneaud

FROM docker.io/debian:bookworm-slim

WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /sys/fs/bpf

COPY --from=builder /workspace/juneaud /juneaud

USER 0:0

ENTRYPOINT ["/juneaud"]
