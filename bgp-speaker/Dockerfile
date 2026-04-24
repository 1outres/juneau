FROM docker.io/golang:1.24 AS builder
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
COPY test/e2e/go.mod test/e2e/go.mod

COPY controller/ controller/
COPY bgp-speaker/ bgp-speaker/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -C bgp-speaker -a -o /workspace/bgpspeaker ./cmd/bgpspeaker

FROM docker.io/alpine:3.23

WORKDIR /

# alpine 3.23 ships BIRD 3.1.6 (with BMP + adj-rib-in pre/post policy monitoring).
# The package is called `bird` (not `bird2`) since the merge in 3.23.
RUN apk add --no-cache bird

COPY --from=builder /workspace/bgpspeaker /bgpspeaker

USER 0:0

ENTRYPOINT ["/bgpspeaker"]
