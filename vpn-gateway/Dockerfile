FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod *.go ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -o /vpn-gateway .

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl libcharon-extra-plugins libstrongswan-standard-plugins \
    bird2 iproute2 iptables procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /vpn-gateway /usr/local/bin/vpn-gateway
ENTRYPOINT ["/usr/local/bin/vpn-gateway"]
