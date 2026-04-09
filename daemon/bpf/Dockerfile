FROM golang:1.24-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpftool \
    clang \
    libbpf-dev \
    llvm \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/clang /usr/local/bin/bpf-clang
RUN ln -sf /usr/bin/llvm-strip /usr/local/bin/bpf-llvm-strip

WORKDIR /workspace/daemon
