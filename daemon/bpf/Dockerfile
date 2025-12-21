FROM ghcr.io/cilium/ebpf-builder:1762345965

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 90
RUN update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-17 90

RUN apt update && apt install -y libssl-dev

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool \
    && cd /tmp/bpftool/src \
    && make install \
    && rm -r /tmp/bpftool

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /vmlinux.h

ENTRYPOINT ["/entrypoint.sh"]
