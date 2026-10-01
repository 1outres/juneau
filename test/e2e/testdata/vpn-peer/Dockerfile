FROM vpn-gateway:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl python3 iputils-ping tcpdump \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/sh"]
